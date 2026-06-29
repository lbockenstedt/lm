"""Unit test — dirty-flag persistence mechanics (locks in the H2 write-coalescing).

``StateManager`` no longer rewrites both encrypted state files every 60s
unconditionally; the persistence loop flushes only when dirty, and in-memory
mutators mark dirty. These tests exercise the mechanics directly (no 60s
sleep): a mutator marks dirty, ``_flush_if_dirty`` writes once and clears the
flag, a second flush with nothing dirty is a no-op, and a failed write
restores the flag so the next tick retries. ``save_state()`` (the synchronous
explicit-save path) also clears the flag.

Paths are redirected to ``tmp_path`` after construction so the test never
touches the real ``/var/lib/lm/state``. The files are encrypted at rest, so we
read them back via ``_load_file`` (which decrypts) to assert content.
"""

import pytest

from state.manager import StateManager


@pytest.fixture
def store(tmp_path):
    s = StateManager()
    # Redirect to an isolated tmp dir; reset to known state so the test is
    # independent of whatever the dev machine's real state file contains.
    s.system_path = str(tmp_path / "system.json")
    s.tenants_path = str(tmp_path / "tenants.json")
    s.system_state = {"global_config": {}, "approved_modules": {}, "known_modules": [],
                      "module_names": {}, "module_metadata": {}, "active_sessions": {},
                      "active_tenant": "default", "users": {}, "agent_config": {}, "resources": {}}
    s.tenant_state = {"tenants": {}}
    with s._dirty_lock:
        s._dirty = False
    return s


@pytest.mark.asyncio
async def test_in_memory_mutator_marks_dirty_without_writing(store, tmp_path):
    assert store._dirty is False
    store.update_global_config({"hub_branch": "main"})
    assert store._dirty is True
    # Nothing written yet — the in-memory mutation only flagged dirty
    assert not (tmp_path / "system.json").exists()


@pytest.mark.asyncio
async def test_flush_if_dirty_writes_once_and_clears_flag(store, tmp_path):
    store.update_global_config({"hub_branch": "main"})
    wrote = await store._flush_if_dirty()
    assert wrote is True
    assert store._dirty is False
    # File exists and round-trips through decrypt → contains the mutation
    loaded = store._load_file(store.system_path)
    assert loaded["global_config"]["hub_branch"] == "main"


@pytest.mark.asyncio
async def test_flush_when_not_dirty_is_noop(store, tmp_path):
    # Nothing dirty → no write, returns False
    wrote = await store._flush_if_dirty()
    assert wrote is False
    assert not (tmp_path / "system.json").exists()


@pytest.mark.asyncio
async def test_failed_write_restores_dirty_for_retry(store):
    # Point system_path at an unwritable location so _save_file raises
    store.update_global_config({"hub_branch": "main"})
    assert store._dirty is True
    store.system_path = "/nonexistent/dir/system.json"
    wrote = await store._flush_if_dirty()
    assert wrote is False            # write failed
    assert store._dirty is True      # flag restored → next tick retries


@pytest.mark.asyncio
async def test_save_state_clears_dirty(store, tmp_path):
    store.update_tenant("acme", {"name": "Acme"})
    assert store._dirty is True
    store.save_state()                # synchronous explicit save
    assert store._dirty is False
    # The tenant persisted
    loaded = store._load_file(store.tenants_path)
    assert loaded["tenants"]["acme"]["name"] == "Acme"
    # And a subsequent flush is a no-op (not dirty)
    wrote = await store._flush_if_dirty()
    assert wrote is False


@pytest.mark.asyncio
async def test_racing_mutation_during_flush_not_lost(store, tmp_path):
    """clear-before-write: a mutation that lands during the write re-marks dirty
    so it is picked up on the next tick. Simulated by mutating after the flush
    clears the flag but conceptually during the window — the next flush persists
    it and clears the flag again."""
    store.update_global_config({"a": 1})
    await store._flush_if_dirty()
    assert store._dirty is False
    # A new mutation arrives
    store.update_global_config({"b": 2})
    assert store._dirty is True
    wrote = await store._flush_if_dirty()
    assert wrote is True
    loaded = store._load_file(store.system_path)
    assert loaded["global_config"] == {"a": 1, "b": 2}
    assert store._dirty is False