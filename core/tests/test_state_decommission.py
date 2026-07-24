"""StateManager soft-retire surface — decommission / restore / predicates.

``decommission_module``/``restore_module`` (spokes + generic Hub-direct agents,
keyed by primary key) and ``decommission_agent``/``restore_agent`` (relayed
Proxmox node agents, keyed by agent_id) back the Spokes & Agents view's
Decommission / Restore actions. A decommissioned box keeps its record (stays
visible + re-onboardable) but the out-of-contact alert loop skips it; restore
re-enables alerting. The flag persists in the encrypted ``system.json`` under
``decommissioned_spokes`` / ``decommissioned_agents``. ``remove_module`` clears
a stale marker on full delete so the lists don't accrete dead ids.
"""
import pytest

from state.manager import StateManager


@pytest.fixture
def store(tmp_path):
    s = StateManager()
    s.system_path = str(tmp_path / "system.json")
    s.tenants_path = str(tmp_path / "tenants.json")
    s.system_state = {"global_config": {}, "approved_modules": {}, "known_modules": [],
                      "module_names": {}, "module_metadata": {}, "active_sessions": {},
                      "active_tenant": "default", "users": {}, "agent_config": {},
                      "resources": {}, "decommissioned_spokes": [], "decommissioned_agents": []}
    s.tenant_state = {"tenants": {}}
    with s._dirty_lock:
        s._dirty = False
    return s


# ── spokes / generic agents ─────────────────────────────────────────────────

def test_decommission_module_sets_flag_and_persists(store, tmp_path):
    assert store.decommission_module("s1") is True
    assert store.is_module_decommissioned("s1") is True
    # persisted to system.json
    loaded = store._load_file(store.system_path)
    assert loaded["decommissioned_spokes"] == ["s1"]


def test_decommission_module_idempotent(store):
    assert store.decommission_module("s1") is True
    assert store.decommission_module("s1") is False  # already retired — no change
    assert store.system_state["decommissioned_spokes"] == ["s1"]


def test_restore_module_clears_flag(store):
    store.decommission_module("s1")
    assert store.restore_module("s1") is True
    assert store.is_module_decommissioned("s1") is False
    assert "s1" not in store.system_state["decommissioned_spokes"]


def test_restore_module_when_not_decommissioned_is_noop(store):
    assert store.restore_module("s1") is False
    assert store.system_state["decommissioned_spokes"] == []


# ── relayed agents ───────────────────────────────────────────────────────────

def test_decommission_agent_sets_flag(store):
    assert store.decommission_agent("pxmx-host") is True
    assert store.is_agent_decommissioned("pxmx-host") is True
    assert store.is_agent_decommissioned("other") is False


def test_restore_agent_clears_flag(store):
    store.decommission_agent("pxmx-host")
    assert store.restore_agent("pxmx-host") is True
    assert store.is_agent_decommissioned("pxmx-host") is False


def test_agent_and_module_lists_are_independent(store):
    # same id in both lists must not cross-resolve (spoke id vs agent id).
    store.decommission_module("x")
    assert store.is_module_decommissioned("x") is True
    assert store.is_agent_decommissioned("x") is False


# ── remove_module clears a stale marker ──────────────────────────────────────

def test_remove_module_clears_decommission_marker(store, tmp_path):
    store.decommission_module("s1")
    # seed the registration so remove_module has something to drop
    store.system_state["known_modules"] = ["s1"]
    store.system_state["module_metadata"] = {"s1": {"name": "s1"}}
    store.remove_module("s1")
    assert store.is_module_decommissioned("s1") is False
    assert "s1" not in store.system_state["decommissioned_spokes"]