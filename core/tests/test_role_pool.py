"""routes.role_pool — auto-load/auto-unload for coordinator-role instance
binding (nac/ipam/ldap → cppm/netbox/ldap roles).

Unit-tests the two primitives directly against a fake hub (no HTTP layer) —
ensure_role_loaded (used by add/update) and maybe_unload_orphaned_role (used
by delete/reassign).
"""
import pytest

from routes.role_pool import (
    PRODUCT_ROLE, ensure_role_loaded, maybe_unload_orphaned_role,
)


class _FakeHub:
    _CMD_UNAUTHENTICATED = "unauthenticated"

    def __init__(self):
        self.active_connections = {}
        self.spoke_module_types = {}
        self.load_role_calls = []
        self.unload_role_calls = []
        self.load_role_result = None  # set per-test; defaults to a SUCCESS below

    def _primary_key(self, sid):
        return sid

    def spoke_can_accept_commands(self, sid):
        return True, None

    async def request_response(self, spoke_id, cmd, payload, timeout=None):
        if cmd == "LOAD_ROLE":
            self.load_role_calls.append((spoke_id, payload))
            if self.load_role_result is not None:
                return self.load_role_result
            role = payload["role"]
            sub_id = f"{spoke_id}-{role}"
            # Simulate the real spoke connecting as the new sub-spoke.
            self.active_connections[sub_id] = object()
            self.spoke_module_types[sub_id] = PRODUCT_ROLE_MODULE.get(role, role)
            return {"payload": {"data": {
                "status": "SUCCESS", "sub_spoke_id": sub_id,
                "module_type": self.spoke_module_types[sub_id]}}}
        if cmd == "UNLOAD_ROLE":
            self.unload_role_calls.append((spoke_id, payload))
            return {"payload": {"data": {"status": "SUCCESS"}}}
        raise AssertionError(f"unexpected command {cmd}")


PRODUCT_ROLE_MODULE = {role: module_type for role, module_type in PRODUCT_ROLE.values()}


def _connect(hub, sid, module_type):
    hub.active_connections[sid] = object()
    hub.spoke_module_types[sid] = module_type


# ── ensure_role_loaded ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_ensure_role_loaded_noop_when_already_the_right_connected_subspoke():
    hub = _FakeHub()
    _connect(hub, "spokeA-cppm", "nac")
    result = await ensure_role_loaded(hub, "spokeA-cppm", "cppm", "nac")
    assert result == "spokeA-cppm"
    assert hub.load_role_calls == []  # no auto-load needed


@pytest.mark.asyncio
async def test_ensure_role_loaded_reuses_already_loaded_subspoke_from_base_id():
    """Operator picked the BASE agent id, but its cppm sub-spoke already exists
    and is connected — reuse it, don't re-trigger LOAD_ROLE."""
    hub = _FakeHub()
    _connect(hub, "spokeA", "agent")
    _connect(hub, "spokeA-cppm", "nac")
    result = await ensure_role_loaded(hub, "spokeA", "cppm", "nac")
    assert result == "spokeA-cppm"
    assert hub.load_role_calls == []


@pytest.mark.asyncio
async def test_ensure_role_loaded_auto_loads_on_bare_base_agent():
    hub = _FakeHub()
    _connect(hub, "spokeA", "agent")
    result = await ensure_role_loaded(hub, "spokeA", "cppm", "nac")
    assert result == "spokeA-cppm"
    assert hub.load_role_calls == [("spokeA", {"role": "cppm", "config": {}})]
    assert hub.spoke_module_types["spokeA-cppm"] == "nac"


@pytest.mark.asyncio
async def test_ensure_role_loaded_returns_falsy_spoke_id_unchanged():
    hub = _FakeHub()
    assert await ensure_role_loaded(hub, "", "cppm", "nac") == ""
    assert await ensure_role_loaded(hub, None, "cppm", "nac") is None
    assert hub.load_role_calls == []


@pytest.mark.asyncio
async def test_ensure_role_loaded_raises_when_base_agent_offline():
    from fastapi import HTTPException
    hub = _FakeHub()  # spokeA never connected
    with pytest.raises(HTTPException) as ei:
        await ensure_role_loaded(hub, "spokeA", "cppm", "nac")
    assert ei.value.status_code == 503


@pytest.mark.asyncio
async def test_ensure_role_loaded_raises_on_load_failure():
    from fastapi import HTTPException
    hub = _FakeHub()
    _connect(hub, "spokeA", "agent")
    hub.load_role_result = {"payload": {"data": {
        "status": "ERROR", "message": "sibling repo clone failed"}}}
    with pytest.raises(HTTPException) as ei:
        await ensure_role_loaded(hub, "spokeA", "cppm", "nac")
    assert ei.value.status_code == 502
    assert "sibling repo clone failed" in ei.value.detail


# ── maybe_unload_orphaned_role ────────────────────────────────────────────

@pytest.mark.asyncio
async def test_maybe_unload_sends_unload_role_when_no_records_reference_it():
    hub = _FakeHub()
    _connect(hub, "spokeA", "agent")
    await maybe_unload_orphaned_role(hub, "spokeA-cppm", "cppm", other_records=[])
    assert hub.unload_role_calls == [("spokeA", {"role": "cppm"})]


@pytest.mark.asyncio
async def test_maybe_unload_skips_when_another_record_still_references_it():
    hub = _FakeHub()
    _connect(hub, "spokeA", "agent")
    other = [{"id": "other-instance", "spoke_id": "spokeA-cppm"}]
    await maybe_unload_orphaned_role(hub, "spokeA-cppm", "cppm", other_records=other)
    assert hub.unload_role_calls == []


@pytest.mark.asyncio
async def test_maybe_unload_noop_when_spoke_id_is_falsy():
    hub = _FakeHub()
    await maybe_unload_orphaned_role(hub, "", "cppm", other_records=[])
    assert hub.unload_role_calls == []


@pytest.mark.asyncio
async def test_maybe_unload_noop_when_base_agent_offline():
    """Best-effort cleanup — if the base agent isn't even connected, there's
    nothing to send UNLOAD_ROLE to; must not raise."""
    hub = _FakeHub()  # spokeA never connected
    await maybe_unload_orphaned_role(hub, "spokeA-cppm", "cppm", other_records=[])
    assert hub.unload_role_calls == []


@pytest.mark.asyncio
async def test_maybe_unload_swallows_rpc_failure():
    """A failed UNLOAD_ROLE must never propagate — cleanup is best-effort and
    must not block the delete/reassign that triggered it."""
    class _FailingHub(_FakeHub):
        async def request_response(self, spoke_id, cmd, payload, timeout=None):
            if cmd == "UNLOAD_ROLE":
                raise RuntimeError("relay unreachable")
            return await super().request_response(spoke_id, cmd, payload, timeout)

    hub = _FailingHub()
    _connect(hub, "spokeA", "agent")
    await maybe_unload_orphaned_role(hub, "spokeA-cppm", "cppm", other_records=[])  # must not raise


@pytest.mark.asyncio
async def test_maybe_unload_ignores_a_spoke_id_that_isnt_a_role_subspoke():
    """A spoke_id that doesn't end in -<role> isn't one we auto-loaded —
    nothing to unload (defensive: pre-existing/legacy records)."""
    hub = _FakeHub()
    _connect(hub, "some-other-shape", "agent")
    await maybe_unload_orphaned_role(hub, "some-other-shape", "cppm", other_records=[])
    assert hub.unload_role_calls == []


def test_product_role_maps_the_three_coordinator_instance_products():
    assert PRODUCT_ROLE == {
        "nac-instances": ("cppm", "nac"),
        "ipam-instances": ("netbox", "ipam"),
        "ldap-instances": ("ldap", "directory"),
    }
