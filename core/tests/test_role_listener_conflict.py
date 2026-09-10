"""Two roles that bind the same host port must never be stacked on one VM.

A live box lost its WebUI to exactly this: the ``proxmox`` role's agent listener
bound ``wss://0.0.0.0:443`` two seconds before the ``proxy`` role loaded, so the
edge proxy could never bind. Nothing failed loudly — the proxy logged EADDRINUSE
and retried forever while every browser request was answered by the agent
listener with a bare ``OK``.

``routes/agents._guard_listener_conflicts`` is the authoritative gate: it runs
inside ``_load_roles_impl``, so BOTH the admin ``/api/agent/*`` and the tenant
``/tenant/agent/*`` load-role routes are covered, and a hub-side re-push cannot
recreate the collision either.
"""
import pytest

from routes import agents
from fastapi import HTTPException


# ── the pure conflict helper ────────────────────────────────────────────────

def test_port_binding_roles_conflict_with_each_other():
    assert agents._listener_conflict(["proxmox"], "proxy") == "proxmox"
    assert agents._listener_conflict(["proxy"], "proxmox") == "proxy"
    assert agents._listener_conflict(["simulation"], "proxy") == "simulation"
    assert agents._listener_conflict(["proxmox"], "simulation") == "proxmox"


def test_non_listener_roles_never_conflict():
    """dns/dhcp/ldap/... bind nothing, so they stack freely — including
    alongside a port-binding role."""
    for role in ("dns", "dhcp", "le", "netbox", "cppm", "truenas"):
        assert agents._listener_conflict(["proxmox", "proxy"], role) is None
    assert agents._listener_conflict(["dns", "dhcp", "le"], "proxy") is None


def test_role_does_not_conflict_with_itself():
    """Re-loading an already-loaded role is a no-op upgrade, not a collision."""
    assert agents._listener_conflict(["proxy"], "proxy") is None


def test_conflict_message_names_both_roles_and_the_port():
    msg = agents._listener_conflict_message("box-1", "proxy", "proxmox")
    assert "proxy" in msg and "proxmox" in msg and "443" in msg
    assert "box-1" in msg


# ── fakes ───────────────────────────────────────────────────────────────────

class _Hub:
    """Minimal hub: records commands and replies to GET_AVAILABLE_ROLES."""

    def __init__(self, active=(), available_raises=False):
        self._active = list(active)
        self._available_raises = available_raises
        self.sent = []

    def _primary_key(self, sid):
        return sid

    async def request_response(self, spoke_id, command, payload, timeout=None):
        self.sent.append(command)
        if command == "GET_AVAILABLE_ROLES":
            if self._available_raises:
                raise TimeoutError("agent did not answer")
            return {"payload": {"data": {
                "active": [{"role": r} for r in self._active],
                "available": [],
            }}}
        return {"payload": {"data": {"status": "SUCCESS"}}}


# ── the guard ───────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_guard_blocks_role_conflicting_with_already_loaded_role():
    hub = _Hub(active=["proxmox", "dns"])
    with pytest.raises(HTTPException) as ei:
        await agents._guard_listener_conflicts(hub, "box-1", ["proxy"])
    assert ei.value.status_code == 409
    assert "proxmox" in ei.value.detail


@pytest.mark.asyncio
async def test_guard_blocks_two_conflicting_roles_in_one_batch():
    """The batch is rejected on its own, before the agent is even consulted —
    otherwise the first role would load and poison the box for the second."""
    hub = _Hub(active=[])
    with pytest.raises(HTTPException) as ei:
        await agents._guard_listener_conflicts(hub, "box-1", ["proxmox", "proxy"])
    assert ei.value.status_code == 409
    assert "GET_AVAILABLE_ROLES" not in hub.sent


@pytest.mark.asyncio
async def test_guard_allows_a_listener_role_on_a_clean_box():
    hub = _Hub(active=["dns", "le"])
    await agents._guard_listener_conflicts(hub, "box-1", ["proxy"])


@pytest.mark.asyncio
async def test_guard_skips_the_probe_when_no_candidate_binds_a_port():
    """Loading dns/dhcp must not cost an extra round trip to the agent."""
    hub = _Hub(active=["proxmox"])
    await agents._guard_listener_conflicts(hub, "box-1", ["dns", "dhcp"])
    assert hub.sent == []


@pytest.mark.asyncio
async def test_guard_allows_reloading_the_same_listener_role():
    hub = _Hub(active=["proxy"])
    await agents._guard_listener_conflicts(hub, "box-1", ["proxy"])


@pytest.mark.asyncio
async def test_unreachable_agent_does_not_block_the_load():
    """An agent that can't answer GET_AVAILABLE_ROLES must stay manageable.
    Unknown != conflicting; the spoke-side bind retry still contains the damage."""
    hub = _Hub(active=["proxmox"], available_raises=True)
    await agents._guard_listener_conflicts(hub, "box-1", ["proxy"])


@pytest.mark.asyncio
async def test_malformed_available_roles_payload_does_not_block():
    class _Junk(_Hub):
        async def request_response(self, spoke_id, command, payload, timeout=None):
            if command == "GET_AVAILABLE_ROLES":
                return {"payload": {"data": "not-a-dict"}}
            return {"payload": {"data": {"status": "SUCCESS"}}}

    await agents._guard_listener_conflicts(_Junk(), "box-1", ["proxy"])


@pytest.mark.asyncio
async def test_active_role_names_accepts_bare_strings():
    """Older agents report ``active`` as plain role names, not dicts."""
    class _Bare(_Hub):
        async def request_response(self, spoke_id, command, payload, timeout=None):
            return {"payload": {"data": {"active": ["proxmox", "dns"]}}}

    assert await agents._active_role_names(_Bare(), "box-1") == {"proxmox", "dns"}


# ── enforced through the real dispatch (both route families) ────────────────

@pytest.mark.asyncio
async def test_single_load_role_is_rejected_and_never_relayed():
    hub = _Hub(active=["proxmox"])
    with pytest.raises(HTTPException) as ei:
        await agents._load_roles_impl(hub, "box-1", {"role": "proxy"})
    assert ei.value.status_code == 409
    assert "LOAD_ROLE" not in hub.sent


@pytest.mark.asyncio
async def test_batch_load_role_is_rejected_and_never_relayed():
    hub = _Hub(active=["proxmox"])
    with pytest.raises(HTTPException) as ei:
        await agents._load_roles_impl(
            hub, "box-1", {"roles": [{"role": "dns"}, {"role": "proxy"}]})
    assert ei.value.status_code == 409
    # The whole batch is refused — dns must not be half-applied.
    assert "LOAD_ROLE" not in hub.sent


@pytest.mark.asyncio
async def test_safe_batch_still_loads():
    hub = _Hub(active=["dns"])
    res = await agents._load_roles_impl(
        hub, "box-1", {"roles": [{"role": "le"}, {"role": "proxy"}]})
    assert res["status"] == "SUCCESS"
    assert hub.sent.count("LOAD_ROLE") == 2


def test_statuspage_is_covered():
    """The status page serves its own HTTPS on web_port, default 443
    (statuspage/src/statuspage_spoke.py) — it collides with the edge proxy just
    as proxmox does, and was the easiest of these to miss."""
    assert agents._listener_conflict(["proxy"], "statuspage") == "proxy"
    assert agents._listener_conflict(["statuspage"], "proxmox") == "statuspage"


def test_webui_table_matches_the_backend_table():
    """WebUI/main.js mirrors LISTENER_PORT_ROLES; a role added to one and not
    the other means the UI silently offers a combination the hub rejects."""
    import os
    import re
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    js = open(os.path.join(root, "WebUI", "main.js")).read()
    block = re.search(r"const ROLE_LISTENER_PORTS = \{(.*?)\};", js, re.S).group(1)
    ui = {m.group(1): int(m.group(2))
          for m in re.finditer(r"'([\w-]+)'\s*:\s*(\d+)", block)}
    assert ui == agents._LISTENER_PORT_ROLES
