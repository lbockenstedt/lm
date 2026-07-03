"""Hub parent-auto-approve for multi-role generic agents.

A generic agent hosts N role sub-spokes (``spoke_id {base}-{role}``, each its own
WS connection). Instead of admin-approving every sub-spoke by hand, the hub
auto-approves any sub-spoke whose **parent agent** (``parent_spoke_id``, sent in
the sub-spoke's auth frame) is already approved + connected + module_type
``"agent"``, binding the sub-spoke to the parent's tenant. This reuses
``LabManagerHub.approve_and_bind_spoke`` — the same state machine as admin + PSK
approval (register approved, set tenant, generate + push session key, push
APPROVED + config).

Two orderings are covered:
  * **sub-after-parent** — the sub-spoke connects once the base is already
    approved: the connect-time block in ``handle_connection`` auto-approves it.
  * **sub-before-parent** — the sub-spoke connects first and waits pending; when
    the base agent is later approved, ``_auto_approve_pending_subspokes`` sweeps
    it up (called at the end of ``approve_and_bind_spoke`` for module_type
    ``"agent"``).

The fake hub mirrors only the attributes these production methods touch (same
pattern as ``test_install_uuid_identity``'s ``_ReconcileHub``) but forwards
``approve_and_bind_spoke`` / ``_can_parent_auto_approve`` /
``_auto_approve_pending_subspokes`` to the REAL ``LabManagerHub``
implementations, so the approve+tenant-bind+key-push state machine is exercised
end-to-end (only the WS send is stubbed).
"""

import asyncio
import os
import sys
from collections import deque

_LM_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _LM_ROOT not in sys.path:
    sys.path.insert(0, _LM_ROOT)

import main  # noqa: E402
from security.key_manager import KeyManager  # noqa: E402
from state.manager import StateManager  # noqa: E402


# ── fixtures ─────────────────────────────────────────────────────────────────

def _make_km():
    """KeyManager whose persistence lives in /tmp, not core/data."""
    km = KeyManager("keys_parent_auto_test.json", "hub_secret_parent_auto_test.json")
    km.storage_path = "/tmp/lm_keys_parent_auto_test.json"
    km.hub_secret_path = "/tmp/lm_hub_secret_parent_auto_test.json"
    for p in (km.storage_path, km.hub_secret_path):
        try:
            os.remove(p)
        except OSError:
            pass
    return km


def _fresh_state(tmp_path):
    """A real StateManager with a clean system_state + redirected disk paths."""
    s = StateManager()
    s.system_path = str(tmp_path / "system.json")
    s.tenants_path = str(tmp_path / "tenants.json")
    s.system_state = {
        "approved_modules": {},
        "known_modules": [],
        "module_names": {},
        "module_metadata": {},
        "agent_config": {},
        "agent_display_names": {},
    }
    return s


class _Ws:
    """Sentinel websocket — only membership in active_connections matters here."""


class _AutoApproveHub:
    """Minimal stand-in exposing exactly what the parent-auto-approve path
    touches. Forwards the three production methods to the real LabManagerHub
    implementations (bound to this fake via ``self``)."""

    def __init__(self, state, km):
        self.state = state
        self.key_manager = km
        self.approved_modules = {}
        self.active_connections = {}
        self.spoke_module_types = {}
        self.spoke_parent_map = {}
        self.known_modules = state.system_state["known_modules"]
        self.spoke_event_limit = 100
        self.spoke_events = {}

    def record_spoke_event(self, spoke_id, event, detail=""):
        if not spoke_id:
            return
        buf = self.spoke_events.setdefault(spoke_id, deque(maxlen=self.spoke_event_limit))
        buf.append({"ts": 0.0, "event": event, "detail": detail})

    async def send_to_spoke(self, message, signing_secret=None):
        return  # no real WS — the key-push is exercised via key_manager state

    async def push_config_to_spoke(self, spoke_id):
        return  # no-op

    # Forward to the real implementations (async fns return coroutines; awaiting
    # the returned coroutine runs the production code with self = this fake).
    def approve_and_bind_spoke(self, spoke_id, tenant_id):
        return main.LabManagerHub.approve_and_bind_spoke(self, spoke_id, tenant_id)

    def _can_parent_auto_approve(self, spoke_id, parent_spoke_id):
        return main.LabManagerHub._can_parent_auto_approve(self, spoke_id, parent_spoke_id)

    async def _auto_approve_pending_subspokes(self, parent_spoke_id):
        return await main.LabManagerHub._auto_approve_pending_subspokes(self, parent_spoke_id)


def _events_of(hub, sid, kind):
    return [e for e in hub.spoke_events.get(sid, []) if e["event"] == kind]


async def _connect_time_auto_approve(hub, spoke_id, parent_spoke_id):
    """Mirror of the parent-auto-approve block in handle_connection (sub-after-
    parent ordering): record the parent claim, and if the sub is pending + the
    parent can vouch for it, approve+bind it to the parent's tenant + record the
    lifecycle event. Runs the REAL approve_and_bind_spoke state machine."""
    hub.spoke_parent_map[spoke_id] = parent_spoke_id
    if (not hub.approved_modules.get(spoke_id, False)
            and hub._can_parent_auto_approve(spoke_id, parent_spoke_id)):
        tenant = hub.state.get_spoke_tenant(parent_spoke_id) or ""
        await hub.approve_and_bind_spoke(spoke_id, tenant)
        hub.record_spoke_event(spoke_id, "parent_auto_approve",
                               f"parent={parent_spoke_id}")


def _seed_base_agent(hub, base_id, tenant):
    """Mark a base generic agent approved + connected + tenant-bound + module_type
    'agent' (the state an admin-approved Generic Node is in when its sub-spokes
    connect)."""
    hub.spoke_module_types[base_id] = "agent"
    hub.active_connections[base_id] = _Ws()
    hub.approved_modules[base_id] = True
    hub.state.register_module(base_id, approved=True)
    hub.state.set_spoke_tenant(base_id, tenant)


# ── _can_parent_auto_approve: pure gating logic ──────────────────────────────

def test_can_parent_auto_approve_happy_path(tmp_path):
    hub = _AutoApproveHub(_fresh_state(tmp_path), _make_km())
    _seed_base_agent(hub, "agent-1", "tenant-A")
    assert hub._can_parent_auto_approve("agent-1-dns", "agent-1") is True


def test_can_parent_auto_approve_rejects_non_prefix_tied_id(tmp_path):
    """An unrelated spoke can't claim a parent it isn't id-tied to."""
    hub = _AutoApproveHub(_fresh_state(tmp_path), _make_km())
    _seed_base_agent(hub, "agent-1", "tenant-A")
    assert hub._can_parent_auto_approve("agent-2-dns", "agent-1") is False
    assert hub._can_parent_auto_approve("agent-1", "agent-1") is False  # not a sub


def test_can_parent_auto_approve_rejects_unapproved_parent(tmp_path):
    hub = _AutoApproveHub(_fresh_state(tmp_path), _make_km())
    hub.spoke_module_types["agent-1"] = "agent"
    hub.active_connections["agent-1"] = _Ws()       # connected but NOT approved
    assert hub._can_parent_auto_approve("agent-1-dns", "agent-1") is False


def test_can_parent_auto_approve_rejects_disconnected_parent(tmp_path):
    hub = _AutoApproveHub(_fresh_state(tmp_path), _make_km())
    hub.spoke_module_types["agent-1"] = "agent"
    hub.approved_modules["agent-1"] = True          # approved but NOT connected
    assert hub._can_parent_auto_approve("agent-1-dns", "agent-1") is False


def test_can_parent_auto_approve_rejects_non_agent_parent(tmp_path):
    """A sub-spoke can't be vouched for by a non-agent spoke (e.g. a real dns
    spoke that happens to share the prefix). Only generic agents host roles."""
    hub = _AutoApproveHub(_fresh_state(tmp_path), _make_km())
    hub.spoke_module_types["agent-1"] = "dns"        # not "agent"
    hub.active_connections["agent-1"] = _Ws()
    hub.approved_modules["agent-1"] = True
    assert hub._can_parent_auto_approve("agent-1-dns", "agent-1") is False


def test_can_parent_auto_approve_rejects_empty_parent(tmp_path):
    hub = _AutoApproveHub(_fresh_state(tmp_path), _make_km())
    assert hub._can_parent_auto_approve("agent-1-dns", "") is False


# ── sub-after-parent: connect-time auto-approve ──────────────────────────────

def test_sub_after_parent_is_auto_approved_and_tenant_bound(tmp_path):
    """Base agent already approved+connected → a sub-spoke connecting with
    parent_spoke_id is auto-approved, bound to the parent's tenant, and gets a
    provisioned session key pushed (key_manager holds a key for it)."""
    hub = _AutoApproveHub(_fresh_state(tmp_path), _make_km())
    _seed_base_agent(hub, "agent-1", "tenant-A")
    # Sub-spoke connects (in active_connections, module_type = the role's).
    hub.spoke_module_types["agent-1-dns"] = "dns"
    hub.active_connections["agent-1-dns"] = _Ws()

    asyncio.run(_connect_time_auto_approve(hub, "agent-1-dns", "agent-1"))

    assert hub.approved_modules.get("agent-1-dns") is True
    assert hub.state.get_spoke_tenant("agent-1-dns") == "tenant-A"
    # The session key was generated + would be pushed (send_to_spoke is stubbed,
    # but key_manager now holds a first-secret for the sub-spoke).
    assert hub.key_manager.keys.get("agent-1-dns") is not None
    # Lifecycle event recorded on the sub-spoke's timeline.
    assert _events_of(hub, "agent-1-dns", "parent_auto_approve")


def test_sub_after_parent_unapproved_parent_stays_pending(tmp_path):
    """Parent not yet approved → the sub-spoke stays pending (records the parent
    claim but does NOT auto-approve). It awaits admin approval or the later
    parent-approval sweep."""
    hub = _AutoApproveHub(_fresh_state(tmp_path), _make_km())
    hub.spoke_module_types["agent-1"] = "agent"
    hub.active_connections["agent-1"] = _Ws()       # connected, NOT approved
    hub.spoke_module_types["agent-1-dns"] = "dns"
    hub.active_connections["agent-1-dns"] = _Ws()

    asyncio.run(_connect_time_auto_approve(hub, "agent-1-dns", "agent-1"))

    assert hub.approved_modules.get("agent-1-dns") is None
    # Parent claim still recorded for the later sweep.
    assert hub.spoke_parent_map.get("agent-1-dns") == "agent-1"
    assert not hub.key_manager.keys.get("agent-1-dns")


def test_sub_after_parent_not_prefix_tied_stays_pending(tmp_path):
    hub = _AutoApproveHub(_fresh_state(tmp_path), _make_km())
    _seed_base_agent(hub, "agent-1", "tenant-A")
    hub.spoke_module_types["agent-2-dns"] = "dns"
    hub.active_connections["agent-2-dns"] = _Ws()

    asyncio.run(_connect_time_auto_approve(hub, "agent-2-dns", "agent-1"))

    assert hub.approved_modules.get("agent-2-dns") is None
    assert not _events_of(hub, "agent-2-dns", "parent_auto_approve")


# ── sub-before-parent: sweep on base-agent approval ──────────────────────────

def test_sub_before_parent_swept_up_when_base_approved(tmp_path):
    """A sub-spoke connects first and waits pending; when the base agent is later
    approved, _auto_approve_pending_subspokes approves the sub + binds it to the
    parent's tenant on its already-open connection."""
    hub = _AutoApproveHub(_fresh_state(tmp_path), _make_km())
    # Sub-spoke connects first (pending): connected, claimed parent, NOT approved.
    hub.spoke_module_types["agent-1-dns"] = "dns"
    hub.active_connections["agent-1-dns"] = _Ws()
    hub.spoke_parent_map["agent-1-dns"] = "agent-1"
    # Base agent connects (not yet approved).
    hub.spoke_module_types["agent-1"] = "agent"
    hub.active_connections["agent-1"] = _Ws()

    # Admin approves the base agent → sweep runs inside approve_and_bind_spoke.
    asyncio.run(hub.approve_and_bind_spoke("agent-1", "tenant-A"))

    # Base approved + the pending sub was swept up.
    assert hub.approved_modules.get("agent-1") is True
    assert hub.approved_modules.get("agent-1-dns") is True
    assert hub.state.get_spoke_tenant("agent-1-dns") == "tenant-A"
    assert hub.key_manager.keys.get("agent-1-dns") is not None
    assert _events_of(hub, "agent-1-dns", "parent_auto_approve")


def test_sweep_skips_already_approved_subspokes(tmp_path):
    """An already-approved sub-spoke is not re-approved by the sweep."""
    hub = _AutoApproveHub(_fresh_state(tmp_path), _make_km())
    hub.spoke_module_types["agent-1-dns"] = "dns"
    hub.active_connections["agent-1-dns"] = _Ws()
    hub.spoke_parent_map["agent-1-dns"] = "agent-1"
    hub.approved_modules["agent-1-dns"] = True          # already approved
    hub.state.register_module("agent-1-dns", approved=True)
    hub.spoke_module_types["agent-1"] = "agent"
    hub.active_connections["agent-1"] = _Ws()

    km_before = hub.key_manager.keys.get("agent-1-dns")
    asyncio.run(hub.approve_and_bind_spoke("agent-1", "tenant-A"))

    # No new key was generated for the already-approved sub-spoke.
    assert hub.key_manager.keys.get("agent-1-dns") is km_before


def test_sweep_skips_subspokes_claiming_a_different_parent(tmp_path):
    """A pending sub-spoke that claimed a different parent is left untouched when
    agent-1 is approved (only agent-1's own sub-spokes are swept)."""
    hub = _AutoApproveHub(_fresh_state(tmp_path), _make_km())
    hub.spoke_module_types["agent-9-dns"] = "dns"
    hub.active_connections["agent-9-dns"] = _Ws()
    hub.spoke_parent_map["agent-9-dns"] = "agent-9"     # different parent
    hub.spoke_module_types["agent-1"] = "agent"
    hub.active_connections["agent-1"] = _Ws()

    asyncio.run(hub.approve_and_bind_spoke("agent-1", "tenant-A"))

    assert hub.approved_modules.get("agent-9-dns") is None
    assert not hub.key_manager.keys.get("agent-9-dns")


def test_sweep_only_runs_for_agent_module_type(tmp_path):
    """A non-agent spoke approval (e.g. a standalone dns spoke) does NOT trigger
    the sub-spoke sweep — only generic agents (module_type 'agent') host roles."""
    hub = _AutoApproveHub(_fresh_state(tmp_path), _make_km())
    hub.spoke_module_types["agent-1-dns"] = "dns"
    hub.active_connections["agent-1-dns"] = _Ws()
    hub.spoke_parent_map["agent-1-dns"] = "dns-spoke-99"
    # The approved spoke is a real dns spoke, not an agent.
    hub.spoke_module_types["dns-spoke-99"] = "dns"
    hub.active_connections["dns-spoke-99"] = _Ws()

    asyncio.run(hub.approve_and_bind_spoke("dns-spoke-99", "tenant-A"))

    assert hub.approved_modules.get("agent-1-dns") is None