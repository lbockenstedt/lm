"""Hub parent-auto-approve for multi-role generic agents (H3: signed parent vouch).

A generic agent hosts N role sub-spokes (``spoke_id {base}-{role}``, each its own
WS connection). Instead of admin-approving every sub-spoke by hand, the hub
auto-approves any sub-spoke whose **parent agent vouches for it** — the hub asks
the claimed parent, over the signed ``request_response`` channel, to confirm the
sub-spoke is one it spawned (``VOUCH_SUBSPOKE``), and only a verified affirmative
vouch (status SUCCESS + ``vouched`` True + ``sub_spoke_id`` echo match) authorizes
auto-approve + tenant-bind. This replaces the old claim-based gate that trusted
the child's unsigned ``parent_spoke_id`` WS-auth field (H3: an attacker who merely
learns an approved base agent's observable spoke_id and connects as ``{base}-evil``
is NOT vouched for → stays pending admin approval, no session key, no tenant bind).

Two orderings are covered:
  * **sub-after-parent** — the sub-spoke connects once the base is already
    approved: the connect-time block in ``handle_connection`` runs the vouch and,
    on success, auto-approves it.
  * **sub-before-parent** — the sub-spoke connects first and waits pending; when
    the base agent is later approved, ``_auto_approve_pending_subspokes`` sweeps
    it up (called at the end of ``approve_and_bind_spoke`` for module_type
    ``"agent"``), running the same vouch.

On any vouch failure (parent not connected / unauthenticated / timeout / denied /
echo mismatch / not an agent / prefix mismatch) the sub-spoke falls through to
pending admin approval — the connection is NOT closed — and a
``parent_vouch_failed`` event records the reason for Setup diagnostics.

The fake hub mirrors only the attributes these production methods touch (same
pattern as ``test_install_uuid_identity``'s ``_ReconcileHub``) but forwards
``approve_and_bind_spoke`` / ``_parent_vouches`` / ``spoke_can_accept_commands`` /
``_auto_approve_pending_subspokes`` to the REAL ``LabManagerHub`` implementations,
so the approve+tenant-bind+key-push state machine + the vouch pre-flight guard are
exercised end-to-end (only the WS send + the ``request_response`` round-trip are
stubbed).
"""

import asyncio
import os
import sys
import time
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


# A request_response timeout (no payload) — the round-trip itself failed.
_TIMEOUT_REPLY = {"status": "ERROR", "message": "Timed out waiting for spoke response"}


def _vouch_reply(vouched, sub_spoke_id, status="SUCCESS"):
    """Build the wire frame a parent's VOUCH_SUBSPOKE handler returns, as the hub
    sees it from request_response (payload.data = the handler's return dict)."""
    return {"payload": {"type": "COMMAND_RESULT",
                        "data": {"status": status,
                                 "data": {"vouched": vouched, "sub_spoke_id": sub_spoke_id}}}}


class _AutoApproveHub:
    """Minimal stand-in exposing exactly what the parent-auto-approve path
    touches. Forwards the production methods to the real LabManagerHub
    implementations (bound to this fake via ``self``); stubs only the WS send
    and the ``request_response`` round-trip (configurable per sub_spoke_id)."""

    # spoke_can_accept_commands returns these reason constants (class attrs on
    # LabManagerHub) — mirror them so the forwarded real impl finds them on self.
    _CMD_NOT_CONNECTED = "not_connected"
    _CMD_UNAUTHENTICATED = "unauthenticated"

    def __init__(self, state, km):
        self.state = state
        self.key_manager = km
        self.approved_modules = {}
        self.active_connections = {}
        self.spoke_module_types = {}
        self.spoke_parent_map = {}
        self.spoke_authenticated = {}
        self.spoke_telemetry = {}
        self.known_modules = state.system_state["known_modules"]
        self.spoke_event_limit = 100
        self.spoke_events = {}
        # Configurable vouch replies keyed by sub_spoke_id. Absent → timeout.
        self._vouch_replies = {}
        self.request_response_calls = 0
        # Phase 2: forwarded real methods resolve state keys via _primary_key.
        # Alias empty -> _primary_key returns spoke_id (pre-2b2-trigger).
        self.spoke_id_alias = {}

    def _primary_key(self, spoke_id):
        return self.spoke_id_alias.get(spoke_id, spoke_id)

    def record_spoke_event(self, spoke_id, event, detail=""):
        if not spoke_id:
            return
        buf = self.spoke_events.setdefault(spoke_id, deque(maxlen=self.spoke_event_limit))
        buf.append({"ts": 0.0, "event": event, "detail": detail})

    async def send_to_spoke(self, message, signing_secret=None):
        return  # no real WS — the key-push is exercised via key_manager state

    async def push_config_to_spoke(self, spoke_id):
        return  # no-op

    async def request_response(self, spoke_id, command_type, data, timeout=5.0,
                               signing_secret=None):
        """Stubbed round-trip: return the configured vouch reply for the
        sub_spoke_id in ``data``, or a timeout (no payload) if none configured."""
        self.request_response_calls += 1
        assert command_type == "VOUCH_SUBSPOKE", command_type
        sub_id = (data or {}).get("sub_spoke_id")
        return self._vouch_replies.get(sub_id, _TIMEOUT_REPLY)

    # Forward to the real implementations (async fns return coroutines; awaiting
    # the returned coroutine runs the production code with self = this fake).
    def approve_and_bind_spoke(self, spoke_id, tenant_id):
        return main.LabManagerHub.approve_and_bind_spoke(self, spoke_id, tenant_id)

    def spoke_can_accept_commands(self, spoke_id):
        return main.LabManagerHub.spoke_can_accept_commands(self, spoke_id)

    def _parent_vouches(self, spoke_id, parent_spoke_id):
        return main.LabManagerHub._parent_vouches(self, spoke_id, parent_spoke_id)

    async def _auto_approve_pending_subspokes(self, parent_spoke_id):
        return await main.LabManagerHub._auto_approve_pending_subspokes(self, parent_spoke_id)


def _events_of(hub, sid, kind):
    return [e for e in hub.spoke_events.get(sid, []) if e["event"] == kind]


async def _connect_time_auto_approve(hub, spoke_id, parent_spoke_id):
    """Mirror of the parent-auto-approve block in handle_connection (sub-after-
    parent ordering): record the parent claim, and if the sub is pending + the
    parent vouches for it, approve+bind it to the parent's tenant + record the
    lifecycle event; otherwise record a parent_vouch_failed event (the real
    handle_connection then falls through to pending admin approval). Runs the
    REAL _parent_vouches + approve_and_bind_spoke state machine."""
    hub.spoke_parent_map[spoke_id] = parent_spoke_id
    if not hub.approved_modules.get(spoke_id, False):
        vouched, reason = await hub._parent_vouches(spoke_id, parent_spoke_id)
        if vouched:
            tenant = hub.state.get_spoke_tenant(parent_spoke_id) or ""
            await hub.approve_and_bind_spoke(spoke_id, tenant)
            hub.record_spoke_event(spoke_id, "parent_auto_approve",
                                   f"parent={parent_spoke_id}")
        else:
            hub.record_spoke_event(spoke_id, "parent_vouch_failed",
                                   f"parent={parent_spoke_id} reason={reason}")


def _seed_base_agent(hub, base_id, tenant, authenticated=True):
    """Mark a base generic agent approved + connected + tenant-bound + module_type
    'agent' (the state an admin-approved Generic Node is in when its sub-spokes
    connect). ``authenticated`` sets spoke_authenticated so the real
    spoke_can_accept_commands pre-flight passes (the parent can sign a vouch)."""
    hub.spoke_module_types[base_id] = "agent"
    hub.active_connections[base_id] = _Ws()
    hub.approved_modules[base_id] = True
    hub.state.register_module(base_id, approved=True)
    hub.state.set_spoke_tenant(base_id, tenant)
    if authenticated:
        hub.spoke_authenticated[base_id] = True


# ── _parent_vouches: the vouch gate ──────────────────────────────────────────

def test_vouch_happy_path_approves_and_binds(tmp_path):
    """Parent vouches (SUCCESS + vouched True + echo match) → sub-spoke is
    auto-approved, bound to the parent's tenant, and gets a provisioned session
    key pushed (key_manager holds a key for it)."""
    hub = _AutoApproveHub(_fresh_state(tmp_path), _make_km())
    _seed_base_agent(hub, "agent-1", "tenant-A")
    hub.spoke_module_types["agent-1-dns"] = "dns"
    hub.active_connections["agent-1-dns"] = _Ws()
    hub._vouch_replies["agent-1-dns"] = _vouch_reply(True, "agent-1-dns")

    asyncio.run(_connect_time_auto_approve(hub, "agent-1-dns", "agent-1"))

    assert hub.approved_modules.get("agent-1-dns") is True
    assert hub.state.get_spoke_tenant("agent-1-dns") == "tenant-A"
    assert hub.key_manager.keys.get("agent-1-dns") is not None
    assert _events_of(hub, "agent-1-dns", "parent_auto_approve")
    assert hub.request_response_calls == 1


def test_vouch_false_stays_pending(tmp_path):
    """Parent replies vouched=False (it doesn't track this sub-spoke) → NOT
    approved; falls to pending with a parent_vouch_failed event. No session key."""
    hub = _AutoApproveHub(_fresh_state(tmp_path), _make_km())
    _seed_base_agent(hub, "agent-1", "tenant-A")
    hub.spoke_module_types["agent-1-dns"] = "dns"
    hub.active_connections["agent-1-dns"] = _Ws()
    hub._vouch_replies["agent-1-dns"] = _vouch_reply(False, "agent-1-dns")

    asyncio.run(_connect_time_auto_approve(hub, "agent-1-dns", "agent-1"))

    assert hub.approved_modules.get("agent-1-dns") is None
    assert not hub.key_manager.keys.get("agent-1-dns")
    assert _events_of(hub, "agent-1-dns", "parent_vouch_failed")
    assert not _events_of(hub, "agent-1-dns", "parent_auto_approve")


def test_vouch_timeout_stays_pending(tmp_path):
    """request_response times out (no payload) → pending, parent_vouch_failed
    with reason=timeout. (Also the case for an older agent that never implemented
    VOUCH_SUBSPOKE and never replied.)"""
    hub = _AutoApproveHub(_fresh_state(tmp_path), _make_km())
    _seed_base_agent(hub, "agent-1", "tenant-A")
    hub.spoke_module_types["agent-1-dns"] = "dns"
    hub.active_connections["agent-1-dns"] = _Ws()
    # No _vouch_replies entry → timeout.

    asyncio.run(_connect_time_auto_approve(hub, "agent-1-dns", "agent-1"))

    assert hub.approved_modules.get("agent-1-dns") is None
    fails = _events_of(hub, "agent-1-dns", "parent_vouch_failed")
    assert fails and "reason=timeout" in fails[0]["detail"]


def test_vouch_error_reply_stays_pending(tmp_path):
    """Parent replies ERROR (ran a handler but refused, or an older agent's
    fallback) → pending, parent_vouch_failed with reason=denied (payload present
    distinguishes it from a timeout)."""
    hub = _AutoApproveHub(_fresh_state(tmp_path), _make_km())
    _seed_base_agent(hub, "agent-1", "tenant-A")
    hub.spoke_module_types["agent-1-dns"] = "dns"
    hub.active_connections["agent-1-dns"] = _Ws()
    hub._vouch_replies["agent-1-dns"] = _vouch_reply(False, "agent-1-dns", status="ERROR")

    asyncio.run(_connect_time_auto_approve(hub, "agent-1-dns", "agent-1"))

    assert hub.approved_modules.get("agent-1-dns") is None
    fails = _events_of(hub, "agent-1-dns", "parent_vouch_failed")
    assert fails and "reason=denied" in fails[0]["detail"]


def test_vouch_echo_mismatch_stays_pending(tmp_path):
    """A vouch "yes" for a DIFFERENT sub_spoke_id must not authorize this child
    (the echo match prevents a generic/replayed yes). → pending, reason=mismatch."""
    hub = _AutoApproveHub(_fresh_state(tmp_path), _make_km())
    _seed_base_agent(hub, "agent-1", "tenant-A")
    hub.spoke_module_types["agent-1-dns"] = "dns"
    hub.active_connections["agent-1-dns"] = _Ws()
    hub._vouch_replies["agent-1-dns"] = _vouch_reply(True, "agent-1-EVIL")

    asyncio.run(_connect_time_auto_approve(hub, "agent-1-dns", "agent-1"))

    assert hub.approved_modules.get("agent-1-dns") is None
    fails = _events_of(hub, "agent-1-dns", "parent_vouch_failed")
    assert fails and "reason=mismatch" in fails[0]["detail"]


def test_vouch_unauthenticated_parent_no_round_trip(tmp_path):
    """Parent connected but never authenticated (structurally can't sign) →
    pending, reason=unauthenticated, and NO request_response round-trip is
    attempted (the pre-flight guard short-circuits, no 3s hang)."""
    hub = _AutoApproveHub(_fresh_state(tmp_path), _make_km())
    # Connected + approved + agent, but NOT authenticated, and past the grace
    # window so spoke_can_accept_commands returns (False, "unauthenticated").
    hub.spoke_module_types["agent-1"] = "agent"
    hub.active_connections["agent-1"] = _Ws()
    hub.approved_modules["agent-1"] = True
    hub.state.register_module("agent-1", approved=True)
    hub.spoke_telemetry["agent-1"] = {"last_attempt": time.time() - 100}
    hub.spoke_module_types["agent-1-dns"] = "dns"
    hub.active_connections["agent-1-dns"] = _Ws()
    hub._vouch_replies["agent-1-dns"] = _vouch_reply(True, "agent-1-dns")

    asyncio.run(_connect_time_auto_approve(hub, "agent-1-dns", "agent-1"))

    assert hub.approved_modules.get("agent-1-dns") is None
    assert hub.request_response_calls == 0  # short-circuited, no round-trip
    fails = _events_of(hub, "agent-1-dns", "parent_vouch_failed")
    assert fails and "reason=unauthenticated" in fails[0]["detail"]


def test_vouch_disconnected_parent_no_round_trip(tmp_path):
    """Parent not connected → pending, reason=not_connected, no round-trip."""
    hub = _AutoApproveHub(_fresh_state(tmp_path), _make_km())
    hub.spoke_module_types["agent-1"] = "agent"
    hub.approved_modules["agent-1"] = True
    hub.state.register_module("agent-1", approved=True)
    hub.spoke_authenticated["agent-1"] = True
    # NOTE: agent-1 NOT in active_connections.
    hub.spoke_module_types["agent-1-dns"] = "dns"
    hub.active_connections["agent-1-dns"] = _Ws()
    hub._vouch_replies["agent-1-dns"] = _vouch_reply(True, "agent-1-dns")

    asyncio.run(_connect_time_auto_approve(hub, "agent-1-dns", "agent-1"))

    assert hub.approved_modules.get("agent-1-dns") is None
    assert hub.request_response_calls == 0
    fails = _events_of(hub, "agent-1-dns", "parent_vouch_failed")
    assert fails and "reason=not_connected" in fails[0]["detail"]


def test_vouch_non_agent_parent_no_round_trip(tmp_path):
    """A sub-spoke claiming a non-agent parent (e.g. a real dns spoke sharing
    the prefix) → pending, reason=not_agent, no round-trip (only agents implement
    VOUCH_SUBSPOKE)."""
    hub = _AutoApproveHub(_fresh_state(tmp_path), _make_km())
    hub.spoke_module_types["agent-1"] = "dns"  # not "agent"
    hub.active_connections["agent-1"] = _Ws()
    hub.approved_modules["agent-1"] = True
    hub.state.register_module("agent-1", approved=True)
    hub.spoke_authenticated["agent-1"] = True
    hub.spoke_module_types["agent-1-dns"] = "dns"
    hub.active_connections["agent-1-dns"] = _Ws()
    hub._vouch_replies["agent-1-dns"] = _vouch_reply(True, "agent-1-dns")

    asyncio.run(_connect_time_auto_approve(hub, "agent-1-dns", "agent-1"))

    assert hub.approved_modules.get("agent-1-dns") is None
    assert hub.request_response_calls == 0
    fails = _events_of(hub, "agent-1-dns", "parent_vouch_failed")
    assert fails and "reason=not_agent" in fails[0]["detail"]


def test_vouch_prefix_mismatch_no_round_trip(tmp_path):
    """An unrelated spoke can't claim a parent it isn't id-tied to → pending,
    reason=prefix_mismatch, no round-trip."""
    hub = _AutoApproveHub(_fresh_state(tmp_path), _make_km())
    _seed_base_agent(hub, "agent-1", "tenant-A")
    hub.spoke_module_types["agent-2-dns"] = "dns"
    hub.active_connections["agent-2-dns"] = _Ws()
    hub._vouch_replies["agent-2-dns"] = _vouch_reply(True, "agent-2-dns")

    asyncio.run(_connect_time_auto_approve(hub, "agent-2-dns", "agent-1"))

    assert hub.approved_modules.get("agent-2-dns") is None
    assert hub.request_response_calls == 0
    fails = _events_of(hub, "agent-2-dns", "parent_vouch_failed")
    assert fails and "reason=prefix_mismatch" in fails[0]["detail"]


def test_vouch_empty_parent_no_round_trip(tmp_path):
    hub = _AutoApproveHub(_fresh_state(tmp_path), _make_km())
    hub.spoke_module_types["agent-1-dns"] = "dns"
    hub.active_connections["agent-1-dns"] = _Ws()

    asyncio.run(_connect_time_auto_approve(hub, "agent-1-dns", ""))

    assert hub.approved_modules.get("agent-1-dns") is None
    assert hub.request_response_calls == 0


# ── sub-before-parent: sweep on base-agent approval ──────────────────────────

def test_sub_before_parent_swept_up_when_base_approved(tmp_path):
    """A sub-spoke connects first and waits pending; when the base agent is later
    approved, _auto_approve_pending_subspokes runs the vouch and — on a yes —
    approves the sub + binds it to the parent's tenant on its already-open
    connection."""
    hub = _AutoApproveHub(_fresh_state(tmp_path), _make_km())
    hub.spoke_module_types["agent-1-dns"] = "dns"
    hub.active_connections["agent-1-dns"] = _Ws()
    hub.spoke_parent_map["agent-1-dns"] = "agent-1"
    hub.spoke_module_types["agent-1"] = "agent"
    hub.active_connections["agent-1"] = _Ws()
    hub.spoke_authenticated["agent-1"] = True
    hub._vouch_replies["agent-1-dns"] = _vouch_reply(True, "agent-1-dns")

    # Admin approves the base agent → sweep runs inside approve_and_bind_spoke.
    asyncio.run(hub.approve_and_bind_spoke("agent-1", "tenant-A"))

    assert hub.approved_modules.get("agent-1") is True
    assert hub.approved_modules.get("agent-1-dns") is True
    assert hub.state.get_spoke_tenant("agent-1-dns") == "tenant-A"
    assert hub.key_manager.keys.get("agent-1-dns") is not None
    assert _events_of(hub, "agent-1-dns", "parent_auto_approve")


def test_sweep_vouch_false_leaves_subspoke_pending(tmp_path):
    """The sweep's vouch can fail too: a pending sub-spoke the parent doesn't
    vouch for is left pending with a parent_vouch_failed event (not approved)."""
    hub = _AutoApproveHub(_fresh_state(tmp_path), _make_km())
    hub.spoke_module_types["agent-1-dns"] = "dns"
    hub.active_connections["agent-1-dns"] = _Ws()
    hub.spoke_parent_map["agent-1-dns"] = "agent-1"
    hub.spoke_module_types["agent-1"] = "agent"
    hub.active_connections["agent-1"] = _Ws()
    hub.spoke_authenticated["agent-1"] = True
    hub._vouch_replies["agent-1-dns"] = _vouch_reply(False, "agent-1-dns")

    asyncio.run(hub.approve_and_bind_spoke("agent-1", "tenant-A"))

    assert hub.approved_modules.get("agent-1") is True
    assert hub.approved_modules.get("agent-1-dns") is None
    assert not hub.key_manager.keys.get("agent-1-dns")
    assert _events_of(hub, "agent-1-dns", "parent_vouch_failed")
    assert not _events_of(hub, "agent-1-dns", "parent_auto_approve")


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
    hub.spoke_authenticated["agent-1"] = True
    hub._vouch_replies["agent-1-dns"] = _vouch_reply(True, "agent-1-dns")

    km_before = hub.key_manager.keys.get("agent-1-dns")
    asyncio.run(hub.approve_and_bind_spoke("agent-1", "tenant-A"))

    # No new key was generated for the already-approved sub-spoke; no vouch
    # round-trip was made for it (the sweep skips approved subs).
    assert hub.key_manager.keys.get("agent-1-dns") is km_before
    assert hub.request_response_calls == 0


def test_sweep_skips_subspokes_claiming_a_different_parent(tmp_path):
    """A pending sub-spoke that claimed a different parent is left untouched when
    agent-1 is approved (only agent-1's own sub-spokes are swept)."""
    hub = _AutoApproveHub(_fresh_state(tmp_path), _make_km())
    hub.spoke_module_types["agent-9-dns"] = "dns"
    hub.active_connections["agent-9-dns"] = _Ws()
    hub.spoke_parent_map["agent-9-dns"] = "agent-9"     # different parent
    hub.spoke_module_types["agent-1"] = "agent"
    hub.active_connections["agent-1"] = _Ws()
    hub.spoke_authenticated["agent-1"] = True
    hub._vouch_replies["agent-9-dns"] = _vouch_reply(True, "agent-9-dns")

    asyncio.run(hub.approve_and_bind_spoke("agent-1", "tenant-A"))

    assert hub.approved_modules.get("agent-9-dns") is None
    assert not hub.key_manager.keys.get("agent-9-dns")
    # Not agent-1's sub-spoke → no vouch round-trip for it.
    assert hub.request_response_calls == 0


def test_sweep_only_runs_for_agent_module_type(tmp_path):
    """A non-agent spoke approval (e.g. a standalone dns spoke) does NOT trigger
    the sub-spoke sweep — only generic agents (module_type 'agent') host roles."""
    hub = _AutoApproveHub(_fresh_state(tmp_path), _make_km())
    hub.spoke_module_types["agent-1-dns"] = "dns"
    hub.active_connections["agent-1-dns"] = _Ws()
    hub.spoke_parent_map["agent-1-dns"] = "dns-spoke-99"
    hub.spoke_module_types["dns-spoke-99"] = "dns"
    hub.active_connections["dns-spoke-99"] = _Ws()
    hub.spoke_authenticated["dns-spoke-99"] = True
    hub._vouch_replies["agent-1-dns"] = _vouch_reply(True, "agent-1-dns")

    asyncio.run(hub.approve_and_bind_spoke("dns-spoke-99", "tenant-A"))

    assert hub.approved_modules.get("agent-1-dns") is None
    assert hub.request_response_calls == 0