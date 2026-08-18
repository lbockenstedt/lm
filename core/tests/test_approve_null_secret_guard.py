"""Regression: ``approve_pending_agent`` must never hand a node-agent a falsy
(``None``/``""``) secret.

The bug (observed on cs-svr-06 loading the simulation role on a unified agent):
a pxmx/unified node-agent connects zero-touch to the role's ``/ws/agent``
listener and sits in ``pending_agents``. When the admin clicks Approve, the hub
relays ``APPROVAL_SUCCESS`` down to the role sub-spoke, which calls
``approve_pending_agent``. If the sub-spoke never provisioned an
``agent_secret`` (a generic/unified agent-hosting role has no install-written
``/etc/lm-agent/config.json``), the old code sent ``{"status":"APPROVED",
"secret": None}``. The node-agent only PERSISTS a *truthy* provisioned secret
(pxmx agent ``_save_secret``), so it reconnected zero-touch → straight back to
``APPROVAL_REQUIRED`` — the "approve, then it shows offline again" flap.

The guard: if ``agent_secret`` is falsy at approval time, self-heal via the
role's ``_ensure_agent_secret`` hook (RoleConnection); if there is STILL no
secret, refuse (log + return) rather than ship a null secret that can only loop.
A truthy secret keeps the original behavior untouched.
"""
import asyncio
import json
import os
import sys

_LM_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _LM_ROOT not in sys.path:
    sys.path.insert(0, _LM_ROOT)

from core.src.messaging.agent_hosting import AgentHostingControlPlane  # noqa: E402
from core.src.security.signer import MessageSigner                     # noqa: E402


class _Host(AgentHostingControlPlane):
    """Minimal harness — bypass BaseControlPlane.__init__, set only what
    ``approve_pending_agent`` touches."""

    def __init__(self, secret, ensure=None):
        self.agent_secret = secret
        self.agent_signer = MessageSigner(secret or "")
        self.connected_agents = {}
        self.pending_agents = {}
        if ensure is not None:
            # Emulate RoleConnection._ensure_agent_secret (provision + re-arm).
            self._ensure_agent_secret = ensure  # type: ignore[assignment]


class _FakePendingWS:
    def __init__(self):
        self.sent = []

    async def send(self, payload):
        self.sent.append(payload)


class _FakeEvent:
    """Loop-independent stand-in — production only calls ``.set()`` on approval
    (avoids asyncio.Event's Py3.9 event-loop binding at construction time)."""

    def __init__(self):
        self._set = False

    def set(self):
        self._set = True

    def is_set(self):
        return self._set


def _pending(host, agent_id="node-a"):
    ws = _FakePendingWS()
    ev = _FakeEvent()
    host.pending_agents[agent_id] = {"ws": ws, "event": ev}
    return ws, ev


def test_refuses_to_send_null_secret():
    """No secret and no provisioning hook → NOTHING is sent, the agent stays
    pending (not popped), and the event is NOT set — so no null-secret flap."""
    host = _Host(secret="")
    ws, ev = _pending(host)
    asyncio.run(host.approve_pending_agent("node-a"))
    assert ws.sent == [], "must not send an APPROVED frame with a null secret"
    assert ev.is_set() is False
    assert "node-a" in host.pending_agents, "agent must remain pending, not consumed"


def test_self_heals_via_ensure_hook_then_approves():
    """A falsy secret WITH an ``_ensure_agent_secret`` hook self-provisions, then
    APPROVED is sent carrying the freshly-provisioned (truthy) secret."""
    provisioned = {"n": 0}

    def _ensure():
        provisioned["n"] += 1
        host.agent_secret = "healed-secret-xyz"
        host.agent_signer = MessageSigner(host.agent_secret)

    host = _Host(secret="", ensure=_ensure)
    ws, ev = _pending(host)
    asyncio.run(host.approve_pending_agent("node-a"))
    assert provisioned["n"] == 1, "the provisioning hook must be invoked once"
    assert len(ws.sent) == 1
    msg = json.loads(ws.sent[0])
    assert msg["status"] == "APPROVED"
    assert msg["secret"] == "healed-secret-xyz"
    assert ev.is_set() is True


def test_truthy_secret_unchanged():
    """The happy path is untouched: a configured secret is delivered as-is."""
    host = _Host(secret="already-provisioned-123")
    ws, ev = _pending(host)
    asyncio.run(host.approve_pending_agent("node-a"))
    assert len(ws.sent) == 1
    msg = json.loads(ws.sent[0])
    assert msg["status"] == "APPROVED"
    assert msg["secret"] == "already-provisioned-123"
    assert ev.is_set() is True


def test_ensure_hook_failure_still_refuses():
    """If the provisioning hook raises and leaves no secret, still refuse (no
    null APPROVED) rather than propagate — approval is best-effort self-heal."""
    def _boom():
        raise RuntimeError("disk full")

    host = _Host(secret="", ensure=_boom)
    ws, ev = _pending(host)
    asyncio.run(host.approve_pending_agent("node-a"))
    assert ws.sent == []
    assert ev.is_set() is False
    assert "node-a" in host.pending_agents
