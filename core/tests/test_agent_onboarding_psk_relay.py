"""main.py's PSK auto-approve path for RELAYED node-agents (a Proxmox/cs
agent dialing a pxmx/cs spoke's ``/ws/agent``, NOT a hub-direct spoke — see
``test_psk_hub_proof.py`` for the hub-direct-spoke counterpart,
``_try_psk_self_provision``).

``_handle_agent_onboarding_psk`` is the entry point (an ``AGENT_ONBOARDING_PSK``
frame, relayed fire-and-forget by agent_hosting.py's ``_agent_handler`` pending
branch the instant a zero-touch agent presents an onboarding PSK + tenant
hint). ``_try_psk_agent_auto_approve`` does the actual PSK validation and, on
a match, delegates to ``routes.setup._perform_agent_approval`` with an
``explicit_tenant`` so the credential wins over any spoke-tenant inheritance.
Neither ever raises, and neither leaks PSK validity via any side channel
other than the (already-existing) eventual APPROVAL_SUCCESS relay.
"""
import asyncio
import os
import sys

_LM_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _LM_ROOT not in sys.path:
    sys.path.insert(0, _LM_ROOT)

import main  # noqa: E402
import routes.setup as setup_routes  # noqa: E402


class _StubStore:
    def __init__(self, psks_by_tenant):
        self._psks = psks_by_tenant

    async def get_psks(self, tenant):
        return self._psks.get(tenant, [])


class _StubHub:
    def __init__(self, psks_by_tenant):
        self.simulations_store = _StubStore(psks_by_tenant)
        self.events = []
        # _try_psk_agent_auto_approve calls self._psk_is_valid — bind the REAL
        # (already separately tested, see test_psk_hub_proof.py) implementation
        # rather than reimplementing PSK matching here.
        self._psk_is_valid = main.LabManagerHub._psk_is_valid.__get__(self)

    def record_spoke_event(self, spoke_id, event, detail):
        self.events.append((spoke_id, event, detail))


def _run(coro):
    return asyncio.run(coro)


# ── _try_psk_agent_auto_approve ─────────────────────────────────────────────

def test_valid_psk_delegates_to_perform_agent_approval_with_explicit_tenant(monkeypatch):
    calls = []

    async def _fake_approve(hub, spoke_id, agent_id, explicit_tenant=None):
        calls.append((spoke_id, agent_id, explicit_tenant))
        return {"ok": True}

    monkeypatch.setattr(setup_routes, "_perform_agent_approval", _fake_approve)
    hub = _StubHub({"lrb": ["correct-psk"]})
    ok = _run(main.LabManagerHub._try_psk_agent_auto_approve(
        hub, "pxmx-spoke-1", "node-agent-1", "lrb", "correct-psk"))
    assert ok is True
    assert calls == [("pxmx-spoke-1", "node-agent-1", "lrb")]
    assert hub.events and hub.events[0][1] == "agent_psk_auto_approve"


def test_invalid_psk_never_calls_perform_agent_approval(monkeypatch):
    calls = []

    async def _fake_approve(hub, spoke_id, agent_id, explicit_tenant=None):
        calls.append(1)
        return {}

    monkeypatch.setattr(setup_routes, "_perform_agent_approval", _fake_approve)
    hub = _StubHub({"lrb": ["correct-psk"]})
    ok = _run(main.LabManagerHub._try_psk_agent_auto_approve(
        hub, "pxmx-spoke-1", "node-agent-1", "lrb", "wrong-psk"))
    assert ok is False
    assert calls == []
    assert hub.events == []


def test_unknown_tenant_never_calls_perform_agent_approval(monkeypatch):
    calls = []

    async def _fake_approve(hub, spoke_id, agent_id, explicit_tenant=None):
        calls.append(1)

    monkeypatch.setattr(setup_routes, "_perform_agent_approval", _fake_approve)
    hub = _StubHub({"lrb": ["correct-psk"]})
    ok = _run(main.LabManagerHub._try_psk_agent_auto_approve(
        hub, "pxmx-spoke-1", "node-agent-1", "no-such-tenant", "correct-psk"))
    assert ok is False
    assert calls == []


def test_approval_failure_returns_false_and_never_raises(monkeypatch):
    async def _boom(hub, spoke_id, agent_id, explicit_tenant=None):
        raise RuntimeError("mailbox exploded")

    monkeypatch.setattr(setup_routes, "_perform_agent_approval", _boom)
    hub = _StubHub({"lrb": ["correct-psk"]})
    ok = _run(main.LabManagerHub._try_psk_agent_auto_approve(
        hub, "pxmx-spoke-1", "node-agent-1", "lrb", "correct-psk"))
    assert ok is False


# ── _handle_agent_onboarding_psk ────────────────────────────────────────────

def test_handle_missing_fields_is_a_noop():
    calls = []

    async def _fake_try(spoke_id, agent_id, tenant_hint, psk):
        calls.append(1)
        return True

    hub = _StubHub({})
    hub._try_psk_agent_auto_approve = _fake_try
    for data in ({}, {"agent_id": "a"}, {"agent_id": "a", "tenant_hint": "t"},
                 {"agent_id": "a", "psk": "p"}, {"tenant_hint": "t", "psk": "p"}):
        _run(main.LabManagerHub._handle_agent_onboarding_psk(hub, "spoke-1", data))
    assert calls == []


def test_handle_full_fields_delegates_to_try_auto_approve():
    calls = []

    async def _fake_try(spoke_id, agent_id, tenant_hint, psk):
        calls.append((spoke_id, agent_id, tenant_hint, psk))
        return True

    hub = _StubHub({})
    hub._try_psk_agent_auto_approve = _fake_try
    _run(main.LabManagerHub._handle_agent_onboarding_psk(
        hub, "spoke-1", {"agent_id": "a1", "tenant_hint": "lrb", "psk": "secret"}))
    assert calls == [("spoke-1", "a1", "lrb", "secret")]


def test_handle_never_raises_when_try_auto_approve_blows_up():
    async def _boom(spoke_id, agent_id, tenant_hint, psk):
        raise RuntimeError("boom")

    hub = _StubHub({})
    hub._try_psk_agent_auto_approve = _boom
    # Must not raise — this runs inline in the main WS message loop.
    _run(main.LabManagerHub._handle_agent_onboarding_psk(
        hub, "spoke-1", {"agent_id": "a1", "tenant_hint": "lrb", "psk": "secret"}))
