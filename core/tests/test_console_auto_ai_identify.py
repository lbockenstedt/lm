"""Unit tests for the hub's auto-escalation of an unidentified console port to
the LLM AI-identify path (HubVncConsoleMixin._handle_console_probe).

When the local static fingerprint comes back with no vendor and no identity, and
AI-assisted identify is enabled, the hub should call the LLM orchestrator instead
of syncing a placeholder NetBox device. A result that itself came from the LLM
(method="llm") must NOT re-trigger escalation (no recursion).
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from hub_vnc_console import HubVncConsoleMixin  # noqa: E402
from routes import console_llm_identify as llm  # noqa: E402


class _Hub(HubVncConsoleMixin):
    """Minimal hub exposing only what _handle_console_probe touches."""
    def __init__(self):
        self.synced = []
        self.orchestrated = []

    # NetBox device sync surface — records what would be synced.
    def get_spoke_by_type(self, t):
        return "netbox-1" if t == "ipam" else None

    class _State:
        def get_spoke_tenant(self, sid):
            return "acme"

        def get_tenant(self, tid):
            return {"netbox_tenant_slug": "acme", "name": "Acme"}

    state = _State()

    async def request_response(self, sid, cmd, payload, timeout=60.0):
        self.synced.append((cmd, payload))
        return {}


def _run(coro):
    import asyncio
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@pytest.fixture(autouse=True)
def _stub_llm(monkeypatch):
    monkeypatch.setattr(llm, "hub_llm_identify_enabled", lambda hub: True)
    monkeypatch.setattr(llm, "find_bugfixer", lambda hub: "bugfixer-1")

    async def _fake_orchestrate(hub, agent, sid, port_id):
        hub.orchestrated.append((agent, sid, port_id))
        return {"identified": False}

    monkeypatch.setattr(llm, "orchestrate", _fake_orchestrate)


def test_unidentified_port_escalates_to_llm_and_skips_sync():
    hub = _Hub()
    _run(hub._handle_console_probe("console-1", {
        "port_id": "usb-067b:2303@6-2.4", "vendor": None, "identity": {},
        "banner": "MIA-SW-AOSS> \r\nInvalid input: get", "method": "login",
    }))
    assert hub.orchestrated == [("bugfixer-1", "console-1", "usb-067b:2303@6-2.4")]
    assert hub.synced == []  # placeholder device NOT created


def test_llm_result_does_not_re_escalate():
    hub = _Hub()
    _run(hub._handle_console_probe("console-1", {
        "port_id": "usb-1", "vendor": None, "identity": {},
        "banner": "some banner", "method": "llm",
    }))
    assert hub.orchestrated == []  # no recursion
    # method=llm with no identity falls through to the port_id-named sync path.
    assert hub.synced and hub.synced[0][0] == "NETBOX_SYNC_DEVICES"


def test_identified_vendor_does_not_escalate():
    hub = _Hub()
    _run(hub._handle_console_probe("console-1", {
        "port_id": "usb-1", "vendor": "hp-procurve",
        "identity": {"hostname": "MIA-SW-AOSS"},
        "banner": "MIA-SW-AOSS> ", "method": "login",
    }))
    assert hub.orchestrated == []
    assert hub.synced and hub.synced[0][0] == "NETBOX_SYNC_DEVICES"


def test_no_escalation_when_ai_disabled(monkeypatch):
    monkeypatch.setattr(llm, "hub_llm_identify_enabled", lambda hub: False)
    hub = _Hub()
    _run(hub._handle_console_probe("console-1", {
        "port_id": "usb-1", "vendor": None, "identity": {},
        "banner": "unknown device", "method": "login",
    }))
    assert hub.orchestrated == []
    # disabled → falls through to existing behavior (placeholder sync).
    assert hub.synced and hub.synced[0][0] == "NETBOX_SYNC_DEVICES"


def test_product_string_used_as_name_over_port_id():
    hub = _Hub()
    _run(hub._handle_console_probe("console-1", {
        "port_id": "usb-067b:2303@6-2.4", "vendor": "hp-procurve", "identity": {},
        "banner": "MIA-SW-AOSS> ", "method": "login",
        "product": "USB Serial Controller",
    }))
    dev = hub.synced[0][1]["devices"][0]
    assert dev["hostname"] == "USB Serial Controller"  # not the cryptic port id


def test_real_hostname_beats_product_string():
    hub = _Hub()
    _run(hub._handle_console_probe("console-1", {
        "port_id": "usb-1", "vendor": "hp-procurve",
        "identity": {"hostname": "MIA-SW-AOSS"},
        "banner": "MIA-SW-AOSS> ", "method": "login",
        "product": "USB Serial Controller",
    }))
    dev = hub.synced[0][1]["devices"][0]
    assert dev["hostname"] == "MIA-SW-AOSS"  # real hostname wins
