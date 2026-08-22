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
import access  # noqa: E402


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
    monkeypatch.setattr(llm, "find_ab", lambda hub: "ab-1")

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
    assert hub.orchestrated == [("ab-1", "console-1", "usb-067b:2303@6-2.4")]
    assert hub.synced == []  # placeholder device NOT created


def test_gleaned_hostname_without_vendor_still_escalates():
    # A logged-in port we named from its prompt (hostname set) but whose vendor
    # we couldn't recognize must STILL auto-escalate to the LLM — a name alone
    # doesn't tell us the device type. Escalation keys on missing vendor, not on
    # missing identity.
    hub = _Hub()
    _run(hub._handle_console_probe("console-1", {
        "port_id": "usb-1", "vendor": None,
        "identity": {"hostname": "edge-core"},
        "banner": "edge-core> ", "method": "login",
    }))
    assert hub.orchestrated == [("ab-1", "console-1", "usb-1")]
    assert hub.synced == []


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


def test_serial_included_in_synced_payload():
    """The scraped serial rides in the NETBOX_SYNC_DEVICES device record so the
    sink can match/create by serial (the strongest key)."""
    hub = _Hub()
    _run(hub._handle_console_probe("console-1", {
        "port_id": "usb-1", "vendor": "hp-procurve",
        "identity": {"hostname": "MIA-SW-1", "serial": "SG12345678"},
        "banner": "MIA-SW-1> ", "method": "login",
    }))
    dev = hub.synced[0][1]["devices"][0]
    assert dev["serial"] == "SG12345678"
    assert hub.synced[0][1]["source"] == "Console"


def test_disabled_toggle_skips_netbox_sync():
    """With the System → Sync toggle off, an identify does NOT push to NetBox."""
    hub = _Hub()
    hub.state.system_state = {"global_config": {
        "console_netbox_device_sync": {"enabled": False}}}
    try:
        _run(hub._handle_console_probe("console-1", {
            "port_id": "usb-1", "vendor": "hp-procurve",
            "identity": {"hostname": "MIA-SW-1", "serial": "SG1"},
            "banner": "MIA-SW-1> ", "method": "login",
        }))
        assert hub.synced == []
    finally:
        # `state` is a shared class attribute — restore the default (enabled).
        hub.state.system_state = {}


def test_status_recorded_on_success():
    """A successful console sync is tracked per tenant for the UI status card."""
    hub = _Hub()
    hub.state.system_state = {}  # enabled by default
    _run(hub._handle_console_probe("console-1", {
        "port_id": "usb-1", "vendor": "hp-procurve",
        "identity": {"hostname": "MIA-SW-1"},
        "banner": "MIA-SW-1> ", "method": "login",
    }))
    rows = hub.console_netbox_sync_status()
    assert rows and rows[0]["status"] == "success"
    assert rows[0]["synced"] == 1
    assert rows[0]["last_device"] == "MIA-SW-1"


# ── Cross-tenant attribution guard (tenant-hop hardening) ────────────────────
# A console spoke's probe payload is spoke-controlled. A compromised/rogue spoke
# dedicated to tenant "acme" must NOT be able to write a device into another
# tenant's NetBox inventory by putting that tenant's id in the payload.

def test_dedicated_spoke_cannot_claim_foreign_tenant(monkeypatch):
    monkeypatch.setattr(access, "tenant_is_shared", lambda tid: False)
    hub = _Hub()
    hub.state.system_state = {}
    _run(hub._handle_console_probe("console-1", {
        "port_id": "usb-1", "vendor": "hp-procurve",
        "identity": {"hostname": "VICTIM-SW", "ip": "10.9.9.9"},
        "banner": "VICTIM-SW> ", "method": "login",
        "tenant_id": "victim-corp",   # forged claim
    }))
    # Synced, but forced back to the spoke's OWN registered tenant.
    assert hub.synced and hub.synced[0][0] == "NETBOX_SYNC_DEVICES"
    assert hub.synced[0][1]["tenant_id"] == "acme"


def test_matching_claim_is_honored(monkeypatch):
    monkeypatch.setattr(access, "tenant_is_shared", lambda tid: False)
    hub = _Hub()
    hub.state.system_state = {}
    _run(hub._handle_console_probe("console-1", {
        "port_id": "usb-1", "vendor": "hp-procurve",
        "identity": {"hostname": "ACME-SW", "ip": "10.1.1.1"},
        "banner": "ACME-SW> ", "method": "login",
        "tenant_id": "acme",   # matches the spoke's registered tenant
    }))
    assert hub.synced[0][1]["tenant_id"] == "acme"


def test_shared_spoke_claim_requires_prefix_match(monkeypatch):
    # A SHARED console spoke may attribute a device to a specific tenant, but
    # only when the device IP is contained in that tenant's prefixes.
    monkeypatch.setattr(access, "tenant_is_shared", lambda tid: tid == "acme")

    async def _fake_attr(hub, records):
        ip = (records[0].get("ip") or "")
        return ({"victim-corp": records} if ip == "10.9.9.9" else {}), 0
    monkeypatch.setattr(access, "attribute_by_prefix", _fake_attr)

    # IP owned by the claimed tenant → honored.
    hub = _Hub()
    hub.state.system_state = {}
    _run(hub._handle_console_probe("console-1", {
        "port_id": "usb-1", "vendor": "hp-procurve",
        "identity": {"hostname": "SW", "ip": "10.9.9.9"},
        "banner": "SW> ", "method": "login", "tenant_id": "victim-corp",
    }))
    assert hub.synced[0][1]["tenant_id"] == "victim-corp"

    # Same claim, IP the tenant does NOT own → refused, falls back to base.
    hub2 = _Hub()
    hub2.state.system_state = {}
    _run(hub2._handle_console_probe("console-1", {
        "port_id": "usb-1", "vendor": "hp-procurve",
        "identity": {"hostname": "SW", "ip": "10.2.2.2"},
        "banner": "SW> ", "method": "login", "tenant_id": "victim-corp",
    }))
    assert hub2.synced[0][1]["tenant_id"] == "acme"
