"""Tests for auto-picking/building Zabbix templates for new device types."""
import asyncio
import os
import sys
import types

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import monitor_templates as mt  # noqa: E402
import nw_seen_hosts as seen  # noqa: E402

PDU = "Acme Rack PDU AP8841 v6.1.1 at 10.1.2.3 00:11:22:33:44:55"


def test_signature_ignores_addresses_and_versions():
    assert mt.signature(PDU) == mt.signature("Acme Rack PDU AP8841 v7.0.0 at 10.9.9.9")
    assert "10.1.2.3" not in mt.scrub(PDU) and "00:11" not in mt.scrub(PDU)


def test_monitor_rows_carry_sysdescr_only_for_unclassified_hosts():
    reg = {"t": {"10.0.0.5": {"hostname": "PDU1", "snmp_ok": True, "snmp_credential_id": "c",
                              "last_seen": 100, "profile": {"sys_descr": PDU}},
                 "10.0.0.6": {"hostname": "NAS", "snmp_ok": True, "snmp_credential_id": "c",
                              "last_seen": 100, "profile": {"sys_descr": "TrueNAS SCALE"}},
                 "10.0.0.7": {"hostname": "SW", "snmp_ok": True, "snmp_credential_id": "c",
                              "last_seen": 100, "object_type": "cx_switch",
                              "profile": {"sys_descr": "ArubaOS-CX"}}}}
    rows = {r["name"]: r for r in seen.monitor_rows(reg, 100, set(), set())}
    assert "10.1.2.3" not in rows["PDU1"]["sys_descr"] and rows["PDU1"]["sys_descr"]
    assert "sys_descr" not in rows["NAS"] and "sys_descr" not in rows["SW"]


def test_parse_reply_tolerates_wrapping_and_garbage():
    assert mt.parse_reply('ok ```{"action":"use","template":"X"}```')["template"] == "X"
    assert mt.parse_reply("nonsense")["action"] == "none"
    assert mt.parse_reply('{"action":"drop"}')["action"] == "none"


class Hub:
    """Counting fake hub: one monitoring spoke and one AB agent."""

    def __init__(self, templates, reply, install=None):
        self.state = types.SimpleNamespace(system_state={"global_config": {}}, _mark_dirty=lambda: None)
        self.calls, self.templates, self.reply = [], templates, reply
        self.install = install or {"status": "SUCCESS", "installed": True, "template": "Acme PDU by SNMP"}

    def get_spoke_by_type(self, kind):
        return "zbx"

    async def request_response(self, target, cmd, data, timeout=0):
        self.calls.append(cmd)
        if cmd == "MON_TEMPLATE_FIND":
            return {"status": "SUCCESS", "templates": self.templates, "zabbix_version": "7.0.1"}
        if cmd == "MON_TEMPLATE_INSTALL":
            return self.install
        return {"status": "SUCCESS", "assistant": {"content": self.reply}}


def run_resolve(hub, monkeypatch):
    import routes.console_llm_identify as cli
    monkeypatch.setattr(cli, "find_ab", lambda h: "ab")
    return asyncio.run(mt.resolve(hub, {mt.signature(PDU): PDU}))


def test_existing_template_is_used_and_cached_without_repeat_calls(monkeypatch):
    hub = Hub(["Acme PDU by SNMP"], '{"action":"use","template":"Acme PDU by SNMP"}')
    assert run_resolve(hub, monkeypatch) == 1
    assert mt.chosen(hub.state.system_state["global_config"], mt.signature(PDU)) == "Acme PDU by SNMP"
    n = len(hub.calls)
    assert run_resolve(hub, monkeypatch) == 0 and len(hub.calls) == n
    assert "MON_TEMPLATE_INSTALL" not in hub.calls


def test_missing_template_is_generated_and_installed(monkeypatch):
    hub = Hub([], '{"action":"create","template_yaml":"zabbix_export: {}"}')
    assert run_resolve(hub, monkeypatch) == 1
    assert "MON_TEMPLATE_INSTALL" in hub.calls


def test_invented_name_and_failed_install_are_cached_as_failures(monkeypatch):
    hub = Hub(["Real"], '{"action":"use","template":"Made Up"}')
    assert run_resolve(hub, monkeypatch) == 0
    gc = hub.state.system_state["global_config"]
    sig = mt.signature(PDU)
    assert not mt.chosen(gc, sig) and not mt.needs_decision(gc, sig, __import__("time").time())
    assert mt.needs_decision(gc, sig, __import__("time").time() + mt.RETRY_S + 1)


def test_switch_off_asks_nothing(monkeypatch):
    hub = Hub([], "{}")
    hub.state.system_state["global_config"]["monitor_templates_config"] = {"enabled": False}
    assert run_resolve(hub, monkeypatch) == 0 and hub.calls == []
