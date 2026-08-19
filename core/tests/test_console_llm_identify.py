"""Unit tests for hub-orchestrated LLM console identify (routes.console_llm_identify).

The orchestrator only depends on ``hub.request_response`` (async), so we drive it
with a scripted fake hub — no live LLM, spoke, or app needed. Covers: identify in
one round, the two-round command path, and the inconclusive/error paths.
"""
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from routes import console_llm_identify as m  # noqa: E402


class _FakeHub:
    """Scripts request_response by command. ``llm_replies`` is an ordered queue of
    assistant-content strings returned for successive HELP_ASK calls."""
    def __init__(self, capture="", llm_replies=None, collect=None, collect_with_creds=None):
        self.capture = capture
        self.llm_replies = list(llm_replies or [])
        self.collect = collect or {}
        self.collect_with_creds = collect_with_creds
        self.stored = None
        self.commands_sent = None
        self.credentials_sent = None
        self.active_connections = {"ab": object()}

    def _primary_key(self, sid):
        return sid

    async def request_response(self, target, cmd, payload, timeout=None):
        if cmd == "HELP_ASK":
            content = self.llm_replies.pop(0) if self.llm_replies else ""
            return {"payload": {"data": {"status": "SUCCESS",
                                         "assistant": {"content": content}}}}
        if cmd == "CONSOLE_GET_CAPTURE":
            return {"payload": {"data": {"status": "SUCCESS", "capture": self.capture}}}
        if cmd == "CONSOLE_LLM_COLLECT":
            self.commands_sent = payload.get("commands")
            if payload.get("credentials"):
                self.credentials_sent = payload.get("credentials")
                if self.collect_with_creds is not None:
                    return {"payload": {"data": {"status": "SUCCESS", **self.collect_with_creds}}}
            return {"payload": {"data": {"status": "SUCCESS", **self.collect}}}
        if cmd == "CONSOLE_LLM_STORE":
            self.stored = payload
            return {"payload": {"data": {"status": "SUCCESS"}}}
        raise AssertionError(f"unexpected command {cmd}")


def test_find_ab_and_gate(monkeypatch):
    hub = _FakeHub()
    assert m.find_ab(hub) == "ab"
    hub.active_connections = {"web-1": object()}
    assert m.find_ab(hub) is None
    monkeypatch.delenv("LM_CONSOLE_LLM_IDENTIFY", raising=False)
    assert m.hub_llm_identify_enabled() is False
    monkeypatch.setenv("LM_CONSOLE_LLM_IDENTIFY", "true")
    assert m.hub_llm_identify_enabled() is True


def test_orchestrate_identifies_in_one_round():
    hub = _FakeHub(
        capture="Cisco IOS Software, Version 15.2\r\nSwitch>",
        llm_replies=['{"identified": true, "vendor": "cisco-ios", "model": "C2960", "confidence": 0.95}'],
    )
    import asyncio
    res = asyncio.run(m.orchestrate(hub, "ab", "console-1", "good"))
    assert res["status"] == "OK"
    assert res["identified"] is True
    assert res["vendor"] == "cisco-ios"
    assert res["rounds"] == 1
    assert hub.commands_sent is None            # no commands needed
    assert hub.stored["vendor"] == "cisco-ios"  # persisted


def test_orchestrate_runs_commands_then_extracts():
    import asyncio
    hub = _FakeHub(
        capture="\r\nlogin: ",
        llm_replies=[
            '{"identified": false, "commands": ["show version", "reload"]}',
            '{"identified": true, "vendor": "juniper", "model": "EX4300", "serial": "JN123"}',
        ],
        collect={"logged_in": True, "outputs": {"show version": "Junos 20.4 EX4300 SN JN123"},
                 "rejected": ["reload"]},
    )
    res = asyncio.run(m.orchestrate(hub, "ab", "console-1", "good"))
    assert res["status"] == "OK"
    assert res["rounds"] == 2
    assert res["vendor"] == "juniper"
    assert res["identity"]["serial"] == "JN123"
    assert res["commands_run"] == ["show version"]
    assert res["rejected"] == ["reload"]
    assert hub.commands_sent == ["show version", "reload"]  # spoke does the filtering
    assert hub.stored["identity"]["serial"] == "JN123"


def test_orchestrate_inconclusive_when_no_commands_and_no_id():
    import asyncio
    hub = _FakeHub(capture="garbage", llm_replies=['{"identified": false}'])
    res = asyncio.run(m.orchestrate(hub, "ab", "console-1", "good"))
    assert res["status"] == "INCONCLUSIVE"
    assert res["identified"] is False
    assert hub.stored is None


def test_orchestrate_collect_error_surfaces():
    import asyncio
    hub = _FakeHub(
        capture="login: ",
        llm_replies=['{"identified": false, "commands": ["show version"]}'],
        collect={"status": "ERROR", "message": "port is in use; close sessions first"},
    )
    res = asyncio.run(m.orchestrate(hub, "ab", "console-1", "good"))
    assert res["status"] == "ERROR"
    assert "in use" in res["message"]
    assert hub.stored is None


def test_hub_setting_overrides_env(monkeypatch):
    class _H:
        class state:
            system_state = {}
    monkeypatch.setenv("LM_CONSOLE_LLM_IDENTIFY", "true")
    h = _H()
    assert m.hub_llm_identify_enabled(h) is True          # env default
    h.state.system_state["console_llm_identify_enabled"] = False
    assert m.hub_llm_identify_enabled(h) is False          # stored setting wins
    h.state.system_state["console_llm_identify_enabled"] = True
    monkeypatch.delenv("LM_CONSOLE_LLM_IDENTIFY", raising=False)
    assert m.hub_llm_identify_enabled(h) is True


def test_orchestrate_asks_llm_for_credentials_when_login_stuck():
    """When the stored + factory-default creds fail (login prompt still showing),
    the orchestrator asks the LLM for credentials and retries the collect with
    them, then extracts the identity from the post-login output."""
    import asyncio
    hub = _FakeHub(
        capture="\r\ndevice login: ",
        llm_replies=[
            '{"identified": false, "commands": ["show version"]}',       # round 1
            '{"credentials": [{"username": "admin", "password": "aruba123"}]}',  # cred ask
            '{"identified": true, "vendor": "aruba", "model": "CX6300", "serial": "AR9"}',  # extract
        ],
        collect={"logged_in": False, "outputs": {}, "rejected": [],
                 "diag": {"login_prompt_seen": True, "password_prompt_seen": True,
                          "reason": "credentials rejected"}},
        collect_with_creds={"logged_in": True,
                            "outputs": {"show version": "ArubaOS-CX CX6300 SN AR9"},
                            "rejected": []},
    )
    res = asyncio.run(m.orchestrate(hub, "ab", "console-1", "good"))
    assert hub.credentials_sent == [{"username": "admin", "password": "aruba123"}]
    assert res["llm_credentials_tried"] == 1
    assert res["logged_in"] is True
    assert res["vendor"] == "aruba"
    assert res["identity"]["serial"] == "AR9"
    assert res["status"] == "OK"


def test_scrub_for_llm_redacts_sensitive_data():
    s = m.scrub_for_llm
    out = s("Mgmt 192.168.1.20/24 gw 10.0.0.1")
    assert "192.168" not in out and out.count("[IP]") == 2
    out = s("MAC 0011.2233.4455 / aa:bb:cc:dd:ee:ff")
    assert "0011.2233" not in out and "aa:bb:cc" not in out and out.count("[MAC]") == 2
    out = s("enable secret 5 $1$abcQ$defGHIjklMNOpqrs")
    assert "$1$abcQ" not in out and "[REDACTED" in out
    out = s("username admin password Sup3rSecret!")
    assert "Sup3rSecret" not in out and "[REDACTED]" in out
    out = s("snmp-server community PrivateStr RO")
    assert "PrivateStr" not in out
    out = s("hostname CoreSwitch-01")
    assert "CoreSwitch-01" not in out and "[HOST]" in out
    out = s("CoreSwitch-01(config)#")
    assert out.strip() == "[HOST](config)#"
    out = s("fe80::1 and 2001:db8:1234:5678::1")
    assert "fe80" not in out and "2001:db8" not in out


def test_scrub_for_llm_preserves_identification_cues():
    s = m.scrub_for_llm
    # vendor/model/OS strings and timestamps must survive (that's what identifies).
    txt = "Cisco IOS Software, Version 15.2(4)E\r\nAug 15 12:34:56 uptime 1 day"
    out = s(txt)
    assert "Cisco IOS Software, Version 15.2(4)E" in out
    assert "12:34:56" in out            # a clock time is not an IPv6/MAC


def test_scrub_for_llm_strips_terminal_escapes():
    s = m.scrub_for_llm
    # ArubaOS-Switch menu CLI: VT100 escapes must be stripped so the LLM sees the
    # readable prompt/error text, not cursor-move noise.
    txt = ("\x1b[24;1H\x1b[24;14HMIA-SW-AOSS> \x1b[?25h\x1b[1;24r"
           "Invalid input: get\x1b[2K\x1b]0;name\x07")
    out = s(txt)
    assert "\x1b" not in out
    assert "[24;1H" not in out and "[?25h" not in out and "[1;24r" not in out
    assert "Invalid input: get" in out


def test_ask_llm_scrubs_before_sending(monkeypatch):
    import asyncio

    class _CapHub(_FakeHub):
        def __init__(self):
            super().__init__()
            self.sent_user = None

        async def request_response(self, target, cmd, payload, timeout=None):
            if cmd == "HELP_ASK":
                self.sent_user = payload["messages"][0]["content"]
                return {"payload": {"data": {"status": "SUCCESS", "assistant": {"content": "{}"}}}}
            return await super().request_response(target, cmd, payload, timeout)

    hub = _CapHub()
    asyncio.run(m._ask_llm(hub, "ab", "sys", "device 10.1.2.3 hostname Edge-1 password hunter2"))
    assert "10.1.2.3" not in hub.sent_user
    assert "Edge-1" not in hub.sent_user
    assert "hunter2" not in hub.sent_user


def test_finalize_drops_placeholder_identity_values():
    result = {"vendor": None, "identity": {}, "identified": False}
    m._finalize(result, {"identified": True, "vendor": "cisco-ios",
                         "hostname": "[HOST]", "serial": "FTX9"})
    assert result["vendor"] == "cisco-ios"
    assert "hostname" not in result["identity"]       # scrubbed placeholder dropped
    assert result["identity"]["serial"] == "FTX9"      # real value kept


# ── Local self-building fingerprint DB (routes.console_learn) ──────────────────
from routes import console_learn as cl  # noqa: E402


class _DiskHub(_FakeHub):
    """A FakeHub whose ``state.data_dir`` points at a real temp dir, so the
    console_learn JSON database actually persists to disk."""
    def __init__(self, data_dir, **kw):
        super().__init__(**kw)

        class _S:
            pass
        self.state = _S()
        self.state.data_dir = str(data_dir)


def test_signature_is_stable_and_scrubbed():
    # Different hostnames / IPs / serials on the same class of device collapse to
    # the same signature (scrubbed + digit-generalized).
    a = cl.signature("Edge-01(config)#\r\nmgmt 10.0.0.5")
    b = cl.signature("Core-99(config)#\r\nmgmt 172.16.4.9")
    assert a == b
    assert "10.0.0.5" not in a and "Edge-01" not in a


def test_learn_persists_to_json_file(tmp_path):
    cl._CACHE.clear()
    hub = _DiskHub(tmp_path)
    sig = cl.signature("Switch> ")
    cl.learn_commands(hub, sig, ["show version"], sample="Switch> ")
    cl.learn_identity(hub, sig, "cisco-ios", {"model": "C2960"})
    path = tmp_path / "console_fingerprints.json"
    assert path.exists()
    import json as _json
    data = _json.loads(path.read_text())
    rec = data["entries"][sig]
    assert rec["commands"] == ["show version"]
    assert rec["vendor"] == "cisco-ios"
    assert rec["identity"]["model"] == "C2960"
    assert rec["seen"] == 2
    # A fresh cache reload reads the same knowledge back off disk.
    cl._CACHE.clear()
    assert cl.lookup(hub, sig)["vendor"] == "cisco-ios"


def test_orchestrate_reuses_learned_fingerprint_without_llm(tmp_path):
    """First device teaches the DB; a second device with the same signature is
    identified by replaying the learned commands — with NO first LLM round."""
    import asyncio
    cl._CACHE.clear()
    capture = "\r\nlogin: "
    # 1) Teach: full LLM path (identify -> commands -> extract).
    hub1 = _DiskHub(
        tmp_path,
        capture=capture,
        llm_replies=[
            '{"identified": false, "commands": ["show version"]}',
            '{"identified": true, "vendor": "juniper", "model": "EX4300"}',
        ],
        collect={"logged_in": True, "outputs": {"show version": "Junos EX4300"},
                 "rejected": []},
    )
    res1 = asyncio.run(m.orchestrate(hub1, "ab", "console-1", "portA"))
    assert res1["vendor"] == "juniper"
    assert res1["rounds"] == 2

    # 2) Reuse: same signature on another port — no LLM replies queued at all.
    hub2 = _DiskHub(
        tmp_path,
        capture=capture,
        llm_replies=[],   # would blank if the LLM were consulted for identify
        collect={"logged_in": True, "outputs": {"show version": "Junos EX4300"},
                 "rejected": []},
    )
    res2 = asyncio.run(m.orchestrate(hub2, "ab", "console-2", "portB"))
    assert res2.get("learned") is True
    assert res2["rounds"] == 0                 # zero LLM identify rounds
    assert res2["vendor"] == "juniper"         # recalled from the local DB
    assert res2["identified"] is True
    assert hub2.commands_sent == ["show version"]
