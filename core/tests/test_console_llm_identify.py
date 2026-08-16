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
    def __init__(self, capture="", llm_replies=None, collect=None):
        self.capture = capture
        self.llm_replies = list(llm_replies or [])
        self.collect = collect or {}
        self.stored = None
        self.commands_sent = None
        self.active_connections = {"bugfixer": object()}

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
            return {"payload": {"data": {"status": "SUCCESS", **self.collect}}}
        if cmd == "CONSOLE_LLM_STORE":
            self.stored = payload
            return {"payload": {"data": {"status": "SUCCESS"}}}
        raise AssertionError(f"unexpected command {cmd}")


def test_find_bugfixer_and_gate(monkeypatch):
    hub = _FakeHub()
    assert m.find_bugfixer(hub) == "bugfixer"
    hub.active_connections = {"web-1": object()}
    assert m.find_bugfixer(hub) is None
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
    res = asyncio.run(m.orchestrate(hub, "bugfixer", "console-1", "good"))
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
    res = asyncio.run(m.orchestrate(hub, "bugfixer", "console-1", "good"))
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
    res = asyncio.run(m.orchestrate(hub, "bugfixer", "console-1", "good"))
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
    res = asyncio.run(m.orchestrate(hub, "bugfixer", "console-1", "good"))
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
