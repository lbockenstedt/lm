"""routes.sim_assistant — the multi-turn Simulation Build Assistant chat.

Mirrors help_assistant.py's HELP_ASK relay contract (same envelope shape,
same ab-agent gate, same tool-calling loop shape) but tests the actual
registered FastAPI routes (the route logic lives inline in register(), not
a separately-importable function) via TestClient, mirroring
test_cppm_tenant_routing.py's pattern.
"""
import asyncio
import base64
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

import routes.sim_assistant as sim_assistant_module
from routes.sim_assistant import register


class _FakeHub:
    """``replies`` entries are either a plain string (a final content-only
    turn, no tool_calls — the common case) or a dict
    ``{"content": ..., "tool_calls": [...]}`` for scripting a tool-call turn
    in the agentic loop."""

    def __init__(self, connected=True, replies=None, fail=False):
        self.active_connections = {"ab": object()} if connected else {}
        self.replies = list(replies or [])
        self.fail = fail
        self.last_request = None
        self.all_requests = []

    def _primary_key(self, sid):
        return sid

    async def request_response(self, target, cmd, payload, timeout=None):
        self.last_request = (target, cmd, payload)
        self.all_requests.append((target, cmd, payload))
        if self.fail:
            raise RuntimeError("relay unreachable")
        assert cmd == "HELP_ASK"
        reply = self.replies.pop(0) if self.replies else "OK"
        if isinstance(reply, dict):
            assistant = {"content": reply.get("content", ""),
                        "tool_calls": reply.get("tool_calls") or []}
        else:
            assistant = {"content": reply}
        return {"payload": {"data": {"status": "SUCCESS", "assistant": assistant}}}


class _FakeGithubResp:
    def __init__(self, status_code, json_body=None):
        self.status_code = status_code
        self._json_body = json_body or {}

    def json(self):
        return self._json_body


def _b64(text):
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def _build(hub):
    app = FastAPI()
    app.state.hub = hub
    register(app, hub, SimpleNamespace())
    return TestClient(app)


def test_available_true_when_ab_connected():
    c = _build(_FakeHub(connected=True))
    r = c.get("/api/sim-assistant/available")
    assert r.status_code == 200
    assert r.json() == {"available": True}


def test_available_false_when_ab_not_connected():
    c = _build(_FakeHub(connected=False))
    r = c.get("/api/sim-assistant/available")
    assert r.json() == {"available": False}


def test_chat_returns_assistant_reply():
    hub = _FakeHub(replies=["What platform should this target — Linux, Windows, or both?"])
    c = _build(hub)
    r = c.post("/api/sim-assistant/chat", json={
        "messages": [{"role": "user", "content": "I want to build a simulation from this script"}],
    })
    assert r.status_code == 200
    assert "platform" in r.json()["answer"]


def test_chat_forwards_the_full_message_history():
    hub = _FakeHub(replies=["Got it — anything else?"])
    c = _build(hub)
    history = [
        {"role": "user", "content": "I want a new sim"},
        {"role": "assistant", "content": "What does it simulate?"},
        {"role": "user", "content": "DNS timeouts on Windows"},
    ]
    c.post("/api/sim-assistant/chat", json={"messages": history})
    sent_messages = hub.last_request[2]["messages"]
    assert [m["content"] for m in sent_messages] == [h["content"] for h in history]


def test_chat_offers_the_sim_source_reading_tools():
    """The model can look up real sim source (list_available_sims /
    read_sim_source) before answering — not the old tools:None single-shot."""
    hub = _FakeHub(replies=["ok"])
    c = _build(hub)
    c.post("/api/sim-assistant/chat", json={"messages": [{"role": "user", "content": "hi"}]})
    tools = hub.last_request[2]["tools"]
    names = {t["function"]["name"] for t in tools}
    assert names == {"list_available_sims", "read_sim_source"}


def test_chat_system_prompt_references_the_add_simulation_requirements():
    hub = _FakeHub(replies=["ok"])
    c = _build(hub)
    c.post("/api/sim-assistant/chat", json={"messages": [{"role": "user", "content": "hi"}]})
    system = hub.last_request[2]["system"]
    assert "Linux" in system and "Windows" in system
    assert "Aruba Central" in system or "alert" in system.lower()


def test_chat_requires_ab_connected():
    c = _build(_FakeHub(connected=False))
    r = c.post("/api/sim-assistant/chat", json={"messages": [{"role": "user", "content": "hi"}]})
    assert r.status_code == 409


def test_chat_requires_nonempty_messages():
    c = _build(_FakeHub())
    r = c.post("/api/sim-assistant/chat", json={"messages": []})
    assert r.status_code == 400


def test_chat_requires_messages_field():
    c = _build(_FakeHub())
    r = c.post("/api/sim-assistant/chat", json={})
    assert r.status_code == 400


def test_chat_filters_out_malformed_history_entries():
    """A stray non-user/assistant role or missing content must not crash the
    relay — just get dropped before forwarding."""
    hub = _FakeHub(replies=["ok"])
    c = _build(hub)
    r = c.post("/api/sim-assistant/chat", json={"messages": [
        {"role": "system", "content": "should be dropped"},
        {"role": "user", "content": "real question"},
        {"role": "tool", "content": "also dropped"},
        {"notarole": True},
    ]})
    assert r.status_code == 200
    sent_messages = hub.last_request[2]["messages"]
    assert sent_messages == [{"role": "user", "content": "real question"}]


def test_chat_relay_failure_returns_502():
    c = _build(_FakeHub(fail=True))
    r = c.post("/api/sim-assistant/chat", json={"messages": [{"role": "user", "content": "hi"}]})
    assert r.status_code == 502


def test_chat_empty_answer_gets_a_friendly_fallback():
    hub = _FakeHub(replies=[""])
    c = _build(hub)
    r = c.post("/api/sim-assistant/chat", json={"messages": [{"role": "user", "content": "hi"}]})
    assert r.status_code == 200
    assert r.json()["answer"]  # non-empty fallback, not a blank string


# ── scope guardrail: cs-module only ──────────────────────────────────────────
# Two layers, both must hold: (1) retrieval — off-topic docs (mTLS, Azure,
# other modules) are never even readable by this route's doc pool, so there's
# nothing to leak into context; (2) prompt — an explicit instruction to
# decline and redirect off-topic questions rather than answer from general
# training.

def test_system_prompt_declares_hard_scope_boundary():
    hub = _FakeHub(replies=["ok"])
    c = _build(hub)
    c.post("/api/sim-assistant/chat", json={"messages": [{"role": "user", "content": "hi"}]})
    system = hub.last_request[2]["system"]
    assert "decline" in system.lower() and "redirect" in system.lower()
    # Named examples of what's explicitly out of scope.
    for term in ("mTLS", "Azure"):
        assert term in system


def test_system_prompt_allows_general_engine_questions_as_on_topic():
    hub = _FakeHub(replies=["ok"])
    c = _build(hub)
    c.post("/api/sim-assistant/chat", json={"messages": [
        {"role": "user", "content": "how does the quota engine work?"}]})
    system = hub.last_request[2]["system"]
    assert "quota engine" in system.lower() or "engine" in system.lower()


def test_doc_selection_never_includes_non_cs_docs():
    """Structural guarantee: only the cs-module whitelist is ever readable —
    an unrelated doc (e.g. security-pentest, entra-sso) can score highest by
    raw keyword overlap and STILL never appear, because it was never in the
    candidate pool to begin with."""
    hub = _FakeHub(replies=["ok"])
    c = _build(hub)
    c.post("/api/sim-assistant/chat", json={"messages": [
        {"role": "user", "content": "how do I configure mTLS client certs and Azure NSG rules?"}]})
    system = hub.last_request[2]["system"]
    # The mention of "mTLS"/"Azure" above is the REFUSAL instruction text
    # itself (checked in test_system_prompt_declares_hard_scope_boundary) —
    # what matters here is that no DOC content about them was pulled in, i.e.
    # no "=== DOC:" section outside the whitelist appears.
    for forbidden_doc in ("security-pentest", "entra-sso", "cppm", "nw", "dhcp",
                          "dns", "opnsense", "ldap", "console", "netbox", "pxmx"):
        assert f"=== DOC: {forbidden_doc} ===" not in system


def test_doc_selection_picks_a_relevant_cs_doc_for_engine_questions():
    hub = _FakeHub(replies=["ok"])
    c = _build(hub)
    c.post("/api/sim-assistant/chat", json={"messages": [
        {"role": "user", "content": "how does alert generation and the quota engine work?"}]})
    system = hub.last_request[2]["system"]
    assert "=== DOC: alert-generation ===" in system


def test_doc_selection_falls_back_to_cs_doc_when_nothing_scores():
    hub = _FakeHub(replies=["ok"])
    c = _build(hub)
    c.post("/api/sim-assistant/chat", json={"messages": [
        {"role": "user", "content": "xyzzy plugh qux"}]})
    system = hub.last_request[2]["system"]
    assert "=== DOC: cs ===" in system


def test_doc_selection_uses_earlier_turns_not_just_the_latest_message():
    """A short follow-up ("yes") shouldn't lose doc relevance an earlier,
    more descriptive turn already established."""
    hub = _FakeHub(replies=["first reply", "second reply"])
    c = _build(hub)
    history = [
        {"role": "user", "content": "tell me about the dongle quarantine system"},
        {"role": "assistant", "content": "first reply"},
        {"role": "user", "content": "yes"},
    ]
    c.post("/api/sim-assistant/chat", json={"messages": history})
    system = hub.last_request[2]["system"]
    assert "=== DOC: dongle-quarantine ===" in system


# ── existing-sim source reading (read-only tool loop) ────────────────────────
# The assistant has no local checkout of the cs repo — code reads are a live,
# read-only GitHub Contents API fetch, mirrored from
# simulations/github_config_client.py's no-local-clone pattern. Two things to
# verify: the tool loop actually round-trips (assistant calls a tool, hub
# executes it, feeds the result back, model gives a final answer using it),
# and the read-only/scope boundary holds even against a hostile sim_name.

def test_tool_loop_lists_available_sims(monkeypatch):
    async def fake_get(path):
        assert path == "clients/linux"
        return _FakeGithubResp(200, [
            {"type": "file", "name": "dns_fail.sh"},
            {"type": "file", "name": "collab.sh"},
            {"type": "file", "name": "simulation.sh"},  # orchestrator, must be filtered out
            {"type": "file", "name": "common.sh"},      # shared lib, must be filtered out
            {"type": "dir", "name": "some_subdir"},      # non-file entry, ignored
        ])
    monkeypatch.setattr(sim_assistant_module, "_github_get_contents", fake_get)

    hub = _FakeHub(replies=[
        {"content": "", "tool_calls": [
            {"id": "1", "function": {"name": "list_available_sims", "arguments": "{}"}}]},
        "The existing sims are dns_fail and collab.",
    ])
    c = _build(hub)
    r = c.post("/api/sim-assistant/chat", json={"messages": [
        {"role": "user", "content": "what sims already exist?"}]})
    assert r.status_code == 200
    assert "dns_fail" in r.json()["answer"]
    # Second relay round must include the tool's result in the transcript.
    second_round_messages = hub.all_requests[1][2]["messages"]
    tool_msg = next(m for m in second_round_messages if m["role"] == "tool")
    assert "dns_fail" in tool_msg["content"] and "collab" in tool_msg["content"]
    assert "simulation" not in tool_msg["content"]  # orchestrator filtered out


def test_tool_loop_reads_sim_source_for_copying_a_variant(monkeypatch):
    """The concrete use case: 'copy dns_fail for a specific deployment'."""
    async def fake_get(path):
        if path == "clients/linux/dns_fail.sh":
            return _FakeGithubResp(200, {"content": _b64("#!/bin/bash\necho dns_fail linux")})
        if path == "clients/windows/dns_fail.ps1":
            return _FakeGithubResp(200, {"content": _b64("Write-Host 'dns_fail windows'")})
        raise AssertionError(f"unexpected path {path}")
    monkeypatch.setattr(sim_assistant_module, "_github_get_contents", fake_get)

    hub = _FakeHub(replies=[
        {"content": "", "tool_calls": [
            {"id": "1", "function": {
                "name": "read_sim_source",
                "arguments": '{"sim_name": "dns_fail", "platform": "both"}'}}]},
        "Here's a dns_fail_lrb variant based on the real dns_fail source...",
    ])
    c = _build(hub)
    r = c.post("/api/sim-assistant/chat", json={"messages": [
        {"role": "user", "content": "copy dns_fail but for the LRB deployment"}]})
    assert r.status_code == 200
    second_round_messages = hub.all_requests[1][2]["messages"]
    tool_msg = next(msg for msg in second_round_messages if msg["role"] == "tool")
    assert "dns_fail linux" in tool_msg["content"]
    assert "dns_fail windows" in tool_msg["content"]


def test_read_sim_source_rejects_a_path_traversal_sim_name(monkeypatch):
    """sim_name is regex-validated BEFORE it ever becomes a path — a hostile
    value must never reach _github_get_contents at all."""
    called = []

    async def fake_get(path):
        called.append(path)
        return _FakeGithubResp(200, {})
    monkeypatch.setattr(sim_assistant_module, "_github_get_contents", fake_get)

    result = asyncio.run(sim_assistant_module._tool_read_sim_source(
        {"sim_name": "../../etc/passwd", "platform": "linux"}))
    assert "error" in result
    assert not called  # never even attempted a fetch


def test_read_sim_source_only_ever_targets_clients_linux_or_windows(monkeypatch):
    """Even a syntactically-valid sim_name can only ever address a file
    directly under clients/linux/ or clients/windows/ — the directory
    prefix is hardcoded, not model-controlled."""
    seen_paths = []

    async def fake_get(path):
        seen_paths.append(path)
        return _FakeGithubResp(404)
    monkeypatch.setattr(sim_assistant_module, "_github_get_contents", fake_get)

    asyncio.run(sim_assistant_module._tool_read_sim_source(
        {"sim_name": "dns_fail", "platform": "both"}))
    assert seen_paths == ["clients/linux/dns_fail.sh", "clients/windows/dns_fail.ps1"]


def test_system_prompt_instructs_reading_before_copying_a_variant():
    hub = _FakeHub(replies=["ok"])
    c = _build(hub)
    c.post("/api/sim-assistant/chat", json={"messages": [
        {"role": "user", "content": "I want to copy dns_fail for a specific deployment"}]})
    system = hub.last_request[2]["system"]
    assert "read_sim_source" in system
    assert "never guess" in system.lower() or "always read it first" in system.lower()
