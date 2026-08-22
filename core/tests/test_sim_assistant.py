"""routes.sim_assistant — the multi-turn Simulation Build Assistant chat.

Mirrors help_assistant.py's HELP_ASK relay contract (same envelope shape,
same ab-agent gate) but tests the actual registered FastAPI routes (the
route logic lives inline in register(), not a separately-importable
function) via TestClient, mirroring test_cppm_tenant_routing.py's pattern.
"""
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

from routes.sim_assistant import register


class _FakeHub:
    def __init__(self, connected=True, replies=None, fail=False):
        self.active_connections = {"ab": object()} if connected else {}
        self.replies = list(replies or [])
        self.fail = fail
        self.last_request = None

    def _primary_key(self, sid):
        return sid

    async def request_response(self, target, cmd, payload, timeout=None):
        self.last_request = (target, cmd, payload)
        if self.fail:
            raise RuntimeError("relay unreachable")
        assert cmd == "HELP_ASK"
        content = self.replies.pop(0) if self.replies else "OK"
        return {"payload": {"data": {"status": "SUCCESS",
                                     "assistant": {"content": content}}}}


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


def test_chat_disables_tools():
    """V1 is chat-only, no tool-calling loop — HELP_ASK must be called with
    tools=None (a proven-working mode per help_assistant.py's own fallback)."""
    hub = _FakeHub(replies=["ok"])
    c = _build(hub)
    c.post("/api/sim-assistant/chat", json={"messages": [{"role": "user", "content": "hi"}]})
    assert hub.last_request[2]["tools"] is None


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
