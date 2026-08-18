"""Bulk 'AI Identify All' trigger (``POST /api/console/identify-llm-all``).

Enumerates the visible console ports (tenant-scoped, same as the list view),
skips ports currently open in a session, and fires LLM identify for the rest in
the background — returning immediately with the queued/skipped counts.
"""
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from routes import console as console_routes  # noqa: E402
from routes import console_llm_identify as llm  # noqa: E402


class _State:
    system_state = {}

    def get_spoke_tenant(self, sid):
        return "10"

    def get_module_name(self, sid):
        return "agent-1"


class _Hub:
    def __init__(self, ports):
        self._ports = ports
        self.state = _State()

    def get_all_spokes_by_type(self, kind):
        return ["c1"] if kind == "console" else []

    async def request_response(self, sid, cmd, payload, timeout=15.0):
        if cmd == "CONSOLE_LIST_PORTS":
            return {"ports": self._ports}
        return {}


def _build(monkeypatch, ports, *, enabled=True, agent="bf-1", is_admin=True, has_write=True, has_access=True):
    # Deterministic tenant model: dedicated (not shared), admin sees all.
    monkeypatch.setattr(console_routes.access, "filter_enabled", lambda hub, m: False)
    monkeypatch.setattr(console_routes.access, "tenant_is_shared", lambda t: False)
    monkeypatch.setattr(console_routes.access, "spoke_visible_to_session", lambda s, t: True)
    monkeypatch.setattr(llm, "hub_llm_identify_enabled", lambda hub: enabled)
    monkeypatch.setattr(llm, "find_bugfixer", lambda hub: agent)

    orchestrated = []

    async def _fake_orchestrate(hub, ag, sid, pid):
        orchestrated.append((ag, sid, pid))
        return {"identified": False}

    monkeypatch.setattr(llm, "orchestrate", _fake_orchestrate)

    app = FastAPI()
    app.state.hub = _Hub(ports)
    ctx = SimpleNamespace(
        _session_user=lambda req: {"user": {"is_admin": is_admin}},
        _is_admin=lambda s: is_admin,
        _has_console_write_access=lambda s: has_write,
        _has_console_access=lambda s: has_access,
        _resolve_tenant=lambda req, explicit=None: "default",
    )
    console_routes.register(app, app.state.hub, ctx)
    return TestClient(app), orchestrated


def test_identify_all_queues_idle_skips_in_use(monkeypatch):
    ports = [
        {"port_id": "p1", "in_use": False},
        {"port_id": "p2", "in_use": True},   # open in a session → skipped
        {"port_id": "p3", "in_use": False},
    ]
    c, _ = _build(monkeypatch, ports)
    r = c.post("/api/console/identify-llm-all?tenant=default", json={})
    assert r.status_code == 200
    body = r.json()
    assert body["queued"] == 2
    assert body["skipped_in_use"] == 1


def test_identify_all_runs_without_global_toggle(monkeypatch):
    # Profiling is now an explicit, on-demand action — clicking the button is the
    # opt-in, so there is no separate global enable gate to trip a 409.
    c, _ = _build(monkeypatch, [{"port_id": "p1", "in_use": False}], enabled=False)
    r = c.post("/api/console/identify-llm-all?tenant=default", json={})
    assert r.status_code == 200
    assert r.json()["queued"] == 1


def test_identify_all_queues_even_without_agent(monkeypatch):
    # Fingerprint-first: known devices resolve without the AI, so a missing
    # BugFixer agent no longer blocks the bulk profile — it still queues.
    c, _ = _build(monkeypatch, [{"port_id": "p1", "in_use": False}], agent=None)
    r = c.post("/api/console/identify-llm-all?tenant=default", json={})
    assert r.status_code == 200
    assert r.json()["queued"] == 1


def test_identify_all_no_idle_ports(monkeypatch):
    c, _ = _build(monkeypatch, [{"port_id": "p1", "in_use": True}])
    r = c.post("/api/console/identify-llm-all?tenant=default", json={})
    assert r.status_code == 200
    body = r.json()
    assert body["queued"] == 0 and body["skipped_in_use"] == 1


def test_identify_all_allowed_for_tenant_admin(monkeypatch):
    # A tenant admin is NOT a Global Admin but HAS console access. Profiling
    # their own tenant's visible ports must be allowed — the target list is
    # already tenant-scoped.
    c, _ = _build(monkeypatch, [{"port_id": "p1", "in_use": False}],
                  is_admin=False, has_write=True, has_access=True)
    r = c.post("/api/console/identify-llm-all?tenant=default", json={})
    assert r.status_code == 200
    assert r.json()["queued"] == 1


def test_identify_all_allowed_for_read_only_console_user(monkeypatch):
    # Profiling is read-only device identification, so a plain (view-only)
    # console user — no Global Admin, no write tier, but WITH the `console`
    # right — may trigger it on the ports they can already see. The target
    # list (_list_visible_console_ports) is tenant-scoped, so they only reach
    # their own visible ports.
    c, _ = _build(monkeypatch, [{"port_id": "p1", "in_use": False}],
                  is_admin=False, has_write=False, has_access=True)
    r = c.post("/api/console/identify-llm-all?tenant=default", json={})
    assert r.status_code == 200
    assert r.json()["queued"] == 1


def test_identify_all_denied_without_console_access(monkeypatch):
    # A user with NO console access at all (not admin, no `console` right) may
    # not trigger profiling.
    c, _ = _build(monkeypatch, [{"port_id": "p1", "in_use": False}],
                  is_admin=False, has_write=False, has_access=False)
    r = c.post("/api/console/identify-llm-all?tenant=default", json={})
    assert r.status_code == 403
