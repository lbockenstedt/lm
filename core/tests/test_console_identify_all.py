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
        self.warm_cache = {}

    def get_all_spokes_by_type(self, kind):
        return ["c1"] if kind == "console" else []

    def warm_get(self, namespace, key="_"):
        entry = self.warm_cache.get(namespace, {}).get(str(key))
        return entry.get("data") if isinstance(entry, dict) else None

    async def warm_set(self, namespace, key, data):
        self.warm_cache.setdefault(namespace, {})[str(key)] = {"data": data}

    async def request_response(self, sid, cmd, payload, timeout=15.0):
        if cmd == "CONSOLE_LIST_PORTS":
            return {"ports": self._ports}
        return {}


def _build(monkeypatch, ports, *, enabled=True, agent="bf-1", is_admin=True, has_write=True, has_access=True,
           hub=None, llm_result=None):
    # Deterministic tenant model: dedicated (not shared), admin sees all.
    monkeypatch.setattr(console_routes.access, "filter_enabled", lambda hub, m: False)
    monkeypatch.setattr(console_routes.access, "tenant_is_shared", lambda t: False)
    monkeypatch.setattr(console_routes.access, "spoke_visible_to_session", lambda s, t: True)
    monkeypatch.setattr(llm, "hub_llm_identify_enabled", lambda hub: enabled)
    monkeypatch.setattr(llm, "find_ab", lambda hub: agent)

    orchestrated = []

    async def _fake_orchestrate(hub, ag, sid, pid):
        orchestrated.append((ag, sid, pid))
        return llm_result if llm_result is not None else {"identified": False}

    monkeypatch.setattr(llm, "orchestrate", _fake_orchestrate)

    app = FastAPI()
    app.state.hub = hub or _Hub(ports)
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
    # AppBuilder agent no longer blocks the bulk profile — it still queues.
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


# ── Single-port profile (``/api/console/identify-llm`` → _console_profile_one):
#    an ambiguous fingerprint field is resolved by the LLM, the rest is kept. ──
class _ProfileHub(_Hub):
    def __init__(self, autoprobe):
        super().__init__([])
        self._autoprobe = autoprobe
        self._console_creds_seeded = {"c1"}  # skip the credential-vault seed step
        self.calls = []

    async def request_response(self, sid, cmd, payload, timeout=15.0):
        self.calls.append((cmd, payload))
        if cmd == "CONSOLE_AUTOPROBE":
            return self._autoprobe
        if cmd == "CONSOLE_GET_CAPTURE":
            return {"capture": "HP-2530-24G# "}
        return {}

    async def send_to_spoke_command(self, sid, cmd, payload):
        self.calls.append((cmd, payload))


_FP_AMBIGUOUS = {"status": "SUCCESS", "vendor": "hp-procurve", "logged_in": True,
                 "identity": {"hostname": "HP-2530-24G", "serial": "CN12345",
                              "ip": "10.1.1.20", "type": "Switch"},
                 "ambiguous_fields": ["ip"]}


def _build_profile(monkeypatch, autoprobe, *, agent="ab-1", llm_result=None):
    hub = _ProfileHub(autoprobe)
    c, orchestrated = _build(monkeypatch, [], agent=agent, hub=hub, llm_result=llm_result)
    return c, hub, orchestrated


def test_profile_ambiguous_field_resolved_by_llm_and_merged(monkeypatch):
    llm_res = {"status": "OK", "identified": True, "vendor": "Aruba",
               "identity": {"ip": "172.16.50.20", "hostname": "llm-guess", "serial": "WRONG"}}
    c, hub, orchestrated = _build_profile(monkeypatch, _FP_AMBIGUOUS, llm_result=llm_res)
    r = c.post("/api/console/identify-llm", json={"spoke_id": "c1", "port_id": "p1"})
    assert r.status_code == 200
    body = r.json()
    assert orchestrated == [("ab-1", "c1", "p1")]
    assert body["source"] == "fingerprint+llm"
    assert body["llm_resolved_fields"] == ["ip"]
    assert "ambiguous_fields" not in body            # fully resolved now
    # Only the ambiguous field comes from the LLM; trusted fields are kept.
    assert body["identity"] == {"hostname": "HP-2530-24G", "serial": "CN12345",
                                "ip": "172.16.50.20", "type": "Switch"}
    assert body["vendor"] == "hp-procurve"
    assert body["identified"] is True and body["logged_in"] is True
    # The LLM path was permitted on the spoke, and the MERGED identity persisted.
    assert ("CONSOLE_SET_LLM_IDENTIFY", {"enabled": True}) in hub.calls
    stored = [p for cmd, p in hub.calls if cmd == "CONSOLE_LLM_STORE"]
    assert stored and stored[-1]["identity"] == body["identity"]


def test_profile_ambiguous_llm_unresolved_keeps_best_guess(monkeypatch):
    c, hub, orchestrated = _build_profile(monkeypatch, _FP_AMBIGUOUS,
                                          llm_result={"status": "INCONCLUSIVE", "identified": False})
    body = c.post("/api/console/identify-llm", json={"spoke_id": "c1", "port_id": "p1"}).json()
    assert orchestrated == [("ab-1", "c1", "p1")]
    assert body["source"] == "fingerprint"
    assert body["identity"]["ip"] == "10.1.1.20"
    assert body["ambiguous_fields"] == ["ip"]
    assert not any(cmd == "CONSOLE_LLM_STORE" for cmd, _ in hub.calls)


def test_profile_ambiguous_llm_identified_without_field_restores_fingerprint(monkeypatch):
    # The LLM identified the box but gave no IP: keep the flagged best guess, and
    # re-store the fingerprint identity over the LLM-only one orchestrate() saved.
    llm_res = {"status": "OK", "identified": True, "vendor": "Aruba",
               "identity": {"model": "2530"}}
    c, hub, orchestrated = _build_profile(monkeypatch, _FP_AMBIGUOUS, llm_result=llm_res)
    body = c.post("/api/console/identify-llm", json={"spoke_id": "c1", "port_id": "p1"}).json()
    assert orchestrated == [("ab-1", "c1", "p1")]
    assert body["source"] == "fingerprint"
    assert "llm_resolved_fields" not in body
    assert body["ambiguous_fields"] == ["ip"]
    assert body["identity"] == _FP_AMBIGUOUS["identity"]
    stored = [p for cmd, p in hub.calls if cmd == "CONSOLE_LLM_STORE"]
    assert stored and stored[-1]["identity"] == _FP_AMBIGUOUS["identity"]


def test_profile_ambiguous_without_agent_returns_flagged_best_guess(monkeypatch):
    c, hub, orchestrated = _build_profile(monkeypatch, _FP_AMBIGUOUS, agent=None)
    r = c.post("/api/console/identify-llm", json={"spoke_id": "c1", "port_id": "p1"})
    assert r.status_code == 200                      # not a need_agent 409
    body = r.json()
    assert orchestrated == []
    assert body["status"] == "OK" and body["identified"] is True
    assert body["source"] == "fingerprint"
    assert body["identity"]["ip"] == "10.1.1.20"
    assert body["ambiguous_fields"] == ["ip"]        # caller can see it's unconfirmed


def test_profile_unambiguous_fingerprint_short_circuits(monkeypatch):
    fp = {k: v for k, v in _FP_AMBIGUOUS.items() if k != "ambiguous_fields"}
    c, hub, orchestrated = _build_profile(monkeypatch, fp)
    body = c.post("/api/console/identify-llm", json={"spoke_id": "c1", "port_id": "p1"}).json()
    assert orchestrated == []                        # LLM never consulted
    assert body == {"status": "OK", "identified": True, "source": "fingerprint",
                    "vendor": "hp-procurve", "identity": fp["identity"], "logged_in": True}
    assert not any(cmd == "CONSOLE_SET_LLM_IDENTIFY" for cmd, _ in hub.calls)
