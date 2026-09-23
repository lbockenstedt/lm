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
           hub=None):
    # Deterministic tenant model: dedicated (not shared), admin sees all.
    monkeypatch.setattr(console_routes.access, "filter_enabled", lambda hub, m: False)
    monkeypatch.setattr(console_routes.access, "tenant_is_shared", lambda t: False)
    monkeypatch.setattr(console_routes.access, "spoke_visible_to_session", lambda s, t: True)
    monkeypatch.setattr(llm, "hub_llm_identify_enabled", lambda hub: enabled)
    monkeypatch.setattr(llm, "find_ab", lambda hub: agent)

    orchestrated = []

    async def _fake_orchestrate(hub, ag, sid, pid):
        orchestrated.append((ag, sid, pid))
        return {"identified": False}

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
#    an ambiguous fingerprint ip goes to the dedicated resolve_ambiguous_ip()
#    call (never orchestrate(), which redacts every IP); the rest is kept. ──
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
                              "model": "2530-24G", "ip": "10.1.1.20", "type": "Switch"},
                 "ambiguous_fields": ["ip"],
                 "ip_candidates": ["10.1.1.20", "172.16.50.20"],
                 "ip_candidate_context": {
                     "10.1.1.20": "DEFAULT_VLAN | Manual 10.1.1.20 255.255.255.0 No No",
                     "172.16.50.20": "MGMT | Manual 172.16.50.20 255.255.255.0 No No"}}


def _build_profile(monkeypatch, autoprobe, *, agent="ab-1", pick=None):
    hub = _ProfileHub(autoprobe)
    c, orchestrated = _build(monkeypatch, [], agent=agent, hub=hub)
    resolved = []

    async def _fake_resolve(hub, ag, candidates, context=""):
        resolved.append((ag, candidates, context))
        return pick

    monkeypatch.setattr(llm, "resolve_ambiguous_ip", _fake_resolve)
    return c, hub, orchestrated, resolved


def test_profile_ambiguous_ip_resolved_by_llm_and_merged(monkeypatch):
    c, hub, orchestrated, resolved = _build_profile(
        monkeypatch, _FP_AMBIGUOUS, pick={"ip": "172.16.50.20", "confidence": 0.9})
    r = c.post("/api/console/identify-llm", json={"spoke_id": "c1", "port_id": "p1"})
    assert r.status_code == 200
    body = r.json()
    assert orchestrated == []                        # general pipeline never used
    # The real candidate values (with their source lines) reach the resolver.
    assert len(resolved) == 1
    ag, cands, context = resolved[0]
    assert ag == "ab-1"
    assert [x["ip"] for x in cands] == ["10.1.1.20", "172.16.50.20"]
    assert cands[1]["source"].startswith("MGMT")
    assert "hp-procurve" in context and "2530-24G" in context
    assert body["source"] == "fingerprint+llm"
    assert body["llm_resolved_fields"] == ["ip"]
    assert "ambiguous_fields" not in body and "ip_candidates" not in body
    # Only ip comes from the LLM; the deterministic fields are preserved.
    assert body["identity"] == {**_FP_AMBIGUOUS["identity"], "ip": "172.16.50.20"}
    assert body["vendor"] == "hp-procurve"
    assert body["identified"] is True and body["logged_in"] is True
    # The merged identity is persisted over the spoke's first-candidate one.
    assert ("CONSOLE_SET_LLM_IDENTIFY", {"enabled": True}) in hub.calls
    stored = [p for cmd, p in hub.calls if cmd == "CONSOLE_LLM_STORE"]
    assert stored and stored[-1]["identity"] == body["identity"]


def test_profile_ambiguous_ip_without_agent_keeps_first_candidate(monkeypatch):
    c, hub, orchestrated, resolved = _build_profile(monkeypatch, _FP_AMBIGUOUS, agent=None)
    r = c.post("/api/console/identify-llm", json={"spoke_id": "c1", "port_id": "p1"})
    assert r.status_code == 200                      # not a need_agent 409
    body = r.json()
    assert resolved == [] and orchestrated == []
    assert body["status"] == "OK" and body["identified"] is True
    assert body["source"] == "fingerprint"
    assert body["identity"] == _FP_AMBIGUOUS["identity"]   # ip = first candidate
    assert body["ambiguous_fields"] == ["ip"]        # UI can mark it unconfirmed
    assert body["ip_candidates"] == ["10.1.1.20", "172.16.50.20"]
    assert not any(cmd == "CONSOLE_LLM_STORE" for cmd, _ in hub.calls)


def test_profile_ambiguous_ip_llm_cannot_tell_keeps_first_candidate(monkeypatch):
    c, hub, orchestrated, resolved = _build_profile(monkeypatch, _FP_AMBIGUOUS, pick=None)
    body = c.post("/api/console/identify-llm", json={"spoke_id": "c1", "port_id": "p1"}).json()
    assert len(resolved) == 1 and orchestrated == []
    assert body["source"] == "fingerprint"
    assert "llm_resolved_fields" not in body
    assert body["identity"] == _FP_AMBIGUOUS["identity"]
    assert body["ambiguous_fields"] == ["ip"]
    assert body["ip_candidates"] == ["10.1.1.20", "172.16.50.20"]
    assert not any(cmd == "CONSOLE_LLM_STORE" for cmd, _ in hub.calls)


def test_profile_unambiguous_fingerprint_short_circuits(monkeypatch):
    fp = {k: v for k, v in _FP_AMBIGUOUS.items()
          if k not in ("ambiguous_fields", "ip_candidates", "ip_candidate_context")}
    c, hub, orchestrated, resolved = _build_profile(monkeypatch, fp)
    body = c.post("/api/console/identify-llm", json={"spoke_id": "c1", "port_id": "p1"}).json()
    assert resolved == [] and orchestrated == []     # LLM never consulted
    assert body == {"status": "OK", "identified": True, "source": "fingerprint",
                    "vendor": "hp-procurve", "identity": fp["identity"], "logged_in": True}
    assert not any(cmd == "CONSOLE_SET_LLM_IDENTIFY" for cmd, _ in hub.calls)


# ── ip_resolution: WHY the ip ended up confirmed or not ──────────────────────
# "never asked", "asked and the LLM couldn't decide", "the relay errored" and
# "the pick scored too low" are four different states. They all used to surface
# identically (source='fingerprint', ambiguous_fields=['ip']), so a caller could
# not tell a retryable transport failure from a decision the model had already
# declined to make. And because the returned `confidence` was never read, a
# 0.05-confidence guess was adopted and persisted exactly like a 0.99 one.

def test_profile_ambiguous_ip_reports_resolved_with_its_confidence(monkeypatch):
    c, hub, orchestrated, resolved = _build_profile(
        monkeypatch, _FP_AMBIGUOUS, pick={"ip": "172.16.50.20", "confidence": 0.9})
    body = c.post("/api/console/identify-llm", json={"spoke_id": "c1", "port_id": "p1"}).json()
    assert body["ip_resolution"] == "resolved"
    assert body["ip_resolution_confidence"] == 0.9


def test_profile_ambiguous_ip_low_confidence_pick_is_not_adopted(monkeypatch):
    """A guess the model itself is unsure of must not be promoted to a confirmed
    answer, persisted to the spoke, or clear the ambiguity flag."""
    c, hub, orchestrated, resolved = _build_profile(
        monkeypatch, _FP_AMBIGUOUS, pick={"ip": "172.16.50.20", "confidence": 0.05})
    body = c.post("/api/console/identify-llm", json={"spoke_id": "c1", "port_id": "p1"}).json()
    assert body["ip_resolution"] == "low_confidence"
    assert body["ip_resolution_confidence"] == 0.05
    assert body["source"] == "fingerprint"
    assert "llm_resolved_fields" not in body
    assert body["identity"] == _FP_AMBIGUOUS["identity"]     # first candidate kept
    assert body["ambiguous_fields"] == ["ip"]
    assert body["ip_candidates"] == ["10.1.1.20", "172.16.50.20"]
    assert not any(cmd == "CONSOLE_LLM_STORE" for cmd, _ in hub.calls)


def test_profile_ambiguous_ip_without_a_reported_confidence_is_still_adopted(monkeypatch):
    """`confidence: None` means the model reported no score — that is not a low
    score, so the pick is taken (and no score key is invented)."""
    c, hub, orchestrated, resolved = _build_profile(
        monkeypatch, _FP_AMBIGUOUS, pick={"ip": "172.16.50.20", "confidence": None})
    body = c.post("/api/console/identify-llm", json={"spoke_id": "c1", "port_id": "p1"}).json()
    assert body["ip_resolution"] == "resolved"
    assert "ip_resolution_confidence" not in body
    assert body["identity"]["ip"] == "172.16.50.20"


def test_profile_ambiguous_ip_not_asked_without_an_agent(monkeypatch):
    c, hub, orchestrated, resolved = _build_profile(monkeypatch, _FP_AMBIGUOUS, agent=None)
    body = c.post("/api/console/identify-llm", json={"spoke_id": "c1", "port_id": "p1"}).json()
    assert resolved == []
    assert body["ip_resolution"] == "not_asked"


def test_profile_ambiguous_ip_unknown_when_the_llm_cannot_decide(monkeypatch):
    c, hub, orchestrated, resolved = _build_profile(monkeypatch, _FP_AMBIGUOUS, pick=None)
    body = c.post("/api/console/identify-llm", json={"spoke_id": "c1", "port_id": "p1"}).json()
    assert body["ip_resolution"] == "unknown"


def test_profile_ambiguous_ip_failed_is_distinct_from_unknown(monkeypatch):
    """A relay/transport failure is retryable; "the LLM couldn't decide" is not.
    They must not both read as `unknown`."""
    c, hub, orchestrated, resolved = _build_profile(monkeypatch, _FP_AMBIGUOUS)

    async def _boom(hub_, ag, candidates, context=""):
        raise RuntimeError("relay unreachable")

    monkeypatch.setattr(llm, "resolve_ambiguous_ip", _boom)
    body = c.post("/api/console/identify-llm", json={"spoke_id": "c1", "port_id": "p1"}).json()
    assert body["ip_resolution"] == "failed"
    assert body["source"] == "fingerprint"
    assert body["ambiguous_fields"] == ["ip"]


def test_profile_single_candidate_still_publishes_the_candidate_list(monkeypatch):
    """An "ip is ambiguous" result with no candidate list is an inconsistent
    state for the UI: it has nothing to offer the operator."""
    fp = dict(_FP_AMBIGUOUS, ip_candidates=["10.1.1.20"])
    c, hub, orchestrated, resolved = _build_profile(monkeypatch, fp)
    body = c.post("/api/console/identify-llm", json={"spoke_id": "c1", "port_id": "p1"}).json()
    assert resolved == []                                    # fewer than 2 to choose from
    assert body["ip_resolution"] == "not_asked"
    assert body["ambiguous_fields"] == ["ip"]
    assert body["ip_candidates"] == ["10.1.1.20"]


# ── resolve_ambiguous_ip itself: the ONLY call that sends real IPs to the LLM ──
class _RelayHub:
    def __init__(self, reply):
        self.reply = reply
        self.sent = []

    async def request_response(self, sid, cmd, payload, timeout=15.0):
        self.sent.append((sid, cmd, payload))
        return {"status": "SUCCESS", "assistant": {"content": self.reply}}


def _run(coro):
    import asyncio
    return asyncio.run(coro)


_CANDS = [{"ip": "10.1.1.20", "source": "DEFAULT_VLAN | Manual 10.1.1.20 255.255.255.0"},
          {"ip": "172.16.50.20", "source": "MGMT | Manual 172.16.50.20 255.255.255.0"}]


def test_resolve_ambiguous_ip_sends_real_candidates_and_picks_one():
    hub = _RelayHub('Sure:\n```json\n{"ip": "172.16.50.20", "confidence": 0.8}\n```')
    res = _run(llm.resolve_ambiguous_ip(hub, "ab", _CANDS, "hp-procurve, 2530-24G"))
    assert res == {"ip": "172.16.50.20", "confidence": 0.8}
    (sid, cmd, payload), = hub.sent
    assert (sid, cmd) == ("ab", "HELP_ASK")
    assert payload["system"] == llm._SYS_PICK_IP
    user = payload["messages"][0]["content"]
    # Candidate values go out unredacted (the narrow exemption) …
    assert "- 10.1.1.20" in user and "- 172.16.50.20" in user
    # … but the source lines are still scrubbed (their IPs/masks → [IP]).
    assert "MGMT | Manual [IP] [IP]" in user
    assert "255.255.255.0" not in user


@pytest.mark.parametrize("reply", ['{"ip": null}', '{"ip": "192.168.9.9", "confidence": 1}',
                                   "I can't tell from this.", ""])
def test_resolve_ambiguous_ip_rejects_unknown_or_non_candidate(reply):
    assert _run(llm.resolve_ambiguous_ip(_RelayHub(reply), "ab", _CANDS, "x")) is None


def test_resolve_ambiguous_ip_relay_failure_returns_none():
    class _Boom:
        async def request_response(self, *a, **k):
            raise TimeoutError("relay down")
    assert _run(llm.resolve_ambiguous_ip(_Boom(), "ab", _CANDS)) is None


def test_general_llm_path_still_redacts_ips():
    # The exemption must not leak: _ask_llm (used by orchestrate) still scrubs.
    hub = _RelayHub("{}")
    _run(llm._ask_llm(hub, "ab", "sys", "Vlan10 172.16.50.20 up"))
    content = hub.sent[0][2]["messages"][0]["content"]
    assert "172.16.50.20" not in content and "[IP]" in content
