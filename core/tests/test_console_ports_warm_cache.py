"""Warm-cache regression tests for ``/api/console/ports`` (``routes/console.py``).

Pre-fix, the console port list fetched CONSOLE_LIST_PORTS live from each spoke
every request with NO hub-side cache. So while a console host rebooted (spoke
disconnected) — or right after a hub restart, before the spoke re-answered — the
page blanked: the device names/aliases/fingerprint the spoke had persisted were
invisible until it reconnected.

The route now mirrors the pxmx/netbox warm cache: every successful live fetch
persists the raw per-spoke port list (keyed by spoke_id) via ``hub.warm_set``; a
spoke-down / failed fetch serves the last-known list marked ``stale`` instead of
dropping the console. Fully DISCONNECTED spokes (not in the live list) that still
have a cached list are surfaced stale too. These lock in:

* a live fetch persists the raw port list under the spoke_id key;
* a spoke-down with a warm snapshot serves it stale (no error) — names survive;
* a fully-disconnected spoke's cached ports still appear (hub-reboot warm start);
* a spoke-down with NO snapshot falls back to the error map (unchanged).
"""

from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from routes import console


# ── Fakes ────────────────────────────────────────────────────────────────────

class _State:
    def __init__(self, tenants=None, names=None):
        self._tenants = tenants or {}
        self._names = names or {}

    def get_spoke_tenant(self, sid):
        return self._tenants.get(sid, "")

    def get_module_name(self, sid):
        return self._names.get(sid, sid)


class _Hub:
    """Minimal hub: in-memory warm cache + canned CONSOLE_LIST_PORTS replies."""

    def __init__(self, ports_by_spoke=None, connected=None, fail=None):
        self.state = _State(names={s: s for s in (connected or [])})
        self._ports = ports_by_spoke or {}
        self._connected = list(connected or [])
        self._fail = set(fail or [])
        self.warm_cache = {}                 # {ns: {key: {"data": ...}}}
        self._console_creds_seeded = set(self._connected)  # skip cred seeding

    # warm cache surface (mirrors WarmCacheMixin)
    def warm_get(self, namespace, key="_"):
        entry = self.warm_cache.get(namespace, {}).get(str(key))
        return entry.get("data") if isinstance(entry, dict) else None

    async def warm_set(self, namespace, key, data):
        self.warm_cache.setdefault(namespace, {})[str(key)] = {"data": data}

    def get_all_spokes_by_type(self, kind):
        return list(self._connected) if kind == "console" else []

    async def request_response(self, sid, cmd, payload, timeout=15.0,
                               signing_secret=None):
        if sid in self._fail:
            raise RuntimeError(f"{sid} unreachable")
        return {"payload": {"data": {"status": "SUCCESS",
                                     "ports": self._ports.get(sid, [])}}}


class _FakeAccess:
    """Neutral access shim: filter off, nothing shared, admin sees all."""

    @staticmethod
    def filter_enabled(hub, module):
        return False

    @staticmethod
    def tenant_is_shared(t):
        return False

    @staticmethod
    def spoke_visible_to_session(sess, eff):
        return True

    @staticmethod
    async def resolve_prefixes_for_tenant(hub, scope):
        return []

    @staticmethod
    def filter_record_by_prefixes(record, prefixes, fields):
        return record


def _ctx():
    return SimpleNamespace(
        _session_user=lambda request: {"user": {"tenant_id": ""}},
        _is_admin=lambda sess: True,
        _has_console_write_access=lambda *a, **k: True,
        _has_console_access=lambda *a, **k: True,
        _resolve_tenant=lambda request, explicit=None: None,
    )


@pytest.fixture(autouse=True)
def _stub_access(monkeypatch):
    monkeypatch.setattr(console, "access", _FakeAccess)


def _build(hub):
    app = FastAPI()
    app.state.hub = hub
    console.register(app, hub, _ctx())
    return TestClient(app)


def _port(pid, alias="", hostname=""):
    return {"port_id": pid, "device": f"/dev/{pid}", "alias": alias,
            "probe": {"identity": {"hostname": hostname}}}


# ── Tests ────────────────────────────────────────────────────────────────────

def test_live_fetch_persists_to_warm_cache():
    hub = _Hub(connected=["con-1"],
               ports_by_spoke={"con-1": [_port("ttyUSB0", "core-sw", "core-sw01")]})
    c = _build(hub)
    r = c.get("/api/console/ports")
    assert r.status_code == 200
    body = r.json()
    assert len(body["ports"]) == 1
    assert body["ports"][0]["alias"] == "core-sw"
    assert body["ports"][0].get("stale") is not True
    # raw list persisted under the spoke_id key
    assert hub.warm_get("console_ports", "con-1") == [
        _port("ttyUSB0", "core-sw", "core-sw01")]


def test_spoke_down_serves_warm_snapshot_stale():
    """Spoke disconnected mid-life, but a prior fetch left a snapshot → serve it
    stale instead of blanking the console (names survive)."""
    hub = _Hub(connected=["con-1"], fail=["con-1"])
    hub.warm_cache["console_ports"] = {
        "con-1": {"data": [_port("ttyUSB0", "carried-over", "sw01")]}}
    c = _build(hub)
    r = c.get("/api/console/ports")
    assert r.status_code == 200
    body = r.json()
    assert len(body["ports"]) == 1
    assert body["ports"][0]["alias"] == "carried-over"
    assert body["ports"][0]["stale"] is True
    assert "con-1" in body["stale_spokes"]
    assert body["errors"] == {}          # cached → not an error


def test_disconnected_spoke_cached_ports_warm_start():
    """Hub reboot while the console host is also down: the spoke isn't in the
    live list at all, but its cached ports still surface (stale)."""
    hub = _Hub(connected=[])             # nothing connected
    hub.state = _State(names={"con-9": "rack-console"})
    hub.warm_cache["console_ports"] = {
        "con-9": {"data": [_port("ttyUSB0", "edge", "edge01")]}}
    c = _build(hub)
    r = c.get("/api/console/ports")
    assert r.status_code == 200
    body = r.json()
    assert len(body["ports"]) == 1
    assert body["ports"][0]["stale"] is True
    assert "con-9" in body["consoles"]
    assert "con-9" in body["stale_spokes"]


def test_spoke_down_no_cache_falls_back_to_error():
    hub = _Hub(connected=["con-1"], fail=["con-1"])
    c = _build(hub)
    r = c.get("/api/console/ports")
    assert r.status_code == 200
    body = r.json()
    assert body["ports"] == []
    assert "con-1" in body["errors"]
    assert body["stale_spokes"] == []
