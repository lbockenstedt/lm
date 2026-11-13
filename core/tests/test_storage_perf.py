"""5-minute storage performance averages pushed by spokes (StoragePerfStore +
the hub's STORAGE_PERF_SAMPLE handler)."""
import asyncio
import types

import main
from storage_perf import StoragePerfStore

NOW = 1_800_000_000


def _sample(device, ts, write_ops):
    return {"device_id": device, "ts": ts, "samples": 10, "metrics": {"write_ops": write_ops}}


async def test_store_merges_repeats_drops_old_and_persists(tmp_path):
    store = StoragePerfStore(lambda: str(tmp_path))
    kept = store.add("truenas", [
        _sample("a1", NOW - 600, 100), _sample("a1", NOW - 300, 200),
        _sample("a1", NOW - 8 * 86400, 1),            # older than 7 days
        {"device_id": "a1", "ts": "bad", "metrics": {}}], now=NOW)
    assert kept == 2
    # A re-sent bucket replaces the old one rather than duplicating it.
    store.add("truenas", [_sample("a1", NOW - 300, 250)], now=NOW)
    rows = store.get("truenas", "a1", now=NOW)
    assert [(r["ts"], r["metrics"]["write_ops"]) for r in rows] == [(NOW - 600, 100), (NOW - 300, 250)]
    assert store.get("truenas", "a1", start=NOW - 400, now=NOW) == rows[1:]
    for t in list(store._file._tasks):
        t.cancel()
    await store.flush_now()
    again = StoragePerfStore(lambda: str(tmp_path))
    again.load()
    assert again.get("truenas", "a1", now=NOW) == rows


def test_handler_keeps_only_known_appliances_of_this_spoke(tmp_path):
    hub = types.SimpleNamespace(
        storage_perf=StoragePerfStore(lambda: str(tmp_path)),
        state=types.SimpleNamespace(system_state={"global_config": {"truenas_appliances": [
            {"id": "mine"}, {"id": "bound", "spoke_id": "truenas-1"},
            {"id": "other", "spoke_id": "truenas-2"}]}}),
        _primary_key=lambda s: s)
    conn = types.SimpleNamespace(spoke_id="truenas-1")
    ts = (int(__import__("time").time()) // 300) * 300
    payload = {"data": {"module": "truenas", "samples": [
        _sample("mine", ts, 1), _sample("bound", ts, 2),
        _sample("other", ts, 3), _sample("ghost", ts, 4)]}}

    async def _go():
        await main.LabManagerHub._spoke_msg_storage_perf_sample(hub, conn, {}, payload, None)
        for t in list(hub.storage_perf._file._tasks):
            t.cancel()
    asyncio.new_event_loop().run_until_complete(_go())
    assert sorted(hub.storage_perf.series) == ["truenas:bound", "truenas:mine"]


def _route_app(connected):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from routes import truenas

    class _Hub:
        def __init__(self, tmp):
            self.storage_perf = StoragePerfStore(lambda: tmp)
            self.state = types.SimpleNamespace(system_state={"global_config": {
                "truenas_appliances": [{"id": "a1", "tenant_id": "acme", "spoke_id": "tn-1"}]}})
            self.active_connections = {"tn-1": object()} if connected else {}
            self.feeds, self.calls, self.reads = {}, [], []

        def _primary_key(self, s):
            return s

        def get_truenas_spoke_for_tenant(self, tid):
            return ""

        def cache_register_feed(self, name, fn):
            self.feeds[name] = fn

        async def cache_read(self, ns, key, fetch, **kw):
            self.reads.append((ns, key))
            return await fetch()

        def cache_annotate(self, resp, ns, key):
            return dict(resp, cached_at=1)

        async def request_response(self, sid, cmd, payload, timeout=0):
            self.calls.append((cmd, payload))
            return {"payload": {"data": {"status": "SUCCESS", "data": [{"ts": 1}]}}}

    import tempfile
    app = FastAPI()
    hub = _Hub(tempfile.mkdtemp())
    app.state.hub = hub
    truenas.register(app, hub, types.SimpleNamespace(
        _session_user=lambda r: {"user": {"role": "admin"}}, _is_admin=lambda s: True,
        _is_tenant_admin=lambda s: True))
    return TestClient(app), hub


def test_default_history_is_the_warm_cached_last_hour(monkeypatch):
    import access
    monkeypatch.setattr(access, "is_admin", lambda s: True)
    client, hub = _route_app(connected=True)
    # The feed keeps every appliance's last hour warm.
    jobs = list(hub.feeds["truenas"](hub))
    assert [(j.ns, j.key) for j in jobs] == [("truenas_perf_recent", "a1")]
    body = client.get("/api/truenas/a1/performance/history").json()
    assert hub.reads == [("truenas_perf_recent", "a1")]
    assert body["source"] == "spoke" and body["cached_at"] == 1
    cmd, payload = hub.calls[-1]
    assert cmd == "TRUENAS_GET_PERF_HISTORY"
    assert 3590 <= payload["end"] - payload["start"] <= 3610
    # Any other range goes straight to the spoke, not the cache.
    client.get("/api/truenas/a1/performance/history?start=100&end=200")
    assert hub.calls[-1][1]["start"] == 100 and len(hub.reads) == 1


def test_history_falls_back_to_the_hub_copy_when_the_spoke_is_offline(monkeypatch):
    import access
    monkeypatch.setattr(access, "is_admin", lambda s: True)
    client, hub = _route_app(connected=False)
    ts = (int(__import__("time").time()) // 300) * 300 - 300
    hub.storage_perf.add("truenas", [_sample("a1", ts, 7)])
    for t in list(hub.storage_perf._file._tasks):
        t.cancel()
    body = client.get("/api/truenas/a1/performance/history").json()
    assert body["source"] == "hub" and body["data"][0]["metrics"]["write_ops"] == 7
    assert hub.calls == []


# ── firewall (opnsense) performance: same store, module "opnsense" ──────────

def test_handler_keeps_firewall_samples_of_this_spoke_and_ignores_other_modules(tmp_path):
    hub = types.SimpleNamespace(
        storage_perf=StoragePerfStore(lambda: str(tmp_path)),
        state=types.SimpleNamespace(system_state={"global_config": {"firewalls": [
            {"id": "fw-1", "spoke_id": "opn-1"}, {"id": "fw-2", "spoke_id": "opn-2"}]}}),
        _primary_key=lambda s: s)
    conn = types.SimpleNamespace(spoke_id="opn-1")
    ts = (int(__import__("time").time()) // 300) * 300

    async def _go(module, samples):
        payload = {"data": {"module": module, "samples": samples}}
        await main.LabManagerHub._spoke_msg_storage_perf_sample(hub, conn, {}, payload, None)
        for t in list(hub.storage_perf._file._tasks):
            t.cancel()
    loop = asyncio.new_event_loop()
    loop.run_until_complete(_go("opnsense", [_sample("fw-1", ts, 1), _sample("fw-2", ts, 2),
                                             _sample("ghost", ts, 3)]))
    loop.run_until_complete(_go("some-future-module", [_sample("fw-1", ts, 4)]))
    assert sorted(hub.storage_perf.series) == ["opnsense:fw-1"]


def _fw_route_app(monkeypatch, reply):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    import access
    import tempfile
    from routes import firewall
    monkeypatch.setattr(access, "read_scope", lambda sess, tid: "full")

    class _Hub:
        def __init__(self):
            self.storage_perf = StoragePerfStore(lambda: tempfile.mkdtemp())
            self.state = types.SimpleNamespace(system_state={"global_config": {
                "firewalls": [{"id": "fw-1", "spoke_id": "opn-1"}]}})
            self.active_connections = {"opn-1": object()}
            self.calls = []

        def _primary_key(self, s):
            return s

        async def request_response(self, sid, cmd, payload, timeout=0):
            self.calls.append((cmd, payload))
            return {"payload": {"data": reply}}

    app = FastAPI()
    hub = _Hub()
    app.state.hub = hub
    firewall.register(app, hub, types.SimpleNamespace(
        _session_user=lambda r: {"user": {"role": "admin"}}, _is_admin=lambda s: True,
        _is_tenant_admin=lambda s: True, _filter_fw=None))
    ts = (int(__import__("time").time()) // 300) * 300 - 300
    hub.storage_perf.add("opnsense", [_sample("fw-1", ts, 7)])
    for t in list(hub.storage_perf._file._tasks):
        t.cancel()
    return TestClient(app), hub


def test_firewall_history_default_is_the_hub_copy_and_ranges_ask_the_spoke(monkeypatch):
    client, hub = _fw_route_app(monkeypatch, {"status": "SUCCESS", "data": [{"ts": 1}]})
    body = client.get("/api/firewall/fw-1/performance/history").json()
    assert body["source"] == "hub" and body["data"][0]["metrics"]["write_ops"] == 7
    assert hub.calls == []
    body = client.get("/api/firewall/fw-1/performance/history?start=100&end=200").json()
    assert body["source"] == "spoke" and body["data"] == [{"ts": 1}]
    assert hub.calls == [("OPNSENSE_GET_PERF_HISTORY", {"start": 100, "end": 200, "firewall_id": "fw-1"})]
    assert client.get("/api/firewall/nope/performance/history").status_code == 404


def test_firewall_history_falls_back_when_the_spoke_lacks_the_command(monkeypatch):
    client, hub = _fw_route_app(monkeypatch, {"status": "ERROR", "message": "Unknown command"})
    now = int(__import__("time").time())
    body = client.get(f"/api/firewall/fw-1/performance/history?start={now - 3600}&end={now}").json()
    assert body["source"] == "hub" and len(body["data"]) == 1


def test_spoke_history_gaps_are_filled_from_the_hub_copy(monkeypatch):
    """A spoke that lost buckets (restart before a save, or its file
    overwritten) still shows the full range: the hub's copy fills the gap,
    and the spoke's own row wins a bucket both have."""
    now = (int(__import__("time").time()) // 300) * 300
    reply = {"status": "SUCCESS", "data": [{"ts": now - 300, "samples": 5, "metrics": {"x": 1}}]}
    client, hub = _fw_route_app(monkeypatch, reply)
    hub.storage_perf.add("opnsense", [_sample("fw-1", now - 3000, 3)])
    for t in list(hub.storage_perf._file._tasks):
        t.cancel()
    body = client.get(f"/api/firewall/fw-1/performance/history?start={now - 3600}&end={now}").json()
    assert body["source"] == "spoke"
    assert [r["ts"] for r in body["data"]] == [now - 3000, now - 300]
    assert body["data"][1]["metrics"] == {"x": 1}


def test_truenas_spoke_history_gaps_are_filled_from_the_hub_copy(monkeypatch):
    import access
    monkeypatch.setattr(access, "is_admin", lambda s: True)
    client, hub = _route_app(connected=True)
    now = (int(__import__("time").time()) // 300) * 300
    hub.storage_perf.add("truenas", [_sample("a1", now - 3000, 7)])
    for t in list(hub.storage_perf._file._tasks):
        t.cancel()
    body = client.get(f"/api/truenas/a1/performance/history?start={now - 3600}&end={now}").json()
    assert body["source"] == "spoke"
    assert [r["ts"] for r in body["data"]] == [1, now - 3000]
