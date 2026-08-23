"""Node-side operator canary endpoints: the generic engine + the hub-side
``NODE_CANARY_HIT`` response routing.

A node (edge proxy / role-hosted spoke UI) is pushed a set of canary endpoints
by the hub (``NODE_CANARY_SET``); a request to one is a definitive intrusion
attempt, which the node serves + relays up (``NODE_CANARY_HIT``). The hub routes
the response by the reporter's LOCATION exactly like the probe path: a perimeter
reporter → bounded central source block; a tenant reporter → self-scoped
hard-revoke (with the shared tenant-wide escalation ladder).

The engine ships EMPTY and inert — no endpoint or bait is hard-coded in the
public source; the set is supplied at runtime by the hub. These tests pin the
engine contract and the hit-response routing/containment.
"""
import importlib.util
import os
import sys
import asyncio

_SRC = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

os.environ.setdefault("LM_FERNET_KEY", __import__("cryptography.fernet",
                      fromlist=["Fernet"]).Fernet.generate_key().decode())

import main  # noqa: E402


def _load_from_src(modname, relpath):
    target = os.path.join(_SRC, relpath)
    spec = importlib.util.spec_from_file_location(modname, target)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[modname] = mod
    spec.loader.exec_module(mod)
    return mod


_load_from_src("azure_nsg", "azure_nsg.py")
_tm = _load_from_src("security.threat_monitor", os.path.join("security", "threat_monitor.py"))
node_canary = _load_from_src("security.node_canary", os.path.join("security", "node_canary.py"))
ThreatMonitor = _tm.ThreatMonitor


# ─────────────────────────── engine (node-side) ────────────────────────────

def test_engine_inert_by_default():
    node_canary.clear()
    assert node_canary.is_active() is False
    assert node_canary.match("/.env") is None


def test_engine_set_match_and_serve():
    n = node_canary.set_config([
        {"path": "/.env", "status": 200, "ctype": "text/plain", "body": "API_KEY=x"},
        {"path": "/backup.sql", "body": "-- dump"},
    ])
    assert n == 2 and node_canary.is_active() is True
    hit = node_canary.match("/.env")
    assert hit is not None
    assert hit["status"] == 200 and hit["ctype"] == "text/plain"
    assert hit["body"] == b"API_KEY=x"
    # defaults applied when omitted
    d = node_canary.match("/backup.sql")
    assert d["status"] == 200 and d["ctype"] == "text/plain" and d["body"] == b"-- dump"
    assert node_canary.match("/index.html") is None
    node_canary.clear()


def test_engine_path_normalization():
    node_canary.set_config([{"path": "/.env", "body": "x"}])
    for variant in ("/.env", "/.ENV", "/.env/", "/.env?foo=bar", "/.Env?a=1"):
        assert node_canary.match(variant) is not None, variant
    node_canary.clear()


def test_engine_empty_clears():
    node_canary.set_config([{"path": "/.env", "body": "x"}])
    assert node_canary.is_active()
    assert node_canary.set_config([]) == 0
    assert node_canary.is_active() is False
    node_canary.clear()


def test_engine_skips_malformed_entries():
    n = node_canary.set_config([
        {"path": "/.env", "body": "ok"},
        {"path": "no-leading-slash"},   # dropped
        {"path": ""},                    # dropped
        {"nope": 1},                     # dropped
    ])
    assert n == 1
    assert node_canary.match("/.env") is not None
    node_canary.clear()


# ─────────────────────── hub-side hit routing ──────────────────────────────

class _State:
    def __init__(self, data_dir, gc=None):
        self.data_dir = data_dir
        self.system_state = {"global_config": gc or {}}

    def _mark_dirty(self):
        pass


class _TmHub:
    def __init__(self, state):
        self.state = state


class _NoTenantState:
    def get_spoke_tenant(self, pk):
        return None


class _PerimeterHub:
    """Reporter with no tenant binding → the perimeter (bounded NSG block) path."""
    def __init__(self, tm, max_reports=100):
        self.threat_monitor = tm
        self._canary_hit_reports = {}
        self._EDGE_PROBE_MAX = max_reports
        self._EDGE_BLOCK_TTL_S = 3600.0
        self.state = _NoTenantState()

    def _primary_key(self, x):
        return x


class _TenantState:
    def __init__(self, tenant_by_id, known):
        self._tenant_by_id = tenant_by_id
        self.system_state = {"known_modules": list(known)}

    def get_spoke_tenant(self, pk):
        return self._tenant_by_id.get(pk)


class _TenantHub:
    def __init__(self, tm, tenant_by_id, known, escalate=2, window=600.0, max_reports=100):
        self.threat_monitor = tm
        self._canary_hit_reports = {}
        self._EDGE_PROBE_MAX = max_reports
        self._EDGE_BLOCK_TTL_S = 3600.0
        self._tenant_probe_trips = {}
        self._TENANT_PROBE_ESCALATE_NODES = escalate
        self._TENANT_PROBE_WINDOW_S = window
        self.state = _TenantState(tenant_by_id, known)
        self.revoked = []

    def _primary_key(self, x):
        return x

    async def revoke_spoke(self, spoke_id, reason=None, source="admin"):
        self.revoked.append((spoke_id, reason, source))
        return {"status": "SUCCESS", "spoke_id": spoke_id}

    _tenant_probe_hard_revoke = main.LabManagerHub._tenant_probe_hard_revoke


def _tm_for(tmp_path, threshold=5):
    tm = ThreatMonitor(_TmHub(_State(str(tmp_path), {"azure_nsg": {"entries": []}})))
    tm.set_config({"threshold": threshold, "window_s": 600})
    return tm


def _hit(hub, spoke_id, remote_ip, data):
    return main.LabManagerHub._handle_node_canary_hit(hub, spoke_id, remote_ip, data)


def test_perimeter_hit_records_bounded_block(tmp_path):
    tm = _tm_for(tmp_path)
    hub = _PerimeterHub(tm)
    _hit(hub, "proxy-1", "10.0.0.9",
         {"source_ip": "203.0.113.7", "path": "/.env", "method": "GET", "node": "proxy-1"})
    t = tm.snapshot()["totals"]
    assert t["by_kind"]["canary"] == 1
    assert tm._events[0]["ip"] == "203.0.113.7"


def test_perimeter_hit_refuses_internal_and_bad_source(tmp_path):
    tm = _tm_for(tmp_path)
    hub = _PerimeterHub(tm)
    for bad in ("127.0.0.1", "10.0.0.5", "192.168.1.9", "169.254.1.1",
                "100.127.0.1", "not-an-ip", "", None):
        _hit(hub, "proxy-1", "10.0.0.9",
             {"source_ip": bad, "path": "/.env", "method": "GET"})
    assert len(tm._events) == 0


def test_tenant_hit_self_scoped_revoke(tmp_path):
    tm = _tm_for(tmp_path)
    hub = _TenantHub(tm, {"spoke-A": "tenant-x"}, known=["spoke-A", "spoke-B"])
    asyncio.run(_run_hit(hub, "spoke-A", "10.0.0.9",
                {"source_ip": "198.51.100.5", "path": "/.env", "method": "GET"}))
    # only the reporter is revoked (self-scoped), and never via the NSG
    assert [r[0] for r in hub.revoked] == ["spoke-A"]
    assert hub.revoked[0][2] == "threat_auto"
    assert tm.snapshot()["totals"]["by_kind"].get("canary", 0) == 0


def test_forged_tenant_hit_only_revokes_itself(tmp_path):
    # An owned node forging a canary hit can only revoke ITSELF — zero
    # cross-victim leverage (the containment property).
    tm = _tm_for(tmp_path)
    hub = _TenantHub(tm, {"evil": "tenant-x", "victim": "tenant-x"},
                     known=["evil", "victim"], escalate=2)
    asyncio.run(_run_hit(hub, "evil", "10.0.0.9",
                {"source_ip": "198.51.100.5", "path": "/.env", "method": "GET"}))
    assert [r[0] for r in hub.revoked] == ["evil"]


def test_tenant_wide_escalation_shared_with_probe(tmp_path):
    # Two DISTINCT nodes on one tenant tripping within the window escalates to a
    # tenant-wide revoke, and the escalation counter is SHARED with the probe
    # path (both feed _tenant_probe_trips).
    tm = _tm_for(tmp_path)
    hub = _TenantHub(tm, {"n1": "tenant-x", "n2": "tenant-x", "n3": "tenant-x"},
                     known=["n1", "n2", "n3"], escalate=2)
    asyncio.run(_run_hit(hub, "n1", "10.0.0.9",
                {"source_ip": "198.51.100.5", "path": "/.env", "method": "GET"}))
    asyncio.run(_run_hit(hub, "n2", "10.0.0.9",
                {"source_ip": "198.51.100.6", "path": "/backup.sql", "method": "GET"}))
    revoked = {r[0] for r in hub.revoked}
    assert {"n1", "n2", "n3"}.issubset(revoked)  # whole tenant fleet


def test_per_reporter_rate_cap(tmp_path):
    tm = _tm_for(tmp_path, threshold=100)
    hub = _PerimeterHub(tm, max_reports=3)
    for i in range(10):
        _hit(hub, "proxy-1", "10.0.0.9",
             {"source_ip": f"203.0.113.{i}", "path": "/.env", "method": "GET"})
    assert tm.snapshot()["totals"]["by_kind"]["canary"] == 3


async def _run_hit(hub, spoke_id, remote_ip, data):
    # The tenant path schedules the self-revoke via asyncio.create_task; run it
    # on a live loop and let the scheduled task finish.
    _hit(hub, spoke_id, remote_ip, data)
    await asyncio.sleep(0)
    await asyncio.sleep(0)
