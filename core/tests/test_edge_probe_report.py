"""Hub ingest of edge-reported HTTPS-port scanner probes (HTTP_PROBE_REPORT).

An edge component (reverse proxy / AppBuilder / role-hosted spoke UI) detects a
scanner on ITS OWN :443 listener and relays it up the authenticated tunnel so
the hub blocks the source centrally on the NSG — one deny protects every edge.

``LabManagerHub._handle_edge_probe_report`` is the hub-side sink. It runs only
after the frame's signature verified (authenticated spoke), but a *compromised*
edge could still forge reports to poison the blocklist. These tests pin the
three defenses: server-side path re-classification, a per-reporter rate cap, and
reuse of the threat monitor's trusted-IP exemption.
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
ThreatMonitor = _tm.ThreatMonitor


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
    """State for a PERIMETER reporter: no tenant binding (unassigned/infra) →
    the report routes to the central NSG block path."""
    def get_spoke_tenant(self, pk):
        return None


class _FakeHub:
    """Minimal stand-in exposing only what _handle_edge_probe_report reads for
    the PERIMETER (NSG) path — a reporter with no tenant binding."""
    def __init__(self, tm, max_reports=3):
        self.threat_monitor = tm
        self._edge_probe_reports = {}
        self._EDGE_PROBE_MAX = max_reports
        self._EDGE_BLOCK_TTL_S = 3600.0
        self.state = _NoTenantState()

    def _primary_key(self, x):
        return x


class _TenantState:
    """State for a TENANT reporter: a real tenant binding + a known_modules
    roster so the escalation sweep can enumerate the tenant's fleet."""
    def __init__(self, tenant_by_id, known):
        self._tenant_by_id = tenant_by_id
        self.system_state = {"known_modules": list(known)}

    def get_spoke_tenant(self, pk):
        return self._tenant_by_id.get(pk)


class _TenantHub:
    """Stand-in for the tenant-side self-scoped hard-revoke path. Records every
    revoke_spoke call instead of touching real crypto/WS."""
    def __init__(self, tm, tenant_by_id, known, escalate=2, window=600.0, max_reports=100):
        self.threat_monitor = tm
        self._edge_probe_reports = {}
        self._EDGE_PROBE_MAX = max_reports
        self._EDGE_BLOCK_TTL_S = 3600.0
        self._tenant_probe_trips = {}
        self._TENANT_PROBE_ESCALATE_NODES = escalate
        self._TENANT_PROBE_WINDOW_S = window
        self.state = _TenantState(tenant_by_id, known)
        self.revoked = []  # [(spoke_id, reason, source), ...]

    def _primary_key(self, x):
        return x

    async def revoke_spoke(self, spoke_id, reason=None, source="admin"):
        self.revoked.append((spoke_id, reason, source))
        return {"status": "SUCCESS", "spoke_id": spoke_id}

    # Exercise the REAL tenant-side response logic (self-revoke + escalation).
    _tenant_probe_hard_revoke = main.LabManagerHub._tenant_probe_hard_revoke


def _tm_for(tmp_path, entries=None, threshold=5):
    tm = ThreatMonitor(_TmHub(_State(str(tmp_path), {"azure_nsg": {"entries": entries or []}})))
    tm.set_config({"threshold": threshold, "window_s": 600})
    return tm


def _report(hub, spoke_id, remote_ip, data):
    # Call the real method unbound with our fake as self.
    return main.LabManagerHub._handle_edge_probe_report(hub, spoke_id, remote_ip, data)


def test_valid_edge_probe_is_recorded(tmp_path):
    tm = _tm_for(tmp_path)
    hub = _FakeHub(tm)
    _report(hub, "proxy-1", "10.0.0.9",
            {"source_ip": "203.0.113.7", "path": "/wp-login.php", "method": "GET", "node": "proxy-1"})
    t = tm.snapshot()["totals"]
    assert t["by_kind"]["http_probe"] == 1
    ev = tm._events[0]
    assert ev["ip"] == "203.0.113.7"
    assert "edge proxy-1" in ev["detail"]


def test_non_probe_path_is_rejected_server_side(tmp_path):
    # A compromised edge cannot get a BENIGN path attributed to a victim: the hub
    # re-classifies and drops anything that isn't itself a scanner signature.
    tm = _tm_for(tmp_path)
    hub = _FakeHub(tm)
    _report(hub, "proxy-1", "10.0.0.9",
            {"source_ip": "203.0.113.7", "path": "/api/security/overview", "method": "GET"})
    assert tm.snapshot()["totals"]["by_kind"].get("http_probe", 0) == 0
    assert len(tm._events) == 0


def test_loopback_and_bad_source_are_dropped(tmp_path):
    tm = _tm_for(tmp_path)
    hub = _FakeHub(tm)
    for bad in ("127.0.0.1", "0.0.0.0", "not-an-ip", "", None):
        _report(hub, "proxy-1", "10.0.0.9",
                {"source_ip": bad, "path": "/.env", "method": "GET"})
    assert len(tm._events) == 0


def test_internal_source_is_refused(tmp_path):
    # An edge report must never NSG-block one of our own internal ranges (RFC1918
    # / CGNAT / link-local): denying e.g. the 100.127.x hub/spoke private subnet
    # or the 10.x fleet space would sever internal control-plane paths. This is
    # the defense-in-depth backstop to the edge no longer trusting spoofable XFF.
    tm = _tm_for(tmp_path)
    hub = _FakeHub(tm)
    for internal in ("10.0.0.9", "172.16.4.4", "192.168.1.5",
                     "100.127.255.4", "169.254.1.1"):
        _report(hub, "proxy-1", "10.0.0.9",
                {"source_ip": internal, "path": "/.env", "method": "GET"})
    assert len(tm._events) == 0
    assert tm.snapshot()["totals"]["by_kind"].get("http_probe", 0) == 0


def test_per_reporter_rate_cap(tmp_path):
    # A single owned edge cannot flood forged reports to poison the blocklist.
    tm = _tm_for(tmp_path, threshold=100)  # high so the cap, not the block, is what limits
    hub = _FakeHub(tm, max_reports=3)
    for i in range(10):
        _report(hub, "proxy-1", "10.0.0.9",
                {"source_ip": f"203.0.113.{i}", "path": "/xmlrpc.php", "method": "POST"})
    assert tm.snapshot()["totals"]["by_kind"]["http_probe"] == 3  # only up to the cap


def test_repeated_valid_reports_block_the_source(tmp_path):
    tm = _tm_for(tmp_path, threshold=5)
    hub = _FakeHub(tm, max_reports=100)
    for _ in range(6):  # > threshold, same source
        _report(hub, "proxy-1", "10.0.0.9",
                {"source_ip": "203.0.113.44", "path": "/phpmyadmin/index.php", "method": "GET"})
    assert "203.0.113.44" in tm._blocks
    assert tm._blocks["203.0.113.44"]["kind"] == "http_probe"


def test_trusted_source_is_never_blocked_via_report(tmp_path):
    tm = _tm_for(tmp_path, entries=[{"ip": "198.51.100.5/32", "description": "admin"}], threshold=2)
    hub = _FakeHub(tm, max_reports=100)
    for _ in range(10):
        _report(hub, "proxy-1", "10.0.0.9",
                {"source_ip": "198.51.100.5", "path": "/.git/config", "method": "GET"})
    assert "198.51.100.5" not in tm._blocks          # trusted → exempt
    assert tm.snapshot()["totals"]["by_kind"]["http_probe"] == 10  # still counted


def test_missing_threat_monitor_is_a_noop(tmp_path):
    hub = _FakeHub(None)
    # Must not raise even with no monitor wired.
    _report(hub, "proxy-1", "10.0.0.9",
            {"source_ip": "203.0.113.7", "path": "/.env", "method": "GET"})


# ── Tenant-side self-scoped hard-revoke (A3 + Hard Revoke) ──────────────────

def _report_async(hub, spoke_id, remote_ip, data):
    """Drive the sync ingest inside a loop so the tenant-side path's
    ``asyncio.create_task(...)`` actually runs to completion."""
    async def _run():
        main.LabManagerHub._handle_edge_probe_report(hub, spoke_id, remote_ip, data)
        await asyncio.sleep(0)  # let the scheduled task start
        pending = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
        if pending:
            await asyncio.gather(*pending)
    asyncio.run(_run())


def test_tenant_reporter_self_revokes_and_never_touches_nsg(tmp_path):
    # A TENANT node reporting a scanner on its listener is hard-revoked (itself),
    # and the Azure NSG is NEVER written — the tenant node is the thing under
    # attack, not the Azure resources.
    tm = _tm_for(tmp_path, threshold=1)
    hub = _TenantHub(tm, {"proxy-t": "acme"}, ["proxy-t", "other-acme", "shared-x"])
    _report_async(hub, "proxy-t", "10.9.9.9",
                  {"source_ip": "203.0.113.7", "path": "/wp-login.php", "method": "GET"})
    assert hub.revoked == [("proxy-t", hub.revoked[0][1], "threat_auto")]
    assert "recon detected" in hub.revoked[0][1]  # reason is descriptive
    # No NSG / threat-monitor write at all on the tenant path.
    assert len(tm._events) == 0
    assert tm.snapshot()["totals"]["by_kind"].get("http_probe", 0) == 0
    assert tm._blocks == {}


def test_forged_tenant_report_only_revokes_itself(tmp_path):
    # A COMPROMISED tenant node forging a report (even naming a public victim IP)
    # can only revoke ITSELF — self-scoped containment gives an attacker zero
    # cross-victim leverage.
    tm = _tm_for(tmp_path, threshold=1)
    hub = _TenantHub(tm, {"owned": "acme", "victim": "acme"},
                     ["owned", "victim", "other"])
    _report_async(hub, "owned", "10.9.9.9",
                  {"source_ip": "198.51.100.9", "path": "/.git/config",
                   "method": "GET", "node": "victim"})
    revoked_ids = [r[0] for r in hub.revoked]
    assert revoked_ids == ["owned"]           # only the reporter, never "victim"
    assert tm._blocks == {}                    # and never the NSG


def test_tenant_wide_escalation_on_multiple_nodes(tmp_path):
    # >= escalate DISTINCT nodes tripping on the SAME tenant within the window
    # escalates to hard-revoking that whole tenant's fleet (coordinated sweep).
    tm = _tm_for(tmp_path, threshold=1)
    known = ["a-acme", "b-acme", "c-acme", "z-other"]
    tenants = {"a-acme": "acme", "b-acme": "acme", "c-acme": "acme", "z-other": "other"}
    hub = _TenantHub(tm, tenants, known, escalate=2)
    _report_async(hub, "a-acme", "10.0.0.1",
                  {"source_ip": "203.0.113.1", "path": "/.env", "method": "GET"})
    _report_async(hub, "b-acme", "10.0.0.2",
                  {"source_ip": "203.0.113.2", "path": "/.env", "method": "GET"})
    revoked_ids = [r[0] for r in hub.revoked]
    # a-acme + b-acme self-revoked, then the escalation revokes EVERY acme spoke
    # (a/b/c) — never the other tenant's z-other.
    assert "a-acme" in revoked_ids and "b-acme" in revoked_ids and "c-acme" in revoked_ids
    assert "z-other" not in revoked_ids
    # The escalation revoke carries a tenant-wide reason.
    esc = [r for r in hub.revoked if r[1] and "tenant-wide" in r[1]]
    assert esc, "expected a tenant-wide escalation revoke"
    assert tm._blocks == {}  # still never the NSG


def test_single_tenant_node_does_not_escalate(tmp_path):
    # One node tripping (below the escalate threshold) revokes only itself — no
    # tenant-wide sweep.
    tm = _tm_for(tmp_path, threshold=1)
    hub = _TenantHub(tm, {"solo": "acme", "peer": "acme"}, ["solo", "peer"], escalate=2)
    _report_async(hub, "solo", "10.0.0.1",
                  {"source_ip": "203.0.113.1", "path": "/.env", "method": "GET"})
    assert [r[0] for r in hub.revoked] == ["solo"]  # peer untouched

