"""Hub ingest of app-edge login failures (APP_LOGIN_FAILURE).

An app spoke (today just AppBuilder) rejects a credential against ITS OWN
WebUI login form and relays it up the authenticated tunnel so repeat attempts
against that edge count toward the SAME brute-force threshold as a failed
login against the hub's own /login.

``LabManagerHub._handle_app_login_failure`` is the hub-side sink. It runs only
after the frame's signature verified (authenticated spoke), but a
*compromised* app spoke could still forge failures to poison the blocklist.
These tests pin the defenses: a per-reporter rate cap, the internal/bad-source
backstop, bounded (never-permanent) blocking, and the perimeter-vs-tenant
routing split (log-only on the tenant side — an ordinary login failure is not
an unambiguous attack signature, unlike a probe/canary hit).
"""
import importlib.util
import os
import sys

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
    """Minimal stand-in exposing only what _handle_app_login_failure reads for
    the PERIMETER path — a reporter with no tenant binding."""
    def __init__(self, tm, max_reports=3):
        self.threat_monitor = tm
        self._app_login_failure_reports = {}
        self._EDGE_PROBE_MAX = max_reports
        self._EDGE_BLOCK_TTL_S = 3600.0
        self.state = _NoTenantState()

    def _primary_key(self, x):
        return x


class _TenantState:
    def __init__(self, tenant_by_id):
        self._tenant_by_id = tenant_by_id

    def get_spoke_tenant(self, pk):
        return self._tenant_by_id.get(pk)


class _TenantHub:
    """Stand-in for a TENANT reporter — login failures must be log-only here,
    never touching the threat monitor or revoking anything."""
    def __init__(self, tm, tenant_by_id, max_reports=100):
        self.threat_monitor = tm
        self._app_login_failure_reports = {}
        self._EDGE_PROBE_MAX = max_reports
        self._EDGE_BLOCK_TTL_S = 3600.0
        self.state = _TenantState(tenant_by_id)

    def _primary_key(self, x):
        return x


def _tm_for(tmp_path, entries=None, threshold=5):
    tm = ThreatMonitor(_TmHub(_State(str(tmp_path), {"azure_nsg": {"entries": entries or []}})))
    tm.set_config({"threshold": threshold, "window_s": 600})
    return tm


def _report(hub, spoke_id, remote_ip, data):
    return main.LabManagerHub._handle_app_login_failure(hub, spoke_id, remote_ip, data)


def test_valid_login_failure_is_recorded(tmp_path):
    tm = _tm_for(tmp_path)
    hub = _FakeHub(tm)
    _report(hub, "ab-1", "10.0.0.9",
            {"source_ip": "203.0.113.7", "username": "admin", "node": "ab-1"})
    t = tm.snapshot()["totals"]
    assert t["by_kind"]["app_login"] == 1
    ev = tm._events[0]
    assert ev["ip"] == "203.0.113.7"
    assert ev["username"] == "admin"
    assert "app edge ab-1" in ev["detail"]


def test_loopback_and_bad_source_are_dropped(tmp_path):
    tm = _tm_for(tmp_path)
    hub = _FakeHub(tm)
    for bad in ("127.0.0.1", "0.0.0.0", "not-an-ip", "", None):
        _report(hub, "ab-1", "10.0.0.9", {"source_ip": bad, "username": "admin"})
    assert len(tm._events) == 0


def test_internal_source_is_refused(tmp_path):
    tm = _tm_for(tmp_path)
    hub = _FakeHub(tm)
    for internal in ("10.0.0.9", "172.16.4.4", "192.168.1.5",
                     "100.127.255.4", "169.254.1.1"):
        _report(hub, "ab-1", "10.0.0.9", {"source_ip": internal, "username": "admin"})
    assert len(tm._events) == 0
    assert tm.snapshot()["totals"]["by_kind"].get("app_login", 0) == 0


def test_per_reporter_rate_cap(tmp_path):
    # A single compromised app spoke cannot flood forged failures to poison
    # the blocklist.
    tm = _tm_for(tmp_path, threshold=100)
    hub = _FakeHub(tm, max_reports=3)
    for i in range(10):
        _report(hub, "ab-1", "10.0.0.9",
                {"source_ip": f"203.0.113.{i}", "username": "admin"})
    assert tm.snapshot()["totals"]["by_kind"]["app_login"] == 3  # only up to the cap


def test_repeated_failures_block_the_source_but_never_permanently(tmp_path):
    tm = _tm_for(tmp_path, threshold=5)
    hub = _FakeHub(tm, max_reports=100)
    for _ in range(6):  # > threshold, same source
        _report(hub, "ab-1", "10.0.0.9",
                {"source_ip": "203.0.113.44", "username": "root"})
    assert "203.0.113.44" in tm._blocks
    assert tm._blocks["203.0.113.44"]["kind"] == "app_login"
    # Edge-reported signal: bounded, can never be flagged permanent.
    assert tm._blocks["203.0.113.44"].get("permanent") is not True


def test_trusted_source_is_never_blocked_via_report(tmp_path):
    tm = _tm_for(tmp_path, entries=[{"ip": "198.51.100.5/32", "description": "admin"}], threshold=2)
    hub = _FakeHub(tm, max_reports=100)
    for _ in range(10):
        _report(hub, "ab-1", "10.0.0.9", {"source_ip": "198.51.100.5", "username": "admin"})
    assert "198.51.100.5" not in tm._blocks          # trusted → exempt
    assert tm.snapshot()["totals"]["by_kind"]["app_login"] == 10  # still counted


def test_missing_threat_monitor_is_a_noop(tmp_path):
    hub = _FakeHub(None)
    _report(hub, "ab-1", "10.0.0.9", {"source_ip": "203.0.113.7", "username": "admin"})


def test_tenant_reporter_is_log_only_never_blocks_or_revokes(tmp_path):
    # A mistyped password is not an unambiguous attack signature the way a
    # probe/canary hit is, so the tenant-side path never touches the threat
    # monitor (and there is nothing to hard-revoke here, unlike HTTP_PROBE_REPORT).
    tm = _tm_for(tmp_path, threshold=1)
    hub = _TenantHub(tm, {"ab-tenant": "acme"})
    for _ in range(10):
        _report(hub, "ab-tenant", "10.9.9.9",
                {"source_ip": "203.0.113.7", "username": "admin"})
    assert len(tm._events) == 0
    assert tm.snapshot()["totals"]["by_kind"].get("app_login", 0) == 0
    assert tm._blocks == {}
