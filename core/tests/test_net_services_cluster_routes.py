"""net_services.py cluster routes: DNS resolver cluster + Kea HA pair.

Two things this locks in:

* The three DNS cluster routes and three DHCP HA routes relay the right command
  to the tenant-resolved spoke — the hub stays a relay, the module owns the
  topology.
* The non-admin diagnostics redaction extends to the new ``cluster`` block: a
  tenant user still sees the VERDICT (state, convergence, per-member health) but
  never member hostnames, per-node error text, or the last commit/apply detail.
"""
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

from routes.net_services import register


class FakeState:
    def __init__(self):
        self.system_state = {"global_config": {}}

    def get_spoke_tenant(self, sid):
        return ""


class FakeHub:
    def __init__(self, replies=None):
        self.active_connections = {"dns-1", "dhcp-1"}
        self.approved_modules = {"dns-1": True, "dhcp-1": True}
        self.state = FakeState()
        self.replies = replies or {}
        self.forwarded = []

    def _primary_key(self, sid):
        return sid

    def get_spoke_by_type(self, module_type):
        return {"dns": "dns-1", "dhcp": "dhcp-1"}.get(module_type)

    def get_all_spokes_by_type(self, module_type):
        return [self.get_spoke_by_type(module_type)]

    def get_dns_spoke_for_tenant(self, tenant_id=None):
        return "dns-1"

    def get_dns_spoke_for_shared(self):
        return "dns-1"

    def get_dhcp_spoke_for_tenant(self, tenant_id=None):
        return "dhcp-1"

    def get_dhcp_spoke_for_shared(self):
        return "dhcp-1"

    async def request_response(self, sid, cmd, payload=None, timeout=None):
        self.forwarded.append((sid, cmd, payload))
        data = (self.replies.get(sid) or {}).get(cmd, {"status": "SUCCESS"})
        return {"payload": {"data": data}}


async def _apassthrough(*a, **k):
    return a[1] if len(a) > 1 else None


def _client(sess, hub):
    app = FastAPI()
    ctx = SimpleNamespace(
        _session_user=lambda request: sess,
        _is_admin=lambda s: bool(s and s.get("user", {}).get("is_admin")),
        _effective_tenant=lambda request, explicit=None: explicit,
        _filter_session=_apassthrough,
        _filter_tenant=_apassthrough,
    )
    register(app, hub, ctx)
    app.state.hub = hub
    return TestClient(app)


ADMIN = {"user": {"is_admin": True}}
TENANT = {"user": {"is_admin": False, "tenant_id": "t1"}}


# ── DNS cluster routes ──────────────────────────────────────────────────────

def test_dns_cluster_get_relays_the_status_command():
    hub = FakeHub({"dns-1": {"DNS_CLUSTER_STATUS": {
        "status": "SUCCESS", "enabled": True, "state": "converged",
        "member_count": 2}}})
    r = _client(ADMIN, hub).get("/api/dns/cluster")
    assert r.status_code == 200
    assert r.json()["state"] == "converged"
    assert hub.forwarded[-1][:2] == ("dns-1", "DNS_CLUSTER_STATUS")


def test_dns_cluster_post_relays_the_body_verbatim():
    hub = FakeHub()
    body = {"members": [{"id": "dns-a", "host": "10.0.1.1"},
                        {"id": "dns-b", "host": "10.0.1.2"}],
            "worker_secret": "psk"}
    r = _client(ADMIN, hub).post("/api/dns/cluster", json=body)
    assert r.status_code == 200
    sid, cmd, payload = hub.forwarded[-1]
    assert (sid, cmd) == ("dns-1", "DNS_CLUSTER_CONFIG")
    assert payload == body


def test_dns_cluster_reconcile_relays_the_reconcile_command():
    hub = FakeHub({"dns-1": {"DNS_CLUSTER_RECONCILE": {
        "status": "SUCCESS", "reconciled": ["dns-b"]}}})
    r = _client(ADMIN, hub).post("/api/dns/cluster/reconcile")
    assert r.json()["reconciled"] == ["dns-b"]
    assert hub.forwarded[-1][:2] == ("dns-1", "DNS_CLUSTER_RECONCILE")


def test_a_spoke_error_becomes_a_502_not_a_200():
    hub = FakeHub({"dns-1": {"DNS_CLUSTER_RECONCILE": {
        "status": "ERROR", "message": "DNS cluster is not enabled"}}})
    r = _client(ADMIN, hub).post("/api/dns/cluster/reconcile")
    assert r.status_code == 502
    assert "not enabled" in r.json()["detail"]


# ── DHCP HA routes ──────────────────────────────────────────────────────────

def test_dhcp_ha_get_relays_the_status_command():
    hub = FakeHub({"dhcp-1": {"DHCP_HA_STATUS": {
        "status": "SUCCESS", "enabled": True, "mode": "hot-standby",
        "state": "healthy"}}})
    r = _client(ADMIN, hub).get("/api/dhcp/ha")
    assert r.json()["mode"] == "hot-standby"
    assert hub.forwarded[-1][:2] == ("dhcp-1", "DHCP_HA_STATUS")


def test_dhcp_ha_post_relays_members_and_mode():
    hub = FakeHub()
    body = {"members": [{"id": "kea-a", "host": "10.0.1.10"},
                        {"id": "kea-b", "host": "10.0.1.11"}],
            "mode": "load-balancing"}
    _client(ADMIN, hub).post("/api/dhcp/ha", json=body)
    sid, cmd, payload = hub.forwarded[-1]
    assert (sid, cmd) == ("dhcp-1", "DHCP_HA_CONFIG")
    assert payload["mode"] == "load-balancing"


def test_dhcp_ha_apply_relays_the_apply_command():
    hub = FakeHub({"dhcp-1": {"DHCP_HA_APPLY": {
        "status": "SUCCESS", "applied": ["kea-b", "kea-a"]}}})
    r = _client(ADMIN, hub).post("/api/dhcp/ha/apply")
    assert r.json()["applied"] == ["kea-b", "kea-a"]
    assert hub.forwarded[-1][:2] == ("dhcp-1", "DHCP_HA_APPLY")


# ── Non-admin redaction of the cluster block ────────────────────────────────

_DNS_DIAG = {
    "status": "SUCCESS", "healthy": False,
    "service": {"ok": True, "output": "active", "error": ""},
    "config": {"ok": True, "output": "", "error": ""},
    "control": {"ok": True, "output": "", "error": ""},
    "sockets": {"ok": True, "listeners": ["0.0.0.0:53"], "error": "",
                "has_port_53_listener": True, "has_lan_listener": True},
    "configured_interfaces": ["0.0.0.0"], "access_controls": ["10.0.0.0/8 allow"],
    "local_ipv4s": ["10.0.1.9"], "probes": [], "conf_path": "/etc/unbound/x.conf",
    "recommendations": ["Resolver 'dns-b' is not connected"],
    "diagnostics_source": "dns-a",
    "members": {"dns-a": {"status": "SUCCESS", "healthy": True}},
    "cluster": {
        "enabled": True, "state": "partial", "converged": False,
        "member_count": 2, "converged_count": 1,
        "desired": {"version": 4, "digest": "deadbeef", "record_count": 3,
                    "updated_at": 1.0},
        "members": [
            {"id": "dns-a", "host": "10.0.1.1", "role": "", "connected": True,
             "convergence": "converged", "applied_digest": "deadbeef",
             "applied_version": 4, "unbound_running": True},
            {"id": "dns-b", "host": "10.0.1.2", "role": "", "connected": False,
             "convergence": "unreachable", "applied_digest": None,
             "applied_version": None, "unbound_running": None},
        ],
        "last_commit": {"status": "PARTIAL", "errors": {"dns-b": "no response"}},
        "recommendations": ["Resolver 'dns-b' is not connected"],
    },
}


def test_admin_sees_the_full_dns_cluster_block():
    hub = FakeHub({"dns-1": {"DNS_DIAGNOSTICS": _DNS_DIAG}})
    body = _client(ADMIN, hub).get("/api/dns/diagnostics").json()
    assert body["cluster"]["members"][0]["host"] == "10.0.1.1"
    assert body["cluster"]["last_commit"]["status"] == "PARTIAL"
    assert body["members"]


def test_non_admin_keeps_the_dns_verdict_but_loses_the_addressing():
    hub = FakeHub({"dns-1": {"DNS_DIAGNOSTICS": _DNS_DIAG}})
    body = _client(TENANT, hub).get("/api/dns/diagnostics").json()
    cluster = body["cluster"]
    assert cluster["state"] == "partial" and cluster["converged"] is False
    assert cluster["converged_count"] == 1 and cluster["member_count"] == 2
    assert [m["convergence"] for m in cluster["members"]] == ["converged", "unreachable"]
    for member in cluster["members"]:
        assert "host" not in member and "applied_digest" not in member
    assert cluster["last_commit"] == {}
    assert "digest" not in cluster["desired"]
    assert body["members"] == {}
    assert body["local_ipv4s"] == [] and body["conf_path"] == ""


_DHCP_DIAG = {
    "status": "SUCCESS", "healthy": False,
    "units": {"kea-dhcp4-server": {"ActiveState": "active", "error": "boom"}},
    "ca": {"reachable": True, "url": "http://10.0.1.10:8001", "error": "x"},
    "config_test": {"ok": True, "output": "", "error": ""},
    "interfaces_configured": ["eth0"], "interface_missing": [],
    "subnets": [{"id": 1, "subnet": "10.0.1.0/24", "pools": []}],
    "lease_db": {"path": "/var/lib/kea/x.csv", "exists": True, "leases": 3},
    "listeners": {"dhcp4": ["0.0.0.0:67"], "control_agent": [], "error": ""},
    "last_errors": ["something"], "recommendations": ["Kea node 'kea-b' ..."],
    "diagnostics_source": "kea-a",
    "members": {"kea-a": {"status": "SUCCESS", "healthy": True}},
    "cluster": {
        "enabled": True, "mode": "hot-standby", "state": "degraded",
        "healthy": False, "config_converged": False, "member_count": 2,
        "healthy_count": 1,
        "peers": [{"name": "kea-a", "url": "http://10.0.1.10:8001/",
                   "role": "primary"}],
        "members": [
            {"id": "kea-a", "host": "10.0.1.10", "connected": True,
             "health": "healthy", "ha_role": "primary", "ha_state": "hot-standby",
             "ha_enabled": True, "config_digest": "abc", "error": ""},
            {"id": "kea-b", "host": "10.0.1.11", "connected": False,
             "health": "unreachable", "ha_role": "standby", "ha_state": "unknown",
             "ha_enabled": False, "config_digest": None, "error": "gone"},
        ],
        "last_apply": {"status": "PARTIAL", "errors": {"kea-b": "refused"}},
        "recommendations": ["Kea node 'kea-b' is not reachable"],
    },
}


def test_admin_sees_the_full_dhcp_ha_block():
    hub = FakeHub({"dhcp-1": {"DHCP_DIAGNOSTICS": _DHCP_DIAG}})
    body = _client(ADMIN, hub).get("/api/dhcp/diagnostics").json()
    assert body["cluster"]["peers"][0]["url"].startswith("http://10.0.1.10")
    assert body["cluster"]["last_apply"]["status"] == "PARTIAL"


def test_non_admin_keeps_the_ha_verdict_but_loses_the_node_detail():
    hub = FakeHub({"dhcp-1": {"DHCP_DIAGNOSTICS": _DHCP_DIAG}})
    body = _client(TENANT, hub).get("/api/dhcp/diagnostics").json()
    cluster = body["cluster"]
    assert cluster["state"] == "degraded" and cluster["config_converged"] is False
    assert cluster["mode"] == "hot-standby" and cluster["healthy_count"] == 1
    assert [m["health"] for m in cluster["members"]] == ["healthy", "unreachable"]
    for member in cluster["members"]:
        assert "host" not in member and "config_digest" not in member
        assert "error" not in member
    assert cluster["peers"] == [] and cluster["last_apply"] == {}
    assert body["members"] == {}
    assert body["last_errors"] == []


def test_single_host_diagnostics_are_untouched_by_the_cluster_redaction():
    """A module with no cluster block must produce exactly the same body as
    before this feature — for admins and tenant users alike."""
    plain = {k: v for k, v in _DNS_DIAG.items()
             if k not in ("cluster", "members", "diagnostics_source")}
    hub = FakeHub({"dns-1": {"DNS_DIAGNOSTICS": plain}})
    admin_body = _client(ADMIN, hub).get("/api/dns/diagnostics").json()
    assert admin_body == plain
    tenant_body = _client(TENANT, hub).get("/api/dns/diagnostics").json()
    assert "cluster" not in tenant_body and "members" not in tenant_body
    assert tenant_body["service"] == {"ok": True}


def test_non_admin_sees_which_nodes_have_not_reported_config():
    """REGRESSION (review #12): 'unknown' and 'mismatched' are different
    verdicts and both must survive redaction."""
    diag = {**_DHCP_DIAG, "cluster": {**_DHCP_DIAG["cluster"],
                                      "config_digests_missing": ["kea-b"]}}
    hub = FakeHub({"dhcp-1": {"DHCP_DIAGNOSTICS": diag}})
    body = _client(TENANT, hub).get("/api/dhcp/diagnostics").json()
    assert body["cluster"]["config_digests_missing"] == ["kea-b"]
    assert body["cluster"]["config_converged"] is False


# ── Review round 2, #15: the STATUS endpoints redact like diagnostics ──────

_DNS_CLUSTER_REPORT = {
    "status": "SUCCESS", "enabled": True, "state": "partial", "converged": False,
    "member_count": 2, "converged_count": 1,
    "desired": {"version": 4, "digest": "deadbeef", "record_count": 3},
    "members": [
        {"id": "dns-a", "host": "10.0.1.1", "connected": True,
         "convergence": "converged", "applied_digest": "deadbeef"},
        {"id": "dns-b", "host": "10.0.1.2", "connected": False,
         "convergence": "unreachable", "applied_digest": None},
    ],
    "last_commit": {"status": "PARTIAL", "errors": {"dns-b": "no response"}},
    "recommendations": ["Resolver 'dns-b' is not connected"],
}

_DHCP_HA_REPORT = {
    "status": "SUCCESS", "enabled": True, "mode": "hot-standby",
    "state": "degraded", "healthy": False, "config_converged": False,
    "member_count": 2, "healthy_count": 1,
    "peers": [{"name": "kea-a", "url": "https://10.0.1.10:8002/",
               "role": "primary", "basic-auth": True}],
    "members": [
        {"id": "kea-a", "host": "10.0.1.10", "connected": True,
         "health": "healthy", "ha_role": "primary", "config_digest": "abc",
         "error": ""},
        {"id": "kea-b", "host": "10.0.1.11", "connected": False,
         "health": "unreachable", "ha_role": "standby", "config_digest": None,
         "error": "gone"},
    ],
    "last_apply": {"status": "PARTIAL", "errors": {"kea-b": "refused"}},
    "recommendations": ["Kea node 'kea-b' is not reachable"],
}


def test_admin_sees_the_full_dns_cluster_status():
    hub = FakeHub({"dns-1": {"DNS_CLUSTER_STATUS": _DNS_CLUSTER_REPORT}})
    body = _client(ADMIN, hub).get("/api/dns/cluster").json()
    assert body["members"][0]["host"] == "10.0.1.1"
    assert body["last_commit"]["status"] == "PARTIAL"
    assert body["desired"]["digest"] == "deadbeef"


def test_non_admin_dns_cluster_status_is_redacted_like_diagnostics():
    """REGRESSION: a status endpoint that skipped the redaction handed a tenant
    exactly what the diagnostics endpoint withholds."""
    hub = FakeHub({"dns-1": {"DNS_CLUSTER_STATUS": _DNS_CLUSTER_REPORT}})
    body = _client(TENANT, hub).get("/api/dns/cluster").json()
    assert body["state"] == "partial" and body["converged"] is False
    assert body["converged_count"] == 1
    for member in body["members"]:
        assert "host" not in member and "applied_digest" not in member
    assert body["last_commit"] == {}
    assert "digest" not in body["desired"]
    assert body["desired"]["version"] == 4


def test_admin_sees_the_full_dhcp_ha_status():
    hub = FakeHub({"dhcp-1": {"DHCP_HA_STATUS": _DHCP_HA_REPORT}})
    body = _client(ADMIN, hub).get("/api/dhcp/ha").json()
    assert body["peers"][0]["url"].startswith("https://10.0.1.10")
    assert body["last_apply"]["status"] == "PARTIAL"


def test_non_admin_dhcp_ha_status_is_redacted_like_diagnostics():
    hub = FakeHub({"dhcp-1": {"DHCP_HA_STATUS": _DHCP_HA_REPORT}})
    body = _client(TENANT, hub).get("/api/dhcp/ha").json()
    assert body["mode"] == "hot-standby" and body["state"] == "degraded"
    assert body["peers"] == [] and body["last_apply"] == {}
    for member in body["members"]:
        assert "host" not in member and "config_digest" not in member
        assert "error" not in member


def test_a_disabled_cluster_status_survives_redaction():
    hub = FakeHub({"dns-1": {"DNS_CLUSTER_STATUS": {
        "status": "SUCCESS", "enabled": False, "members": [], "member_count": 0,
        "reason": "fewer than two resolver members configured"}}})
    body = _client(TENANT, hub).get("/api/dns/cluster").json()
    assert body["enabled"] is False
    assert body["reason"] == "fewer than two resolver members configured"
