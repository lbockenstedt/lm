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
        return "shared"

    def _mark_dirty(self):
        pass


class FakeHub:
    def __init__(self, replies=None):
        self.active_connections = {"dns-1", "dhcp-1"}
        self.approved_modules = {"dns-1": True, "dhcp-1": True}
        self.state = FakeState()
        self.replies = replies or {}
        self.forwarded = []
        self.spoke_module_types = {"dns-worker-agent": "agent"}
        self.spoke_parent_map = {}
        self.spoke_telemetry = {
            "dns-worker-agent": {"remote_ip": "10.0.0.11"},
        }

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


def test_dns_forwarder_post_relays_zone_and_upstreams():
    hub = FakeHub({"dns-1": {"DNS_FORWARDER_ADD": {
        "status": "SUCCESS", "zone": ".", "upstreams": ["1.1.1.1"]}}})

    response = _client(ADMIN, hub).post(
        "/api/dns/forwarders",
        json={"zone": ".", "upstreams": ["1.1.1.1"]},
    )

    assert response.status_code == 200
    assert hub.forwarded[-1] == (
        "dns-1",
        "DNS_FORWARDER_ADD",
        {"zone": ".", "upstreams": ["1.1.1.1"]},
    )


def test_dns_worker_discovery_enrolls_installed_server_role_without_user_secret():
    cert = "-----BEGIN CERTIFICATE-----\npublic\n-----END CERTIFICATE-----"
    hub = FakeHub({
        "dns-1": {
            "DNS_CLUSTER_STATUS": {
                "status": "SUCCESS", "enabled": False, "members": []},
            "DNS_CLUSTER_ENROLL_WORKER": {
                "status": "SUCCESS",
                "coordinator": "dns-management.example",
                "worker_secret": "generated-inside-dns-management",
                "coordinator_ca_pem": cert,
            },
        },
        "dns-worker-agent": {
            "GET_AVAILABLE_ROLES": {
                "status": "SUCCESS",
                "installed_deploy_roles": ["dns-server"],
                "active_deploy_roles": ["dns-server"],
                "configured_worker_roles": [],
                "configured_workers": [],
                "service_addresses": ["10.0.0.11"],
            },
            "LOAD_ROLE": {
                "status": "SUCCESS",
                "message": "Deployment of 'dns-server' started in background",
            },
        },
    })
    hub.active_connections.add("dns-worker-agent")

    r = _client(ADMIN, hub).post("/api/dns/cluster/discover")

    assert r.status_code == 200
    assert r.json()["workers"][0]["status"] == "configuring"
    load = next(call for call in hub.forwarded
                if call[:2] == ("dns-worker-agent", "LOAD_ROLE"))
    config = load[2]["config"]
    assert config["member_id"] == "dns-worker-agent"
    assert config["worker_secret"] == "generated-inside-dns-management"
    assert config["coordinator_ca_pem"] == cert
    saved = hub.state.system_state["global_config"]["dns_instances"][0]
    assert saved["discovered"] is True
    assert "worker_secret" not in saved


def test_dns_worker_discovery_restores_inventory_for_healthy_existing_worker():
    hub = FakeHub({
        "dns-1": {
            "DNS_CLUSTER_STATUS": {
                "status": "SUCCESS",
                "enabled": True,
                "members": [{
                    "id": "dns-worker-agent",
                    "host": "10.0.0.11",
                    "connected": True,
                }],
                "desired": {"version": 1},
            },
        },
        "dns-worker-agent": {
            "GET_AVAILABLE_ROLES": {
                "status": "SUCCESS",
                "installed_deploy_roles": ["dns-server"],
                "active_deploy_roles": ["dns-server"],
                "configured_worker_roles": ["dns-server"],
                "configured_workers": [{
                    "role": "dns-server",
                    "member_id": "dns-worker-agent",
                }],
                "service_addresses": ["10.0.0.11"],
            },
        },
    })
    hub.active_connections.add("dns-worker-agent")
    hub.state.system_state["module_names"] = {
        "dns-worker-agent": "MIPBE-SVCS2",
    }

    r = _client(ADMIN, hub).post("/api/dns/cluster/discover")

    assert r.status_code == 200
    assert r.json()["workers"] == [{
        "spoke_id": "dns-worker-agent",
        "status": "already-configured",
    }]
    assert not any(cmd == "LOAD_ROLE" for _sid, cmd, _payload in hub.forwarded)
    assert hub.state.system_state["global_config"]["dns_instances"] == [{
        "id": "discovered-dns-worker-agent",
        "name": "MIPBE-SVCS2",
        "member_id": "dns-worker-agent",
        "host": "10.0.0.11",
        "spoke_id": "dns-1",
        "tenant_id": "shared",
        "source_agent_id": "dns-worker-agent",
        "discovered": True,
    }]


def test_dns_worker_discovery_finalizes_once_after_all_workers_are_connected():
    hub = FakeHub()
    hub.spoke_module_types = {"dns-a-agent": "agent", "dns-b-agent": "agent"}
    hub.active_connections.update(hub.spoke_module_types)
    hub.spoke_telemetry = {
        "dns-a-agent": {"remote_ip": "10.0.0.11"},
        "dns-b-agent": {"remote_ip": "10.0.0.12"},
    }
    members = []

    async def request_response(sid, cmd, payload=None, timeout=None):
        hub.forwarded.append((sid, cmd, payload))
        if cmd == "GET_AVAILABLE_ROLES":
            data = {
                "status": "SUCCESS",
                "installed_deploy_roles": ["dns-server"],
                "active_deploy_roles": ["dns-server"],
                "configured_worker_roles": [],
                "configured_workers": [],
                "service_addresses": [
                    "10.0.0.11" if sid == "dns-a-agent" else "10.0.0.12"],
            }
        elif cmd == "DNS_CLUSTER_ENROLL_WORKER":
            members.append({"id": payload["member"]["id"], "connected": True})
            data = {
                "status": "SUCCESS",
                "coordinator": "dns-management.example",
                "worker_secret": "generated-secret",
                "coordinator_ca_pem": (
                    "-----BEGIN CERTIFICATE-----\npublic\n"
                    "-----END CERTIFICATE-----"),
            }
        elif cmd == "DNS_CLUSTER_STATUS":
            data = {
                "status": "SUCCESS",
                "enabled": bool(members),
                "members": list(members),
                "desired": {"version": 0},
            }
        elif cmd == "DNS_CLUSTER_FINALIZE_ENROLLMENT":
            data = {"status": "SUCCESS", "version": 1}
        elif cmd == "LOAD_ROLE":
            data = {"status": "SUCCESS", "deploy": False}
        else:
            raise AssertionError(cmd)
        return {"payload": {"data": data}}

    hub.request_response = request_response
    r = _client(ADMIN, hub).post("/api/dns/cluster/discover")

    assert r.status_code == 200
    commands = [(sid, cmd) for sid, cmd, _payload in hub.forwarded]
    finalize_index = commands.index(("dns-1", "DNS_CLUSTER_FINALIZE_ENROLLMENT"))
    assert finalize_index > commands.index(("dns-a-agent", "LOAD_ROLE"))
    assert finalize_index > commands.index(("dns-b-agent", "LOAD_ROLE"))
    assert len([cmd for _sid, cmd in commands
                if cmd == "DNS_CLUSTER_FINALIZE_ENROLLMENT"]) == 1


def test_dns_worker_discovery_never_uses_public_websocket_source_address():
    hub = FakeHub({
        "dns-1": {
            "DNS_CLUSTER_STATUS": {
                "status": "SUCCESS", "enabled": False, "members": []},
        },
        "dns-worker-agent": {
            "GET_AVAILABLE_ROLES": {
                "status": "SUCCESS",
                "installed_deploy_roles": ["dns-server"],
                "active_deploy_roles": ["dns-server"],
                "configured_worker_roles": [],
                "configured_workers": [],
                "service_addresses": [],
            },
        },
    })
    hub.active_connections.add("dns-worker-agent")
    hub.spoke_telemetry["dns-worker-agent"] = {
        "remote_ip": "104.36.251.61"}

    r = _client(ADMIN, hub).post("/api/dns/cluster/discover")

    assert r.status_code == 502
    assert "refusing to use its public/NAT" in r.json()["detail"]
    assert not any(cmd == "DNS_CLUSTER_ENROLL_WORKER"
                   for _sid, cmd, _payload in hub.forwarded)


def test_dns_worker_discovery_repairs_connected_member_with_stale_public_host():
    hub = FakeHub({
        "dns-1": {
            "DNS_CLUSTER_STATUS": {
                "status": "SUCCESS",
                "enabled": True,
                "members": [{
                    "id": "dns-worker-agent",
                    "host": "104.36.251.61",
                    "connected": True,
                }],
                "desired": {"version": 1},
            },
            "DNS_CLUSTER_ENROLL_WORKER": {
                "status": "SUCCESS",
                "coordinator": "dns-management.example",
                "worker_secret": "generated-secret",
                "coordinator_ca_pem": (
                    "-----BEGIN CERTIFICATE-----\npublic\n"
                    "-----END CERTIFICATE-----"),
            },
        },
        "dns-worker-agent": {
            "GET_AVAILABLE_ROLES": {
                "status": "SUCCESS",
                "installed_deploy_roles": ["dns-server"],
                "active_deploy_roles": ["dns-server"],
                "configured_worker_roles": ["dns-server"],
                "configured_workers": [{
                    "role": "dns-server",
                    "member_id": "dns-worker-agent",
                }],
                "service_addresses": ["10.0.0.11"],
            },
            "LOAD_ROLE": {"status": "SUCCESS", "deploy": False},
        },
    })
    hub.active_connections.add("dns-worker-agent")

    r = _client(ADMIN, hub).post("/api/dns/cluster/discover")

    assert r.status_code == 200
    enrollment = next(
        call for call in hub.forwarded
        if call[:2] == ("dns-1", "DNS_CLUSTER_ENROLL_WORKER"))
    assert enrollment[2]["member"]["host"] == "10.0.0.11"


def test_dns_worker_discovery_uses_dns_parent_private_address_as_coordinator():
    cert = "-----BEGIN CERTIFICATE-----\npublic\n-----END CERTIFICATE-----"
    hub = FakeHub({
        "dns-1": {
            "DNS_CLUSTER_STATUS": {
                "status": "SUCCESS", "enabled": False, "members": []},
            "DNS_CLUSTER_ENROLL_WORKER": {
                "status": "SUCCESS",
                "coordinator": "unresolvable-hostname",
                "worker_secret": "generated-secret",
                "coordinator_ca_pem": cert,
            },
        },
        "dns-manager-agent": {
            "GET_AVAILABLE_ROLES": {
                "status": "SUCCESS",
                "installed_deploy_roles": [],
                "active_deploy_roles": [],
                "service_addresses": ["172.17.1.10"],
            },
        },
        "dns-worker-agent": {
            "GET_AVAILABLE_ROLES": {
                "status": "SUCCESS",
                "installed_deploy_roles": ["dns-server"],
                "active_deploy_roles": ["dns-server"],
                "configured_worker_roles": [],
                "configured_workers": [],
                "service_addresses": ["172.17.1.11"],
            },
            "LOAD_ROLE": {"status": "SUCCESS", "deploy": False},
        },
    })
    hub.spoke_module_types["dns-manager-agent"] = "agent"
    hub.active_connections.add("dns-manager-agent")
    hub.active_connections.add("dns-worker-agent")
    hub.spoke_parent_map["dns-1"] = "dns-manager-agent"

    r = _client(ADMIN, hub).post("/api/dns/cluster/discover")

    assert r.status_code == 200
    load = next(call for call in hub.forwarded
                if call[:2] == ("dns-worker-agent", "LOAD_ROLE"))
    assert load[2]["config"]["coordinator"] == "172.17.1.10"


def test_dns_worker_discovery_waits_for_existing_dns_deployment(monkeypatch):
    hub = FakeHub()
    hub.active_connections.add("dns-worker-agent")
    deployment_checks = 0

    async def no_sleep(_seconds):
        pass

    async def request_response(sid, cmd, payload=None, timeout=None):
        nonlocal deployment_checks
        hub.forwarded.append((sid, cmd, payload))
        if cmd == "GET_AVAILABLE_ROLES":
            data = {
                "status": "SUCCESS",
                "installed_deploy_roles": ["dns-server"],
                "active_deploy_roles": ["dns-server"],
                "configured_worker_roles": [],
                "configured_workers": [],
                "service_addresses": ["172.17.1.11"],
            }
        elif cmd == "DNS_CLUSTER_ENROLL_WORKER":
            data = {
                "status": "SUCCESS",
                "coordinator": "172.17.1.10",
                "worker_secret": "generated-secret",
                "coordinator_ca_pem": (
                    "-----BEGIN CERTIFICATE-----\npublic\n"
                    "-----END CERTIFICATE-----"),
            }
        elif cmd == "LOAD_ROLE":
            data = {
                "status": "ERROR",
                "message": "A deployment is already running",
            }
        elif cmd == "GET_DEPLOY_STATUS":
            deployment_checks += 1
            data = {
                "status": "SUCCESS",
                "active_role": "dns-server",
                "deploy": {
                    "role": "dns-server",
                    "state": "running" if deployment_checks == 1 else "completed",
                },
            }
        elif cmd == "DNS_CLUSTER_STATUS":
            data = {
                "status": "SUCCESS",
                "enabled": True,
                "members": [{
                    "id": "dns-worker-agent",
                    "host": "172.17.1.11",
                    "connected": deployment_checks > 1,
                }],
                "desired": {"version": 1},
            }
        else:
            raise AssertionError(cmd)
        return {"payload": {"data": data}}

    monkeypatch.setattr("routes.net_services.asyncio.sleep", no_sleep)
    hub.request_response = request_response

    r = _client(ADMIN, hub).post("/api/dns/cluster/discover")

    assert r.status_code == 200
    assert r.json()["workers"][0]["status"] == "configured"
    assert deployment_checks == 2


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


def test_dhcp_worker_discovery_configures_exactly_two_server_roles():
    hub = FakeHub()
    hub.spoke_module_types = {
        "dhcp-a-agent": "agent",
        "dhcp-b-agent": "agent",
    }
    hub.active_connections.update(hub.spoke_module_types)
    cert = "-----BEGIN CERTIFICATE-----\npublic\n-----END CERTIFICATE-----"
    key = "-----BEGIN PRIVATE KEY-----\nprivate\n-----END PRIVATE KEY-----"
    calls = 0

    async def request_response(sid, cmd, payload=None, timeout=None):
        nonlocal calls
        hub.forwarded.append((sid, cmd, payload))
        if cmd == "GET_AVAILABLE_ROLES":
            data = {
                "status": "SUCCESS",
                "installed_deploy_roles": ["dhcp-server"],
                "active_deploy_roles": ["dhcp-server"],
                "configured_worker_roles": [],
                "configured_workers": [],
                "service_addresses": [
                    "10.0.1.10" if sid == "dhcp-a-agent" else "10.0.1.11"],
            }
        elif cmd == "DHCP_HA_STATUS":
            calls += 1
            data = {
                "status": "SUCCESS",
                "enabled": calls > 1,
                "members": [] if calls == 1 else [
                    {"id": "dhcp-a-agent", "host": "10.0.1.10",
                     "connected": True},
                    {"id": "dhcp-b-agent", "host": "10.0.1.11",
                     "connected": True},
                ],
            }
        elif cmd == "DHCP_HA_ENROLL_WORKERS":
            data = {
                "status": "SUCCESS",
                "workers": {
                    member["id"]: {
                        "member_id": member["id"],
                        "coordinator": "dhcp-management.example",
                        "worker_secret": "worker-secret",
                        "coordinator_ca_pem": cert,
                        "ha_user": "kea-ha",
                        "ha_password": "ha-secret",
                        "ha_ca_pem": cert,
                        "ha_cert_pem": cert,
                        "ha_key_pem": key,
                        "ha_peers": [
                            other["host"] for other in payload["members"]
                            if other["id"] != member["id"]],
                    }
                    for member in payload["members"]
                },
            }
        elif cmd == "DHCP_HA_COMMIT_ENROLLMENT":
            data = {"status": "SUCCESS"}
        elif cmd == "LOAD_ROLE":
            data = {"status": "SUCCESS", "deploy": False}
        else:
            raise AssertionError(cmd)
        return {"payload": {"data": data}}

    hub.request_response = request_response
    response = _client(ADMIN, hub).post("/api/dhcp/ha/discover")

    assert response.status_code == 200
    assert response.json()["cluster_ready"] is True
    assert [worker["status"] for worker in response.json()["workers"]] == [
        "configured", "configured"]
    enrollment = next(call for call in hub.forwarded
                      if call[:2] == ("dhcp-1", "DHCP_HA_ENROLL_WORKERS"))
    assert [member["host"] for member in enrollment[2]["members"]] == [
        "10.0.1.10", "10.0.1.11"]
    loads = [call for call in hub.forwarded if call[1] == "LOAD_ROLE"]
    assert len(loads) == 2
    assert loads[0][2]["config"]["ha_key_pem"] == key
    assert hub.state.system_state["global_config"]["dhcp_instances"][0][
        "discovered"] is True


def test_dhcp_worker_deploy_polling_ignores_a_stale_unrelated_role_failure(monkeypatch):
    """Regression: GET_DEPLOY_STATUS's singular ``deploy`` field is just the
    MOST-RECENTLY-STARTED deploy role on that agent (agent_spoke.py's
    ``_deploy_status_by_role``), not necessarily the one this poll loop cares
    about. An agent that once ran ``netbox-server`` (which then failed, or is
    simply an older entry in the dict) and is NOW deploying ``dhcp-server``
    must not have the DHCP enrollment loop read netbox-server's stale
    'failed' tail and report "DHCP worker configuration failed" — it should
    key off ``deploys`` (the per-role map) and only look at the entry whose
    ``role`` is ``dhcp-server``."""
    hub = FakeHub()
    hub.spoke_module_types = {
        "dhcp-a-agent": "agent",
        "dhcp-b-agent": "agent",
    }
    hub.active_connections.update(hub.spoke_module_types)
    cert = "-----BEGIN CERTIFICATE-----\npublic\n-----END CERTIFICATE-----"
    key = "-----BEGIN PRIVATE KEY-----\nprivate\n-----END PRIVATE KEY-----"
    ha_calls = 0
    deploy_checks = {"dhcp-a-agent": 0, "dhcp-b-agent": 0}

    async def no_sleep(_seconds):
        pass

    async def request_response(sid, cmd, payload=None, timeout=None):
        nonlocal ha_calls
        hub.forwarded.append((sid, cmd, payload))
        if cmd == "GET_AVAILABLE_ROLES":
            data = {
                "status": "SUCCESS",
                "installed_deploy_roles": ["dhcp-server"],
                "active_deploy_roles": ["dhcp-server"],
                "configured_worker_roles": [],
                "configured_workers": [],
                "service_addresses": [
                    "10.0.1.10" if sid == "dhcp-a-agent" else "10.0.1.11"],
            }
        elif cmd == "DHCP_HA_STATUS":
            ha_calls += 1
            data = {
                "status": "SUCCESS",
                "enabled": ha_calls > 1,
                "members": [] if ha_calls == 1 else [
                    {"id": "dhcp-a-agent", "host": "10.0.1.10",
                     "connected": True},
                    {"id": "dhcp-b-agent", "host": "10.0.1.11",
                     "connected": True},
                ],
            }
        elif cmd == "DHCP_HA_ENROLL_WORKERS":
            data = {
                "status": "SUCCESS",
                "workers": {
                    member["id"]: {
                        "member_id": member["id"],
                        "coordinator": "dhcp-management.example",
                        "worker_secret": "worker-secret",
                        "coordinator_ca_pem": cert,
                        "ha_user": "kea-ha",
                        "ha_password": "ha-secret",
                        "ha_ca_pem": cert,
                        "ha_cert_pem": cert,
                        "ha_key_pem": key,
                        "ha_peers": [
                            other["host"] for other in payload["members"]
                            if other["id"] != member["id"]],
                    }
                    for member in payload["members"]
                },
            }
        elif cmd == "DHCP_HA_COMMIT_ENROLLMENT":
            data = {"status": "SUCCESS"}
        elif cmd == "LOAD_ROLE":
            # Only "dhcp-b-agent" is mid-deploy; "dhcp-a-agent" loads clean.
            if sid == "dhcp-b-agent":
                data = {"status": "ERROR", "message": "A deployment is already running"}
            else:
                data = {"status": "SUCCESS", "deploy": False}
        elif cmd == "GET_DEPLOY_STATUS":
            deploy_checks[sid] += 1
            # A stale netbox-server failure sits ahead of the real dhcp-server
            # entry in ``deploys`` — the buggy code read the singular
            # ``deploy`` field (whichever role started MOST RECENTLY on this
            # agent) without checking its ``role`` matches "dhcp-server", so a
            # long-past failed netbox-server deploy could surface here as a
            # false "DHCP worker configuration failed".
            data = {
                "status": "SUCCESS",
                "active_role": "netbox-server",
                "deploy": {
                    "role": "netbox-server", "state": "failed",
                    "tail": "unrelated NetBox install output",
                },
                "deploys": [
                    {"role": "netbox-server", "state": "failed",
                     "tail": "unrelated NetBox install output"},
                    {"role": "dhcp-server",
                     "state": "running" if deploy_checks[sid] == 1 else "completed"},
                ],
            }
        else:
            raise AssertionError(cmd)
        return {"payload": {"data": data}}

    monkeypatch.setattr("routes.net_services.asyncio.sleep", no_sleep)
    hub.request_response = request_response

    response = _client(ADMIN, hub).post("/api/dhcp/ha/discover")

    assert response.status_code == 200
    assert [worker["status"] for worker in response.json()["workers"]] == [
        "configured", "configured"]
    assert deploy_checks["dhcp-b-agent"] == 2


def test_dhcp_worker_discovery_waits_until_two_servers_exist():
    hub = FakeHub({
        "dhcp-1": {"DHCP_HA_STATUS": {
            "status": "SUCCESS", "enabled": False, "members": []}},
        "dns-worker-agent": {"GET_AVAILABLE_ROLES": {
            "status": "SUCCESS",
            "installed_deploy_roles": ["dhcp-server"],
            "active_deploy_roles": ["dhcp-server"],
            "service_addresses": ["10.0.1.10"],
        }},
    })
    hub.active_connections.add("dns-worker-agent")

    response = _client(ADMIN, hub).post("/api/dhcp/ha/discover")

    assert response.status_code == 200
    assert response.json()["cluster_ready"] is False
    assert response.json()["workers"][0]["status"] == "waiting"
    assert not any(cmd == "DHCP_HA_ENROLL_WORKERS"
                   for _sid, cmd, _payload in hub.forwarded)


def test_dhcp_worker_discovery_is_global_admin_only():
    response = _client(TENANT, FakeHub()).post("/api/dhcp/ha/discover")
    assert response.status_code == 403


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


# ── DNS cluster member display_name ─────────────────────────────────────────
# The MEMBER column's primary label should be a human-friendly name, not the
# raw member id (typically a UUID/agent-id) — see docs/dns.md's "See it"
# paragraph and WebUI/main.js's _dnsClusterPanel. The id itself must never be
# dropped: it stays on the response (and, in the WebUI, as a secondary line +
# tooltip) so identity remains traceable.

def _report_with_two_live_members():
    return {
        "status": "SUCCESS", "enabled": True, "state": "converged",
        "converged": True, "member_count": 2, "converged_count": 2,
        "desired": {"version": 1, "record_count": 2},
        "members": [
            {"id": "dns-worker-agent-1", "host": "10.0.1.1", "connected": True,
             "convergence": "converged"},
            {"id": "dns-worker-agent-2", "host": "10.0.1.2", "connected": True,
             "convergence": "converged"},
        ],
        "last_commit": {"status": "SUCCESS"},
        "recommendations": [],
    }


def test_dns_cluster_status_names_members_from_the_managed_device_inventory():
    """Primary source: dns_instances (the DNS managed-device inventory
    discovery already populates), matched by member_id."""
    hub = FakeHub({"dns-1": {"DNS_CLUSTER_STATUS": _report_with_two_live_members()}})
    hub.state.system_state["global_config"]["dns_instances"] = [
        {"member_id": "dns-worker-agent-1", "name": "MIPBE-SVCS1"},
        {"member_id": "dns-worker-agent-2", "name": "MIPBE-SVCS2"},
    ]
    body = _client(ADMIN, hub).get("/api/dns/cluster").json()
    names = {m["id"]: m["display_name"] for m in body["members"]}
    assert names == {
        "dns-worker-agent-1": "MIPBE-SVCS1",
        "dns-worker-agent-2": "MIPBE-SVCS2",
    }
    # the raw id must survive alongside the name — traceability is preserved
    assert {m["id"] for m in body["members"]} == {
        "dns-worker-agent-1", "dns-worker-agent-2"}


def test_dns_cluster_status_falls_back_to_module_names_without_inventory():
    """A member added by hand via DNS_CLUSTER_CONFIG (never discovered, so no
    dns_instances entry) still gets named if the hub knows it as a spoke."""
    hub = FakeHub({"dns-1": {"DNS_CLUSTER_STATUS": _report_with_two_live_members()}})
    hub.state.system_state["module_names"] = {
        "dns-worker-agent-1": "MIPBE-SVCS1",
        "dns-worker-agent-2": "MIPBE-SVCS2",
    }
    body = _client(ADMIN, hub).get("/api/dns/cluster").json()
    names = {m["id"]: m["display_name"] for m in body["members"]}
    assert names == {
        "dns-worker-agent-1": "MIPBE-SVCS1",
        "dns-worker-agent-2": "MIPBE-SVCS2",
    }


def test_dns_cluster_status_falls_back_to_module_metadata_display_name():
    hub = FakeHub({"dns-1": {"DNS_CLUSTER_STATUS": _report_with_two_live_members()}})
    hub.state.system_state["module_metadata"] = {
        "dns-worker-agent-1": {"display_name": "MIPBE-SVCS1"},
    }
    body = _client(ADMIN, hub).get("/api/dns/cluster").json()
    names = {m["id"]: m["display_name"] for m in body["members"]}
    assert names["dns-worker-agent-1"] == "MIPBE-SVCS1"
    # no name known anywhere for member 2 -> falls back to its own id, exactly
    # the pre-existing behavior for an install with no naming data.
    assert names["dns-worker-agent-2"] == "dns-worker-agent-2"


def test_dns_cluster_status_display_name_defaults_to_id_with_no_naming_data():
    """Backward compatibility: an install with no module_names/metadata/
    inventory entries at all gets display_name == id, so an old UI that
    already only reads id sees nothing different, and a new UI has a safe
    field to read either way."""
    hub = FakeHub({"dns-1": {"DNS_CLUSTER_STATUS": _report_with_two_live_members()}})
    body = _client(ADMIN, hub).get("/api/dns/cluster").json()
    for m in body["members"]:
        assert m["display_name"] == m["id"]


def test_non_admin_dns_cluster_status_keeps_display_name_but_not_host():
    hub = FakeHub({"dns-1": {"DNS_CLUSTER_STATUS": _report_with_two_live_members()}})
    hub.state.system_state["global_config"]["dns_instances"] = [
        {"member_id": "dns-worker-agent-1", "name": "MIPBE-SVCS1"},
    ]
    body = _client(TENANT, hub).get("/api/dns/cluster").json()
    member = next(m for m in body["members"] if m["id"] == "dns-worker-agent-1")
    assert member["display_name"] == "MIPBE-SVCS1"
    assert "host" not in member


def test_dns_diagnostics_cluster_block_carries_display_name_for_admin():
    hub = FakeHub({"dns-1": {"DNS_DIAGNOSTICS": {
        "status": "SUCCESS", "healthy": True,
        "cluster": _report_with_two_live_members(),
        "members": {},
    }}})
    hub.state.system_state["module_names"] = {"dns-worker-agent-1": "MIPBE-SVCS1"}
    body = _client(ADMIN, hub).get("/api/dns/diagnostics").json()
    member = next(m for m in body["cluster"]["members"]
                  if m["id"] == "dns-worker-agent-1")
    assert member["display_name"] == "MIPBE-SVCS1"
    # unrelated diagnostics fields untouched for admin
    assert body["healthy"] is True


def test_dns_diagnostics_cluster_block_carries_display_name_for_non_admin():
    hub = FakeHub({"dns-1": {"DNS_DIAGNOSTICS": {
        "status": "SUCCESS", "healthy": True,
        "cluster": _report_with_two_live_members(),
        "members": {"dns-worker-agent-1": {"status": "SUCCESS"}},
    }}})
    hub.state.system_state["module_names"] = {"dns-worker-agent-1": "MIPBE-SVCS1"}
    body = _client(TENANT, hub).get("/api/dns/diagnostics").json()
    member = next(m for m in body["cluster"]["members"]
                  if m["id"] == "dns-worker-agent-1")
    assert member["display_name"] == "MIPBE-SVCS1"
    assert "host" not in member
    # non-admin redaction of the outer diagnostics body is unaffected
    assert body["members"] == {}


def test_dns_diagnostics_evidence_source_and_per_member_cards_use_display_name():
    """The per-member evidence cards (top-level ``members`` dict, keyed by
    raw id) and the "evidence below is from ..." source line used to show
    the raw UUID/agent-id even where the cluster table already resolved a
    friendly name. Both now carry the same display_name."""
    hub = FakeHub({"dns-1": {"DNS_DIAGNOSTICS": {
        "status": "SUCCESS", "healthy": True,
        "diagnostics_source": "dns-worker-agent-1",
        "cluster": _report_with_two_live_members(),
        "members": {
            "dns-worker-agent-1": {"status": "SUCCESS", "healthy": True},
            "dns-worker-agent-2": {"status": "ERROR", "message": "timeout"},
        },
        "recommendations": ["[dns-worker-agent-2] diagnostics unavailable: timeout"],
    }}})
    hub.state.system_state["module_names"] = {
        "dns-worker-agent-1": "MIPBE-SVCS1",
        "dns-worker-agent-2": "MIPBE-SVCS2",
    }
    body = _client(ADMIN, hub).get("/api/dns/diagnostics").json()
    assert body["diagnostics_source_name"] == "MIPBE-SVCS1"
    assert body["members"]["dns-worker-agent-1"]["display_name"] == "MIPBE-SVCS1"
    assert body["members"]["dns-worker-agent-2"]["display_name"] == "MIPBE-SVCS2"
    assert body["recommendations"] == ["[MIPBE-SVCS2] diagnostics unavailable: timeout"]


def test_dns_diagnostics_evidence_defaults_to_id_with_no_naming_data():
    hub = FakeHub({"dns-1": {"DNS_DIAGNOSTICS": {
        "status": "SUCCESS", "healthy": True,
        "diagnostics_source": "dns-worker-agent-1",
        "cluster": _report_with_two_live_members(),
        "members": {"dns-worker-agent-1": {"status": "SUCCESS"}},
    }}})
    body = _client(ADMIN, hub).get("/api/dns/diagnostics").json()
    assert body["diagnostics_source_name"] == "dns-worker-agent-1"
    assert body["members"]["dns-worker-agent-1"]["display_name"] == "dns-worker-agent-1"


def test_dhcp_diagnostics_evidence_source_and_per_member_cards_use_display_name():
    """Same UUID/agent-id -> friendly-name treatment as the DNS diagnostics
    endpoint, applied to the DHCP HA diagnostics screen: the 'evidence below
    is from ...' source line, per-member evidence cards, and per-member
    recommendation prefixes."""
    hub = FakeHub({"dhcp-1": {"DHCP_DIAGNOSTICS": {
        "status": "SUCCESS", "healthy": True,
        "diagnostics_source": "dhcp-worker-agent-1",
        "cluster": {"enabled": True, "mode": "hot-standby", "state": "healthy",
                    "member_count": 2, "healthy_count": 2,
                    "members": [
                        {"id": "dhcp-worker-agent-1", "health": "healthy"},
                        {"id": "dhcp-worker-agent-2", "health": "healthy"},
                    ]},
        "members": {
            "dhcp-worker-agent-1": {"status": "SUCCESS", "healthy": True},
            "dhcp-worker-agent-2": {"status": "ERROR", "message": "timeout"},
        },
        "recommendations": ["[dhcp-worker-agent-2] diagnostics unavailable: timeout"],
    }}})
    hub.state.system_state["module_names"] = {
        "dhcp-worker-agent-1": "MIPBE-SVCS1",
        "dhcp-worker-agent-2": "MIPBE-SVCS2",
    }
    body = _client(ADMIN, hub).get("/api/dhcp/diagnostics").json()
    assert body["diagnostics_source_name"] == "MIPBE-SVCS1"
    assert body["members"]["dhcp-worker-agent-1"]["display_name"] == "MIPBE-SVCS1"
    assert body["members"]["dhcp-worker-agent-2"]["display_name"] == "MIPBE-SVCS2"
    assert body["recommendations"] == ["[MIPBE-SVCS2] diagnostics unavailable: timeout"]
    assert body["cluster"]["members"][0]["display_name"] == "MIPBE-SVCS1"
    assert body["cluster"]["members"][1]["display_name"] == "MIPBE-SVCS2"


def test_dhcp_diagnostics_evidence_defaults_to_id_with_no_naming_data():
    hub = FakeHub({"dhcp-1": {"DHCP_DIAGNOSTICS": {
        "status": "SUCCESS", "healthy": True,
        "diagnostics_source": "dhcp-worker-agent-1",
        "cluster": {"enabled": True, "mode": "hot-standby", "state": "healthy",
                    "member_count": 1, "healthy_count": 1,
                    "members": [{"id": "dhcp-worker-agent-1", "health": "healthy"}]},
        "members": {"dhcp-worker-agent-1": {"status": "SUCCESS"}},
    }}})
    body = _client(ADMIN, hub).get("/api/dhcp/diagnostics").json()
    assert body["diagnostics_source_name"] == "dhcp-worker-agent-1"
    assert body["members"]["dhcp-worker-agent-1"]["display_name"] == "dhcp-worker-agent-1"


def test_dhcp_ha_status_carries_display_name_per_member():
    hub = FakeHub({"dhcp-1": {"DHCP_HA_STATUS": {
        "status": "SUCCESS", "enabled": True, "mode": "hot-standby",
        "state": "healthy", "healthy": True, "config_converged": True,
        "member_count": 2, "healthy_count": 2,
        "members": [
            {"id": "kea-a", "health": "healthy"},
            {"id": "kea-b", "health": "healthy"},
        ],
        "recommendations": [],
    }}})
    hub.state.system_state["module_names"] = {"kea-a": "MIPBE-SVCS1", "kea-b": "MIPBE-SVCS2"}
    body = _client(ADMIN, hub).get("/api/dhcp/ha").json()
    assert body["members"][0]["display_name"] == "MIPBE-SVCS1"
    assert body["members"][1]["display_name"] == "MIPBE-SVCS2"


def test_dhcp_diagnostics_kea_node_quoted_ids_and_missing_config_list_resolve_to_names():
    """kea_ha.py's HA-pair-level recommendations use \"Kea node '<id>' ...\" and
    \"Configuration state is unknown for: <id>, <id>\" formats (not the
    '[<id>] ...' per-member prefix) — both must also resolve to friendly names."""
    hub = FakeHub({"dhcp-1": {"DHCP_DIAGNOSTICS": {
        "status": "SUCCESS", "healthy": False,
        "diagnostics_source": "kea-a",
        "cluster": {"enabled": True, "mode": "hot-standby", "state": "down",
                    "member_count": 2, "healthy_count": 0,
                    "members": [{"id": "kea-a", "health": "unreachable"},
                                {"id": "kea-b", "health": "unreachable"}]},
        "members": {"kea-a": {"status": "SUCCESS"}},
        "recommendations": [
            "Kea node 'kea-b' is not reachable through the DHCP module; "
            "check lm-dhcp-worker and kea-ctrl-agent on that host.",
            "Configuration state is unknown for: kea-a, kea-b — the pair "
            "cannot be confirmed converged until every node reports its "
            "running configuration.",
        ],
    }}})
    hub.state.system_state["module_names"] = {"kea-a": "MIPBE-SVCS1", "kea-b": "MIPBE-SVCS2"}
    body = _client(ADMIN, hub).get("/api/dhcp/diagnostics").json()
    assert "kea-b" not in body["recommendations"][0]
    assert "MIPBE-SVCS2" in body["recommendations"][0]
    assert "kea-a" not in body["recommendations"][1] and "kea-b" not in body["recommendations"][1]
    assert "MIPBE-SVCS1" in body["recommendations"][1] and "MIPBE-SVCS2" in body["recommendations"][1]
