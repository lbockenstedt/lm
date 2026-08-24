"""Fleet Health keys on API CHECK-IN, correlated to the running sim-VM set.

The old metric counted ``online AND gateway_reachable`` ÷ registered clients.
That showed 0% for a fleet whose clients report to the API but never associate
to an SSID by design (gateway_reachable false), and it hid VMs whose client
never checked in at all (they have no registry row, so they fell out of the
denominator). The new metric:

  * working  = a RUNNING sim VM whose same-hostname client is online (checked in)
  * eligible = the running sim VMs the hypervisor reports (the expected pool)
  * not_reporting = running sim VMs with no live client (the reclone candidates)
  * gateway_reachable is IGNORED (connectivity-breaking sims still beacon)

with a safe fallback to the registry metric when there's no VM telemetry, or
when VM names don't correlate to any online client (a name↔hostname mismatch
that must not surface as a false 0%).
"""
import asyncio

from simulations.service import SimulationsService


class _State:
    def __init__(self, agent_config, spoke_tenants):
        self.system_state = {"agent_config": agent_config,
                             "module_metadata": spoke_tenants}

    def get_spoke_tenant(self, sid):
        return self.system_state["module_metadata"].get(sid, {}).get("tenant_id")


class _Hub:
    def __init__(self, cache, agent_config=None, spoke_tenants=None):
        self.simulations_cache = cache
        self.active_connections = {}
        self.spoke_id_alias = {}
        self.state = _State(agent_config or {}, spoke_tenants or {})

    def _primary_key(self, spoke_id):
        return self.spoke_id_alias.get(spoke_id, spoke_id)


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def _vm(vmid, name, status="running"):
    return {"vmid": vmid, "name": name, "status": status}


def _client(hostname, online=True, gateway_reachable=False, sims=None):
    return {"hostname": hostname, "online": online,
            "gateway_reachable": gateway_reachable,
            "active_simulations": sims or []}


def _cache(spoke_id, clients, vms):
    return {spoke_id: {
        "spoke_name": "cs-svr-01-spoke",
        "clients": clients,
        "proxmox_hosts": [{"hostname": "pxmx-cs-svr-01", "proxmox_vms": vms}],
    }}


def _svc(cache, agent_config=None):
    hub = _Hub(cache, agent_config or {},
               spoke_tenants={"cs-svr-01-spoke": {"tenant_id": "lrb"}})
    return SimulationsService(hub)


def _fh(cache, agent_config=None):
    return _run(_svc(cache, agent_config).get_clients_data("lrb"))["fleet_health"]


# ── API check-in, gateway_reachable ignored ─────────────────────────────────

def test_online_clients_count_even_with_gateway_unreachable():
    """The reported bug: clients check into the API but never reach a gateway
    (they run auth_fail etc.). They MUST count as working — not 0%."""
    clients = [_client("c90001", online=True, gateway_reachable=False,
                       sims=["auth_fail"]),
               _client("c90002", online=True, gateway_reachable=False)]
    vms = [_vm(90001, "c90001"), _vm(90002, "c90002")]
    fh = _fh(_cache("cs-svr-01-spoke", clients, vms))
    assert fh["basis"] == "vm_checkin"
    assert fh["working"] == 2
    assert fh["eligible"] == 2
    assert fh["pct"] == 100.0
    assert fh["not_reporting"] == 0
    assert fh["status"] == "ok"


# ── the VM/client gap: running VMs whose client never checked in ────────────

def test_never_reporting_vm_counts_against_health():
    """100 VMs / 68 clients: VMs that boot but never check in count against
    health (and are the reclone candidates), instead of being invisible."""
    clients = [_client("c90001", online=True),
               _client("c90002", online=True)]
    vms = [_vm(90001, "c90001"), _vm(90002, "c90002"),
           _vm(90003, "c90003"), _vm(90004, "c90004")]  # two never checked in
    fh = _fh(_cache("cs-svr-01-spoke", clients, vms))
    assert fh["basis"] == "vm_checkin"
    assert fh["working"] == 2
    assert fh["eligible"] == 4
    assert fh["not_reporting"] == 2
    assert fh["pct"] == 50.0
    assert fh["status"] == "critical"
    # The two silent VMs are named so the Clients/Offline view can synthesize a
    # verifiable "never checked in" row for each (they have no client record).
    names = {n["hostname"]: n["vmid"] for n in fh["not_reporting_names"]}
    assert names == {"c90003": 90003, "c90004": 90004}


def test_offline_client_is_not_reporting():
    """A registry row that exists but went silent (offline) is not working."""
    clients = [_client("c90001", online=True),
               _client("c90002", online=False)]
    vms = [_vm(90001, "c90001"), _vm(90002, "c90002")]
    fh = _fh(_cache("cs-svr-01-spoke", clients, vms))
    assert fh["working"] == 1
    assert fh["not_reporting"] == 1
    assert fh["pct"] == 50.0


# ── VM-set filtering ────────────────────────────────────────────────────────

def test_templates_lxc_and_subfloor_vms_excluded():
    clients = [_client("c90001", online=True)]
    vms = [_vm(90001, "c90001"),
           {"vmid": 90002, "name": "tmpl", "status": "running", "is_template": True},
           {"vmid": 90003, "name": "ct", "status": "running", "type": "lxc"},
           _vm(100, "infra"),            # below the sim floor
           _vm(90004, "stopped", status="stopped")]
    fh = _fh(_cache("cs-svr-01-spoke", clients, vms))
    assert fh["eligible"] == 1          # only the running sim VM
    assert fh["working"] == 1
    assert fh["pct"] == 100.0


def test_cs_disabled_host_vms_excluded_from_denominator():
    """The VM Server view hides CS-disabled hosts; their VMs must not deflate
    health against VMs the user can't see."""
    cache = {"cs-svr-01-spoke": {
        "spoke_name": "cs-svr-01-spoke",
        "clients": [_client("c90001", online=True)],
        "proxmox_hosts": [
            {"hostname": "pxmx-on", "proxmox_vms": [_vm(90001, "c90001")]},
            {"hostname": "pxmx-off", "proxmox_vms": [_vm(90002, "c90002")]},
        ],
    }}
    agent_config = {"pxmx-off": {"client_simulation": {"enabled": False}},
                    "pxmx-on": {"client_simulation": {"enabled": True}}}
    fh = _fh(cache, agent_config)
    assert fh["eligible"] == 1          # pxmx-off's VM excluded
    assert fh["working"] == 1
    assert fh["pct"] == 100.0


# ── fallbacks ───────────────────────────────────────────────────────────────

def test_fallback_to_registry_when_no_vm_telemetry():
    """No proxmox VM data → fall back to online-clients ÷ registered."""
    cache = {"cs-svr-01-spoke": {
        "spoke_name": "cs-svr-01-spoke",
        "clients": [_client("c1", online=True), _client("c2", online=False)],
    }}
    fh = _fh(cache)
    assert fh["basis"] == "client_checkin"
    assert fh["working"] == 1
    assert fh["eligible"] == 2
    assert fh["pct"] == 50.0


def test_name_mismatch_falls_back_instead_of_false_zero():
    """VMs exist and clients ARE checking in, but the VM names don't match any
    client hostname (a rename/correlation gap). Must NOT publish a false 0%."""
    clients = [_client("real-host-a", online=True),
               _client("real-host-b", online=True)]
    vms = [_vm(90001, "unmatched-x"), _vm(90002, "unmatched-y")]
    fh = _fh(_cache("cs-svr-01-spoke", clients, vms))
    assert fh["basis"] == "client_checkin"   # fell back
    assert fh["working"] == 2                 # both online clients
    assert fh["pct"] == 100.0


def test_no_data_when_empty():
    cache = {"cs-svr-01-spoke": {"spoke_name": "cs-svr-01-spoke", "clients": []}}
    fh = _fh(cache)
    assert fh["pct"] is None
    assert fh["status"] == "no_data"
