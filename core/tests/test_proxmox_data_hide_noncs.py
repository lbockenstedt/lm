"""get_proxmox_data hides CS-disabled agents' hosts + VMs everywhere in the cs app.

An agent attached to a cs spoke with ``client_simulation.enabled=false`` on the
hub must not show its host + VMs in the cs app (the bridge SKIPs it, so the user
can't act on its VMs — showing them is a dead end). The choke point is
``SimulationsService.get_proxmox_data`` (every VM Server child consumes
``csVmHosts = data.hosts`` from ``/aggregate/proxmox``); the Command Queue
renderer also filters on the visible-host set by ``target`` hostname, so hiding
a host drops its queued commands too.

Host rows carry the pxmx ``hostname`` (not ``agent_id``), so the filter joins
against ``agent_config`` by hostname (entries keyed by agent_id OR hostname —
tolerant, mirroring ``gateway/cs_bridge._agent_config_entry``). Unknown hosts
default to shown so a freshly-connected agent still appears while its config
row is created.
"""
import asyncio

from simulations.service import SimulationsService, _agent_cs_enabled


class _State:
    def __init__(self, agent_config, spoke_tenants):
        self.system_state = {"agent_config": agent_config, "module_metadata": spoke_tenants}

    def get_spoke_tenant(self, sid):
        return self.system_state["module_metadata"].get(sid, {}).get("tenant_id")


class _Hub:
    def __init__(self, cache, agent_config, spoke_tenants=None):
        self.simulations_cache = cache
        self.active_connections = {}  # spoke_online reads this; empty = offline is fine
        self.spoke_id_alias = {}  # Phase 2: _is_online resolves state keys via _primary_key
        self.state = _State(agent_config, spoke_tenants or {})

    def _primary_key(self, spoke_id):
        return self.spoke_id_alias.get(spoke_id, spoke_id)


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def _multi_host_cache(spoke_id, hosts):
    """One cs spoke aggregating several pxmx hosts (the multi-host shape)."""
    return {spoke_id: {
        "spoke_name": "cs-svr-04-spoke",
        "proxmox_hosts": [{"hostname": hn, "proxmox": {"vm_count": 2},
                            "proxmox_vms": [{"vmid": 100}, {"vmid": 101}]}
                           for hn in hosts],
    }}


# ── _agent_cs_enabled unit cases ─────────────────────────────────────────────

def test_enabled_unknown_hostname_defaults_shown():
    hub = _Hub({}, {})
    assert _agent_cs_enabled(hub, "brand-new-host") is True


def test_enabled_empty_hostname_shown():
    hub = _Hub({}, {})
    assert _agent_cs_enabled(hub, "") is True


def test_enabled_hostname_keyed_entry_disabled():
    hub = _Hub({}, {"pxmx-cs-svr-02": {"client_simulation": {"enabled": False}}})
    assert _agent_cs_enabled(hub, "pxmx-cs-svr-02") is False


def test_enabled_hostname_keyed_entry_enabled():
    hub = _Hub({}, {"pxmx-cs-svr-03": {"client_simulation": {"enabled": True}}})
    assert _agent_cs_enabled(hub, "pxmx-cs-svr-03") is True


def test_enabled_matches_by_display_name_when_not_keyed_by_hostname():
    """agent_config entries are often keyed by agent_id, not hostname. The
    filter falls back to matching the entry's hostname/display_name."""
    hub = _Hub({}, {"pxmx-cs-svr-02-agent": {
        "display_name": "pxmx-cs-svr-02", "client_simulation": {"enabled": False}}})
    assert _agent_cs_enabled(hub, "pxmx-cs-svr-02") is False


def test_enabled_entry_without_client_simulation_shown():
    """An entry with no client_simulation block is an unconfigured agent — show
    (only an EXPLICIT enabled=false hides)."""
    hub = _Hub({}, {"ag-1": {"display_name": "host-1"}})
    assert _agent_cs_enabled(hub, "host-1") is True


# ── get_proxmox_data end-to-end ──────────────────────────────────────────────

def test_disabled_agent_host_hidden_from_get_proxmox_data():
    """svr-02's agent has CS disabled → its host + VMs vanish from the VM Server
    list (the svr-02 can't-delete symptom: the bridge SKIPs it, so showing its
    VMs was a dead end)."""
    cache = _multi_host_cache("cs-svr-04-spoke",
                              ["pxmx-cs-svr-02", "pxmx-cs-svr-03", "pxmx-cs-svr-04"])
    agent_config = {
        "pxmx-cs-svr-02": {"client_simulation": {"enabled": False}},
        "pxmx-cs-svr-03": {"client_simulation": {"enabled": True}},
        "pxmx-cs-svr-04": {"client_simulation": {"enabled": True}},
    }
    hub = _Hub(cache, agent_config,
               spoke_tenants={"cs-svr-04-spoke": {"tenant_id": "lrb"}})
    svc = SimulationsService(hub)

    data = _run(svc.get_proxmox_data("lrb"))
    hostnames = sorted(h["hostname"] for h in data["hosts"])
    assert hostnames == ["pxmx-cs-svr-03", "pxmx-cs-svr-04"]


def test_enabled_agents_all_shown():
    cache = _multi_host_cache("cs-svr-04-spoke",
                              ["pxmx-cs-svr-02", "pxmx-cs-svr-03"])
    agent_config = {
        "pxmx-cs-svr-02": {"client_simulation": {"enabled": True}},
        "pxmx-cs-svr-03": {"client_simulation": {"enabled": True}},
    }
    hub = _Hub(cache, agent_config,
               spoke_tenants={"cs-svr-04-spoke": {"tenant_id": "lrb"}})
    svc = SimulationsService(hub)

    data = _run(svc.get_proxmox_data("lrb"))
    assert sorted(h["hostname"] for h in data["hosts"]) == ["pxmx-cs-svr-02", "pxmx-cs-svr-03"]


def test_unknown_agent_host_shown_by_default():
    """A freshly-connected agent with no agent_config row yet still shows."""
    cache = _multi_host_cache("cs-svr-04-spoke", ["pxmx-cs-svr-02"])
    hub = _Hub(cache, {},  # no agent_config entries
               spoke_tenants={"cs-svr-04-spoke": {"tenant_id": "lrb"}})
    svc = SimulationsService(hub)

    data = _run(svc.get_proxmox_data("lrb"))
    assert [h["hostname"] for h in data["hosts"]] == ["pxmx-cs-svr-02"]


def test_disabled_agent_vm_count_not_in_total():
    """Hidden hosts' VMs don't appear in the aggregated list (the VMs tab
    flattens proxmox_vms across hosts)."""
    cache = _multi_host_cache("cs-svr-04-spoke",
                              ["pxmx-cs-svr-02", "pxmx-cs-svr-03"])
    agent_config = {
        "pxmx-cs-svr-02": {"client_simulation": {"enabled": False}},
        "pxmx-cs-svr-03": {"client_simulation": {"enabled": True}},
    }
    hub = _Hub(cache, agent_config,
               spoke_tenants={"cs-svr-04-spoke": {"tenant_id": "lrb"}})
    svc = SimulationsService(hub)

    data = _run(svc.get_proxmox_data("lrb"))
    vms = [vm for h in data["hosts"] for vm in h.get("proxmox_vms", [])]
    # svr-02 hidden → only svr-03's 2 VMs.
    assert len(vms) == 2