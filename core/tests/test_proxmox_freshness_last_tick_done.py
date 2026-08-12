"""Regression guard: SimulationsService.get_proxmox_data's freshness dict must
carry last_tick_done_ts through from agent_telemetry.

The WebUI's telemetry-freshness panel (csFreshnessPanel, sim-views.js) flags a
host as "no telemetry tick has COMPLETED" whenever ``freshness.last_tick_done_ts
== null`` while ``freshness.iter != null`` — a state meant to catch a genuinely
wedged agent. The freshness dict here is built by hand-enumerating fields out
of the agent's ``agent_telemetry`` blob, and last_tick_done_ts was simply never
one of the fields listed (iter, right next to it, was) — so EVERY host showed
that banner unconditionally regardless of actual agent health. Confirmed live:
the agent side was ticking normally the whole time; only this hub-side field
was ever missing.
"""
import asyncio

from simulations.service import SimulationsService


class _State:
    def __init__(self, agent_config, spoke_tenants):
        self.system_state = {"agent_config": agent_config, "module_metadata": spoke_tenants}

    def get_spoke_tenant(self, sid):
        return self.system_state["module_metadata"].get(sid, {}).get("tenant_id")


class _Hub:
    def __init__(self, cache, agent_config, spoke_tenants=None):
        self.simulations_cache = cache
        self.active_connections = {}
        self.spoke_id_alias = {}
        self.state = _State(agent_config, spoke_tenants or {})

    def _primary_key(self, spoke_id):
        return self.spoke_id_alias.get(spoke_id, spoke_id)


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def test_last_tick_done_ts_survives_into_the_freshness_dict():
    hostname = "pxmx-cs-svr-01"
    cache = {"cs-svr-01-spoke": {
        "spoke_name": "cs-svr-01-spoke",
        "proxmox_hosts": [{
            "hostname": hostname,
            "proxmox": {
                "vm_count": 88,
                "agent_telemetry": {
                    "gen_ts": 1000.0,
                    "iter": 42,
                    "interval_s": 60,
                    "last_tick_done_ts": 999.5,
                },
            },
            "proxmox_vms": [],
        }],
    }}
    hub = _Hub(cache, {"pxmx-cs-svr-01": {"client_simulation": {"enabled": True}}},
               spoke_tenants={"cs-svr-01-spoke": {"tenant_id": "lrb"}})
    svc = SimulationsService(hub)

    data = _run(svc.get_proxmox_data("lrb"))
    hosts = {h["hostname"]: h for h in data["hosts"]}
    fr = hosts[hostname]["freshness"]

    assert fr["iter"] == 42
    assert fr["last_tick_done_ts"] == 999.5, (
        "last_tick_done_ts was dropped from the freshness dict — this is "
        "exactly the bug that made every host show 'no telemetry tick has "
        "ever completed' regardless of real agent health")


def test_missing_last_tick_done_ts_in_source_stays_none_not_stale_default():
    """An agent build that predates this field (or a genuinely fresh boot with
    no completed tick yet) must still surface as None here — the fix adds the
    field, it must not paper over a REAL never-completed state with a fake
    value."""
    hostname = "pxmx-cs-svr-02"
    cache = {"cs-svr-02-spoke": {
        "spoke_name": "cs-svr-02-spoke",
        "proxmox_hosts": [{
            "hostname": hostname,
            "proxmox": {
                "vm_count": 1,
                "agent_telemetry": {"gen_ts": 1000.0, "iter": 1, "interval_s": 60},
            },
            "proxmox_vms": [],
        }],
    }}
    hub = _Hub(cache, {"pxmx-cs-svr-02": {"client_simulation": {"enabled": True}}},
               spoke_tenants={"cs-svr-02-spoke": {"tenant_id": "lrb"}})
    svc = SimulationsService(hub)

    data = _run(svc.get_proxmox_data("lrb"))
    fr = {h["hostname"]: h for h in data["hosts"]}[hostname]["freshness"]
    assert fr["iter"] == 1
    assert fr["last_tick_done_ts"] is None
