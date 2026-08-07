"""_stale_clients_no_vm — the safety-rail logic behind the automatic
client-fleet scrub (routes.py's _clients_scrub_loop). Unattended, machine-
driven, and deletes data, so its guardrails need direct coverage, not just
review-time inspection of the diff:

  1. A registered client whose hostname matches a live VM is never flagged.
  2. A client with no matching VM, quiet past the grace window, IS flagged.
  3. A client with no matching VM but seen inside the grace window is NOT
     flagged (still settling in / VM just created, telemetry hasn't caught
     up yet).
  4. The tenant is skipped ENTIRELY (empty result) when the fleet reports no
     VM at all — even when host entries are present but every host's VM
     list is empty (a real partial-telemetry-outage shape, not merely a
     "no host connected" one). A guard keyed on host-presence instead of
     VM-presence would miss exactly this case and scrub the whole registry.
  5. Multi-spoke: the FRESHEST last_seen for a hostname wins across every
     spoke that reports it, not whichever spoke happens to be iterated
     first — a phantom override-stub (last_seen=0) on one spoke must not
     let a genuinely-active client on another spoke get scrubbed depending
     on cache iteration order.
"""

from fastapi import FastAPI

from simulations.routes import register_simulations_routes


class FakeHub:
    def __init__(self, cache):
        self.simulations_cache = cache
        self.active_connections = {"cs-spoke-1"}
        self.simulations_store = type("Store", (), {})()
        self.state = type("State", (), {"get_spoke_tenant": staticmethod(lambda sid: "T1")})()

    def get_client_sim_spoke(self, tenant_id):
        return "cs-spoke-1"

    def get_client_sim_spokes(self, tenant_id):
        return list(self.simulations_cache.keys())

    async def request_response(self, sid, cmd_type, payload, timeout=8.0):
        return {"payload": {"data": {"status": "SUCCESS"}}}


def _build(cache):
    app = FastAPI()
    hub = FakeHub(cache)
    register_simulations_routes(
        app, hub,
        session_user_fn=lambda req: None,
        resolve_tenant_fn=lambda req: None,
        is_admin_fn=lambda u: True,
        check_tenant_access_fn=None,
        sessions=None,
        has_cs_access_fn=lambda u: True,
    )
    return hub


def test_client_matching_a_vm_is_never_flagged():
    hub = _build({
        "cs-spoke-1": {
            "proxmox_hosts": [{"proxmox_vms": [{"name": "khenderson"}]}],
            "clients": [{"hostname": "khenderson", "last_seen": 0}],
        },
    })
    assert hub._stale_clients_no_vm("T1") == []


def test_no_matching_vm_past_grace_is_flagged():
    hub = _build({
        "cs-spoke-1": {
            "proxmox_hosts": [{"proxmox_vms": [{"name": "khenderson"}]}],
            "clients": [{"hostname": "ghost-old", "last_seen": 1000.0}],
        },
    })
    assert hub._stale_clients_no_vm("T1") == ["ghost-old"]


def test_no_matching_vm_inside_grace_window_is_not_flagged():
    import time
    hub = _build({
        "cs-spoke-1": {
            "proxmox_hosts": [{"proxmox_vms": [{"name": "khenderson"}]}],
            "clients": [{"hostname": "brand-new", "last_seen": time.time()}],
        },
    })
    assert hub._stale_clients_no_vm("T1") == []


def test_empty_fleet_wide_vm_list_skips_the_whole_tenant():
    # Host entries are present (spoke is connected, telemetry is flowing) but
    # every host's own VM list is empty — a real partial-outage shape. Must
    # NOT read as "every VM is gone" and scrub the whole registry.
    hub = _build({
        "cs-spoke-1": {
            "proxmox_hosts": [{"proxmox_vms": []}, {"proxmox_vms": []}],
            "clients": [{"hostname": "ghost-old", "last_seen": 1000.0},
                       {"hostname": "ghost-old-2", "last_seen": 1000.0}],
        },
    })
    assert hub._stale_clients_no_vm("T1") == []


def test_no_host_data_at_all_skips_the_tenant():
    hub = _build({
        "cs-spoke-1": {"clients": [{"hostname": "ghost-old", "last_seen": 1000.0}]},
    })
    assert hub._stale_clients_no_vm("T1") == []


def test_multi_spoke_freshest_last_seen_wins_regardless_of_order():
    # A phantom override-stub (no last_seen) for "realuser" sits on cs-spoke-1;
    # the real, actively-reporting client sits on cs-spoke-2 with a fresh
    # last_seen. Neither hostname matches a VM (VM inventory only lives on
    # spoke-1's cache, same as it would in a real fleet). The client must
    # survive because SOME spoke's copy is fresh — not get scrubbed just
    # because spoke-1 (iterated first) happens to hold the stale copy.
    import time
    hub = _build({
        "cs-spoke-1": {
            "proxmox_hosts": [{"proxmox_vms": [{"name": "someone-else"}]}],
            "clients": [{"hostname": "realuser", "last_seen": 0}],
        },
        "cs-spoke-2": {
            "clients": [{"hostname": "realuser", "last_seen": time.time()}],
        },
    })
    assert hub._stale_clients_no_vm("T1") == []
