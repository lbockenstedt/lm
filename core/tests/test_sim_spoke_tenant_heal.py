"""Self-heal an UNBOUND simulation spoke's tenant from its backing agent.

A cs (simulation) spoke can be approved WITHOUT a tenant binding
(``module_metadata.tenant_id`` unset). Such a spoke is invisible to BOTH the
per-tenant Simulation VM Server view (``service._spokes_for_tenant``) and the
per-tenant Hypervisor Overview (``get_hypervisor_spokes_for_tenant``), which key
off the SPOKE's tenant — so a CS-enabled, tenant-pinned box silently drops off
its tenant's pages even though its telemetry is flowing (observed live for
pxmx-cs-svr-02: sim spoke tenant=None while the agent's client_simulation was
pinned to 'lrb').

``LabManagerHub._infer_sim_spoke_tenant`` joins the spoke's ``proxmox_hosts``
against ``agent_config`` (by hostname, tolerant of agent_id/hostname keying) and
returns the single tenant its CS-enabled agents agree on; ``_handle_cs_telemetry``
binds an unbound spoke to it. These lock in the join + the single-tenant guard.
"""
import os
import sys

_LM_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _LM_ROOT not in sys.path:
    sys.path.insert(0, _LM_ROOT)
_SRC = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

import main  # noqa: E402

_infer = main.LabManagerHub._infer_sim_spoke_tenant


def test_binds_from_pinned_agent_keyed_by_guid_with_hostname_field():
    """The live shape: agent_config keyed by install guid, hostname in the
    entry's ``hostname`` field, CS enabled + tenant pinned."""
    hosts = [{"hostname": "pxmx-cs-svr-02"}]
    agent_config = {
        "22af8aa1-d19f-43bb-b458-46b2edb2a952": {
            "hostname": "pxmx-cs-svr-02",
            "client_simulation": {"enabled": True, "tenant_id": "lrb",
                                  "tenant_pinned": True},
        }
    }
    assert _infer(hosts, agent_config) == "lrb"


def test_binds_when_agent_config_keyed_by_hostname():
    hosts = [{"hostname": "pxmx-cs-svr-02"}]
    agent_config = {
        "pxmx-cs-svr-02": {
            "client_simulation": {"enabled": True, "tenant_id": "acme"},
        }
    }
    assert _infer(hosts, agent_config) == "acme"


def test_hostname_match_is_case_insensitive():
    hosts = [{"hostname": "PXMX-CS-SVR-02"}]
    agent_config = {
        "g1": {"hostname": "pxmx-cs-svr-02",
               "client_simulation": {"enabled": True, "tenant_id": "lrb"}},
    }
    assert _infer(hosts, agent_config) == "lrb"


def test_none_when_agent_cs_disabled():
    hosts = [{"hostname": "pxmx-cs-svr-02"}]
    agent_config = {
        "g1": {"hostname": "pxmx-cs-svr-02",
               "client_simulation": {"enabled": False, "tenant_id": "lrb"}},
    }
    assert _infer(hosts, agent_config) is None


def test_none_when_no_tenant_on_agent():
    hosts = [{"hostname": "pxmx-cs-svr-02"}]
    agent_config = {
        "g1": {"hostname": "pxmx-cs-svr-02",
               "client_simulation": {"enabled": True}},
    }
    assert _infer(hosts, agent_config) is None


def test_none_when_backing_agents_disagree_on_tenant():
    """A shared spoke aggregating hosts pinned to DIFFERENT tenants must NOT be
    auto-bound (ambiguous) — left for the operator."""
    hosts = [{"hostname": "host-a"}, {"hostname": "host-b"}]
    agent_config = {
        "a": {"hostname": "host-a",
              "client_simulation": {"enabled": True, "tenant_id": "t1"}},
        "b": {"hostname": "host-b",
              "client_simulation": {"enabled": True, "tenant_id": "t2"}},
    }
    assert _infer(hosts, agent_config) is None


def test_single_tenant_when_agents_agree():
    hosts = [{"hostname": "host-a"}, {"hostname": "host-b"}]
    agent_config = {
        "a": {"hostname": "host-a",
              "client_simulation": {"enabled": True, "tenant_id": "lrb"}},
        "b": {"hostname": "host-b",
              "client_simulation": {"enabled": True, "tenant_id": "lrb"}},
    }
    assert _infer(hosts, agent_config) == "lrb"


def test_none_on_empty_or_missing_hosts():
    assert _infer(None, {}) is None
    assert _infer([], {"g": {"client_simulation": {"enabled": True, "tenant_id": "lrb"}}}) is None


def test_none_when_host_has_no_matching_agent():
    hosts = [{"hostname": "unknown-host"}]
    agent_config = {
        "g1": {"hostname": "pxmx-cs-svr-02",
               "client_simulation": {"enabled": True, "tenant_id": "lrb"}},
    }
    assert _infer(hosts, agent_config) is None
