"""``_usb_provisioning_status_payload`` (the pure helper behind
``/sim/api/{tenant}/usb-provisioning-status``) projects the cs spoke's cached
``provision`` diagnostic into the per-spoke + per-host response and counts the
hypervisor agents that actually have ``client_simulation.enabled`` for the
tenant. The latter is what surfaces the most common "I enabled Auto-Provisioning
but nothing provisions" cause (the tenant toggle alone spawns no loop)."""

from simulations.routes import _usb_provisioning_status_payload


def _prov(reason="no dongle_vidpids configured", loop_running=True, on=True):
    return {
        "cs_enabled": True,
        "loop_running": loop_running,
        "auto_provision_on": on,
        "reason": reason,
        "halt": None,
        "config": {"dongle_vidpids": 0, "image1_template_id": False,
                   "image2_template_id": False, "max_slots": 24,
                   "vmid_range": {"start": 90000, "end": 99999},
                   "active_usb_vms": None},
    }


def _tenant_cache():
    return {
        "cs-spoke-1": {
            "spoke_name": "CS Spoke 1",
            "proxmox": {
                "present_usb": [{"vidpid": "1234:5678"}],
                "unknown_usb": [{"vidpid": "abcd:ef01"}, {"vidpid": "0000:0001"}],
                "provision": _prov(),
            },
            "proxmox_hosts": [
                {"hostname": "host-a", "proxmox": {"provision": _prov()}},
                {"hostname": "host-b", "proxmox": {"provision": _prov("provisioning: attempted 3, provisioned 1")}},
            ],
        },
    }


def _agent_config():
    # One CS-enabled agent bound to this tenant, one bound to another tenant,
    # one disabled — only the first should count.
    return {
        "agent-pxmx-01": {"client_simulation": {"enabled": True, "tenant_id": "10"}},
        "agent-pxmx-02": {"client_simulation": {"enabled": True, "tenant_id": "99"}},
        "agent-pxmx-03": {"client_simulation": {"enabled": False, "tenant_id": "10"}},
    }


def test_provision_threaded_into_spoke_and_hosts():
    out = _usb_provisioning_status_payload({"usb_auto_provision": "on"},
                                           _tenant_cache(), _agent_config(), "10")
    spoke = out["spokes"][0]
    # Primary-host provision block surfaced on the spoke row.
    assert spoke["provision"]["reason"] == "no dongle_vidpids configured"
    assert spoke["present_usb"] == 1
    assert spoke["unknown_usb"] == 2
    # Per-host rows carry their own provision diagnostic.
    hosts = spoke["hosts"]
    assert [h["hostname"] for h in hosts] == ["host-a", "host-b"]
    assert hosts[0]["provision"]["loop_running"] is True
    assert hosts[1]["provision"]["reason"] == "provisioning: attempted 3, provisioned 1"


def test_cs_enabled_agent_count_is_tenant_scoped():
    out = _usb_provisioning_status_payload({}, _tenant_cache(), _agent_config(), "10")
    # Only agent-pxmx-01 (enabled + tenant 10) counts; the tenant-99 + disabled
    # agents are excluded.
    assert out["cs_enabled_agent_count"] == 1


def test_usb_auto_provision_defaults_off_and_empty_inputs():
    out = _usb_provisioning_status_payload({}, {}, {}, None)
    assert out["usb_auto_provision"] == "off"
    assert out["spokes"] == []
    assert out["cs_enabled_agent_count"] == 0


def test_str_and_int_tenant_ids_match():
    # tenant_id may arrive as int (route Depends) or str (cache comparison) —
    # the helper str()-coerces both sides.
    out_int = _usb_provisioning_status_payload({}, {}, _agent_config(), 10)
    assert out_int["cs_enabled_agent_count"] == 1