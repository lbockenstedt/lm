"""``LabManagerHub.push_cs_hub_config`` re-pushes the tenant's hub-owned CS
provisioning config (``usb_vidpids`` / templates / ...) to a reconnecting cs
spoke as a ``CS_CONFIG_UPDATE``. Without it a restarting cs spoke comes up with
``usb_vidpids="[]"`` → the pxmx agent's ``_dongle_vidpids`` reads 0 →
auto-provision never fires ("no dongle_vidpids configured") until an admin
re-saves Setup/Proxmox. USB certified/ignored are the EFFECTIVE (global + tenant)
lists so a global-only certification still reaches the spoke.
"""
import json

import main  # noqa: E402  (core/src on sys.path via conftest)


class _State:
    def __init__(self, tenant):
        self._tenant = tenant

    def get_spoke_tenant(self, spoke_id):
        return self._tenant


class _Store:
    """Async stub of the bits of SimulationsStore push_cs_hub_config reads."""
    def __init__(self, hub_config, global_cert=None, global_ign=None,
                 sim_override="", user_override=""):
        self._hc = hub_config
        self._g_cert = global_cert or []
        self._g_ign = global_ign or []
        self._sim_override = sim_override
        self._user_override = user_override

    async def get_hub_config(self, tenant_id):
        return self._hc

    async def get_global_usb_vidpids(self):
        return self._g_cert

    async def get_global_usb_ignored_vidpids(self):
        return self._g_ign

    async def get_sim_conf_content(self, tenant_id):
        return self._sim_override

    async def get_user_overrides_content(self, tenant_id):
        return self._user_override


class _Hub:
    """Minimal stub: only the attributes push_cs_hub_config touches."""
    def __init__(self, state, store):
        self.state = state
        self.simulations_store = store
        self.sent = []  # list of (cmd, data)
        # Drain state (hub never drains in these tests).
        self._draining_spokes = {}
        self.DRAIN_WINDOW_S = 180.0

    def mark_draining(self, spoke_id, window=None):
        if spoke_id:
            self._draining_spokes[spoke_id] = 0

    def is_draining(self, spoke_id):
        return False

    def clear_draining(self, spoke_id):
        self._draining_spokes.pop(spoke_id, None)

    async def request_response(self, spoke_id, cmd, data, timeout=5.0):
        self.sent.append((cmd, data))
        return {"status": "SUCCESS"}

    async def push_or_queue_to_spoke(self, spoke_id, cmd, data, timeout=5.0):
        # Record the push (the non-draining path routes through here now) and
        # return a non-queued success so push_cs_hub_config treats it as live.
        self.sent.append((cmd, data))
        return {"status": "ok", "queued": False, "result": {"status": "SUCCESS"}}

    async def _drain_aware_config_push(self, spoke_id, cmd, data, timeout=5.0):
        return await self.push_or_queue_to_spoke(spoke_id, cmd, data, timeout=timeout)


def _vidpid(vp, type_="wireless", label=None):
    return {"vidpid": vp, "type": type_, "label": label or vp}


async def test_repush_merges_global_and_tenant_usb_and_threads_templates():
    # Tenant hub_config has one certified vidpid + templates; the GLOBAL store
    # adds a second certified vidpid + an ignored one. The spoke must receive
    # the EFFECTIVE (merged) usb lists plus the tenant's template keys.
    hub_config = {
        "hub_config_enabled": True,
        "hub_config": {
            "usb_vidpids": json.dumps([_vidpid("1111:2222", "wired")]),
            "usb_ignored_vidpids": json.dumps(["dead:beef"]),
            "usb_auto_provision": "on",
            "vm_image_1_template_id": 100,
            "vm_image_2_template_id": 200,
        },
    }
    hub = _Hub(
        _State("10"),
        _Store(hub_config,
               global_cert=[_vidpid("3333:4444", "storage")],
               global_ign=["cafe:0000"]),
    )

    await main.LabManagerHub.push_cs_hub_config(hub, "cs-spoke-1")

    assert len(hub.sent) == 1
    cmd, data = hub.sent[0]
    assert cmd == "CS_CONFIG_UPDATE"
    # Effective certified = global (3333:4444) + tenant (1111:2222), deduped.
    cert = json.loads(data["usb_vidpids"])
    assert sorted(d["vidpid"] for d in cert) == ["1111:2222", "3333:4444"]
    # Effective ignored = global (cafe:0000) + tenant (dead:beef).
    assert sorted(json.loads(data["usb_ignored_vidpids"])) == ["cafe:0000", "dead:beef"]
    # Template + auto-provision keys threaded through from the tenant hub_config.
    assert data["vm_image_1_template_id"] == 100
    assert data["vm_image_2_template_id"] == 200
    assert data["usb_auto_provision"] == "on"


async def test_repush_noop_without_tenant_binding():
    hub = _Hub(_State(None), _Store({"hub_config_enabled": True,
                                    "hub_config": {"usb_vidpids": "[]"}}))
    await main.LabManagerHub.push_cs_hub_config(hub, "cs-spoke-1")
    assert hub.sent == []  # unbound spoke → nothing pushed


async def test_repush_noop_when_hub_config_disabled():
    hub = _Hub(_State("10"),
               _Store({"hub_config_enabled": False,
                       "hub_config": {"usb_vidpids": json.dumps([_vidpid("1111:2222")])}}))
    await main.LabManagerHub.push_cs_hub_config(hub, "cs-spoke-1")
    assert hub.sent == []  # disabled → don't push (would clear spoke-side certs)


async def test_repush_dedupes_overlap_between_global_and_tenant():
    # Same vidpid in both global + tenant → appears once.
    hub_config = {"hub_config_enabled": True,
                  "hub_config": {"usb_vidpids": json.dumps([_vidpid("1111:2222")])}}
    hub = _Hub(_State("10"),
               _Store(hub_config, global_cert=[_vidpid("1111:2222", "wired")]))
    await main.LabManagerHub.push_cs_hub_config(hub, "cs-spoke-1")
    cert = json.loads(hub.sent[0][1]["usb_vidpids"])
    assert [d["vidpid"] for d in cert] == ["1111:2222"]


async def test_repush_sim_and_user_overrides_recover_after_restart():
    # The Sim Config editor saves sim_conf_override / user_conf_override INI
    # text; a restarting spoke must recover them. They're re-pushed as a
    # CS_CONFIG_UPDATE independent of hub_config_enabled.
    hub_config = {"hub_config_enabled": True,
                  "hub_config": {"usb_vidpids": json.dumps([_vidpid("1111:2222")])}}
    hub = _Hub(_State("10"),
               _Store(hub_config,
                      sim_override="[simulation]\nkill_switch=on\n",
                      user_override="[amoran]\nwsite=LAX\n"))
    await main.LabManagerHub.push_cs_hub_config(hub, "cs-spoke-1")
    # Two pushes: one for overrides, one for hub_config (usb/templates).
    assert len(hub.sent) == 2
    cmds = [c for c, _ in hub.sent]
    assert cmds == ["CS_CONFIG_UPDATE", "CS_CONFIG_UPDATE"]
    override_payload = hub.sent[0][1]
    assert override_payload["sim_conf_override"] == "[simulation]\nkill_switch=on\n"
    assert override_payload["user_conf_override"] == "[amoran]\nwsite=LAX\n"
    # hub_config push still carries usb_vidpids separately.
    assert "usb_vidpids" in hub.sent[1][1]


async def test_repush_overrides_even_when_hub_config_disabled():
    # Overrides are their own bucket — they must re-push even if hub_config
    # isn't enabled (the gate only suppresses the usb/template push).
    hub = _Hub(_State("10"),
               _Store({"hub_config_enabled": False, "hub_config": {}},
                      sim_override="[simulation]\nkill_switch=on\n"))
    await main.LabManagerHub.push_cs_hub_config(hub, "cs-spoke-1")
    # Exactly one push: the override. The disabled hub_config suppresses the
    # second push (no usb/templates).
    assert len(hub.sent) == 1
    assert hub.sent[0][0] == "CS_CONFIG_UPDATE"
    assert hub.sent[0][1]["sim_conf_override"] == "[simulation]\nkill_switch=on\n"


async def test_repush_no_overrides_means_no_override_push():
    # No stored override content → no override push; hub_config still pushes.
    hub_config = {"hub_config_enabled": True,
                  "hub_config": {"usb_vidpids": json.dumps([_vidpid("1111:2222")])}}
    hub = _Hub(_State("10"), _Store(hub_config))  # no overrides
    await main.LabManagerHub.push_cs_hub_config(hub, "cs-spoke-1")
    assert len(hub.sent) == 1  # only the hub_config push
    assert "sim_conf_override" not in hub.sent[0][1]