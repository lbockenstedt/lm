"""A new tenant's Setup/Proxmox card must show the default details, not a blank
grid — and one tenant's hub_config must not bleed into another's.

``SimulationsStore.get_hub_config`` seeds ``_DEFAULT_HUB_CONFIG`` (mirroring the
cs speak ``_DEFAULTS``) for fields the tenant hasn't stored, so a fresh tenant
sees usb_max_slots=24, cpu_provision_threshold=80, vmid_start=90000, etc. Stored
values win; the seed is display-only (the first save's GET-merge-PUT persists).
The store is keyed by tenant_id, so tenant isolation is structural — this test
also pins that writing one tenant's hub_config does not touch another's.
"""

from simulations.store import SimulationsStore


async def test_get_hub_config_seeds_defaults_for_new_tenant(tmp_path):
    s = SimulationsStore(str(tmp_path))
    hc = await s.get_hub_config("new-tenant")
    assert hc["hub_config_enabled"] is False
    cfg = hc["hub_config"]
    # Provisioning behavior + thresholds + templates + vmid range all defaulted.
    assert cfg["usb_auto_provision"] == "off"
    assert cfg["usb_missing_timeout"] == 60
    assert cfg["usb_max_slots"] == 24
    assert cfg["cpu_provision_threshold"] == 80
    assert cfg["cpu_delete_threshold"] == 90
    assert cfg["mem_provision_threshold"] == 80
    assert cfg["mem_delete_threshold"] == 90
    assert cfg["vm_image_1_template_id"] == 100
    assert cfg["vm_image_2_template_id"] == 200
    assert cfg["vm_image_1_pct"] == 50
    assert cfg["reclone_concurrency"] == 1
    assert cfg["vmid_start"] == 90000
    assert cfg["vmid_end"] == 99999
    # JSON-list / empty fields are NOT seeded (placeholder display).
    assert "usb_vidpids" not in cfg
    assert "protected_vmids" not in cfg


async def test_stored_values_win_over_defaults_and_persist(tmp_path):
    s = SimulationsStore(str(tmp_path))
    await s.set_hub_config("t1", True, {"usb_auto_provision": "on", "usb_max_slots": 4})
    hc = await s.get_hub_config("t1")
    assert hc["hub_config_enabled"] is True
    assert hc["hub_config"]["usb_auto_provision"] == "on"      # stored wins
    assert hc["hub_config"]["usb_max_slots"] == 4              # stored wins
    assert hc["hub_config"]["cpu_provision_threshold"] == 80   # default still fills


async def test_one_tenant_hub_config_does_not_leak_into_another(tmp_path):
    s = SimulationsStore(str(tmp_path))
    await s.set_hub_config("tenantA", True, {"usb_auto_provision": "on", "usb_max_slots": 9})
    # tenantB has never been written — must not see tenantA's values.
    hcb = await s.get_hub_config("tenantB")
    assert hcb["hub_config"]["usb_auto_provision"] == "off"   # default, not tenantA's "on"
    assert hcb["hub_config"]["usb_max_slots"] == 24           # default, not tenantA's 9
    assert hcb["hub_config_enabled"] is False
    # tenantA is unchanged by tenantB's read.
    hca = await s.get_hub_config("tenantA")
    assert hca["hub_config"]["usb_auto_provision"] == "on"
    assert hca["hub_config"]["usb_max_slots"] == 9


async def test_reset_hub_config_restores_knobs_but_preserves_certified_usb(tmp_path):
    s = SimulationsStore(str(tmp_path))
    await s.set_hub_config("t1", True, {
        "usb_auto_provision": "on",
        "usb_max_slots": 4,
        "cpu_provision_threshold": 55,
        "protected_vmids": "9000,9005",
        "reclone_schedule_cron": "monday 03:00",
        "repo_branch": "custom",
        "usb_vidpids": '[{"vidpid":"1a2b:3c4d","type":"wireless"}]',
        "usb_ignored_vidpids": '["dead:beef"]',
        "ignored_hostnames": '["sim-rpi-0000"]',
    })
    r = await s.reset_hub_config("t1")
    cfg = r["hub_config"]
    # Knobs reset to factory defaults.
    assert cfg["usb_auto_provision"] == "off"
    assert cfg["usb_max_slots"] == 24
    assert cfg["cpu_provision_threshold"] == 80
    # Non-defaulted visible fields cleared to empty.
    assert cfg["protected_vmids"] == ""
    assert cfg["reclone_schedule_cron"] == ""
    assert cfg["repo_branch"] == ""
    # Certified/ignored USB + ignored hostnames PRESERVED (real data, not knobs).
    assert cfg["usb_vidpids"] == '[{"vidpid":"1a2b:3c4d","type":"wireless"}]'
    assert cfg["usb_ignored_vidpids"] == '["dead:beef"]'
    assert cfg["ignored_hostnames"] == '["sim-rpi-0000"]'
    # enabled flag preserved across reset.
    assert r["hub_config_enabled"] is True
    # Persisted: a fresh store reload sees the reset values.
    s2 = SimulationsStore(str(tmp_path))
    reloaded = (await s2.get_hub_config("t1"))["hub_config"]
    assert reloaded["usb_max_slots"] == 24
    assert reloaded["usb_vidpids"] == '[{"vidpid":"1a2b:3c4d","type":"wireless"}]'


async def test_reset_hub_config_is_tenant_scoped(tmp_path):
    s = SimulationsStore(str(tmp_path))
    await s.set_hub_config("tenantA", True, {"usb_max_slots": 4})
    await s.set_hub_config("tenantB", True, {"usb_max_slots": 7})
    await s.reset_hub_config("tenantA")
    a = (await s.get_hub_config("tenantA"))["hub_config"]
    b = (await s.get_hub_config("tenantB"))["hub_config"]
    assert a["usb_max_slots"] == 24   # reset
    assert b["usb_max_slots"] == 7    # untouched