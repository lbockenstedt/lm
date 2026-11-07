import asyncio
import os
import sys
from types import SimpleNamespace

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import cred_vault  # noqa: E402
import instance_vault  # noqa: E402
from routes import monitoring  # noqa: E402


def test_inventory_devices_resolves_vault_and_shapes_devices(monkeypatch):
    async def fake_overlay_many(hub, records, storage_key):
        if storage_key == "nw_scan_credentials":
            return records
        return [dict(r, snmp_community="s3cret") for r in records]

    async def no_snmp(hub, sec_type, buckets=None):
        return []

    monkeypatch.setattr(cred_vault, "automation_list_by_type", no_snmp)
    monkeypatch.setattr(instance_vault, "overlay_many", fake_overlay_many)
    hub = SimpleNamespace(state=SimpleNamespace(system_state={"global_config": {"nw_devices": [
        {"name": "sw1", "address": "10.0.0.1/24", "tenant": "t1", "type": "switch", "snmp_ok": True},
        {"name": "unverified", "address": "10.0.0.2", "tenant": "t1"},
        {"name": "no-address"},
    ]}}))
    devices = asyncio.run(monitoring.inventory_devices(hub))
    assert devices == [{"tenant": "t1", "name": "sw1", "type": "switch", "ip": "10.0.0.1",
                        "snmp": True, "snmp_community": "s3cret"}]


def test_scanned_device_inherits_tenant_scan_snmp_community(monkeypatch):
    async def fake_overlay_many(hub, records, storage_key):
        return records

    async def no_snmp(hub, sec_type, buckets=None):
        return []

    monkeypatch.setattr(cred_vault, "automation_list_by_type", no_snmp)
    monkeypatch.setattr(instance_vault, "overlay_many", fake_overlay_many)
    hub = SimpleNamespace(state=SimpleNamespace(system_state={"global_config": {
        "nw_devices": [{"name": "sw1", "address": "10.0.0.1", "tenant_id": "t1",
                        "object_type": "cx_switch", "transport": "ssh", "snmp_ok": True}],
        "nw_scan_credentials": [{"tenant_id": "t1", "snmp_community": "pub"}]}}))
    (d,) = asyncio.run(monitoring.inventory_devices(hub))
    assert d["type"] == "cx_switch" and d["snmp"] and d["snmp_community"] == "pub"


def test_only_snmp_verified_devices_and_seen_hosts_are_monitored(monkeypatch):
    import time

    async def fake_overlay_many(hub, records, storage_key):
        return records

    async def snmp_secrets(hub, sec_type, buckets=None):
        return [{"bucket": "t1", "name": "SNMP", "value": {"snmp_community": "v"}}]

    monkeypatch.setattr(cred_vault, "automation_list_by_type", snmp_secrets)
    monkeypatch.setattr(instance_vault, "overlay_many", fake_overlay_many)
    now = time.time()
    ok = {"snmp_ok": True, "snmp_credential_id": "snmp:t1:SNMP", "last_seen": now}
    hub = SimpleNamespace(state=SimpleNamespace(system_state={"global_config": {
        "nw_devices": [{"name": "sw1", "address": "10.0.0.1", "tenant_id": "t1"},
                       {"name": "sw2", "address": "10.0.0.2", "tenant_id": "t1"}],
        "nw_seen_hosts": {"t1": {
            "10.0.0.1": {"address": "10.0.0.1", **ok},                          # fleet, SNMP ok
            "10.0.0.2": {"address": "10.0.0.2", "last_seen": now},              # fleet, ping only
            "10.0.0.7": {"address": "10.0.0.7", "hostname": "pdu-a", "last_seen": now},
            "10.0.0.9": {"address": "10.0.0.9", "hostname": "tor1", **ok},
            "10.0.0.8": {"address": "10.0.0.8", **ok, "last_seen": now - 3 * 86400},  # gone
        }}}}))
    rows = asyncio.run(monitoring.inventory_devices(hub))
    assert [(r["name"], r["ip"], r["snmp"], r["snmp_community"]) for r in rows] == [
        ("sw1", "10.0.0.1", True, "v"), ("tor1", "10.0.0.9", True, "v")]


def test_vault_snmp_secret_applies_to_tenant_devices(monkeypatch):
    async def fake_overlay_many(hub, records, storage_key):
        return records

    async def snmp_secrets(hub, sec_type, buckets=None):
        assert sec_type == "snmp"
        return [{"bucket": "t1", "name": "SNMP", "value": {"snmp_community": "vaulted"}}]

    monkeypatch.setattr(cred_vault, "automation_list_by_type", snmp_secrets)
    monkeypatch.setattr(instance_vault, "overlay_many", fake_overlay_many)
    hub = SimpleNamespace(state=SimpleNamespace(system_state={"global_config": {
        "nw_devices": [{"name": "a", "address": "10.0.0.1", "tenant_id": "t1", "snmp_ok": True},
                       {"name": "b", "address": "10.0.0.2", "tenant_id": "t2", "snmp_ok": True}]}}))
    (a,) = asyncio.run(monitoring.inventory_devices(hub))
    assert a["name"] == "a" and a["snmp_community"] == "vaulted" and a["snmp"]


def test_admin_slot_snmp_secret_is_only_the_default_tenants(monkeypatch):
    async def fake_overlay_many(hub, records, storage_key):
        return records

    async def snmp_secrets(hub, sec_type, buckets=None):
        return [{"bucket": cred_vault.ADMIN_BUCKET, "name": "SNMP", "value": {"snmp_community": "adm"}}]

    monkeypatch.setattr(cred_vault, "automation_list_by_type", snmp_secrets)
    monkeypatch.setattr(instance_vault, "overlay_many", fake_overlay_many)
    hub = SimpleNamespace(state=SimpleNamespace(system_state={"global_config": {
        "nw_devices": [{"name": "a", "address": "10.0.0.1", "tenant_id": "other", "snmp_ok": True},
                       {"name": "b", "address": "10.0.0.2", "tenant_id": "default", "snmp_ok": True}]}}))
    (b,) = asyncio.run(monitoring.inventory_devices(hub))
    assert b["name"] == "b" and b["snmp_community"] == "adm" and b["snmp"]


def test_verify_credentials_reports_ssh_and_snmp_and_gates_failed_snmp(monkeypatch):
    async def fake_overlay_many(hub, records, storage_key):
        return [dict(r, snmp_community="pub") if r["id"].startswith("snmp:") else r for r in records]

    sent = {}

    class Hub:
        state = SimpleNamespace(system_state={"global_config": {
            "nw_devices": [{"name": "a", "address": "10.0.0.1", "tenant_id": "default", "spoke_id": "s1",
                            "vault_credential": {"bucket": "default", "name": "ssh"}},
                           {"name": "b", "address": "10.0.0.2", "tenant_id": "default", "spoke_id": "s1"}],
            "cred_vault": {"secrets": {"__admin__": {"Global SNMP": {"type": "snmp", "mode": "hub"}}}}}},
            _mark_dirty=lambda self=None: None)

        async def request_response(self, spoke, cmd, payload, timeout):
            sent.update(payload)
            return {"payload": {"data": {"identified": [
                {"address": "10.0.0.1", "reachable": True, "method": "ssh", "credential": "ssh",
                 "snmp_ok": True, "snmp_credential_id": "snmp:__admin__:Global SNMP"}],
                "reachable": [{"address": "10.0.0.2", "reachable": True, "snmp_ok": False}]}}}

    monkeypatch.setattr(instance_vault, "overlay_many", fake_overlay_many)
    hub = Hub()
    rep = asyncio.run(monitoring.verify_credentials(hub, "default", apply=True))
    assert {c["id"] for c in sent["credentials"]} == {"ssh:default:ssh", "snmp:__admin__:Global SNMP"}
    a, b = rep["devices"]
    assert a["ssh"] == "ssh" and a["snmp_ok"] is True and b["snmp_ok"] is False
    devs = hub.state.system_state["global_config"]["nw_devices"]
    assert devs[0]["snmp_ok"] is True and devs[1]["snmp_ok"] is False


def test_zbxproxy_load_config_uses_monitoring_server_setting():
    import pytest
    from types import SimpleNamespace
    from routes.agents import _zbxproxy_load_config
    from api import HTTPException
    hub = SimpleNamespace(state=SimpleNamespace(system_state={"global_config": {}}))
    with pytest.raises(HTTPException):
        _zbxproxy_load_config(hub, {})
    hub.state.system_state["global_config"]["monitoring_server"] = "zbx.example.com:10051"
    assert _zbxproxy_load_config(hub, {})["server"] == "zbx.example.com:10051"
    assert _zbxproxy_load_config(hub, {"server": "x"})["server"] == "x"
    assert _zbxproxy_load_config(hub, {})["proxy_name"] == "lm-default"
    assert _zbxproxy_load_config(hub, {"proxy_name": "mine"})["proxy_name"] == "mine"


def test_zbxproxy_default_name_follows_tenant_proxies_mapping():
    # A reinstall without a name must keep the proxy the monitoring sync
    # assigns the tenant's hosts to, not rename it to lm-<tenant>.
    from types import SimpleNamespace
    from routes.agents import _zbxproxy_load_config
    gc = {"monitoring_server": "zbx:10051", "monitoring_tls": False,
          "monitoring": {"tenant_proxies": {"default": "mipbe-default"}}}
    hub = SimpleNamespace(state=SimpleNamespace(system_state={"global_config": gc},
                                                get_spoke_tenant=lambda pk: pk and "dxp"),
                          _primary_key=lambda s: s)
    assert _zbxproxy_load_config(hub, {})["proxy_name"] == "mipbe-default"
    assert _zbxproxy_load_config(hub, {}, "s1")["proxy_name"] == "lm-dxp"


def test_monitoring_hosts_are_tenant_scoped_and_problems_flattened():
    from routes import monitoring as m
    hosts = [
        {"name": "a", "tenant": "t1", "problems": [{"name": "p1", "severity": 2, "clock": 5}]},
        {"name": "b", "tenant": "t2", "problems": [{"name": "p2", "severity": 5, "clock": 1}]},
    ]
    user = {"user": {"tenants": ["t1"]}}
    assert [h["name"] for h in m.scope_monitoring_hosts(hosts, None, user, False)] == ["a"]
    assert m.scope_monitoring_hosts(hosts, "t2", user, False) == []
    assert [h["name"] for h in m.scope_monitoring_hosts(hosts, "t2", user, True)] == ["b"]
    assert m.scope_monitoring_hosts(hosts, "default", {}, True) == []
    assert len(m.scope_monitoring_hosts(hosts, None, {}, True)) == 2
    assert m.scope_monitoring_hosts(hosts, None, {"user": {}}, False) == []
    assert [p["name"] for p in m.monitoring_problem_list(hosts)] == ["p2", "p1"]


def test_monitoring_sync_config_defaults_and_status_record():
    hub = SimpleNamespace(state=SimpleNamespace(
        system_state={"global_config": {}}, _mark_dirty=lambda: None))
    assert monitoring.monitoring_sync_config(hub) == {"enabled": True, "interval_minutes": 5}
    hub.state.system_state["global_config"]["monitoring_sync"] = {"enabled": False, "interval_minutes": 15}
    assert monitoring.monitoring_sync_config(hub) == {"enabled": False, "interval_minutes": 15}
    monitoring.record_monitoring_sync(hub, res={"payload": {"data": {"created": 2, "errors": ["x"]}}})
    st = hub.state.system_state["global_config"]["monitoring_sync_status"]
    assert st["status"] == "error" and st["created"] == 2 and st["errors"] == 1


def test_device_moved_into_tenant_group_uses_member_snmp_and_proxies(monkeypatch):
    import access

    async def fake_overlay_many(hub, records, storage_key):
        return records

    async def snmp_secrets(hub, sec_type, buckets=None):
        return [{"bucket": "default", "name": "SNMP", "value": {"snmp_community": "mbr"}}]

    monkeypatch.setattr(cred_vault, "automation_list_by_type", snmp_secrets)
    monkeypatch.setattr(instance_vault, "overlay_many", fake_overlay_many)
    monkeypatch.setattr(access, "_GROUP_MEMBERS", {"group:ssplm": {"shared", "default"}})
    hub = SimpleNamespace(state=SimpleNamespace(system_state={"global_config": {"nw_devices": [
        {"name": "sw1", "address": "10.0.0.1", "tenant_id": "group:ssplm", "transport": "ssh",
         "snmp_ok": True, "moved_from": {"tenant_id": "default", "spoke_id": "s1"}}]}}))
    (d,) = asyncio.run(monitoring.inventory_devices(hub))
    assert d["snmp_community"] == "mbr" and d["snmp"]
    assert d["proxy_tenants"] == ["default", "shared"] and d["moved_from"] == "default"


def test_ipam_pinned_ips_are_monitored_by_snmp_or_ping(monkeypatch):
    async def fake_overlay_many(hub, records, storage_key):
        return records

    async def snmp_secrets(hub, sec_type, buckets=None):
        return [{"bucket": "t1", "name": "SNMP", "value": {"snmp_community": "v"}}]

    monkeypatch.setattr(cred_vault, "automation_list_by_type", snmp_secrets)
    monkeypatch.setattr(instance_vault, "overlay_many", fake_overlay_many)
    hub = SimpleNamespace(state=SimpleNamespace(system_state={"global_config": {
        "nw_devices": [{"name": "sw1", "address": "10.0.0.1", "tenant_id": "t1"},
                       {"name": "sw2", "address": "10.0.0.2", "tenant_id": "t1", "snmp_ok": True}],
        "monitoring_watch": {"t1": {"10.0.0.1": {"name": ""},             # unverified device
                                    "10.0.0.2": {"name": "x"},            # verified device
                                    "10.0.0.5": {"name": "pdu-a"},        # new, ping only
                                    "10.0.0.6": {"name": "sw1"}}},        # name clash -> IP
    }}))
    rows = asyncio.run(monitoring.inventory_devices(hub))
    assert sorted((r["name"], r["ip"], r["snmp"]) for r in rows) == [
        ("10.0.0.6", "10.0.0.6", False), ("pdu-a", "10.0.0.5", False),
        ("sw1", "10.0.0.1", False), ("sw2", "10.0.0.2", True)]
