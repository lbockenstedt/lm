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
        {"name": "sw1", "address": "10.0.0.1/24", "tenant": "t1", "type": "switch"},
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
                        "object_type": "cx_switch", "transport": "ssh"}],
        "nw_scan_credentials": [{"tenant_id": "t1", "snmp_community": "pub"}]}}))
    (d,) = asyncio.run(monitoring.inventory_devices(hub))
    assert d["type"] == "cx_switch" and d["snmp"] and d["snmp_community"] == "pub"


def test_vault_snmp_secret_applies_to_tenant_devices(monkeypatch):
    async def fake_overlay_many(hub, records, storage_key):
        return records

    async def snmp_secrets(hub, sec_type, buckets=None):
        assert sec_type == "snmp"
        return [{"bucket": "t1", "name": "SNMP", "value": {"snmp_community": "vaulted"}}]

    monkeypatch.setattr(cred_vault, "automation_list_by_type", snmp_secrets)
    monkeypatch.setattr(instance_vault, "overlay_many", fake_overlay_many)
    hub = SimpleNamespace(state=SimpleNamespace(system_state={"global_config": {
        "nw_devices": [{"name": "a", "address": "10.0.0.1", "tenant_id": "t1"},
                       {"name": "b", "address": "10.0.0.2", "tenant_id": "t2"}]}}))
    a, b = asyncio.run(monitoring.inventory_devices(hub))
    assert a["snmp_community"] == "vaulted" and a["snmp"]
    assert not b["snmp"]


def test_admin_slot_snmp_secret_is_the_global_default(monkeypatch):
    async def fake_overlay_many(hub, records, storage_key):
        return records

    async def snmp_secrets(hub, sec_type, buckets=None):
        return [{"bucket": cred_vault.ADMIN_BUCKET, "name": "SNMP", "value": {"snmp_community": "adm"}}]

    monkeypatch.setattr(cred_vault, "automation_list_by_type", snmp_secrets)
    monkeypatch.setattr(instance_vault, "overlay_many", fake_overlay_many)
    hub = SimpleNamespace(state=SimpleNamespace(system_state={"global_config": {
        "nw_devices": [{"name": "a", "address": "10.0.0.1", "tenant_id": "other"}]}}))
    (a,) = asyncio.run(monitoring.inventory_devices(hub))
    assert a["snmp_community"] == "adm"


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
