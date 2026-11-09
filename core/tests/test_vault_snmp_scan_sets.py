import os
import sys
from types import SimpleNamespace

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import access  # noqa: E402
from routes.monitoring import vault_snmp_scan_sets  # noqa: E402


def _hub(secrets):
    return SimpleNamespace(state=SimpleNamespace(system_state={
        "global_config": {"cred_vault": {"secrets": secrets}}}))


def test_snmp_secret_in_a_tenant_group_bucket_reaches_member_tenants(monkeypatch):
    snmp = {"type": "snmp", "mode": "hub"}
    hub = _hub({"dxp": {"own": snmp}, "group:ssplm": {"shared": snmp},
                "group:other": {"nope": snmp}, "mip": {"mip-only": snmp}})
    monkeypatch.setattr(access, "_GROUP_MEMBERS", {"group:ssplm": {"dxp"}, "group:other": {"mip"}})
    names = {c["name"] for c in vault_snmp_scan_sets(hub, "dxp")}
    assert names == {"own", "shared"}
