"""Tenant scoping of the rack-placement dashboard data."""
from routes.netbox import filter_autorack_report

RES = {"ts": 1, "racked": 5, "named": 7,
       "conflicts": [{"name": "A", "tenant": "ssplm"}, {"name": "B", "tenant": "other"}],
       "cannot": [{"name": "C", "tenant": "SSPLM", "mismatch": True}, {"name": "D", "tenant": ""}]}


def test_tenant_sees_only_its_devices():
    out = filter_autorack_report(RES, {"tenant": "ssplm", "tenant_group": None, "slugs": ["ssplm"], "key": "ssplm"})
    assert [x["name"] for x in out["conflicts"]] == ["A"]
    assert [x["name"] for x in out["cannot"]] == ["C"] and out["mismatches"][0]["name"] == "C"
    assert out["summary"]["racked"] is None


def test_group_scope_uses_member_slugs_and_admin_sees_all():
    grp = filter_autorack_report(RES, {"tenant": None, "tenant_group": "g", "slugs": ["other"], "key": "group:g"})
    assert [x["name"] for x in grp["conflicts"]] == ["B"] and grp["cannot"] == []
    allv = filter_autorack_report(RES, {"tenant": None, "tenant_group": None, "slugs": [], "key": "_all_"})
    assert len(allv["conflicts"]) == 2 and len(allv["cannot"]) == 2 and allv["summary"]["named"] == 7
