"""Tests for the Sim-Quota config foundation — hub twin.

Byte-identical schema/validation block to ``cs/lm-spoke/src/sim_quota.py`` plus
the INI-text catalog helpers (centralized mode parses the store's
``sim_conf_content``; distributed mode forwards to the cs spoke).
"""
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC = HERE.parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from simulations import sim_quota  # noqa: E402

_SIM_CONF = """\
[address]
iperf_server=10.0.0.1
[s0]
wsite=MIA
dhcp_fail=off
dns_fail=off
ping_test=on
www_traffic=on
[s1]
wsite=MIA
assoc_fail=on
www_traffic=on
[s8]
wsite=DFW
dns_fail=on
"""


# ── normalize_quota ────────────────────────────────────────────────────────
def test_normalize_quota_defaults_multi_capable_from_sim_meta():
    q = sim_quota.normalize_quota({"alert_id": "CLIENT_DHCP_FAILURE", "sim_id": "dhcp_fail", "count": "10", "site": "MIA"})
    assert q["sim_id"] == "dhcp_fail"
    assert q["count"] == 10
    assert q["multi_capable"] is False
    assert q["enabled"] is False
    assert q["alert_type"] == "alert"


def test_normalize_quota_traffic_sim_defaults_multi_capable_true():
    assert sim_quota.normalize_quota({"alert_id": "X", "sim_id": "ping_test", "count": 5})["multi_capable"] is True


def test_normalize_quota_explicit_multi_capable_overrides_default():
    assert sim_quota.normalize_quota({"alert_id": "X", "sim_id": "dhcp_fail", "multi_capable": True})["multi_capable"] is True


def test_normalize_quota_count_floor():
    assert sim_quota.normalize_quota({"alert_id": "X", "sim_id": "dns_fail", "count": 0})["count"] == 1
    assert sim_quota.normalize_quota({"alert_id": "X", "sim_id": "dns_fail", "count": "7"})["count"] == 7
    assert sim_quota.normalize_quota({"alert_id": "X", "sim_id": "dns_fail", "count": "garbage"})["count"] == 1


# ── validate_sim_quotas / resolve ──────────────────────────────────────────
def test_validate_drops_missing_fields():
    clean, errs = sim_quota.validate_sim_quotas(
        [{"sim_id": "dns_fail"}, {"alert_id": "X"}], ["dns_fail"])
    assert clean == [] and len(errs) == 2


def test_validate_drops_unknown_sim_when_set_provided():
    clean, errs = sim_quota.validate_sim_quotas(
        [{"alert_id": "A", "sim_id": "nope", "count": 3}], ["dns_fail", "dhcp_fail"])
    assert clean == [] and any("nope" in e for e in errs)


def test_validate_no_sim_set_skips_filter():
    clean, _ = sim_quota.validate_sim_quotas([{"alert_id": "A", "sim_id": "nope", "count": 3}], None)
    assert len(clean) == 1 and clean[0]["sim_id"] == "nope"


def test_validate_dedupe_last_wins():
    clean, _ = sim_quota.validate_sim_quotas(
        [{"alert_id": "A", "sim_id": "dns_fail", "count": 3, "site": "MIA"},
         {"alert_id": "A", "sim_id": "dhcp_fail", "count": 7, "site": "MIA"}],
        ["dns_fail", "dhcp_fail"])
    assert len(clean) == 1 and clean[0]["count"] == 7


def test_resolve_effective_quotas_only_enabled():
    eff = sim_quota.resolve_effective_quotas(
        [{"alert_id": "A", "sim_id": "dns_fail", "enabled": True, "count": 10, "site": "MIA"},
         {"alert_id": "B", "sim_id": "dhcp_fail", "enabled": False, "count": 5, "site": "MIA"}],
        ["dns_fail", "dhcp_fail"])
    assert len(eff) == 1 and eff[0]["alert_id"] == "A"


# ── merge_effective_quotas (global defaults + tenant overrides) ────────────
def test_merge_tenant_overrides_win_per_alert():
    g = [{"alert_id": "A", "sim_id": "dhcp_fail", "count": 10, "site": "", "enabled": True},
         {"alert_id": "B", "sim_id": "dns_fail", "count": 8, "site": "", "enabled": True}]
    t = [{"alert_id": "A", "sim_id": "dhcp_fail", "count": 5, "site": "MIA", "enabled": True}]
    eff = sim_quota.merge_effective_quotas(g, t)
    # Tenant owns alert A entirely (global A dropped); alert B inherits global.
    by = {(q["alert_id"], q["site"]): q for q in eff}
    assert ("A", "MIA") in by and by[("A", "MIA")]["count"] == 5
    assert ("A", "") not in by                       # global A superseded
    assert ("B", "") in by and by[("B", "")]["count"] == 8


def test_merge_global_applies_when_tenant_silent():
    g = [{"alert_id": "A", "sim_id": "dhcp_fail", "count": 10, "site": "", "enabled": True}]
    eff = sim_quota.merge_effective_quotas(g, [])
    assert len(eff) == 1 and eff[0]["alert_id"] == "A" and eff[0]["count"] == 10


def test_merge_disabled_rows_excluded():
    g = [{"alert_id": "A", "sim_id": "dhcp_fail", "count": 10, "enabled": True},
         {"alert_id": "B", "sim_id": "dns_fail", "count": 8, "enabled": False}]
    t = [{"alert_id": "A", "sim_id": "dhcp_fail", "count": 3, "enabled": False}]
    eff = sim_quota.merge_effective_quotas(g, t)
    # Tenant's A is disabled → tenant owns alert A but contributes no enabled
    # rows → A drops entirely (global A NOT reinstated). B disabled globally.
    assert eff == []


def test_merge_tenant_multiple_sites_for_one_alert():
    g = [{"alert_id": "A", "sim_id": "dhcp_fail", "count": 10, "site": "", "enabled": True}]
    t = [{"alert_id": "A", "sim_id": "dhcp_fail", "count": 5, "site": "MIA", "enabled": True},
         {"alert_id": "A", "sim_id": "dhcp_fail", "count": 7, "site": "DFW", "enabled": True}]
    eff = sim_quota.merge_effective_quotas(g, t)
    sites = sorted(q["site"] for q in eff if q["alert_id"] == "A")
    assert sites == ["DFW", "MIA"]                   # tenant's two sites; global "" gone
    assert all(q["alert_id"] == "A" for q in eff)


def test_merge_drops_tenant_quota_for_unknown_sim():
    # Tenant side is filtered against SIM_META — a quota pointing at a sim not in
    # SIM_META (typo, or a primitive removed in a refresh) is dropped, so the
    # global default for that alert reinstates (tenant no longer "owns" it).
    g = [{"alert_id": "A", "sim_id": "dns_fail", "count": 8, "site": "", "enabled": True}]
    t = [{"alert_id": "A", "sim_id": "not_a_real_sim", "count": 5, "site": "MIA",
          "enabled": True}]
    eff = sim_quota.merge_effective_quotas(g, t)
    # The bogus tenant row is dropped → tenant doesn't own alert A → global wins.
    assert len(eff) == 1
    assert eff[0]["sim_id"] == "dns_fail"
    assert eff[0]["site"] == "" and eff[0]["count"] == 8


# ── catalog from raw INI text (centralized mode) ───────────────────────────
def test_available_sims_from_ini():
    sims = sim_quota.available_sims_from_ini(_SIM_CONF)
    ids = [s["sim_id"] for s in sims]
    assert "ping_test" in ids and "assoc_fail" in ids and "dns_fail" in ids
    # Bucket sims lead; a PRIMITIVE not named in any bucket (e.g. download) trails.
    assert ids.index("ping_test") < ids.index("download")
    for s in sims:
        assert "category" in s and "multi_capable" in s


def test_available_sites_from_ini_merges_central_mappings():
    sites = sim_quota.available_sites_from_ini(_SIM_CONF, {"MIA": "MIA-CENTRAL", "ATL": "ATL-CENTRAL"})
    assert "MIA" in sites and "DFW" in sites and "ATL" in sites and "ATL-CENTRAL" in sites
    assert sites == sorted(sites)


def test_sim_quota_catalog_from_ini_shape():
    cat = sim_quota.sim_quota_catalog_from_ini(_SIM_CONF, {"MIA": "MIA"})
    assert set(cat.keys()) == {"sims", "sites", "suggested", "meta"}
    assert cat["suggested"]["CLIENT_DHCP_FAILURE"] == "dhcp_fail"
    assert "dns_fail" in cat["meta"]


def test_available_sims_from_empty_ini_still_lists_all_primitives():
    # Empty/broken INI → fall back to the full SIM_META catalog.
    sims = sim_quota.available_sims_from_ini("")
    assert len(sims) == len(sim_quota.SIM_META)


# ── global defaults store (Setup → Simulations) ────────────────────────────
async def test_global_sim_quota_defaults_roundtrip_and_isolation(tmp_path):
    from simulations.store import SimulationsStore
    s = SimulationsStore(str(tmp_path))
    assert await s.get_sim_quota_defaults() == []
    await s.set_sim_quota_defaults([
        {"alert_id": "CLIENT_DHCP_FAILURE", "sim_id": "dhcp_fail", "count": 10, "site": ""},
        {"alert_id": "CLIENT_DNS_FAILURE", "sim_id": "dns_fail", "count": 8, "site": "MIA"},
    ])
    got = await s.get_sim_quota_defaults()
    assert len(got) == 2 and got[0]["sim_id"] == "dhcp_fail"
    # Global defaults live under __global__ — must NOT bleed into a tenant's
    # central_sites_config.sim_quotas (tenant isolation).
    csc = await s.get_central_sites_config("acme")
    assert csc.get("sim_quotas") in (None, [], {})