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


def test_normalize_quota_learning_default_off_explicit_on():
    assert sim_quota.normalize_quota({"alert_id": "X", "sim_id": "dns_fail"})["learning"] is False
    assert sim_quota.normalize_quota({"alert_id": "X", "sim_id": "dns_fail", "learning": True})["learning"] is True
    assert sim_quota.normalize_quota({"alert_id": "X", "sim_id": "dns_fail", "learning": "true"})["learning"] is True


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

# ── presence quotas (Clients Associated — sim_id empty) ────────────────────
def test_normalize_presence_quota_forces_multi_capable():
    q = sim_quota.normalize_quota({"sim_id": "", "count": 17, "site": "MIA"})
    assert q["sim_id"] == "" and q["site"] == "MIA" and q["count"] == 17
    assert q["multi_capable"] is True
    assert sim_quota.normalize_quota(
        {"sim_id": "", "count": 17, "site": "MIA", "multi_capable": False}
    )["multi_capable"] is True


def test_validate_presence_quota_needs_site_not_alert_id():
    clean, errs = sim_quota.validate_sim_quotas(
        [{"sim_id": "", "count": 17, "site": "MIA", "enabled": True}], ["dns_fail"])
    assert errs == [] and len(clean) == 1
    clean, errs = sim_quota.validate_sim_quotas(
        [{"sim_id": "", "count": 17, "enabled": True}], ["dns_fail"])
    assert clean == [] and any("requires a site" in e for e in errs)


def test_validate_presence_dedup_by_site_last_wins():
    clean, _ = sim_quota.validate_sim_quotas(
        [{"sim_id": "", "count": 17, "site": "MIA", "enabled": True},
         {"sim_id": "", "count": 10, "site": "MIA", "enabled": True},
         {"sim_id": "", "count": 5, "site": "DFW", "enabled": True}])
    assert len(clean) == 2
    assert [c for c in clean if c["site"] == "MIA"][0]["count"] == 10


def test_merge_presence_per_site_tenant_overrides_global():
    # Global presence at MIA + DFW; tenant presence at MIA only → tenant owns
    # MIA (its count wins), DFW inherits global.
    g = [{"sim_id": "", "count": 17, "site": "MIA", "enabled": True},
         {"sim_id": "", "count": 5, "site": "DFW", "enabled": True}]
    t = [{"sim_id": "", "count": 10, "site": "MIA", "enabled": True}]
    eff = sim_quota.merge_effective_quotas(g, t)
    by = {q["site"]: q for q in eff if not q["sim_id"]}
    assert by["MIA"]["count"] == 10          # tenant override wins
    assert by["DFW"]["count"] == 5           # inherited global


def test_merge_presence_tenant_disabled_suppresses_global():
    # A tenant disabled presence row for MIA suppresses the global MIA presence
    # (tenant owns the site; contributes no enabled row) — mirrors sim-quota
    # alert-disable semantics. DFW still inherits.
    g = [{"sim_id": "", "count": 17, "site": "MIA", "enabled": True},
         {"sim_id": "", "count": 5, "site": "DFW", "enabled": True}]
    t = [{"sim_id": "", "count": 99, "site": "MIA", "enabled": False}]
    eff = sim_quota.merge_effective_quotas(g, t)
    sites = {q["site"] for q in eff if not q["sim_id"]}
    assert "MIA" not in sites                 # suppressed by the tenant disable
    assert "DFW" in sites


def test_merge_presence_and_sim_quotas_coexist():
    # Presence (per-site) and sim (per-alert) merge independently without
    # colliding on the (alert_type, alert_id) grouping.
    g = [{"sim_id": "", "count": 17, "site": "MIA", "enabled": True},
         {"alert_id": "A", "sim_id": "dns_fail", "count": 8, "site": "MIA",
          "enabled": True}]
    eff = sim_quota.merge_effective_quotas(g, [])
    pres = [q for q in eff if not q["sim_id"]]
    sim = [q for q in eff if q["sim_id"]]
    assert len(pres) == 1 and pres[0]["site"] == "MIA"
    assert len(sim) == 1 and sim[0]["alert_id"] == "A"


# ── Adaptive harvest controller (design §9) ────────────────────────────────
def _aq(**kw):
    base = {"alert_type": "alert", "alert_id": "DNS Server Failed to Respond",
            "sim_id": "dns_fail", "site": "MIA-PSK", "count": 1,
            "min": 1, "max": 15, "enabled": True}
    base.update(kw)
    return base


def _run_thermostat(q, firing_seq, applied_op=None, start=None):
    """Drive the thermostat through a sequence of (firing, now) ticks; return
    the final state dict. ``firing_seq`` is a list of (firing, now) tuples
    spaced >= settle so each advances."""
    st = start or {}
    for firing, now in firing_seq:
        st = sim_quota.adaptive_step(st, q, firing=firing, now=now,
                                     applied_op=applied_op)
    return st


def test_adaptive_is_on_requires_max_above_min():
    assert sim_quota.adaptive_is_on(_aq(min=1, max=15)) is True
    assert sim_quota.adaptive_is_on(_aq(min=5, max=5)) is False   # min==max → fixed
    assert sim_quota.adaptive_is_on(_aq(max=None)) is False        # no max → fixed
    assert sim_quota.adaptive_is_on({"count": 10}) is False        # plain quota


# ── apply_adaptive_targets: learning-ON probe vs consumer seed/lift ─────────
def test_apply_learning_row_runs_own_probe_target_not_lifted():
    """A learning-ON lab row runs its OWN thermostat target as count — it is the
    source of the learned value, not a consumer of it, so applied_op never
    overrides its probe."""
    lab = _aq(site="DFW", learning=True, min=1, max=15)
    state = {sim_quota.adaptive_key(lab): {"target": 8, "phase": "down_floor",
                                           "learned_op": 11, "last_change": 0}}
    out = sim_quota.apply_adaptive_targets([dict(lab)], state,
                                           {"alert:DNS Server Failed to Respond": {"op": 14}})
    assert out[0]["count"] == 8  # own probe, not lifted to 14


def test_apply_consumer_adopts_max_of_target_and_applied_op():
    """A learning-OFF consumer takes max(its target, applied_op) — lifted up to
    the learned op but never dropped below its working count."""
    lab = _aq(site="DFW", learning=True, min=1, max=15)
    cons = _aq(site="MIA-PSK", learning=False, min=1, max=15)
    state = {
        sim_quota.adaptive_key(lab): {"target": 11, "phase": "stable",
                                      "learned_op": 11, "last_change": 0},
        sim_quota.adaptive_key(cons): {"target": 5, "phase": "up_find",
                                       "last_change": 0},
    }
    out = sim_quota.apply_adaptive_targets([dict(lab), dict(cons)], state)
    by_site = {q["site"]: q for q in out}
    assert by_site["DFW"]["count"] == 11      # lab own target
    assert by_site["MIA-PSK"]["count"] == 11  # consumer lifted 5 → 11


def test_apply_consumer_never_drops_below_working_target():
    """A published global op LOWER than the consumer's working target does not
    drop it (up-only / always-firing)."""
    cons = _aq(site="MIA-PSK", learning=False, min=1, max=15)
    state = {sim_quota.adaptive_key(cons): {"target": 9, "phase": "stable",
                                            "last_change": 0}}
    out = sim_quota.apply_adaptive_targets([dict(cons)], state,
                                           {"alert:DNS Server Failed to Respond": {"op": 4}})
    assert out[0]["count"] == 9  # kept its working count; op=4 ignored


def test_apply_consumer_cold_start_seeds_from_global():
    """No controller state yet + a published global op → consumer seeds at the
    global op (its initial starting point), not min."""
    cons = _aq(site="MIA-PSK", learning=False, min=1, max=15)
    out = sim_quota.apply_adaptive_targets([dict(cons)], {},
                                           {"alert:DNS Server Failed to Respond": {"op": 11}})
    assert out[0]["count"] == 11


def test_apply_consumer_cold_start_falls_back_to_min():
    """No state and no learned op anywhere → consumer starts at min (bootstrap)."""
    cons = _aq(site="MIA-PSK", learning=False, min=1, max=15)
    out = sim_quota.apply_adaptive_targets([dict(cons)], {})
    assert out[0]["count"] == 1


def test_apply_highest_learned_op_wins_across_learners():
    """Multiple learning-ON stable rows for the same alert: the highest
    learned_op wins as the applied_op consumers adopt."""
    lab_a = _aq(site="DFW", learning=True, min=1, max=15)
    lab_b = _aq(site="ATL", learning=True, min=1, max=20)
    cons = _aq(site="MIA-PSK", learning=False, min=1, max=20)
    state = {
        sim_quota.adaptive_key(lab_a): {"target": 11, "phase": "stable",
                                        "learned_op": 11, "last_change": 0},
        sim_quota.adaptive_key(lab_b): {"target": 14, "phase": "stable",
                                        "learned_op": 14, "last_change": 0},
        sim_quota.adaptive_key(cons): {"target": 3, "phase": "up_find",
                                       "last_change": 0},
    }
    out = sim_quota.apply_adaptive_targets([dict(lab_a), dict(lab_b), dict(cons)],
                                           state)
    by_site = {q["site"]: q for q in out}
    assert by_site["MIA-PSK"]["count"] == 14  # max(11, 14) wins


def test_apply_leaves_fixed_quotas_untouched():
    """A non-adaptive quota (no max>min) keeps its configured count."""
    fixed = {"alert_type": "alert", "alert_id": "X", "sim_id": "ping_test",
             "site": "MIA", "count": 7, "enabled": True}
    out = sim_quota.apply_adaptive_targets([dict(fixed)],
                                           {"alert:X:MIA": {"target": 99}})
    assert out[0]["count"] == 7


# ── adaptive_step: learning-ON full thermostat ──────────────────────────────
def test_learning_on_full_cycle_settles_at_floor_plus_buffer():
    """up_find → down_floor → up_confirm → stable. Threshold fires at >=9;
    the lab ramps to 9, ratchets down to 8 (stops), restores 9, confirms, and
    settles at ceil(9*1.2)=11 with learned_op=11."""
    q = _aq(learning=True, min=1, max=15, step=1, buffer=0.2)
    threshold = 9
    # (firing, now) ticks spaced 1800s. The target entering tick i is i (tick 0
    # cold-seeds to 1; each not-firing up_find tick +1). So targets 1..8 don't
    # fire, 9 fires (down_floor→8), 8 stops (up_confirm→9), 9 fires (stable@11).
    firings = [False, False, False, False, False, False, False, False, False,  # 1..8
               True,   # target=9 fires → down_floor, target→8
               False,  # target=8 stops → up_confirm, target→9
               True]   # target=9 fires → stable @ 11
    seq = [(f, i * 1800) for i, f in enumerate(firings)]
    st = _run_thermostat(q, seq)
    assert st["phase"] == "stable"
    assert st["floor"] == 9
    assert st["learned_op"] == 11
    assert st["target"] == 11
    assert st["mode"] == "stable"


def test_learning_on_floor_relearned_fresh_not_stale():
    """From stable + firing, the lab re-probes down (continuous learning) and
    floor tracks the new probe target — it does NOT get stuck at the old floor."""
    q = _aq(learning=True, min=1, max=15, step=1, buffer=0.2)
    start = {"target": 11, "floor": 9, "phase": "stable", "learned_op": 11,
             "last_change": 0}
    after = sim_quota.adaptive_step(start, q, firing=True, now=10_000)
    assert after["phase"] == "down_floor"
    assert after["floor"] == 11  # re-seeded to the current target, not stuck at 9
    assert after["target"] == 10


def test_learning_on_drift_up_relearning_when_stable_stops_firing():
    """If the learned op stops firing (drift up), stable → up_find ramps higher."""
    q = _aq(learning=True, min=1, max=15, step=1, buffer=0.2)
    start = {"target": 11, "floor": 9, "phase": "stable", "learned_op": 11,
             "last_change": 0}
    after = sim_quota.adaptive_step(start, q, firing=False, now=10_000)
    assert after["phase"] == "up_find"
    assert after["target"] == 12


# ── adaptive_step: learning-OFF consumer (up-only) ──────────────────────────
def test_consumer_cold_start_seeds_from_applied_op():
    q = _aq(learning=False, min=1, max=15, step=1)
    after = sim_quota.adaptive_step({}, q, firing=False, now=0, applied_op=11)
    assert after["target"] == 11
    assert after["phase"] == "up_find"


def test_consumer_holds_when_firing_never_down_ratchets():
    """Consumer firing → hold (stable); a later not-firing tick ramps UP, never
    down, so a firing site can't be driven below its working count."""
    q = _aq(learning=False, min=1, max=15, step=1)
    st = {"target": 9, "phase": "up_find", "last_change": 0}
    hold = sim_quota.adaptive_step(st, q, firing=True, now=10_000)
    assert hold["target"] == 9 and hold["phase"] == "stable"   # held, not decayed
    up = sim_quota.adaptive_step(hold, q, firing=False, now=11_800 + 1800)
    assert up["target"] == 10 and up["phase"] == "up_find"     # ramped up, not down


def test_consumer_at_max_when_ceiling_reached_and_not_firing():
    q = _aq(learning=False, min=1, max=15, step=1)
    st = {"target": 15, "phase": "up_find", "last_change": 0}
    after = sim_quota.adaptive_step(st, q, firing=False, now=10_000)
    assert after["target"] == 15 and after["mode"] == "at_max"


# ── adaptive_step: settle-window guard (applies to both) ────────────────────
def test_adaptive_step_holds_within_settle_window():
    """No target change within 30 min of the last change, even when not firing."""
    q = _aq(learning=True, min=1, max=15, step=1)
    st = {"target": 5, "phase": "up_find", "last_change": 9_900}
    after = sim_quota.adaptive_step(st, q, firing=False, now=10_000)  # 100s < 1800
    assert after["target"] == 5  # unchanged
