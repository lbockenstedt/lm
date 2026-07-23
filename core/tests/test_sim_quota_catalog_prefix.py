"""Source-tagging + ``Central:``/``Mist:`` prefix for the shared alert/insight
catalog (Phase 1 of the Mist build).

Central and Mist are separate products. The hub-wide ``__alert_insight_history__``
catalog stamps each observed alert/insight with a ``source`` (``central``/``mist``)
on write; readers default a missing source to ``central`` (every pre-Mist row is
Aruba). The Sim-Quota picker catalog emits the id PREFIXED (``Central:``/``Mist:``)
so a Central alert and a Mist alert with the same bare name are distinct options
and the engine can route a row to its source — while the STORED id stays bare
(dashboard / reports / firing compare bare). These tests pin the store-level
source tag + lazy migration + the prefix helpers the catalog closure uses.
"""
from simulations.store import SimulationsStore
from simulations.sim_quota import parse_alert_source, prefixed_alert_id


# ── prefix helpers (the catalog closure's prefix-on-read transform) ─────────

def test_parse_alert_source_splits_or_defaults_central():
    assert parse_alert_source("Central:DNS Fail") == ("central", "DNS Fail")
    assert parse_alert_source("Mist:ap_offline") == ("mist", "ap_offline")
    # legacy bare id (pre-Mist row, or an untethered row's display) -> central
    assert parse_alert_source("DNS Fail") == ("central", "DNS Fail")
    assert parse_alert_source("") == ("central", "")
    # unknown prefix / empty after colon -> central + bare
    assert parse_alert_source("Foo:bar") == ("central", "Foo:bar")
    assert parse_alert_source("Mist:") == ("central", "Mist:")


def test_prefixed_alert_id_renders_and_is_idempotent():
    assert prefixed_alert_id("mist", "ap_offline") == "Mist:ap_offline"
    assert prefixed_alert_id("central", "DNS Fail") == "Central:DNS Fail"
    assert prefixed_alert_id(None, "x") == "Central:x"  # unknown -> central
    assert prefixed_alert_id("mist", "Mist:ap_offline") == "Mist:ap_offline"  # idempotent
    assert prefixed_alert_id("central", "Central:DNS Fail") == "Central:DNS Fail"
    assert prefixed_alert_id("mist", "") == ""


# ── store: source tag on write + default on read + lazy migration ───────────

async def test_record_tags_source_and_defaults_central(tmp_path):
    s = SimulationsStore(str(tmp_path))
    await s.record_alert_insight_seen([
        {"type": "alert", "id": "ap_offline", "name": "ap_offline", "site": "MIA",
         "source": "mist"},
        {"type": "alert", "id": "DNS Fail", "name": "DNS Fail", "site": "MIA"},  # no source
    ])
    hist = {f"{e['type']}:{e['id']}": e for e in await s.get_alert_insight_history()}
    assert hist["alert:ap_offline"]["source"] == "mist"
    # missing source defaults to central on write.
    assert hist["alert:DNS Fail"]["source"] == "central"
    # invalid source coerces to central.
    await s.record_alert_insight_seen([
        {"type": "alert", "id": "weird", "name": "weird", "site": "", "source": "foo"}])
    hist = {f"{e['type']}:{e['id']}": e for e in await s.get_alert_insight_history()}
    assert hist["alert:weird"]["source"] == "central"


async def test_legacy_entry_defaults_central_on_read(tmp_path):
    """A row written before ``source`` existed (manually seeded, no source field)
    reads back as source=central so the picker can prefix it Central:."""
    import time as _t
    s = SimulationsStore(str(tmp_path))
    s._data[s._AIH_KEY] = {
        "alert:LEGACY": {"type": "alert", "id": "LEGACY", "name": "LEGACY", "site": "",
                         "first_seen": _t.time(), "last_seen": _t.time()}}
    hist = {f"{e['type']}:{e['id']}": e for e in await s.get_alert_insight_history()}
    assert hist["alert:LEGACY"]["source"] == "central"


async def test_lazy_migration_backfills_source_on_next_write(tmp_path):
    """A legacy entry re-observed by the central poller is backfilled source=central
    and that backfill persists (one-time write, no churn after)."""
    import time as _t
    s = SimulationsStore(str(tmp_path))
    s._data[s._AIH_KEY] = {
        "alert:AP_DOWN": {"type": "alert", "id": "AP_DOWN", "name": "AP_DOWN", "site": "MIA",
                          "first_seen": _t.time(), "last_seen": _t.time()}}
    # Re-observe from the central poller path (source=central): migration backfills.
    added = await s.record_alert_insight_seen([
        {"type": "alert", "id": "AP_DOWN", "name": "AP_DOWN", "site": "MIA", "source": "central"}])
    assert added == 0  # not a new entry
    hist = {f"{e['type']}:{e['id']}": e for e in await s.get_alert_insight_history()}
    assert hist["alert:AP_DOWN"]["source"] == "central"
    # Reload from disk to confirm the backfill persisted.
    s2 = SimulationsStore(str(tmp_path))
    hist2 = {f"{e['type']}:{e['id']}": e for e in await s2.get_alert_insight_history()}
    assert hist2["alert:AP_DOWN"]["source"] == "central"


async def test_central_and_mist_same_bare_id_share_storage_key(tmp_path):
    """The stored id stays BARE and the storage key is ``type:bare_id`` (no source
    in the key) — so the dashboard/reports/firing compare bare. The SOURCE field
    (not the key) is the seam. A later sighting from a different product updates
    the source (rare; the user guarantees Mist/Central alerts differ in name)."""
    s = SimulationsStore(str(tmp_path))
    await s.record_alert_insight_seen([
        {"type": "alert", "id": "shared_id", "name": "shared_id", "site": "MIA", "source": "central"}])
    hist = {f"{e['type']}:{e['id']}": e for e in await s.get_alert_insight_history()}
    assert "alert:shared_id" in hist  # bare key, no source prefix
    assert hist["alert:shared_id"]["id"] == "shared_id"  # stored id stays bare
    assert hist["alert:shared_id"]["source"] == "central"