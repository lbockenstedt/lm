"""Unit tests for the per-tenant/per-module JSON sharding helper.

Pure stdlib (no create_app import) so it runs under the 3.9 sandbox. Covers the
round-trip (save→load merge), dirty-only writes, empty-slice file removal, the
one-time legacy migration (split + archive), and the corruption-recovery resets.
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import tenant_sharded as ts  # noqa: E402


def _mk(tmp):
    return str(tmp)


def test_save_load_roundtrip_composite_keys(tmp_path):
    d = _mk(tmp_path)
    resident = {
        f"t1{ts._KEYSEP}siteA{ts._KEYSEP}chk1": {"ok": 1},
        f"t1{ts._KEYSEP}siteA{ts._KEYSEP}chk2": {"ok": 2},
        f"t2{ts._KEYSEP}siteB{ts._KEYSEP}chk1": {"ok": 3},
    }
    ts.shard_save(d, "simulations", "check_health_history.json", resident)
    # one file per tenant
    assert os.path.exists(ts.shard_path(d, "t1", "simulations", "check_health_history.json"))
    assert os.path.exists(ts.shard_path(d, "t2", "simulations", "check_health_history.json"))
    merged = ts.shard_load(d, "simulations", "check_health_history.json")
    assert merged == resident


def test_dirty_only_writes_one_tenant(tmp_path):
    d = _mk(tmp_path)
    resident = {f"t1{ts._KEYSEP}s{ts._KEYSEP}c": {"v": 1},
                f"t2{ts._KEYSEP}s{ts._KEYSEP}c": {"v": 2}}
    ts.shard_save(d, "m", "n.json", resident)
    p2 = ts.shard_path(d, "t2", "m", "n.json")
    mtime2 = os.path.getmtime(p2)
    # change only t1, save with dirty={t1} → t2 file untouched
    resident[f"t1{ts._KEYSEP}s{ts._KEYSEP}c"] = {"v": 99}
    ts.shard_save(d, "m", "n.json", resident, dirty={"t1"})
    assert os.path.getmtime(p2) == mtime2
    assert ts.shard_load(d, "m", "n.json")[f"t1{ts._KEYSEP}s{ts._KEYSEP}c"] == {"v": 99}


def test_empty_slice_removes_file(tmp_path):
    d = _mk(tmp_path)
    resident = {f"t1{ts._KEYSEP}s{ts._KEYSEP}c": {"v": 1}}
    ts.shard_save(d, "m", "n.json", resident)
    p = ts.shard_path(d, "t1", "m", "n.json")
    assert os.path.exists(p)
    # drop t1's only key, mark dirty → file removed
    resident.clear()
    ts.shard_save(d, "m", "n.json", resident, dirty={"t1"})
    assert not os.path.exists(p)


def test_tenant_keyed_grouper(tmp_path):
    d = _mk(tmp_path)
    resident = {"t1": {"status": "ok"}, "t2": {"status": "warn"}}
    ts.shard_save(d, "simulations", "central_hub_status.json", resident,
                  tenant_of=lambda k: k)  # keyed directly by tenant
    merged = ts.shard_load(d, "simulations", "central_hub_status.json")
    assert merged == resident


def test_migrate_legacy_splits_and_archives(tmp_path):
    d = _mk(tmp_path)
    legacy = os.path.join(d, "check_poll_window.json")
    data = {f"t1{ts._KEYSEP}s{ts._KEYSEP}c": [[1, True]],
            f"t2{ts._KEYSEP}s{ts._KEYSEP}c": [[2, False]]}
    with open(legacy, "w") as f:
        json.dump(data, f)
    assert ts.migrate_legacy(d, "simulations", "check_poll_window.json") is True
    # legacy archived, shards created, content preserved
    assert not os.path.exists(legacy)
    assert os.path.exists(legacy + ".migrated")
    assert ts.shard_load(d, "simulations", "check_poll_window.json") == data
    # second call is a no-op (shards already exist)
    assert ts.migrate_legacy(d, "simulations", "check_poll_window.json") is False


def test_encrypt_decrypt_hooks(tmp_path):
    d = _mk(tmp_path)
    # trivial reversible "encryption" to exercise the hooks
    enc = lambda s: ("ENC:" + s).encode("utf-8")
    dec = lambda b: b.decode("utf-8")[4:]
    resident = {"t1": {"a": 1}}
    ts.shard_save(d, "simulations", "simulations_cache.json", resident,
                  tenant_of=lambda k: k, encrypt=enc)
    raw = open(ts.shard_path(d, "t1", "simulations", "simulations_cache.json"), "rb").read()
    assert raw.startswith(b"ENC:")
    assert ts.shard_load(d, "simulations", "simulations_cache.json", decrypt=dec) == resident


def test_snapshot_save_load_roundtrip(tmp_path):
    d = _mk(tmp_path)
    p = os.path.join(d, "pxmx", "agents_cache.json")
    obj = {"data": [{"agent_id": "a1"}], "ts": 123.0}
    ts.snapshot_save(p, obj)
    assert ts.snapshot_load(p) == obj
    # absent → default; encrypt hook round-trips
    assert ts.snapshot_load(os.path.join(d, "nope.json"), default={"x": 1}) == {"x": 1}
    enc = lambda s: ("E:" + s).encode("utf-8")
    dec = lambda b: b.decode("utf-8")[2:]
    p2 = os.path.join(d, "le", "cert_reports.json")
    ts.snapshot_save(p2, obj, encrypt=enc)
    assert open(p2, "rb").read().startswith(b"E:")
    assert ts.snapshot_load(p2, decrypt=dec) == obj


def test_reset_tenant_and_global(tmp_path):
    d = _mk(tmp_path)
    ts.shard_save(d, "simulations", "a.json", {"t1": {"x": 1}}, tenant_of=lambda k: k)
    ts.shard_save(d, "nw", "b.json", {"t1": {"y": 2}, "t2": {"y": 3}}, tenant_of=lambda k: k)
    # a data_dir-root config file must survive both resets
    cfg = os.path.join(d, "simulations_store.json")
    with open(cfg, "w") as f:
        f.write("{}")
    # per-tenant reset removes only t1's subtree
    n = ts.reset_tenant_files(d, "t1")
    assert n >= 2
    assert not os.path.isdir(os.path.join(ts.tenants_root(d), "t1"))
    assert os.path.isdir(os.path.join(ts.tenants_root(d), "t2"))
    assert os.path.exists(cfg)
    # global reset removes the whole tenants/ tree, config still intact
    ts.reset_all_tenant_files(d)
    assert not os.path.isdir(ts.tenants_root(d))
    assert os.path.exists(cfg)
