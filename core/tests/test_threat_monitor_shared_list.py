"""Threat-monitor shared trusted-list unification (nsg-unify-blockcfg).

Covers the three pure-logic changes:
  1. One-time ``_never`` → ``global_config['azure_nsg']['entries']`` migration
     (union + dedup by CIDR + normalize; existing descriptions preserved).
  2. ``_is_exempt`` honors the shared entries (a bare IP matches its /32 entry).
  3. ``priority_conflict_warning`` (Deny priority must be < Allow priority).
"""
import importlib.util
import json
import os
import sys

import pytest  # noqa: F401  (collected by pytest)

# HARNESS HYGIENE (no production effect): ``core/src/routes/`` contains modules
# (``security.py``, ``azure_nsg.py``) whose bare names collide with the top-level
# ``security`` package and the ``azure_nsg`` engine. Some sibling tests prepend
# ``core/src/routes`` to sys.path without cleanup, so during a full-directory
# collection a bare ``import security`` / ``import azure_nsg`` can resolve to the
# ROUTE module instead. In production ``core/src/routes`` is never on sys.path
# (routes load as ``routes.*``), so the engine + package always win. Load the
# two modules under test STRICTLY from core/src by file path so this test is
# deterministic regardless of collection order.
_SRC = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))


def _load_from_src(modname, relpath):
    target = os.path.join(_SRC, relpath)
    cached = sys.modules.get(modname)
    if cached is not None and getattr(cached, "__file__", None) \
            and os.path.abspath(cached.__file__) == target:
        return cached
    spec = importlib.util.spec_from_file_location(modname, target)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[modname] = mod
    spec.loader.exec_module(mod)
    return mod


# The engine must be resolvable for ThreatMonitor's runtime ``import azure_nsg``.
_load_from_src("azure_nsg", "azure_nsg.py")
_tm = _load_from_src("security.threat_monitor", os.path.join("security", "threat_monitor.py"))
ThreatMonitor = _tm.ThreatMonitor
priority_conflict_warning = _tm.priority_conflict_warning


class _State:
    def __init__(self, data_dir, global_config=None):
        self.data_dir = data_dir
        self.system_state = {"global_config": global_config or {}}
        self.dirtied = 0

    def _mark_dirty(self):
        self.dirtied += 1


class _Hub:
    def __init__(self, state):
        self.state = state


def _entries(hub):
    return hub.state.system_state["global_config"]["azure_nsg"]["entries"]


def _write_tm_file(data_dir, never):
    with open(os.path.join(data_dir, "threat_monitor.json"), "w", encoding="utf-8") as f:
        json.dump({"config": {}, "blocks": {}, "offense": {}, "never": never}, f)


# ── 1. migration ────────────────────────────────────────────────────────────

def test_migration_unions_dedups_normalizes(tmp_path):
    # Existing shared entry (with a description) that also appears in _never;
    # a bare IP and a CIDR only in _never.
    gc = {"azure_nsg": {"entries": [{"ip": "10.0.0.5/32", "description": "keepme"}]}}
    _write_tm_file(str(tmp_path), ["10.0.0.5", "192.168.1.10", "172.16.0.0/24"])
    tm = ThreatMonitor(_Hub(_State(str(tmp_path), gc)))

    ents = _entries(tm.hub)
    by_ip = {e["ip"]: e["description"] for e in ents}
    # Bare IP normalized to /32; CIDR preserved; dupe not duplicated.
    assert "10.0.0.5/32" in by_ip
    assert "192.168.1.10/32" in by_ip
    assert "172.16.0.0/24" in by_ip
    assert len(ents) == 3, ents
    # Existing description preserved (NOT clobbered by "migrated from never-block").
    assert by_ip["10.0.0.5/32"] == "keepme"
    # Newly migrated ones are tagged.
    assert by_ip["192.168.1.10/32"] == "migrated from never-block"
    # _never emptied and persisted empty.
    assert tm._never == []
    with open(os.path.join(str(tmp_path), "threat_monitor.json"), encoding="utf-8") as f:
        assert (json.load(f).get("never") or []) == []


def test_migration_noop_when_never_empty(tmp_path):
    _write_tm_file(str(tmp_path), [])
    tm = ThreatMonitor(_Hub(_State(str(tmp_path), {"azure_nsg": {"entries": []}})))
    assert _entries(tm.hub) == []


# ── 2. exemption via shared list ────────────────────────────────────────────

def test_is_exempt_honors_shared_entries(tmp_path):
    gc = {"azure_nsg": {"entries": [{"ip": "10.0.0.5/32", "description": ""}]}}
    tm = ThreatMonitor(_Hub(_State(str(tmp_path), gc)))
    assert tm._is_exempt("10.0.0.5") is True    # exact IP inside its /32
    assert tm._is_exempt("10.0.0.6") is False


def test_add_trusted_normalizes_and_dedups(tmp_path):
    tm = ThreatMonitor(_Hub(_State(str(tmp_path), {"azure_nsg": {"entries": []}})))
    tm.add_trusted("8.8.8.8", "dns")
    tm.add_trusted("8.8.8.8", "again")   # dupe by CIDR — description updated
    ents = _entries(tm.hub)
    assert [e["ip"] for e in ents] == ["8.8.8.8/32"]
    assert ents[0]["description"] == "again"
    assert tm._is_exempt("8.8.8.8") is True
    tm.remove_trusted("8.8.8.8")         # bare IP removes the /32 entry
    assert _entries(tm.hub) == []


def test_add_trusted_immediately_unblocks_now_exempt_ip(tmp_path):
    tm = ThreatMonitor(_Hub(_State(str(tmp_path), {"azure_nsg": {"entries": []}})))
    tm.block_manual("9.9.9.9", "test")
    assert "9.9.9.9" in tm._blocks
    tm.add_trusted("9.9.9.9")
    assert "9.9.9.9" not in tm._blocks


# ── 3. priority ordering validation ─────────────────────────────────────────

def test_priority_conflict_warning():
    assert priority_conflict_warning(200, 300) == ""      # deny < allow — OK
    assert priority_conflict_warning(300, 300) != ""      # equal — warn
    assert priority_conflict_warning(350, 300) != ""      # deny > allow — warn
    assert priority_conflict_warning("x", 300) == ""      # unparseable — silent
    assert priority_conflict_warning(200, None) == ""
