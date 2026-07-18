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
validate_nsg_priorities = _tm.validate_nsg_priorities


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


# ── 3. priority ordering validation (NEW rule: allow < deny < 1000) ──────────
# Azure evaluates LOWER priority numbers FIRST → the ALLOW rule must be evaluated
# before the DENY rule, and both must sit below Azure's default allow on 443
# (priority 1000). Invariant: allow_priority < block_priority < 1000.

def test_validate_nsg_priorities_ok():
    ok, msg = validate_nsg_priorities(300, 400)   # allow < deny < 1000
    assert ok is True and msg == ""
    ok, _ = validate_nsg_priorities(100, 999)
    assert ok is True


def test_validate_nsg_priorities_allow_not_below_deny():
    # allow >= deny → violation naming both numbers.
    ok, msg = validate_nsg_priorities(400, 300)
    assert ok is False and "must be LOWER than Deny" in msg
    assert "400" in msg and "300" in msg
    # equal is also a violation.
    ok, msg = validate_nsg_priorities(300, 300)
    assert ok is False and "must be LOWER than Deny" in msg


def test_validate_nsg_priorities_deny_not_below_1000():
    # allow < deny but deny >= 1000 → below-1000 violation.
    ok, msg = validate_nsg_priorities(300, 1000)
    assert ok is False and "below 1000" in msg
    ok, msg = validate_nsg_priorities(300, 1500)
    assert ok is False and "below 1000" in msg


def test_validate_nsg_priorities_both_above_1000():
    # allow >= deny AND both >= 1000 → multiple violations reported.
    ok, msg = validate_nsg_priorities(1200, 1100)
    assert ok is False
    assert "must be LOWER than Deny" in msg and "below 1000" in msg


def test_validate_nsg_priorities_unparseable():
    ok, msg = validate_nsg_priorities("x", 300)
    assert ok is False and "integer" in msg
    ok, msg = validate_nsg_priorities(300, None)
    assert ok is False and "integer" in msg


def test_priority_conflict_warning_backcompat_alias():
    # Legacy arg order is (block, allow). "" when valid (allow < block < 1000).
    assert priority_conflict_warning(400, 300) == ""      # deny=400, allow=300 — OK
    assert priority_conflict_warning(300, 300) != ""      # equal — violation
    assert priority_conflict_warning(200, 300) != ""      # deny < allow — violation (new rule)
    assert priority_conflict_warning(1500, 300) != ""     # deny >= 1000 — violation


def test_fresh_defaults_satisfy_invariant():
    # A fresh install must satisfy allow(300) < deny(400) < 1000.
    assert _tm._DEFAULTS["block_priority"] == 400
    ok, msg = validate_nsg_priorities(300, _tm._DEFAULTS["block_priority"])
    assert ok is True and msg == ""


# ── 4. save-rejection logic (pure-logic mirror of the route guards) ─────────
# create_app cannot import under Python 3.9 (unrelated `int|None` annotations in
# sibling modules), so the two save endpoints' guard is exercised at the pure
# validate_nsg_priorities level exactly as the routes call it.

def test_security_config_save_rejects_bad_deny():
    # PUT /api/security/config validates the incoming deny against CURRENT allow.
    current_allow = 300
    ok, message = validate_nsg_priorities(current_allow, 200)  # deny below allow
    assert ok is False          # → route raises HTTP 400 with `message`
    assert "300" in message and "200" in message


def test_azure_nsg_save_rejects_bad_allow():
    # POST /setup/azure-nsg validates the incoming allow against CURRENT deny.
    current_deny = 400
    ok, message = validate_nsg_priorities(500, current_deny)   # allow above deny
    assert ok is False
    assert "500" in message and "400" in message
    # A valid pair passes → route persists + reconciles.
    ok, _ = validate_nsg_priorities(350, current_deny)
    assert ok is True
