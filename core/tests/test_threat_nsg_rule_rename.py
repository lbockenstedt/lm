"""ThreatMonitor.reconcile_nsg — renaming the deny (block) rule must delete
the OLD-named rule before creating the new one.

Root cause this locks in: Azure NSG rules are keyed by NAME. set_config()
just overwrites block_rule_name in place; reconcile_nsg() used to only PUT
the new name, leaving the old-named rule (same priority + Inbound direction)
still live in the NSG — ARM then rejects the PUT with SecurityRuleConflict
("Rules cannot have the same Priority and Direction"). self._nsg_live_rule_name
tracks the name actually confirmed pushed (distinct from self._cfg, which
updates synchronously on every set_config() call regardless of whether the
async reconcile has run yet).
"""
import asyncio
import importlib.util
import os
import sys

_SRC = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))


def _load_from_src(modname, relpath):
    target = os.path.join(_SRC, relpath)
    spec = importlib.util.spec_from_file_location(modname, target)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[modname] = mod
    spec.loader.exec_module(mod)
    return mod


if _SRC not in sys.path:
    sys.path.insert(0, _SRC)
_nsg_mod = _load_from_src("azure_nsg", "azure_nsg.py")
_tm = _load_from_src("security.threat_monitor", os.path.join("security", "threat_monitor.py"))
ThreatMonitor = _tm.ThreatMonitor


class _State:
    def __init__(self, data_dir, global_config=None):
        self.data_dir = data_dir
        self.system_state = {"global_config": global_config or {}}

    def _mark_dirty(self):
        pass


class _Hub:
    def __init__(self, state):
        self.state = state


def _tm_for(tmp_path, auto_block=True, block_rule_name="lm-threat-block", block_priority=400):
    gc = {
        "azure_nsg": {
            "subscription_id": "sub-1", "resource_group": "rg-1", "nsg_name": "nsg-1",
            "entries": [],
        },
    }
    tm = ThreatMonitor(_Hub(_State(str(tmp_path), gc)))
    tm._cfg["auto_block"] = auto_block
    tm._cfg["block_rule_name"] = block_rule_name
    tm._cfg["block_priority"] = block_priority
    tm._nsg_live_rule_name = block_rule_name  # simulate "already live under this name"
    return tm


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def _patch_reconcile(monkeypatch):
    calls = []

    # reconcile_nsg() resolves Azure lazily (``import azure_nsg`` INSIDE the
    # coroutine), so it picks up whatever ``sys.modules["azure_nsg"]`` holds at
    # call time. Several sibling threat tests load their own copy of the module
    # into that slot at import time, so patching only this file's ``_nsg_mod``
    # silently missed and the real ARM code ran -- these tests passed alone and
    # failed in a full run with status ERROR. Pin the slot to the object being
    # patched (monkeypatch restores it, so this no longer leaks either).
    monkeypatch.setitem(sys.modules, "azure_nsg", _nsg_mod)

    async def _fake(cfg, azcfg, ips, http=None):
        calls.append({"rule_name": azcfg.get("rule_name"), "ips": list(ips)})
        if not ips:
            return {"applied": True, "prefixes": [], "deleted": True}
        return {"applied": True, "prefixes": list(ips), "deleted": False}
    monkeypatch.setattr(_nsg_mod, "reconcile_allowlist", _fake)

    # Stub the priority-slot sweep so tests never touch ARM. Default: nothing to
    # clear (returns []). test_slot_clear_* override this with a recorder.
    async def _fake_clear(cfg, azcfg, *, priority, direction, keep_name, http=None):
        return []
    monkeypatch.setattr(_nsg_mod, "clear_priority_slot", _fake_clear)
    return calls


def test_rename_deletes_old_rule_before_creating_new_one(tmp_path, monkeypatch):
    calls = _patch_reconcile(monkeypatch)
    tm = _tm_for(tmp_path, block_rule_name="Threat-Block")
    tm._blocks = {"203.0.113.5": {}}

    # Simulate the WebUI rename: set_config() overwrites block_rule_name in
    # place — self._nsg_live_rule_name still holds the OLD name at this point.
    tm.set_config({"block_rule_name": "lm-threat-block"})
    res = _run(tm.reconcile_nsg())

    assert res["status"] == "SUCCESS"
    # Old name deleted (empty ips) BEFORE the new name is created.
    assert calls[0] == {"rule_name": "Threat-Block", "ips": []}
    assert calls[1] == {"rule_name": "lm-threat-block", "ips": ["203.0.113.5"]}
    assert tm._nsg_live_rule_name == "lm-threat-block"


def test_no_rename_does_not_touch_the_old_rule(tmp_path, monkeypatch):
    """A normal config save (e.g. threshold change) that leaves the name
    unchanged must not trigger any delete call — just the one PUT."""
    calls = _patch_reconcile(monkeypatch)
    tm = _tm_for(tmp_path, block_rule_name="lm-threat-block")
    tm._blocks = {"203.0.113.5": {}}

    tm.set_config({"threshold": 10})  # name unchanged
    res = _run(tm.reconcile_nsg())

    assert res["status"] == "SUCCESS"
    assert calls == [{"rule_name": "lm-threat-block", "ips": ["203.0.113.5"]}]


def test_rapid_double_rename_deletes_the_original_live_name_not_the_intermediate(tmp_path, monkeypatch):
    """A -> B -> C before any reconcile fires: self._cfg already reflects "C"
    (set_config updates it synchronously), but self._nsg_live_rule_name is
    still "A" (no reconcile has actually run) — B was never pushed to Azure,
    so only A needs deleting, not B."""
    calls = _patch_reconcile(monkeypatch)
    tm = _tm_for(tmp_path, block_rule_name="A")
    tm._blocks = {}

    tm.set_config({"block_rule_name": "B"})
    tm.set_config({"block_rule_name": "C"})  # no reconcile ran in between
    res = _run(tm.reconcile_nsg())

    assert res["status"] == "SUCCESS"
    assert calls[0]["rule_name"] == "A"  # deletes the ORIGINAL live name
    assert "B" not in [c["rule_name"] for c in calls]  # B never existed in Azure
    assert tm._nsg_live_rule_name == "C"


def test_rename_delete_is_harmless_when_old_rule_never_existed(tmp_path, monkeypatch):
    """auto_block was off when the name last changed, so the 'old' name was
    never actually created — the delete call is still made (reconcile_allowlist
    is 404-tolerant) but must not fail the overall reconcile."""
    calls = _patch_reconcile(monkeypatch)
    tm = _tm_for(tmp_path, block_rule_name="never-existed")
    tm._blocks = {"203.0.113.5": {}}

    tm.set_config({"block_rule_name": "lm-threat-block"})
    res = _run(tm.reconcile_nsg())

    assert res["status"] == "SUCCESS"
    assert calls[0]["rule_name"] == "never-existed"
    assert calls[1]["rule_name"] == "lm-threat-block"


def test_priority_or_auto_block_change_alone_does_not_trigger_a_delete(tmp_path, monkeypatch):
    calls = _patch_reconcile(monkeypatch)
    tm = _tm_for(tmp_path, block_rule_name="lm-threat-block", block_priority=400)
    tm._blocks = {"203.0.113.5": {}}

    tm.set_config({"block_priority": 401})
    _run(tm.reconcile_nsg())

    assert len(calls) == 1
    assert calls[0]["rule_name"] == "lm-threat-block"


def test_fresh_process_boot_does_not_self_delete(tmp_path, monkeypatch):
    """On a fresh ThreatMonitor() with no prior persisted state,
    _nsg_live_rule_name defaults to the same value as block_rule_name — no
    spurious delete of a rule that (as far as we know) is exactly what's live."""
    calls = _patch_reconcile(monkeypatch)
    gc = {"azure_nsg": {"subscription_id": "s", "resource_group": "r", "nsg_name": "n", "entries": []}}
    tm = ThreatMonitor(_Hub(_State(str(tmp_path), gc)))
    tm._cfg["auto_block"] = True
    tm._blocks = {"203.0.113.5": {}}
    tm._nsg_dirty = True

    _run(tm.reconcile_nsg())

    assert len(calls) == 1  # just the PUT, no delete-old-name call
    assert calls[0]["rule_name"] == "lm-threat-block"


def test_slot_clear_runs_with_configured_name_and_priority(tmp_path, monkeypatch):
    """The deny reconcile must sweep the (block_priority, Inbound) slot,
    keeping the CONFIGURED (new) name — this is what deletes a live rule that
    sits in the slot under ANY other name (e.g. an older-version or renamed
    'lm-threat-block') so the subsequent PUT of 'Threat-Monitor-Blocked' does
    not hit SecurityRuleConflict. Regression for: rename saved in config but
    the live Azure rule kept its old name."""
    calls = _patch_reconcile(monkeypatch)
    slot = {}

    async def _rec_clear(cfg, azcfg, *, priority, direction, keep_name, http=None):
        slot.update(priority=priority, direction=direction, keep_name=keep_name,
                    rule_name=azcfg.get("rule_name"))
        return ["lm-threat-block"]  # simulate clearing the stale live rule
    monkeypatch.setattr(_nsg_mod, "clear_priority_slot", _rec_clear)

    tm = _tm_for(tmp_path, block_rule_name="lm-threat-block", block_priority=200)
    tm._blocks = {"203.0.113.5": {}}
    tm.set_config({"block_rule_name": "Threat-Monitor-Blocked"})
    res = _run(tm.reconcile_nsg())

    assert res["status"] == "SUCCESS"
    # Slot swept at the deny priority + Inbound, keeping the NEW configured name.
    assert slot == {"priority": 200, "direction": "Inbound",
                    "keep_name": "Threat-Monitor-Blocked",
                    "rule_name": "Threat-Monitor-Blocked"}
    # And the new-named rule is then PUT with the blocked IP.
    assert calls[-1] == {"rule_name": "Threat-Monitor-Blocked", "ips": ["203.0.113.5"]}


def test_slot_clear_failure_does_not_abort_reconcile(tmp_path, monkeypatch):
    """The slot sweep is best-effort: an ARM hiccup while clearing must not
    prevent the deny rule from being (re)written."""
    calls = _patch_reconcile(monkeypatch)

    async def _boom(cfg, azcfg, *, priority, direction, keep_name, http=None):
        raise RuntimeError("ARM 500")
    monkeypatch.setattr(_nsg_mod, "clear_priority_slot", _boom)

    tm = _tm_for(tmp_path, block_rule_name="lm-threat-block", block_priority=200)
    tm._blocks = {"203.0.113.5": {}}
    tm.set_config({"threshold": 7})  # no rename
    res = _run(tm.reconcile_nsg())

    assert res["status"] == "SUCCESS"
    assert calls[-1] == {"rule_name": "lm-threat-block", "ips": ["203.0.113.5"]}
