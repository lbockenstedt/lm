"""ThreatMonitor strike accounting — forgiving a strike when a block is lifted.

Strikes (``_offense``) are what drive ``permanent_after``: once an address has
that many, its next block is PERMANENT — no TTL, no auto-release. Yet ``unblock``
only ever removed the block record and left the strike banked, so a false
positive stayed on the address's permanent record even after the operator
overturned it. Clear three bad blocks and the fourth is an unappealable ban,
earned entirely from blocks that were all judged wrong.

That is not hypothetical: a shared corporate egress IP (e.g. a proxy whose exit
address rotates) can trip a session-anomaly heuristic repeatedly, and the
operator clearing it each time was silently arming the permanent ban.

Covered here: a manual unblock forgives exactly the strike it overturned,
genuine history is preserved, ``forgive=False`` keeps the strike, the explicit
``forgive()`` clears an accumulated backlog, and the lifetime ``totals`` stay
monotonic throughout (they are evidence, not policy input).
"""
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
_load_from_src("azure_nsg", "azure_nsg.py")
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


def _tm_for(tmp_path, entries=None):
    return ThreatMonitor(_Hub(_State(str(tmp_path), {"azure_nsg": {"entries": entries or []}})))


def _trip(tm, ip):
    """Drive one auto-block for ``ip`` (threshold is set to 1 → 2nd failure)."""
    tm.record_failure(ip, "login")
    tm.record_failure(ip, "login")


# ── unblock forgives the strike it overturned ────────────────────────────────
def test_unblock_forgives_the_strike(tmp_path):
    tm = _tm_for(tmp_path)
    tm.set_config({"threshold": 1, "window_s": 600})
    _trip(tm, "203.0.113.9")
    assert tm._offense["203.0.113.9"] == 1

    res = tm.unblock("203.0.113.9")

    assert res["forgiven"] is True
    assert res["strikes"] == 0
    assert "203.0.113.9" not in tm._offense


def test_repeated_overturned_blocks_never_reach_permanent(tmp_path):
    """The regression that matters: clearing a bad block three times used to
    leave three strikes banked, making the fourth block permanent."""
    tm = _tm_for(tmp_path)
    tm.set_config({"threshold": 1, "window_s": 600, "permanent_after": 3})
    for _ in range(4):
        _trip(tm, "198.51.100.96")
        tm.unblock("198.51.100.96")

    _trip(tm, "198.51.100.96")

    assert tm._blocks["198.51.100.96"]["permanent"] is False
    assert tm._blocks["198.51.100.96"]["expires_at"] is not None


def test_forgive_only_drops_one_strike(tmp_path):
    """Genuine earlier offences must survive — an unblock overturns ONE block,
    not the address's whole history."""
    tm = _tm_for(tmp_path)
    tm.set_config({"threshold": 1, "window_s": 600, "permanent_after": 10})
    for _ in range(3):
        _trip(tm, "203.0.113.9")
        tm.unblock("203.0.113.9", forgive=False)
    assert tm._offense["203.0.113.9"] == 3

    _trip(tm, "203.0.113.9")
    tm.unblock("203.0.113.9")

    assert tm._offense["203.0.113.9"] == 3


def test_unblock_can_keep_the_strike(tmp_path):
    tm = _tm_for(tmp_path)
    tm.set_config({"threshold": 1, "window_s": 600})
    _trip(tm, "203.0.113.9")

    res = tm.unblock("203.0.113.9", forgive=False)

    assert res["forgiven"] is False
    assert tm._offense["203.0.113.9"] == 1


def test_unblock_of_unblocked_ip_is_a_noop(tmp_path):
    tm = _tm_for(tmp_path)
    tm.set_config({"threshold": 1, "window_s": 600})
    _trip(tm, "203.0.113.9")
    tm.unblock("203.0.113.9", forgive=False)

    res = tm.unblock("203.0.113.9")

    assert res["removed"] is False
    assert tm._offense["203.0.113.9"] == 1  # not forgiven by a no-op call


def test_unblock_keeps_lifetime_totals_monotonic(tmp_path):
    """Forgiving a strike must not rewrite the evidence trail."""
    tm = _tm_for(tmp_path)
    tm.set_config({"threshold": 1, "window_s": 600})
    _trip(tm, "203.0.113.9")
    tm.unblock("203.0.113.9")

    t = tm.snapshot()["totals"]
    assert t["blocks_placed"] == 1
    assert t["unblocks"] == 1
    assert t["failures"] == 2
    assert t["currently_blocked"] == 0


# ── explicit forgive() ───────────────────────────────────────────────────────
def test_forgive_clears_an_accumulated_backlog(tmp_path):
    """Cleanup path for strikes banked before unblock forgave anything — an
    address can already sit past permanent_after with no active block."""
    tm = _tm_for(tmp_path)
    tm._offense["127.0.0.1"] = 4

    res = tm.forgive("127.0.0.1")

    assert res["cleared"] == 4
    assert "127.0.0.1" not in tm._offense


def test_forgive_unknown_ip_reports_nothing_cleared(tmp_path):
    assert _tm_for(tmp_path).forgive("198.51.100.7")["cleared"] == 0


def test_forgive_leaves_an_active_block_in_place(tmp_path):
    """Forgiving is about future permanence, not amnesty for a live block."""
    tm = _tm_for(tmp_path)
    tm.set_config({"threshold": 1, "window_s": 600})
    _trip(tm, "203.0.113.9")

    tm.forgive("203.0.113.9")

    assert "203.0.113.9" in tm._blocks


def test_forgiven_address_blocks_normally_afterwards(tmp_path):
    tm = _tm_for(tmp_path)
    tm.set_config({"threshold": 1, "window_s": 600, "permanent_after": 3})
    tm._offense["198.51.100.96"] = 4
    tm.forgive("198.51.100.96")

    _trip(tm, "198.51.100.96")

    assert "198.51.100.96" in tm._blocks
    assert tm._blocks["198.51.100.96"]["permanent"] is False


# ── snapshot visibility ──────────────────────────────────────────────────────
def test_snapshot_exposes_strikes_for_unblocked_addresses(tmp_path):
    """Strikes used to be visible only on an ACTIVE block record, so an address
    one strike from a permanent ban showed nothing at all in the UI."""
    tm = _tm_for(tmp_path)
    tm.set_config({"permanent_after": 3})
    tm._offense.update({"127.0.0.1": 4, "198.51.100.96": 1})

    rows = {r["ip"]: r for r in tm.snapshot()["strikes"]}

    assert rows["127.0.0.1"]["strikes"] == 4
    assert rows["127.0.0.1"]["at_limit"] is True
    assert rows["198.51.100.96"]["at_limit"] is False
    assert rows["198.51.100.96"]["permanent_after"] == 3


def test_snapshot_strikes_exclude_actively_blocked_ips(tmp_path):
    """Those already appear under permanent/temporary with their offense_count;
    repeating them would double-count the same address in the UI."""
    tm = _tm_for(tmp_path)
    tm.set_config({"threshold": 1, "window_s": 600})
    _trip(tm, "203.0.113.9")

    assert tm.snapshot()["strikes"] == []


def test_snapshot_strikes_sorted_worst_first(tmp_path):
    tm = _tm_for(tmp_path)
    tm._offense.update({"198.51.100.1": 1, "198.51.100.2": 5, "198.51.100.3": 3})

    assert [r["ip"] for r in tm.snapshot()["strikes"]] == [
        "198.51.100.2", "198.51.100.3", "198.51.100.1"]


def test_strikes_survive_a_reload(tmp_path):
    tm = _tm_for(tmp_path)
    tm._offense["203.0.113.9"] = 2
    tm._persist()

    assert _tm_for(tmp_path).snapshot()["strikes"][0]["strikes"] == 2
