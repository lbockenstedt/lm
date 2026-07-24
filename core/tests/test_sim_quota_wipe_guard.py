"""Anti-blast safeguard for ``sim_quotas`` — ``guard_sim_quota_wipe``.

A config save that takes a tenant from N>0 quotas to 0 is almost always
unintentional (a stale ``simulation.conf`` makes ``validate_sim_quotas`` drop
every row on the next save of *anything*; a UI load race sends
``sim_quotas: []``). The guard refuses that wipe unless the caller explicitly
opts in via ``force_sim_quotas_clear``. Mirrored in the cs spoke twin.
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC = HERE.parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from simulations import sim_quota  # noqa: E402


def _q(sim_id="dns_fail", alert_id="CLIENT_DNS_FAILURE", site="MIA"):
    return {"sim_id": sim_id, "alert_type": "alert", "alert_id": alert_id,
            "site": site, "count": 5, "enabled": True}


def test_wipe_blocked_when_existing_nonempty_and_clean_empty():
    # The blast case: existing had quotas, the save would leave none. Without an
    # explicit opt-in the existing quotas are returned and the block is flagged.
    existing = [_q(), _q("dhcp_fail", "CLIENT_DHCP_FAILURE")]
    kept, blocked = sim_quota.guard_sim_quota_wipe(existing, [], {})
    assert blocked is True
    assert kept == existing


def test_wipe_allowed_with_force_flag():
    # A deliberate "clear all" sets force_sim_quotas_clear — the empty list is
    # honored (the one legit path to zero quotas).
    existing = [_q()]
    kept, blocked = sim_quota.guard_sim_quota_wipe(existing, [],
                                                   {"force_sim_quotas_clear": True})
    assert blocked is False
    assert kept == []


def test_force_flag_truthy_strings_honored():
    for val in ("true", "yes", "1", "on", "True"):
        kept, blocked = sim_quota.guard_sim_quota_wipe([_q()], [], {"force_sim_quotas_clear": val})
        assert blocked is False, f"force={val!r} should allow the wipe"
        assert kept == []


def test_no_block_when_existing_already_empty():
    # Nothing to protect — an empty-to-empty save is a no-op, not a wipe.
    kept, blocked = sim_quota.guard_sim_quota_wipe([], [], {})
    assert blocked is False
    assert kept == []


def test_no_block_when_clean_nonempty():
    # A normal save (some rows survive validation) is never blocked.
    existing = [_q()]
    clean = [_q(), _q("dhcp_fail", "CLIENT_DHCP_FAILURE")]
    kept, blocked = sim_quota.guard_sim_quota_wipe(existing, clean, {})
    assert blocked is False
    assert kept == clean


def test_partial_drop_not_blocked():
    # The guard only stops a FULL wipe. A partial drop (some rows invalidated by
    # a stale sim_ids list) is allowed — bulk edits legitimately remove rows.
    existing = [_q(), _q("dhcp_fail", "CLIENT_DHCP_FAILURE"), _q("assoc_fail", "X")]
    clean = [_q()]  # two dropped, one survives
    kept, blocked = sim_quota.guard_sim_quota_wipe(existing, clean, {})
    assert blocked is False
    assert kept == clean


def test_force_false_or_missing_does_not_allow_wipe():
    for body in ({}, {"force_sim_quotas_clear": False},
                 {"force_sim_quotas_clear": ""}, {"force_sim_quotas_clear": "no"}):
        kept, blocked = sim_quota.guard_sim_quota_wipe([_q()], [], body)
        assert blocked is True, f"body={body!r} must NOT allow the wipe"
        assert kept == [_q()]


def test_non_dict_body_treated_as_no_force():
    # A malformed body (not a dict) can't carry the opt-in → block.
    kept, blocked = sim_quota.guard_sim_quota_wipe([_q()], [], None)
    assert blocked is True
    assert kept == [_q()]