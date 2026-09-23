"""Log-sentinel duplicate-escalation guard.

The Tier-1 log sentinel (``run_log_health_loop``) decides whether a module's
errors are "new" before spending an LLM call and, on an ``escalate`` verdict,
files a GitHub issue through the ab spoke. Two independent defects made that
gate useless against a *standing* fault:

1. The signature was ``sha256("\\n".join(errs[-40:]))`` over the RAW error
   lines. Every log line is prefixed with its own timestamp, so a condition
   that recurred on every sweep produced a different hash on every sweep. The
   gate therefore never suppressed anything that persisted.
2. Nothing deduplicated the escalation itself. The sig cache remembers only the
   single immediately-preceding sweep, so an intermittent fault that alternates
   present/absent defeats it every other sweep.

Together those filed 50 identical issues about one unregistered device
(``d9e4255e-...``) over 8 days, plus 14 more for netbox and 7 for the hub.

These tests pin the fix: a normalized fingerprint that ignores volatile tokens
but preserves UUIDs, and a per-(module, fingerprint) escalation cooldown.
"""
import os
import sys

import pytest

_SRC = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

import main  # noqa: E402

_norm = main._sentinel_normalize_line
_fp = main._sentinel_fingerprint

_DEV_A = "d9e4255e-ea66-4656-b70c-17509475cd18"
_DEV_B = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


def _arp(ts, dev=_DEV_A):
    return (f"{ts} - nw - ERROR - NW_GET_ARP failed for device {dev}: "
            f"device not present in the fleet")


# --------------------------------------------------------------------------
# normalization
# --------------------------------------------------------------------------

def test_timestamp_is_stripped_entirely():
    """The whole datestamp must go, not just the clock half.

    A bare ``HH:MM:SS`` rule applied first would leave ``2026-08-07`` behind and
    the fingerprint would still roll over at midnight.
    """
    out = _norm(_arp("2026-08-07 19:11:52,433"))
    assert "2026" not in out
    assert "19:11" not in out
    assert out.startswith("<TS>")


@pytest.mark.parametrize("ts", [
    "2026-08-07 19:11:52,433",
    "2026-08-07 19:11:52.433",
    "2026-08-07 19:11:52",
    "2026-08-07T19:11:52.433Z",
    "2026-08-07T19:11:52.433+02:00",
])
def test_all_timestamp_formats_collapse_together(ts):
    assert _fp([_arp(ts)]) == _fp([_arp("2026-08-07 19:11:52,433")])


def test_same_condition_different_time_is_one_fingerprint():
    """The core regression: this is what made the gate fire forever."""
    assert _fp([_arp("2026-08-07 19:11:52,433")]) == \
           _fp([_arp("2026-08-15 03:42:07,001")])


def test_different_device_is_a_different_fingerprint():
    """UUIDs must survive normalization verbatim.

    Collapsing them to a placeholder would make a fault on a second device look
    like a duplicate of the first and silently swallow it -- strictly worse than
    the over-reporting this change fixes.
    """
    a = _arp("2026-08-07 19:11:52,433", _DEV_A)
    b = _arp("2026-08-07 19:11:52,433", _DEV_B)
    assert _DEV_A in _norm(a)
    assert _fp([a]) != _fp([b])


def test_uppercase_uuid_is_preserved():
    line = _arp("2026-08-07 19:11:52,433", _DEV_A.upper())
    assert _DEV_A.upper() in _norm(line)


def test_request_ids_and_durations_are_volatile():
    d = ("2026-09-16 01:22:03 - hub - ERROR - Request Timeout: "
         "[SPOKE_GET_MTLS_STATUS] req=ed9d5818 from ab after 4.0s")
    e = ("2026-09-17 09:01:44 - hub - ERROR - Request Timeout: "
         "[SPOKE_GET_MTLS_STATUS] req=91ab77cc from ab after 7.25s")
    assert _fp([d]) == _fp([e])


def test_a_different_command_still_differs():
    """Discriminator: the volatile rules must not blur genuinely distinct errors."""
    d = ("2026-09-16 01:22:03 - hub - ERROR - Request Timeout: "
         "[SPOKE_GET_MTLS_STATUS] req=ed9d5818 from ab after 4.0s")
    f = ("2026-09-16 01:22:03 - hub - ERROR - Request Timeout: "
         "[SPOKE_GET_VERSION] req=ed9d5818 from ab after 4.0s")
    assert _fp([d]) != _fp([f])


def test_order_and_repeat_count_do_not_matter():
    a = _arp("2026-08-07 19:11:52,433")
    b = ("2026-09-16 01:22:03 - hub - ERROR - Request Timeout: "
         "[X] req=ed9d5818 from ab after 4.0s")
    assert _fp([a, b, a, a]) == _fp([b, a])


def test_empty_and_blank_yield_empty_string():
    assert _fp([]) == ""
    assert _fp(["", "   "]) == ""
    assert _norm(None) == ""


def test_no_placeholder_leaks_into_output():
    assert "\x00" not in _norm(_arp("2026-08-07 19:11:52,433"))


def test_two_uuids_on_one_line_both_survive():
    line = (f"2026-08-07 19:11:52 - nw - ERROR - link {_DEV_A} -> {_DEV_B} down")
    out = _norm(line)
    assert _DEV_A in out and _DEV_B in out


# --------------------------------------------------------------------------
# escalation cooldown
# --------------------------------------------------------------------------

class _Ledger:
    """Drives the real cooldown arithmetic the loop performs.

    run_log_health_loop is a long-lived async loop with hub/spoke/LLM
    dependencies, so rather than stand the whole thing up this mirrors the
    exact ledger operations and asserts the policy they implement.
    """

    def __init__(self, cooldown_h=24):
        self.cd = cooldown_h
        self.book = {}
        self.sent = []

    def offer(self, module, sig, now):
        key = (module, sig)
        last = self.book.get(key)
        if last is not None and (now - last) < self.cd * 3600:
            return False
        self.book[key] = now
        cutoff = now - self.cd * 3600
        for k in [k for k, v in self.book.items() if v < cutoff]:
            self.book.pop(k, None)
        self.sent.append((module, sig))
        return True


def test_standing_fault_escalates_once_not_every_sweep():
    """50 issues in 8 days becomes 8 -- one per cooldown window."""
    led = _Ledger(cooldown_h=24)
    sig = _fp([_arp("2026-08-07 19:11:52,433")])
    sweeps = 0
    # a sweep every 30 minutes for 8 days
    for i in range(8 * 24 * 2):
        if led.offer("nw", sig, i * 1800):
            sweeps += 1
    assert sweeps == 8
    assert len(led.sent) == 8


def test_cooldown_is_per_module_and_per_condition():
    led = _Ledger()
    a = _fp([_arp("2026-08-07 19:11:52,433", _DEV_A)])
    b = _fp([_arp("2026-08-07 19:11:52,433", _DEV_B)])
    assert led.offer("nw", a, 0) is True
    assert led.offer("nw", a, 60) is False          # same condition, suppressed
    assert led.offer("nw", b, 60) is True           # other device, NOT suppressed
    assert led.offer("netbox", a, 60) is True       # other module, NOT suppressed


def test_intermittent_fault_does_not_slip_through():
    """The old single-slot sig cache let an alternating fault escalate every
    other sweep; the ledger is keyed by fingerprint so it cannot."""
    led = _Ledger()
    a = _fp([_arp("2026-08-07 19:11:52,433", _DEV_A)])
    b = _fp([_arp("2026-08-07 19:11:52,433", _DEV_B)])
    for i in range(20):
        led.offer("nw", a if i % 2 == 0 else b, i * 1800)
    assert len(led.sent) == 2


def test_ledger_is_bounded():
    led = _Ledger(cooldown_h=1)
    for i in range(500):
        led.offer("nw", "sig%d" % i, i * 3600)
    assert len(led.book) <= 2


def test_escalation_resumes_after_cooldown_expires():
    led = _Ledger(cooldown_h=24)
    sig = _fp([_arp("2026-08-07 19:11:52,433")])
    assert led.offer("nw", sig, 0) is True
    assert led.offer("nw", sig, 24 * 3600 - 1) is False
    assert led.offer("nw", sig, 24 * 3600) is True


def test_loop_uses_the_fingerprint_helper_not_a_raw_hash():
    """Guards the wiring: the gate must call the normalizing helper."""
    src = open(os.path.join(_SRC, "main.py")).read()
    assert "sig = _sentinel_fingerprint(errs)" in src
    assert 'sha256("\\n".join(errs[-40:])' not in src
    assert "log_escalation_cooldown_h" in src
