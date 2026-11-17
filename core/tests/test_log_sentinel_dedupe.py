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


# --------------------------------------------------------------------------
# high-volume warnings + persisted ledger
# --------------------------------------------------------------------------

def _timeout_warn(i):
    return (f"2026-10-27 00:08:{i % 60:02d} - Hub - WARNING - dhcp_feed: spoke "
            f"8889182b-a4c5-58df-8456-d2fe1e048edd rejected DHCP_STATS: Timed out waiting")


def test_volume_lines_flag_repeated_warnings_with_stable_text():
    lines = [_timeout_warn(i) for i in range(120)] + ["2026-10-27 - Hub - WARNING - rare thing"]

    out = main._sentinel_volume_lines(lines, threshold=50, minutes=30)

    assert len(out) == 1
    assert "at least 50 WARNING lines in 30m" in out[0]
    assert "Timed out waiting" in out[0]
    assert main._sentinel_volume_lines(lines + lines[:30], 50, 30) == out  # same bucket


def test_volume_lines_ignore_patterns_below_threshold():
    assert main._sentinel_volume_lines([_timeout_warn(i) for i in range(49)], 50, 30) == []


def test_escalation_ledger_survives_restart(tmp_path):
    import types
    hub = types.SimpleNamespace(state=types.SimpleNamespace(data_dir=str(tmp_path)),
                                _log_sentinel_escalated={"hub|abc": 123.0})
    for name in ("_sentinel_ledger_path", "_load_sentinel_ledger", "_save_sentinel_ledger"):
        setattr(hub, name, getattr(main.LabManagerHub, name).__get__(hub))

    hub._save_sentinel_ledger()

    assert hub._load_sentinel_ledger() == {"hub|abc": 123.0}


# --------------------------------------------------------------------------
# 5xx API responses
# --------------------------------------------------------------------------

def _access(status, ip="4.148.8.120:13267", query="?tenant=central"):
    return (f'2026-11-17 21:34:05 - uvicorn.access - INFO - {ip} - '
            f'"POST /api/dhcp/ha/discover{query} HTTP/1.1" {status}')


def test_5xx_lines_flag_failing_api_routes_once_with_stable_text():
    """A route answering 502 is an error even when its reason was a WARNING;
    client address and query string must not split the fingerprint."""
    lines = [_access(502), _access(502, ip="10.0.0.9:443", query="?tenant=ra"),
             "2026-11-17 - Hub - WARNING - DHCP worker discovery failed: ..."]

    out = main._sentinel_5xx_lines(lines)

    assert out == ["[http-5xx] ERROR - POST /api/dhcp/ha/discover returned 502"]
    assert main._sentinel_5xx_lines([_access(502, ip="1.2.3.4:5555")]) == out


def test_5xx_lines_ignore_4xx_and_non_api_paths():
    lines = [_access(409), _access(404),
             '2026-11-17 - uvicorn.access - INFO - 1.2.3.4:1 - "GET /ws/spoke HTTP/1.1" 503']
    assert main._sentinel_5xx_lines(lines) == []



def test_analysis_text_carries_findings_from_the_wider_window():
    """A 5xx seen only in the wide tail must reach the analyzer, or it judges
    an unrelated healthy tail and never escalates what opened the gate."""
    tail = ["2026-11-17 - Hub - INFO - all quiet",
            "2026-11-17 - Hub - ERROR - already in the tail"]
    synth = main._sentinel_5xx_lines([_access(502)])
    errs = [tail[1]] + synth

    text = main._sentinel_analysis_text(tail, errs)

    assert text.endswith(synth[0])
    assert text.count("already in the tail") == 1
    assert main._sentinel_analysis_text(tail, [tail[1]]) == "\n".join(tail)


def test_loop_sends_the_findings_to_the_analyzer():
    src = open(os.path.join(_SRC, "main.py")).read()
    assert "_sentinel_analysis_text(lines, errs)" in src


def test_gate_reopens_when_a_failure_returns_after_a_quiet_window():
    """A stable 5xx fingerprint must not stay suppressed forever: a quiet
    window clears it, so the same route failing later is analyzed again."""
    sigs = {}
    errs = main._sentinel_5xx_lines([_access(502)])

    first = main._sentinel_gate(sigs, "hub", errs)
    assert first
    assert main._sentinel_gate(sigs, "hub", errs) is None   # standing, unchanged
    assert main._sentinel_gate(sigs, "hub", []) is None     # quiet window
    assert main._sentinel_gate(sigs, "hub", errs) == first  # back again: reopens


def test_gate_keeps_the_fingerprint_when_no_logs_were_read():
    """An empty read (log read failed, relay gap) is not proof the fault
    cleared, so a still-active fault is not re-analyzed when logs resume."""
    sigs = {}
    errs = main._sentinel_5xx_lines([_access(502)])
    main._sentinel_gate(sigs, "hub", errs)

    assert main._sentinel_gate(sigs, "hub", [], observed=False) is None
    assert main._sentinel_gate(sigs, "hub", errs) is None


def test_loop_uses_the_gate_helper():
    src = open(os.path.join(_SRC, "main.py")).read()
    assert "sig = _sentinel_gate(self._log_sentinel_sig, module, errs,\n" in src
    assert "observed=bool(raw))" in src


def test_loop_forgets_fingerprints_while_ab_is_unavailable(monkeypatch):
    """With AB gone the sweep does not run, so a fault can clear and recur
    unseen; its old fingerprint must not suppress it once AB is back."""
    import asyncio
    import types

    sleeps = []

    async def _sleep(_s):
        sleeps.append(_s)
        if len(sleeps) > 2:
            raise asyncio.CancelledError

    monkeypatch.setattr(asyncio, "sleep", _sleep)
    hub = types.SimpleNamespace(
        state=types.SimpleNamespace(get_global_config=lambda: {}),
        get_spoke_by_type=lambda _t: None,
        _load_sentinel_ledger=lambda: {},
        _log_sentinel_sig={"hub": "stale"},
    )

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(main.LabManagerHub.run_log_health_loop(hub))

    assert hub._log_sentinel_sig == {}


def test_log_analysis_config_saves_the_triage_knobs():
    # The 5xx / WARNING-volume knobs must be readable and settable through the
    # Log Analysis config route the WebUI uses (rule 3.2: UI for everything).
    from types import SimpleNamespace
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from routes import setup_admin

    gc = {}
    state = SimpleNamespace(get_global_config=lambda: gc, system_state={},
                            _mark_dirty=lambda: None)
    hub = SimpleNamespace(state=state, get_spoke_by_type=lambda t: None)
    app = FastAPI()
    app.state.hub = hub
    setup_admin.register(app, hub, SimpleNamespace())
    client = TestClient(app)

    got = client.get("/setup/log-analysis/config").json()
    assert (got["log_5xx_triage"], got["log_volume_triage"],
            got["log_volume_threshold"]) == (True, True, 10)

    saved = client.post("/setup/log-analysis/config", json={
        "log_5xx_triage": False, "log_volume_triage": False,
        "log_volume_threshold": 0}).json()
    assert gc["log_5xx_triage"] is False and gc["log_volume_triage"] is False
    assert gc["log_volume_threshold"] == 1
    assert saved["log_volume_threshold"] == 1

    client.post("/setup/log-analysis/config", json={"log_volume_threshold": "x"})
    assert gc["log_volume_threshold"] == 1


def test_sentinel_reads_each_module_once_and_hub_log_off_the_loop():
    # hub.log can be hundreds of MB: a deque() walk of the whole file on the
    # event loop stalled the hub. The sweep must read one tail per module, the
    # hub's via the seek-based _tail_lines inside asyncio.to_thread.
    import inspect
    from main import LabManagerHub
    tail_src = inspect.getsource(LabManagerHub._read_hub_log_tail)
    assert "_tail_lines(p, n)" in tail_src and "deque(" not in tail_src
    loop_src = inspect.getsource(LabManagerHub.run_log_health_loop)
    assert "await _aio.to_thread(self._read_hub_log_tail, n)" in loop_src
    assert loop_src.count("_gather_module_log_lines(") == 1
