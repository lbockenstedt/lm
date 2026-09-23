"""Toast wording for the "clear USB state" command: an UNREPORTED fan-out count
must never be announced as zero.

``POST /sim/api/{tenant}/proxmx/command`` has two reply shapes. The fan-out
(``all_spokes``) path reports ``pushed_to_spokes`` / ``spokes_total``; the
single-spoke enqueue path reports neither — it returns a queue result. The UI
used ``r.pushed_to_spokes || 0``, which collapsed three different states into
"0": field absent (no count reported), field present and genuinely 0, and a
falsy non-number. The result was "Cleared 0 spoke(s)" on a command the server
had in fact accepted — the same regression the ``csPushToast`` helper directly
above ``_csUsbClearCmd`` already documents for the config-push routes.

The queued count had the same defect: ``r.queued === true`` means "queued,
count unknown" (one spoke), and ``|| (isQueued ? 1 : 0)`` rendered that as the
concrete, invented count "1".

These tests EXECUTE the real function out of ``WebUI/sim-views.js`` under node
with stubbed globals and assert the toast text, so a syntax/scope error (an
undefined variable in one branch, say) fails here rather than in a browser.
"""
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

SIM_VIEWS_JS = Path(__file__).resolve().parents[2] / "WebUI" / "sim-views.js"

pytestmark = pytest.mark.skipif(shutil.which("node") is None,
                                reason="node is required to execute the WebUI helper")


def _extract_fn() -> str:
    js = SIM_VIEWS_JS.read_text(encoding="utf-8")
    start = js.index("async function _csUsbClearCmd(")
    end = js.index("\n}\n", start) + len("\n}\n")
    return js[start:end]


def _run(reply, all_spokes=True):
    """Execute _csUsbClearCmd against a stubbed csFetch and return (msg, type)."""
    harness = """
%s
const _calls = [];
globalThis.showToast = (msg, type) => _calls.push([msg, type]);
globalThis.csTenant = () => 't1';
globalThis.csFetch = async () => REPLY;
const REPLY = %s;
_csUsbClearCmd('host1', 'clear_usb_history', 'Dongle history purged', %s)
    .then(() => console.log(JSON.stringify(_calls)));
""" % (_extract_fn(), json.dumps(reply), "true" if all_spokes else "false")
    out = subprocess.run(["node", "--input-type=module", "-e", harness],
                         capture_output=True, text=True, timeout=30)
    assert out.returncode == 0, out.stderr
    calls = json.loads(out.stdout.strip().splitlines()[-1])
    assert len(calls) == 1, calls
    return calls[0][0], calls[0][1]


def test_missing_count_is_not_announced_as_zero():
    """Single-spoke enqueue path: no fan-out fields at all."""
    msg, kind = _run({"status": "ok"}, all_spokes=False)
    assert kind == "success"
    assert "0 spoke" not in msg
    assert "Cleared 0" not in msg


def test_missing_count_with_all_spokes_is_not_a_failure():
    """all_spokes was requested but the reply carried no count: that is 'no
    spoke data returned', NOT 'no spokes were reachable'."""
    msg, kind = _run({"status": "ok"}, all_spokes=True)
    assert kind == "success"
    assert "No spokes were reachable" not in msg


def test_reported_zero_still_warns():
    msg, kind = _run({"pushed_to_spokes": 0, "spokes_total": 3})
    assert kind == "warning"
    assert "No spokes were reachable" in msg
    assert "0/3" in msg


def test_queued_true_does_not_invent_a_count_of_one():
    """`queued: true` means queued with an UNKNOWN count."""
    msg, kind = _run({"queued": True})
    assert kind == "warning"
    assert "queued for delivery on reconnect" in msg
    assert not re.search(r"queued for 1 ", msg)


def test_known_queued_count_is_still_reported():
    msg, kind = _run({"pushed_to_spokes": 2, "spokes_total": 5,
                      "queued_to_spokes": 3})
    assert kind == "warning"
    assert "queued for 3 unreachable spoke(s)" in msg
    assert "2/5" in msg


def test_queued_names_are_listed():
    msg, kind = _run({"pushed_to_spokes": 1, "queued": ["spoke-a", "spoke-b"]})
    assert kind == "warning"
    assert "queued for 2 unreachable spoke(s)" in msg
    assert "spoke-a, spoke-b" in msg


def test_error_branch_omits_the_count_when_it_was_not_reported():
    msg, kind = _run({"errors": ["spoke-x: boom"]}, all_spokes=False)
    assert kind == "error"
    assert "spoke-x: boom" in msg
    assert "Cleared 0" not in msg
    # No empty count slot either.
    assert "Cleared  spoke" not in msg


def test_error_branch_keeps_a_reported_count():
    msg, kind = _run({"pushed_to_spokes": 4, "spokes_total": 5,
                      "errors": ["spoke-x: boom"]})
    assert kind == "error"
    assert "4/5" in msg
    assert "spoke-x: boom" in msg


def test_no_response_still_reports_failure():
    msg, kind = _run(None)
    assert kind == "error"
    assert "no response received" in msg
