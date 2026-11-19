"""Network → Scan schedules table (WebUI/js/nw.js ``_nwScanSchedulesHtml``).

Several Credential Vault buckets naming the tenant (``vault_error`` from GET
/api/nw/scan-schedules, a configuration error) show as "vault conflict" in the
Credentials cell and the reason once, never "discovery only"; whether a run
happens stays in the Agent and Last run cells. The last run's error is added
only when it says something else. Runs the real renderer under jsc/node."""

import json
import os
import shutil
import subprocess
import tempfile

import pytest
from webui_src import main_js_source

_JSC = ("/System/Library/Frameworks/JavaScriptCore.framework/Versions/A"
        "/Helpers/jsc")
_SRC = main_js_source()


def _fn(name):
    """The source of the top-level ``function <name>(...) {...}``. Its
    parameters may hold braces (``{ future } = {}``), so the body is matched
    from the first ``{`` after the parameter list closes."""
    i = _SRC.index(f"\nfunction {name}(") + 1
    j, depth = _SRC.index("(", i), 0
    # Skip the parameter list.
    while True:
        depth += {"(": 1, ")": -1}.get(_SRC[j], 0)
        j += 1
        if depth == 0:
            break
    # Match the body's braces.
    j = _SRC.index("{", j)
    for k in range(j, len(_SRC)):
        depth += {"{": 1, "}": -1}.get(_SRC[k], 0)
        if depth == 0:
            return _SRC[i:k + 1]
    raise AssertionError(f"unterminated function {name}")


def _render(*rows):
    """The schedules table HTML for enabled ``rows``, each laid over a plain row."""
    base = {"enabled": True, "tenant_name": "Acme", "interval_seconds": 21600,
            "dry_run": False, "discovery_only": False, "vault_error": "",
            "credential_names": ["acme login"], "spoke_id": "", "spoke_connected": False,
            "last_run_at": None, "last_status": None, "last_added": 0, "last_error": ""}
    d = {"runtime_since_restart": True, "schedules": [{**base, **r} for r in rows]}
    script = "\n".join([
        "var OUT = typeof print === 'function' ? print : console.log;",
        "var _NW_SCHED_INTERVALS = [];",
        *(_fn(n) for n in ("escapeHtml", "_nwSchedEvery", "_nwSchedWhen",
                           "_nwScanSchedulesHtml")),
        "OUT(JSON.stringify(_nwScanSchedulesHtml(%s)));" % json.dumps(d),
    ])
    if os.path.exists(_JSC):
        runtime = [_JSC]
    elif shutil.which("node"):
        runtime = [shutil.which("node")]
    else:  # pragma: no cover
        pytest.skip("no JavaScript runtime (jsc/node) available")
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False,
                                     encoding="utf-8") as fh:
        fh.write(script)
        path = fh.name
    try:
        proc = subprocess.run(runtime + [path], capture_output=True,
                              text=True, timeout=60)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        return json.loads(proc.stdout.strip().splitlines()[-1])
    finally:
        os.unlink(path)


def test_a_vault_conflict_shows_as_such_and_its_reason_once():
    why = "Credential Vault: tenant 'acme' has 2 buckets <ACME>"
    html = _render({"vault_error": why, "last_status": "error", "last_run_at": 1,
                    "last_error": why})
    assert ">vault conflict<" in html and "discovery only" not in html
    assert "acme login" not in html
    assert html.count("Credential Vault: tenant") == 1
    assert "&lt;ACME&gt;" in html and "<ACME>" not in html


def test_a_different_last_error_follows_the_vault_error():
    html = _render({"vault_error": "Credential Vault: two buckets",
                    "last_error": "scan failed: timeout"})
    assert "Credential Vault: two buckets \u00b7 last error: scan failed: timeout" in html


def test_without_a_vault_error_the_last_error_shows_as_before():
    html = _render({"last_status": "error", "last_run_at": 1, "last_error": "timeout"})
    assert "last error: timeout" in html and "vault conflict" not in html
    assert "acme login" in html


def test_a_vault_conflict_on_a_skipped_run_is_not_shown_as_its_outcome():
    """With the agent offline the run is skipped: the Credentials cell names
    the conflict and the Agent and Last run cells say what the run did."""
    html = _render({"vault_error": "Credential Vault: two buckets",
                    "spoke_id": "nw-acme", "spoke_connected": False,
                    "last_status": "skipped", "last_run_at": 1})
    assert ">vault conflict<" in html and ">offline<" in html
    assert "skipped" in html and ">refused<" not in html
