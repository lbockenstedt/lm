"""The generated ``/usr/local/bin/lm-update-restart`` must define its own health
probes.

Why this test exists: ``install_all.sh`` defines ``_status_200`` / ``_gated_401``
in its OWN shell scope, but writes the helper from a **quoted** heredoc
(``<<'HELPER'``), so nothing from the installer's scope carries into the
generated file. For a long time the helper *called* those probes without
defining them, and the deployed script failed every probe with::

    /usr/local/bin/lm-update-restart: line 41: _status_200: command not found

``poll_health``/``poll_status`` could then never succeed, so EVERY hub
self-update was declared "failed to boot", rolled back, and the rollback was
declared failed too — writing the ``update_failed.json`` double-failure marker
and marking a perfectly healthy version bad in ``bad_versions.json``.

These tests pin both halves: the helper defines the probes, and its copies stay
identical to the installer's own.
"""
import os
import re
import shutil
import subprocess

import pytest

INSTALLER = os.path.join(os.path.dirname(__file__), "..", "..", "install_all.sh")


def _installer_text():
    with open(INSTALLER) as fh:
        return fh.read()


def _helper_text():
    """The exact body written to /usr/local/bin/lm-update-restart."""
    src = _installer_text()
    marker = "cat > /usr/local/bin/lm-update-restart <<'HELPER'\n"
    assert marker in src, "lm-update-restart heredoc not found (installer restructured?)"
    body = src.split(marker, 1)[1]
    end = body.index("\nHELPER\n")
    return body[:end]


def _extract_func(text, name):
    """Return the source of shell function ``name`` from ``text``."""
    m = re.search(rf"^{re.escape(name)}\(\) \{{\n(.*?)^\}}$", text, re.S | re.M)
    return m.group(1) if m else None


def test_the_heredoc_is_quoted():
    """A quoted heredoc is WHY the probes must be redefined inside. If someone
    unquotes it, the probes would interpolate but every $var in the helper would
    expand at install time instead — a different, worse bug."""
    assert "cat > /usr/local/bin/lm-update-restart <<'HELPER'" in _installer_text()


@pytest.mark.parametrize("fn", ["_status_200", "_gated_401"])
def test_helper_defines_the_probe_it_calls(fn):
    helper = _helper_text()
    assert f"{fn}()" in helper, (
        f"{fn} is CALLED in lm-update-restart but never defined there — every "
        f"health probe would fail with 'command not found', rolling back healthy "
        f"code and marking it bad")


@pytest.mark.parametrize("fn", ["_status_200", "_gated_401"])
def test_probe_bodies_match_the_installers(fn):
    """The helper's copy and the installer's copy must stay byte-identical."""
    helper_body = _extract_func(_helper_text(), fn)
    # The installer's own copy lives outside the heredoc.
    outside = _installer_text().split(
        "cat > /usr/local/bin/lm-update-restart <<'HELPER'", 1)[0]
    installer_body = _extract_func(outside, fn)
    assert helper_body is not None, f"{fn} not found in the generated helper"
    assert installer_body is not None, f"{fn} not found in the installer scope"
    assert helper_body == installer_body, (
        f"{fn} has DRIFTED between install_all.sh and the generated "
        f"lm-update-restart — they must stay identical")


@pytest.mark.parametrize("fn", ["_status_200", "_gated_401"])
def test_helper_actually_calls_the_probe(fn):
    """Guards against the inverse fix: deleting the calls instead of adding the
    definitions would make this file's whole purpose vanish silently."""
    assert re.search(rf"(?<!^){re.escape(fn)}\b(?!\(\))", _helper_text(), re.M)


def test_helper_refuses_to_run_without_its_probes():
    """Defence in depth: an already-deployed stale helper (self-update never
    re-installs /usr/local/bin) must fail loudly, not silently roll back."""
    helper = _helper_text()
    assert "declare -F" in helper
    assert "refusing to run" in helper


@pytest.mark.skipif(not shutil.which("bash"), reason="bash not available")
def test_generated_helper_is_valid_bash():
    """`bash -n` the exact generated text — a syntax error here would break the
    hub's only self-update path."""
    proc = subprocess.run(["bash", "-n"], input=_helper_text(),
                          text=True, capture_output=True)
    assert proc.returncode == 0, f"generated helper is not valid bash:\n{proc.stderr}"


@pytest.mark.skipif(not shutil.which("bash"), reason="bash not available")
def test_probes_return_nonzero_when_nothing_is_listening():
    """Sanity-check the extracted probe really is a working function (not, say,
    an empty stub that would pass the presence assertions above)."""
    body = _extract_func(_helper_text(), "_status_200")
    script = f"_status_200() {{\n{body}}}\n_status_200; echo rc=$?"
    proc = subprocess.run(["bash", "-c", script], text=True, capture_output=True)
    # Nothing is serving /status in CI -> must report failure, not crash.
    assert "rc=1" in proc.stdout, proc.stdout + proc.stderr
