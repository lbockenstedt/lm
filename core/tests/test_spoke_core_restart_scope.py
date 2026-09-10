"""A spoke must not restart for a core change it cannot possibly have loaded.

Spokes restarted on ANY core commit, so a WebUI-only fix bounced every role on
every spoke in the fleet — including the edge proxy, which drops its :443
listener on restart. That is pure downtime for an asset that is already live:
the hub serves WebUI/ off disk per request.

The hub already avoided this (``UpdatePipelineMixin._NO_RESTART_PREFIXES``);
these tests pin the same rule for spokes, and — more importantly — pin that it
fails SAFE. Skipping a restart that was genuinely needed leaves a spoke running
stale code indefinitely, which is far worse than an unnecessary bounce, so
every uncertain case must still restart.
"""
import subprocess
import sys
import types
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
for p in (str(SRC), str(SRC / "messaging")):
    if p not in sys.path:
        sys.path.insert(0, p)

from messaging.self_update import SelfUpdateMixin  # noqa: E402


class _Updater(SelfUpdateMixin):
    """Exercises the real method with git stubbed out."""

    def __init__(self, out="", rc=0, boom=False):
        self._out, self._rc, self._boom = out, rc, boom
        self.calls = []

    def _run_git(self, args, cwd=None):
        self.calls.append((tuple(args), cwd))
        if self._boom:
            raise subprocess.SubprocessError("git exploded")
        return types.SimpleNamespace(returncode=self._rc, stdout=self._out, stderr="")


A, B = "a" * 40, "b" * 40


def _needs(out, rc=0, boom=False, frm=A, to=B, root="/opt/lm"):
    return _Updater(out, rc, boom)._core_change_needs_restart(root, frm, to)


# ── changes that must NOT restart ────────────────────────────────────────────

def test_webui_only_change_does_not_restart():
    assert _needs("WebUI/main.js\n") is False


def test_docs_and_readme_only_change_does_not_restart():
    assert _needs("docs/edge-proxy-role.md\nREADME.md\n") is False


def test_core_tests_only_change_does_not_restart():
    assert _needs("core/tests/test_oci_vault.py\n") is False


def test_several_static_paths_together_do_not_restart():
    assert _needs("WebUI/main.js\ndocs/a.md\n.github/workflows/ci.yml\n"
                  "core/tests/test_x.py\nLICENSE\n") is False


def test_identical_commits_do_not_restart():
    """A no-op pull is not a change; don't even shell out."""
    u = _Updater("")
    assert u._core_change_needs_restart("/opt/lm", A, A) is False
    assert u.calls == []


# ── changes that MUST restart ────────────────────────────────────────────────

def test_core_source_change_restarts():
    assert _needs("core/src/oci_vault.py\n") is True


def test_base_spoke_change_restarts():
    """Every spoke imports base_spoke — this is the case that must never be
    optimised away."""
    assert _needs("core/src/base_spoke.py\n") is True


def test_agent_change_restarts():
    assert _needs("agent/src/spoke_client.py\n") is True


def test_mixed_static_and_code_restarts():
    """One real code file among static assets still requires the restart."""
    assert _needs("WebUI/main.js\ndocs/a.md\ncore/src/base_spoke.py\n") is True


def test_unknown_top_level_directory_restarts():
    """Deny-list, not allow-list: anything unrecognised is treated as code."""
    assert _needs("newthing/whatever.py\n") is True


def test_path_that_merely_contains_a_static_name_restarts():
    """Prefix match must be anchored — 'core/src/WebUI_helper.py' is code."""
    assert _needs("core/src/WebUI_helper.py\n") is True


# ── fail-safe behaviour ──────────────────────────────────────────────────────

def test_git_failure_restarts():
    assert _needs("", rc=1) is True


def test_git_exception_restarts():
    assert _needs("", boom=True) is True


def test_empty_diff_between_differing_commits_restarts():
    """Commits differ but git reported no files — unexplained, so restart."""
    assert _needs("") is True


def test_missing_commit_information_restarts():
    assert _needs("WebUI/main.js\n", frm="", to=B) is True
    assert _needs("WebUI/main.js\n", frm=A, to="") is True


def test_missing_core_root_restarts():
    assert _needs("WebUI/main.js\n", root="") is True


def test_blank_lines_in_diff_are_ignored():
    assert _needs("WebUI/main.js\n\n   \ndocs/a.md\n") is False


def test_the_diff_is_taken_between_the_two_commits():
    u = _Updater("WebUI/main.js\n")
    u._core_change_needs_restart("/opt/lm", A, B)
    args, cwd = u.calls[0]
    assert args == ("diff", "--name-only", A, B)
    assert cwd == "/opt/lm"
