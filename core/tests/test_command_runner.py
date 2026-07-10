"""Command-runner allowlist/shell gate — security-relevant, so lock it in.

Diagnostic (allowlist) mode must: allow a curated binary, reject a
non-allowlisted binary, and reject shell metacharacters (so an allowlisted
binary can't be chained into arbitrary exec). Shell mode runs verbatim. Both
modes are bounded by a timeout + output cap.
"""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from command_runner import run_local_command  # noqa: E402


def test_allowlist_permits_curated_binary():
    r = run_local_command("date", allow_shell=False)
    assert r["ok"] and r["rc"] == 0 and r["mode"] == "allowlist"


def test_allowlist_rejects_non_allowlisted_binary():
    r = run_local_command("rm -rf /tmp/whatever", allow_shell=False)
    assert not r["ok"] and r["rc"] is None
    assert "allowlist" in r["error"]


def test_allowlist_rejects_shell_metacharacters():
    for cmd in ("cat /etc/hostname | grep x",   # pipe
                "id; rm -rf /",                    # chain
                "id && reboot",                    # and
                "cat $(id)",                        # substitution
                "echo hi > /etc/passwd",           # redirect
                "id `whoami`"):                     # backtick
        r = run_local_command(cmd, allow_shell=False)
        assert not r["ok"], cmd
        assert "metacharacter" in r["error"] or "allowlist" in r["error"], cmd


def test_shell_mode_runs_arbitrary():
    r = run_local_command("echo one && echo two", allow_shell=True)
    assert r["ok"] and r["rc"] == 0 and r["mode"] == "shell"
    assert r["stdout"].split() == ["one", "two"]


def test_timeout_is_enforced():
    r = run_local_command("sleep 5", allow_shell=True, timeout=1)
    assert not r["ok"] and "timed out" in r["error"]


def test_output_is_capped():
    # ~200 KB of output, capped to max_bytes.
    r = run_local_command("head -c 200000 /dev/zero | tr '\\0' 'a'", allow_shell=True, max_bytes=1024)
    assert r["ok"] and r["truncated"] and len(r["stdout"]) <= 1024 + 32


def test_empty_command_is_rejected():
    r = run_local_command("   ", allow_shell=True)
    assert not r["ok"] and "empty" in r["error"]
