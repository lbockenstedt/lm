"""Local command runner for the WebUI Remote Console (troubleshooting).

Shared by the hub (runs on itself) and every ``BaseControlPlane`` spoke/agent
(runs via the ``RUN_COMMAND`` system command). Two modes:

* **allowlist** (default): the command's binary must be in ``ALLOWED_BINARIES``
  and the command must carry NO shell metacharacters — a curated, mostly
  read-only diagnostic set (``systemctl status``, ``journalctl``, ``tail``,
  ``grep``, ``ps``, ``df``, ``ip`` …). This is a fat-finger / casual-mutation
  guard, not a hard security boundary — a Global-Admin can flip the WebUI
  "debug mode" knob for full shell.
* **shell** (opt-in via the WebUI "debug mode" knob): the command runs verbatim
  through ``bash -lc`` — arbitrary execution. Global-Admin only, audit-logged,
  and the whole feature is OFF until an admin enables it in the WebUI.

Always bounded: a wall-clock timeout and an output byte cap (stdout + stderr are
truncated, never streamed unbounded into the hub log / WebUI).
"""

# os.path.basename extracts the program name from a possibly full path like /usr/bin/tail.
import os
# shlex splits a command line into argv the same way a POSIX shell would (quotes honoured).
import shlex
# subprocess actually launches the command and captures its output.
import subprocess

# Curated diagnostic binaries for allowlist mode. Deliberately EXCLUDES anything
# that trivially executes arbitrary code even without shell metacharacters
# (sh/bash/python/perl/awk/find -exec via a single token, curl|pip that fetch +
# run) — those require the explicit shell toggle.
ALLOWED_BINARIES = {
    "systemctl", "journalctl", "service",
    "tail", "head", "cat", "grep", "egrep", "zgrep",
    "ls", "find", "stat", "readlink", "file", "wc",
    "ps", "pgrep", "df", "du", "free", "uptime", "uname", "hostname",
    "date", "whoami", "id", "env",
    "ip", "ss", "netstat", "ping", "dig", "nslookup", "host", "getent",
    "git", "cut", "sort", "uniq", "tr",
}

# Shell metacharacters rejected in allowlist mode — block chaining, pipelines,
# redirection and substitution so an allowlisted binary can't be turned into an
# arbitrary-exec vector.
_SHELL_METACHARS = set(";|&`$><\n\\!(){}")


def _check_allowlisted(command: str):
    """Return ``(ok, reason)``. Allowlisted iff the command parses as a single
    simple command whose binary basename is in ``ALLOWED_BINARIES`` and it
    contains no shell metacharacters."""
    # Collect every forbidden shell character present (sorted for a stable, readable message).
    bad = sorted({c for c in command if c in _SHELL_METACHARS})
    # Any metacharacter means chaining/redirection could be attempted, so refuse.
    if bad:
        return False, (f"shell metacharacters {''.join(bad)!r} are not allowed in "
                       "diagnostic mode — enable Debug (shell) mode to run those")
    # Split into argv; unbalanced quotes raise ValueError, which we report as a clear error.
    try:
        parts = shlex.split(command)
    except ValueError as e:
        return False, f"unparseable command: {e}"
    # Only whitespace was given, so there is nothing to run.
    if not parts:
        return False, "empty command"
    # Compare only the program name so "/usr/bin/tail" and "tail" are treated the same.
    binary = os.path.basename(parts[0])
    # Program is not on the curated diagnostic list, so refuse in allowlist mode.
    if binary not in ALLOWED_BINARIES:
        return False, (f"'{binary}' is not in the diagnostic allowlist — enable "
                       "Debug (shell) mode to run arbitrary commands")
    # Passed every check: safe to run as a plain argv command.
    return True, ""


def run_local_command(command: str, allow_shell: bool = False,
                      timeout: float = 30.0, max_bytes: int = 64 * 1024) -> dict:
    """Run ``command`` locally; return a dict with ``ok``/``rc``/``stdout``/
    ``stderr``/``truncated``/``error``/``mode``.

    ``allow_shell=False`` → allowlist gate + no metacharacters, run via argv (no
    shell). ``allow_shell=True`` → run verbatim through ``bash -lc`` (arbitrary).
    Bounded by ``timeout`` seconds and ``max_bytes`` per stream.
    """
    # Treat None as empty and drop surrounding whitespace before validating.
    command = (command or "").strip()
    # Common result fields shared by every return path; individual paths override pieces.
    base = {"ok": False, "rc": None, "stdout": "", "stderr": "", "truncated": False}
    # Nothing to run, so return an error immediately.
    if not command:
        return {**base, "error": "empty command"}

    # Debug (shell) mode: hand the text to bash verbatim; -l loads the login profile/PATH.
    if allow_shell:
        argv = ["/bin/bash", "-lc", command]
        mode = "shell"
    # Diagnostic mode: enforce the allowlist and never involve a shell.
    else:
        ok, reason = _check_allowlisted(command)
        # Rejected by the allowlist; return the human-readable reason.
        if not ok:
            return {**base, "error": reason}
        # Safe to split into argv and execute directly (no shell interpretation).
        argv = shlex.split(command)
        mode = "allowlist"

    # Run with captured text output, a hard timeout, and "/" as working dir for predictability.
    try:
        proc = subprocess.run(argv, capture_output=True, text=True,
                              timeout=timeout, cwd="/")
    # The command ran too long and was killed by subprocess.run.
    except subprocess.TimeoutExpired:
        return {**base, "error": f"command timed out after {timeout:.0f}s", "mode": mode}
    # The program itself does not exist on this machine.
    except FileNotFoundError:
        return {**base, "error": f"binary not found: {argv[0]}", "mode": mode}
    # Any other launch failure (permissions, OS error) is reported back instead of raised.
    except Exception as e:  # noqa: BLE001 — surface any spawn failure to the caller
        return {**base, "error": str(e), "mode": mode}

    # Start from the captured streams (None becomes ""), assuming no truncation yet.
    out, err, truncated = proc.stdout or "", proc.stderr or "", False
    # Cap stdout so a huge output cannot flood the hub log / WebUI.
    if len(out) > max_bytes:
        out, truncated = out[:max_bytes] + "\n…[truncated]", True
    # Cap stderr for the same reason.
    if len(err) > max_bytes:
        err, truncated = err[:max_bytes] + "\n…[truncated]", True
    # Report success (the command ran) along with its exit code and captured output.
    return {"ok": True, "rc": proc.returncode, "stdout": out, "stderr": err,
            "truncated": truncated, "error": "", "mode": mode}
