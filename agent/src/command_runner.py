"""Local command runner for the Agent's generic RUN_COMMAND primitive.

Parity copy of ``core/src/command_runner.py`` / the pxmx node-agent's runner —
the spoke relays a signed RUN_COMMAND down to the Agent (hub → spoke → agent),
and the Agent runs it here and returns the result up the same path. Two modes:

* **allowlist** (default): the command's binary must be in ``ALLOWED_BINARIES``
  and carry NO shell metacharacters — a curated diagnostic set. A fat-finger
  guard, not a hard boundary.
* **shell** (opt-in, ``allow_shell=True``): runs verbatim through ``bash -lc``.
  The *spoke* holds the product logic and decides when to send a shell command
  (e.g. calling a role-provisioned cert helper); the Agent stays generic.

Always bounded: a wall-clock timeout and an output byte cap.
"""

# os: take the base name of the binary and create directories / replace files.
import os
# shlex: split a command string into arguments the way a shell would (without running one).
import shlex
# subprocess: actually run the command with a timeout and capture its output.
import subprocess

# Diagnostic-mode allowlist: read-only/inspection tools (services, logs, files, processes, disk,
# network, git, text filters) that are safe to run without opening a full shell.
ALLOWED_BINARIES = {
    "systemctl", "journalctl", "service",
    "tail", "head", "cat", "grep", "egrep", "zgrep",
    "ls", "find", "stat", "readlink", "file", "wc",
    "ps", "pgrep", "df", "du", "free", "uptime", "uname", "hostname",
    "date", "whoami", "id", "env",
    "ip", "ss", "netstat", "ping", "dig", "nslookup", "host", "getent",
    "git", "cut", "sort", "uniq", "tr",
    "nginx",  # cert-reload validation (nginx -t) on web hosts
}

# Characters that let a shell chain, redirect, substitute or escape commands. Allowlist mode
# refuses them because it does not use a shell and they would signal shell intent.
_SHELL_METACHARS = set(";|&`$><\n\\!(){}")


def _check_allowlisted(command: str):
    """Return (True, "") if command is safe for allowlist mode, else (False, reason)."""
    # Collect any forbidden characters present (sorted for a stable error message).
    bad = sorted({c for c in command if c in _SHELL_METACHARS})
    if bad:
        return False, (f"shell metacharacters {''.join(bad)!r} are not allowed in "
                       "diagnostic mode — send allow_shell to run those")
    # Split into arguments; unbalanced quotes make shlex raise ValueError.
    try:
        parts = shlex.split(command)
    except ValueError as e:
        return False, f"unparseable command: {e}"
    # Nothing left after splitting (e.g. only quotes) is rejected.
    if not parts:
        return False, "empty command"
    # Compare only the program name, so "/usr/bin/tail" matches "tail".
    binary = os.path.basename(parts[0])
    if binary not in ALLOWED_BINARIES:
        return False, (f"'{binary}' is not in the diagnostic allowlist — send "
                       "allow_shell to run arbitrary commands")
    # Passed every check.
    return True, ""


def run_local_command(command: str, allow_shell: bool = False,
                      timeout: float = 30.0, max_bytes: int = 64 * 1024) -> dict:
    """Run command locally and return a result dict (never raises).

    Args:
        command: the command line to run.
        allow_shell: True runs it verbatim via bash; False enforces the allowlist.
        timeout: seconds before the command is killed.
        max_bytes: cap on characters kept from stdout and from stderr each.

    Returns:
        dict with ok, rc, stdout, stderr, truncated, error and mode keys.
    """
    # Treat None as empty and drop surrounding whitespace.
    command = (command or "").strip()
    # Common shape of every result, so callers always find the same keys.
    base = {"ok": False, "rc": None, "stdout": "", "stderr": "", "truncated": False}
    # Refuse an empty command up front.
    if not command:
        return {**base, "error": "empty command"}

    # Shell mode: hand the whole string to a login bash so pipes, redirects and env work.
    if allow_shell:
        argv = ["/bin/bash", "-lc", command]
        mode = "shell"
    # Allowlist mode: validate first, then run the split argv directly (no shell involved).
    else:
        ok, reason = _check_allowlisted(command)
        if not ok:
            return {**base, "error": reason}
        argv = shlex.split(command)
        mode = "allowlist"

    # Run from "/" so relative paths never depend on the agent's working directory.
    try:
        proc = subprocess.run(argv, capture_output=True, text=True,
                              timeout=timeout, cwd="/")
    # The command ran too long and was killed.
    except subprocess.TimeoutExpired:
        return {**base, "error": f"command timed out after {timeout:.0f}s", "mode": mode}
    # The program does not exist on this host.
    except FileNotFoundError:
        return {**base, "error": f"binary not found: {argv[0]}", "mode": mode}
    # Any other launch failure is reported rather than raised, so the agent keeps running.
    except Exception as e:  # noqa: BLE001
        return {**base, "error": str(e), "mode": mode}

    # Normalise missing output to "" and start with "not truncated".
    out, err, truncated = proc.stdout or "", proc.stderr or "", False
    # Cap each stream so a huge log dump cannot flood the hub; mark the result as truncated.
    if len(out) > max_bytes:
        out, truncated = out[:max_bytes] + "\n…[truncated]", True
    if len(err) > max_bytes:
        err, truncated = err[:max_bytes] + "\n…[truncated]", True
    # Successful run (ok means "it ran", rc carries the command's own exit status).
    return {"ok": True, "rc": proc.returncode, "stdout": out, "stderr": err,
            "truncated": truncated, "error": "", "mode": mode}


def write_local_file(path: str, content: str = "", *, b64: str = "",
                     mode: int = 0o600, mkdirs: bool = True,
                     atomic: bool = True) -> dict:
    """Write ``content`` (or base64 ``b64``) to ``path`` with ``mode``.

    Generic primitive the Agent exposes for spokes that need to place a file on
    the host (e.g. a TLS cert). Atomic by default (tmp + ``os.replace``). The
    spoke owns *what* to write and *where*; the Agent just does it."""
    # Imported here because only this function needs base64 decoding.
    import base64 as _b64
    # Any filesystem/decoding error is returned in the result dict instead of raised.
    try:
        # Binary payloads arrive base64-encoded; decode them to raw bytes.
        if b64:
            data = _b64.b64decode(b64)
        # Otherwise encode text to bytes (or coerce an existing bytes-like value).
        else:
            data = (content or "").encode() if isinstance(content, str) else bytes(content or b"")
        # Create the parent directory if asked and it is missing.
        d = os.path.dirname(path)
        if mkdirs and d and not os.path.exists(d):
            os.makedirs(d, exist_ok=True)
        # Atomic writes go to "<path>.tmp" first so readers never see a half-written file.
        target = (path + ".tmp") if atomic else path
        # Write the bytes and set permissions (0600 by default because certs/keys are secret).
        with open(target, "wb") as f:
            f.write(data)
        os.chmod(target, mode)
        # Swap the finished temp file into place in one step.
        if atomic:
            os.replace(target, path)
        # Report success and how many bytes were written.
        return {"ok": True, "path": path, "bytes": len(data)}
    except Exception as e:  # noqa: BLE001
        # Report the failure to the spoke instead of crashing the agent.
        return {"ok": False, "path": path, "error": str(e)}
