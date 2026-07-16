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

import os
import shlex
import subprocess

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

_SHELL_METACHARS = set(";|&`$><\n\\!(){}")


def _check_allowlisted(command: str):
    bad = sorted({c for c in command if c in _SHELL_METACHARS})
    if bad:
        return False, (f"shell metacharacters {''.join(bad)!r} are not allowed in "
                       "diagnostic mode — send allow_shell to run those")
    try:
        parts = shlex.split(command)
    except ValueError as e:
        return False, f"unparseable command: {e}"
    if not parts:
        return False, "empty command"
    binary = os.path.basename(parts[0])
    if binary not in ALLOWED_BINARIES:
        return False, (f"'{binary}' is not in the diagnostic allowlist — send "
                       "allow_shell to run arbitrary commands")
    return True, ""


def run_local_command(command: str, allow_shell: bool = False,
                      timeout: float = 30.0, max_bytes: int = 64 * 1024) -> dict:
    command = (command or "").strip()
    base = {"ok": False, "rc": None, "stdout": "", "stderr": "", "truncated": False}
    if not command:
        return {**base, "error": "empty command"}

    if allow_shell:
        argv = ["/bin/bash", "-lc", command]
        mode = "shell"
    else:
        ok, reason = _check_allowlisted(command)
        if not ok:
            return {**base, "error": reason}
        argv = shlex.split(command)
        mode = "allowlist"

    try:
        proc = subprocess.run(argv, capture_output=True, text=True,
                              timeout=timeout, cwd="/")
    except subprocess.TimeoutExpired:
        return {**base, "error": f"command timed out after {timeout:.0f}s", "mode": mode}
    except FileNotFoundError:
        return {**base, "error": f"binary not found: {argv[0]}", "mode": mode}
    except Exception as e:  # noqa: BLE001
        return {**base, "error": str(e), "mode": mode}

    out, err, truncated = proc.stdout or "", proc.stderr or "", False
    if len(out) > max_bytes:
        out, truncated = out[:max_bytes] + "\n…[truncated]", True
    if len(err) > max_bytes:
        err, truncated = err[:max_bytes] + "\n…[truncated]", True
    return {"ok": True, "rc": proc.returncode, "stdout": out, "stderr": err,
            "truncated": truncated, "error": "", "mode": mode}


def write_local_file(path: str, content: str = "", *, b64: str = "",
                     mode: int = 0o600, mkdirs: bool = True,
                     atomic: bool = True) -> dict:
    """Write ``content`` (or base64 ``b64``) to ``path`` with ``mode``.

    Generic primitive the Agent exposes for spokes that need to place a file on
    the host (e.g. a TLS cert). Atomic by default (tmp + ``os.replace``). The
    spoke owns *what* to write and *where*; the Agent just does it."""
    import base64 as _b64
    try:
        if b64:
            data = _b64.b64decode(b64)
        else:
            data = (content or "").encode() if isinstance(content, str) else bytes(content or b"")
        d = os.path.dirname(path)
        if mkdirs and d and not os.path.exists(d):
            os.makedirs(d, exist_ok=True)
        target = (path + ".tmp") if atomic else path
        with open(target, "wb") as f:
            f.write(data)
        os.chmod(target, mode)
        if atomic:
            os.replace(target, path)
        return {"ok": True, "path": path, "bytes": len(data)}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "path": path, "error": str(e)}
