"""Runtime dependency self-heal — install missing venv deps at startup.

A component (hub / spoke / agent) can boot into a venv that's missing a declared
requirement: a skewed auto-update that pulled code but didn't finish ``pip
install`` (the hub forward path before lm ``1df455a``), a partial install, a
manually-wiped venv, or the bootstrap catch where a new dep lands via git pull
but the running process predates the dep-realign fix. The result is either a
warning (an optional dep like ``zeroconf`` guarded by ``try/except ImportError``)
or a hard crash at import (a required dep like ``websockets``).

``ensure_requirements`` is the safety net: at the very top of each entrypoint —
BEFORE the heavy third-party imports — it parses the component's
``requirements.txt``, checks each top-level package is importable via
``importlib.util.find_spec``, and if any are missing runs
``pip install -r requirements.txt`` in the current venv (``sys.executable``) so
the subsequent imports find the just-installed packages (site-packages is already
on ``sys.path``; no re-exec needed). When everything is present it does no I/O
and no network — the check is ~ms — so it's cheap to call on every boot.

This module is **stdlib-only** (``importlib.util, logging, os, re, subprocess,
sys``) so it loads even when every third-party dep is missing. It is vendored
verbatim into the standalone pxmx agent (``pxmx/agent/src/dep_guard.py``) which
has no lm-core dependency — keep the two copies in sync. Best-effort by design:
a pip failure (air-gapped box, PyPI unreachable, venv not writable) is logged
and the function returns False; it NEVER raises, so optional deps' own graceful
``try/except ImportError`` still applies and a hard dep surfaces as a normal
ImportError on the caller's subsequent import (which systemd ``Restart=always``
will retry — and the next boot's guard will retry the install).
"""

# importlib.util.find_spec checks whether a package is importable without importing it.
import importlib.util
# Standard-library logging for self-heal progress and failures.
import logging
# os is used for the disable env var and checking the requirements file exists.
import os
# re splits a requirement line at its version specifier.
import re
# subprocess runs "pip install" in the current interpreter.
import subprocess
# sys gives the running interpreter path (sys.executable) and the module cache.
import sys
# Type hints only.
from typing import List

# One named logger so dependency-guard messages can be filtered together.
logger = logging.getLogger("DepGuard")

# pip distribution name → import name, for the cases where they differ. Anything
# not listed uses the default heuristic (strip extras/version, replace "-" with
# "_"). A wrong guess is harmless: find_spec returns None → we trigger a
# `pip install -r` that is a no-op when the dep is actually satisfied, then the
# caller's real import (under the correct name) succeeds.
_IMPORT_NAME = {
    "python-dotenv": "dotenv",
    "pyyaml": "yaml",
    "pyyaml3": "yaml",
    "dnspython": "dns",
    "beautifulsoup4": "bs4",
    "pillow": "PIL",
    "python-dateutil": "dateutil",
    "protobuf": "google.protobuf",
    "pyjwt": "jwt",
}


def _import_name_for(pip_name: str) -> str:
    """Map a requirements.txt line's pip name to its top-level import name."""
    # Remove any "[extras]" suffix, e.g. "uvicorn[standard]" -> "uvicorn".
    base = pip_name.split("[", 1)[0]            # drop [extras]
    base = re.split(r"[<>=!~;\s]", base)[0]     # drop version specs / whitespace
    # Trim leftover whitespace and stray environment-marker semicolons.
    base = base.strip().strip(";").strip()
    # Nothing usable left (odd line), so there is no import name to check.
    if not base:
        return ""
    # Use the known override if the names differ, else assume "-" maps to "_".
    return _IMPORT_NAME.get(base.lower(), base.replace("-", "_"))


def _parse_requirements(path: str) -> List[str]:
    """Return the non-comment, non-flag requirement lines from ``path``."""
    # Collected requirement lines to return.
    out: List[str] = []
    # Reading is best-effort; an unreadable file just yields an empty list.
    try:
        with open(path, "r") as f:
            # Look at each line of requirements.txt.
            for line in f:
                # Ignore surrounding whitespace.
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    # skip comments, blank lines, and pip flags (-e, -r, --foo)
                    continue
                line = line.split("#", 1)[0].strip()   # strip inline comments
                # The line was only an inline comment, so skip it.
                if not line:
                    continue
                # Keep this real requirement line.
                out.append(line)
    # File unreadable: log quietly and return what we have (usually nothing).
    except Exception as e:
        logger.debug("could not read requirements %s: %s", path, e)
    return out


def _missing_imports(path: str) -> List[str]:
    """Requirement lines whose top-level import name is NOT importable."""
    # Requirement lines whose package cannot currently be imported.
    missing: List[str] = []
    # Check each declared requirement in turn.
    for spec_line in _parse_requirements(path):
        # Work out the module name Python would import for this requirement.
        imp = _import_name_for(spec_line)
        # Could not derive a name; skip rather than guess.
        if not imp:
            continue
        try:
            # find_spec returns None when the package is not installed.
            if importlib.util.find_spec(imp) is None:
                missing.append(spec_line)
        except Exception:
            # find_spec can raise for malformed names; treat as missing.
            missing.append(spec_line)
    # Everything still needing installation.
    return missing


def ensure_requirements(requirements_path: str, timeout: int = 300) -> bool:
    """Ensure every declared requirement is importable; self-heal if not.

    Returns True if all deps are importable (after any install), False if a dep
    is still missing after a best-effort install attempt. Never raises.

    Set ``LM_DEP_GUARD_DISABLE=1`` to skip entirely (operators who manage the
    venv out-of-band, and the test suite — importing ``main`` triggers this at
    module load, and a dev box missing e.g. ``zeroconf`` must not attempt a
    real ``pip install`` into the test interpreter).
    """
    # Opt-out switch: report success without checking anything.
    if os.environ.get("LM_DEP_GUARD_DISABLE") == "1":
        return True
    # No requirements file found for this component.
    if not os.path.isfile(requirements_path):
        # Nothing to check (component has no requirements.txt) — not an error.
        return True

    # Find which declared packages are not importable right now.
    missing = _missing_imports(requirements_path)
    # All present: the common, fast path with no I/O beyond the check.
    if not missing:
        return True

    # Tell the operator what is missing before we try to fix it.
    logger.warning(
        "Missing venv deps (%s); running pip install -r %s to self-heal…",
        ", ".join(missing), requirements_path,
    )
    # Install into the same interpreter/venv that is running this process.
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "pip", "install", "-q", "-r", requirements_path],
            capture_output=True, text=True, timeout=timeout,
        )
        # pip ran but failed; log a trimmed error and still re-check below.
        if proc.returncode != 0:
            logger.warning(
                "dep self-heal pip install rc=%d: %s",
                proc.returncode, (proc.stderr or proc.stdout).strip()[:500],
            )
    # pip could not even be started or timed out; give up this boot.
    except Exception as e:
        logger.warning("dep self-heal pip install failed (continuing): %s", e)
        return False

    # Clear any stale None/Partial entries so the caller's subsequent imports
    # retry against the just-installed packages.
    # Forget cached import failures for each package we just tried to install.
    for spec_line in missing:
        imp = _import_name_for(spec_line)
        if imp:
            sys.modules.pop(imp, None)

    # Re-check after the install attempt.
    still = _missing_imports(requirements_path)
    # Some packages are still missing; report and signal failure.
    if still:
        logger.warning("Still missing after self-heal: %s", ", ".join(still))
        return False
    # Everything is importable now.
    logger.info("dep self-heal installed missing deps.")
    return True


def _main() -> int:
    """CLI: ``python -m dep_guard <requirements.txt> [--timeout N]`` → exit 0
    if all deps importable (after any install), 1 otherwise. For ad-hoc checks."""
    # argparse is imported lazily since it is only needed for the CLI entry point.
    import argparse

    # Build the command-line parser: one positional path and an optional timeout.
    parser = argparse.ArgumentParser(description="Self-heal missing venv deps.")
    parser.add_argument("requirements", help="path to requirements.txt")
    parser.add_argument("--timeout", type=int, default=300,
                        help="pip install timeout in seconds (default 300)")
    # Parse the command line arguments.
    args = parser.parse_args()
    # Exit code 0 when all deps are present (after self-heal), otherwise 1.
    return 0 if ensure_requirements(args.requirements, args.timeout) else 1


# Only run the CLI when executed directly, not when imported.
if __name__ == "__main__":
    sys.exit(_main())