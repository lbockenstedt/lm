"""Shared logging configuration for every LM process entrypoint.

Single source of truth for the log format, level, and destination so the
~10 hub/spoke/agent entrypoints can't drift (the drift that made opnsense +
nw silently drop all INFO logs at cold start because they had no
``basicConfig`` at all).

Contract (matches ``base_spoke.py``): LIBRARY modules must NOT call
``basicConfig`` — only the process entrypoint calls :func:`configure_logging`
once at startup. Library modules just do ``logging.getLogger("<FixedName>")``.

Level resolution: the ``LOG_LEVEL`` env var (case-insensitive
DEBUG/INFO/WARNING/ERROR) overrides ``default_level`` at boot; the WebUI
"Enable Debug" button calls :func:`set_log_level` at runtime to flip root +
every named logger between DEBUG and INFO.
"""

import logging
import logging.handlers
import os
import sys

DEFAULT_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
DEFAULT_DATEFMT = '%Y-%m-%d %H:%M:%S'

# Circular (size-capped) logging so a component's /var/log/lm/<x>.log can't grow
# unbounded and fill the box's disk. Every entrypoint routes through
# configure_logging(), so capping here gives ALL modules/spokes/agents rotation
# at once. Tunable via env; LM_LOG_MAX_BYTES=0 disables rotation (plain append).
# Default: 20 MB × 5 backups = ~120 MB max per component.
_DEFAULT_LOG_MAX_BYTES = 20 * 1024 * 1024
_DEFAULT_LOG_BACKUPS = 5


def _int_env(name: str, default: int) -> int:
    try:
        v = int(str(os.getenv(name) or "").strip())
        return v if v >= 0 else default
    except (TypeError, ValueError):
        return default


def _build_file_handler(log_file: str) -> logging.Handler:
    """A size-capped RotatingFileHandler for ``log_file`` (falls back to a plain
    FileHandler when rotation is disabled via ``LM_LOG_MAX_BYTES=0`` or if the
    handlers module is somehow unavailable). ``delay=True`` so the file isn't
    opened until the first record — cheap when a component logs elsewhere.

    NOTE on systemd ``StandardError=append:`` co-writers: the entrypoint drops
    the stderr StreamHandler for the canonical /var/log/lm file, so this handler
    owns the bulk log stream and rotates it; only rare uncaught-traceback stderr
    (captured by systemd) may trail into the last rotated file — bounded and
    acceptable. Boxes that also install the /etc/logrotate.d/lm copytruncate
    drop-in get belt-and-suspenders coverage of that stderr stream too."""
    max_bytes = _int_env("LM_LOG_MAX_BYTES", _DEFAULT_LOG_MAX_BYTES)
    backups = _int_env("LM_LOG_BACKUPS", _DEFAULT_LOG_BACKUPS)
    if max_bytes <= 0:
        return logging.FileHandler(log_file)
    return logging.handlers.RotatingFileHandler(
        log_file, maxBytes=max_bytes, backupCount=backups, delay=True)


def _resolve_level(default_level: int) -> int:
    """Return the effective level: ``LOG_LEVEL`` env (if a valid level name)
    wins, else ``default_level``."""
    raw = (os.getenv("LOG_LEVEL") or "").strip().upper()
    if raw:
        resolved = getattr(logging, raw, None)
        if isinstance(resolved, int):
            return resolved
    return default_level


def configure_logging(default_level: int = logging.INFO, *,
                      log_file: str = None,
                      line_buffered: bool = True,
                      fmt: str = DEFAULT_FORMAT,
                      datefmt: str = DEFAULT_DATEFMT) -> int:
    """Configure the root logger once from a process entrypoint.

    Parameters
    ----------
    default_level:
        Fallback level when ``LOG_LEVEL`` is unset/invalid. Spokes use INFO.
    log_file:
        If set, attach a ``FileHandler`` alongside the stderr
        ``StreamHandler`` — for standalone agents that run off-hub on Proxmox
        nodes where stderr isn't captured by systemd. None → stderr only.
    line_buffered:
        Reconfigure stdout/stderr to line buffering so systemd file redirects
        (``StandardOutput=append:``) flush promptly instead of block-buffering
        (which loses the last lines on a crash/restart).
    """
    level = _resolve_level(default_level)
    handlers = None
    if log_file:
        try:
            os.makedirs(os.path.dirname(log_file) or ".", exist_ok=True)
        except Exception:
            pass
        handlers = [_build_file_handler(log_file), logging.StreamHandler()]
    logging.basicConfig(level=level, format=fmt, datefmt=datefmt,
                        handlers=handlers, force=True)
    if line_buffered:
        for stream in (sys.stdout, sys.stderr):
            try:
                stream.reconfigure(line_buffering=True)
            except Exception:
                pass
    return level


def set_log_level(enabled: bool) -> int:
    """Runtime DEBUG/INFO flip used by the WebUI "Enable Debug" button
    (``POST /setup/debug-mode`` → ``broadcast_log_level`` → spokes/agents, and
    the hub's own route handler).

    Sets the root logger AND every existing named logger so per-module
    overrides don't block the toggle. Overrides the boot ``LOG_LEVEL`` live;
    on restart the env value takes effect again. ``enabled=False`` returns to
    INFO (the button is a binary DEBUG/INFO toggle).
    """
    level = logging.DEBUG if enabled else logging.INFO
    logging.getLogger().setLevel(level)
    for name in list(logging.root.manager.loggerDict):
        logging.getLogger(name).setLevel(level)
    return level