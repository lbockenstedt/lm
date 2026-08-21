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
import threading
import time

DEFAULT_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
DEFAULT_DATEFMT = '%Y-%m-%d %H:%M:%S'

# Circular (size-capped) logging so a component's /var/log/lm/<x>.log can't grow
# unbounded and fill the box's disk. Every entrypoint routes through
# configure_logging(), so capping here gives ALL modules/spokes/agents a single
# 50 MB circular file at once — NO rotated backups to maintain.
#
# Two enforcement layers, both driven from configure_logging():
#   1. The process FileHandler (this file's writer) — plain append, no rollover.
#   2. An in-process size-cap watchdog thread (_start_log_cap_watchdog) that
#      every ~30 s truncates any /var/log/lm/*.log over the cap IN PLACE.
# Layer 2 is what actually enforces the cap because most LM services run under
# systemd with StandardOutput/StandardError=append:/var/log/lm/<x>.log — i.e.
# systemd (NOT the FileHandler) owns the fd, so a RotatingFileHandler's rollover
# never fires. Truncate-in-place (open(path,"w")) works regardless: both the
# FileHandler fd and systemd's O_APPEND fd resume writing at offset 0 after the
# truncate (same inode), so the file stays a single circular file with no
# backups. See truncate_log_files() for the full rationale on why in-place.
#
# Tunable via env: LM_LOG_MAX_BYTES=0 disables the cap entirely (unbounded).
# Default: 50 MB, 0 backups.
_DEFAULT_LOG_MAX_BYTES = 50 * 1024 * 1024
_DEFAULT_LOG_BACKUPS = 0
_DEFAULT_LOG_CAP_INTERVAL = 30.0

# Liveness-poll endpoints whose successful (2xx/3xx) uvicorn.access lines are pure
# noise — the hub/agents health-probe these per second, flooding spoke/hub logs.
# 4xx/5xx responses still log (real failures), and all other requests log. In
# debug mode the filter is bypassed so every access line shows. Tunable via env
# (comma-separated); set LM_QUIET_ACCESS_PATHS="" to disable filtering.
_DEFAULT_QUIET_ACCESS_PATHS = "/api/health,/api/status"


class _QuietSuccessAccessFilter(logging.Filter):
    """Drop uvicorn.access lines for noisy liveness endpoints, but only on
    success (status < 400) — failing probes still log so troubleshooting isn't
    lost. Bypassed entirely when the uvicorn.access logger is at DEBUG."""

    def __init__(self, quiet_paths: tuple) -> None:
        super().__init__()
        self._quiet_paths = quiet_paths

    def filter(self, record: logging.LogRecord) -> bool:
        # In debug mode show every access line.
        if logging.getLogger("uvicorn.access").getEffectiveLevel() <= logging.DEBUG:
            return True
        try:
            msg = record.getMessage()
        except Exception:  # noqa: BLE001 — never block a record on a format error
            return True
        if not any(p in msg for p in self._quiet_paths):
            return True
        # Status code is the trailing token in uvicorn's access format:
        # `'<client> - "<request_line>" <status_code>'. Keep non-2xx/3xx.
        tail = msg.rsplit(" ", 1)[-1] if " " in msg else ""
        if tail.isdigit() and int(tail) < 400:
            return False
        return True


def _quiet_access_paths() -> tuple:
    """Resolve the quiet-access-path list. Unset env → defaults; empty env →
    filtering disabled; otherwise the comma-separated list."""
    raw = os.getenv("LM_QUIET_ACCESS_PATHS")
    if raw is None:
        raw = _DEFAULT_QUIET_ACCESS_PATHS
    paths = tuple(p for p in (s.strip() for s in raw.split(",")) if p)
    return paths


class _QuietUvicornLifecycleFilter(logging.Filter):
    """Drop per-connection uvicorn lifecycle noise so a high-volume client-WS
    spoke (e.g. cs with many sim clients) doesn't flood the journal + the hub
    relay buffer with a line per connect/disconnect:

      - ``uvicorn.error``: ``connection open`` / ``connection closed`` — each
        HTTP/WebSocket connection emits both, so at 10k clients this is the
        single biggest source of INFO spam.
      - ``uvicorn.access`` / ``uvicorn.error``: ``<addr> - "WebSocket /path"
        [accepted]`` — one per WS handshake.

    These are redundant at INFO: the client registry + CS telemetry already
    track connected clients. Bypassed entirely at DEBUG (Enable Debug reveals
    them) and NEVER suppresses WARNING+ (real rejections / handshake failures
    / shutdown errors still log). Idempotent across re-inits.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        # Never quiet warnings/errors — only the INFO lifecycle chatter.
        if record.levelno >= logging.WARNING:
            return True
        # In debug mode show every lifecycle line.
        if logging.getLogger(record.name).getEffectiveLevel() <= logging.DEBUG:
            return True
        try:
            msg = record.getMessage()
        except Exception:  # noqa: BLE001 — never block a record on a format error
            return True
        if msg in ("connection open", "connection closed"):
            return False
        # WebSocket accept line: ``<addr> - "WebSocket /path" [accepted]``.
        # Match on the two stable substrings so it survives uvicorn format
        # tweaks without over-matching ordinary HTTP access lines.
        if '"WebSocket ' in msg and " [accepted]" in msg:
            return False
        return True


def _int_env(name: str, default: int) -> int:
    try:
        v = int(str(os.getenv(name) or "").strip())
        return v if v >= 0 else default
    except (TypeError, ValueError):
        return default


def _build_file_handler(log_file: str) -> logging.Handler:
    """A FileHandler for ``log_file``. The 50 MB cap is enforced out-of-band by
    the in-process watchdog (:func:`_start_log_cap_watchdog`), NOT by handler
    rollover — because most LM services run under systemd with
    ``StandardOutput/StandardError=append:`` owning the fd, so a
    RotatingFileHandler's rollover would never fire anyway. So when backups are
    disabled (the default, ``LM_LOG_BACKUPS=0``) we attach a plain FileHandler
    and let the watchdog truncate-in-place at the cap. A RotatingFileHandler is
    only used if an operator explicitly asks for backups
    (``LM_LOG_BACKUPS>=1``), for the rare standalone-file case where this
    handler actually owns the writer. ``delay=True`` so the file isn't opened
    until the first record — cheap when a component logs elsewhere."""
    max_bytes = _int_env("LM_LOG_MAX_BYTES", _DEFAULT_LOG_MAX_BYTES)
    backups = _int_env("LM_LOG_BACKUPS", _DEFAULT_LOG_BACKUPS)
    if max_bytes <= 0 or backups <= 0:
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


_log_cap_watchdog_started = False
_log_cap_watchdog_lock = threading.Lock()


def cap_oversized_logs(log_dir: str, max_bytes: int) -> list:
    """Truncate every ``*.log`` in ``log_dir`` currently larger than
    ``max_bytes`` to zero bytes, in place. One watchdog pass.

    Truncation is ``open(path, "w")`` (``O_TRUNC`` on the existing inode) so
    both this process's held FileHandler fd AND systemd's
    ``StandardOutput/StandardError=append:`` fd keep writing at offset 0 after
    the truncate — the file stays a single circular file with NO backups. See
    :func:`truncate_log_files` for the full "why in-place, not unlink"
    rationale. Best-effort per file: any error is swallowed so the watchdog can
    never crash the process it runs inside. Returns the list of filenames it
    truncated on this pass."""
    if max_bytes <= 0:
        return []
    truncated = []
    try:
        names = os.listdir(log_dir)
    except Exception:  # noqa: BLE001 — dir may not exist yet; try next pass
        return truncated
    for name in names:
        if not name.endswith(".log"):
            continue
        path = os.path.join(log_dir, name)
        try:
            if os.path.isfile(path) and os.path.getsize(path) > max_bytes:
                with open(path, "w"):
                    pass  # O_TRUNC in place — see truncate_log_files() docstring
                truncated.append(name)
        except Exception:  # noqa: BLE001 — per-file best-effort, never raise
            pass
    return truncated


def _start_log_cap_watchdog(log_dir: str, max_bytes: int,
                            interval: float = _DEFAULT_LOG_CAP_INTERVAL) -> None:
    """Start (once per process) a daemon thread that every ``interval`` seconds
    truncates any oversized ``*.log`` in ``log_dir`` back under ``max_bytes``.

    This is the actual 50 MB circular-log enforcement: it works even when
    systemd (``append:``), not the Python FileHandler, owns the log fd — the
    case for every LM service — because it truncates the inode in place. Daemon
    thread so it never blocks interpreter shutdown; idempotent so repeated
    ``configure_logging`` calls don't spawn duplicates; ``max_bytes<=0``
    (``LM_LOG_MAX_BYTES=0``) disables it (unbounded logs)."""
    global _log_cap_watchdog_started
    if max_bytes <= 0:
        return
    with _log_cap_watchdog_lock:
        if _log_cap_watchdog_started:
            return
        _log_cap_watchdog_started = True

    def _loop():
        while True:
            try:
                cap_oversized_logs(log_dir, max_bytes)
            except Exception:  # noqa: BLE001 — never let the watchdog die
                pass
            time.sleep(interval)

    threading.Thread(target=_loop, name="lm-log-cap-watchdog", daemon=True).start()


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

    # Suppress noisy successful liveness-poll access lines (per-second
    # /api/health, /api/status) on the uvicorn.access logger. Bypassed in debug
    # mode; failing probes (4xx/5xx) still log. Idempotent across re-inits.
    quiet_paths = _quiet_access_paths()
    if quiet_paths:
        access_logger = logging.getLogger("uvicorn.access")
        if not any(isinstance(f, _QuietSuccessAccessFilter) for f in access_logger.filters):
            access_logger.addFilter(_QuietSuccessAccessFilter(quiet_paths))

    # Suppress per-connection uvicorn lifecycle noise ("connection open" /
    # "connection closed" / WebSocket "[accepted]") on both uvicorn.error and
    # uvicorn.access so a high-volume client-WS spoke (cs) doesn't flood the
    # journal + hub relay with a line per connect/disconnect. Bypassed in debug
    # mode; WARNING+ (rejections/failures) always log. Idempotent across re-inits.
    for _lname in ("uvicorn.error", "uvicorn.access"):
        _lg = logging.getLogger(_lname)
        if not any(isinstance(f, _QuietUvicornLifecycleFilter) for f in _lg.filters):
            _lg.addFilter(_QuietUvicornLifecycleFilter())

    # Start the 50 MB circular-log watchdog. Derive the log dir from log_file
    # when given, else the canonical /var/log/lm (CS + some spokes call
    # configure_logging() with no log_file — their file is written by systemd's
    # append: redirect, which the watchdog still caps in place). Idempotent, so
    # a re-init won't spawn a second thread. LM_LOG_MAX_BYTES=0 disables.
    _cap_dir = os.path.dirname(log_file) if log_file else "/var/log/lm"
    _start_log_cap_watchdog(_cap_dir or "/var/log/lm",
                            _int_env("LM_LOG_MAX_BYTES", _DEFAULT_LOG_MAX_BYTES))
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


def truncate_log_files(log_dir: str = "/var/log/lm"):
    """Truncate every ``*.log`` file in ``log_dir`` to zero bytes, in place.

    Used by the WebUI "Clear Logs" button (``POST /setup/logs/clear`` on the
    hub, and the ``CLEAR_LOGS`` command the hub broadcasts to every connected
    spoke/agent) so an operator can wipe the on-disk log trail across the whole
    fleet from one place — the hub's own ``/var/log/lm/hub.log`` plus every
    co-located spoke file on the hub box, and each remote spoke's own
    ``/var/log/lm/<x>.log`` via the broadcast.

    Truncation is ``open(path, "w")`` (``O_TRUNC`` on the existing inode) — NOT
    an unlink+recreate. The :class:`logging.handlers.RotatingFileHandler` each
    process holds open for its own log file keeps the same file descriptor
    pointing at the same (now-empty) inode, so its next ``emit`` writes at
    offset 0 (``shouldRollover`` seeks to end → 0 → no rollover, then the write
    lands at 0). Unlinking instead would detach the handler to a stale inode
    and silently lose every subsequent log line — the classic logrotate pitfall
    that ``copytruncate`` exists to avoid, sidestepped here by truncating in
    place. Returns the list of filenames truncated (best-effort per file:
    a permission error on one file is logged + skipped, not raised)."""
    truncated = []
    try:
        names = os.listdir(log_dir)
    except FileNotFoundError:
        return truncated
    except Exception:  # noqa: BLE001 — never let log-clearing crash the caller
        return truncated
    for name in names:
        if not name.endswith(".log"):
            continue
        path = os.path.join(log_dir, name)
        try:
            if not os.path.isfile(path):
                continue
            with open(path, "w"):
                pass  # O_TRUNC in place — see docstring on why not unlink
            truncated.append(name)
        except Exception:  # noqa: BLE001 — per-file best-effort
            logging.getLogger(__name__).warning(
                "truncate_log_files: could not truncate %s: %s", path,
                exc_info=True if logging.getLogger().isEnabledFor(logging.DEBUG) else None)
    return truncated