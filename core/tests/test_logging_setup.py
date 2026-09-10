"""Unit tests for the shared logging setup helper (``core/src/logging_setup.py``).

These lock in the contract every entrypoint relies on: ``LOG_LEVEL`` env
overrides the default, the standard format is applied, ``log_file`` attaches a
FileHandler alongside stderr, and the runtime ``set_log_level`` flips root +
every named logger. The root logger is restored between tests so the suite
isn't polluted.
"""

import logging
import os
from unittest import mock

import logging_setup


def _root_handlers():
    return list(logging.getLogger().handlers)


def _restore_root(handlers, level):
    root = logging.getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)
    for h in handlers:
        root.addHandler(h)
    root.setLevel(level)


def test_configure_logging_default_is_info():
    saved_h, saved_lvl = _root_handlers(), logging.getLogger().level
    try:
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("LOG_LEVEL", None)
            level = logging_setup.configure_logging(line_buffered=False)
        assert level == logging.INFO
        assert logging.getLogger().getEffectiveLevel() == logging.INFO
    finally:
        _restore_root(saved_h, saved_lvl)


def test_configure_logging_respects_log_level_env():
    saved_h, saved_lvl = _root_handlers(), logging.getLogger().level
    try:
        for val, expected in (("DEBUG", logging.DEBUG),
                              ("debug", logging.DEBUG),
                              ("WARNING", logging.WARNING),
                              ("ERROR", logging.ERROR)):
            with mock.patch.dict(os.environ, {"LOG_LEVEL": val}):
                level = logging_setup.configure_logging(line_buffered=False)
            assert level == expected, f"LOG_LEVEL={val!r} -> {level} != {expected}"
    finally:
        _restore_root(saved_h, saved_lvl)


def test_configure_logging_invalid_log_level_falls_back_to_default():
    saved_h, saved_lvl = _root_handlers(), logging.getLogger().level
    try:
        with mock.patch.dict(os.environ, {"LOG_LEVEL": "VERBOSE"}):
            level = logging_setup.configure_logging(
                default_level=logging.WARNING, line_buffered=False)
        assert level == logging.WARNING  # invalid name -> default retained
    finally:
        _restore_root(saved_h, saved_lvl)


def test_configure_logging_applies_standard_format():
    saved_h, saved_lvl = _root_handlers(), logging.getLogger().level
    try:
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("LOG_LEVEL", None)
            logging_setup.configure_logging(line_buffered=False)
        fmt = logging.getLogger().handlers[0].formatter
        assert fmt._fmt == logging_setup.DEFAULT_FORMAT
        assert fmt.datefmt == logging_setup.DEFAULT_DATEFMT
    finally:
        _restore_root(saved_h, saved_lvl)


def test_log_file_attaches_file_handler_alongside_stream():
    saved_h, saved_lvl = _root_handlers(), logging.getLogger().level
    path = "/tmp/test_lm_logging_setup.log"
    try:
        if os.path.exists(path):
            os.remove(path)
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("LOG_LEVEL", None)
            logging_setup.configure_logging(log_file=path, line_buffered=False)
        kinds = {type(h).__name__ for h in logging.getLogger().handlers}
        # _build_file_handler returns a RotatingFileHandler (a FileHandler subclass)
        # when rotation is enabled (the default); accept any FileHandler subclass.
        file_handlers = [h for h in logging.getLogger().handlers if isinstance(h, logging.FileHandler)]
        assert file_handlers, "expected a FileHandler attached to the root logger"
        # delay=True means the file isn't opened until the first record; assert the
        # handler is wired to the target path via baseFilename instead of os.path.exists.
        assert os.path.basename(file_handlers[0].baseFilename) == os.path.basename(path)
        assert "StreamHandler" in kinds  # FileHandler subclasses StreamHandler; both present
    finally:
        if os.path.exists(path):
            os.remove(path)
        _restore_root(saved_h, saved_lvl)


def test_set_log_level_flips_root_and_named_loggers():
    saved_h, saved_lvl = _root_handlers(), logging.getLogger().level
    named = logging.getLogger("TestNamedLogger")
    saved_named_lvl = named.level
    try:
        logging.getLogger("TestNamedLogger").setLevel(logging.INFO)
        logging_setup.set_log_level(True)
        assert logging.getLogger().getEffectiveLevel() == logging.DEBUG
        assert logging.getLogger("TestNamedLogger").getEffectiveLevel() == logging.DEBUG
        logging_setup.set_log_level(False)
        assert logging.getLogger().getEffectiveLevel() == logging.INFO
        assert logging.getLogger("TestNamedLogger").getEffectiveLevel() == logging.INFO
    finally:
        named.setLevel(saved_named_lvl)
        _restore_root(saved_h, saved_lvl)


def test_configure_logging_force_reconfigures_cleanly():
    """A second call (force=True) replaces prior handlers rather than stacking."""
    saved_h, saved_lvl = _root_handlers(), logging.getLogger().level
    try:
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("LOG_LEVEL", None)
            logging_setup.configure_logging(line_buffered=False)
            n1 = len(logging.getLogger().handlers)
            logging_setup.configure_logging(line_buffered=False)
            n2 = len(logging.getLogger().handlers)
        assert n2 == n1  # no handler accumulation across force=True re-configs
    finally:
        _restore_root(saved_h, saved_lvl)


def test_quiet_uvicorn_lifecycle_filter_drops_connection_lifecycle_at_info():
    """Per-connection uvicorn lifecycle noise ('connection open'/'closed' and
    WebSocket '[accepted]') is dropped at INFO so a high-volume client-WS spoke
    can't flood the journal, but WARNING+ and DEBUG-mode records pass through."""
    saved_h, saved_lvl = _root_handlers(), logging.getLogger().level
    try:
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("LOG_LEVEL", None)
            logging_setup.configure_logging(line_buffered=False)
        f = logging_setup._QuietUvicornLifecycleFilter()

        def _rec(name, level, msg):
            r = logging.LogRecord(name=name, level=level, pathname="", lineno=0,
                                   msg=msg, args=None, exc_info=None)
            return r

        # INFO lifecycle chatter on both uvicorn loggers is dropped.
        assert f.filter(_rec("uvicorn.error", logging.INFO, "connection open")) is False
        assert f.filter(_rec("uvicorn.error", logging.INFO, "connection closed")) is False
        assert f.filter(_rec("uvicorn.access", logging.INFO,
                            '169.253.1.66:60530 - "WebSocket /ws/client?hostname=x" [accepted]')) is False
        # A real rejection (WARNING) is preserved.
        assert f.filter(_rec("uvicorn.error", logging.WARNING,
                            "connection rejected: invalid subprotocol")) is True
        # A non-lifecycle INFO line is preserved.
        assert f.filter(_rec("uvicorn.error", logging.INFO,
                            "Application startup complete")) is True

        # In DEBUG mode the lifecycle lines are revealed again.
        logging.getLogger("uvicorn.error").setLevel(logging.DEBUG)
        logging.getLogger("uvicorn.access").setLevel(logging.DEBUG)
        assert f.filter(_rec("uvicorn.error", logging.INFO, "connection open")) is True
    finally:
        _restore_root(saved_h, saved_lvl)

def test_cap_oversized_logs_truncates_only_oversized_dot_log(tmp_path):
    """The 50 MB circular-log watchdog pass truncates every *.log OVER the cap
    to zero bytes in place, leaves under-cap files and non-.log files alone,
    and returns the names it truncated. Uses a tiny cap so the test is fast."""
    big = tmp_path / "hub.log"
    big.write_bytes(b"x" * 2048)
    small = tmp_path / "agent.log"
    small.write_bytes(b"y" * 100)
    other = tmp_path / "keep.txt"
    other.write_bytes(b"z" * 4096)

    truncated = logging_setup.cap_oversized_logs(str(tmp_path), max_bytes=1024)

    assert truncated == ["hub.log"]
    assert big.stat().st_size == 0          # oversized .log truncated in place
    assert small.stat().st_size == 100      # under-cap .log untouched
    assert other.stat().st_size == 4096     # non-.log untouched even if oversized


def test_cap_oversized_logs_disabled_and_missing_dir_are_safe(tmp_path):
    """max_bytes<=0 (LM_LOG_MAX_BYTES=0 -> cap disabled) is a no-op, and a
    non-existent dir never raises (watchdog must never crash its host)."""
    f = tmp_path / "hub.log"
    f.write_bytes(b"x" * 4096)
    assert logging_setup.cap_oversized_logs(str(tmp_path), max_bytes=0) == []
    assert f.stat().st_size == 4096
    assert logging_setup.cap_oversized_logs(str(tmp_path / "nope"), max_bytes=10) == []


# ── _QuietSuccessAccessFilter / _quiet_access_paths ─────────────────────────
#
# Pins two related fixes: (1) the default quiet-access paths used to be
# "/api/health,/api/status" — neither route exists ANYWHERE in the codebase,
# so liveness-poll suppression had silently never worked; the real routes are
# the bare "/status" (routes/setup.py) and "/api/hub/health"
# (routes/net_services.py). (2) the filter now does an EXACT path match (via
# _ACCESS_LINE_RE) instead of a raw substring test, so quieting "/status"
# doesn't also swallow unrelated routes that merely contain that substring,
# e.g. "/api/le/status" or "/setup/repo-sync/status".

def _access_record(msg, levelno=logging.INFO):
    return logging.LogRecord("uvicorn.access", levelno, __file__, 1, msg, None, None)


def test_default_quiets_every_successful_request():
    """Successful access lines (e.g. `GET /setup/diagnostics 200`) are routine
    request chatter and are debug-only by default, not just the two liveness
    routes. The path-scoped mode remains available via the env var."""
    saved = os.environ.pop("LM_QUIET_ACCESS_PATHS", None)
    try:
        assert logging_setup._quiet_access_paths() == ("*",)
    finally:
        if saved is not None:
            os.environ["LM_QUIET_ACCESS_PATHS"] = saved


def test_wildcard_drops_any_successful_path():
    logging.getLogger("uvicorn.access").setLevel(logging.INFO)
    f = logging_setup._QuietSuccessAccessFilter(("*",))
    for path, code in (
        ("/setup/diagnostics", 200),
        ("/api/le/status", 200),
        ("/", 304),
        ("/static/main.js", 200),
    ):
        rec = _access_record(f'170.9.228.83:55688 - "GET {path} HTTP/1.1" {code}')
        assert f.filter(rec) is False, path


def test_wildcard_still_logs_failures():
    """4xx/5xx are real signal and must survive the broadened default."""
    logging.getLogger("uvicorn.access").setLevel(logging.INFO)
    f = logging_setup._QuietSuccessAccessFilter(("*",))
    for code in (401, 404, 500, 502):
        rec = _access_record(f'1.2.3.4:1 - "GET /setup/diagnostics HTTP/1.1" {code}')
        assert f.filter(rec) is True, code


def test_wildcard_bypassed_at_debug():
    saved = logging.getLogger("uvicorn.access").level
    try:
        logging.getLogger("uvicorn.access").setLevel(logging.DEBUG)
        f = logging_setup._QuietSuccessAccessFilter(("*",))
        rec = _access_record('1.2.3.4:1 - "GET /setup/diagnostics HTTP/1.1" 200')
        assert f.filter(rec) is True
    finally:
        logging.getLogger("uvicorn.access").setLevel(saved)


def test_explicit_path_list_does_not_enable_wildcard():
    """An operator narrowing the list back to specific paths must not get
    match-all behaviour."""
    logging.getLogger("uvicorn.access").setLevel(logging.INFO)
    f = logging_setup._QuietSuccessAccessFilter(("/status",))
    rec = _access_record('1.2.3.4:1 - "GET /setup/diagnostics HTTP/1.1" 200')
    assert f.filter(rec) is True


def test_empty_env_disables_filtering_entirely():
    with mock.patch.dict(os.environ, {"LM_QUIET_ACCESS_PATHS": ""}):
        assert logging_setup._quiet_access_paths() == ()


def test_env_override_is_comma_split_and_trimmed():
    with mock.patch.dict(os.environ, {"LM_QUIET_ACCESS_PATHS": " /foo , /bar/baz "}):
        assert logging_setup._quiet_access_paths() == ("/foo", "/bar/baz")


def test_successful_liveness_poll_is_dropped():
    logging.getLogger("uvicorn.access").setLevel(logging.INFO)
    f = logging_setup._QuietSuccessAccessFilter(("/status",))
    rec = _access_record('127.0.0.1:0 - "GET /status HTTP/1.1" 200')
    assert f.filter(rec) is False


def test_failing_liveness_poll_still_logs():
    logging.getLogger("uvicorn.access").setLevel(logging.INFO)
    f = logging_setup._QuietSuccessAccessFilter(("/status",))
    rec = _access_record('127.0.0.1:0 - "GET /status HTTP/1.1" 503')
    assert f.filter(rec) is True


def test_query_string_is_stripped_before_matching():
    logging.getLogger("uvicorn.access").setLevel(logging.INFO)
    f = logging_setup._QuietSuccessAccessFilter(("/status",))
    rec = _access_record('127.0.0.1:0 - "GET /status?foo=bar HTTP/1.1" 200')
    assert f.filter(rec) is False


def test_substring_lookalike_route_is_not_swallowed():
    """The bug this pins: a raw substring match on '/status' used to also
    silence '/api/le/status' and similar routes that merely CONTAIN the
    quieted path, even though they're a different, real endpoint."""
    logging.getLogger("uvicorn.access").setLevel(logging.INFO)
    f = logging_setup._QuietSuccessAccessFilter(("/status",))
    rec = _access_record('127.0.0.1:0 - "GET /api/le/status HTTP/1.1" 200')
    assert f.filter(rec) is True
    rec2 = _access_record('127.0.0.1:0 - "GET /setup/repo-sync/status HTTP/1.1" 200')
    assert f.filter(rec2) is True


def test_debug_level_bypasses_filter_entirely():
    saved = logging.getLogger("uvicorn.access").level
    try:
        logging.getLogger("uvicorn.access").setLevel(logging.DEBUG)
        f = logging_setup._QuietSuccessAccessFilter(("/status",))
        rec = _access_record('127.0.0.1:0 - "GET /status HTTP/1.1" 200')
        assert f.filter(rec) is True
    finally:
        logging.getLogger("uvicorn.access").setLevel(saved)


def test_non_access_log_line_is_never_dropped():
    logging.getLogger("uvicorn.access").setLevel(logging.INFO)
    f = logging_setup._QuietSuccessAccessFilter(("/status",))
    rec = _access_record("some unrelated log message with no request line")
    assert f.filter(rec) is True
