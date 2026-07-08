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