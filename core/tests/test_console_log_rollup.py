"""Console-module log roll-up to the admin Logs → Console tab.

The console module is hub-native (VNC/serial relay, credential handling, port
learn/identify) with NO spoke of its own. Before this wiring its lines only
landed in the general "Hub" log and there was no Console log tab at all. The fix
mirrors the cert-distribution (le) and CS-bridge (cs) hub-side buffers:

1. Every console source module logs under the dedicated ``"Console"`` logger
   (NOT the shared ``"Hub"`` logger) — so a single handler can scoop exactly the
   console lines without also capturing unrelated hub activity.
2. main.py attaches a ``ConsoleLogHandler`` to ``getLogger("Console")`` that
   appends formatted records to ``hub.console_logs`` (pinned INFO).
3. ``setup_admin.get_module_logs("console")`` returns ``hub.console_logs`` so
   ``GET /setup/logs/console`` (WebUI Logs → Console) shows them.

This pins pieces (1) and (2): the source modules use the ``Console`` logger and
a production-shape handler captures their INFO lines into the buffer. If a
future edit reverts a console file to ``getLogger("Hub")`` / ``__name__`` the
name assertion fails loudly — that drift is exactly what silently empties the
Console tab.
"""
import importlib
import logging
from collections import deque


CONSOLE_SOURCE_MODULES = [
    "routes.console",
    "routes.console_learn",
    "routes.console_llm_identify",
    "hub_vnc_console",
]


def test_console_source_modules_use_the_console_logger():
    # Every console source module must log under the dedicated "Console" logger
    # so the ConsoleLogHandler captures it (and only it).
    for name in CONSOLE_SOURCE_MODULES:
        mod = importlib.import_module(name)
        assert mod.logger.name == "Console", (
            f"{name}.logger must be the 'Console' logger for its lines to roll "
            f"up into Logs → Console; got '{mod.logger.name}'")


def test_console_logger_lines_land_in_the_buffer():
    # Reproduce the production wiring from main.py: a handler that appends
    # formatted records to a bounded deque, attached to getLogger("Console")
    # pinned at INFO.
    console_logs = deque(maxlen=500)

    class _ConsoleLogHandler(logging.Handler):
        def emit(self, record):
            try:
                console_logs.append(self.format(record))
            except Exception:  # noqa: BLE001
                pass

    handler = _ConsoleLogHandler()
    handler.setFormatter(logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"))
    console_log = logging.getLogger("Console")
    console_log.setLevel(logging.INFO)
    console_log.addHandler(handler)
    # Belt-and-braces: a global logging.disable() would suppress our
    # INFO/WARNING regardless of the logger level. Sibling modules now scope
    # theirs to a fixture, but clear it for the duration of this test anyway so
    # we test the wiring rather than another test's leftover global state.
    prev_disable = logging.root.manager.disable
    logging.disable(logging.NOTSET)
    try:
        # A line emitted through any console source module's own logger must be
        # captured (they all share the "Console" logger).
        con = importlib.import_module("routes.console")
        con.logger.info("console: relay opened for session abc123")
        con.logger.warning("console ws xyz relay failed: boom")

        assert any("relay opened for session abc123" in l for l in console_logs)
        assert any("relay failed: boom" in l for l in console_logs)
        # Canonical shape (asctime - name - level - message), same as the other
        # hub-side buffers so the Logs view renders console lines uniformly.
        assert any(" - Console - INFO - " in l for l in console_logs)

        # The get_module_logs("console") contract is a simple tail slice.
        assert list(console_logs)[-500:] == list(console_logs)
    finally:
        console_log.removeHandler(handler)
        logging.disable(prev_disable)
