"""Spoke/agent log relay + uncaught-exception relay — ``LogRelayMixin``.

Pure textual extraction from ``control_plane.py``: the SPOKE_LOG relay drain +
pre-exit flush helpers and the sync/asyncio uncaught-exception relays mixed into
``BaseControlPlane``. The relay queue + handler state stays in
``BaseControlPlane.__init__`` (``self._log_relay_queue`` / ``self._log_relay_handler``);
these methods only reference that ``self`` state, so ``BaseControlPlane`` (and
its subclasses AgentHostingControlPlane / SpokeGateway) inherit them unchanged.
No behavior change.
"""

import asyncio
import queue
import sys
import time
import uuid
import logging

logger = logging.getLogger("BaseControlPlane")


def format_asyncio_context(context) -> str:
    """Extract WHICH task/future/handle an asyncio loop exception concerns, so a
    bare ``Task was destroyed but it is pending!`` names the offending coroutine
    and its source location instead of being anonymous. Returns a ``; ``-prefixed
    suffix to append to the log message (empty string when nothing useful is
    present). ``source_traceback`` — where the task was CREATED, the single best
    clue for a "destroyed but pending" leak — is included when present (asyncio
    populates it only under debug mode; enable with LM_ASYNCIO_DEBUG=1)."""
    parts = []
    for key in ("task", "future", "handle", "protocol", "transport"):
        obj = context.get(key)
        if obj is None:
            continue
        try:
            parts.append(f"{key}={obj!r}")
        except Exception:  # noqa: BLE001 — a repr must never break logging
            parts.append(f"{key}=<unreprable {type(obj).__name__}>")
    detail = ("; " + ", ".join(parts)) if parts else ""
    src_tb = context.get("source_traceback")
    if src_tb:
        try:
            import traceback as _tb
            detail += "\n  task created at:\n" + "".join(_tb.format_list(src_tb)).rstrip()
        except Exception:  # noqa: BLE001
            pass
    return detail


class LogRelayMixin:
    """SPOKE_LOG relay + uncaught-exception relay mixed into BaseControlPlane."""

    async def _send_spoke_log(self, websocket, entries) -> None:
        """Send one signed SPOKE_LOG message carrying the given log entries."""
        msg = {
            "header": {
                "message_id": str(uuid.uuid4()),
                "timestamp": time.time(),
                "sender_id": self.spoke_id,
                "destination_id": "hub",
            },
            "payload": {"type": "SPOKE_LOG", "data": {"entries": entries}},
        }
        await websocket.send(self._encode_frame(msg))

    async def _log_relay_task(self, websocket) -> None:
        """Drain the log queue and send captured log entries to the Hub as SPOKE_LOG.

        Flushes every 5 s (not 30 s) so a short-lived spoke process — which can be
        torn down ~22 s after startup — still gets several relay windows before
        it dies, and the Hub/WebUI/BugFixer see the connect/handshake trail and
        the final log line rather than losing everything in the queue.
        """
        while True:
            await asyncio.sleep(5)
            entries = []
            try:
                while True:
                    entries.append(self._log_relay_queue.get_nowait())
            except queue.Empty:
                pass
            if not entries:
                continue
            try:
                await self._send_spoke_log(websocket, entries)
            except Exception as e:
                logger.debug("Log relay send failed: %s", e)

    def _flush_log_relay_sync(self, timeout: float = 2.0) -> None:
        """Best-effort final flush of queued log entries before a hard exit.

        Called from the updater thread (a separate thread from the event loop)
        right before ``os._exit(0)`` during a self-update restart, so the spoke's
        last lines — including the "restarting service ..." message — actually
        reach the Hub instead of dying with the queue still populated. Schedules
        the send on the captured event loop and blocks briefly for it; any
        failure (no loop, loop closed, websocket gone, timeout) is swallowed
        because the process is about to exit regardless.
        """
        entries = []
        try:
            while True:
                entries.append(self._log_relay_queue.get_nowait())
        except queue.Empty:
            pass
        if not entries:
            return
        loop = self._loop
        ws = self._hub_ws
        if loop is None or ws is None:
            return
        try:
            fut = asyncio.run_coroutine_threadsafe(self._send_spoke_log(ws, entries), loop)
            fut.result(timeout=timeout)
        except Exception as e:
            logger.debug("Pre-exit log flush failed: %s", e)

    async def _flush_log_relay_async(self, timeout: float = 2.0) -> None:
        """Best-effort final flush of queued log entries before a hard exit.

        Event-loop counterpart to ``_flush_log_relay_sync``: use this from
        command handlers (which run inside the event loop, e.g. the
        ``SPOKE_UPDATE`` handler) right before ``os._exit(0)`` during a
        self-update restart, so the spoke's final lines reach the Hub instead
        of dying with the relay queue still populated. Drains the queue and
        awaits a single SPOKE_LOG send; any failure is swallowed because the
        process is about to exit regardless.
        """
        entries = []
        try:
            while True:
                entries.append(self._log_relay_queue.get_nowait())
        except queue.Empty:
            pass
        if not entries:
            return
        ws = self._hub_ws
        if ws is None:
            return
        try:
            await asyncio.wait_for(self._send_spoke_log(ws, entries), timeout=timeout)
        except Exception as e:
            logger.debug("Pre-exit async log flush failed: %s", e)

    def _install_uncaught_exception_relay(self) -> None:
        """Route uncaught SYNC exceptions through the module logger (→ relay
        handler → hub Error Log + BugFixer) before the interpreter's default
        handler runs. The asyncio-task counterpart is set in run(). Without
        both, a genuine crash reaches only local stderr, never the hub — see
        logging-observability-contract.md req 4."""
        _prev = sys.excepthook

        def _hook(exc_type, exc, tb):
            try:
                if not issubclass(exc_type, KeyboardInterrupt):
                    logger.error("Uncaught exception", exc_info=(exc_type, exc, tb))
            finally:
                _prev(exc_type, exc, tb)

        sys.excepthook = _hook

    def _asyncio_exception_relay(self, loop, context) -> None:
        """asyncio loop exception handler — logs unhandled task exceptions via
        the module logger (→ relay → hub) then defers to the default handler for
        local reporting."""
        exc = context.get("exception")
        msg = context.get("message") or "unhandled asyncio exception"
        detail = format_asyncio_context(context)
        if exc is not None:
            logger.error("Uncaught asyncio exception: %s%s", msg, detail, exc_info=exc)
        else:
            logger.error("asyncio error: %s%s", msg, detail)
        loop.default_exception_handler(context)
