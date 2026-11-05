"""Spoke/agent log relay + uncaught-exception relay — ``LogRelayMixin``.

Pure textual extraction from ``control_plane.py``: the SPOKE_LOG relay drain +
pre-exit flush helpers and the sync/asyncio uncaught-exception relays mixed into
``BaseControlPlane``. The relay queue + handler state stays in
``BaseControlPlane.__init__`` (``self._log_relay_queue`` / ``self._log_relay_handler``);
these methods only reference that ``self`` state, so ``BaseControlPlane`` (and
its subclass AgentHostingControlPlane) inherit them unchanged.
No behavior change.
"""

# asyncio: sleeping between relay flushes and scheduling sends on the event loop.
import asyncio
# queue.Empty signals that the thread-safe log queue has been fully drained.
import queue
# sys.excepthook is wrapped to relay uncaught synchronous exceptions.
import sys
# time/uuid stamp and uniquely identify each SPOKE_LOG envelope.
import time
import uuid
# Standard-library logging for this module's own diagnostics.
import logging

# Reuse the control plane's logger name so these messages group with its output.
logger = logging.getLogger("BaseControlPlane")


def format_asyncio_context(context) -> str:
    """Extract WHICH task/future/handle an asyncio loop exception concerns, so a
    bare ``Task was destroyed but it is pending!`` names the offending coroutine
    and its source location instead of being anonymous. Returns a ``; ``-prefixed
    suffix to append to the log message (empty string when nothing useful is
    present). ``source_traceback`` — where the task was CREATED, the single best
    clue for a "destroyed but pending" leak — is included when present (asyncio
    populates it only under debug mode; enable with LM_ASYNCIO_DEBUG=1)."""
    # Collect "key=repr" fragments for every object asyncio attached to the error context.
    parts = []
    # These are the context keys asyncio may populate to identify the failing object.
    for key in ("task", "future", "handle", "protocol", "transport"):
        # Skip keys asyncio did not supply for this particular error.
        obj = context.get(key)
        if obj is None:
            continue
        # repr() of a broken object can itself raise; fall back to just its type name.
        try:
            parts.append(f"{key}={obj!r}")
        except Exception:  # noqa: BLE001 — a repr must never break logging
            parts.append(f"{key}=<unreprable {type(obj).__name__}>")
    # Join the fragments into a "; "-prefixed suffix, or nothing if none were found.
    detail = ("; " + ", ".join(parts)) if parts else ""
    # Where the task was created (only present when asyncio debug mode is on).
    src_tb = context.get("source_traceback")
    if src_tb:
        # Append the creation stack; a formatting failure must never break the error log.
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
        # Build the standard hub envelope: header with a fresh id/time plus the SPOKE_LOG payload.
        msg = {
            "header": {
                "message_id": str(uuid.uuid4()),
                "timestamp": time.time(),
                "sender_id": self.spoke_id,
                "destination_id": "hub",
            },
            "payload": {"type": "SPOKE_LOG", "data": {"entries": entries}},
        }
        # Encode (and sign) the frame using the control plane's codec, then send it.
        await websocket.send(self._encode_frame(msg))

    async def _log_relay_task(self, websocket) -> None:
        """Drain the log queue and send captured log entries to the Hub as SPOKE_LOG.

        Flushes every 5 s (not 30 s) so a short-lived spoke process — which can be
        torn down ~22 s after startup — still gets several relay windows before
        it dies, and the Hub/WebUI/AppBuilder see the connect/handshake trail and
        the final log line rather than losing everything in the queue.
        """
        # Loop forever for the lifetime of the hub connection.
        while True:
            # Wait between flushes so log lines are batched instead of sent one per frame.
            await asyncio.sleep(5)
            # Pull every queued entry without blocking until the queue reports empty.
            entries = []
            try:
                while True:
                    entries.append(self._log_relay_queue.get_nowait())
            except queue.Empty:
                pass
            # Nothing logged since the last flush: skip sending an empty message.
            if not entries:
                continue
            # A failed send is only logged at debug level (logging it louder would loop back into
            # the relay itself); the entries are dropped and the next window continues.
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
        # Drain everything currently queued, without blocking.
        entries = []
        try:
            while True:
                entries.append(self._log_relay_queue.get_nowait())
        except queue.Empty:
            pass
        # Nothing to send, so nothing to flush.
        if not entries:
            return
        # The event loop and hub websocket captured when the connection was set up.
        loop = self._loop
        ws = self._hub_ws
        # Without a running loop or a live connection there is no way to send; give up quietly.
        if loop is None or ws is None:
            return
        # Schedule the send on the loop from this (non-loop) thread and wait a bounded time.
        try:
            fut = asyncio.run_coroutine_threadsafe(self._send_spoke_log(ws, entries), loop)
            fut.result(timeout=timeout)
        # Swallow every failure: the process is about to exit regardless.
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
        # Drain everything currently queued, without blocking.
        entries = []
        try:
            while True:
                entries.append(self._log_relay_queue.get_nowait())
        except queue.Empty:
            pass
        # Nothing to send, so nothing to flush.
        if not entries:
            return
        # No live hub connection means nowhere to send the entries.
        ws = self._hub_ws
        if ws is None:
            return
        # Await one SPOKE_LOG send, but never block shutdown longer than the timeout.
        try:
            await asyncio.wait_for(self._send_spoke_log(ws, entries), timeout=timeout)
        # Swallow every failure: the process is about to exit regardless.
        except Exception as e:
            logger.debug("Pre-exit async log flush failed: %s", e)

    def _install_uncaught_exception_relay(self) -> None:
        """Route uncaught SYNC exceptions through the module logger (→ relay
        handler → hub Error Log + AppBuilder) before the interpreter's default
        handler runs. The asyncio-task counterpart is set in run(). Without
        both, a genuine crash reaches only local stderr, never the hub — see
        logging-observability-contract.md req 4."""
        # Remember the previous hook so normal stderr reporting still happens afterwards.
        _prev = sys.excepthook

        def _hook(exc_type, exc, tb):
            """Log an uncaught exception through the relay, then hand it to the previous hook."""
            # Ctrl-C is a normal shutdown, not a crash, so it is not reported as an error.
            try:
                if not issubclass(exc_type, KeyboardInterrupt):
                    logger.error("Uncaught exception", exc_info=(exc_type, exc, tb))
            # Always chain to the original hook, even if logging itself failed.
            finally:
                _prev(exc_type, exc, tb)

        # Install the wrapper as the interpreter-wide uncaught-exception hook.
        sys.excepthook = _hook

    def _asyncio_exception_relay(self, loop, context) -> None:
        """asyncio loop exception handler — logs unhandled task exceptions via
        the module logger (→ relay → hub) then defers to the default handler for
        local reporting."""
        # Pull the exception (if any) and the human-readable message out of the context.
        exc = context.get("exception")
        msg = context.get("message") or "unhandled asyncio exception"
        # Describe which task/future the error concerns.
        detail = format_asyncio_context(context)
        # Include the traceback when there is a real exception object; otherwise log the message.
        if exc is not None:
            logger.error("Uncaught asyncio exception: %s%s", msg, detail, exc_info=exc)
        else:
            logger.error("asyncio error: %s%s", msg, detail)
        # Let asyncio's default handler also report it locally.
        loop.default_exception_handler(context)
