"""Heartbeat thread — loop-independent 30s cadence + stall detection.

The heartbeat moved from an asyncio.create_task (shared loop → starved by any
loop-blocking sync-I/O in a command handler) to a dedicated OS thread with its
own time.sleep clock. These tests pin: (1) it sends a HEARTBEAT frame via the
loop, (2) a send that doesn't complete within HEARTBEAT_SEND_DEADLINE_S logs an
explicit 'event loop stalled' warning and the thread survives, (3) the stop
event exits the thread, (4) a closed connection exits the thread cleanly.
"""
import asyncio
import logging
import threading
import time

import pytest
import websockets

from core.src.messaging.control_plane import BaseControlPlane


class _FakeSelf:
    """Just the attributes _heartbeat_thread_target touches."""
    def __init__(self, deadline=5.0):
        self.spoke_id = "s1"
        self.HEARTBEAT_SEND_DEADLINE_S = deadline
        self.encoded = []
    def _encode_frame(self, msg):
        self.encoded.append(msg)
        return "HEARTBEAT-FRAME"


class _FakeWS:
    def __init__(self, behavior="ok"):
        self.sent = []
        self._behavior = behavior
    async def send(self, frame):
        if self._behavior == "ok":
            self.sent.append(frame)
        elif self._behavior == "stall":
            await asyncio.sleep(10)  # well past the deadline
        elif self._behavior == "closed":
            # ConnectionClosed.__init__ asserts on its args; build via __new__ to
            # get a catchable instance without exercising the constructor.
            exc = websockets.exceptions.ConnectionClosed.__new__(
                websockets.exceptions.ConnectionClosed)
            raise exc


class _LoopRunner:
    """Run an asyncio loop in a dedicated thread for run_coroutine_threadsafe."""
    def __init__(self):
        self.loop = asyncio.new_event_loop()
        self._t = threading.Thread(target=self.loop.run_forever, daemon=True)
        self._t.start()
    def stop(self):
        self.loop.call_soon_threadsafe(self.loop.stop)
        self._t.join(timeout=2.0)


def _run_target(fake_self, ws, deadline_send=0.4, tick=30.0):
    """Run the heartbeat target briefly in a thread; return (thread, stop, loop)."""
    runner = _LoopRunner()
    stop = threading.Event()
    t = threading.Thread(
        target=BaseControlPlane._heartbeat_thread_target,
        args=(fake_self, ws, runner.loop, stop),
        daemon=True)
    t.start()
    return t, stop, runner


def test_heartbeat_thread_sends_a_frame():
    fs = _FakeSelf()
    ws = _FakeWS("ok")
    t, stop, runner = _run_target(fs, ws)
    try:
        # Wait for the immediate first send (the loop processes it quickly).
        deadline = time.time() + 2.0
        while not ws.sent and time.time() < deadline:
            time.sleep(0.02)
        assert ws.sent == ["HEARTBEAT-FRAME"]
        assert fs.encoded and fs.encoded[0]["payload"]["type"] == "HEARTBEAT"
    finally:
        stop.set()
        t.join(timeout=2.0)
        runner.stop()
    assert not t.is_alive()


def test_heartbeat_thread_logs_stall_warning_when_send_overdue(caplog):
    fs = _FakeSelf(deadline=0.3)
    ws = _FakeWS("stall")  # send blocks 10s >> 0.3s deadline
    t, stop, runner = _run_target(fs, ws)
    try:
        with caplog.at_level(logging.WARNING, logger="BaseControlPlane"):
            # Wait for the stall warning to fire (deadline 0.3s + slack).
            deadline = time.time() + 2.0
            while not any("stalled" in r.message.lower() for r in caplog.records) \
                    and time.time() < deadline:
                time.sleep(0.02)
        assert any("stalled" in r.message.lower() for r in caplog.records)
        # The thread survives the stall (didn't return) — it's still alive,
        # blocked in stop_event.wait(30) after the stall log.
        assert t.is_alive()
    finally:
        stop.set()
        t.join(timeout=2.0)
        runner.stop()


def test_heartbeat_thread_exits_on_stop_event():
    fs = _FakeSelf()
    ws = _FakeWS("ok")
    runner = _LoopRunner()
    stop = threading.Event()
    stop.set()  # pre-set: the target should exit immediately (no send)
    t = threading.Thread(
        target=BaseControlPlane._heartbeat_thread_target,
        args=(fs, ws, runner.loop, stop), daemon=True)
    t.start()
    t.join(timeout=2.0)
    runner.stop()
    assert not t.is_alive()
    assert ws.sent == []  # never got past the is_set() guard


def test_heartbeat_thread_exits_on_closed_connection():
    fs = _FakeSelf()
    ws = _FakeWS("closed")
    t, stop, runner = _run_target(fs, ws)
    try:
        t.join(timeout=2.0)
    finally:
        stop.set()
        t.join(timeout=2.0)
        runner.stop()
    assert not t.is_alive()  # returned cleanly on ConnectionClosed