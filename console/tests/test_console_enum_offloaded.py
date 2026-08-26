"""Regression: serial-port enumeration must never block the spoke's asyncio
event loop.

pyserial's ``comports()`` is a blocking call, and on a host with a wedged
USB-serial adapter it can stall for many seconds. Earlier, CONSOLE_LIST_PORTS
(and the background scan loops) called ``enumerate_ports()`` directly on the
event loop, so one hung bus froze the whole spoke — heartbeats and every other
CONSOLE_* command stalled, and CONSOLE_LIST_PORTS blew past the hub's 15s
timeout. Enumeration is now offloaded to a worker thread, so a slow bus can
delay the listing but can never freeze the loop.
"""
import asyncio
import sys
import time
import types
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(_SRC))

_bs = types.ModuleType("base_spoke")


class _BaseSpoke:
    def __init__(self, spoke_id, config):
        self.spoke_id = spoke_id
        self.config = config


_bs.BaseSpoke = _BaseSpoke
sys.modules.setdefault("base_spoke", _bs)

import serial_manager as sm  # noqa: E402
import console_spoke as cs  # noqa: E402
from test_serial_manager import _FakeSerial  # noqa: E402


def _make_spoke(monkeypatch, tmp_path):
    monkeypatch.setattr(sm, "serial", _FakeSerial)
    sp = cs.ConsoleSpoke("console-1", {"console_monitor": False, "auto_identify": False})
    sp.store = sm.PortStore(path=tmp_path / "ports.json")
    sp._monitor_task = object()
    sp._autoprobe_task = object()
    return sp


def test_slow_enumeration_does_not_block_the_event_loop(monkeypatch, tmp_path):
    """A ~0.4s blocking enumeration must run OFF the loop: while CONSOLE_LIST_PORTS
    is in flight, other coroutines on the same loop keep making progress."""
    spoke = _make_spoke(monkeypatch, tmp_path)

    def _slow_enumerate():
        time.sleep(0.4)  # simulate a stalling comports()
        return [{"port_id": "p1", "device": "/dev/ttyUSB0", "product": "FTDI"}]

    monkeypatch.setattr(cs, "enumerate_ports", _slow_enumerate)

    async def _scenario():
        ticks = 0

        async def _heartbeat():
            nonlocal ticks
            # If enumeration blocked the loop, these sleeps couldn't advance while
            # the list command runs.
            for _ in range(20):
                await asyncio.sleep(0.02)
                ticks += 1

        hb = asyncio.create_task(_heartbeat())
        res = await spoke.handle_command("CONSOLE_LIST_PORTS", {})
        await hb
        return res, ticks

    res, ticks = asyncio.run(_scenario())
    assert res["status"] == "SUCCESS"
    assert {p["port_id"] for p in res["ports"]} == {"p1"}
    # The heartbeat kept ticking during the blocking enumeration → loop stayed live.
    assert ticks >= 10


def test_list_ports_reflects_a_fresh_enumeration(monkeypatch, tmp_path):
    """Each CONSOLE_LIST_PORTS re-enumerates (no stale caching hiding a change)."""
    spoke = _make_spoke(monkeypatch, tmp_path)

    monkeypatch.setattr(cs, "enumerate_ports",
                        lambda: [{"port_id": "p1", "device": "/dev/ttyUSB0"}])
    r1 = asyncio.run(spoke.handle_command("CONSOLE_LIST_PORTS", {}))
    assert {p["port_id"] for p in r1["ports"]} == {"p1"}

    # Device unplugged → next listing must drop it immediately.
    monkeypatch.setattr(cs, "enumerate_ports", lambda: [])
    r2 = asyncio.run(spoke.handle_command("CONSOLE_LIST_PORTS", {}))
    assert r2["ports"] == []
