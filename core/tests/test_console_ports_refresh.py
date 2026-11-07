"""Unit tests for the hub-side console-ports warm-cache refresh engine
(``HubVncConsoleMixin.refresh_console_ports_cache`` / ``run_console_ports_refresh_loop``).

The background loop is what lets ``/api/console/ports`` serve from RAM instead of
live-polling each console spoke per request. These lock in:

* a successful poll stores the unwrapped raw ``ports`` list under the spoke_id;
* a wedged/offline spoke is skipped so its last-known snapshot survives (the
  sweep never blows away a good cache with an error);
* the envelope-unwrap matches the route's (payload.data.ports).
"""

import asyncio

from hub_vnc_console import HubVncConsoleMixin


class _Hub(HubVncConsoleMixin):
    def __init__(self, ports_by_spoke=None, connected=None, fail=None):
        self._ports = ports_by_spoke or {}
        self._connected = list(connected or [])
        self._fail = set(fail or [])
        self.warm_cache = {}

    def get_all_spokes_by_type(self, kind):
        return list(self._connected) if kind == "console" else []

    async def warm_set(self, namespace, key, data):
        self.warm_cache.setdefault(namespace, {})[str(key)] = {"data": data}

    def warm_get(self, namespace, key="_"):
        entry = self.warm_cache.get(namespace, {}).get(str(key))
        return entry.get("data") if isinstance(entry, dict) else None

    async def request_response(self, sid, cmd, payload, timeout=15.0,
                               signing_secret=None):
        if sid in self._fail:
            raise RuntimeError(f"{sid} unreachable")
        return {"payload": {"data": {"status": "SUCCESS",
                                     "ports": self._ports.get(sid, [])}}}


def test_refresh_stores_unwrapped_ports_for_all_connected():
    hub = _Hub(connected=["con-1", "con-2"],
               ports_by_spoke={"con-1": [{"port_id": "ttyUSB0"}], "con-2": []})
    refreshed = asyncio.get_event_loop().run_until_complete(
        hub.refresh_console_ports_cache())
    assert refreshed == {"con-1", "con-2"}
    assert hub.warm_get("console_ports", "con-1") == [{"port_id": "ttyUSB0"}]
    assert hub.warm_get("console_ports", "con-2") == []


def test_refresh_skips_wedged_spoke_and_keeps_snapshot():
    hub = _Hub(connected=["con-1"], fail=["con-1"])
    hub.warm_cache["console_ports"] = {"con-1": {"data": [{"port_id": "keep"}]}}
    refreshed = asyncio.get_event_loop().run_until_complete(
        hub.refresh_console_ports_cache())
    assert refreshed == set()
    # last-known snapshot untouched — a failed poll must not blank the cache
    assert hub.warm_get("console_ports", "con-1") == [{"port_id": "keep"}]


def test_unwrap_ports_matches_route_envelope():
    assert HubVncConsoleMixin._console_unwrap_ports(
        {"payload": {"data": {"ports": [1, 2]}}}) == [1, 2]
    assert HubVncConsoleMixin._console_unwrap_ports({"ports": [3]}) == [3]
    assert HubVncConsoleMixin._console_unwrap_ports(None) == []
    assert HubVncConsoleMixin._console_unwrap_ports({"payload": {"data": {}}}) == []


def test_sweep_backs_off_a_spoke_that_keeps_failing_and_recovers():
    hub = _Hub(connected=["con-1", "con-2"], fail=["con-1"])
    polled = []
    real = hub.request_response

    async def spy(sid, *a, **kw):
        polled.append(sid)
        return await real(sid, *a, **kw)
    hub.request_response = spy
    run = asyncio.get_event_loop().run_until_complete
    run(hub.refresh_console_ports_cache())
    run(hub.refresh_console_ports_cache())
    # con-1 failed once so the next sweep skips it; con-2 is polled every time.
    assert polled == ["con-1", "con-2", "con-2"]
    # An explicit refresh ignores the backoff, and success clears it.
    hub._fail.clear()
    run(hub.refresh_console_ports_cache(["con-1"]))
    assert "con-1" not in hub._console_ports_backoff
