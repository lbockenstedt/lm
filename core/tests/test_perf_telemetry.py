import perf_telemetry as pt


def test_slow_routes_and_commands_are_ranked_and_report_is_built():
    t = pt.PerfTelemetry()
    t.record_route("GET", "/api/fast", 0.1)
    t.record_route("GET", "/api/netbox/racks/{rack_id}/elevation", 9.0)
    t.record_command("netbox-1", "NETBOX_GET_DEVICES", 12.0)
    t.record_command("netbox-1", "NETBOX_HEALTH", 0.2)
    snap = t.snapshot()
    assert snap["routes"][0]["key"] == "GET /api/netbox/racks/{rack_id}/elevation"
    assert snap["routes"][0]["slow"] == 1 and snap["routes"][1]["slow"] == 0
    assert snap["commands"][0]["key"] == "NETBOX_GET_DEVICES" and snap["commands"][0]["spoke"] == "netbox-1"


def test_bulk_sweeps_are_only_slow_past_the_bulk_threshold():
    """A 16 s ping sweep is normal; it was flagged as slow on every call."""
    t = pt.PerfTelemetry()
    t.record_command("nw-1", "NW_PING_SWEEP", 16.0)
    t.record_command("nw-1", "NW_PING_SWEEP", 400.0)
    t.record_command("nw-1", "NW_GET_MAC_TABLE", 16.0)
    rows = {r["key"]: r for r in t.snapshot()["commands"]}
    assert rows["NW_PING_SWEEP"]["slow"] == 1
    assert rows["NW_GET_MAC_TABLE"]["slow"] == 1


def test_scans_vm_sync_and_log_analysis_are_long_by_design():
    """A full NW scan, the NetBox VM sync and the LLM log analysis take tens of
    seconds to minutes every time; they filled the AB Health page as slow."""
    t = pt.PerfTelemetry()
    for cmd in ("NW_SCAN", "NETBOX_SYNC_VMS", "ANALYZE_LOGS"):
        t.record_command("s", cmd, 60.0)
    assert all(r["slow"] == 0 for r in t.snapshot()["commands"])


def test_build_report_tolerates_a_bare_hub():
    class Hub:
        _request_timeouts_total = 3
        _request_timeouts_by_spoke = {"s1": {"NW_POLL": 3}}

    rep = pt.build_report(Hub())
    assert rep["timeouts_total"] == 3 and rep["timeouts_by_spoke"] == {"s1": {"NW_POLL": 3}}
    assert "host" in rep and "perf" in rep


def test_spoke_queue_snapshot_collects_stats_and_skips_silent_spokes():
    """GET_HEALTH_REPORT's spoke_queues: one entry per answering spoke, by label."""
    import asyncio
    import os
    os.environ.setdefault("LM_FERNET_KEY", __import__("cryptography.fernet",
                                                      fromlist=["Fernet"]).Fernet.generate_key().decode())
    import main

    class Hub:
        active_connections = {"a": 1, "b": 1}

        def _spoke_label(self, sid):
            return "spoke-" + sid

        async def request_response(self, sid, cmd, data, timeout=None):
            if sid == "b":
                raise TimeoutError
            return {"payload": {"data": {"inflight": 4, "max_inflight": 4, "rejected_full": 9}}}

    out = asyncio.run(main.LabManagerHub._spoke_queue_snapshot(Hub()))
    assert out == {"spoke-a": {"inflight": 4, "max_inflight": 4, "rejected_full": 9}}


def test_spoke_queue_snapshot_does_not_ask_appbuilder():
    """AB has no command queue; asking it only produced a timeout per health report."""
    import asyncio
    import os
    os.environ.setdefault("LM_FERNET_KEY", __import__("cryptography.fernet",
                                                      fromlist=["Fernet"]).Fernet.generate_key().decode())
    import main

    asked = []

    class Hub:
        active_connections = {"a": 1, "ab": 1}

        def get_spoke_by_type(self, t):
            return "ab" if t == "ab" else None

        def _spoke_label(self, sid):
            return sid

        async def request_response(self, sid, cmd, data, timeout=None):
            asked.append(sid)
            return {"payload": {"data": {"inflight": 0}}}

    asyncio.run(main.LabManagerHub._spoke_queue_snapshot(Hub()))
    assert asked == ["a"]


def test_fleet_health_snapshot_summarises_netbox_and_dhcp():
    """Auto-rack problems, duplicate groups and DHCP declines reach the report."""
    import asyncio
    import os
    os.environ.setdefault("LM_FERNET_KEY", __import__("cryptography.fernet",
                                                      fromlist=["Fernet"]).Fernet.generate_key().decode())
    import main

    replies = {
        "NETBOX_AUTORACK_SWEEP": {"status": "SUCCESS", "ts": 1, "named": 5,
                                  "conflicts": [{"name": "srv-N31-R44", "reason": "slot taken"}],
                                  "cannot": []},
        "NETBOX_DEDUPE_DEVICES": {"status": "SUCCESS", "scanned": 9,
                                  "groups": [{"key": "SN1", "survivor_name": "a", "duplicate_ids": [2]}]},
        "DHCP_STATS": {"status": "SUCCESS", "subnets": [
            {"subnet": "10.0.0.0/24", "declined_addresses": 7, "total_addresses": 200},
            {"subnet": "10.0.1.0/24", "declined_addresses": 0, "total_addresses": 200}]},
    }

    class Hub:
        def get_spoke_by_type(self, t):
            return t

        async def request_response(self, sid, cmd, data, timeout=None):
            return {"payload": {"data": replies[cmd]}}

        def _stale_spoke_versions(self, now):
            return [{"spoke": "dns-1", "version": "7", "latest": "2.42", "stale_s": 4000}]

    h = Hub()
    out = asyncio.run(main.LabManagerHub._fleet_health_snapshot(h))
    assert out["stale_versions"][0]["spoke"] == "dns-1"
    assert out["autorack"]["conflicts"] == 1 and out["autorack"]["sample"][0]["name"] == "srv-N31-R44"
    assert out["netbox_duplicates"]["groups"] == 1
    assert out["dhcp_declines"] == [{"subnet": "10.0.0.0/24", "declined": 7, "total": 200}]


def test_cached_fleet_health_never_waits_for_a_slow_snapshot():
    """GET_HEALTH_REPORT must answer inside AppBuilder's 30 s even when spokes are slow."""
    import asyncio
    import os
    os.environ.setdefault("LM_FERNET_KEY", __import__("cryptography.fernet",
                                                      fromlist=["Fernet"]).Fernet.generate_key().decode())
    import main

    class Hub:
        calls = 0

        async def _fleet_health_snapshot(self):
            Hub.calls += 1
            await asyncio.sleep(0.2)
            return {"autorack": {"named": 1}}

    async def run():
        h = Hub()
        first = main.LabManagerHub._cached_fleet_health(h)
        again = main.LabManagerHub._cached_fleet_health(h)  # refresh already running
        await asyncio.sleep(0.3)
        later = main.LabManagerHub._cached_fleet_health(h)
        return first, again, later

    first, again, later = asyncio.run(run())
    assert first == {} and again == {}
    assert later == {"autorack": {"named": 1}}
    assert Hub.calls == 2  # one refresh at a time, a new one once it finished


def test_snapshot_reports_read_command_rates():
    import perf_telemetry as pt
    t = pt.PerfTelemetry()
    t.started -= 3600
    for _ in range(10):
        t.record_command("sp", "NETBOX_GET_IPS", 0.1)
    t.record_command("sp", "NETBOX_ADD_RACK", 0.1)
    snap = t.snapshot()
    assert [r["key"] for r in snap["command_rates"]] == ["NETBOX_GET_IPS"]
    assert 9 <= snap["command_rates"][0]["per_hour"] <= 11 and snap["uptime_s"] >= 3600


def _stale_hub(versions, latest="2.42"):
    """A hub with connected spokes reporting ``versions``."""
    import os
    os.environ.setdefault("LM_FERNET_KEY", __import__("cryptography.fernet",
                                                      fromlist=["Fernet"]).Fernet.generate_key().decode())
    import main
    from types import SimpleNamespace

    class Hub:
        active_connections = {k: 1 for k in versions}
        spoke_versions = dict(versions)
        spoke_module_types = {k: "dns" for k in versions}
        state = SimpleNamespace(get_module_name=lambda pk: "name-" + pk)

        def latest_version_for_module(self, module_type):
            return latest

    return main, Hub()


def test_spoke_behind_is_reported_only_after_the_stuck_period():
    """A rollout clears in minutes; a spoke still behind an hour later is stuck."""
    main, h = _stale_hub({"old": "2.40", "ok": "2.42"})
    stale = main.LabManagerHub._stale_spoke_versions
    assert stale(h, 1000.0) == []
    assert stale(h, 1000.0 + main._UPDATE_STUCK_S) == [
        {"spoke": "name-old", "version": "2.40", "latest": "2.42",
         "stale_s": int(main._UPDATE_STUCK_S)}]


def test_unreadable_version_counts_as_out_of_date():
    """The hub once stored a desired-state counter ("9") as a spoke's version."""
    main, h = _stale_hub({"dns": "9"})
    main.LabManagerHub._stale_spoke_versions(h, 0.0)
    assert main.LabManagerHub._stale_spoke_versions(h, main._UPDATE_STUCK_S)[0]["version"] == "9"


def test_spoke_that_catches_up_starts_the_clock_again():
    main, h = _stale_hub({"s": "2.40"})
    stale = main.LabManagerHub._stale_spoke_versions
    stale(h, 0.0)
    h.spoke_versions["s"] = "2.42"
    assert stale(h, 10.0) == []
    h.spoke_versions["s"] = "2.40"
    assert stale(h, main._UPDATE_STUCK_S + 20.0) == []
