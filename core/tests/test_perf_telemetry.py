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

    h = Hub()
    out = asyncio.run(main.LabManagerHub._fleet_health_snapshot(h))
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
