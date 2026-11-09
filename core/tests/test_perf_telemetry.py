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
