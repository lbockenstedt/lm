"""``/admin/ops/spoke-logs`` — tail a spoke's relayed SPOKE_LOG buffer."""
import asyncio
import os
import tempfile
from collections import deque

from routes import admin_ops

from test_admin_ops_guard import _FakeApp, _FakeRequest, _State


class _Hub:
    def __init__(self, data_dir):
        self.state = _State(data_dir)
        self.active_connections = {}
        self.agent_logs = {"sid-1": deque([
            "t - TruenasClient - ERROR - truenas connect 10.0.0.5 failed: x",
            "t - TruenasSpoke - INFO - Handling Truenas Command: TRUENAS_POLL",
            "t - BaseControlPlane - INFO - heartbeat",
        ])}

    def _primary_key(self, spoke_id):
        return {"name-1": "sid-1"}.get(spoke_id, spoke_id)


def _run(body):
    with tempfile.TemporaryDirectory() as tmp:
        app = _FakeApp()
        admin_ops.register(app, _Hub(tmp), ctx=None)
        tok = open(os.path.join(tmp, "admin_ops_token")).read().strip()
        req = _FakeRequest("127.0.0.1", tok)
        req.url = type("U", (), {"path": "/admin/ops/spoke-logs"})()

        async def _json():
            return body
        req.json = _json
        route = app.routes[("POST", "/admin/ops/spoke-logs")]
        return asyncio.new_event_loop().run_until_complete(route(req))


def test_filters_by_name_alias_and_text():
    out = _run({"target": "name-1", "contains": "TRUENAS"})
    assert out["count"] == 2
    assert all("Truenas" in line for line in out["lines"])


def test_lines_caps_to_most_recent():
    out = _run({"target": "sid-1", "lines": 1})
    assert out["lines"] == ["t - BaseControlPlane - INFO - heartbeat"]


def test_spoke_memory_report_names_the_large_containers():
    # There was no way to see what a spoke process holds (LM-AGENT grew
    # ~190 MB in 30 min and was OOM-killed). The report lists top types and
    # the largest containers with sample keys so the owning cache is visible.
    from messaging.control_plane import memory_report

    class Engine:
        pass
    eng = Engine()
    # A str->int dict is not gc-tracked; it is found through its owner.
    eng.cache = {f"device-{i}": i for i in range(5000)}
    rep = memory_report()
    assert rep["gc_tracked"] > 0 and rep["by_count"] and rep["by_bytes"]
    hit = [c for c in rep["largest_containers"] if c["len"] == 5000 and c["type"] == "dict"]
    assert hit and hit[0]["sample"][0] == "'device-0'"
    del eng
