"""Fleet-wide "clear USB quarantine / exclusions" fan-out
(``POST /sim/api/{tenant}/proxmx/command`` with ``all_spokes``).

Clearing the quarantine / exclusion list is idempotent and self-repairing, so
unreachable spokes are QUEUED for delivery on reconnect instead of failing the
whole request with a 502. The fan-out is concurrent (N dead spokes cost one
timeout, not N) and messages name spokes via ``hub._spoke_label``. The
destructive ``clear_usb_history`` must never be queued.
"""

import asyncio
import time
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

from simulations.routes import register_simulations_routes

SIM_VIEWS_JS = Path(__file__).resolve().parents[2] / "WebUI" / "sim-views.js"

TIMEOUT = {"status": "ERROR", "message": "Timed out waiting for spoke response"}


class _Hub:
    """Fake hub with N cs spokes. ``live`` / ``queue`` map spoke id -> async
    behaviour: return a reply dict, or raise."""

    def __init__(self, n=5, live=None, queue=None, delay=0.0, labels=False):
        self.spokes = [f"spoke-{i}-aaaa" for i in range(n)]
        self.simulations_cache = {}
        # register_simulations_routes reads this at app-build time.
        self.simulations_store = type("_Store", (), {"__getattr__": lambda s, n: (lambda *a, **k: None)})()
        self._live = live or (lambda sid: {"status": "SUCCESS"})
        self._queue = queue or (lambda sid: {"status": "ok", "queued": True,
                                             "message": "queued"})
        self._delay = delay
        self.live_calls = []
        self.queue_calls = []
        if labels:
            self._spoke_label = lambda sid: f"cs-svr-05 ({sid[:8]})"

    def get_client_sim_spokes(self, tenant_id):
        return list(self.spokes)

    async def request_response(self, sid, cmd_type, payload, timeout=8.0):
        self.live_calls.append(sid)
        await asyncio.sleep(self._delay)
        r = self._live(sid)
        if isinstance(r, Exception):
            raise r
        return r

    async def push_or_queue_to_spoke(self, sid, cmd_type, payload, timeout=None):
        self.queue_calls.append(sid)
        await asyncio.sleep(self._delay)
        r = self._queue(sid)
        if isinstance(r, Exception):
            raise r
        return r


def _client(hub):
    app = FastAPI()
    register_simulations_routes(
        app, hub,
        session_user_fn=lambda req: None,
        resolve_tenant_fn=lambda req: None,
        is_admin_fn=lambda u: True,
        check_tenant_access_fn=None,
        sessions=None,
        has_cs_access_fn=lambda u: True,
    )
    return TestClient(app)


def _post(hub, action="clear_usb_quarantine"):
    return _client(hub).post(
        "/sim/api/10/proxmx/command?tenant_id=10",
        json={"action": action, "all_spokes": True})


def test_fan_out_is_concurrent():
    hub = _Hub(n=5, delay=0.2)
    t0 = time.monotonic()
    r = _post(hub, "clear_usb_history")
    elapsed = time.monotonic() - t0
    assert r.status_code == 200
    assert r.json()["pushed_to_spokes"] == 5
    assert elapsed < 0.6, elapsed


def test_quarantine_all_timeouts_are_queued_not_502():
    # Live path times out on every spoke; push_or_queue falls back to the queue.
    hub = _Hub(n=5, live=lambda sid: TIMEOUT, delay=0.05)
    r = _post(hub, "clear_usb_quarantine")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "SUCCESS"
    assert body["queued_to_spokes"] == 5
    assert body["pushed_to_spokes"] == 0
    assert body["spokes_total"] == 5
    assert len(body["queued"]) == 5
    assert body["errors"] == [] and body["refusals"] == []


def test_exclusions_also_queueable():
    hub = _Hub(n=2)
    body = _post(hub, "clear_usb_exclusions").json()
    assert body["queued_to_spokes"] == 2
    assert hub.live_calls == []


def test_mixed_live_and_queued():
    live_ids = {"spoke-0-aaaa", "spoke-1-aaaa"}
    hub = _Hub(
        n=5, labels=True,
        queue=lambda sid: ({"status": "ok", "queued": False,
                            "result": {"payload": {"data": {"status": "SUCCESS"}}}}
                           if sid in live_ids else
                           {"status": "ok", "queued": True, "message": "queued"}))
    body = _post(hub).json()
    assert body["pushed_to_spokes"] == 2
    assert body["queued_to_spokes"] == 3
    assert body["spokes_total"] == 5
    assert len(body["queued"]) == 3
    assert all(q.startswith("cs-svr-05 (") for q in body["queued"])


def test_refusal_is_not_queued():
    hub = _Hub(
        n=3,
        queue=lambda sid: (
            {"status": "ok", "queued": False,
             "result": {"status": "ERROR", "message": "protected vmid"}}
            if sid == "spoke-0-aaaa" else
            {"status": "ok", "queued": True, "message": "queued"}))
    body = _post(hub).json()
    assert body["queued_to_spokes"] == 2
    assert body["pushed_to_spokes"] == 0
    assert len(body["refusals"]) == 1 and "protected vmid" in body["refusals"][0]


def test_all_refusals_is_502_with_text():
    hub = _Hub(n=3, queue=lambda sid: {
        "status": "ok", "queued": False,
        "result": {"status": "ERROR", "message": "protected vmid"}})
    r = _post(hub)
    assert r.status_code == 502
    assert r.json()["detail"].count("protected vmid") == 3


def test_history_clear_is_never_queued():
    hub = _Hub(n=5, live=lambda sid: TIMEOUT)
    r = _post(hub, "clear_usb_history")
    assert r.status_code == 502
    assert "Timed out waiting for spoke response" in r.json()["detail"]
    assert hub.queue_calls == []


def test_live_exception_on_non_queueable_is_error_entry():
    hub = _Hub(n=2, live=lambda sid: ConnectionError("down")
               if sid == "spoke-0-aaaa" else {"status": "SUCCESS"})
    body = _post(hub, "clear_usb_history").json()
    assert body["pushed_to_spokes"] == 1
    assert body["errors"] == ["spoke-0-aaaa: down"]


def test_messages_use_spoke_labels():
    hub = _Hub(n=2, live=lambda sid: TIMEOUT, labels=True)
    r = _post(hub, "clear_usb_history")
    assert r.status_code == 502
    assert "cs-svr-05 (spoke-0-): Timed out waiting for spoke response" in r.json()["detail"]


def test_messages_fall_back_to_raw_id_without_label_helper():
    hub = _Hub(n=2, live=lambda sid: TIMEOUT)
    assert not hasattr(hub, "_spoke_label")
    r = _post(hub, "clear_usb_history")
    assert "spoke-0-aaaa: Timed out waiting for spoke response" in r.json()["detail"]


def test_label_helper_failure_falls_back_to_raw_id():
    hub = _Hub(n=1, live=lambda sid: TIMEOUT)

    def boom(sid):
        raise RuntimeError("no metadata")
    hub._spoke_label = boom
    r = _post(hub, "clear_usb_history")
    assert "spoke-0-aaaa: Timed out" in r.json()["detail"]


def test_ui_handles_queued_to_spokes():
    js = SIM_VIEWS_JS.read_text(encoding="utf-8")
    start = js.index("async function _csUsbClearCmd(")
    fn = js[start:js.index("window.csClearUsbHistory", start)]
    assert "queued_to_spokes" in fn
    assert "'warning'" in fn
