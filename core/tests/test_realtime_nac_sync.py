"""Critical path — Realtime NAC → IPAM reverse sync (the bidirectional
counterpart to ``test_fw_discovery_sync.py``).

``test_realtime_nac_sync.py`` locks in the recent-sessions pull + MAC
normalization (MAC-less drop), the prefix-containment attribution (shared with
fw-discovery via ``access.attribute_by_prefix``) + drop+count of unattributed
IPs, the per-tenant push payload (``replace=False`` only-add-missing +
``defaults`` forwarded + tenant slug from the tenant cfg), the unbound-tenant
skip + NetBox-offline error, the [sync-error] marker on per-record errors, and
the disabled-loop no-op — using a FakeHub whose ``request_response`` returns
canned CPPM_GET_RECENT_SESSIONS + NETBOX_GET_PREFIXES / NETBOX_SYNC_ACCESS_TRACKER
payloads. Mirrors ``test_fw_discovery_sync.py``.
"""

import asyncio
import logging

import pytest

import realtime_ipam_nac_sync as rt
from realtime_ipam_nac_sync import RealtimeIpamNacSyncMixin
from _fakes import FakeState


# ── config helpers ───────────────────────────────────────────────────────────

def test_cfg_key_and_modules_are_fixed():
    assert RealtimeIpamNacSyncMixin._REALTIME_NAC_CFG_KEY == "realtime_ipam_nac_sync"
    assert RealtimeIpamNacSyncMixin._RT_NAC_SOURCE_MODULE == "nac"
    assert RealtimeIpamNacSyncMixin._RT_NAC_SINK_MODULE == "ipam"
    assert RealtimeIpamNacSyncMixin._RT_NAC_PULL_COMMAND == "CPPM_GET_RECENT_SESSIONS"
    assert RealtimeIpamNacSyncMixin._RT_NAC_PUSH_COMMAND == "NETBOX_SYNC_ACCESS_TRACKER"


def test_lookback_clamps():
    m = RealtimeIpamNacSyncMixin()
    m.state = FakeState(system_state={"global_config":
        {"realtime_ipam_nac_sync": {"lookback_minutes": 999}}})
    assert m._rt_nac_lookback() == 60
    m.state = FakeState(system_state={"global_config":
        {"realtime_ipam_nac_sync": {"lookback_minutes": 0}}})
    assert m._rt_nac_lookback() == 1
    m.state = FakeState(system_state={"global_config": {}})
    assert m._rt_nac_lookback() == 2  # default


def test_interval_clamps_to_60_floor():
    m = RealtimeIpamNacSyncMixin()
    m.state = FakeState(system_state={"global_config":
        {"realtime_ipam_nac_sync": {"interval_seconds": 10}}})
    assert m._rt_nac_interval() == 60.0   # can't hot-loop the hub
    m.state = FakeState(system_state={"global_config": {}})
    assert m._rt_nac_interval() == 60.0   # default


def test_norm_mac_canonicalizes_and_drops_unknown():
    assert RealtimeIpamNacSyncMixin._rt_norm_mac("AA-BB-CC-DD-EE-05") == "aa:bb:cc:dd:ee:05"
    assert RealtimeIpamNacSyncMixin._rt_norm_mac("aabbccddeeff") == "aa:bb:cc:dd:ee:ff"
    assert RealtimeIpamNacSyncMixin._rt_norm_mac("") == ""
    assert RealtimeIpamNacSyncMixin._rt_norm_mac("unknown") == ""


# ── canned-relay hub (async) ─────────────────────────────────────────────────

class _FakeSimulationsStore:
    def __init__(self):
        self.recorded = {}

    async def set_realtime_nac_sync_status(self, tenant_id, status):
        self.recorded[tenant_id] = status


class _RtHub(RealtimeIpamNacSyncMixin):
    """Minimal hub stand-in: canned request_response + NAC/IPAM spoke routing.
    The real ``access.attribute_by_prefix`` → ``fetch_tenant_prefixes`` runs
    through this (it only needs hub.get_spoke_by_type('ipam') + get_tenant_scoping,
    both faked via FakeState)."""

    def __init__(self, responses=None, tenants=None, global_config=None,
                 nac_spoke="cppm-1", ipam_spoke="netbox-1"):
        self.state = FakeState(
            system_state={"global_config": global_config or {}},
            tenants=tenants or {"acme": {"name": "Acme", "netbox_tenant_slug": "acme"}},
        )
        self.simulations_store = _FakeSimulationsStore()
        self._responses = responses or {}
        self._nac = nac_spoke
        self._ipam = ipam_spoke
        self.request_log = []

    def get_spoke_by_type(self, module_type):
        if module_type == "nac":
            return self._nac
        if module_type == "ipam":
            return self._ipam
        return None

    async def request_response(self, spoke_id, command, payload, timeout=30.0):
        self.request_log.append((spoke_id, command, payload))
        return self._responses[(spoke_id, command)]


def _sessions_payload():
    return {"payload": {"data": {"status": "SUCCESS", "total": 3,
        "window_start": "2026-06-30T10:00:00Z", "window_end": "2026-06-30T10:02:00Z",
        "sessions": [
            # in 10.20.0.0/24 (acme) — normalized mac
            {"mac": "AA-BB-CC-DD-EE-05", "ip": "10.20.0.5", "nas_ip": "10.20.0.1",
             "nas_name": "sw-core", "nas_port": "Ethernet1/0/12", "username": "alice",
             "start_time": "2026-06-30T10:00:30"},
            # MAC-less → dropped hub-side (nothing to match/create by)
            {"mac": "", "ip": "10.20.0.6", "nas_ip": "10.20.0.1",
             "username": "bob", "start_time": "2026-06-30T10:00:45"},
            # unattributed: no tenant prefix contains 10.30.0.99 → dropped + counted
            {"mac": "aa:bb:cc:dd:ee:99", "ip": "10.30.0.99", "nas_ip": "10.30.0.1",
             "username": "carol", "start_time": "2026-06-30T10:00:50"},
        ]}}}


def _prefixes_payload():
    return {"payload": {"data": {"status": "SUCCESS", "prefixes": [
        {"prefix": "10.20.0.0/24"},
    ]}}}


def _sync_ok(n, skipped=0):
    return {"payload": {"data": {"status": "SUCCESS", "pushed": n, "errors": 0,
                                 "skipped": skipped, "deleted": 0,
                                 "sessions_total": n + skipped, "message": "ok"}}}


def _hub(responses=None, **kw):
    responses = responses or {}
    responses.setdefault(("cppm-1", "CPPM_GET_RECENT_SESSIONS"), _sessions_payload())
    responses.setdefault(("netbox-1", "NETBOX_GET_PREFIXES"), _prefixes_payload())
    responses.setdefault(("netbox-1", "NETBOX_SYNC_ACCESS_TRACKER"), _sync_ok(1, 1))
    return _RtHub(responses=responses, **kw)


# ── pull / attribute ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_pull_normalizes_mac_and_drops_macless():
    h = _hub()
    sessions, info = await h._rt_pull_sessions()
    # 3 rows → 2 with a MAC (the mac-less one dropped hub-side).
    assert len(sessions) == 2
    by_ip = {s["ip"]: s for s in sessions}
    assert by_ip["10.20.0.5"]["mac"] == "aa:bb:cc:dd:ee:05"   # normalized from AA-BB-…
    assert by_ip["10.20.0.5"]["nas_ip"] == "10.20.0.1"
    assert by_ip["10.20.0.5"]["nas_port"] == "Ethernet1/0/12"
    assert by_ip["10.20.0.5"]["username"] == "alice"
    assert info["errors"] == []
    assert info["window_start"] == "2026-06-30T10:00:00Z"


@pytest.mark.asyncio
async def test_pull_error_when_no_nac_spoke():
    h = _hub(nac_spoke=None)
    sessions, info = await h._rt_pull_sessions()
    assert sessions == []
    assert info["errors"] == ["no NAC spoke connected"]


@pytest.mark.asyncio
async def test_attribute_buckets_by_prefix_and_drops_unattributed():
    h = _hub()
    sessions, _ = await h._rt_pull_sessions()
    buckets, dropped = await h._rt_attribute(sessions)
    assert set(buckets.keys()) == {"acme"}
    assert len(buckets["acme"]) == 1          # 10.20.0.5 (the mac-less 10.20.0.6 was dropped in pull)
    assert dropped == 1                        # 10.30.0.99 unmatched


# ── push / entry points ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_sync_tenant_realtime_pushes_replace_false_with_sessions():
    h = _RtHub(global_config={"realtime_ipam_nac_sync": {
        "defaults": {"role": "discovered", "switch_role": "switch"}}},
        responses={
            ("cppm-1", "CPPM_GET_RECENT_SESSIONS"): _sessions_payload(),
            ("netbox-1", "NETBOX_GET_PREFIXES"): _prefixes_payload(),
            ("netbox-1", "NETBOX_SYNC_ACCESS_TRACKER"): _sync_ok(1, 1),
        })
    status = await h.sync_tenant_realtime("acme")
    assert status["status"] == "success"
    assert status["pushed"] == 1
    assert status["skipped"] == 1
    assert status["tenant_name"] == "Acme"
    assert status["sessions_total_global"] == 2     # 2 MAC-bearing sessions pulled
    assert status["dropped_unattributed"] == 1       # 10.30.0.99
    # Push command carried replace=False (only-add-missing) + tenant slug + sessions + defaults.
    push = next(p for sid, cmd, p in h.request_log
                if cmd == "NETBOX_SYNC_ACCESS_TRACKER" and sid == "netbox-1")
    assert push["replace"] is False
    assert push["tenant_slug"] == "acme"
    assert push["defaults"]["switch_role"] == "switch"
    assert len(push["sessions"]) == 1
    assert push["sessions"][0]["mac"] == "aa:bb:cc:dd:ee:05"
    # Per-tenant status persisted to the store.
    assert h.simulations_store.recorded["acme"]["status"] == "success"


@pytest.mark.asyncio
async def test_sync_tenant_realtime_skipped_when_unbound():
    # Tenant has no netbox_tenant_slug → skipped (not an error).
    h = _RtHub(tenants={"acme": {"name": "Acme"}},  # no netbox_tenant_slug
               responses={
                   ("cppm-1", "CPPM_GET_RECENT_SESSIONS"): _sessions_payload(),
                   ("netbox-1", "NETBOX_GET_PREFIXES"): _prefixes_payload(),
               })
    status = await h.sync_tenant_realtime("acme")
    assert status["status"] == "skipped"
    assert "netbox_tenant_slug" in status["message"]
    # No push command issued.
    assert not any(cmd == "NETBOX_SYNC_ACCESS_TRACKER"
                   for _, cmd, _ in h.request_log)


@pytest.mark.asyncio
async def test_sync_tenant_realtime_error_when_ipam_offline():
    h = _hub(ipam_spoke=None)  # no netbox → push records an error
    status = await h.sync_tenant_realtime("acme")
    assert status["status"] == "error"
    assert "NetBox spoke not connected" in status["message"]


@pytest.mark.asyncio
async def test_run_all_returns_summary():
    h = _hub()
    agg = await h.run_realtime_nac_sync_all()
    assert agg["sessions_total"] == 2
    assert agg["dropped_unattributed"] == 1
    assert len(agg["results"]) == 1
    assert agg["results"][0]["tenant_id"] == "acme"
    assert agg["results"][0]["pushed"] == 1


@pytest.mark.asyncio
async def test_push_with_errors_emits_sync_error_marker_with_message(caplog):
    """A per-tenant push that returns batch SUCCESS with per-record errors must
    emit a [sync-error] WARNING carrying the sink's first-error message (same
    diagnosability contract as the other syncs)."""
    with caplog.at_level(logging.WARNING, logger="Hub"):
        h = _RtHub(responses={
            ("cppm-1", "CPPM_GET_RECENT_SESSIONS"): _sessions_payload(),
            ("netbox-1", "NETBOX_GET_PREFIXES"): _prefixes_payload(),
            ("netbox-1", "NETBOX_SYNC_ACCESS_TRACKER"):
                {"payload": {"data": {"status": "SUCCESS", "pushed": 0, "errors": 5,
                                      "skipped": 0, "deleted": 0, "sessions_total": 1,
                                      "message": "0 added, 5 errors — first error: custom field missing"}}},
        })
        status = await h.sync_tenant_realtime("acme")
    assert status["status"] == "success"
    assert status["errors"] == 5
    warns = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert any("[sync-error]" in r.getMessage()
               and "first error: custom field missing" in r.getMessage()
               and "tenant=acme" in r.getMessage() for r in warns), \
        "expected a [sync-error] WARNING with the sink's first-error message"


# ── loop guard ───────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_loop_disabled_does_not_sync(monkeypatch):
    """When the config has enabled=False the loop must be a no-op: it must not
    call run_realtime_nac_sync_all. Breaks the loop after the second sleep via a
    CancelledError (BaseException — not caught by the loop's `except Exception`)."""
    h = _RtHub(global_config={"realtime_ipam_nac_sync": {"enabled": False}})

    async def _boom():
        raise AssertionError("run_realtime_nac_sync_all must not run when disabled")
    h.run_realtime_nac_sync_all = _boom

    real_sleep = asyncio.sleep
    state = {"n": 0}

    async def fake_sleep(t):
        state["n"] += 1
        if state["n"] >= 2:
            raise asyncio.CancelledError()
        await real_sleep(0)

    monkeypatch.setattr(rt.asyncio, "sleep", fake_sleep)
    with pytest.raises(asyncio.CancelledError):
        await h.run_realtime_nac_sync_loop()