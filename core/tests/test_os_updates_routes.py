"""``routes/os_updates.py`` — admin gating + the auto-check schedule endpoints.

Pins the new "auto-check every N hours" feature (Setup -> OS Updates): a
GET/POST pair at ``/api/os-updates/auto-check`` that reads/writes the hub's
``osu_autocheck_config()`` / ``osu_set_autocheck_config()`` (HubOsUpdatesMixin,
see ``test_hub_os_updates.py`` for the mixin-level contract). This module only
exercises the route wiring: admin gating, request/response shape, and that a
bad interval is rejected the same way the mixin clamps it.
"""
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from routes import os_updates as os_updates_routes  # noqa: E402


class _FakeHub:
    """Just enough of HubOsUpdatesMixin's surface for the route layer."""

    def __init__(self):
        self._cfg = {"enabled": True, "interval_hours": 6.0}
        self._snapshot = {"nodes": [], "totals": {}}
        self.checked = []

    def osu_autocheck_config(self):
        return dict(self._cfg)

    def osu_set_autocheck_config(self, enabled, interval_hours):
        try:
            hours = float(interval_hours)
        except (TypeError, ValueError):
            hours = 6.0
        hours = max(1.0, hours)
        self._cfg = {"enabled": bool(enabled), "interval_hours": hours}
        return dict(self._cfg)

    def osu_snapshot(self):
        return self._snapshot

    async def osu_check_fleet(self, refresh=True):
        self.checked.append(refresh)
        return self._snapshot


def _client(is_admin=True):
    app = FastAPI()
    hub = _FakeHub()
    ctx = SimpleNamespace(
        _session_user=lambda req: {"user": "root", "is_admin": is_admin},
        _is_admin=lambda s: is_admin,
    )
    os_updates_routes.register(app, hub, ctx)
    return TestClient(app), hub


def test_autocheck_get_returns_current_config():
    c, _ = _client()
    r = c.get("/api/os-updates/auto-check")
    assert r.status_code == 200
    assert r.json() == {"enabled": True, "interval_hours": 6.0}


def test_autocheck_post_updates_config():
    c, hub = _client()
    r = c.post("/api/os-updates/auto-check", json={"enabled": False, "interval_hours": 12})
    assert r.status_code == 200
    assert r.json() == {"enabled": False, "interval_hours": 12.0}
    assert hub.osu_autocheck_config() == {"enabled": False, "interval_hours": 12.0}


def test_autocheck_post_defaults_enabled_true_when_omitted():
    c, hub = _client()
    r = c.post("/api/os-updates/auto-check", json={"interval_hours": 3})
    assert r.status_code == 200
    assert r.json()["enabled"] is True


def test_autocheck_post_clamps_bad_interval_via_mixin():
    c, _ = _client()
    r = c.post("/api/os-updates/auto-check", json={"enabled": True, "interval_hours": 0})
    assert r.status_code == 200
    assert r.json()["interval_hours"] == 1.0


def test_autocheck_get_requires_admin():
    c, _ = _client(is_admin=False)
    r = c.get("/api/os-updates/auto-check")
    assert r.status_code == 403


def test_autocheck_post_requires_admin():
    c, _ = _client(is_admin=False)
    r = c.post("/api/os-updates/auto-check", json={"enabled": True, "interval_hours": 6})
    assert r.status_code == 403


def test_manual_check_still_works_alongside_autocheck_route():
    c, hub = _client()
    r = c.post("/api/os-updates/check", json={"refresh": True})
    assert r.status_code == 200
    assert hub.checked == [True]
