"""``routes/os_updates.py`` — admin gating + the auto-check schedule endpoints.

Pins the new "auto-check every N hours" feature (OS Updates view): a
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

    async def osu_apply_fleet(self, node_keys=None, actor="", packages=None,
                              security_only=False):
        self.applied = {"nodes": node_keys, "packages": packages,
                        "security_only": security_only}
        return {"status": "SUCCESS", "queued": 1}

    def osu_cancel_run(self, actor=""):
        return {"status": "ERROR", "message": "no update run in progress"}

    def osu_autopatch_config(self):
        return {"security_only": getattr(self, "_sec", True),
                "nodes": sorted(getattr(self, "_nodes", set()))}

    def osu_set_autopatch_security_only(self, on):
        self._sec = on
        return self.osu_autopatch_config()

    def osu_set_autopatch_node(self, key, on):
        self._nodes = getattr(self, "_nodes", set())
        (self._nodes.add if on else self._nodes.discard)(key)
        return self.osu_autopatch_config()

    async def osu_fix_access(self, key, username, password, actor=""):
        self.fixed = (key, username, password)
        return {"status": "SUCCESS", "message": "updates enabled"}

    async def osu_reboot_node(self, key, actor=""):
        self.rebooted = key
        return {"status": "SUCCESS", "message": "reboot scheduled in 1 minute"}


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


def test_apply_passes_packages_and_security_only():
    c, hub = _client()
    r = c.post("/api/os-updates/apply", json={
        "nodes": ["spoke:a"], "packages": {"agent:b": ["openssl"]}, "security_only": True})
    assert r.status_code == 200
    assert hub.applied == {"nodes": ["spoke:a"], "packages": {"agent:b": ["openssl"]},
                           "security_only": True}


def test_apply_rejects_malformed_packages():
    c, _ = _client()
    assert c.post("/api/os-updates/apply", json={"packages": ["openssl"]}).status_code == 400
    assert c.post("/api/os-updates/apply",
                  json={"packages": {"spoke:a": "openssl"}}).status_code == 400


def test_cancel_without_a_run_is_409():
    c, _ = _client()
    assert c.post("/api/os-updates/cancel", json={}).status_code == 409


def test_reboot_requires_node_and_admin():
    c, hub = _client()
    assert c.post("/api/os-updates/reboot", json={}).status_code == 400
    r = c.post("/api/os-updates/reboot", json={"node": "hub:hub"})
    assert r.status_code == 200 and hub.rebooted == "hub:hub"
    c, _ = _client(is_admin=False)
    assert c.post("/api/os-updates/reboot", json={"node": "hub:hub"}).status_code == 403


def test_autopatch_per_node_roundtrip():
    c, hub = _client()
    assert c.get("/api/os-updates/auto-patch").json() == {"security_only": True, "nodes": []}
    c.post("/api/os-updates/auto-patch", json={"node": "spoke:s1", "enabled": True})
    r = c.post("/api/os-updates/auto-patch", json={"security_only": False})
    assert r.json() == {"security_only": False, "nodes": ["spoke:s1"]}
    r = c.post("/api/os-updates/auto-patch", json={"node": "spoke:s1", "enabled": False})
    assert r.json()["nodes"] == []
    assert c.post("/api/os-updates/auto-patch", json={"node": ""}).status_code == 400


def test_fix_access_requires_a_password_and_relays_it():
    c, hub = _client()
    assert c.post("/api/os-updates/fix-access", json={"node": "spoke:s1"}).status_code == 400
    r = c.post("/api/os-updates/fix-access",
               json={"node": "spoke:s1", "username": "root", "password": "pw"})
    assert r.status_code == 200 and hub.fixed == ("spoke:s1", "root", "pw")


def test_autopatch_and_fix_access_are_admin_only():
    c, _ = _client(is_admin=False)
    assert c.get("/api/os-updates/auto-patch").status_code == 403
    assert c.post("/api/os-updates/fix-access",
                  json={"node": "x", "password": "pw"}).status_code == 403
