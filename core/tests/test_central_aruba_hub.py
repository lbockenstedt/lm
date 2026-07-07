"""Hub-side Aruba Central token probe (centralized processing mode).

``simulations.aruba.test_central_from_config`` runs a real token exchange on
the HUB using the creds the operator typed into Setup → Central API
(``central_config``), so the ``/sim/api/{tenant}/test-central`` button validates
the hub's own creds instead of echoing cached spoke telemetry. This tests the
three branches (not-configured / connected / failed) plus the underlying
``ArubaClient._ensure_token`` new_central (HPE SSO client_credentials) and
classic (cluster refresh_token) token flows.
"""
import asyncio

import httpx
import pytest

from simulations import aruba as _aruba
from simulations.aruba import ArubaClient


# ── test_central_from_config branches ──────────────────────────────────────

def test_not_configured_returns_missing():
    row = asyncio.run(_aruba.test_central_from_config({}))
    assert row["token_valid"] is False
    assert row["token_state"] == "missing"
    assert "not configured" in row["status"].lower()
    assert row["spoke_name"] == "Hub (centralized)"


def test_connected_when_ensure_token_succeeds(monkeypatch):
    async def fake_ensure(self, client):
        return "tok"
    monkeypatch.setattr(ArubaClient, "_ensure_token", fake_ensure)
    cfg = {"cluster_url": "https://example.api.central.arubanetworks.com",
           "api_version": "new_central", "client_id": "cid", "client_secret": "sec"}

    async def go():
        return await _aruba.test_central_from_config(cfg)
    row = asyncio.run(go())
    assert row["token_valid"] is True
    assert row["token_state"] == "present"
    assert row["status"] == "Connected."


def test_failed_surfaces_exception_string(monkeypatch):
    async def boom(self, client):
        raise RuntimeError("nope: boom")
    monkeypatch.setattr(ArubaClient, "_ensure_token", boom)
    cfg = {"cluster_url": "https://example.api.central.arubanetworks.com",
           "api_version": "new_central", "client_id": "cid", "client_secret": "sec"}

    async def go():
        return await _aruba.test_central_from_config(cfg)
    row = asyncio.run(go())
    assert row["token_valid"] is False
    assert row["token_state"] == "missing"
    assert "Connection failed:" in row["status"]
    assert "boom" in row["status"]


# ── ArubaClient._ensure_token real token flows (MockTransport) ──────────────

def test_new_central_posts_client_credentials_to_sso():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["body"] = request.content.decode() if isinstance(request.content, bytes) else str(request.content)
        return httpx.Response(200, json={"access_token": "TOK", "expires_in": 7200})

    cfg = {"cluster_url": "https://example.api.central.arubanetworks.com",
           "api_version": "new_central", "client_id": "cid", "client_secret": "sec"}
    client = ArubaClient(cfg)

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            return await client._ensure_token(http)
    token = asyncio.run(go())
    assert token == "TOK"
    assert seen["url"] == "https://sso.common.cloud.hpe.com/as/token.oauth2"
    assert "client_credentials" in seen["body"]
    assert "client_id=cid" in seen["body"]


def test_classic_posts_refresh_token_to_cluster():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["body"] = request.content.decode() if isinstance(request.content, bytes) else str(request.content)
        return httpx.Response(200, json={"access_token": "TOK2", "refresh_token": "RT2", "expires_in": 3600})

    cfg = {"cluster_url": "https://example.api.central.arubanetworks.com",
           "api_version": "classic", "client_id": "cid", "client_secret": "sec",
           "refresh_token": "RT", "customer_id": "cust123"}
    client = ArubaClient(cfg)

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            return await client._ensure_token(http)
    token = asyncio.run(go())
    assert token == "TOK2"
    assert seen["url"] == "https://example.api.central.arubanetworks.com/oauth2/token"
    assert "refresh_token=RT" in seen["body"]
    assert "customer_id=cust123" in seen["body"]


def test_api_version_falls_back_from_mode_central():
    # stored central_config may carry only `mode` (central|classic) without an
    # explicit api_version; the hub client must still pick new_central.
    client = ArubaClient({"mode": "central", "client_id": "x", "client_secret": "y"})
    assert client.api_version == "new_central"
    client2 = ArubaClient({"mode": "classic", "cluster_url": "https://x", "refresh_token": "r"})
    assert client2.api_version == "classic"


def test_static_access_token_short_circuits_new_central():
    cfg = {"api_version": "new_central", "access_token": "STATIC"}
    client = ArubaClient(cfg)

    def handler(request):
        pytest.fail("no HTTP call should be made for a static access token")

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            return await client._ensure_token(http)
    token = asyncio.run(go())
    assert token == "STATIC"


def test_classic_missing_refresh_token_raises():
    cfg = {"cluster_url": "https://x", "api_version": "classic",
           "client_id": "cid", "client_secret": "sec"}
    client = ArubaClient(cfg)

    def handler(request):
        pytest.fail("no HTTP call should be made when creds are incomplete")

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            return await client._ensure_token(http)
    with pytest.raises(ValueError, match="incomplete"):
        asyncio.run(go())


# ── available_checks (centralized-mode check catalog) ─────────────────────

def test_available_checks_new_central_returns_static_catalog():
    # new_central needs no cluster_url and makes NO API call — the catalog is static.
    client = ArubaClient({"api_version": "new_central", "client_id": "cid", "client_secret": "sec"})
    cat = asyncio.run(client.available_checks())
    assert cat["warning"] is None
    assert len(cat["alerts"]) == 5  # DEFAULT_NEW_CENTRAL_MONITORED_CHECKS
    assert any(a["id"] == "AP_DOWN" for a in cat["alerts"])
    assert cat["insights"] == []
    assert len(cat["hardware"]) == 3  # DEFAULT_NEW_CENTRAL_HARDWARE_CHECKS


def test_available_checks_not_configured_returns_warning():
    # classic with no cluster_url is not configured → "Central not configured."
    client = ArubaClient({"api_version": "classic"})
    cat = asyncio.run(client.available_checks())
    assert cat["alerts"] == [] and cat["insights"] == [] and cat["hardware"] == []
    assert cat["warning"] == "Central not configured."


def test_available_checks_classic_falls_back_to_known_types_on_empty(monkeypatch):
    # classic cluster returns empty alerts/insights → fallback to KNOWN_CLASSIC_*.
    cfg = {"cluster_url": "https://cluster.example", "api_version": "classic",
           "client_id": "cid", "client_secret": "sec", "refresh_token": "RT", "customer_id": "cust"}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/oauth2/token":
            return httpx.Response(200, json={"access_token": "T", "refresh_token": "RT2", "expires_in": 3600})
        return httpx.Response(200, json={"alerts": [], "insights": []})

    # available_checks builds its own httpx.AsyncClient internally; patch the class
    # the aruba module sees so that internal client uses a MockTransport.
    import simulations.aruba as _a

    class _Client(_a.httpx.AsyncClient):
        def __init__(self, *a, **k):
            k["transport"] = httpx.MockTransport(handler)
            super().__init__(*a, **k)
    monkeypatch.setattr(_a.httpx, "AsyncClient", _Client)

    client = ArubaClient(cfg)
    cat = asyncio.run(client.available_checks())
    assert len(cat["alerts"]) > 0  # KNOWN_CLASSIC_ALERT_TYPES fallback
    assert "AP_DOWN" in {a["id"] for a in cat["alerts"]}
    assert len(cat["insights"]) > 0  # KNOWN_CLASSIC_INSIGHT_CATEGORIES fallback
    assert "No live checks returned by Central" in (cat["warning"] or "")


def test_get_central_available_from_config_surfaces_failure(monkeypatch):
    async def boom(self):
        raise RuntimeError("catalog exploded")
    monkeypatch.setattr(ArubaClient, "available_checks", boom)
    from simulations.aruba import get_central_available_from_config
    cat = asyncio.run(get_central_available_from_config({"api_version": "new_central"}))
    assert cat["alerts"] == [] and cat["hardware"] == []
    assert "catalog fetch failed" in (cat["warning"] or "").lower()