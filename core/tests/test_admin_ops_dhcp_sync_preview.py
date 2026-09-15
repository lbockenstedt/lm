"""``/admin/ops/dhcp-sync-preview`` — why a DHCP reservation never reached Kea.

Why this exists: a NetBox -> Kea sync reports ``status: "ok"`` even when the
Kea spoke applied NONE of the reservations it was handed. A real run on the
fleet returned ``reservations_synced: 123`` from the hub and
``{"reservations": 0, "reservations_skipped": 123}`` from the spoke — a total
silent drop that is indistinguishable, from the WebUI, from "there are no
reservations". An operator asking "where is my reservation for x.x.x.199?"
had nothing to query.

A reservation is only applied when its IP falls inside a prefix that is
actually synced as a scope (not ``status=container`` AND
``custom_fields.dhcp_enabled`` set). This route recomputes the payload with
the very same ``build_dhcp_payload`` the sync uses and says which side of that
line each reservation falls on.

The properties pinned here are the ones that make it trustworthy: it must
never mutate anything, its scope-eligibility verdict must agree with the real
sync, and an unmatched reservation must be reported rather than dropped.
"""
import asyncio
import os

import pytest

from routes import admin_ops

from test_admin_ops_guard import _FakeApp, _FakeRequest, _State


class _SyncHub:
    """Hub double returning canned NetBox prefix/IP payloads."""

    def __init__(self, data_dir, prefixes, ips, boom=None):
        self.state = _State(data_dir)
        self.active_connections = {}
        self._prefixes = prefixes
        self._ips = ips
        self._boom = boom
        self.sent = []

    def _primary_key(self, spoke_id):
        return spoke_id

    async def request_response(self, *a, **kw):  # pragma: no cover - guard
        self.sent.append(a)
        raise AssertionError("dhcp-sync-preview must never send an RPC")

    async def _netbox_prefixes_and_ips(self):
        if self._boom:
            raise self._boom
        return ({"prefixes": self._prefixes}, {"ip_addresses": self._ips})


def _mk(tmp, prefixes, ips, boom=None):
    app = _FakeApp()
    hub = _SyncHub(tmp, prefixes, ips, boom)
    admin_ops.register(app, hub, ctx=None)
    tok = open(os.path.join(tmp, "admin_ops_token")).read().strip()
    return app.routes[("GET", "/admin/ops/dhcp-sync-preview")], hub, tok


def _req(tok):
    r = _FakeRequest("127.0.0.1", tok)
    r.url = type("U", (), {"path": "/admin/ops/dhcp-sync-preview"})()
    return r


def _call(tmp, prefixes, ips):
    route, hub, tok = _mk(tmp, prefixes, ips)
    return asyncio.get_event_loop().run_until_complete(route(_req(tok))), hub


# A scope that IS synced, and one that is not because nobody ticked the box.
_PREFIXES = [
    {"prefix": "172.17.1.0/24", "status": "active",
     "custom_fields": {"dhcp_enabled": True}},
    {"prefix": "172.16.0.0/24", "status": "active",
     "custom_fields": {"dhcp_enabled": False}},
    {"prefix": "172.16.0.0/12", "status": "container",
     "custom_fields": {"dhcp_enabled": True}},
]
_IPS = [
    {"address": "172.17.1.199/24", "dns_name": "good",
     "custom_fields": {"mac_address": "aa:bb:cc:dd:ee:01"}},
    {"address": "172.16.0.50/24", "dns_name": "orphan",
     "custom_fields": {"mac_address": "aa:bb:cc:dd:ee:02"}},
]


def test_reservation_inside_an_enabled_scope_is_reported_as_applying(tmp_path):
    out, _ = _call(str(tmp_path), _PREFIXES, _IPS)
    assert out["totals"]["would_apply"] == 1
    ips = [r["ip"] for r in out["matched_reservations"]]
    assert ips == ["172.17.1.199"]
    assert out["matched_reservations"][0]["subnet_match"] == "172.17.1.0/24"


def test_reservation_with_no_enabled_scope_is_named_not_silently_dropped(tmp_path):
    """The whole point: the dropped reservation must be visible BY IP."""
    out, _ = _call(str(tmp_path), _PREFIXES, _IPS)
    assert out["totals"]["would_skip"] == 1
    orphans = [r["ip"] for r in out["unmatched_reservations"]]
    assert orphans == ["172.16.0.50"]
    assert out["unmatched_reservations"][0]["subnet_match"] is None


def test_totals_account_for_every_reservation(tmp_path):
    out, _ = _call(str(tmp_path), _PREFIXES, _IPS)
    t = out["totals"]
    assert t["would_apply"] + t["would_skip"] == t["reservations"] == 2


def test_scopes_match_what_the_real_sync_would_push(tmp_path):
    """Verdict must come from build_dhcp_payload, not a reimplementation."""
    from dns_dhcp_sync import build_dhcp_payload
    subnets, reservations = build_dhcp_payload(
        {"prefixes": _PREFIXES}, {"ip_addresses": _IPS})
    out, _ = _call(str(tmp_path), _PREFIXES, _IPS)
    assert out["scopes"] == [s["subnet"] for s in subnets] == ["172.17.1.0/24"]
    assert out["totals"]["reservations"] == len(reservations)


def test_each_prefix_carries_the_reason_it_is_not_a_scope(tmp_path):
    """The actionable half — 'tick dhcp_enabled on <prefix>'."""
    out, _ = _call(str(tmp_path), _PREFIXES, _IPS)
    by_prefix = {p["prefix"]: p for p in out["prefixes"]}
    assert by_prefix["172.17.1.0/24"]["synced_as_scope"] is True
    assert by_prefix["172.17.1.0/24"]["reason"] == ""
    assert by_prefix["172.16.0.0/24"]["synced_as_scope"] is False
    assert "dhcp_enabled" in by_prefix["172.16.0.0/24"]["reason"]
    # A container is excluded even though the checkbox IS ticked on it.
    assert by_prefix["172.16.0.0/12"]["synced_as_scope"] is False
    assert "container" in by_prefix["172.16.0.0/12"]["reason"]


def test_preview_never_sends_an_rpc(tmp_path):
    """Read-only: a diagnostic that mutates is not a diagnostic."""
    _out, hub = _call(str(tmp_path), _PREFIXES, _IPS)
    assert hub.sent == []


def test_an_ip_without_a_mac_is_not_a_reservation_at_all(tmp_path):
    out, _ = _call(str(tmp_path), _PREFIXES, [
        {"address": "172.17.1.5/24", "custom_fields": {}},
        {"address": "172.17.1.6/24", "custom_fields": {"mac_address": "  "}},
    ])
    assert out["totals"]["reservations"] == 0


def test_a_malformed_reservation_ip_is_reported_as_unmatched(tmp_path):
    """Must not raise — a bad record cannot sink the diagnostic."""
    out, _ = _call(str(tmp_path), _PREFIXES, [
        {"address": "not-an-ip/24", "custom_fields": {"mac_address": "aa:bb:cc:dd:ee:03"}},
    ])
    assert out["totals"]["would_skip"] == 1
    assert out["unmatched_reservations"][0]["subnet_match"] is None


def test_netbox_failure_surfaces_as_500_not_a_bogus_empty_answer(tmp_path):
    """An empty preview would read as 'you have no reservations' — wrong."""
    app = _FakeApp()
    hub = _SyncHub(str(tmp_path), _PREFIXES, _IPS,
                   boom=RuntimeError("NetBox spoke not connected"))
    admin_ops.register(app, hub, ctx=None)
    tok = open(os.path.join(str(tmp_path), "admin_ops_token")).read().strip()
    route = app.routes[("GET", "/admin/ops/dhcp-sync-preview")]
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as ei:
        asyncio.get_event_loop().run_until_complete(route(_req(tok)))
    assert ei.value.status_code == 500
    assert "NetBox" in str(ei.value.detail)


def test_route_is_loopback_and_token_gated(tmp_path):
    """Same two gates as every other /admin/ops route."""
    from fastapi import HTTPException
    route, _hub, tok = _mk(str(tmp_path), _PREFIXES, _IPS)
    loop = asyncio.get_event_loop()

    remote = _FakeRequest("10.0.0.9", tok)
    remote.url = type("U", (), {"path": "/admin/ops/dhcp-sync-preview"})()
    with pytest.raises(HTTPException):
        loop.run_until_complete(route(remote))

    bad = _FakeRequest("127.0.0.1", "not-the-token")
    bad.url = type("U", (), {"path": "/admin/ops/dhcp-sync-preview"})()
    with pytest.raises(HTTPException):
        loop.run_until_complete(route(bad))
