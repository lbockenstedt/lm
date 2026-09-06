"""Threat Monitor participant client: publication filter, wire schema, failure posture.

The filter is the safety-critical half. Publishing an address is a request for
other people to block it, so a wrong entry is paid for by the whole network, not
by the install that reported it. These tests pin what may never leave the
process:

* nothing whose meaning is not global (private, loopback, CGNAT, reserved),
* nothing on the operator's never-publish list (shared NAT/CDN egress, their own
  hub and spokes),
* and never the decoy path that tripped — the set is the sensor, and disclosing
  which path fired burns it for every participant at once.

They also pin the failure posture: the service is an enrichment, so any outage
must leave the install behaving exactly as if no service were configured.
"""

import os
import sys

import httpx
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from security.tm_client import (  # noqa: E402
    TMClient,
    build_report,
    filter_reports,
    is_publishable,
)


# ── publication filter ───────────────────────────────────────────────────────

@pytest.mark.parametrize("ip", [
    "10.0.0.5", "192.168.1.10", "172.16.4.4",   # RFC1918
    "127.0.0.1",                                  # loopback
    "169.254.10.10",                              # link-local
    "100.64.3.9",                                 # carrier-grade NAT
    "224.0.0.1",                                  # multicast
    "0.0.0.0",                                    # unspecified
    "fd00::1",                                    # unique-local v6
    "::1",                                        # loopback v6
])
def test_non_global_addresses_are_never_published(ip):
    """Each of these names a different machine at every site (or no machine at
    all). Publishing one asks other participants to block their own
    infrastructure."""
    ok, why = is_publishable(ip)
    assert ok is False and why


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"])
def test_global_addresses_are_publishable(ip):
    assert is_publishable(ip)[0] is True


@pytest.mark.parametrize("ip", ["203.0.113.7", "198.51.100.4", "192.0.2.9", "2001:db8::1"])
def test_documentation_ranges_are_refused(ip):
    """TEST-NET and 2001:db8:: are reserved for documentation, so a real
    attacker is never behind one — but they are extremely common in configs and
    test fixtures, which is exactly how they would leak into a live feed."""
    assert is_publishable(ip)[0] is False


@pytest.mark.parametrize("bad", ["", "   ", "not-an-ip", "999.1.1.1", "1.2.3.4/24"])
def test_unparseable_addresses_fail_closed(bad):
    """A malformed address helps nobody and could carry an injection into a
    consumer's blocklist."""
    assert is_publishable(bad)[0] is False


def test_operator_never_publish_list_is_honoured():
    """The dangerous case: a shared NAT/CDN egress. Blocking it takes out every
    unrelated tenant behind it."""
    ok, why = is_publishable("8.8.8.8", never_publish=["8.8.8.0/24"])
    assert ok is False and "never-publish" in why
    assert is_publishable("1.1.1.1", never_publish=["8.8.8.0/24"])[0] is True


def test_never_publish_accepts_bare_addresses_and_ignores_junk():
    """Operators hand-edit this list, so a single malformed entry must not
    disable the rest of it."""
    nev = ["not-a-cidr", "8.8.8.8"]
    assert is_publishable("8.8.8.8", never_publish=nev)[0] is False
    assert is_publishable("9.9.9.9", never_publish=nev)[0] is True


def test_never_publish_does_not_cross_address_families():
    assert is_publishable("2606:4700:4700::1111", never_publish=["0.0.0.0/0"])[0] is True


def test_filter_is_applied_on_the_way_out_not_left_to_the_server():
    """Only this install knows which addresses are its operator's own
    infrastructure; the server cannot infer it."""
    keep, refused = filter_reports(
        [build_report("10.0.0.1", "bait_used"), build_report("8.8.8.8", "http_probe")])
    assert [r["ip"] for r in keep] == ["8.8.8.8"]
    assert refused[0][0] == "10.0.0.1"


# ── wire schema ──────────────────────────────────────────────────────────────

def test_report_never_carries_the_decoy_path():
    """The decoy set is the sensor. Publishing which path tripped tells an
    attacker exactly what is watched, and burns it for every participant."""
    rec = build_report("8.8.8.8", "default_decoy")
    assert "path" not in rec and "decoy" not in rec
    assert set(rec) == {"ip", "tier", "first_seen", "count"}


def test_unknown_tier_degrades_to_the_weakest():
    """Confidence must never be inflated by an unrecognised label."""
    assert build_report("8.8.8.8", "totally-made-up")["tier"] == "http_probe"


def test_duplicate_addresses_collapse_to_the_strongest_tier():
    """Otherwise one attacker reported under several tiers inflates its own
    corroboration count, and a consumer acts on the weaker signal."""
    keep, _ = filter_reports([
        build_report("8.8.8.8", "http_probe", count=3),
        build_report("8.8.8.8", "bait_used", count=1),
    ])
    assert len(keep) == 1
    assert keep[0]["tier"] == "bait_used"
    assert keep[0]["count"] == 4


# ── failure posture ──────────────────────────────────────────────────────────

def _client(**kw):
    return TMClient(base_url="https://tm.invalid", tenant_id="t1",
                    install_uuid="u1", credential="c1", **kw)


@pytest.mark.asyncio
async def test_unreachable_service_never_raises(monkeypatch):
    """The local sensors are the authority for this install; the feed is an
    enrichment. An outage must not change local behaviour."""
    async def _boom(*a, **kw):
        raise httpx.ConnectError("down")

    monkeypatch.setattr(httpx.AsyncClient, "request", _boom)
    c = _client()
    assert await c.fetch_decoys() is None
    assert await c.fetch_feed() is None
    assert (await c.report([build_report("8.8.8.8", "bait_used")]))["status"] == "ERROR"
    assert (await c.enroll())["status"] == "error"


@pytest.mark.asyncio
async def test_failed_decoy_fetch_returns_None_not_empty(monkeypatch):
    """None means 'keep the current set'; [] is a deliberate stand-down. If a
    fetch failure returned [], one unreachable service would silently disarm
    every participant's sensor at once."""
    async def _boom(*a, **kw):
        raise httpx.ConnectError("down")

    monkeypatch.setattr(httpx.AsyncClient, "request", _boom)
    assert await _client().fetch_decoys() is None


@pytest.mark.asyncio
async def test_nothing_is_sent_when_every_record_is_withheld(monkeypatch):
    """A report of only private addresses must not produce a request at all."""
    called = []

    async def _spy(*a, **kw):
        called.append(kw)
        raise AssertionError("should not have been called")

    monkeypatch.setattr(httpx.AsyncClient, "request", _spy)
    out = await _client().report([build_report("10.0.0.1", "bait_used")])
    assert out == {"status": "SKIPPED", "published": 0, "withheld": 1}
    assert called == []


@pytest.mark.asyncio
async def test_credential_is_sent_as_bearer_with_both_identifiers(monkeypatch):
    """One credential per install keeps the binding 1:1; the tenant tag is what
    lets the service count independent reporters rather than one org's several
    installs."""
    seen = {}

    async def _ok(self, method, url, **kw):
        seen["headers"] = kw.get("headers") or {}
        return httpx.Response(200, json={"records": []},
                              request=httpx.Request(method, url))

    monkeypatch.setattr(httpx.AsyncClient, "request", _ok)
    await _client().fetch_feed()
    assert seen["headers"]["Authorization"] == "Bearer c1"
    assert seen["headers"]["X-TM-Install"] == "u1"
    assert seen["headers"]["X-TM-Tenant"] == "t1"


@pytest.mark.asyncio
async def test_error_status_is_not_treated_as_data(monkeypatch):
    async def _err(self, method, url, **kw):
        return httpx.Response(503, text="nope", request=httpx.Request(method, url))

    monkeypatch.setattr(httpx.AsyncClient, "request", _err)
    assert await _client().fetch_feed() is None


@pytest.mark.asyncio
async def test_enroll_stores_a_granted_credential(monkeypatch):
    async def _ok(self, method, url, **kw):
        return httpx.Response(200, json={"status": "approved", "credential": "new-cred"},
                              request=httpx.Request(method, url))

    monkeypatch.setattr(httpx.AsyncClient, "request", _ok)
    c = TMClient("https://tm.invalid", "t1", "u1", enrollment_psk="psk")
    assert (await c.enroll())["status"] == "approved"
    assert c.credential == "new-cred"


@pytest.mark.asyncio
async def test_pending_enrollment_grants_no_credential(monkeypatch):
    """A participant that cannot hold a PSK is not excluded — it waits for a
    human, and must not believe it is enrolled meanwhile."""
    async def _pending(self, method, url, **kw):
        return httpx.Response(200, json={"status": "pending"},
                              request=httpx.Request(method, url))

    monkeypatch.setattr(httpx.AsyncClient, "request", _pending)
    c = TMClient("https://tm.invalid", "t1", "u1")
    assert (await c.enroll())["status"] == "pending"
    assert c.credential == ""


@pytest.mark.asyncio
async def test_no_base_url_makes_the_client_inert(monkeypatch):
    """An install that has not opted in must make no outbound requests."""
    async def _spy(*a, **kw):
        raise AssertionError("should not have been called")

    monkeypatch.setattr(httpx.AsyncClient, "request", _spy)
    c = TMClient("", "t1", "u1")
    assert await c.fetch_feed() is None
