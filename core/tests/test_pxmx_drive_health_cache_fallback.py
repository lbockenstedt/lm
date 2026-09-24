"""Diagnostics must survive the spoke going away.

While the hub or an agent is updating, the hypervisor spoke drops for a minute
or two. Overview and the VM list already warm-start from ``hub.warm_*`` in that
window; **Diagnostics did not** — it answered with an empty drive table (which
reads as "this host has no drives", not "we couldn't ask"), or bubbled up
``Timed out waiting for spoke response`` as a red error card.

These cover the fallback and, just as importantly, the cases where serving
cached data would be WRONG: the ADMIN/``default`` tenant prompt, and data old
enough that the shared ``StalenessPolicy`` calls it expired.
"""

import pytest

from cache_core import DEFAULT_EXPIRE_AFTER_S
from routes import pxmx

from test_pxmx_drive_health_route import _MockHub, _build_client

_NS = "pxmx_drive_health"


@pytest.fixture(autouse=True)
def _reset_caches():
    pxmx._NODES_CACHE.clear()
    yield
    pxmx._NODES_CACHE.clear()


def _cached_payload(node="pve1", wear=12):
    return {
        "nodes": [{
            "node": node,
            "cluster": "lab-cluster",
            "drives": [{"block_device": "/dev/sda", "wear_level": wear,
                        "health_status": "healthy"}],
            "summary": {"total_drives": 1, "healthy": 1, "warning": 0,
                        "critical": 0, "unknown": 0},
            "status": "SUCCESS",
        }],
        "summary": {"total_drives": 1, "healthy": 1, "warning": 0,
                    "critical": 0, "unknown": 0},
        "spoke_connected": True,
    }


def test_successful_fetch_populates_the_cache():
    """Nothing can be served later if the good answer was never kept."""
    hub = _MockHub(bound_spoke="pxmx-1")
    client = _build_client(hub, tenant="t1")
    assert client.get("/api/pxmx/drive-health?tenant=t1").status_code == 200

    cached = hub.warm_get(_NS, "t1|node=")
    assert cached is not None
    assert cached["nodes"], "cached an empty aggregate"
    assert hub.warm_fetched_at(_NS, "t1|node=") > 0


def test_spoke_gone_serves_cached_drives_marked_stale():
    """The reported bug: spoke down during an update → empty table / timeout.

    The drive rows must still come back, flagged so the UI can badge them.
    """
    hub = _MockHub(bound_spoke=None, global_spoke=None)
    hub.seed_warm(_NS, "t1|node=", _cached_payload(), age_s=45)
    client = _build_client(hub, tenant="t1")

    body = client.get("/api/pxmx/drive-health?tenant=t1").json()
    assert body["stale"] is True
    assert body["spoke_connected"] is False
    assert [n["node"] for n in body["nodes"]] == ["pve1"]
    assert body["summary"]["total_drives"] == 1
    assert body["cached_at"] > 0


def test_spoke_present_but_timing_out_serves_cache():
    """A connected-but-unresponsive spoke is the update window's real shape:
    the request_response call raises rather than the spoke list being empty."""
    hub = _MockHub(bound_spoke="pxmx-1")
    hub.seed_warm(_NS, "t1|node=", _cached_payload(), age_s=10)

    async def _timeout(sid, cmd, payload, timeout=30.0, signing_secret=None):
        if cmd == "GET_NODE_STATS":
            return {"payload": {"data": {"nodes": hub.node_stats}}}
        raise TimeoutError("Timed out waiting for spoke response")

    hub.request_response = _timeout
    client = _build_client(hub, tenant="t1")

    body = client.get("/api/pxmx/drive-health?tenant=t1").json()
    assert body["stale"] is True
    assert body["nodes"], "timeout produced an empty drive table"


def test_expired_cache_is_not_served():
    """A day-old snapshot is no longer evidence about the hardware — past
    ``expire_after_s`` the honest answer is the empty/no-spoke state."""
    hub = _MockHub(bound_spoke=None, global_spoke=None)
    hub.seed_warm(_NS, "t1|node=", _cached_payload(),
                  age_s=DEFAULT_EXPIRE_AFTER_S + 60)
    client = _build_client(hub, tenant="t1")

    body = client.get("/api/pxmx/drive-health?tenant=t1").json()
    assert body.get("stale") is not True
    assert body["nodes"] == []


def test_admin_default_tenant_never_serves_another_tenants_cache():
    """``default`` is the ADMIN scope, not "All". It prompts for a tenant, and
    must NOT answer with whatever tenant was last viewed — that would reopen
    the cross-tenant leak the select_tenant prompt exists to close."""
    hub = _MockHub(bound_spoke=None, global_spoke="pxmx-global")
    hub.seed_warm(_NS, "t1|node=", _cached_payload(node="secret-host"), age_s=5)
    hub.seed_warm(_NS, "default|node=", _cached_payload(node="secret-host"), age_s=5)
    client = _build_client(hub, tenant="default")

    body = client.get("/api/pxmx/drive-health?tenant=default").json()
    assert body["select_tenant"] is True
    assert body["nodes"] == []
    assert body.get("stale") is not True


def test_cache_is_keyed_per_tenant_and_node():
    """One tenant's diagnostics must never satisfy another's request."""
    hub = _MockHub(bound_spoke=None, global_spoke=None)
    hub.seed_warm(_NS, "t1|node=", _cached_payload(node="t1-host"), age_s=5)
    client = _build_client(hub, tenant="t2")

    body = client.get("/api/pxmx/drive-health?tenant=t2").json()
    assert body["nodes"] == [], "served tenant t1's cache to tenant t2"


def test_a_failed_fetch_does_not_overwrite_good_cache():
    """A timeout must not replace real drive data with an empty aggregate —
    otherwise the first failure destroys the very fallback being built."""
    hub = _MockHub(bound_spoke="pxmx-1")
    hub.seed_warm(_NS, "t1|node=", _cached_payload(wear=12), age_s=5)

    async def _timeout(sid, cmd, payload, timeout=30.0, signing_secret=None):
        if cmd == "GET_NODE_STATS":
            return {"payload": {"data": {"nodes": hub.node_stats}}}
        raise TimeoutError("Timed out waiting for spoke response")

    hub.request_response = _timeout
    client = _build_client(hub, tenant="t1")
    client.get("/api/pxmx/drive-health?tenant=t1")

    still = hub.warm_get(_NS, "t1|node=")
    assert still["nodes"][0]["drives"][0]["wear_level"] == 12


def test_recovery_replaces_stale_with_live():
    """Once the spoke is back the badge must clear on the next request."""
    hub = _MockHub(bound_spoke="pxmx-1")
    hub.seed_warm(_NS, "t1|node=", _cached_payload(), age_s=300)
    client = _build_client(hub, tenant="t1")

    body = client.get("/api/pxmx/drive-health?tenant=t1").json()
    assert body.get("stale") is not True
    assert body["spoke_connected"] is True


# ── WebUI: the banner the backend's stale flag is for ───────────────────────

def _main_js():
    from pathlib import Path
    return (Path(__file__).resolve().parents[2] / "WebUI" / "main.js").read_text()


def test_stale_banner_markup_is_not_duplicated():
    """Overview and the VM list each carried a verbatim copy of this markup,
    which is why Diagnostics could be missed entirely. One definition only."""
    js = _main_js()
    assert js.count("Showing cached data") == 1, (
        "stale-banner markup was copied again instead of calling "
        "pxmxStaleBanner()")
    assert "function pxmxStaleBanner(" in js


def test_all_three_hypervisor_tabs_render_the_banner():
    js = _main_js()
    assert js.count("pxmxStaleBanner(") >= 4, (
        "expected the helper definition plus a call from Overview, the VM "
        "list and Diagnostics")


def test_diagnostics_prefers_stale_data_over_the_no_spoke_card():
    """The hub answers a spoke restart with cached rows AND
    spoke_connected=false. Branching on spoke_connected alone would discard
    them and render 'No Hypervisor Spoke Connected' — defeating the fallback."""
    js = _main_js()
    assert "if (!spokeConnected && !isStale) {" in js


def test_genuinely_empty_cluster_is_not_papered_over_with_stale_rows():
    """A spoke that ANSWERS with zero nodes is not an outage.

    The fallback keys on spoke_connected alone, never on "the node list came
    back empty". spoke_connected only flips true once some spoke returned a
    usable envelope, so an empty list alongside it means the spoke genuinely
    reported zero nodes -- e.g. every host was removed from the cluster. Serving
    the cache there would resurrect drives that no longer exist, which is the
    same "no data" vs "couldn't ask" conflation the fallback exists to remove,
    just pointing the other way.
    """
    hub = _MockHub(bound_spoke="pxmx-1")
    hub.seed_warm(_NS, "t1|node=", _cached_payload(), age_s=60)

    # Spoke is up and replies, but the cluster now has no nodes at all.
    hub.drive_response = {"status": "SUCCESS", "nodes": []}
    body = _build_client(hub, tenant="t1").get(
        "/api/pxmx/drive-health?tenant=t1").json()

    assert body["nodes"] == [], "stale rows resurrected over a real empty answer"
    assert not body.get("stale")
    assert body["spoke_connected"] is True


def test_total_spoke_silence_still_falls_back():
    """The counterpart: nothing answered, so the cache is the right answer."""
    hub = _MockHub(bound_spoke="pxmx-1")
    hub.seed_warm(_NS, "t1|node=", _cached_payload(), age_s=60)

    async def _boom(*a, **k):
        raise RuntimeError("Timed out waiting for spoke response")

    hub.request_response = _boom
    body = _build_client(hub, tenant="t1").get(
        "/api/pxmx/drive-health?tenant=t1").json()

    assert body["stale"] is True
    assert body["spoke_connected"] is False
    assert [n["node"] for n in body["nodes"]] == ["pve1"]
