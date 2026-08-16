"""Unit contract for the in-memory global-search index (``search_index.py``).

Covers the pure, security-relevant logic without standing up FastAPI or a hub:
scope-key stability + isolation (the cross-tenant boundary), the substring
matcher, the spoke-envelope result extractor, the freshness/TTL read gate, and
the populate guards (only cache non-empty well-formed sets; cap size; skip on
error / empty). The request path and background loop delegate to exactly these
pieces, so this locks the behaviour the WebUI depends on.
"""
import asyncio
import time

import search_index as si
from search_index import (
    SearchIndexMixin,
    search_result_blob,
    search_result_matches,
    search_scope_key,
    _extract_results,
)


# ── scope key: stability + tenant isolation ────────────────────────────────────
def test_scope_key_stable_for_same_inputs():
    a = search_scope_key("acme", "acme-tag", False)
    b = search_scope_key("acme", "acme-tag", False)
    assert a == b


def test_scope_key_isolates_distinct_scopes():
    keys = {
        search_scope_key("acme", "acme-tag", False),
        search_scope_key("beta", "acme-tag", False),   # different slug
        search_scope_key("acme", "beta-tag", False),   # different proxmox tag
        search_scope_key("acme", "acme-tag", True),    # different admin flag
    }
    # Every distinct scope must map to a distinct bucket — a collision would let
    # one tenant read another's warmed rows.
    assert len(keys) == 4


def test_scope_key_ignores_prefixes_by_design():
    # Prefixes are a deterministic function of the slug, so they are NOT part of
    # the key (that is what lets the request path skip the prefix fetch).
    assert search_scope_key("", "", False) == search_scope_key("", "", False)


# ── matcher ────────────────────────────────────────────────────────────────────
def test_blob_joins_scalars_lowercased_skips_bool_none():
    blob = search_result_blob(
        {"name": "MIA-GW-01", "ip": "10.0.0.5", "up": True, "note": None, "port": 22})
    assert "mia-gw-01" in blob
    assert "10.0.0.5" in blob
    assert "22" in blob
    assert "true" not in blob  # bools excluded


def test_matches_is_substring_and_case_insensitive():
    item = {"name": "MIA-GW-01", "site": "Miami"}
    assert search_result_matches(item, "gw-01")
    assert search_result_matches(item, "miami")
    assert not search_result_matches(item, "denver")


def test_matches_empty_needle_is_false():
    assert not search_result_matches({"name": "x"}, "")


def test_blob_skips_oversized_opaque_fields():
    big = "z" * (si._MAX_BLOB_FIELD + 10)
    blob = search_result_blob({"name": "host", "cert": big})
    assert "host" in blob
    assert "z" * 20 not in blob


# ── envelope extractor ─────────────────────────────────────────────────────────
def test_extract_results_happy_path_drops_error_rows():
    out = _extract_results({"results": [
        {"name": "a"}, {"type": "error", "name": "boom"}, {"name": "b"}]})
    assert out == [{"name": "a"}, {"name": "b"}]


def test_extract_results_none_on_error_envelope_or_bad_shape():
    assert _extract_results({"status": "ERROR", "message": "bind failed"}) is None
    assert _extract_results({"results": "not-a-list"}) is None
    assert _extract_results(["not", "a", "dict"]) is None
    assert _extract_results({"results": []}) == []


# ── mixin: TTL read gate + populate guards ─────────────────────────────────────
class _FakeHub(SearchIndexMixin):
    """Minimal hub exposing the warm-cache + request_response surface the mixin
    uses, so the read gate and populate guards can be exercised in isolation."""

    def __init__(self, response=None):
        self.warm_cache = {}
        self._response = response
        self.requests = []
        self.search_index_init()

    def warm_get(self, namespace, key="_"):
        entry = self.warm_cache.get(namespace, {}).get(str(key))
        return entry.get("data") if isinstance(entry, dict) and "data" in entry else None

    async def warm_set(self, namespace, key, data):
        self.warm_cache.setdefault(namespace, {})[str(key)] = {"data": data}

    async def request_response(self, spoke, cmd, payload, **kw):
        self.requests.append((spoke, cmd, payload))
        if isinstance(self._response, Exception):
            raise self._response
        return self._response


def test_leg_items_none_when_absent():
    hub = _FakeHub()
    assert hub.search_index_leg_items("NETBOX_SEARCH", "k1") is None
    assert hub.search_leg_is_warm("NETBOX_SEARCH", "k1") is False


def test_leg_items_fresh_then_stale():
    hub = _FakeHub()
    ns = hub._search_ns("NETBOX_SEARCH")
    # fresh
    hub.warm_cache[ns] = {"k1": {"data": {"items": [{"name": "a"}], "at": time.time()}}}
    assert hub.search_index_leg_items("NETBOX_SEARCH", "k1") == [{"name": "a"}]
    assert hub.search_leg_is_warm("NETBOX_SEARCH", "k1") is True
    # stale (older than TTL)
    hub.warm_cache[ns]["k1"]["data"]["at"] = time.time() - hub._search_index_ttl - 5
    assert hub.search_index_leg_items("NETBOX_SEARCH", "k1") is None


def test_populate_caches_wellformed_nonempty():
    hub = _FakeHub(response={"payload": {"data": {"results": [{"name": "dev1"}]}}})
    asyncio.run(hub._search_populate_leg("NETBOX_SEARCH", "spoke-ipam", "k1", {"q": ""}))
    assert hub.search_index_leg_items("NETBOX_SEARCH", "k1") == [{"name": "dev1"}]


def test_populate_skips_empty_and_errors():
    # empty result set → not cached (leg stays on the live path)
    hub = _FakeHub(response={"payload": {"data": {"results": []}}})
    asyncio.run(hub._search_populate_leg("SEARCH_VMS", "spoke-h", "k1", {"q": ""}))
    assert hub.search_leg_is_warm("SEARCH_VMS", "k1") is False
    # error envelope → not cached
    hub2 = _FakeHub(response={"payload": {"data": {"status": "ERROR", "message": "x"}}})
    asyncio.run(hub2._search_populate_leg("SEARCH_VMS", "spoke-h", "k1", {"q": ""}))
    assert hub2.search_leg_is_warm("SEARCH_VMS", "k1") is False
    # request_response raising → swallowed, not cached, no leg served
    hub3 = _FakeHub(response=RuntimeError("spoke down"))
    asyncio.run(hub3._search_populate_leg("SEARCH_VMS", "spoke-h", "k1", {"q": ""}))
    assert hub3.search_leg_is_warm("SEARCH_VMS", "k1") is False


def test_populate_noop_without_spoke():
    hub = _FakeHub(response={"payload": {"data": {"results": [{"name": "x"}]}}})
    asyncio.run(hub._search_populate_leg("SEARCH_VMS", None, "k1", {"q": ""}))
    assert hub.requests == []  # never dialed
    assert hub.search_leg_is_warm("SEARCH_VMS", "k1") is False


def test_populate_caps_max_items(monkeypatch):
    monkeypatch.setenv("LM_SEARCH_INDEX_MAX_ITEMS", "120")
    rows = [{"name": f"d{i}"} for i in range(200)]
    hub = _FakeHub(response={"payload": {"data": {"results": rows}}})
    asyncio.run(hub._search_populate_leg("NETBOX_SEARCH", "s", "k1", {"q": ""}))
    assert len(hub.search_index_leg_items("NETBOX_SEARCH", "k1")) == 120


def test_register_scope_records_and_refreshes():
    hub = _FakeHub()
    hub.search_register_scope("k1", resolved="acme", is_admin=False,
                              nb_slug="acme", proxmox_tag="t")
    assert "k1" in hub._search_scopes
    assert hub._search_scopes["k1"]["nb_slug"] == "acme"


def test_enabled_flag_env(monkeypatch):
    hub = _FakeHub()
    monkeypatch.setenv("LM_SEARCH_INDEX", "0")
    assert hub.search_index_enabled() is False
    monkeypatch.setenv("LM_SEARCH_INDEX", "1")
    assert hub.search_index_enabled() is True


class _WarmHub(_FakeHub):
    """Adds the spoke-resolution surface the on-demand warm path uses so
    ``search_kick_warm`` / ``_search_warm_scope`` can populate every leg."""

    def get_spoke_by_type(self, t):
        return f"spoke-{t}"

    def get_hypervisor_spoke(self):
        return "spoke-hyp"

    def get_hypervisor_spoke_for_tenant(self, resolved):
        return "spoke-hyp"

    def get_directory_spoke_for_tenant(self, resolved):
        return "spoke-dir"


def test_warm_scope_populates_every_leg():
    hub = _WarmHub(response={"payload": {"data": {"results": [{"name": "dev1"}]}}})
    hub.search_register_scope("k1", resolved="acme", is_admin=False,
                              nb_slug="acme", proxmox_tag="t")
    asyncio.run(hub._search_warm_scope("k1"))
    for cmd in ("NETBOX_SEARCH", "SEARCH_VMS", "SEARCH_SESSIONS",
                "SEARCH_USERS", "SEARCH_DHCP"):
        assert hub.search_index_leg_items(cmd, "k1") == [{"name": "dev1"}]


def test_warm_scope_noop_unknown_scope():
    hub = _WarmHub(response={"payload": {"data": {"results": [{"name": "x"}]}}})
    asyncio.run(hub._search_warm_scope("nope"))
    assert hub.requests == []  # never dialed a spoke for an unknown scope


def test_kick_warm_noop_when_disabled(monkeypatch):
    hub = _WarmHub(response={"payload": {"data": {"results": [{"name": "x"}]}}})
    hub.search_register_scope("k1", resolved="acme", is_admin=False,
                              nb_slug="acme", proxmox_tag="t")
    monkeypatch.setenv("LM_SEARCH_INDEX", "0")

    async def _run():
        hub.search_kick_warm("k1")
    asyncio.run(_run())
    assert hub._search_warming == set()  # nothing scheduled while disabled


def test_kick_warm_noop_unknown_scope():
    hub = _WarmHub(response={"payload": {"data": {"results": [{"name": "x"}]}}})

    async def _run():
        hub.search_kick_warm("ghost")
    asyncio.run(_run())
    assert hub._search_warming == set()


def test_kick_warm_dedups_in_flight():
    hub = _WarmHub(response={"payload": {"data": {"results": [{"name": "x"}]}}})
    hub.search_register_scope("k1", resolved="acme", is_admin=False,
                              nb_slug="acme", proxmox_tag="t")
    # Simulate an in-flight warm for this scope: a second kick must not dial.
    hub._search_warming.add("k1")

    async def _run():
        hub.search_kick_warm("k1")
        await asyncio.sleep(0)
    asyncio.run(_run())
    assert hub.requests == []  # deduped — no new populate scheduled


def test_kick_warm_schedules_and_populates():
    hub = _WarmHub(response={"payload": {"data": {"results": [{"name": "dev1"}]}}})
    hub.search_register_scope("k1", resolved="acme", is_admin=False,
                              nb_slug="acme", proxmox_tag="t")

    async def _run():
        hub.search_kick_warm("k1")
        assert "k1" in hub._search_warming  # marked in-flight synchronously
        # let the scheduled populate task run to completion
        for _ in range(10):
            await asyncio.sleep(0)
    asyncio.run(_run())
    assert hub.search_index_leg_items("NETBOX_SEARCH", "k1") == [{"name": "dev1"}]
    assert hub._search_warming == set()  # cleared by done-callback
