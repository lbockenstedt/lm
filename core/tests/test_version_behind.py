"""Per-repo ".NN" behind-detection (update_pipeline).

Each provisioning repo (lm, cs, pxmx, netbox, opnsense, ldap, nw, cppm, le,
bugfixer) autobumps an INDEPENDENT ``.NN``. A spoke's ``.NN`` is only comparable
to the LATEST ``.NN`` of ITS OWN repo, so the hub resolves that latest locally
and flags a spoke "behind" only when BOTH sides are valid ``.NN`` and the spoke's
is strictly older. The cardinal rule is NEVER false-positive: any unknown /
non-``.NN`` on either side leaves the spoke NOT behind.

Covers the pure comparison helpers (``_parse_nn`` / ``_version_behind``) and the
mixin resolver (``latest_version_for_module``) incl. its mtime read cache.
"""

import asyncio
import os

import update_pipeline
from update_pipeline import (
    UpdatePipelineMixin,
    _parse_nn,
    _version_behind,
    _github_version_url,
    _VERSION_CHECK_TTL_S,
    _IN_LM_REPO_MODULE_TYPES,
    _MODULE_REPO_DIR,
)


def test_parse_nn():
    assert _parse_nn(".486") == 486
    assert _parse_nn(".0") == 0
    assert _parse_nn("  .400 ") == 400
    # Anything not on the .NN numbering → None (no comparison possible).
    for bad in ("unknown", "v.01", "1.2.3", "486", ".", ".x", "", None):
        assert _parse_nn(bad) is None, bad


def test_version_behind_true_when_strictly_older():
    assert _version_behind(".400", ".486") is True
    assert _version_behind(".0", ".1") is True


def test_version_behind_false_when_current_or_ahead():
    assert _version_behind(".486", ".486") is False   # current
    assert _version_behind(".500", ".486") is False   # ahead of a stale checkout


def test_version_behind_never_false_positive_on_unknown():
    # Either side unknown / non-.NN → NEVER behind (the invariant).
    assert _version_behind("unknown", ".486") is False
    assert _version_behind(".400", None) is False
    assert _version_behind(".400", "unknown") is False
    assert _version_behind("v.01", ".486") is False
    assert _version_behind("1.2.3", ".486") is False
    assert _version_behind(None, None) is False


class _StubHub(UpdatePipelineMixin):
    """Bare mixin instance — latest_version_for_module reads only VERSION files
    off disk (via the mtime cache), needing no other Hub state."""


def test_latest_version_for_module_reads_hub_version_for_in_repo_types():
    hub = _StubHub()
    # The hub's own VERSION (lm repo) backs dns/dhcp/console/agent.
    hub_version_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..", "VERSION"))
    expected = open(hub_version_path).read().strip()
    for mt in _IN_LM_REPO_MODULE_TYPES:
        assert hub.latest_version_for_module(mt) == expected


def test_latest_version_for_module_unknown_type_is_none():
    hub = _StubHub()
    # No repo mapping + not an in-lm-repo type → None → caller must not flag.
    assert hub.latest_version_for_module("totally-made-up") is None
    assert hub.latest_version_for_module("") is None
    assert hub.latest_version_for_module(None) is None


def test_latest_version_for_module_sibling_uses_local_checkout(tmp_path, monkeypatch):
    """A sibling repo resolves to a local VERSION checkout when one is present,
    and returns None when none of the candidate paths exist (no false-positive)."""
    hub = _StubHub()
    # "firewall" → opnsense repo per _MODULE_REPO_DIR.
    assert _MODULE_REPO_DIR["firewall"] == "opnsense"

    # No checkout anywhere → unknown latest.
    monkeypatch.setattr(hub, "_sibling_version_candidates",
                        lambda repo: [str(tmp_path / repo / "VERSION")])
    assert hub.latest_version_for_module("firewall") is None

    # Now stand up a local checkout and confirm it is read + cached by mtime.
    vpath = tmp_path / "opnsense" / "VERSION"
    vpath.parent.mkdir(parents=True)
    vpath.write_text(".612\n")
    assert hub.latest_version_for_module("firewall") == ".612"
    # A spoke reporting an older .NN is behind; a matching one is not.
    assert _version_behind(".600", hub.latest_version_for_module("firewall")) is True
    assert _version_behind(".612", hub.latest_version_for_module("firewall")) is False


def test_read_version_cached_reflects_change_on_mtime_bump(tmp_path):
    hub = _StubHub()
    p = tmp_path / "VERSION"
    p.write_text(".100\n")
    assert hub._read_version_cached(str(p)) == ".100"
    # Rewrite with a bumped mtime → cache invalidates and re-reads.
    os.utime(str(p), None)
    p.write_text(".101\n")
    os.utime(str(p), (10**9 + 5, 10**9 + 5))  # force a distinct mtime
    assert hub._read_version_cached(str(p)) == ".101"
    # Missing file → None (never raises).
    assert hub._read_version_cached(str(tmp_path / "nope" / "VERSION")) is None


# ── GitHub hourly latest-version cache ──────────────────────────────────────
# The version-bump bot COMMITS a `.NN` VERSION to the default branch (no tag),
# so the hub reads the latest from the raw VERSION file over HTTPS, hourly-cached
# with lazy stale-while-revalidate. No test makes a real network call — the fetch
# is mocked. The cardinal rule holds: a fetch failure NEVER false-positives.


def test_github_version_url():
    assert _github_version_url("opnsense") == (
        "https://raw.githubusercontent.com/lbockenstedt/opnsense/main/VERSION")
    assert _github_version_url("lm") == (
        "https://raw.githubusercontent.com/lbockenstedt/lm/main/VERSION")
    assert _github_version_url("cs", owner="acme", branch="dev") == (
        "https://raw.githubusercontent.com/acme/cs/dev/VERSION")


def test_github_latest_cached_serves_cache_never_calls_network(monkeypatch):
    """The sync cache read must NEVER hit the network — it reads the in-memory
    cache only. A fresh entry is served as-is; no refresh is scheduled."""
    hub = _StubHub()
    hub._github_version_cache = {"opnsense": (10**12, ".612")}  # far-future ts → fresh

    def _boom(*a, **k):  # any network fetch here is a bug
        raise AssertionError("network fetch in a synchronous cache read")

    monkeypatch.setattr(update_pipeline, "_fetch_github_version", _boom)
    assert hub._github_latest_cached("opnsense") == ".612"


def test_github_latest_cached_cold_returns_none_no_false_positive():
    """Cold cache (nothing fetched yet) → None. With no running loop the
    scheduled refresh is silently skipped, so this never raises and the spoke is
    never flagged behind."""
    hub = _StubHub()
    assert hub._github_latest_cached("netbox") is None
    assert _version_behind(".400", hub._github_latest_cached("netbox")) is False


def test_github_latest_cached_stale_reschedules_and_serves_last_good():
    hub = _StubHub()
    # Stale entry (ts older than TTL) is still SERVED while a refresh would be
    # scheduled (no loop here → skipped), so the last-good value keeps showing.
    stale_ts = 1.0  # epoch → definitely older than TTL
    hub._github_version_cache = {"cs": (stale_ts, ".300")}
    assert hub._github_latest_cached("cs") == ".300"


class _StateStub:
    """Minimal state exposing get_global_config — mirrors the real Hub state so
    _github_check_enabled can read repo_sync.enabled."""

    def __init__(self, cfg):
        self._cfg = cfg

    def get_global_config(self):
        return self._cfg


def _hub_with_repo_sync(enabled):
    hub = _StubHub()
    hub.state = _StateStub({"repo_sync": {"enabled": enabled}})
    return hub


def test_github_check_gated_by_repo_sync_enabled():
    # repo_sync replication OFF → version check OFF (None regardless of cache).
    off = _hub_with_repo_sync(False)
    off._github_version_cache = {"opnsense": (10**12, ".612")}
    assert off._github_latest_cached("opnsense") is None
    # repo_sync ON → cache served.
    on = _hub_with_repo_sync(True)
    on._github_version_cache = {"opnsense": (10**12, ".612")}
    assert on._github_latest_cached("opnsense") == ".612"


def test_github_check_defaults_enabled_without_state():
    # A stub/early hub with no .state → defaults enabled (never raises).
    hub = _StubHub()
    assert hub._github_check_enabled() is True
    hub._github_version_cache = {"cs": (10**12, ".5")}
    assert hub._github_latest_cached("cs") == ".5"


def test_refresh_all_module_versions_disabled_is_noop():
    hub = _hub_with_repo_sync(False)
    asyncio.run(hub._refresh_all_module_versions())
    # Disabled → nothing fetched, cache stays empty.
    assert hub.__dict__.get("_github_version_cache", {}) == {}


def test_refresh_all_module_versions_populates_all_repos(monkeypatch):
    hub = _hub_with_repo_sync(True)
    monkeypatch.setattr(update_pipeline, "_fetch_github_version",
                        lambda repo, *a, **k: ".999")
    asyncio.run(hub._refresh_all_module_versions())
    for repo in set(_MODULE_REPO_DIR.values()):
        assert hub._github_version_cache[repo][1] == ".999"


def test_refresh_github_version_stores_good_value(monkeypatch):
    hub = _StubHub()
    monkeypatch.setattr(update_pipeline, "_fetch_github_version",
                        lambda repo, *a, **k: ".700")
    asyncio.run(hub._refresh_github_version("opnsense"))
    entry = hub._github_version_cache["opnsense"]
    assert entry[1] == ".700"
    # TTL fresh now → served synchronously.
    assert hub._github_latest_cached("opnsense") == ".700"


def test_refresh_github_version_failure_keeps_last_good(monkeypatch):
    hub = _StubHub()
    # Seed a good value, then a failing fetch must KEEP it (reset TTL), not drop it.
    hub._github_version_cache = {"cs": (1.0, ".300")}
    monkeypatch.setattr(update_pipeline, "_fetch_github_version",
                        lambda repo, *a, **k: None)
    asyncio.run(hub._refresh_github_version("cs"))
    entry = hub._github_version_cache["cs"]
    assert entry[1] == ".300"          # last-good retained
    assert entry[0] > 1.0              # TTL reset so we don't hammer


def test_refresh_github_version_failure_cold_stays_none(monkeypatch):
    hub = _StubHub()
    monkeypatch.setattr(update_pipeline, "_fetch_github_version",
                        lambda repo, *a, **k: None)
    asyncio.run(hub._refresh_github_version("nw"))
    assert hub._github_version_cache["nw"][1] is None
    # No value ever → never behind.
    assert hub._github_latest_cached("nw") is None


def test_refresh_github_version_rejects_non_nn(monkeypatch):
    """A garbage / non-.NN body (e.g. an HTML 404 page) is treated as failure —
    never stored as a latest, so it can't false-positive."""
    hub = _StubHub()
    monkeypatch.setattr(update_pipeline, "_fetch_github_version",
                        lambda repo, *a, **k: "<html>Not Found</html>")
    asyncio.run(hub._refresh_github_version("le"))
    assert hub._github_version_cache["le"][1] is None


def test_latest_version_for_module_uses_github_when_no_local(monkeypatch):
    """With no local sibling checkout, latest resolves from the GitHub cache."""
    hub = _StubHub()
    monkeypatch.setattr(hub, "_sibling_version_candidates", lambda repo: [])
    hub._github_version_cache = {"opnsense": (10**12, ".900")}
    assert hub.latest_version_for_module("firewall") == ".900"
    assert _version_behind(".899", hub.latest_version_for_module("firewall")) is True


def test_ttl_boundary_is_stale(monkeypatch):
    """An entry exactly at/over the TTL edge is treated as stale (refresh path),
    but still served as last-good; a within-TTL entry is fresh."""
    import time as _t
    hub = _StubHub()
    now = _t.time()
    hub._github_version_cache = {"pxmx": (now - _VERSION_CHECK_TTL_S - 1, ".10")}
    # Stale but served.
    assert hub._github_latest_cached("pxmx") == ".10"
    hub._github_version_cache = {"pxmx": (now, ".11")}
    assert hub._github_latest_cached("pxmx") == ".11"
