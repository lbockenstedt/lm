"""CVE lookup: Debian version ordering, debsecan feed matching, and the hub's
"who is affected by CVE-X?" search over the inventory nodes report."""
import asyncio
import os
import sys
import zlib

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import os_cve  # noqa: E402
import os_update  # noqa: E402
from os_cve import Feed, match_node, version_compare  # noqa: E402
from test_hub_os_updates import _FakeHub  # noqa: E402

FEED = zlib.compress("\n".join([
    "VERSION 1",
    "CVE-2026-0001,,PHP heap overflow",
    "CVE-2026-0002,,unfixed thing in foo-bin",
    "CVE-2026-0003,,another PHP issue",
    "",
    "php8.4,0, HRF,8.4.10-1,8.4.5-1~deb13u2",
    "foo-bin,1,B   ,,",
    "php8.4,2, L F,8.4.10-1,8.4.5-1~deb13u1 8.4.5-1~deb13u2",
    "",
    "",
]).encode())


@pytest.mark.parametrize("a,b,sign", [
    ("1.0~rc1", "1.0", -1),
    ("1:0.9", "2.0", 1),
    ("2.10", "2.9", 1),
    ("1.0", "1.0-0", 0),
    ("8.4.5-1~deb13u1", "8.4.5-1~deb13u2", -1),
    ("8.4.5-1~deb13u2", "8.4.5-1", -1),
    ("1.2.3+dfsg-1", "1.2.3-1", 1),
])
def test_version_compare_follows_dpkg(a, b, sign):
    r = version_compare(a, b)
    assert (r > 0) - (r < 0) == sign


def test_match_by_source_package_with_patched_release_version():
    feed = Feed(FEED)
    entries = [feed.entry(ln) for ln in feed.by_cve["CVE-2026-0001"]]
    old = [["php8.4-cli", "8.4.5-1~deb13u1", "php8.4", "8.4.5-1~deb13u1"]]
    fixed = [["php8.4-cli", "8.4.5-1~deb13u2", "php8.4", "8.4.5-1~deb13u2"]]
    hit = match_node(feed, old, entries, pending=["php8.4-cli"])
    assert [(a["cve"], a["binaries"], a["update_pending"]) for a in hit["affected"]] == \
        [("CVE-2026-0001", ["php8.4-cli"], True)]
    assert hit["affected"][0]["urgency"] == "high" and hit["affected"][0]["remote"] is True
    miss = match_node(feed, fixed, entries)
    assert not miss["affected"] and miss["patched"][0]["package"] == "php8.4"
    assert match_node(feed, [["vim", "9.1-1"]], entries) == {"affected": [], "patched": []}


def test_binary_entry_without_fix_matches_any_version():
    feed = Feed(FEED)
    entries = [feed.entry(ln) for ln in feed.by_cve["CVE-2026-0002"]]
    hit = match_node(feed, [["foo-bin", "1.0-1"]], entries)
    assert hit["affected"][0]["fix_available"] is False


def _cve_hub(tmp_path):
    hub = _FakeHub(connections={"s1": object(), "s2": object(), "s3": object()},
                   module_metadata={k: {"display_name": k.upper()} for k in ("s1", "s2", "s3")})
    hub.cache_dir = str(tmp_path)
    inv = lambda ver: {"os": {"id": "debian", "codename": "trixie"},  # noqa: E731
                       "installed": [["php8.4-cli", ver, "php8.4", ver], ["vim", "9.1-1"]]}
    hub._responses = {
        "s1": {"eligible": True, "packages": [{"package": "php8.4-cli"}], "count": 1, **inv("8.4.5-1~deb13u1")},
        "s2": {"eligible": True, **inv("8.4.5-1~deb13u2")},
        "s3": {"eligible": True},  # older LM: no inventory reported
    }
    fc = os_cve.FeedCache(str(tmp_path))
    fc._download = lambda codename: FEED
    hub._osu_cve_feeds = fc
    asyncio.run(hub.osu_check_fleet(refresh=False))
    return hub


def test_cve_search_lists_affected_patched_and_unknown_nodes(tmp_path):
    hub = _cve_hub(tmp_path)
    assert "inventory" not in str(hub.osu_snapshot()["nodes"])
    r = asyncio.run(hub.osu_cve_search("cve-2026-0001"))
    assert r["kind"] == "cve" and r["known"] and r["affected_nodes"] == 1 and r["checked_nodes"] == 2
    [res] = r["results"]
    assert [(a["label"], a["update_pending"]) for a in res["affected"]] == [("S1", True)]
    assert [a["label"] for a in res["patched"]] == ["S2"]
    assert [u["label"] for u in r["unknown"]] == ["S3"]


def test_cve_search_unknown_cve_and_package_query(tmp_path):
    hub = _cve_hub(tmp_path)
    r = asyncio.run(hub.osu_cve_search("CVE-2026-9999"))
    assert not r["known"] and r["results"] == []
    r = asyncio.run(hub.osu_cve_search("php"))
    assert r["kind"] == "package"
    # CVE-2026-0003 lists S1's ~deb13u1 as a fixed version, so only 0001 hits.
    assert {x["cve"]: [a["label"] for a in x["affected"]] for x in r["results"]} == \
        {"CVE-2026-0001": ["S1"]}


def test_inventory_survives_unreachable_check_and_hub_restart(tmp_path):
    hub = _cve_hub(tmp_path)

    async def _recheck_and_flush():
        hub._responses.pop("s1")
        await hub.osu_check_fleet(refresh=False)
        await hub._osu_file().flush_now()
    asyncio.run(_recheck_and_flush())
    assert "spoke:s1" in hub._osu_state()["inventory"]
    fresh = _FakeHub()
    fresh.cache_dir = str(tmp_path)
    fresh.osu_load_state()
    assert set(fresh._osu_state()["inventory"]) == {"spoke:s1", "spoke:s2"}


def test_installed_packages_parses_dpkg_query(monkeypatch):
    class _R:
        stdout = ("ii \tphp8.4-cli\t8.4.5-1\tphp8.4\t8.4.5-1\n"
                  "ii \tvim\t2:9.1-1\tvim\t2:9.1-1\n"
                  "rc \tgone\t1.0\tgone\t1.0\n")
    monkeypatch.setattr(os_update, "_run", lambda argv, t: _R())
    assert os_update.installed_packages() == [
        ["php8.4-cli", "8.4.5-1", "php8.4", "8.4.5-1"], ["vim", "2:9.1-1"]]
