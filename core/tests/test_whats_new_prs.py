"""Unit tests for the merged-GitHub-PR "What's New" source (``whats_new_prs.py``).

This is the SECOND, independent source merged into ``GET /api/whats-new``
alongside the bug-store (``_committed_features``, see ``test_whats_new.py``,
UNCHANGED by this file). It classifies a merged PR from its HEAD BRANCH NAME
(the reliable signal — branch names consistently use ``feat/``, ``fix/``,
``perf/``; titles are inconsistent), and excludes ``promote/*`` /
``backmerge/*`` release-flow carrier PRs. Pure logic is exercised offline with
fixed timestamps (mirroring ``test_whats_new.py``'s ``NOW``/``DAY`` style); the
network fetch is driven with a fake async client (mirroring
``test_github_config_client.py``'s ``FakeClient``/``FakeResp`` pattern), never
real HTTP.
"""
import asyncio
import time
from datetime import datetime, timezone

import pytest

import whats_new_prs as wn

NOW = 1_000_000_000
DAY = 86400
RECENT = NOW - DAY  # inside the 14-day window


@pytest.fixture(autouse=True)
def _clear_pr_cache():
    wn._CACHE.clear()
    yield
    wn._CACHE.clear()


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── classify_pr_branch ───────────────────────────────────────────────────────

@pytest.mark.parametrize("ref,expected", [
    ("feat/x", "feature"),
    ("feature/x", "feature"),
    ("perf/x", "feature"),
    ("fix/x", "bug"),
    ("hotfix/x", "bug"),
    ("bugfix/x", "bug"),
    ("docs/x", None),
    ("promote/dev-to-qa", None),
    ("", None),
    (None, None),
])
def test_classify_pr_branch(ref, expected):
    assert wn.classify_pr_branch(ref) == expected


# ── pr_summary ───────────────────────────────────────────────────────────────

@pytest.mark.parametrize("title,expected", [
    ("feat(pxmx): add diagnostics", "add diagnostics"),
    ("fix: null spoke payload", "null spoke payload"),
    ("Improve DNS query names display", "Improve DNS query names display"),
    ("docs:", "docs:"),  # prefix-only strip would empty it -> fall back
])
def test_pr_summary(title, expected):
    assert wn.pr_summary(title) == expected


# ── is_excluded_pr ───────────────────────────────────────────────────────────

def test_is_excluded_pr_promote_branch():
    assert wn.is_excluded_pr("promote/qa-to-main", "promote: qa -> main") is True


def test_is_excluded_pr_backmerge_branch():
    assert wn.is_excluded_pr("backmerge/main-to-dev", "Backmerge main into dev") is True


def test_is_excluded_pr_normal_branch_is_not_excluded():
    assert wn.is_excluded_pr("feat/x", "some unrelated title") is False


def test_is_excluded_pr_title_prefix_is_case_insensitive():
    assert wn.is_excluded_pr("feat/some-branch", "Promote: something") is True


# ── merged_prs_to_items ──────────────────────────────────────────────────────

def test_merged_prs_to_items_realistic_mix():
    old = NOW - 20 * DAY
    prs = [
        # real PR #968: title carries no conventional prefix at all — branch is
        # the only reliable classification signal.
        {"number": 968, "title": "Improve DNS query names display",
         "html_url": "http://x/968", "merged_at": RECENT,
         "head_ref": "feat/ipam-reserve-from-ip"},
        # real PR #944: title says "fix(test-feed): ..." but the branch says
        # feat/ — branch wins, this must classify as a feature.
        {"number": 944, "title": "fix(test-feed): stabilize argv parsing",
         "html_url": "http://x/944", "merged_at": RECENT - 10,
         "head_ref": "feat/feed-full-fleet-argv"},
        {"number": 900, "title": "promote: qa -> main", "html_url": "http://x/900",
         "merged_at": RECENT, "head_ref": "promote/qa-to-main"},           # excluded: promote
        {"number": 800, "title": "docs: update readme", "html_url": "http://x/800",
         "merged_at": RECENT, "head_ref": "docs/update-readme"},          # excluded: unrecognised branch
        {"number": 700, "title": "fix: old bug", "html_url": "http://x/700",
         "merged_at": old, "head_ref": "fix/old-bug"},                    # excluded: outside window
        {"number": 600, "title": "fix: unmerged", "html_url": "http://x/600",
         "merged_at": None, "head_ref": "fix/unmerged"},                  # excluded: not merged
        {"number": 500, "title": "fix: null spoke payload", "html_url": "http://x/500",
         "merged_at": RECENT - 5, "head_ref": "fix/spoke-payload"},
    ]
    out = wn.merged_prs_to_items(prs, now=NOW, within_days=14)

    assert [it["id"] for it in out] == ["pr-968", "pr-500", "pr-944"]  # newest-first
    by_id = {it["id"]: it for it in out}
    assert by_id["pr-968"]["type"] == "feature"
    assert by_id["pr-968"]["summary"] == "Improve DNS query names display"
    assert by_id["pr-968"]["issue_url"] == "http://x/968"
    assert by_id["pr-944"]["type"] == "feature"  # branch-classified despite a fix()-titled PR
    assert by_id["pr-944"]["summary"] == "stabilize argv parsing"
    assert by_id["pr-500"]["type"] == "bug"
    assert by_id["pr-500"]["summary"] == "null spoke payload"
    for it in out:
        assert it["id"].startswith("pr-")
        assert it["type"] in ("feature", "bug")


def test_merged_prs_to_items_empty_input():
    assert wn.merged_prs_to_items([], now=NOW) == []
    assert wn.merged_prs_to_items(None, now=NOW) == []


# ── fetch_recent_merged_prs (fake async client, no real network) ────────────

class FakeResp:
    def __init__(self, status_code, json_data=None):
        self.status_code = status_code
        self._json = json_data if json_data is not None else []

    def json(self):
        return self._json


class FakeClient:
    def __init__(self, get_responses=None):
        self.get_calls = []
        self._get = list(get_responses or [])

    async def get(self, url, params=None, headers=None):
        self.get_calls.append({"url": url, "params": params, "headers": headers})
        return self._get.pop(0)


class RaisingClient:
    async def get(self, url, params=None, headers=None):
        raise ConnectionError("github unreachable")


def _pr(number, title, head_ref, merged_at_ts):
    return {"number": number, "title": title, "html_url": f"http://x/{number}",
            "merged_at": _iso(merged_at_ts) if merged_at_ts is not None else None,
            "head": {"ref": head_ref}}


def test_fetch_single_page_success():
    now = time.time()
    client = FakeClient(get_responses=[FakeResp(200, [_pr(1, "feat: add x", "feat/x", now - 3600)])])
    items = asyncio.run(wn.fetch_recent_merged_prs("o", "single-page", within_days=14, client=client))
    assert len(items) == 1
    assert items[0]["number"] == 1
    assert items[0]["title"] == "feat: add x"
    assert items[0]["html_url"] == "http://x/1"
    assert items[0]["head_ref"] == "feat/x"
    assert abs(items[0]["merged_at"] - (now - 3600)) < 2
    assert len(client.get_calls) == 1


def test_fetch_stops_pagination_when_page_all_old():
    now = time.time()
    old_page = [_pr(i, f"fix: old {i}", "fix/old", now - 30 * DAY) for i in range(50)]
    client = FakeClient(get_responses=[FakeResp(200, old_page)])
    items = asyncio.run(wn.fetch_recent_merged_prs("o", "all-old-page", within_days=14, client=client))
    assert len(client.get_calls) == 1  # never fetched a second page
    assert len(items) == 50            # page's items are still returned to the caller


def test_fetch_non_200_returns_empty_without_raising():
    client = FakeClient(get_responses=[FakeResp(404, {"message": "not found"})])
    items = asyncio.run(wn.fetch_recent_merged_prs("o", "not-found-repo", within_days=14, client=client))
    assert items == []


def test_fetch_exception_returns_empty_without_raising(caplog):
    items = asyncio.run(
        wn.fetch_recent_merged_prs("o", "unreachable-repo", within_days=14, client=RaisingClient()))
    assert items == []
    assert any("unreachable-repo" in r.message or "PR fetch failed" in r.message
               for r in caplog.records)


def test_fetch_caches_within_ttl():
    now = time.time()
    client = FakeClient(get_responses=[FakeResp(200, [_pr(9, "feat: z", "feat/z", now - 3600)])])
    first = asyncio.run(wn.fetch_recent_merged_prs("o", "cached-repo", within_days=14, client=client))
    second = asyncio.run(wn.fetch_recent_merged_prs("o", "cached-repo", within_days=14, client=client))
    assert first == second
    assert len(client.get_calls) == 1  # second call served from cache, no second GET


def test_http_timeout_is_five_seconds():
    assert wn._HTTP_TIMEOUT == 5.0


def test_fetch_cache_expires_after_ttl():
    now = time.time()
    client = FakeClient(get_responses=[
        FakeResp(200, [_pr(10, "feat: a", "feat/a", now - 3600)]),
        FakeResp(200, [_pr(11, "feat: b", "feat/b", now - 3600)]),
    ])
    asyncio.run(wn.fetch_recent_merged_prs("o", "expiring-repo", within_days=14, client=client))
    # Simulate TTL expiry by backdating the cache entry directly rather than sleeping.
    ts, items, ttl = wn._CACHE[("o", "expiring-repo", 14)]
    wn._CACHE[("o", "expiring-repo", 14)] = (ts - wn._WHATS_NEW_REPO_CACHE_TTL - 1, items, ttl)
    second = asyncio.run(wn.fetch_recent_merged_prs("o", "expiring-repo", within_days=14, client=client))
    assert len(client.get_calls) == 2
    assert second[0]["number"] == 11


def test_fetch_error_does_not_poison_cache_for_long_ttl():
    now = time.time()
    error_client = FakeClient(get_responses=[FakeResp(500, {"message": "internal error"})])
    items1 = asyncio.run(wn.fetch_recent_merged_prs("o", "err-repo", within_days=14, client=error_client))
    assert items1 == []
    entry = wn._CACHE.get(("o", "err-repo", 14))
    assert entry is not None
    assert entry[2] == wn._WHATS_NEW_NEGATIVE_CACHE_TTL

    ts, items, ttl = entry
    wn._CACHE[("o", "err-repo", 14)] = (ts - wn._WHATS_NEW_NEGATIVE_CACHE_TTL - 1, items, ttl)
    working_client = FakeClient(get_responses=[FakeResp(200, [_pr(100, "feat: recovered", "feat/rec", now - 3600)])])
    items2 = asyncio.run(wn.fetch_recent_merged_prs("o", "err-repo", within_days=14, client=working_client))
    assert len(items2) == 1
    assert items2[0]["number"] == 100

    wn._CACHE.clear()
    rate_client = FakeClient(get_responses=[FakeResp(403, {"message": "rate limit"})])
    items3 = asyncio.run(wn.fetch_recent_merged_prs("o", "rate-repo", within_days=14, client=rate_client))
    assert items3 == []
    entry2 = wn._CACHE.get(("o", "rate-repo", 14))
    assert entry2 is not None
    assert entry2[2] == wn._WHATS_NEW_NEGATIVE_CACHE_TTL

    ts2, items2_cached, ttl2 = entry2
    wn._CACHE[("o", "rate-repo", 14)] = (ts2 - wn._WHATS_NEW_NEGATIVE_CACHE_TTL - 1, items2_cached, ttl2)
    working_client2 = FakeClient(get_responses=[FakeResp(200, [_pr(101, "fix: recovered", "fix/rec", now - 3600)])])
    items4 = asyncio.run(wn.fetch_recent_merged_prs("o", "rate-repo", within_days=14, client=working_client2))
    assert len(items4) == 1
    assert items4[0]["number"] == 101


def test_negative_cache_expires_after_short_ttl():
    now = time.time()
    error_client = FakeClient(get_responses=[FakeResp(500, {"message": "server error"})])
    items1 = asyncio.run(wn.fetch_recent_merged_prs("o", "neg-repo", within_days=14, client=error_client))
    assert items1 == []

    # Entry is cached with short negative TTL (30s), not repo TTL (3600s)
    cache_entry = wn._CACHE.get(("o", "neg-repo", 14))
    assert cache_entry is not None
    ts, cached_items, ttl = cache_entry
    assert cached_items == []
    assert ttl == wn._WHATS_NEW_NEGATIVE_CACHE_TTL
    assert ttl == 30.0

    # Within negative TTL: returns cached [] without calling client
    items_cached = asyncio.run(wn.fetch_recent_merged_prs("o", "neg-repo", within_days=14, client=FakeClient()))
    assert items_cached == []

    # After expiry: re-fetches and recovers
    wn._CACHE[("o", "neg-repo", 14)] = (ts - wn._WHATS_NEW_NEGATIVE_CACHE_TTL - 1, cached_items, ttl)
    working_client = FakeClient(get_responses=[FakeResp(200, [_pr(200, "feat: recovered", "feat/rec", now - 3600)])])
    items2 = asyncio.run(wn.fetch_recent_merged_prs("o", "neg-repo", within_days=14, client=working_client))
    assert len(items2) == 1
    assert items2[0]["number"] == 200
    assert len(working_client.get_calls) == 1


def test_cache_key_includes_within_days():
    now = time.time()
    client14 = FakeClient(get_responses=[FakeResp(200, [_pr(14, "feat: 14d", "feat/14", now - 3600)])])
    client30 = FakeClient(get_responses=[FakeResp(200, [_pr(30, "feat: 30d", "feat/30", now - 3600)])])

    items14 = asyncio.run(wn.fetch_recent_merged_prs("o", "window-repo", within_days=14, client=client14))
    items30 = asyncio.run(wn.fetch_recent_merged_prs("o", "window-repo", within_days=30, client=client30))

    assert len(items14) == 1 and items14[0]["number"] == 14
    assert len(items30) == 1 and items30[0]["number"] == 30
    assert ("o", "window-repo", 14) in wn._CACHE
    assert ("o", "window-repo", 30) in wn._CACHE
    assert wn._CACHE[("o", "window-repo", 14)] != wn._CACHE[("o", "window-repo", 30)]


def test_fetch_pages_continues_past_page_of_closed_unmerged_prs():
    now = time.time()
    page1 = [
        {
            "number": 1000 + i,
            "title": f"chore: unmerged {i}",
            "html_url": f"http://x/{1000 + i}",
            "merged_at": None,
            "updated_at": _iso(now - 100 - i),
            "head": {"ref": "chore/unmerged"},
        }
        for i in range(50)
    ]
    page2 = [
        {
            "number": 42,
            "title": "feat: merged on page 2",
            "html_url": "http://x/42",
            "merged_at": _iso(now - 3600),
            "updated_at": _iso(now - 3600),
            "head": {"ref": "feat/page2"},
        }
    ]
    client = FakeClient(get_responses=[FakeResp(200, page1), FakeResp(200, page2)])
    items = asyncio.run(wn._fetch_pages("o", "two-page-repo", within_days=14, client=client))
    assert len(client.get_calls) == 2
    assert len(items) == 51
    merged = [p for p in items if p["number"] == 42]
    assert len(merged) == 1
    assert merged[0]["merged_at"] is not None


def test_fetch_pages_preserves_partial_results_on_page2_error():
    now = time.time()
    page1 = [
        {
            "number": 1,
            "title": "feat: merged on page 1",
            "html_url": "http://x/1",
            "merged_at": _iso(now - 3600),
            "updated_at": _iso(now - 3600),
            "head": {"ref": "feat/page1"},
        }
    ] + [
        {
            "number": 100 + i,
            "title": f"fix: other {i}",
            "html_url": f"http://x/{100 + i}",
            "merged_at": None,
            "updated_at": _iso(now - 3600),
            "head": {"ref": "fix/other"},
        }
        for i in range(49)
    ]
    client = FakeClient(get_responses=[FakeResp(200, page1), FakeResp(403, {"message": "rate limit"})])
    items = asyncio.run(wn._fetch_pages("o", "partial-repo", within_days=14, client=client))
    assert len(client.get_calls) == 2
    assert len(items) == 50
    assert items[0]["number"] == 1
    assert items[0]["merged_at"] is not None


# ── merge/dedupe (setup_admin._dedupe_and_cap) ───────────────────────────────
# No pure helper lives in this module for the merge step — it's factored as a
# small pure function in routes/setup_admin.py (shared by the whats_new() route
# without duplicating _committed_features' sort/cap logic). Exercised directly
# here per the task's coverage requirement.

def test_dedupe_and_cap_bug_store_item_wins_over_pr_duplicate():
    from routes.setup_admin import _dedupe_and_cap
    bug_item = {"id": "b1", "summary": "Null spoke payload", "type": "bug",
                "fixed_at": RECENT, "issue_url": "http://issue/1"}
    pr_dup = {"id": "pr-500", "summary": "null   spoke  payload", "type": "bug",
              "fixed_at": RECENT - 5, "issue_url": "http://x/500"}
    pr_other = {"id": "pr-501", "summary": "Something else", "type": "feature",
                "fixed_at": RECENT - 1, "issue_url": "http://x/501"}
    out = _dedupe_and_cap([bug_item, pr_dup, pr_other])
    assert [it["id"] for it in out] == ["b1", "pr-501"]  # pr-500 dropped as a duplicate


def test_dedupe_and_cap_caps_at_limit():
    from routes.setup_admin import _dedupe_and_cap
    items = [{"id": str(i), "summary": f"item {i}", "type": "bug",
              "fixed_at": RECENT - i, "issue_url": ""} for i in range(5)]
    out = _dedupe_and_cap(items, limit=3)
    assert [it["id"] for it in out] == ["0", "1", "2"]  # newest-first, capped


def test_dedupe_and_cap_empty():
    from routes.setup_admin import _dedupe_and_cap
    assert _dedupe_and_cap([]) == []
