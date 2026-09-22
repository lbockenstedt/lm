"""Merged-GitHub-PR source for the "What's New" popover (routes/setup_admin.py) -
independent of the bug-store (AB's filed-and-fixed-report cascade), which only
ever contains items that started life as a WebUI "File a Bug" report. A leaf:
stdlib + httpx only, no import of main/api/hub."""
from __future__ import annotations

import logging
import re
import threading
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from routes.github_source import _headers, _token  # noqa: F401 -- same env-var fallback chain

logger = logging.getLogger(__name__)

API = "https://api.github.com"
_HTTP_TIMEOUT = 20.0

_PR_EXCLUDE_BRANCH_PREFIXES = ("promote/", "backmerge/")
_PR_EXCLUDE_TITLE_PREFIXES = ("promote:", "backmerge:")
#: branch prefix -> "feature" | "bug". First match wins; unmatched branches are skipped
#: (not surfaced) rather than guessed, since a wrong guess is worse than an omission.
_PR_BRANCH_TYPE = (
    ("feat/", "feature"), ("feature/", "feature"), ("perf/", "feature"),
    ("fix/", "bug"), ("hotfix/", "bug"), ("bugfix/", "bug"),
)
_CONVENTIONAL_TITLE_RE = re.compile(
    r"^(feat|fix|perf|docs|chore|refactor|test|style|build|ci)(\([^)]*\))?:\s*", re.I)

# Default repo list: just this product itself. Widenable later via
# global_config["whats_new_repos"] (see routes/setup_admin.py) to cover the rest
# of the fleet (cs, pxmx, ...) without changing this module.
_WHATS_NEW_REPOS = ("lbockenstedt/lm",)

# 1h: matches github_source.py's CACHE_TTL_SECONDS reasoning (source activity
# changes on a human timescale; a warm cache keeps popover opens offline).
_WHATS_NEW_REPO_CACHE_TTL = 3600.0
_WHATS_NEW_NEGATIVE_CACHE_TTL = 30.0
_CACHE: Dict[Tuple[str, str], Tuple[float, list]] = {}
_CACHE_LOCK = threading.Lock()


def classify_pr_branch(head_ref: Optional[str]) -> Optional[str]:
    """"feature" | "bug" | None (branch prefix not recognised -> caller skips it)."""
    ref = (head_ref or "").strip().lower()
    if not ref:
        return None
    for prefix, kind in _PR_BRANCH_TYPE:
        if ref.startswith(prefix):
            return kind
    return None


def pr_summary(title: str) -> str:
    """Title with a leading conventional-commit prefix ("feat(scope): ", "fix: ", ...)
    stripped, else the title unchanged. Never empty (falls back to the original title
    if stripping would empty it)."""
    t = title or ""
    stripped = _CONVENTIONAL_TITLE_RE.sub("", t, count=1).strip()
    return stripped if stripped else t


def is_excluded_pr(head_ref: Optional[str], title: Optional[str]) -> bool:
    """True for a promote/backmerge carrier PR (branch prefix OR title prefix,
    case-insensitive) - these carry no new content of their own, the real PR
    already appears separately."""
    ref = (head_ref or "").strip().lower()
    t = (title or "").strip().lower()
    return ref.startswith(_PR_EXCLUDE_BRANCH_PREFIXES) or t.startswith(_PR_EXCLUDE_TITLE_PREFIXES)


def merged_prs_to_items(prs: list, *, now: float = None, within_days: int = 14) -> list:
    """Recently-merged PRs -> items shaped exactly like ``_committed_features``'s
    output. Skips: not merged (``merged_at`` falsy), excluded
    (promote/backmerge, see ``is_excluded_pr``), older than ``within_days``, and
    an unrecognised branch prefix (``classify_pr_branch`` returns None). Pure,
    no network. Newest-first by ``fixed_at``; no cap here (the caller merges
    this with the bug-store source and caps once)."""
    if now is None:
        now = time.time()
    cutoff = now - within_days * 86400
    items = []
    for pr in prs or []:
        merged_at = pr.get("merged_at")
        if not merged_at:
            continue
        head_ref = pr.get("head_ref")
        title = pr.get("title") or ""
        if is_excluded_pr(head_ref, title):
            continue
        if merged_at < cutoff:
            continue
        kind = classify_pr_branch(head_ref)
        if kind is None:
            continue
        items.append({
            "id": f"pr-{pr.get('number')}",
            "summary": pr_summary(title),
            "type": kind,
            "fixed_at": merged_at,
            "issue_url": pr.get("html_url") or "",
        })
    items.sort(key=lambda x: x.get("fixed_at") or 0, reverse=True)
    return items


def _parse_iso(ts: str) -> Optional[float]:
    """GitHub's ISO-8601 ``2024-01-15T10:30:00Z`` -> epoch float. ``None`` on any
    parse failure (fail-soft: caller then treats the PR as unmerged/unaged)."""
    try:
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()
    except (TypeError, ValueError):
        return None


async def _fetch_pages(owner: str, repo: str, within_days: int, *, client=None) -> list:
    cutoff = time.time() - within_days * 86400
    own_client = client is None
    if own_client:
        import httpx
        client = httpx.AsyncClient(timeout=_HTTP_TIMEOUT)
    out: List[dict] = []
    try:
        for page in range(1, 4):  # hard cap: 3 pages / 150 PRs
            # No `base` filter: this repo's flow merges real feat/fix work into
            # `dev` (verified live - every feat/*/fix/* PR in the last 2 weeks
            # has base=dev; only the excluded promote/* carriers target main),
            # and hardcoding either branch name would silently return nothing
            # the moment the integration branch name changed. merged_prs_to_items
            # already filters to merged-only and excludes the promote/backmerge
            # carriers, so an unfiltered `state=closed` listing is exactly as
            # precise and far more robust.
            try:
                resp = await client.get(
                    f"{API}/repos/{owner}/{repo}/pulls",
                    params={"state": "closed", "sort": "updated",
                            "direction": "desc", "per_page": 50, "page": page},
                    headers=_headers())
            except Exception as e:
                logger.warning("whats-new: %s/%s pulls fetch failed on page %s: %s",
                               owner, repo, page, e)
                if page == 1:
                    raise
                break
            if resp.status_code != 200:
                logger.warning("whats-new: %s/%s pulls fetch returned HTTP %s",
                               owner, repo, resp.status_code)
                if page == 1:
                    raise RuntimeError(f"HTTP {resp.status_code}")
                break
            try:
                batch = resp.json()
            except Exception as e:
                logger.warning("whats-new: %s/%s invalid JSON on page %s: %s",
                               owner, repo, page, e)
                if page == 1:
                    raise
                break
            if not batch:
                break
            for pr in batch:
                merged_at = _parse_iso(pr.get("merged_at")) if pr.get("merged_at") else None
                out.append({
                    "number": pr.get("number"),
                    "title": pr.get("title") or "",
                    "html_url": pr.get("html_url") or "",
                    "merged_at": merged_at,
                    "head_ref": (pr.get("head") or {}).get("ref"),
                })
            ts_list = [
                (_parse_iso(p.get("updated_at") or p.get("merged_at")) or 0)
                for p in batch
                if (p.get("updated_at") or p.get("merged_at"))
            ]
            page_older_than_cutoff = bool(ts_list) and all(ts < cutoff for ts in ts_list)
            if page_older_than_cutoff or len(batch) < 50:
                break
        return out
    finally:
        if own_client:
            await client.aclose()


async def fetch_recent_merged_prs(owner: str, repo: str, within_days: int = 14, *,
                                  client=None) -> list:
    """Recently-merged PRs for ``owner/repo``, mapped to the shape
    ``merged_prs_to_items`` expects. TTL-cached per ``(owner, repo)`` so the
    popover does not hit GitHub on every open. Fail-soft: ANY error (network,
    non-200, bad JSON, a malformed item) logs a WARNING and returns ``[]`` for
    the whole call - this source must never break the "What's New" popover, it
    can only shrink it.
    """
    cache_key = (owner, repo)
    with _CACHE_LOCK:
        cached = _CACHE.get(cache_key)
    if cached and (time.time() - cached[0]) < _WHATS_NEW_REPO_CACHE_TTL:
        return cached[1]
    try:
        items = await _fetch_pages(owner, repo, within_days, client=client)
    except Exception as e:  # noqa: BLE001 -- fail-soft: degrade, never raise
        logger.warning("whats-new: %s/%s PR fetch failed: %s", owner, repo, e)
        return []
    with _CACHE_LOCK:
        _CACHE[cache_key] = (time.time(), items)
    return items
