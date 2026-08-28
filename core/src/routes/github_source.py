"""GitHub-backed source corpus for the Help assistant's ``search_source`` tool.

WHY THIS EXISTS
---------------
``search_source`` originally walked the local filesystem: the hub's own repo plus
any *sibling directories* named ``cs``/``pxmx`` that happened to be checked out
next to it. That works on a developer laptop and silently degrades to almost
nothing in production, where the hub is installed to ``/opt/lm`` and no sibling
repo exists. The client simulation scripts the assistant most needs to quote
(``clients/linux/*.sh``, ``clients/windows/*.ps1``) live in the ``cs`` repo and
are therefore invisible to a real deployment — the tool returns 0 hits and the
model concludes the feature doesn't exist.

Rather than shipping a vendored snapshot (which goes stale) or requiring a clone
(which needs a ``git`` binary and disk state), we read the code straight from
GitHub, mirroring the no-clone REST approach already used by
``simulations/github_config_client.py``.

TWO ENDPOINTS, TWO DIFFERENT LIMITS
-----------------------------------
* The **tree API** (``/git/trees/<branch>?recursive=1``) lists the whole repo in
  ONE request, but it is the endpoint that counts against the API rate limit
  (60/hr unauthenticated, 5000/hr with a token).
* **raw.githubusercontent.com** serves file bodies from a CDN and does *not*
  consume that API budget.

So we spend exactly one API call per refresh and pull the bodies from raw. The
whole simulation corpus is 49 files / ~610KB, small enough to hold in memory and
grep directly, so a warm cache costs zero network per question.

A token is optional — ``cs`` is public. Supplying one only raises the tree-API
limit.
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

API = "https://api.github.com"
RAW = "https://raw.githubusercontent.com"

# How long a fetched corpus stays usable before we re-check GitHub. Source code
# changes on a human timescale, so an hour keeps answers current while making
# the common case (several questions in one sitting) entirely offline.
CACHE_TTL_SECONDS = 3600
# Ceiling on a single file we will hold in memory. The sim scripts are a few KB;
# anything far larger is a vendored blob that would only add noise.
MAX_FILE_BYTES = 512_000
MAX_FILES = 400
_HTTP_TIMEOUT = 20.0


class SourceSpec:
    """One GitHub-hosted slice of source to make searchable.

    ``path_prefixes`` and ``exts`` are BOTH required to match, which is what
    keeps the corpus tight: the intent is the client simulation scripts, not the
    entire ``cs`` repo. Widening the scope later means adding a prefix here, not
    touching the search tool.
    """

    def __init__(self, owner: str, repo: str, branch: str,
                 path_prefixes: Tuple[str, ...], exts: Tuple[str, ...],
                 label: Optional[str] = None):
        self.owner = owner
        self.repo = repo
        self.branch = branch
        self.path_prefixes = path_prefixes
        self.exts = tuple(e.lower() for e in exts)
        self.label = label or repo

    def wants(self, path: str) -> bool:
        if not path.startswith(self.path_prefixes):
            return False
        return os.path.splitext(path)[1].lower() in self.exts

    @property
    def key(self) -> str:
        return f"{self.owner}/{self.repo}@{self.branch}"


def default_specs() -> List[SourceSpec]:
    """The shipped scope: the CS client simulation scripts, shell + PowerShell.

    Both platform variants are included on purpose — they are functional twins
    (see the repo's ``dual-copy-guard`` notes), and a question about a
    simulation is just as likely to be about the Windows side. ``clients/lib``
    carries the shared helpers those scripts source, without which a quoted
    snippet often can't be explained.

    Overridable via ``LM_HELP_SOURCE_REPO`` (``owner/name``) and
    ``LM_HELP_SOURCE_BRANCH`` for a fork or a release branch.
    """
    slug = (os.environ.get("LM_HELP_SOURCE_REPO") or "lbockenstedt/cs").strip()
    branch = (os.environ.get("LM_HELP_SOURCE_BRANCH") or "main").strip()
    owner, _, name = slug.partition("/")
    if not owner or not name:
        owner, name = "lbockenstedt", "cs"
    return [SourceSpec(
        owner=owner, repo=name, branch=branch,
        path_prefixes=("clients/linux/", "clients/windows/", "clients/lib/"),
        exts=(".sh", ".ps1"),
        label=name,
    )]


def _token() -> str:
    """Optional PAT. Only affects the tree-API rate limit; the target repo is
    public, so an absent token is a supported configuration, not a failure."""
    for var in ("LM_HELP_SOURCE_TOKEN", "GITHUB_TOKEN", "GH_TOKEN"):
        v = (os.environ.get(var) or "").strip()
        if v:
            return v
    return ""


def _headers() -> Dict[str, str]:
    h = {"Accept": "application/vnd.github+json",
         "User-Agent": "lm-help-assistant"}
    tok = _token()
    if tok:
        h["Authorization"] = f"Bearer {tok}"
    return h


class GitHubSourceCache:
    """In-memory, TTL'd corpus of ``(label/path -> text)``.

    Deliberately fail-soft: every public method returns whatever it already has
    on error. ``search_source`` is one input to an LLM answer, so a GitHub
    outage should degrade the answer, never raise into the user's question. The
    lock collapses concurrent refreshes so N simultaneous questions still cost
    one fetch.
    """

    def __init__(self, specs: Optional[List[SourceSpec]] = None,
                 ttl: int = CACHE_TTL_SECONDS):
        self._specs = specs if specs is not None else default_specs()
        self._ttl = ttl
        self._files: Dict[str, str] = {}
        self._fetched_at = 0.0
        self._last_error = ""
        # Created lazily, NOT here. This cache is constructed while the routes
        # are registered -- i.e. before/outside the running event loop -- and on
        # Python 3.9 asyncio.Lock() binds to the loop current at construction
        # time. Building it eagerly raises "There is no current event loop" at
        # import, or worse, silently binds to the wrong loop and deadlocks the
        # first refresh.
        self._lock_obj: Optional[asyncio.Lock] = None

    def _get_lock(self) -> asyncio.Lock:
        if self._lock_obj is None:
            self._lock_obj = asyncio.Lock()
        return self._lock_obj

    @property
    def fresh(self) -> bool:
        return bool(self._files) and (time.time() - self._fetched_at) < self._ttl

    def stats(self) -> Dict[str, object]:
        return {"files": len(self._files),
                "age_seconds": int(time.time() - self._fetched_at) if self._fetched_at else None,
                "repos": [s.key for s in self._specs],
                "error": self._last_error or None}

    async def files(self) -> Dict[str, str]:
        """The corpus, refreshing it if stale. Never raises."""
        if self.fresh:
            return self._files
        async with self._get_lock():
            if self.fresh:            # another task refreshed while we waited
                return self._files
            try:
                fetched = await self._fetch_all()
                if fetched:
                    self._files = fetched
                    self._fetched_at = time.time()
                    self._last_error = ""
                    logger.info("help source: loaded %d files from %s",
                                len(fetched), ", ".join(s.key for s in self._specs))
                elif not self._files:
                    self._last_error = "no files returned"
            except Exception as e:  # noqa: BLE001
                # Keep serving the stale corpus if we have one; an expired cache
                # is far more useful than an empty one.
                self._last_error = str(e)
                logger.warning("help source: GitHub fetch failed (%s); serving %d cached files",
                               e, len(self._files))
        return self._files

    async def _fetch_all(self) -> Dict[str, str]:
        import httpx
        out: Dict[str, str] = {}
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT,
                                     follow_redirects=True) as client:
            for spec in self._specs:
                try:
                    out.update(await self._fetch_spec(client, spec))
                except Exception as e:  # noqa: BLE001
                    # One unreachable repo must not blank out the others.
                    logger.warning("help source: %s failed: %s", spec.key, e)
        return out

    async def _fetch_spec(self, client, spec: SourceSpec) -> Dict[str, str]:
        resp = await client.get(
            f"{API}/repos/{spec.owner}/{spec.repo}/git/trees/{spec.branch}",
            params={"recursive": "1"}, headers=_headers())
        resp.raise_for_status()
        tree = resp.json() or {}
        if tree.get("truncated"):
            # Only possible on a very large repo. Say so loudly rather than
            # quietly returning a partial corpus that looks complete.
            logger.warning("help source: %s tree truncated — corpus may be partial",
                           spec.key)
        wanted = [n for n in (tree.get("tree") or [])
                  if n.get("type") == "blob" and spec.wants(n.get("path") or "")
                  and int(n.get("size") or 0) <= MAX_FILE_BYTES][:MAX_FILES]

        async def _one(node):
            path = node["path"]
            r = await client.get(f"{RAW}/{spec.owner}/{spec.repo}/{spec.branch}/{path}")
            r.raise_for_status()
            return f"{spec.label}/{path}", r.text

        # Bounded concurrency: fast enough for ~50 small files without opening a
        # burst of connections against the CDN.
        out: Dict[str, str] = {}
        sem = asyncio.Semaphore(8)

        async def _guarded(node):
            async with sem:
                try:
                    k, v = await _one(node)
                    out[k] = v
                except Exception as e:  # noqa: BLE001
                    logger.debug("help source: skip %s: %s", node.get("path"), e)

        await asyncio.gather(*(_guarded(n) for n in wanted))
        return out
