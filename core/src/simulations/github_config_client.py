"""Hub-side GitHub client for tenant config (simulation.conf / user-overrides.conf).

The HUB is the single GitHub client for a GitHub-managed tenant: it PULLs the
config from the repo and PUSHes (commits) editor edits back, then distributes
the resulting config to spokes over CS_CONFIG_UPDATE. Spokes attached to a hub
never talk to GitHub themselves.

INVARIANT (see the plan / config-authority notes): the hub is the config
authority whenever it exists; the spoke's own repo_sync GitHub access is a
standalone-only (no-hub) fallback.

Implementation: the GitHub REST **Contents API** over ``httpx`` with the
tenant's stored ``github_token`` — no local clone, no ``git`` binary, no
per-tenant checkout on the hub. Mirrors the read-only REST pattern already in
``routes/setup_misc.py``. A single-process hub can hold N tenants' repos this
way with no disk state; the only cached state is the last-seen blob SHA per
file (so the poll loop re-distributes only on a real change, and PUT has the
sha it needs to update).
"""
# Allow modern type-hint syntax on older Python versions.
from __future__ import annotations

# base64 is how the GitHub Contents API encodes file bodies.
import base64
# Standard-library logging for push retry notices.
import logging
# Type hints only.
from typing import Any, Dict, Optional, Tuple
# URL parsing, used to pull owner/name out of https repo URLs.
from urllib.parse import urlparse

# Module-level logger named after this module.
logger = logging.getLogger(__name__)

# GitHub REST API base URL.
API = "https://api.github.com"
# Repo-relative paths of the two config files the hub manages.
SIM_CONF_PATH = "configs/simulation.conf"
USER_OVERRIDES_PATH = "configs/user-overrides.conf"
# Branch used when the tenant has not configured one.
_DEFAULT_BRANCH = "main"


def parse_owner_repo(repo_url: str) -> Optional[Tuple[str, str]]:
    """Parse ``(owner, name)`` from a GitHub repo URL or bare ``owner/name``.

    Accepts ``https://github.com/owner/name(.git)``,
    ``git@github.com:owner/name.git``, or ``owner/name``. Returns ``None`` when
    it can't find both parts.
    """
    # Treat None as empty and ignore surrounding whitespace.
    s = (repo_url or "").strip()
    if not s:
        return None
    # SSH form: keep only the part after the colon.
    if s.startswith("git@"):  # git@github.com:owner/name.git
        s = s.split(":", 1)[-1]
    # URL form: keep only the path portion without the leading slash.
    elif "://" in s:
        s = urlparse(s).path.lstrip("/")
    # Drop a trailing .git suffix so the repo name is clean.
    if s.endswith(".git"):
        s = s[:-4]
    # Split into non-empty path segments; the last two are owner and repo.
    parts = [p for p in s.split("/") if p]
    if len(parts) >= 2:
        return parts[-2], parts[-1]
    return None


def is_configured(github_config: Optional[Dict[str, Any]]) -> bool:
    """True when the config has both a repo URL that parses and a token — the
    minimum for the hub to act as the GitHub client for this tenant."""
    # Treat a missing config as empty.
    gc = github_config or {}
    # Need both a token and a parseable repo URL.
    return bool(gc.get("github_token")) and parse_owner_repo(gc.get("repo_url", "")) is not None


def _branch(github_config: Dict[str, Any]) -> str:
    """Return the tenant's configured branch, or the default branch when unset."""
    return (github_config.get("repo_branch") or "").strip() or _DEFAULT_BRANCH


def _headers(token: str) -> Dict[str, str]:
    """Build the GitHub API request headers, adding the auth token when present."""
    # Ask for the GitHub JSON media type and pin the API version.
    h = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    # Authenticate only when a token is available.
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def _decode(node: Dict[str, Any]) -> str:
    """Decode the base64 body of a Contents API file node into text."""
    # GitHub wraps base64 at 60 characters; strip newlines before decoding.
    b64 = (node.get("content") or "").replace("\n", "")
    # No content means an empty file.
    if not b64:
        return ""
    try:
        # Decode to UTF-8 text, replacing any invalid bytes rather than failing.
        return base64.b64decode(b64).decode("utf-8", "replace")
    except Exception:  # noqa: BLE001 — malformed base64 → treat as empty
        return ""


async def _new_client():
    """Create a new async HTTP client with a 15s timeout for GitHub calls."""
    # Imported lazily so the module loads even where httpx is not installed.
    import httpx
    return httpx.AsyncClient(timeout=15.0)


async def _get_file(client, owner: str, repo: str, path: str, branch: str,
                    token: str) -> Tuple[Optional[str], Optional[str]]:
    """GET one file → ``(content, sha)``. A missing file (404) returns
    ``(None, None)`` so a fresh repo (no config yet) is handled gracefully."""
    # Request the file at the given branch via the Contents API.
    resp = await client.get(
        f"{API}/repos/{owner}/{repo}/contents/{path}",
        params={"ref": branch}, headers=_headers(token))
    # Missing file: report "no content, no sha" instead of raising.
    if resp.status_code == 404:
        return None, None
    # Any other error status propagates to the caller.
    resp.raise_for_status()
    # Return the decoded text plus the blob sha needed for later updates.
    node = resp.json()
    return _decode(node), node.get("sha")


async def pull(github_config: Dict[str, Any], *, client=None) -> Optional[Dict[str, Any]]:
    """Pull both config files from the tenant's GitHub repo.

    Returns ``{"sim_conf", "user_overrides", "sim_sha", "user_sha", "branch"}``
    (content strings; ``None`` content/sha for a file that doesn't exist yet), or
    ``None`` when the tenant isn't configured for GitHub (no token / bad URL).
    Never raises for a normal missing-file case; network/auth errors propagate to
    the caller (poll loop logs + skips).
    """
    # Not configured for GitHub: nothing to pull.
    if not is_configured(github_config):
        return None
    # Resolve repo coordinates, branch and token from the tenant config.
    owner, repo = parse_owner_repo(github_config.get("repo_url", ""))  # type: ignore[misc]
    branch = _branch(github_config)
    token = github_config.get("github_token") or ""
    # Create (and later close) our own HTTP client unless the caller passed one in.
    owns = client is None
    if owns:
        client = await _new_client()
    # Fetch both config files; the finally block always closes a client we created.
    try:
        sim_conf, sim_sha = await _get_file(client, owner, repo, SIM_CONF_PATH, branch, token)
        user_conf, user_sha = await _get_file(client, owner, repo, USER_OVERRIDES_PATH, branch, token)
    finally:
        if owns:
            await client.aclose()
    # Bundle contents and shas so the caller can detect changes and push updates.
    return {
        "sim_conf": sim_conf, "sim_sha": sim_sha,
        "user_overrides": user_conf, "user_sha": user_sha,
        "branch": branch,
    }


async def push(github_config: Dict[str, Any], path: str, content: str,
               message: str, sha: Optional[str] = None, *, client=None) -> Optional[str]:
    """Commit ``content`` to ``path`` on the tenant's repo/branch. Returns the new
    blob SHA. Creates the file when ``sha`` is None; updates it otherwise.

    On a 409/422 stale-sha conflict (someone else committed since we read), it
    re-GETs the current sha once and retries — so a concurrent external edit
    doesn't drop the hub's write on the floor.
    """
    # Pushing without a token or repo is a caller bug, so fail loudly.
    if not is_configured(github_config):
        raise ValueError("github_config not configured (missing token or repo_url)")
    # Resolve repo coordinates, branch and token from the tenant config.
    owner, repo = parse_owner_repo(github_config.get("repo_url", ""))  # type: ignore[misc]
    branch = _branch(github_config)
    token = github_config.get("github_token") or ""
    # Create (and later close) our own HTTP client unless the caller passed one in.
    owns = client is None
    if owns:
        client = await _new_client()
    # Write the file, allowing one stale-sha retry; always close a client we created.
    try:
        return await _put_file(client, owner, repo, path, content, message,
                               branch, token, sha, retry=True)
    finally:
        if owns:
            await client.aclose()


async def _put_file(client, owner, repo, path, content, message, branch, token,
                    sha, retry: bool) -> Optional[str]:
    """Create or update one file via the Contents API, retrying once on a stale sha."""
    # Commit message, base64-encoded content and target branch for the PUT body.
    body: Dict[str, Any] = {
        "message": message,
        "content": base64.b64encode(content.encode("utf-8")).decode("ascii"),
        "branch": branch,
    }
    # Including the current sha turns the request into an update instead of a create.
    if sha:
        body["sha"] = sha
    # Send the commit to GitHub.
    resp = await client.put(
        f"{API}/repos/{owner}/{repo}/contents/{path}",
        json=body, headers=_headers(token))
    if resp.status_code in (409, 422) and retry:
        # Stale sha — re-read the current sha and retry once.
        cur_content, cur_sha = await _get_file(client, owner, repo, path, branch, token)
        logger.info("github push %s/%s:%s stale sha (%s) — retrying with %s",
                    owner, repo, path, resp.status_code, cur_sha)
        return await _put_file(client, owner, repo, path, content, message,
                               branch, token, cur_sha, retry=False)
    # Any other error status propagates to the caller.
    resp.raise_for_status()
    # Return the new blob sha from the response, if the response is the expected shape.
    j = resp.json()
    return ((j.get("content") or {}).get("sha")) if isinstance(j, dict) else None
