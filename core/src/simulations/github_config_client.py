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
from __future__ import annotations

import base64
import logging
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

API = "https://api.github.com"
SIM_CONF_PATH = "configs/simulation.conf"
USER_OVERRIDES_PATH = "configs/user-overrides.conf"
_DEFAULT_BRANCH = "main"


def parse_owner_repo(repo_url: str) -> Optional[Tuple[str, str]]:
    """Parse ``(owner, name)`` from a GitHub repo URL or bare ``owner/name``.

    Accepts ``https://github.com/owner/name(.git)``,
    ``git@github.com:owner/name.git``, or ``owner/name``. Returns ``None`` when
    it can't find both parts.
    """
    s = (repo_url or "").strip()
    if not s:
        return None
    if s.startswith("git@"):  # git@github.com:owner/name.git
        s = s.split(":", 1)[-1]
    elif "://" in s:
        s = urlparse(s).path.lstrip("/")
    if s.endswith(".git"):
        s = s[:-4]
    parts = [p for p in s.split("/") if p]
    if len(parts) >= 2:
        return parts[-2], parts[-1]
    return None


def is_configured(github_config: Optional[Dict[str, Any]]) -> bool:
    """True when the config has both a repo URL that parses and a token — the
    minimum for the hub to act as the GitHub client for this tenant."""
    gc = github_config or {}
    return bool(gc.get("github_token")) and parse_owner_repo(gc.get("repo_url", "")) is not None


def _branch(github_config: Dict[str, Any]) -> str:
    return (github_config.get("repo_branch") or "").strip() or _DEFAULT_BRANCH


def _headers(token: str) -> Dict[str, str]:
    h = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def _decode(node: Dict[str, Any]) -> str:
    b64 = (node.get("content") or "").replace("\n", "")
    if not b64:
        return ""
    try:
        return base64.b64decode(b64).decode("utf-8", "replace")
    except Exception:  # noqa: BLE001 — malformed base64 → treat as empty
        return ""


async def _new_client():
    import httpx
    return httpx.AsyncClient(timeout=15.0)


async def _get_file(client, owner: str, repo: str, path: str, branch: str,
                    token: str) -> Tuple[Optional[str], Optional[str]]:
    """GET one file → ``(content, sha)``. A missing file (404) returns
    ``(None, None)`` so a fresh repo (no config yet) is handled gracefully."""
    resp = await client.get(
        f"{API}/repos/{owner}/{repo}/contents/{path}",
        params={"ref": branch}, headers=_headers(token))
    if resp.status_code == 404:
        return None, None
    resp.raise_for_status()
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
    if not is_configured(github_config):
        return None
    owner, repo = parse_owner_repo(github_config.get("repo_url", ""))  # type: ignore[misc]
    branch = _branch(github_config)
    token = github_config.get("github_token") or ""
    owns = client is None
    if owns:
        client = await _new_client()
    try:
        sim_conf, sim_sha = await _get_file(client, owner, repo, SIM_CONF_PATH, branch, token)
        user_conf, user_sha = await _get_file(client, owner, repo, USER_OVERRIDES_PATH, branch, token)
    finally:
        if owns:
            await client.aclose()
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
    if not is_configured(github_config):
        raise ValueError("github_config not configured (missing token or repo_url)")
    owner, repo = parse_owner_repo(github_config.get("repo_url", ""))  # type: ignore[misc]
    branch = _branch(github_config)
    token = github_config.get("github_token") or ""
    owns = client is None
    if owns:
        client = await _new_client()
    try:
        return await _put_file(client, owner, repo, path, content, message,
                               branch, token, sha, retry=True)
    finally:
        if owns:
            await client.aclose()


async def _put_file(client, owner, repo, path, content, message, branch, token,
                    sha, retry: bool) -> Optional[str]:
    body: Dict[str, Any] = {
        "message": message,
        "content": base64.b64encode(content.encode("utf-8")).decode("ascii"),
        "branch": branch,
    }
    if sha:
        body["sha"] = sha
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
    resp.raise_for_status()
    j = resp.json()
    return ((j.get("content") or {}).get("sha")) if isinstance(j, dict) else None
