"""Setup misc: subnet-filter, delete-user, GitHub repos/branches, global config."""
from api import (
    HTTPException, Request, _FILTER_DEFAULTS, _FILTER_MODULES, _filter_config, asyncio,
    logger,
)


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
        app.state.hub.state.save_state()
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
        hub.state.save_state()
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

            gc = hub.state.system_state.setdefault("global_config", {})
            gc.update(config)
            hub.state.save_state()

            return {"status": "ok", "message": "Global configuration updated."}
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid request: {str(e)}")
