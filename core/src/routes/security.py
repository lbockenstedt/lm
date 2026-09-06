"""Security / threat-monitor routes — the auth-failure audit log, blocked-IP
tiles (permanent / temporary / manual), config, manual block/unblock, and the
never-block allow list. ALL ADMIN-ONLY (on top of the /api/* session gate)."""
from api import HTTPException, Request


def register(app, hub, ctx):
    _session_user = ctx._session_user
    _is_admin = ctx._is_admin

    def _guard(request: Request):
        sess = _session_user(request)
        if not (sess and _is_admin(sess)):
            raise HTTPException(status_code=403, detail="Admin only")
        return sess

    @app.get("/api/security/overview")
    async def security_overview(request: Request):
        """Snapshot for the Security view: config + blocked-IP tiles (permanent /
        temporary / manual) + never-block list + recent auth-failure events."""
        _guard(request)
        return hub.threat_monitor.snapshot()

    @app.put("/api/security/config")
    async def security_config(request: Request):
        """Update policy: enabled, auto_block, threshold (>N fails), window_s,
        ttl_s, permanent_after, success_grace_s, block_rule_name, block_priority.
        When ``block_priority`` is changed it is REJECTED with 400 unless it keeps
        the invariant ``allow_priority < block_priority < 1000`` against the
        CURRENT azure_nsg allow priority (Azure evaluates lower numbers first)."""
        from security.threat_monitor import validate_nsg_priorities
        _guard(request)
        body = await request.json() or {}
        # Enforce the ordering guard when the deny priority is being changed:
        # validate the incoming deny against the CURRENT stored allow priority.
        if "block_priority" in body:
            allow = hub.threat_monitor.allow_priority()
            ok, message = validate_nsg_priorities(allow, body.get("block_priority"))
            if not ok:
                raise HTTPException(status_code=400, detail=message)
        cfg = hub.threat_monitor.set_config(body)
        ok, warning = validate_nsg_priorities(hub.threat_monitor.allow_priority(),
                                              cfg.get("block_priority"))
        return {"status": "ok", "config": cfg,
                "allow_priority": hub.threat_monitor.allow_priority(),
                "warning": "" if ok else warning}

    @app.post("/api/security/block")
    async def security_block(request: Request):
        """Manually block an IP (optionally permanent). Body: {ip, reason, permanent}."""
        _guard(request)
        body = await request.json()
        return hub.threat_monitor.block_manual(
            (body.get("ip") or "").strip(), body.get("reason", ""),
            permanent=bool(body.get("permanent")))

    @app.post("/api/security/unblock")
    async def security_unblock(request: Request):
        """Remove a block (temporary, permanent, or manual). Body: {ip}."""
        _guard(request)
        body = await request.json()
        return hub.threat_monitor.unblock((body.get("ip") or "").strip())

    @app.post("/api/security/never-block")
    async def security_never_add(request: Request):
        """Add an IP/CIDR to the SHARED trusted list (never auto-blocked AND
        allowed through the Azure NSG). Edits ``global_config['azure_nsg']
        ['entries']`` — the same list the Azure NSG tile manages — then reconciles
        the NSG allow rule (opens the hole) when Azure NSG is enabled.
        Body: {cidr|ip, description?}."""
        _guard(request)
        body = await request.json()
        ip = (body.get("cidr") or body.get("ip") or "").strip()
        desc = (body.get("description") or "").strip()
        res = hub.threat_monitor.add_trusted(ip, desc)
        if res.get("status") == "SUCCESS":
            res["allow"] = await hub.threat_monitor.reconcile_allow()
        return res

    @app.delete("/api/security/never-block")
    async def security_never_remove(request: Request):
        """Remove an IP/CIDR from the SHARED trusted list, then reconcile the NSG
        allow rule (closes the hole) when Azure NSG is enabled. Body: {cidr|ip}."""
        _guard(request)
        body = await request.json()
        ip = (body.get("cidr") or body.get("ip") or "").strip()
        res = hub.threat_monitor.remove_trusted(ip)
        if res.get("status") == "SUCCESS":
            res["allow"] = await hub.threat_monitor.reconcile_allow()
        return res

    @app.post("/api/security/reconcile")
    async def security_reconcile(request: Request):
        """Force a push of BOTH managed NSG rule sets onto whichever cloud
        provider is active: the trusted/ALLOW list (Azure and OCI) and the
        blocked-IP DENY rule (Azure only — OCI NSGs are allow-only)."""
        _guard(request)
        return await hub.threat_monitor.sync_nsg_now()

    @app.post("/api/security/geo")
    async def security_geo(request: Request):
        """Best-effort origin enrichment for a set of IPs (reverse DNS + country/
        ISP/ASN) surfaced next to the blocked-IP tiles and the recent-attempt
        feed. Body: {ips: [...]}. Returns {ip: {scope, ptr, country, isp, ...}}.
        Purely advisory (never blocks); private/LAN IPs are classified locally
        and never sent to the external provider."""
        _guard(request)
        from security import ip_geo
        body = await request.json() or {}
        ips = body.get("ips") or []
        if not isinstance(ips, list):
            raise HTTPException(status_code=400, detail="ips must be a list")
        return {"geo": await ip_geo.enrich_many([str(x) for x in ips[:256]])}

    @app.post("/api/security/selftest")
    async def security_selftest(request: Request):
        """Record a synthetic detection signal so the operator can verify the
        pipeline is live (it appears in Lifetime activity + Recent attempts).
        Benign: no IP → never blocks anyone."""
        _guard(request)
        return hub.threat_monitor.self_test()

    # ── Extension source ────────────────────────────────────────────────────
    # Operator-set config for the out-of-band module loader (``site_ext``): a
    # private git source the hub clones at startup, BEFORE the app is built.
    # Deliberately named neutrally here (and in the UI) — the point of the
    # mechanism is that a deployment doesn't advertise what it loads.
    #
    # The token is WRITE-ONLY across this API: it is accepted on PUT and never
    # returned by GET (only a ``token_set`` boolean), so an admin session can
    # configure it but can't read a stored credential back out of the browser.

    _EXT_SECRET_NAME = "lm-ext-source-token"

    async def _store_token(hub, tok: str) -> str:
        """Persist the PAT and return the value to keep in config.

        When a cloud vault is enabled the secret goes THERE and only a
        ``kv:<name>`` reference is kept in config — matching the established
        pattern (``instance_vault`` / HE.NET / LE). With no vault the literal
        rides in ``global_config``, which the StateManager writes Fernet-
        encrypted to a 0700 dir, so it is still encrypted at rest.

        A ``kv:`` reference typed by the operator is passed through untouched."""
        if tok.startswith("kv:"):
            return tok
        try:
            import cloud_vault
            if cloud_vault.active_provider(hub) is not None:
                await cloud_vault.set_secret(hub, _EXT_SECRET_NAME, tok)
                return f"kv:{_EXT_SECRET_NAME}"
        except Exception as e:  # noqa: BLE001 — vault down must not lose the save
            import logging
            logging.getLogger("Hub").warning(
                "ext-source: vault store failed (%s) — keeping token in encrypted state", e)
        return tok

    def _ext_cfg(hub) -> dict:
        gc = hub.state.get_global_config() or {}
        c = gc.get("site_ext") or {}
        return dict(c) if isinstance(c, dict) else {}

    def _ext_status(hub) -> dict:
        import os
        import site_ext
        cfg = _ext_cfg(hub)
        d = site_ext.ext_dir(hub)
        tok = cfg.get("token") or ""
        try:
            import cloud_vault
            vault = cloud_vault.active_provider(hub)
        except Exception:  # noqa: BLE001
            vault = None
        modules = []
        try:
            modules = sorted(os.path.basename(p) for p in __import__("glob").glob(os.path.join(d, "*.py")))
        except Exception:  # noqa: BLE001
            pass
        return {
            "enabled": bool(cfg.get("enabled")),
            "repo": cfg.get("repo") or "",
            "ref": cfg.get("ref") or "main",
            "token_set": bool(cfg.get("token")),
            "token_storage": ("vault" if str(tok).startswith("kv:")
                              else ("state" if tok else "")),
            "vault_available": bool(vault),
            "dir": d,
            "provisioned": os.path.isdir(os.path.join(d, ".git")),
            "modules": modules,
        }

    @app.get("/api/security/ext-source")
    async def ext_source_get(request: Request):
        """Current extension-source config + provisioning status. NEVER returns
        the stored token — only ``token_set``."""
        _guard(request)
        return _ext_status(hub)

    @app.put("/api/security/ext-source")
    async def ext_source_put(request: Request):
        """Save the extension source. Body: {enabled, repo, ref, token,
        clear_token}.

        ``token`` is merge-preserving: omitting it (or sending "") KEEPS the
        stored credential, so an admin can edit the repo/branch without having
        to re-enter the PAT (which the GET deliberately never gave them). Pass
        ``clear_token: true`` to actually remove it."""
        _guard(request)
        body = await request.json() or {}
        cfg = _ext_cfg(hub)
        if "enabled" in body:
            cfg["enabled"] = bool(body.get("enabled"))
        if "repo" in body:
            repo = (body.get("repo") or "").strip()
            if repo and not repo.startswith("https://"):
                raise HTTPException(status_code=400,
                                    detail="repo must be an https:// git URL")
            cfg["repo"] = repo
        if "ref" in body:
            cfg["ref"] = (body.get("ref") or "").strip() or "main"
        if body.get("clear_token"):
            old = cfg.pop("token", None)
            if old and str(old).startswith("kv:"):
                try:
                    import cloud_vault
                    await cloud_vault.delete_secret(hub, str(old)[3:])
                except Exception:  # noqa: BLE001 — config is authoritative
                    pass
        else:
            tok = (body.get("token") or "").strip()
            if tok:
                cfg["token"] = await _store_token(hub, tok)
        hub.state.update_global_config({"site_ext": cfg})
        return {"status": "ok", **_ext_status(hub)}

    @app.post("/api/security/ext-source/provision")
    async def ext_source_provision(request: Request):
        """Fetch now, so a bad token/branch/URL surfaces immediately instead of
        at the next restart. Modules are only *registered* during app build, so
        a restart is still required for newly fetched routes to serve."""
        _guard(request)
        import site_ext
        before = _ext_status(hub)
        if not before["enabled"] or not before["repo"]:
            raise HTTPException(status_code=400,
                                detail="enable the source and set a repo first")
        await site_ext.provision(hub)
        after = _ext_status(hub)
        return {"status": "ok", "restart_required": after["modules"] != before["modules"]
                or not before["provisioned"], **after}
