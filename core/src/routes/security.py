"""Security / threat-monitor routes — the auth-failure audit log, blocked-IP
tiles (permanent / temporary / manual), config, manual block/unblock, and the
never-block allow list. ALL ADMIN-ONLY (on top of the /api/* session gate)."""
import logging
import os

from api import HTTPException, Request

logger = logging.getLogger("Hub")


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

    @app.post("/api/security/ext-source/purge")
    async def ext_source_purge(request: Request):
        """Forget the source entirely: credential, config, and the checkout.

        Clearing the token alone leaves the fetched module sitting in the
        extension directory, where it keeps being imported and registered on
        every app build. An operator who has revoked a credential reasonably
        believes the code is gone; leaving it loaded is the gap between
        "revoked" and "removed".

        Deletes the whole extension directory rather than its ``*.py`` files.
        A leftover ``.git`` is a working checkout with an upstream: it holds
        the content in its object store, and any future provisioning run would
        fast-forward it straight back.

        Not merged into the PUT ``clear_token`` path, because deleting code
        from disk should be something an operator asked for in those terms
        rather than a side effect of unticking a box.
        """
        _guard(request)
        import shutil
        import site_ext

        cfg = _ext_cfg(hub)
        removed_token = bool(cfg.get("token"))
        old = cfg.get("token")
        if old and str(old).startswith("kv:"):
            try:
                import cloud_vault
                await cloud_vault.delete_secret(hub, str(old)[3:])
            except Exception:  # noqa: BLE001 — config is authoritative
                pass

        # The directory is resolved BEFORE the config is cleared: ext_dir()
        # honours a `dir` override that lives in the very config being wiped,
        # so clearing first would delete the pointer and then remove the
        # default location instead of the one actually in use.
        target = site_ext.ext_dir(hub)
        removed_dir = False
        detail = ""
        if os.path.isdir(target):
            try:
                shutil.rmtree(target)
                removed_dir = True
            except Exception as e:  # noqa: BLE001 — report, never raise
                detail = f"could not remove {target}: {e}"
                logger.warning("ext-source purge: %s", detail)

        hub.state.update_global_config({"site_ext": {"enabled": False}})
        await hub.state.save_state_now()
        logger.warning("ext-source purged: token_removed=%s dir_removed=%s (%s)",
                       removed_token, removed_dir, target)
        # _ext_status is spread FIRST so the explicit keys below win. It
        # recomputes the extension dir from the config that was just cleared,
        # and spreading it last would report the default location while the
        # configured one was the thing actually deleted.
        return {**_ext_status(hub),
                "status": "ok", "token_removed": removed_token,
                "dir_removed": removed_dir, "dir": target,
                "detail": detail,
                # Modules are imported at app build, so what is already loaded
                # keeps serving until the process restarts. Saying otherwise
                # would be telling an operator the code is gone while it runs.
                "restart_required": True}

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
        result = await site_ext.provision(hub)
        after = _ext_status(hub)
        if not result.get("ok"):
            # Report the actual cause instead of "check the log". The detail is
            # already redacted by site_ext, so it is safe to return.
            raise HTTPException(status_code=502, detail=result.get("detail")
                                or "fetch did not complete")
        return {"status": "ok", "restart_required": after["modules"] != before["modules"]
                or not before["provisioned"], **after}

    # ── Data subscription (Subscription Service) ─────────────────────────
    # The tenant-facing counterpart to the extension source above. That tile
    # fetches CODE from a private repo; this one subscribes to DATA from the
    # exchange. They are kept apart deliberately: the sensor content is no
    # longer distributed as source to anyone, so the only supported way to get
    # threat and simulation intelligence is this subscription.
    _SUB_SECRET_NAME = "lm-subscription-credential"

    # Channels a tenant may turn on. Kept as an explicit allow-list rather than
    # passing whatever the UI posts, so a typo or a crafted request cannot
    # enrol this install in a channel nobody reviewed.
    _SUB_CHANNELS = {
        "threat_monitor": "Threat database",
        "client_simulations": "Simulation database",
    }

    # Channels an install needs to make a chosen one work, but which are not a
    # separate decision for a tenant. Subscribing to the threat database means
    # running the tripwire, and a tripwire with no decoy routes observes
    # nothing — so asking an operator to tick a second box would only give them
    # a way to half-enable the feature.
    _SUB_IMPLIED = {"threat_monitor": ("decoys",)}

    def _sub_requested(channels) -> list:
        """Expand the tenant's choices into what enrolment actually asks for."""
        out = list(channels)
        for c in channels:
            for extra in _SUB_IMPLIED.get(c, ()):
                if extra not in out:
                    out.append(extra)
        return out

    def _sub_cfg(hub) -> dict:
        gc = hub.state.get_global_config() or {}
        c = gc.get("subscription") or {}
        return dict(c) if isinstance(c, dict) else {}

    async def _sub_store_credential(hub, cred: str) -> str:
        """Persist the credential, preferring the vault — same pattern as the
        extension PAT. TMClient owns no storage, so persisting what enrolment
        returns is the caller's job; losing it means re-enrolling and burning a
        second credential for the same install."""
        try:
            import cloud_vault
            if cloud_vault.active_provider(hub) is not None:
                await cloud_vault.set_secret(hub, _SUB_SECRET_NAME, cred)
                return f"kv:{_SUB_SECRET_NAME}"
        except Exception as e:  # noqa: BLE001 — vault down must not lose the credential
            logger.warning(
                "subscription: vault store failed (%s) — keeping credential in encrypted state", e)
        return cred

    async def _sub_resolve_credential(hub, cfg: dict) -> str:
        cred = str(cfg.get("credential") or "")
        if cred.startswith("kv:"):
            try:
                import cloud_vault
                return str(await cloud_vault.resolve_ref(hub, cred) or "")
            except Exception as e:  # noqa: BLE001
                logger.warning("subscription: could not resolve credential: %s", e)
                return ""
        return cred

    def _sub_identity(cfg: dict) -> tuple:
        """Return ``(tenant_id, install_uuid)``, minting either if absent.

        LM has no pre-existing install identity, so one is generated here.
        Both are opaque: the exchange needs to tell participants apart and to
        group an org's several installs so they are not miscounted as several
        independent confirmations, and neither of those needs a real name.
        """
        import uuid
        tid = str(cfg.get("tenant_id") or "").strip() or uuid.uuid4().hex
        iid = str(cfg.get("install_uuid") or "").strip() or uuid.uuid4().hex
        return tid, iid

    def _sub_status(hub) -> dict:
        cfg = _sub_cfg(hub)
        try:
            import cloud_vault
            vault = cloud_vault.active_provider(hub)
        except Exception:  # noqa: BLE001
            vault = None
        chans = [c for c in (cfg.get("channels") or []) if c in _SUB_CHANNELS]
        cred = str(cfg.get("credential") or "")
        return {
            "enabled": bool(cfg.get("enabled")),
            "status": cfg.get("status") or "not_enrolled",
            "tenant_id": cfg.get("tenant_id") or "",
            "install_uuid": cfg.get("install_uuid") or "",
            "channels": chans,
            "available_channels": [{"id": k, "label": v}
                                   for k, v in sorted(_SUB_CHANNELS.items())],
            "contact_email": cfg.get("contact_email") or "",
            "enrolled_at": cfg.get("enrolled_at") or 0,
            "last_error": cfg.get("last_error") or "",
            # The credential is bearer material: report only that one exists.
            "credential_set": bool(cred),
            "credential_storage": ("vault" if cred.startswith("kv:")
                                   else ("state" if cred else "")),
            "vault_available": bool(vault),
            "psk_set": bool(cfg.get("enrollment_psk")),
        }

    async def _sub_client(hub, cfg: dict):
        """Build a client from stored config. The service URL is NEVER taken
        from config — it is a constant in the client module, so a tenant cannot
        redirect their sensor data somewhere else."""
        from security.tm_client import TMClient
        tid, iid = _sub_identity(cfg)
        return TMClient(
            tenant_id=tid,
            install_uuid=iid,
            credential=await _sub_resolve_credential(hub, cfg),
            enrollment_psk=str(cfg.get("enrollment_psk") or ""),
            enabled=bool(cfg.get("enabled")),
        )

    @app.get("/api/security/subscription")
    async def subscription_get(request: Request):
        """Current subscription state. Never returns the credential or PSK."""
        _guard(request)
        return _sub_status(hub)

    @app.put("/api/security/subscription")
    async def subscription_put(request: Request):
        """Turn the subscription on/off and choose channels.

        Deliberately does NOT accept a service URL. A tenant chooses whether to
        participate and in what; they do not choose where their sensor data is
        sent.
        """
        _guard(request)
        body = await request.json()
        cfg = _sub_cfg(hub)
        tid, iid = _sub_identity(cfg)
        cfg["tenant_id"], cfg["install_uuid"] = tid, iid

        if "enabled" in body:
            cfg["enabled"] = bool(body.get("enabled"))
        if "channels" in body:
            want = body.get("channels") or []
            if not isinstance(want, list):
                raise HTTPException(status_code=400, detail="channels must be a list")
            unknown = [c for c in want if c not in _SUB_CHANNELS]
            if unknown:
                raise HTTPException(status_code=400,
                                    detail=f"unknown channel(s): {', '.join(map(str, unknown))}")
            cfg["channels"] = list(dict.fromkeys(want))
        if "contact_email" in body:
            cfg["contact_email"] = str(body.get("contact_email") or "").strip()
        # An empty PSK preserves what is stored, matching the PAT field above;
        # clearing is explicit so a blank submit never silently drops it.
        if body.get("clear_psk"):
            cfg.pop("enrollment_psk", None)
        elif str(body.get("enrollment_psk") or "").strip():
            cfg["enrollment_psk"] = str(body["enrollment_psk"]).strip()
        # An org that groups its installs supplies a shared id; blank keeps the
        # minted one rather than wiping identity on an unrelated save.
        if str(body.get("tenant_id") or "").strip():
            cfg["tenant_id"] = str(body["tenant_id"]).strip()

        hub.state.update_global_config({"subscription": cfg})
        await hub.state.save_state_now()
        return {"status": "ok", **_sub_status(hub)}

    @app.post("/api/security/subscription/enroll")
    async def subscription_enroll(request: Request):
        """Register with the exchange and persist whatever it returns.

        Approval may be immediate (with a PSK) or pending a human. Both are
        normal outcomes and are reported as such — an install waiting for
        approval is not an error state.
        """
        _guard(request)
        import time
        cfg = _sub_cfg(hub)
        if not cfg.get("enabled"):
            raise HTTPException(status_code=400,
                                detail="enable the subscription first")
        chans = [c for c in (cfg.get("channels") or []) if c in _SUB_CHANNELS]
        if not chans:
            raise HTTPException(status_code=400,
                                detail="choose at least one database to subscribe to")
        tid, iid = _sub_identity(cfg)
        cfg["tenant_id"], cfg["install_uuid"] = tid, iid

        body = await request.json() if await request.body() else {}
        client = await _sub_client(hub, cfg)
        result = await client.enroll(
            subscriptions=_sub_requested(chans),
            contact_email=str(cfg.get("contact_email") or ""),
            contact_message=str((body or {}).get("message") or ""),
        )
        status = str(result.get("status") or "error").lower()
        cfg["status"] = status
        cfg["last_error"] = "" if status in ("approved", "pending") else str(
            result.get("reason") or "enrolment did not complete")
        if status == "approved" and client.credential:
            cfg["credential"] = await _sub_store_credential(hub, client.credential)
            cfg["enrolled_at"] = time.time()
        hub.state.update_global_config({"subscription": cfg})
        await hub.state.save_state_now()
        return {"status": status, "reason": cfg["last_error"], **_sub_status(hub)}

    @app.post("/api/security/subscription/unsubscribe")
    async def subscription_unsubscribe(request: Request):
        """Stop participating and forget the credential.

        Turning the feature off without dropping the credential would leave
        valid bearer material for the exchange sitting in state for an install
        that believes it has withdrawn.
        """
        _guard(request)
        cfg = _sub_cfg(hub)
        cred = str(cfg.get("credential") or "")
        if cred.startswith("kv:"):
            try:
                import cloud_vault
                await cloud_vault.delete_secret(hub, cred[3:])
            except Exception:  # noqa: BLE001 — config is authoritative
                pass
        # Identity is KEPT: re-subscribing with the same install_uuid is a
        # rejoin, while a fresh one would look like a new participant and lose
        # whatever standing this install had built up.
        for k in ("credential", "enrollment_psk", "enrolled_at", "last_error"):
            cfg.pop(k, None)
        cfg["enabled"] = False
        cfg["channels"] = []
        cfg["status"] = "not_enrolled"
        hub.state.update_global_config({"subscription": cfg})
        await hub.state.save_state_now()
        logger.warning("subscription: unsubscribed, credential forgotten")
        return {"status": "ok", **_sub_status(hub)}
