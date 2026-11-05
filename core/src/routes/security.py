"""Security / threat-monitor routes — the auth-failure audit log, blocked-IP
tiles (permanent / temporary / manual), config, manual block/unblock, and the
never-block allow list. ALL ADMIN-ONLY (on top of the /api/* session gate)."""
# logging provides this module's logger.
import logging
# os is used for path handling when purging the extension checkout.
import os

# FastAPI request/error types re-exported by the api module.
from api import HTTPException, Request

# Log under the shared "Hub" logger so these messages sit alongside other hub logs.
logger = logging.getLogger("Hub")


def register(app, hub, ctx):
    """Register the security / threat-monitor admin routes on the Hub app.

    Args: app is the FastAPI app, hub is the running hub (owns ``threat_monitor``), ctx carries
    shared auth helpers.
    """
    # Pull the session and admin-check helpers off the shared context once for all routes.
    _session_user = ctx._session_user
    _is_admin = ctx._is_admin

    def _guard(request: Request):
        """Raise 403 unless the request comes from a logged-in admin; return the session."""
        # Look up the logged-in session for this request.
        sess = _session_user(request)
        # Every security route is admin-only.
        if not (sess and _is_admin(sess)):
            raise HTTPException(status_code=403, detail="Admin only")
        return sess

    def _as_bool(value, default: bool) -> bool:
        """Strict-ish JSON boolean coercion for request bodies.

        ``x is not False`` is wrong for a policy-relaxing flag: a client sending
        the JSON string ``"false"``, ``"0"``, ``"no"`` or the integer ``0``
        would silently be read as *true* and forgive a strike the operator
        meant to keep. Accept real booleans, the usual string spellings, and
        0/1; anything else — including an empty/whitespace-only string, which
        carries no operator intent — falls back to ``default``."""
        # Missing value: use the caller's default.
        if value is None:
            return default
        # Real JSON booleans are taken as-is.
        if isinstance(value, bool):
            return value
        # Numbers: 0 is false, anything else true (bools were already handled above).
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return bool(value)
        # Strings: accept the common spellings of true/false, ignoring case and spaces.
        if isinstance(value, str):
            v = value.strip().lower()
            if v in ("true", "1", "yes", "on"):
                return True
            if v in ("false", "0", "no", "off"):
                return False
        # Anything unrecognised falls back to the default.
        return default

    # Data for the whole Security page in one call.
    @app.get("/api/security/overview")
    async def security_overview(request: Request):
        """Snapshot for the Security view: config + blocked-IP tiles (permanent /
        temporary / manual) + never-block list + recent auth-failure events."""
        # Admin only; then return the threat monitor's current snapshot.
        _guard(request)
        return hub.threat_monitor.snapshot()

    # Change threat-monitor policy settings.
    @app.put("/api/security/config")
    async def security_config(request: Request):
        """Update policy: enabled, auto_block, threshold (>N fails), window_s,
        ttl_s, permanent_after, success_grace_s, block_rule_name, block_priority.
        When ``block_priority`` is changed it is REJECTED with 400 unless it keeps
        the invariant ``allow_priority < block_priority < 1000`` against the
        CURRENT azure_nsg allow priority (Azure evaluates lower numbers first)."""
        # Imported here to keep this module's import-time dependencies light.
        from security.threat_monitor import validate_nsg_priorities
        # Admin only; read the policy changes from the body.
        _guard(request)
        body = await request.json() or {}
        # Enforce the ordering guard when the deny priority is being changed:
        # validate the incoming deny against the CURRENT stored allow priority.
        if "block_priority" in body:
            allow = hub.threat_monitor.allow_priority()
            ok, message = validate_nsg_priorities(allow, body.get("block_priority"))
            if not ok:
                raise HTTPException(status_code=400, detail=message)
        # Apply and save the new config.
        cfg = hub.threat_monitor.set_config(body)
        # Re-check the stored priorities so the UI can warn about a bad pair without failing.
        ok, warning = validate_nsg_priorities(hub.threat_monitor.allow_priority(),
                                              cfg.get("block_priority"))
        # Return the saved config, the allow priority it was checked against, and any warning.
        return {"status": "ok", "config": cfg,
                "allow_priority": hub.threat_monitor.allow_priority(),
                "warning": "" if ok else warning}

    # Block an IP by hand.
    @app.post("/api/security/block")
    async def security_block(request: Request):
        """Manually block an IP (optionally permanent). Body: {ip, reason, permanent}."""
        # Admin only; then ask the threat monitor to block the trimmed IP with the given reason.
        _guard(request)
        body = await request.json()
        return hub.threat_monitor.block_manual(
            (body.get("ip") or "").strip(), body.get("reason", ""),
            permanent=bool(body.get("permanent")))

    # Remove a block.
    @app.post("/api/security/unblock")
    async def security_unblock(request: Request):
        """Remove a block (temporary, permanent, or manual). Body:
        ``{ip, forgive?}``.

        ``forgive`` defaults to **true**: a manual unblock is normally the
        operator overturning a bad block, and strikes drive ``permanent_after``,
        so banking a strike for a block that was wrong walks a legitimate
        address toward a permanent ban. Send ``forgive: false`` to let the
        address back in while keeping the strike on record. Parsing is strict
        (see ``_as_bool``) so ``"false"``/``0`` are honoured as false rather
        than silently forgiving the strike."""
        # Admin only; unblock the trimmed IP, forgiving its strike unless told not to.
        _guard(request)
        body = await request.json()
        return hub.threat_monitor.unblock((body.get("ip") or "").strip(),
                                          forgive=_as_bool(body.get("forgive"), True))

    # Clear an address's strike count.
    @app.post("/api/security/forgive")
    async def security_forgive(request: Request):
        """Clear an address's accumulated strikes without touching any active
        block. Body: ``{ip}``.

        Strikes were historically never decremented, so an address can already
        sit at or past ``permanent_after`` from blocks that were all overturned
        — arming an instant, TTL-less permanent ban on its next trip. This
        clears that backlog."""
        # Admin only; then reset the strikes for the trimmed IP.
        _guard(request)
        body = await request.json()
        return hub.threat_monitor.forgive((body.get("ip") or "").strip())

    # Add an address to the never-block / trusted list.
    @app.post("/api/security/never-block")
    async def security_never_add(request: Request):
        """Add an IP/CIDR to the SHARED trusted list (never auto-blocked AND
        allowed through the Azure NSG). Edits ``global_config['azure_nsg']
        ['entries']`` — the same list the Azure NSG tile manages — then reconciles
        the NSG allow rule (opens the hole) when Azure NSG is enabled.
        Body: {cidr|ip, description?}."""
        # Admin only; accept "cidr" or "ip" and an optional description.
        _guard(request)
        body = await request.json()
        ip = (body.get("cidr") or body.get("ip") or "").strip()
        desc = (body.get("description") or "").strip()
        # Add it to the trusted list.
        res = hub.threat_monitor.add_trusted(ip, desc)
        # When the add worked, update the cloud NSG allow rule to match and report the result.
        if res.get("status") == "SUCCESS":
            res["allow"] = await hub.threat_monitor.reconcile_allow()
        return res

    # Remove an address from the never-block / trusted list.
    @app.delete("/api/security/never-block")
    async def security_never_remove(request: Request):
        """Remove an IP/CIDR from the SHARED trusted list, then reconcile the NSG
        allow rule (closes the hole) when Azure NSG is enabled. Body: {cidr|ip}."""
        # Admin only; accept "cidr" or "ip".
        _guard(request)
        body = await request.json()
        ip = (body.get("cidr") or body.get("ip") or "").strip()
        # Remove it from the trusted list.
        res = hub.threat_monitor.remove_trusted(ip)
        # When the removal worked, update the cloud NSG allow rule to match and report the result.
        if res.get("status") == "SUCCESS":
            res["allow"] = await hub.threat_monitor.reconcile_allow()
        return res

    # Re-push NSG rules to the cloud provider now.
    @app.post("/api/security/reconcile")
    async def security_reconcile(request: Request):
        """Force a push of BOTH managed NSG rule sets onto whichever cloud
        provider is active: the trusted/ALLOW list (Azure and OCI) and the
        blocked-IP DENY rule (Azure only — OCI NSGs are allow-only)."""
        # Admin only; then push both rule sets and return the outcome.
        _guard(request)
        return await hub.threat_monitor.sync_nsg_now()

    # Look up origin details (DNS name, country, ISP) for IPs.
    @app.post("/api/security/geo")
    async def security_geo(request: Request):
        """Best-effort origin enrichment for a set of IPs (reverse DNS + country/
        ISP/ASN) surfaced next to the blocked-IP tiles and the recent-attempt
        feed. Body: {ips: [...]}. Returns {ip: {scope, ptr, country, isp, ...}}.
        Purely advisory (never blocks); private/LAN IPs are classified locally
        and never sent to the external provider."""
        # Admin only; ip_geo is imported lazily since only this route needs it.
        _guard(request)
        from security import ip_geo
        # Read the list of IPs to look up; it must be a list.
        body = await request.json() or {}
        ips = body.get("ips") or []
        if not isinstance(ips, list):
            raise HTTPException(status_code=400, detail="ips must be a list")
        # Look up at most 256 IPs per call to bound outside lookups.
        return {"geo": await ip_geo.enrich_many([str(x) for x in ips[:256]])}

    # Record a harmless test detection to prove monitoring works.
    @app.post("/api/security/selftest")
    async def security_selftest(request: Request):
        """Record a synthetic detection signal so the operator can verify the
        pipeline is live (it appears in Lifetime activity + Recent attempts).
        Benign: no IP → never blocks anyone."""
        # Admin only; then record the synthetic signal.
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

    # Name of the vault secret that holds the extension-source access token.
    _EXT_SECRET_NAME = "lm-ext-source-token"

    async def _store_token(hub, tok: str) -> str:
        """Persist the PAT and return the value to keep in config.

        When a cloud vault is enabled the secret goes THERE and only a
        ``kv:<name>`` reference is kept in config — matching the established
        pattern (``instance_vault`` / HE.NET / LE). With no vault the literal
        rides in ``global_config``, which the StateManager writes Fernet-
        encrypted to a 0700 dir, so it is still encrypted at rest.

        A ``kv:`` reference typed by the operator is passed through untouched."""
        # The operator already gave a vault reference, so store it unchanged.
        if tok.startswith("kv:"):
            return tok
        # Try to put the token in the active cloud vault and keep only a reference to it.
        try:
            import cloud_vault
            if cloud_vault.active_provider(hub) is not None:
                await cloud_vault.set_secret(hub, _EXT_SECRET_NAME, tok)
                return f"kv:{_EXT_SECRET_NAME}"
        # Vault failure: log it and fall back to keeping the token in encrypted state.
        except Exception as e:  # noqa: BLE001 — vault down must not lose the save
            import logging
            logging.getLogger("Hub").warning(
                "ext-source: vault store failed (%s) — keeping token in encrypted state", e)
        # No vault (or vault failed): keep the literal token.
        return tok

    def _ext_cfg(hub) -> dict:
        """Return a copy of the stored ``site_ext`` config, or ``{}`` if missing or malformed."""
        # Read the global config and the extension-source section in it.
        gc = hub.state.get_global_config() or {}
        c = gc.get("site_ext") or {}
        # Copy so callers can edit it without changing stored state until they save.
        return dict(c) if isinstance(c, dict) else {}

    def _ext_status(hub) -> dict:
        """Build the extension-source status for the UI, never including the token itself."""
        # os for paths; site_ext knows where the extension checkout lives.
        import os
        import site_ext
        # Current config, checkout directory, and stored token (or its vault reference).
        cfg = _ext_cfg(hub)
        d = site_ext.ext_dir(hub)
        tok = cfg.get("token") or ""
        # Detect whether a cloud vault is available; any error means "no vault".
        try:
            import cloud_vault
            vault = cloud_vault.active_provider(hub)
        except Exception:  # noqa: BLE001
            vault = None
        # List the extension modules (*.py files) in the checkout; empty if it cannot be read.
        modules = []
        try:
            modules = sorted(os.path.basename(p) for p in __import__("glob").glob(os.path.join(d, "*.py")))
        except Exception:  # noqa: BLE001
            pass
        # Report config, where the token is stored (vault/state/none), and checkout status.
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

    # Read the extension-source config and status.
    @app.get("/api/security/ext-source")
    async def ext_source_get(request: Request):
        """Current extension-source config + provisioning status. NEVER returns
        the stored token — only ``token_set``."""
        # Admin only; then return the status (no token).
        _guard(request)
        return _ext_status(hub)

    # Save the extension-source config.
    @app.put("/api/security/ext-source")
    async def ext_source_put(request: Request):
        """Save the extension source. Body: {enabled, repo, ref, token,
        clear_token}.

        ``token`` is merge-preserving: omitting it (or sending "") KEEPS the
        stored credential, so an admin can edit the repo/branch without having
        to re-enter the PAT (which the GET deliberately never gave them). Pass
        ``clear_token: true`` to actually remove it."""
        # Admin only; start from the stored config and apply only fields present in the body.
        _guard(request)
        body = await request.json() or {}
        cfg = _ext_cfg(hub)
        # Turn the loader on or off.
        if "enabled" in body:
            cfg["enabled"] = bool(body.get("enabled"))
        # The repo must be an https git URL (or blank to clear it).
        if "repo" in body:
            repo = (body.get("repo") or "").strip()
            if repo and not repo.startswith("https://"):
                raise HTTPException(status_code=400,
                                    detail="repo must be an https:// git URL")
            cfg["repo"] = repo
        # Branch/tag to use; blank means "main".
        if "ref" in body:
            cfg["ref"] = (body.get("ref") or "").strip() or "main"
        # Explicit token removal; also delete the vault copy when stored there.
        if body.get("clear_token"):
            old = cfg.pop("token", None)
            if old and str(old).startswith("kv:"):
                try:
                    import cloud_vault
                    await cloud_vault.delete_secret(hub, str(old)[3:])
                # The vault delete is best-effort; config no longer references it anyway.
                except Exception:  # noqa: BLE001 — config is authoritative
                    pass
        # Otherwise a non-empty token replaces the stored one (vault first, if available).
        else:
            tok = (body.get("token") or "").strip()
            if tok:
                cfg["token"] = await _store_token(hub, tok)
        # Save the updated config and return the new status.
        hub.state.update_global_config({"site_ext": cfg})
        return {"status": "ok", **_ext_status(hub)}

    # Remove the extension source entirely.
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
        # Admin only; shutil deletes the checkout tree, site_ext locates it.
        _guard(request)
        import shutil
        import site_ext

        # Read the config and remember whether a token was stored, for the response.
        cfg = _ext_cfg(hub)
        removed_token = bool(cfg.get("token"))
        old = cfg.get("token")
        # If the token lives in the vault, delete it there too (best-effort).
        if old and str(old).startswith("kv:"):
            try:
                import cloud_vault
                await cloud_vault.delete_secret(hub, str(old)[3:])
            # The vault delete is best-effort; the config is cleared below regardless.
            except Exception:  # noqa: BLE001 — config is authoritative
                pass

        # The directory is resolved BEFORE the config is cleared: ext_dir()
        # honours a `dir` override that lives in the very config being wiped,
        # so clearing first would delete the pointer and then remove the
        # default location instead of the one actually in use.
        target = site_ext.ext_dir(hub)
        # Track what was removed and any error text for the response.
        removed_dir = False
        detail = ""
        # Delete the whole checkout directory if it exists; a failure is reported, not raised.
        if os.path.isdir(target):
            try:
                shutil.rmtree(target)
                removed_dir = True
            except Exception as e:  # noqa: BLE001 — report, never raise
                detail = f"could not remove {target}: {e}"
                logger.warning("ext-source purge: %s", detail)

        # Reset the config to just "disabled", save immediately, and log the purge.
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
        # Admin only; site_ext performs the fetch.
        _guard(request)
        import site_ext
        # Status before the fetch, to tell later whether anything changed.
        before = _ext_status(hub)
        # Nothing to fetch until the source is enabled and has a repo.
        if not before["enabled"] or not before["repo"]:
            raise HTTPException(status_code=400,
                                detail="enable the source and set a repo first")
        # Fetch now and read the status afterwards.
        result = await site_ext.provision(hub)
        after = _ext_status(hub)
        if not result.get("ok"):
            # Report the actual cause instead of "check the log". The detail is
            # already redacted by site_ext, so it is safe to return.
            raise HTTPException(status_code=502, detail=result.get("detail")
                                or "fetch did not complete")
        # A restart is needed when the module list changed or this was the first fetch.
        return {"status": "ok", "restart_required": after["modules"] != before["modules"]
                or not before["provisioned"], **after}

    # ── Data subscription (Subscription Service) ─────────────────────────
    # The tenant-facing counterpart to the extension source above. That tile
    # fetches CODE from a private repo; this one subscribes to DATA from the
    # exchange. They are kept apart deliberately: the sensor content is no
    # longer distributed as source to anyone, so the only supported way to get
    # threat and simulation intelligence is this subscription.
    # Name of the vault secret holding the exchange-issued subscription credential.
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
        # Start with the chosen channels, then add each one's implied channels once.
        out = list(channels)
        for c in channels:
            for extra in _SUB_IMPLIED.get(c, ()):
                if extra not in out:
                    out.append(extra)
        return out

    def _sub_cfg(hub) -> dict:
        """Return a copy of the stored ``subscription`` config, or ``{}`` if missing or malformed.
        """
        # Read the global config and the subscription section in it.
        gc = hub.state.get_global_config() or {}
        c = gc.get("subscription") or {}
        # Copy so callers can edit it without changing stored state until they save.
        return dict(c) if isinstance(c, dict) else {}

    async def _sub_store_credential(hub, cred: str) -> str:
        """Persist the credential, preferring the vault — same pattern as the
        extension PAT. TMClient owns no storage, so persisting what enrolment
        returns is the caller's job; losing it means re-enrolling and burning a
        second credential for the same install."""
        # Try to put the credential in the active cloud vault and keep only a reference.
        try:
            import cloud_vault
            if cloud_vault.active_provider(hub) is not None:
                await cloud_vault.set_secret(hub, _SUB_SECRET_NAME, cred)
                return f"kv:{_SUB_SECRET_NAME}"
        # Vault failure: log it and fall back to keeping the credential in encrypted state.
        except Exception as e:  # noqa: BLE001 — vault down must not lose the credential
            logger.warning(
                "subscription: vault store failed (%s) — keeping credential in encrypted state", e)
        # No vault (or vault failed): keep the literal credential.
        return cred

    async def _sub_resolve_credential(hub, cfg: dict) -> str:
        """Return the usable credential, fetching it from the vault for a ``kv:`` reference.

        Returns "" when nothing is stored or the vault lookup fails.
        """
        # Stored credential or vault reference.
        cred = str(cfg.get("credential") or "")
        # Vault reference: resolve it; on failure log and return "" (not enrolled, in effect).
        if cred.startswith("kv:"):
            try:
                import cloud_vault
                return str(await cloud_vault.resolve_ref(hub, cred) or "")
            except Exception as e:  # noqa: BLE001
                logger.warning("subscription: could not resolve credential: %s", e)
                return ""
        # Literal credential stored in (encrypted) state.
        return cred

    def _sub_identity(cfg: dict) -> tuple:
        """Return ``(tenant_id, install_uuid)``, minting either if absent.

        LM has no pre-existing install identity, so one is generated here.
        Both are opaque: the exchange needs to tell participants apart and to
        group an org's several installs so they are not miscounted as several
        independent confirmations, and neither of those needs a real name.
        """
        # uuid mints random opaque ids.
        import uuid
        # Keep stored ids; otherwise generate random hex ids.
        tid = str(cfg.get("tenant_id") or "").strip() or uuid.uuid4().hex
        iid = str(cfg.get("install_uuid") or "").strip() or uuid.uuid4().hex
        return tid, iid

    def _sub_status(hub) -> dict:
        """Build the subscription status for the UI, never including the credential or PSK."""
        # Current config.
        cfg = _sub_cfg(hub)
        # Detect whether a cloud vault is available; any error means "no vault".
        try:
            import cloud_vault
            vault = cloud_vault.active_provider(hub)
        except Exception:  # noqa: BLE001
            vault = None
        # Only report channels that are still known (drops stale ones).
        chans = [c for c in (cfg.get("channels") or []) if c in _SUB_CHANNELS]
        # Stored credential or reference, used only to report where it is kept.
        cred = str(cfg.get("credential") or "")
        # Status fields shown on the Subscription tile.
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
        # Imported lazily so the client module loads only when the feature is used.
        from security.tm_client import TMClient
        # Stable (or newly minted) opaque identity for this install.
        tid, iid = _sub_identity(cfg)
        # The client gets identity, resolved credential, PSK, and the on/off flag.
        return TMClient(
            tenant_id=tid,
            install_uuid=iid,
            credential=await _sub_resolve_credential(hub, cfg),
            enrollment_psk=str(cfg.get("enrollment_psk") or ""),
            enabled=bool(cfg.get("enabled")),
        )

    # Read the subscription state.
    @app.get("/api/security/subscription")
    async def subscription_get(request: Request):
        """Current subscription state. Never returns the credential or PSK."""
        # Admin only; then return status (no secrets).
        _guard(request)
        return _sub_status(hub)

    # Change subscription settings.
    @app.put("/api/security/subscription")
    async def subscription_put(request: Request):
        """Turn the subscription on/off and choose channels.

        Deliberately does NOT accept a service URL. A tenant chooses whether to
        participate and in what; they do not choose where their sensor data is
        sent.
        """
        # Admin only; read the changes and the stored config.
        _guard(request)
        body = await request.json()
        cfg = _sub_cfg(hub)
        # Make sure an identity exists and is stored with the config.
        tid, iid = _sub_identity(cfg)
        cfg["tenant_id"], cfg["install_uuid"] = tid, iid

        # Turn the subscription on or off.
        if "enabled" in body:
            cfg["enabled"] = bool(body.get("enabled"))
        # Replace the channel list, which must be a list of known channel ids only.
        if "channels" in body:
            want = body.get("channels") or []
            if not isinstance(want, list):
                raise HTTPException(status_code=400, detail="channels must be a list")
            unknown = [c for c in want if c not in _SUB_CHANNELS]
            if unknown:
                raise HTTPException(status_code=400,
                                    detail=f"unknown channel(s): {', '.join(map(str, unknown))}")
            # Remove duplicates while keeping the order the operator chose.
            cfg["channels"] = list(dict.fromkeys(want))
        # Optional contact email given to the exchange.
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

        # Save immediately and return the new status.
        hub.state.update_global_config({"subscription": cfg})
        await hub.state.save_state_now()
        return {"status": "ok", **_sub_status(hub)}

    # Enrol this install with the exchange.
    @app.post("/api/security/subscription/enroll")
    async def subscription_enroll(request: Request):
        """Register with the exchange and persist whatever it returns.

        Approval may be immediate (with a PSK) or pending a human. Both are
        normal outcomes and are reported as such — an install waiting for
        approval is not an error state.
        """
        # Admin only; time stamps when enrolment succeeded.
        _guard(request)
        import time
        # Enrolment needs the subscription enabled and at least one known channel chosen.
        cfg = _sub_cfg(hub)
        if not cfg.get("enabled"):
            raise HTTPException(status_code=400,
                                detail="enable the subscription first")
        chans = [c for c in (cfg.get("channels") or []) if c in _SUB_CHANNELS]
        if not chans:
            raise HTTPException(status_code=400,
                                detail="choose at least one database to subscribe to")
        # Make sure an identity exists and is stored with the config.
        tid, iid = _sub_identity(cfg)
        cfg["tenant_id"], cfg["install_uuid"] = tid, iid

        # Optional body (a message for the approver); an empty body is allowed.
        body = await request.json() if await request.body() else {}
        # Build the client and request enrolment, including implied channels.
        client = await _sub_client(hub, cfg)
        result = await client.enroll(
            subscriptions=_sub_requested(chans),
            contact_email=str(cfg.get("contact_email") or ""),
            contact_message=str((body or {}).get("message") or ""),
        )
        # Record the outcome; "approved" and "pending" are normal, anything else is an error.
        status = str(result.get("status") or "error").lower()
        cfg["status"] = status
        cfg["last_error"] = "" if status in ("approved", "pending") else str(
            result.get("reason") or "enrolment did not complete")
        # When approved, store the issued credential (vault first) and the enrolment time.
        if status == "approved" and client.credential:
            cfg["credential"] = await _sub_store_credential(hub, client.credential)
            cfg["enrolled_at"] = time.time()
        # Save immediately and return the outcome plus the new status.
        hub.state.update_global_config({"subscription": cfg})
        await hub.state.save_state_now()
        return {"status": status, "reason": cfg["last_error"], **_sub_status(hub)}

    # Leave the exchange and forget the credential.
    @app.post("/api/security/subscription/unsubscribe")
    async def subscription_unsubscribe(request: Request):
        """Stop participating and forget the credential.

        Turning the feature off without dropping the credential would leave
        valid bearer material for the exchange sitting in state for an install
        that believes it has withdrawn.
        """
        # Admin only; read the config and the stored credential.
        _guard(request)
        cfg = _sub_cfg(hub)
        cred = str(cfg.get("credential") or "")
        # If the credential lives in the vault, delete it there too (best-effort).
        if cred.startswith("kv:"):
            try:
                import cloud_vault
                await cloud_vault.delete_secret(hub, cred[3:])
            # The vault delete is best-effort; the config is cleared below regardless.
            except Exception:  # noqa: BLE001 — config is authoritative
                pass
        # Identity is KEPT: re-subscribing with the same install_uuid is a
        # rejoin, while a fresh one would look like a new participant and lose
        # whatever standing this install had built up.
        for k in ("credential", "enrollment_psk", "enrolled_at", "last_error"):
            cfg.pop(k, None)
        # Turn everything off and mark the install not enrolled.
        cfg["enabled"] = False
        cfg["channels"] = []
        cfg["status"] = "not_enrolled"
        # Save immediately, log it, and return the new status.
        hub.state.update_global_config({"subscription": cfg})
        await hub.state.save_state_now()
        logger.warning("subscription: unsubscribed, credential forgotten")
        return {"status": "ok", **_sub_status(hub)}
