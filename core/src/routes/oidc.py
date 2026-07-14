"""OIDC (Azure Entra ID) login routes for the LM hub.

Three PUBLIC endpoints (added to ``_PUBLIC`` in ``api.py`` so the pre-session
access-control middleware lets them through):

* ``GET /auth/oidc/login``    — mint PKCE + state + nonce, stash in a signed
  ``lm_oidc_state`` cookie, 302 to the Entra authorize URL.
* ``GET /auth/oidc/callback`` — validate state, exchange the code (cert-signed
  client assertion), verify the id-token (MFA hard-enforced), provision/sync
  the user from Entra group membership, mint the ``lm_session`` cookie, 302
  to ``/`` (the DOMContentLoaded ``/auth/me`` poll re-enters the app).
* ``GET /auth/oidc/enabled``  — ``{enabled}`` so the WebUI can show the
  "Sign in with Microsoft" button without exposing config.

Plus ``/setup/oidc-config`` (admin-only via the ``/setup/`` gate) mirroring
``/setup/ldap-config``. OIDC is hub-side only — no spoke push.
"""
from __future__ import annotations

from fastapi.responses import RedirectResponse

from api import (
    HTTPException, Request, _SESSION_TTL, _cookie_secure, _record_session,
    _start_cache_for_tenant, logger,
)
from security.oidc import (
    OidcError, discover, exchange_code, extract_member_groups,
    fetch_jwks, fetch_member_groups_via_graph, get_oidc_config,
    provision_or_sync_entra_user, sign_state_cookie, verify_id_token,
    verify_state_cookie, authorize_url, build_user_data,
    generate_client_cert, cert_thumbprint_x5t, fetch_directory_groups,
)
from security.credential_store import resolve_private_key_material

_STATE_COOKIE = "lm_oidc_state"
_STATE_TTL_S = 300


def register(app, hub, ctx):
    """Register the OIDC login + config routes on the Hub app."""

    @app.get("/auth/oidc/enabled")
    async def oidc_enabled():
        """Public: tell the WebUI whether to show the Entra sign-in button.
        Returns only ``{enabled}`` — no tenant/client/cert material."""
        cfg = get_oidc_config(app.state.hub)
        return {"enabled": bool(cfg.enabled and cfg.ready)}

    @app.get("/auth/oidc/login")
    async def oidc_login(request: Request):
        """Begin the Entra Authorization-Code + PKCE flow. Mints ``state`` +
        ``nonce`` + ``code_verifier``, stashes them in a short-lived HMAC-signed
        ``lm_oidc_state`` cookie, and 302s to the Entra authorize URL."""
        hub = app.state.hub
        cfg = get_oidc_config(hub)
        if not cfg.enabled or not cfg.ready:
            raise HTTPException(status_code=404, detail="OIDC not configured")
        try:
            discovery = await discover(cfg)
        except Exception as e:  # noqa: BLE001
            logger.exception("OIDC discovery failed")
            raise HTTPException(status_code=503, detail=f"OIDC discovery failed: {e}")
        state, nonce, code_verifier = _triplet()
        _, code_challenge = _pair(code_verifier)
        url = authorize_url(cfg, discovery, state, nonce, code_challenge)
        resp = RedirectResponse(url, status_code=302)
        resp.set_cookie(
            key=_STATE_COOKIE, value=sign_state_cookie(hub, state, nonce, code_verifier),
            httponly=True, samesite="lax", max_age=_STATE_TTL_S,
            secure=_cookie_secure(),
        )
        return resp

    @app.get("/auth/oidc/callback")
    async def oidc_callback(request: Request):
        """Entra redirects here with ``?code=...&state=...``. Validate the
        state cookie, exchange the code, verify the id-token (MFA gate),
        provision/sync the user, mint the session cookie, 302 to ``/``."""
        hub = app.state.hub
        cfg = get_oidc_config(hub)
        if not cfg.enabled or not cfg.ready:
            raise HTTPException(status_code=404, detail="OIDC not configured")
        # Entra surfaces auth errors as ?error=… on the redirect.
        err = request.query_params.get("error")
        if err:
            raise HTTPException(
                status_code=401,
                detail=f"Entra denied login: {err} ({request.query_params.get('error_description', '')})")
        code = request.query_params.get("code", "")
        qstate = request.query_params.get("state", "")
        if not code or not qstate:
            raise HTTPException(status_code=400, detail="missing code/state")
        cookie = request.cookies.get(_STATE_COOKIE, "")
        triple = verify_state_cookie(hub, cookie)
        if not triple:
            raise HTTPException(status_code=400, detail="invalid or expired OIDC state")
        c_state, nonce, code_verifier = triple
        if not hmac_eq(c_state, qstate):
            raise HTTPException(status_code=400, detail="state mismatch")
        try:
            discovery = await discover(cfg)
            tokens = await exchange_code(cfg, discovery, code, code_verifier)
            id_token = tokens.get("id_token")
            if not id_token:
                raise OidcError("token endpoint returned no id_token")
            jwks = await fetch_jwks(discovery.get("jwks_uri"))
            claims = verify_id_token(cfg, id_token, nonce, jwks)
            member_of = extract_member_groups(claims)
            # Entra groups-claim overflow (>200 groups) → Graph fallback.
            if not member_of and "groups" in (claims.get("_claim_names") or {}):
                at = tokens.get("access_token")
                if at:
                    member_of = await fetch_member_groups_via_graph(at)
            oid = claims.get("oid")
            if not oid:
                raise OidcError("id_token missing oid claim")
            email = claims.get("email") or claims.get("preferred_username") or ""
            name = claims.get("name") or ""
            user_record = provision_or_sync_entra_user(
                hub, oid, email, name, member_of, cfg.allowed_group)
            user_data = build_user_data(hub, user_record, oid)
            token = _record_session(hub, user_data)
            resp = RedirectResponse("/", status_code=302)
            resp.set_cookie(
                key="lm_session", value=token,
                httponly=True, samesite="lax",
                max_age=_SESSION_TTL, secure=_cookie_secure(),
            )
            resp.delete_cookie(_STATE_COOKIE)
            for tid in user_data["tenants"]:
                _start_cache_for_tenant(hub, tid)
            logger.info("OIDC login ok for %s (groups=%s tenants=%s)",
                        oid, member_of, user_data["tenants"])
            return resp
        except OidcError as e:
            logger.warning("OIDC callback refused: %s", e)
            raise HTTPException(status_code=401, detail=str(e))
        except HTTPException:
            raise
        except Exception as e:  # noqa: BLE001
            logger.exception("OIDC callback failed")
            raise HTTPException(status_code=500, detail=f"OIDC login failed: {e}")

    # ── Admin: OIDC configuration (mirror /setup/ldap-config) ────────────────
    # /setup/* is admin-only via the access-control middleware; no extra gate.
    @app.get("/setup/oidc-config")
    async def get_oidc_config_route():
        hub = app.state.hub
        config = hub.state.system_state.get("global_config", {}).get("oidc", {})
        # The stored config holds PATHS only (never key material). Resolve the
        # EFFECTIVE key/cert paths (with the /etc/lm/oidc auto-detect defaults) and
        # report whether each file is present + the cert thumbprint, so the form
        # can show "cert ready / generate needed" and the value to upload to Entra.
        cfg = get_oidc_config(hub)
        status = {"key_path": cfg.key_path, "cert_path": cfg.cert_path,
                  "key_present": False, "cert_present": False, "thumbprint": ""}
        try:
            status["key_present"] = bool(resolve_private_key_material(cfg.key_path))
        except Exception:  # noqa: BLE001
            pass
        try:
            cert_pem = resolve_private_key_material(cfg.cert_path) if cfg.cert_path else None
            if cert_pem:
                status["cert_present"] = True
                status["thumbprint"] = cert_thumbprint_x5t(cert_pem)
        except Exception:  # noqa: BLE001
            pass
        return {"config": config, "cert_status": status}

    @app.post("/setup/oidc-config/generate-cert")
    async def generate_oidc_cert(request: Request):
        """Auto-create the Entra client cert (self-signed RSA-2048) at the
        configured/effective key+cert paths, and persist those paths. Returns the
        public ``cert_pem`` + ``thumbprint`` to upload to the Entra app
        registration. Refuses to overwrite an existing key unless ``{force:true}``.
        Admin-gated via the ``/setup/`` middleware."""
        hub = app.state.hub
        try:
            data = await request.json()
        except Exception:
            data = {}
        force = bool((data or {}).get("force"))
        cfg = get_oidc_config(hub)
        try:
            res = generate_client_cert(key_path=cfg.key_path, cert_path=cfg.cert_path,
                                       force=force)
        except OidcError as e:
            # Existing key without force → 409 so the UI can prompt "overwrite?".
            raise HTTPException(status_code=409, detail=str(e))
        except PermissionError as e:
            raise HTTPException(status_code=500,
                detail=(f"cannot write to {cfg.key_path} — the hub process needs "
                        f"write access to that directory: {e}"))
        except Exception as e:  # noqa: BLE001
            logger.exception("generate_oidc_cert failed")
            raise HTTPException(status_code=500, detail=str(e))
        # Persist the resolved paths so the stored config reflects what's on disk.
        gc = hub.state.system_state.get("global_config", {})
        oidc = dict(gc.get("oidc", {}) or {})
        oidc["key_path"] = res["key_path"]
        oidc["cert_path"] = res["cert_path"]
        gc["oidc"] = oidc
        hub.state.system_state["global_config"] = gc
        hub.state.save_state()
        return {"status": "ok", "key_path": res["key_path"], "cert_path": res["cert_path"],
                "thumbprint": res["thumbprint"], "cert_pem": res["cert_pem"]}

    @app.get("/setup/oidc/groups")
    async def list_oidc_groups():
        """List the tenant's Entra groups (id + displayName) so the admin can map
        an Entra group → a permission group / tenant by NAME instead of pasting a
        GUID. Uses an app-level Graph read (client-credentials, cert-signed) — the
        app registration needs Graph ``Group.Read.All`` (application) with admin
        consent. Degrades to ``{groups:[], warning}`` instead of erroring so the
        UI can fall back to manual entry. Admin-gated via the ``/setup/`` gate."""
        hub = app.state.hub
        cfg = get_oidc_config(hub)
        if not (cfg.tenant_id and cfg.client_id):
            return {"groups": [], "warning": "Set the tenant + client ID (and generate the certificate) first."}
        try:
            groups = await fetch_directory_groups(cfg)
            groups.sort(key=lambda g: (g.get("displayName") or "").lower())
            return {"groups": groups}
        except OidcError as e:
            return {"groups": [], "warning": str(e)}
        except Exception as e:  # noqa: BLE001
            logger.exception("list_oidc_groups failed")
            return {"groups": [], "warning": str(e)}

    @app.post("/setup/oidc-config")
    async def update_oidc_config(request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            config = data.get("config", {}) or {}
            # Whitelist stored fields. cert_path/key_path are intentionally NOT
            # stored from the UI — they're auto-managed at the hub default dir
            # (default_oidc_dir → <data_dir>/oidc, LM_OIDC_DIR/LM_OIDC_CLIENT_* env
            # still override). Omitting them here also CLEARS any stale stored path
            # (this dict replaces the whole oidc config), so a value left over from
            # the old /etc/lm default can't linger and break generation.
            clean = {
                "enabled": bool(config.get("enabled", False)),
                "tenant_id": str(config.get("tenant_id") or "").strip(),
                "client_id": str(config.get("client_id") or "").strip(),
                "redirect_uri": str(config.get("redirect_uri") or "").strip(),
                "allowed_group": str(config.get("allowed_group") or "").strip(),
                "require_mfa": bool(config.get("require_mfa", True)),
            }
            global_config = hub.state.system_state.get("global_config", {})
            global_config["oidc"] = clean
            hub.state.system_state["global_config"] = global_config
            hub.state.save_state()
            # OIDC is hub-side only — no spoke push (unlike ldap-config).
            return {"status": "ok"}
        except Exception as e:  # noqa: BLE001
            logger.exception("update_oidc_config failed")
            raise HTTPException(status_code=500, detail=str(e))


# ── helpers ─────────────────────────────────────────────────────────────────

def _triplet():
    """Return (state, nonce, code_verifier) — three independent randoms."""
    import secrets as _s
    return _s.token_urlsafe(24), _s.token_urlsafe(24), _s.token_urlsafe(48)


def _pair(code_verifier: str):
    """Return (code_verifier, code_challenge) — S256 PKCE."""
    import hashlib, base64
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()).rstrip(b"=").decode()
    return code_verifier, challenge


def hmac_eq(a: str, b: str) -> bool:
    """Constant-time string compare (state validation)."""
    import hmac as _hmac
    return _hmac.compare_digest(a or "", b or "")