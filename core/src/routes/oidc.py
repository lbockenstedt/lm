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

from fastapi.responses import RedirectResponse, HTMLResponse
import html as _html


def _sso_error_page(message: str, status: int = 401) -> HTMLResponse:
    """A styled sign-in-error page (matches the LM look: HPE-green accent, card,
    light/dark aware) instead of a raw JSON ``{detail}`` — the OIDC callback is a
    browser navigation, so an error would otherwise dump JSON at the user."""
    msg = _html.escape(str(message or "Sign-in could not be completed."))
    page = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign-in error</title><style>
:root{color-scheme:light dark}
*{box-sizing:border-box}
body{margin:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;
 background:#f1f5f9;color:#334155;display:flex;min-height:100vh;align-items:center;justify-content:center;padding:1rem}
.card{background:#fff;border:1px solid #e2e8f0;border-radius:14px;box-shadow:0 10px 30px rgba(0,0,0,.08);
 max-width:460px;width:100%;overflow:hidden}
.bar{height:4px;background:#01A982}
.body{padding:2rem}
.icon{width:52px;height:52px;border-radius:50%;background:#fef2f2;color:#dc2626;display:flex;align-items:center;
 justify-content:center;font-size:28px;font-weight:700;margin:0 auto 1.1rem}
h1{font-size:1.15rem;font-weight:700;color:#263040;text-align:center;margin:0 0 .6rem}
p{font-size:.9rem;line-height:1.55;text-align:center;color:#475569;margin:0 0 1.5rem;white-space:pre-line}
a.btn{display:block;text-align:center;background:#01A982;color:#fff;text-decoration:none;font-weight:700;
 padding:.75rem 1rem;border-radius:8px;font-size:.9rem}
a.btn:hover{background:#018f6f}
.tag{font-size:.72rem;color:#94a3b8;text-align:center;margin-top:1.1rem;letter-spacing:.04em;text-transform:uppercase}
@media (prefers-color-scheme:dark){
 body{background:#0f172a;color:#cbd5e1}
 .card{background:#1e293b;border-color:#334155}
 h1{color:#f1f5f9}p{color:#94a3b8}
 .icon{background:#3f1d1d;color:#f87171}
}
</style></head><body>
<div class="card"><div class="bar"></div><div class="body">
<div class="icon">!</div>
<h1>Sign-in couldn&rsquo;t complete</h1>
<p>__MSG__</p>
<a class="btn" href="/">Return to login</a>
<div class="tag">Microsoft Entra SSO</div>
</div></div></body></html>""".replace("__MSG__", msg)
    return HTMLResponse(content=page, status_code=status)

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
    fetch_user_groups_via_app, default_oidc_dir,
)
from security.credential_store import resolve_private_key_material
import os as _os

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
            return _sso_error_page("Single sign-on is not configured on this hub.", 404)
        # Entra surfaces auth errors as ?error=… on the redirect.
        err = request.query_params.get("error")
        if err:
            desc = request.query_params.get("error_description", "")
            return _sso_error_page(f"Microsoft rejected the sign-in.\n{err}"
                                   + (f" — {desc}" if desc else ""), 401)
        code = request.query_params.get("code", "")
        qstate = request.query_params.get("state", "")
        if not code or not qstate:
            return _sso_error_page("The sign-in response was incomplete — please try again.", 400)
        cookie = request.cookies.get(_STATE_COOKIE, "")
        triple = verify_state_cookie(hub, cookie)
        if not triple:
            return _sso_error_page("Your sign-in session expired. Please start again.", 400)
        c_state, nonce, code_verifier = triple
        if not hmac_eq(c_state, qstate):
            return _sso_error_page("The sign-in request could not be verified. Please try again.", 400)
        try:
            discovery = await discover(cfg)
            tokens = await exchange_code(cfg, discovery, code, code_verifier)
            id_token = tokens.get("id_token")
            if not id_token:
                raise OidcError("token endpoint returned no id_token")
            jwks = await fetch_jwks(discovery.get("jwks_uri"))
            claims = verify_id_token(cfg, id_token, nonce, jwks)
            oid = claims.get("oid")
            if not oid:
                raise OidcError("id_token missing oid claim")
            member_of = extract_member_groups(claims)
            # Entra groups-claim overflow (>200 groups) → user-token Graph fallback.
            if not member_of and "groups" in (claims.get("_claim_names") or {}):
                at = tokens.get("access_token")
                if at:
                    member_of = await fetch_member_groups_via_graph(at)
            # No `groups` claim in the token at all (Entra's DEFAULT until Token
            # Configuration adds it) → fetch the user's groups with the hub's APP
            # token (Group.Read.All application). Best-effort: if that permission
            # isn't granted this stays empty and the allowed_group gate refuses.
            if not member_of:
                try:
                    member_of = await fetch_user_groups_via_app(cfg, oid)
                except Exception as _e:  # noqa: BLE001
                    logger.info("OIDC: app-token group fetch failed for %s "
                                "(membership stays empty): %s", oid, _e)
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
            return _sso_error_page(str(e), 401)
        except HTTPException as he:
            return _sso_error_page(str(he.detail), he.status_code)
        except Exception as e:  # noqa: BLE001
            logger.exception("OIDC callback failed")
            return _sso_error_page(f"Sign-in failed: {e}", 500)

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
        # ALWAYS generate into the hub's writable default dir (default_oidc_dir →
        # <data_dir>/oidc, LM_OIDC_DIR overrides) — NOT any stored path, which may
        # be a stale /etc/lm value from the old default that the hub can't write.
        # We then persist these paths, self-healing the stored config.
        oidc_dir = default_oidc_dir(hub)
        key_path = _os.path.join(oidc_dir, "client-key.pem")
        cert_path = _os.path.join(oidc_dir, "client-cert.pem")
        try:
            res = generate_client_cert(key_path=key_path, cert_path=cert_path,
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
        def _friendly(msg: str) -> str:
            # Translate the common Graph failures into an actionable fix.
            low = msg.lower()
            if "authorization_requestdenied" in low or "insufficient privileges" in low \
                    or " 403" in low:
                return ("The app registration is missing the Microsoft Graph "
                        "**Group.Read.All (Application)** permission with admin "
                        "consent — add it under API permissions → Grant admin "
                        "consent, then retry. (raw: " + msg[:160] + ")")
            if " 401" in low or "invalid_client" in low:
                return ("Entra rejected the app token — check the certificate is "
                        "uploaded and its thumbprint matches. (raw: " + msg[:160] + ")")
            return msg
        try:
            groups = await fetch_directory_groups(cfg)
            groups.sort(key=lambda g: (g.get("displayName") or "").lower())
            return {"groups": groups}
        except OidcError as e:
            return {"groups": [], "warning": _friendly(str(e))}
        except Exception as e:  # noqa: BLE001
            logger.exception("list_oidc_groups failed")
            return {"groups": [], "warning": _friendly(str(e))}

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