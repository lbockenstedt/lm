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
# Postponed evaluation of annotations, so "str | None" hints work on older Pythons too.
from __future__ import annotations

# Redirect (302) responses for the login flow, and HTML responses for the styled error page.
from fastapi.responses import RedirectResponse, HTMLResponse
# HTML escaping, so error text can never inject markup into the error page.
import html as _html


def _friendly_title(detail: str) -> str:
    """Map an OIDC error to a plain-language headline (the technical detail is
    shown below it)."""
    # Match on lower-cased keywords; the first matching category wins.
    d = (detail or "").lower()
    if "mfa" in d or "multi-factor" in d:
        return "MFA misconfigured"
    if "allowed group" in d or "not a member" in d:
        return "Access denied"
    if "certificate" in d or "private key" in d or "x5t" in d:
        return "SSO certificate error"
    if "token exchange" in d or "aadsts" in d or "rejected" in d:
        return "Microsoft rejected the sign-in"
    if "state" in d or "expired" in d or "verified" in d:
        return "Sign-in session expired"
    if "not configured" in d or "no id_token" in d or "oid claim" in d:
        return "SSO configuration error"
    # Anything unrecognised gets a generic headline.
    return "Sign-in couldn’t complete"


def _is_stale_auth(detail: str) -> bool:
    """True when a callback failure is a stale/used/expired authorization code
    (or grant) — fixable only by restarting the flow for a FRESH code, not a
    config/authorization problem (allowed-group, MFA, cert) where a restart just
    loops. Matches Entra AADSTS54005 (code already redeemed) and 70008 (expired
    code), plus the generic OAuth invalid_grant."""
    # Lower-case once, then look for the known stale-code markers.
    d = (detail or "").lower()
    return ("aadsts54005" in d or "already redeemed" in d
            or "aadsts70008" in d or "invalid_grant" in d
            or "invalid grant" in d
            or ("code" in d and "expired" in d))


def _sso_error_page(detail: str, status: int = 401, title: str | None = None) -> HTMLResponse:
    """A styled sign-in-error page (matches the LM look: HPE-green accent, card,
    light/dark aware) instead of a raw JSON ``{detail}`` — the OIDC callback is a
    browser navigation, so an error would otherwise dump JSON at the user. Shows a
    plain-language ``title`` headline with the actual error ``detail`` beneath."""
    # Escape the headline and the detail before putting them in the page.
    heading = _html.escape(title or _friendly_title(detail))
    msg = _html.escape(str(detail or "Sign-in could not be completed."))
    # Inline HTML/CSS template; __TITLE__ and __MSG__ are swapped for the escaped text.
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
h1{font-size:1.2rem;font-weight:700;color:#263040;text-align:center;margin:0 0 1rem}
.detail{font-size:.82rem;line-height:1.55;color:#475569;background:#f8fafc;border:1px solid #e2e8f0;
 border-radius:8px;padding:.75rem .9rem;margin:0 0 1.5rem;white-space:pre-line;word-break:break-word}
a.btn{display:block;text-align:center;background:#01A982;color:#fff;text-decoration:none;font-weight:700;
 padding:.75rem 1rem;border-radius:8px;font-size:.9rem}
a.btn:hover{background:#018f6f}
.tag{font-size:.72rem;color:#94a3b8;text-align:center;margin-top:1.1rem;letter-spacing:.04em;text-transform:uppercase}
@media (prefers-color-scheme:dark){
 body{background:#0f172a;color:#cbd5e1}
 .card{background:#1e293b;border-color:#334155}
 h1{color:#f1f5f9}
 .detail{color:#cbd5e1;background:#0f172a;border-color:#334155}
 .icon{background:#3f1d1d;color:#f87171}
}
</style></head><body>
<div class="card"><div class="bar"></div><div class="body">
<div class="icon">!</div>
<h1>__TITLE__</h1>
<div class="detail">__MSG__</div>
<a class="btn" href="/">Return to login</a>
<div class="tag">Microsoft Entra SSO</div>
</div></div></body></html>""".replace("__TITLE__", heading).replace("__MSG__", msg)
    # Return the page with the given HTTP status (401 by default).
    return HTMLResponse(content=page, status_code=status)

# Request/exception types, session settings and helpers (cookie flags, client IP, session store,
# cache warm-up) and the logger from the main API module.
from api import (
    HTTPException, Request, _SESSION_TTL, _client_ip, _cookie_secure, _record_session,
    cache_kick_login, logger,
)
# The Entra OIDC protocol helpers: discovery, token exchange and verification, group lookup, user
# provisioning, state cookie signing and client certificate handling.
from security.oidc import (
    OidcError, discover, exchange_code, extract_member_groups,
    fetch_jwks, fetch_member_groups_via_graph, get_oidc_config,
    provision_or_sync_entra_user, sign_state_cookie, verify_id_token,
    verify_state_cookie, authorize_url, build_user_data,
    generate_client_cert, cert_thumbprint_x5t, fetch_directory_groups,
    fetch_user_groups_via_app, default_oidc_dir, clear_app_token_cache,
)
# Loads a PEM from a file path or credential-store reference, to check the SSO key/cert exist.
from security.credential_store import resolve_private_key_material
# os.path is used to build the certificate file paths.
import os as _os

# Name of the short-lived cookie carrying the signed state/nonce/PKCE verifier during login.
_STATE_COOKIE = "lm_oidc_state"
# Lifetime of that cookie in seconds (5 minutes): long enough to sign in, short enough to limit
# replay.
_STATE_TTL_S = 300


def register(app, hub, ctx):
    """Register the OIDC login + config routes on the Hub app."""

    @app.get("/auth/oidc/enabled")
    async def oidc_enabled():
        """Public: tell the WebUI whether to show the Entra sign-in button.
        Returns only ``{enabled}`` — no tenant/client/cert material."""
        # Read the current config; the button shows only when enabled and fully set up.
        cfg = get_oidc_config(app.state.hub)
        return {"enabled": bool(cfg.enabled and cfg.ready)}

    @app.get("/auth/oidc/login")
    async def oidc_login(request: Request):
        """Begin the Entra Authorization-Code + PKCE flow. Mints ``state`` +
        ``nonce`` + ``code_verifier``, stashes them in a short-lived HMAC-signed
        ``lm_oidc_state`` cookie, and 302s to the Entra authorize URL."""
        # Load the OIDC config; a disabled or incomplete setup looks like "not found".
        hub = app.state.hub
        cfg = get_oidc_config(hub)
        if not cfg.enabled or not cfg.ready:
            raise HTTPException(status_code=404, detail="OIDC not configured")
        # Fetch Entra's discovery document (endpoints, keys); an outage becomes a 503.
        try:
            discovery = await discover(cfg)
        except Exception as e:  # noqa: BLE001
            logger.exception("OIDC discovery failed")
            raise HTTPException(status_code=503, detail=f"OIDC discovery failed: {e}")
        # Mint fresh random state/nonce/verifier and the matching PKCE challenge.
        state, nonce, code_verifier = _triplet()
        _, code_challenge = _pair(code_verifier)
        # Return the user to the host they started from when it is on the allowlist.
        redirect_uri = _pick_redirect_uri(cfg, request)
        # Build the Entra authorize URL and redirect the browser to it.
        url = authorize_url(cfg, discovery, state, nonce, code_challenge,
                            redirect_uri=redirect_uri)
        resp = RedirectResponse(url, status_code=302)
        # Store the signed state in an HttpOnly cookie so the callback can verify it.
        resp.set_cookie(
            key=_STATE_COOKIE,
            value=sign_state_cookie(hub, state, nonce, code_verifier, redirect_uri),
            httponly=True, samesite="lax", max_age=_STATE_TTL_S,
            secure=_cookie_secure(),
        )
        return resp

    @app.get("/auth/oidc/callback")
    async def oidc_callback(request: Request):
        """Entra redirects here with ``?code=...&state=...``. Validate the
        state cookie, exchange the code, verify the id-token (MFA gate),
        provision/sync the user, mint the session cookie, 302 to ``/``."""
        # Load the OIDC config; a disabled or incomplete setup shows the error page.
        hub = app.state.hub
        cfg = get_oidc_config(hub)
        if not cfg.enabled or not cfg.ready:
            return _sso_error_page("Single sign-on is not configured on this hub.", 404)
        # A single-use auth code that arrives stale — e.g. the hub-down splash
        # auto-refreshed THIS callback URL and replayed an already-redeemed or
        # expired ``?code=`` — can never succeed on replay; it just dead-ends at
        # "Microsoft rejected the sign-in". Instead, restart the login flow once
        # to mint a FRESH code (seamless: the user's live Entra SSO session
        # re-issues without re-typing). ``lm_oidc_retry`` bounds this to a SINGLE
        # auto-restart so a genuinely broken flow shows the error, never loops.
        _retried = request.cookies.get("lm_oidc_retry")

        def _recover_or_error(detail: str, status: int):
            """Restart the login once for a fresh code; on a second failure show the error page."""
            # First failure: redirect back to the login start and set a 2-minute retry marker
            # cookie.
            if not _retried:
                r = RedirectResponse("/auth/oidc/login", status_code=302)
                r.set_cookie("lm_oidc_retry", "1", max_age=120, httponly=True,
                             samesite="lax", secure=_cookie_secure())
                return r
            # Already retried: show the error and clear the marker so the next attempt starts clean.
            page = _sso_error_page(detail, status)
            page.delete_cookie("lm_oidc_retry")
            return page
        # Entra surfaces auth errors as ?error=… on the redirect.
        err = request.query_params.get("error")
        if err:
            desc = request.query_params.get("error_description", "")
            return _sso_error_page(f"Microsoft rejected the sign-in.\n{err}"
                                   + (f" — {desc}" if desc else ""), 401)
        # The redirect must carry both the authorization code and the state.
        code = request.query_params.get("code", "")
        qstate = request.query_params.get("state", "")
        if not code or not qstate:
            return _sso_error_page("The sign-in response was incomplete — please try again.", 400)
        # Read and verify the signed state cookie; a missing or expired one restarts the flow once.
        cookie = request.cookies.get(_STATE_COOKIE, "")
        triple = verify_state_cookie(hub, cookie)
        if not triple:
            return _recover_or_error("Your sign-in session expired. Please start again.", 400)
        # Unpack the stored values and make sure the state matches the one in the URL (CSRF check).
        c_state, nonce, code_verifier, redirect_uri = triple
        if not hmac_eq(c_state, qstate):
            return _sso_error_page("The sign-in request could not be verified. Please try again.", 400)
        # Run the token exchange and user provisioning; failures are mapped to error pages below.
        try:
            # Exchange the code for tokens using the PKCE verifier and the same redirect URI.
            discovery = await discover(cfg)
            tokens = await exchange_code(cfg, discovery, code, code_verifier,
                                         redirect_uri=redirect_uri or None)
            # An id_token is required to know who signed in.
            id_token = tokens.get("id_token")
            if not id_token:
                raise OidcError("token endpoint returned no id_token")
            # Fetch Entra's signing keys and verify the id_token (signature, nonce, MFA).
            jwks = await fetch_jwks(discovery.get("jwks_uri"))
            claims = verify_id_token(cfg, id_token, nonce, jwks)
            # The oid claim is the user's stable Entra object id.
            oid = claims.get("oid")
            if not oid:
                raise OidcError("id_token missing oid claim")
            # Read group memberships from the token.
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
            # Pick the best available email and display name from the claims.
            email = claims.get("email") or claims.get("preferred_username") or ""
            name = claims.get("name") or ""
            # Create or update the local user from Entra, refusing if not in the allowed group.
            user_record = provision_or_sync_entra_user(
                hub, oid, email, name, member_of, cfg.allowed_group)
            # Build the session data and record a session bound to the client IP.
            user_data = build_user_data(hub, user_record, oid)
            token = _record_session(hub, user_data, bind_ip=_client_ip(request))
            # Send the browser to the app with the new session cookie.
            resp = RedirectResponse("/", status_code=302)
            resp.set_cookie(
                key="lm_session", value=token,
                httponly=True, samesite="lax",
                max_age=_SESSION_TTL, secure=_cookie_secure(),
            )
            # The login flow is finished: clear the state and retry cookies.
            resp.delete_cookie(_STATE_COOKIE)
            resp.delete_cookie("lm_oidc_retry")
            # Warm caches for the user and log the successful login.
            cache_kick_login(hub, user_data)
            logger.info("OIDC login ok for %s (groups=%s tenants=%s)",
                        oid, member_of, user_data["tenants"])
            return resp
        # Expected OIDC refusals: a stale code restarts the flow once, anything else shows the
        # error.
        except OidcError as e:
            logger.warning("OIDC callback refused: %s", e)
            if _is_stale_auth(str(e)):
                return _recover_or_error(str(e), 401)
            return _sso_error_page(str(e), 401)
        # HTTP errors raised during provisioning are shown with their own status.
        except HTTPException as he:
            return _sso_error_page(str(he.detail), he.status_code)
        # Anything unexpected is logged with a traceback and shown as a 500 page.
        except Exception as e:  # noqa: BLE001
            logger.exception("OIDC callback failed")
            return _sso_error_page(f"Sign-in failed: {e}", 500)

    # ── Admin: OIDC configuration (mirror /setup/ldap-config) ────────────────
    # /setup/* is admin-only via the access-control middleware; no extra gate.
    @app.get("/setup/oidc-config")
    async def get_oidc_config_route():
        """Return the stored OIDC config plus the effective key/cert paths, whether they exist, and
        the cert thumbprint.
        """
        # Read the stored (paths-only) config.
        hub = app.state.hub
        config = hub.state.system_state.get("global_config", {}).get("oidc", {})
        # The stored config holds PATHS only (never key material). Resolve the
        # EFFECTIVE key/cert paths (with the /etc/lm/oidc auto-detect defaults) and
        # report whether each file is present + the cert thumbprint, so the form
        # can show "cert ready / generate needed" and the value to upload to Entra.
        cfg = get_oidc_config(hub)
        status = {"key_path": cfg.key_path, "cert_path": cfg.cert_path,
                  "key_present": False, "cert_present": False, "thumbprint": ""}
        # Check the private key can be loaded; any failure just leaves key_present False.
        try:
            status["key_present"] = bool(resolve_private_key_material(cfg.key_path))
        except Exception:  # noqa: BLE001
            pass
        # Check the certificate exists and compute its thumbprint; failures leave the defaults.
        try:
            cert_pem = resolve_private_key_material(cfg.cert_path) if cfg.cert_path else None
            if cert_pem:
                status["cert_present"] = True
                status["thumbprint"] = cert_thumbprint_x5t(cert_pem)
        except Exception:  # noqa: BLE001
            pass
        # Return the config and the certificate status for the form.
        return {"config": config, "cert_status": status}

    @app.post("/setup/oidc-config/generate-cert")
    async def generate_oidc_cert(request: Request):
        """Auto-create the Entra client cert (self-signed RSA-2048) at the
        configured/effective key+cert paths, and persist those paths. Returns the
        public ``cert_pem`` + ``thumbprint`` to upload to the Entra app
        registration. Refuses to overwrite an existing key unless ``{force:true}``.
        Admin-gated via the ``/setup/`` middleware."""
        hub = app.state.hub
        # Read the optional JSON body; a missing or broken body is treated as empty.
        try:
            data = await request.json()
        except Exception:
            data = {}
        # force=true allows overwriting an existing key.
        force = bool((data or {}).get("force"))
        # ALWAYS generate into the hub's writable default dir (default_oidc_dir →
        # <data_dir>/oidc, LM_OIDC_DIR overrides) — NOT any stored path, which may
        # be a stale /etc/lm value from the old default that the hub can't write.
        # We then persist these paths, self-healing the stored config.
        oidc_dir = default_oidc_dir(hub)
        key_path = _os.path.join(oidc_dir, "client-key.pem")
        cert_path = _os.path.join(oidc_dir, "client-cert.pem")
        # Generate the key and self-signed certificate.
        try:
            res = generate_client_cert(key_path=key_path, cert_path=cert_path,
                                       force=force)
        except OidcError as e:
            # Existing key without force → 409 so the UI can prompt "overwrite?".
            raise HTTPException(status_code=409, detail=str(e))
        # The directory is not writable by the hub process.
        except PermissionError as e:
            raise HTTPException(status_code=500,
                detail=(f"cannot write to {cfg.key_path} — the hub process needs "
                        f"write access to that directory: {e}"))
        # Anything else is logged with a traceback and reported as a 500.
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
        hub.state._mark_dirty()
        # Drop any cached app token, since it was signed with the old certificate.
        clear_app_token_cache()
        # Best effort: a failed push is retried when the spoke reconnects.
        # A fresh Entra client cert/key changes what the directory mirror must use
        # for Entra (ROPC) auth — re-push to every connected ldap spoke now.
        try:
            await hub.push_ldap_config_all()
        except Exception:  # noqa: BLE001 — best-effort; reconnect re-pushes
            logger.debug("generate_oidc_cert: ldap re-push skipped", exc_info=True)
        # Return the paths, thumbprint and public certificate to upload to Entra.
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
        # Load the config; without tenant and client id there is nothing to query.
        hub = app.state.hub
        cfg = get_oidc_config(hub)
        if not (cfg.tenant_id and cfg.client_id):
            return {"groups": [], "warning": "Set the tenant + client ID (and generate the certificate) first."}
        def _friendly(msg: str) -> str:
            """Turn a raw Graph error into a message telling the admin how to fix it."""
            # Translate the common Graph failures into an actionable fix.
            low = msg.lower()
            if "authorization_requestdenied" in low or "insufficient privileges" in low \
                    or " 403" in low:
                # Missing Graph permission or admin consent.
                return ("The app registration is missing the Microsoft Graph "
                        "**Group.Read.All (Application)** permission with admin "
                        "consent — add it under API permissions → Grant admin "
                        "consent, then retry. (raw: " + msg[:160] + ")")
            # The app token itself was refused (certificate not uploaded or wrong).
            if " 401" in low or "invalid_client" in low:
                return ("Entra rejected the app token — check the certificate is "
                        "uploaded and its thumbprint matches. (raw: " + msg[:160] + ")")
            # Unknown error: show it as-is.
            return msg
        # Fetch the groups and sort them by name (case-insensitive) for the dropdown.
        try:
            groups = await fetch_directory_groups(cfg)
            groups.sort(key=lambda g: (g.get("displayName") or "").lower())
            return {"groups": groups}
        # On failure return an empty list plus an actionable warning, so the UI can fall back to
        # manual entry.
        except OidcError as e:
            return {"groups": [], "warning": _friendly(str(e))}
        except Exception as e:  # noqa: BLE001
            logger.exception("list_oidc_groups failed")
            return {"groups": [], "warning": _friendly(str(e))}

    @app.post("/setup/oidc-config")
    async def update_oidc_config(request: Request):
        """Save the OIDC settings posted from the Setup page (tenant, client, redirect URIs, allowed
        group).
        """
        # Everything below runs inside one try so any failure becomes a logged 500.
        hub = app.state.hub
        # Read the posted config from the JSON body.
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
                # Extra registered redirect URIs (one per edge-proxy hostname) so
                # SSO can return users to the proxy they started from. Accepts a
                # list or a comma/newline-delimited string; stored as a clean list.
                "redirect_uris": _clean_uri_list(config.get("redirect_uris")),
                "allowed_group": str(config.get("allowed_group") or "").strip(),
            }
            # Replace the stored OIDC config and flag the state for saving.
            global_config = hub.state.system_state.get("global_config", {})
            global_config["oidc"] = clean
            hub.state.system_state["global_config"] = global_config
            hub.state._mark_dirty()
            # Drop any cached app token, since the tenant/client may have changed.
            clear_app_token_cache()
            # Best effort: a failed push is retried when the spoke reconnects.
            # The hub's OIDC login is hub-side only, BUT the directory (LDAP)
            # spoke reuses these Entra app creds for ROPC auth of Entra-backed
            # directory users — re-push the LDAP+Entra config to every connected
            # ldap spoke so a tenant/client change reaches the mirror now.
            try:
                await hub.push_ldap_config_all()
            except Exception:  # noqa: BLE001 — best-effort; reconnect re-pushes
                logger.debug("update_oidc_config: ldap re-push skipped", exc_info=True)
            return {"status": "ok"}
        # Any failure is logged with a traceback and reported as a 500.
        except Exception as e:  # noqa: BLE001
            logger.exception("update_oidc_config failed")
            raise HTTPException(status_code=500, detail=str(e))


# ── helpers ─────────────────────────────────────────────────────────────────

def _triplet():
    """Return (state, nonce, code_verifier) — three independent randoms."""
    # secrets gives cryptographically strong random values.
    import secrets as _s
    # 24 random bytes each for state and nonce; 48 for the PKCE verifier (within the 43-128 char
    # rule).
    return _s.token_urlsafe(24), _s.token_urlsafe(24), _s.token_urlsafe(48)


def _clean_uri_list(val) -> list:
    """Normalize an admin-supplied redirect-URI allowlist (list or delimited
    string) to an ordered, de-duplicated list of trimmed non-empty strings."""
    # Regular expressions, for splitting a delimited string.
    import re as _re
    # Turn the input into a list of strings: a list as-is, a string split on whitespace/commas.
    items = []
    if isinstance(val, (list, tuple)):
        items = [str(v) for v in val]
    elif isinstance(val, str):
        items = _re.split(r"[\s,]+", val)
    # Keep each trimmed, non-empty URI once, in the order given.
    out = []
    for v in items:
        v = (v or "").strip()
        if v and v not in out:
            out.append(v)
    return out


def _pick_redirect_uri(cfg, request) -> str:
    """Choose the Entra ``redirect_uri`` for THIS login from the host the browser
    actually used, so a user who started at their local edge proxy is returned to
    that proxy after auth — not the hub's default host.

    The originating host comes from ``X-Forwarded-Host``/``-Proto`` (stamped by
    the edge proxy) or the direct ``Host``. Only hosts whose callback URL exactly
    matches an entry in the configured allowlist (``cfg.redirect_uris`` — every
    one also registered in Entra) are honored; anything else (incl. a spoofed
    X-Forwarded-Host) falls back to the default ``cfg.redirect_uri``. This keeps
    the flow safe from open-redirect and satisfies Entra's exact-match rule."""
    # Scheme the browser used: first X-Forwarded-Proto value, else the request's own scheme, else
    # https.
    fwd_proto = request.headers.get("x-forwarded-proto") or ""
    proto = (fwd_proto.split(",")[0].strip()
             or (request.url.scheme if request.url else "") or "https")
    # Host the browser used: first X-Forwarded-Host value, else the Host header.
    fwd_host = request.headers.get("x-forwarded-host") or request.headers.get("host") or ""
    host = fwd_host.split(",")[0].strip()
    # Only use that host when its exact callback URL is on the allowlist.
    if host:
        candidate = f"{proto}://{host}/auth/oidc/callback"
        if candidate in (cfg.redirect_uris or []):
            return candidate
    # Otherwise use the default redirect URI.
    return cfg.redirect_uri


def _pair(code_verifier: str):
    """Return (code_verifier, code_challenge) — S256 PKCE."""
    # hashlib for SHA-256, base64 for URL-safe encoding.
    import hashlib, base64
    # S256 challenge: base64url(SHA-256(verifier)) without "=" padding, as PKCE requires.
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()).rstrip(b"=").decode()
    return code_verifier, challenge


def hmac_eq(a: str, b: str) -> bool:
    """Constant-time string compare (state validation)."""
    # hmac.compare_digest takes the same time whatever the input, so it leaks nothing via timing.
    import hmac as _hmac
    # None is treated as an empty string so a missing value simply fails to match.
    return _hmac.compare_digest(a or "", b or "")