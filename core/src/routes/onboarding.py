"""onboarding.py — generic, module-agnostic tenant self-service spoke
onboarding (the "Add Server" button).

A tenant-admin generates a PSK for their OWN tenant; ANY new spoke (nac, dns,
dhcp, nw, certificates, ...) that connects to the hub presenting that PSK
auto-approves + auto-binds to the tenant — see
``main.py::LabManagerHub._try_psk_self_provision``, which is already
module_type-agnostic (it just registers+approves+binds whatever spoke_id
presented a valid PSK). Nothing there needed to change; this file is purely
the tenant-facing surface to generate/list/revoke that PSK without going
through the Global-Admin-only ``/setup/*`` spoke-approval screen.

Distinct from ``/sim/api/tenant/{tenant}/onboarding-psk``
(simulations/routes.py), which manages the SAME underlying PSK store
(``hub.simulations_store``) but ALSO pushes the PSK to the tenant's
Client-Sim spoke for a DIFFERENT mechanism — that spoke's own sub-agent
vouch/relay onboarding (a cs-spoke-hosts-its-own-children flow). This file
is the generic path for onboarding a spoke that connects DIRECTLY to the
hub, with no cs spoke involved — the PSK itself isn't module-scoped (any
spoke type can use it), only tenant-scoped, so reusing the same store here
is correct; the cs-specific push side effect is not.

Mounted under ``/tenant/*`` so the existing tenant-admin-or-admin middleware
gate (api.py, ``path.startswith("/tenant/")``) covers it for free — this
file only adds the per-tenant ownership check on top (a tenant-admin may
manage only their OWN tenant's PSKs).
"""
import secrets

from api import HTTPException, Request, logger


def register(app, hub, ctx):
    """Register the generic onboarding-PSK routes on the Hub app."""
    _session_user = ctx._session_user
    _is_admin = ctx._is_admin
    _is_tenant_admin = ctx._is_tenant_admin

    def _require_owns_tenant(request: Request, tenant: str):
        """The ``/tenant/*`` middleware gate already requires tenant-admin-or-
        admin to reach here; re-checked anyway (defense in depth, matching
        tenant_devices.py's ``_bind_gate`` — never trust the middleware
        alone), plus the per-tenant ownership check a tenant-admin needs
        (never another tenant's PSKs — mirrors tenant_devices.py's
        ``_owns``)."""
        sess = _session_user(request)
        if _is_admin(sess):
            return sess
        if not (sess and _is_tenant_admin(sess)):
            raise HTTPException(status_code=403, detail="Admin access required")
        allowed = (sess or {}).get("user", {}).get("tenants") or []
        if tenant not in allowed:
            raise HTTPException(status_code=403,
                                detail="You may only manage your own tenant's onboarding PSKs")
        return sess

    @app.get("/tenant/{tenant}/onboarding-psk", operation_id="tenant_list_onboarding_psks")
    async def list_onboarding_psks(request: Request, tenant: str):
        _require_owns_tenant(request, tenant)
        return {"psks": await hub.simulations_store.get_psks(tenant)}

    @app.post("/tenant/{tenant}/onboarding-psk", operation_id="tenant_generate_onboarding_psk")
    async def generate_onboarding_psk(request: Request, tenant: str):
        """Mint a new onboarding PSK for ``tenant``. The caller pastes it (with
        the tenant id) into a new box's install command — see
        ``agent/install_agent.sh --onboarding-psk``/``--tenant-hint``."""
        _require_owns_tenant(request, tenant)
        psk = secrets.token_urlsafe(24)
        await hub.simulations_store.add_psk(tenant, psk)
        logger.info("onboarding-psk: generated for tenant %s", tenant)
        return {"psk": psk, "tenant_id": tenant}

    @app.delete("/tenant/{tenant}/onboarding-psk", operation_id="tenant_revoke_onboarding_psk")
    async def revoke_onboarding_psk(request: Request, tenant: str):
        _require_owns_tenant(request, tenant)
        body = await request.json()
        psk = body.get("psk") if isinstance(body, dict) else None
        removed = await hub.simulations_store.remove_psk(tenant, psk) if psk else False
        if removed:
            logger.info("onboarding-psk: revoked for tenant %s", tenant)
        return {"removed": removed}
