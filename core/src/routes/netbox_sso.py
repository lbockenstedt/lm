"""NetBox Entra SSO — reuse the LM hub's Entra app for NetBox, pushed turn-key.

The LM hub already holds the Entra tenant_id + client_id (cert-authenticated). NetBox
can't use that cert (its OIDC backend needs a client secret), but it CAN reuse the
SAME app registration: add NetBox's redirect URI + one client secret to that app in
Azure. This route stores the NetBox-side extras (secret, redirect, group map,
allowed group) and pushes tenant+client_id (from the hub OIDC config) + those to the
netbox-server host's agent, which applies the SSO block live (NETBOX_APPLY_SSO).

Under ``/setup/`` so the access-control middleware admin-gates it.
"""
from __future__ import annotations

from api import HTTPException, Request, logger
from security.oidc import get_oidc_config


def register(app, hub, ctx):
    _FIELDS = ("enabled", "client_secret", "redirect_uri", "group_map", "allowed_group")

    def _cfg() -> dict:
        c = {"enabled": False, "client_secret": "", "redirect_uri": "",
             "group_map": {}, "allowed_group": ""}
        c.update((hub.state.system_state.get("global_config", {}) or {}).get("netbox_sso", {}) or {})
        if not isinstance(c.get("group_map"), dict):
            c["group_map"] = {}
        return c

    def _save(cfg: dict) -> None:
        gc = hub.state.system_state.setdefault("global_config", {})
        gc["netbox_sso"] = {k: cfg[k] for k in _FIELDS}
        hub.state.save_state()

    def _suggested_group_map() -> dict:
        """{entra-group-obj-id: netbox-group-name} seeded from Permission Groups
        that carry an Entra Directory Group (ldap_group)."""
        out = {}
        for g in (hub.state.system_state.get("permission_groups", {}) or {}).values():
            dg = (g.get("ldap_group") or "").strip()
            if dg:
                out[dg] = g.get("name") or dg
        return out

    def _netbox_server_agents() -> list:
        return [sid for sid in getattr(hub, "netbox_server_agents", set())
                if sid in hub.active_connections]

    @app.get("/setup/netbox-sso")
    async def get_netbox_sso():
        cfg = _cfg()
        oidc = get_oidc_config(hub)
        return {
            # Never echo the stored secret; report only whether one is set.
            "config": {"enabled": cfg["enabled"], "redirect_uri": cfg["redirect_uri"],
                       "group_map": cfg["group_map"], "allowed_group": cfg["allowed_group"],
                       "secret_set": bool(cfg["client_secret"])},
            "oidc": {"tenant_id": oidc.tenant_id, "client_id": oidc.client_id,
                     "configured": bool(oidc.tenant_id and oidc.client_id)},
            "suggested_group_map": _suggested_group_map(),
            "netbox_server_agents": _netbox_server_agents(),
        }

    @app.post("/setup/netbox-sso")
    async def set_netbox_sso(request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        incoming = (body or {}).get("config", body) or {}
        cur = _cfg()
        cur["enabled"] = bool(incoming.get("enabled", cur["enabled"]))
        cur["redirect_uri"] = str(incoming.get("redirect_uri", cur["redirect_uri"]) or "").strip()
        cur["allowed_group"] = str(incoming.get("allowed_group", cur["allowed_group"]) or "").strip()
        if isinstance(incoming.get("group_map"), dict):
            cur["group_map"] = {str(k): str(v) for k, v in incoming["group_map"].items()}
        # A blank secret on save = keep the existing one (the GET never returns it).
        new_secret = incoming.get("client_secret")
        if new_secret:
            cur["client_secret"] = str(new_secret)
        _save(cur)

        oidc = get_oidc_config(hub)
        if cur["enabled"]:
            if not (oidc.tenant_id and oidc.client_id):
                raise HTTPException(status_code=400,
                                    detail="configure Entra SSO on the hub first (Settings → Azure → SSO)")
            if not cur["client_secret"]:
                raise HTTPException(status_code=400, detail="a client secret is required to enable NetBox SSO")

        payload = {
            "enabled": cur["enabled"],
            "tenant": oidc.tenant_id,
            "client_id": oidc.client_id,
            "client_secret": cur["client_secret"],
            "redirect_uri": cur["redirect_uri"],
            "group_map": cur["group_map"],
            "allowed_group": cur["allowed_group"],
        }
        targets = _netbox_server_agents()
        pushed, queued, failed = [], [], []
        for sid in targets:
            try:
                r = await hub.push_or_queue_to_spoke(sid, "NETBOX_APPLY_SSO", payload)
                (queued if r.get("queued") else pushed).append(sid)
            except Exception as e:  # noqa: BLE001
                logger.warning("netbox-sso: push to %s failed: %s", sid, e)
                failed.append(sid)
        logger.info("netbox-sso: %s → %d pushed, %d queued, %d failed",
                    "enabled" if cur["enabled"] else "disabled", len(pushed), len(queued), len(failed))
        return {"status": "ok", "pushed": pushed, "queued": queued, "failed": failed,
                "no_target": not targets}

    @app.post("/setup/netbox-sso/test")
    async def test_netbox_sso(request: Request):
        """Ask the netbox-server agent to probe NetBox's OIDC begin URL and
        confirm it redirects to Entra with the expected tenant/client_id/redirect
        — a browserless 'test login'."""
        targets = _netbox_server_agents()
        if not targets:
            raise HTTPException(status_code=503, detail="no connected netbox-server host to test against")
        cfg = _cfg()
        oidc = get_oidc_config(hub)
        payload = {"tenant": oidc.tenant_id, "client_id": oidc.client_id,
                   "redirect_uri": cfg["redirect_uri"]}
        try:
            res = await hub.request_response(targets[0], "NETBOX_TEST_SSO", payload, timeout=15.0)
            data = res.get("payload", {}).get("data", res) if isinstance(res, dict) else res
        except Exception as e:  # noqa: BLE001
            raise HTTPException(status_code=502, detail=f"test failed: {e}")
        if not isinstance(data, dict) or data.get("status") != "SUCCESS":
            raise HTTPException(status_code=502,
                                detail=(data or {}).get("message", "test failed") if isinstance(data, dict) else "test failed")
        return {"status": "ok", "host": targets[0], **{k: data[k] for k in
                ("ok", "redirects_to_entra", "http_code", "found", "matches", "message") if k in data}}
