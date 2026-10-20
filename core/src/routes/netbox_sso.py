"""NetBox Entra SSO — reuse the LM hub's Entra connection for NetBox, turn-key.

NetBox logs in through the SAME Entra app registration as the hub, ported from
the hub's Azure SSO config: tenant + client_id, the hub's client certificate +
key (NetBox authenticates with a cert-signed client assertion via the agent's
``lm_sso_backend``, so no client secret is needed), the allowed group, and the
Permission Groups' Entra group → NetBox group map (Global Admin groups →
NetBox superuser). The only Azure-side step is registering NetBox's redirect URI
on that app. A client secret is still accepted as a fallback when the hub has
no certificate. Pushed to the netbox-server host's agent (NETBOX_APPLY_SSO —
an app-layer-encrypted frame), which also turns on the "Sign in with
Microsoft" button on NetBox's login page.

Targeting: the push carries the hub's Entra private key, so it goes ONLY to the
agent an admin explicitly picked (``target_agent``) — never to whatever agent
self-advertises a capability (the retired ``netbox_server`` auth flag was the
cross-tenant H2 finding). The UI offers connected, approved generic agents that
report a NetBox install (GET_DEPLOY_STATUS); the hub re-checks the picked agent
right before every push that carries the key.

Under ``/setup/`` so the access-control middleware admin-gates it.
"""
from __future__ import annotations

import asyncio

from api import HTTPException, Request, logger
from security.credential_store import resolve_private_key_material
from security.oidc import get_oidc_config


def register(app, hub, ctx):
    _FIELDS = ("enabled", "client_secret", "redirect_uri", "group_map", "allowed_group",
               "target_agent")

    def _cfg() -> dict:
        c = {"enabled": False, "client_secret": "", "redirect_uri": "",
             "group_map": {}, "allowed_group": "", "target_agent": ""}
        c.update((hub.state.system_state.get("global_config", {}) or {}).get("netbox_sso", {}) or {})
        if not isinstance(c.get("group_map"), dict):
            c["group_map"] = {}
        return c

    def _save(cfg: dict) -> None:
        gc = hub.state.system_state.setdefault("global_config", {})
        gc["netbox_sso"] = {k: cfg[k] for k in _FIELDS}
        hub.state._mark_dirty()

    def _suggested_group_map() -> dict:
        """{entra-group-obj-id: netbox-group-name} seeded from Permission Groups
        that carry an Entra Directory Group (ldap_group)."""
        out = {}
        for g in (hub.state.system_state.get("permission_groups", {}) or {}).values():
            dg = (g.get("ldap_group") or "").strip()
            if dg:
                out[dg] = g.get("name") or dg
        return out

    def _admin_entra_groups() -> list:
        """Entra group ids of Permission Groups granting Global Admin — their
        members become NetBox superusers."""
        out = []
        for g in (hub.state.system_state.get("permission_groups", {}) or {}).values():
            p = g.get("permissions") or {}
            dg = (g.get("ldap_group") or "").strip()
            if dg and (p.get("admin") or p.get("role") == "admin") and dg not in out:
                out.append(dg)
        return out

    def _hub_cert(oidc) -> tuple:
        """(cert_pem, key_pem) of the hub's Entra client cert, or ("", "")."""
        try:
            cert = resolve_private_key_material(oidc.cert_path) if oidc.cert_path else None
            key = resolve_private_key_material(oidc.key_path) if oidc.key_path else None
        except Exception as e:  # noqa: BLE001
            logger.warning("netbox-sso: could not read the hub Entra cert/key: %s", e)
            return "", ""
        if not (cert and key):
            return "", ""
        return cert.decode("utf-8", "replace"), key.decode("utf-8", "replace")

    def _effective(cfg: dict, oidc) -> dict:
        """NetBox-side values with the hub's Azure connection filled in."""
        return {
            "allowed_group": cfg["allowed_group"] or oidc.allowed_group,
            "group_map": cfg["group_map"] or _suggested_group_map(),
            "superuser_groups": _admin_entra_groups(),
        }

    def _approved_connected(sid: str) -> bool:
        if not sid or sid not in hub.active_connections:
            return False
        approved = getattr(hub, "approved_modules", None)
        return True if approved is None else bool(approved.get(sid))

    async def _reports_netbox(sid: str) -> bool:
        """Does ``sid`` (a connected generic agent) report a NetBox install?"""
        try:
            res = await hub.request_response(sid, "GET_DEPLOY_STATUS", {}, timeout=8.0)
            data = res.get("payload", {}).get("data", res) if isinstance(res, dict) else res
        except Exception:  # noqa: BLE001
            return False
        if not isinstance(data, dict):
            return False
        return bool(data.get("netbox_installed")
                    or "netbox-server" in (data.get("installed_deploy_roles") or []))

    async def _candidates() -> list:
        """Connected, approved generic agents that report a NetBox install."""
        sids = [sid for sid in (hub.get_all_spokes_by_type("agent") or [])
                if _approved_connected(sid)]
        oks = await asyncio.gather(*[_reports_netbox(sid) for sid in sids])
        return sorted(sid for sid, ok in zip(sids, oks) if ok)

    @app.get("/setup/netbox-sso")
    async def get_netbox_sso():
        cfg = _cfg()
        oidc = get_oidc_config(hub)
        cert_ok = all(_hub_cert(oidc))
        return {
            # Never echo the stored secret; report only whether one is set.
            "config": {"enabled": cfg["enabled"], "redirect_uri": cfg["redirect_uri"],
                       "target_agent": cfg["target_agent"],
                       "group_map": cfg["group_map"], "allowed_group": cfg["allowed_group"],
                       "secret_set": bool(cfg["client_secret"])},
            "oidc": {"tenant_id": oidc.tenant_id, "client_id": oidc.client_id,
                     "configured": bool(oidc.tenant_id and oidc.client_id),
                     "allowed_group": oidc.allowed_group,
                     "cert_available": cert_ok},
            "auth_mode": "certificate" if cert_ok else ("secret" if cfg["client_secret"] else "none"),
            "effective": _effective(cfg, oidc),
            "suggested_group_map": _suggested_group_map(),
            "netbox_server_agents": await _candidates(),
        }

    @app.post("/setup/netbox-sso")
    async def set_netbox_sso(request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        return await _apply((body or {}).get("config", body) or {})

    async def _apply(incoming: dict) -> dict:
        cur = _cfg()
        prev_target = cur["target_agent"]
        if "target_agent" in incoming:
            cur["target_agent"] = str(incoming.get("target_agent") or "").strip()
        cur["enabled"] = bool(incoming.get("enabled", cur["enabled"]))
        cur["redirect_uri"] = str(incoming.get("redirect_uri", cur["redirect_uri"]) or "").strip()
        cur["allowed_group"] = str(incoming.get("allowed_group", cur["allowed_group"]) or "").strip()
        if isinstance(incoming.get("group_map"), dict):
            cur["group_map"] = {str(k): str(v) for k, v in incoming["group_map"].items()}
        # A blank secret on save = keep the existing one (the GET never returns it).
        new_secret = incoming.get("client_secret")
        if new_secret:
            cur["client_secret"] = str(new_secret)

        oidc = get_oidc_config(hub)
        cert_pem, key_pem = _hub_cert(oidc) if cur["enabled"] else ("", "")
        if cur["enabled"]:
            if not (oidc.tenant_id and oidc.client_id):
                raise HTTPException(status_code=400,
                                    detail="configure Entra SSO on the hub first (Settings → Azure → SSO)")
            if not (cert_pem and key_pem) and not cur["client_secret"]:
                raise HTTPException(status_code=400,
                                    detail="the hub has no Entra client certificate to share — generate one "
                                           "in Settings → Azure → SSO, or paste a client secret")
            if not cur["target_agent"]:
                raise HTTPException(status_code=400,
                                    detail="pick the NetBox host (target agent) to configure")
            # The payload carries the Entra key: only to an approved agent that
            # actually runs NetBox, re-checked now rather than trusted from config.
            if not _approved_connected(cur["target_agent"]):
                raise HTTPException(status_code=409,
                                    detail=f"{cur['target_agent']} is not a connected, approved agent")
            if not await _reports_netbox(cur["target_agent"]):
                raise HTTPException(status_code=409,
                                    detail=f"{cur['target_agent']} does not report a NetBox install")
        _save(cur)

        eff = _effective(cur, oidc)
        payload = {
            "enabled": cur["enabled"],
            "tenant": oidc.tenant_id,
            "client_id": oidc.client_id,
            "client_secret": cur["client_secret"],
            "redirect_uri": cur["redirect_uri"],
            "group_map": eff["group_map"],
            "allowed_group": eff["allowed_group"],
            "superuser_groups": eff["superuser_groups"],
        }
        if cert_pem and key_pem:
            # Same app + cert the hub logs in with (frame is AEAD-encrypted).
            payload["client_cert_pem"] = cert_pem
            payload["client_key_pem"] = key_pem
        targets = [cur["target_agent"]] if cur["target_agent"] else []
        if prev_target and prev_target != cur["target_agent"]:
            # Moved hosts: strip SSO (and the key) from the old one.
            try:
                await hub.push_or_queue_to_spoke(prev_target, "NETBOX_APPLY_SSO", {"enabled": False})
            except Exception as e:  # noqa: BLE001
                logger.warning("netbox-sso: disable on previous host %s failed: %s", prev_target, e)
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
                "no_target": not targets,
                "auth_mode": "certificate" if payload.get("client_key_pem") else "secret"}

    @app.post("/setup/netbox-sso/test")
    async def test_netbox_sso(request: Request):
        """Ask the netbox-server agent to probe NetBox's OIDC begin URL and
        confirm it redirects to Entra with the expected tenant/client_id/redirect
        — a browserless 'test login'."""
        return await _test()

    async def _test() -> dict:
        cfg = _cfg()
        targets = [cfg["target_agent"]] if _approved_connected(cfg["target_agent"]) else []
        if not targets:
            raise HTTPException(status_code=503, detail="the selected NetBox host is not connected")
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

    # Shared with the loopback /admin/ops/netbox-sso routes (admin_ops.py).
    hub.netbox_sso_apply = _apply
    hub.netbox_sso_test = _test
    hub.netbox_sso_status = get_netbox_sso
