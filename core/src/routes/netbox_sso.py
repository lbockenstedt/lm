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
# Postponed evaluation of annotations so type hints stay plain strings at runtime.
from __future__ import annotations

# asyncio is used to probe several candidate agents in parallel.
import asyncio

# Request/exception types and the shared logger from the main API module.
from api import HTTPException, Request, logger
# Loads a PEM (cert or key) from a file path or a credential-store reference.
from security.credential_store import resolve_private_key_material
# Reads the hub's own Entra SSO (OIDC) settings: tenant, client id, cert paths, allowed group.
from security.oidc import get_oidc_config


def register(app, hub, ctx):
    """Attach the NetBox SSO setup routes to the web app and expose them to admin_ops via the hub.

    Args: app is the web application, hub is the running LM hub, ctx carries shared route helpers
    (unused here).
    """
    # The only config keys persisted for NetBox SSO; anything else posted is ignored.
    _FIELDS = ("enabled", "client_secret", "redirect_uri", "group_map", "allowed_group",
               "target_agent")

    def _cfg() -> dict:
        """Return the stored NetBox SSO config with defaults filled in for any missing keys."""
        # Start from safe defaults (disabled, nothing set) and overlay the saved values.
        c = {"enabled": False, "client_secret": "", "redirect_uri": "",
             "group_map": {}, "allowed_group": "", "target_agent": ""}
        c.update((hub.state.system_state.get("global_config", {}) or {}).get("netbox_sso", {}) or {})
        # A corrupt group_map (not a dict) is reset to empty so callers can always iterate it.
        if not isinstance(c.get("group_map"), dict):
            c["group_map"] = {}
        return c

    def _save(cfg: dict) -> None:
        """Persist the NetBox SSO config (only the whitelisted fields) and flag the state for
        saving.
        """
        gc = hub.state.system_state.setdefault("global_config", {})
        gc["netbox_sso"] = {k: cfg[k] for k in _FIELDS}
        hub.state._mark_dirty()

    def _suggested_group_map() -> dict:
        """{entra-group-obj-id: netbox-group-name} seeded from Permission Groups
        that carry an Entra Directory Group (ldap_group)."""
        # Walk every Permission Group and map its Entra group id to the group's name.
        out = {}
        for g in (hub.state.system_state.get("permission_groups", {}) or {}).values():
            dg = (g.get("ldap_group") or "").strip()
            if dg:
                out[dg] = g.get("name") or dg
        return out

    def _admin_entra_groups() -> list:
        """Entra group ids of Permission Groups granting Global Admin — their
        members become NetBox superusers."""
        # Collect, without duplicates, the Entra groups of Permission Groups that grant admin.
        out = []
        for g in (hub.state.system_state.get("permission_groups", {}) or {}).values():
            p = g.get("permissions") or {}
            dg = (g.get("ldap_group") or "").strip()
            if dg and (p.get("admin") or p.get("role") == "admin") and dg not in out:
                out.append(dg)
        return out

    def _hub_cert(oidc) -> tuple:
        """(cert_pem, key_pem) of the hub's Entra client cert, or ("", "")."""
        # Load the hub's cert and key; an unreadable file is logged and treated as "no certificate".
        try:
            cert = resolve_private_key_material(oidc.cert_path) if oidc.cert_path else None
            key = resolve_private_key_material(oidc.key_path) if oidc.key_path else None
        except Exception as e:  # noqa: BLE001
            logger.warning("netbox-sso: could not read the hub Entra cert/key: %s", e)
            return "", ""
        # Both halves are needed for certificate auth; one without the other is useless.
        if not (cert and key):
            return "", ""
        # Return both as text for the JSON payload.
        return cert.decode("utf-8", "replace"), key.decode("utf-8", "replace")

    def _effective(cfg: dict, oidc) -> dict:
        """NetBox-side values with the hub's Azure connection filled in."""
        # Values set on the NetBox page win; otherwise fall back to the hub's group settings.
        return {
            "allowed_group": cfg["allowed_group"] or oidc.allowed_group,
            "group_map": cfg["group_map"] or _suggested_group_map(),
            "superuser_groups": _admin_entra_groups(),
        }

    def _approved_connected(sid: str) -> bool:
        """True when the spoke is connected right now and (if approvals are enforced) approved."""
        # Not connected (or no id) means it cannot receive anything.
        if not sid or sid not in hub.active_connections:
            return False
        # When the hub has no approval list at all, every connected spoke counts as approved.
        approved = getattr(hub, "approved_modules", None)
        return True if approved is None else bool(approved.get(sid))

    async def _reports_netbox(sid: str) -> bool:
        """Does ``sid`` (a connected generic agent) report a NetBox install?"""
        # Ask the agent for its deploy status; no answer or an error means "no NetBox".
        try:
            res = await hub.request_response(sid, "GET_DEPLOY_STATUS", {}, timeout=8.0)
            data = res.get("payload", {}).get("data", res) if isinstance(res, dict) else res
        except Exception:  # noqa: BLE001
            return False
        # Anything other than a dict is not a usable status report.
        if not isinstance(data, dict):
            return False
        # The agent reports NetBox either via an explicit flag or via its installed deploy roles.
        return bool(data.get("netbox_installed")
                    or "netbox-server" in (data.get("installed_deploy_roles") or []))

    async def _candidates() -> list:
        """Connected, approved generic agents that report a NetBox install."""
        # Start from every connected, approved generic agent.
        sids = [sid for sid in (hub.get_all_spokes_by_type("agent") or [])
                if _approved_connected(sid)]
        # Ask them all in parallel whether NetBox is installed, and keep (sorted) the ones that say
        # yes.
        oks = await asyncio.gather(*[_reports_netbox(sid) for sid in sids])
        return sorted(sid for sid, ok in zip(sids, oks) if ok)

    @app.get("/setup/netbox-sso")
    async def get_netbox_sso():
        """Return the NetBox SSO page state: saved config (no secret), the hub's Entra details, the
        effective values and the candidate NetBox hosts.
        """
        # Load the saved config and the hub's Entra settings, and check whether a usable cert/key
        # exists.
        cfg = _cfg()
        oidc = get_oidc_config(hub)
        cert_ok = all(_hub_cert(oidc))
        # Build the page payload; auth_mode tells the UI whether NetBox will use the cert, a secret
        # or nothing.
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
        """Save the NetBox SSO config posted from the Setup page and push it to the NetBox host."""
        # Read the JSON body; a missing or broken body is treated as empty.
        try:
            body = await request.json()
        except Exception:
            body = {}
        # Accept either {"config": {...}} or the bare config object, and apply it.
        return await _apply((body or {}).get("config", body) or {})

    async def _apply(incoming: dict) -> dict:
        """Validate, save and push a NetBox SSO config to the chosen NetBox agent.

        Also used by the loopback admin_ops routes. Returns which agents got the config pushed,
        queued or failed.
        """
        # Start from the saved config and remember the previous target so it can be cleaned up if it
        # changes.
        cur = _cfg()
        prev_target = cur["target_agent"]
        if "target_agent" in incoming:
            cur["target_agent"] = str(incoming.get("target_agent") or "").strip()
        # Overlay the posted values, trimming whitespace and keeping current values for anything not
        # posted.
        cur["enabled"] = bool(incoming.get("enabled", cur["enabled"]))
        cur["redirect_uri"] = str(incoming.get("redirect_uri", cur["redirect_uri"]) or "").strip()
        cur["allowed_group"] = str(incoming.get("allowed_group", cur["allowed_group"]) or "").strip()
        # Replace the group map only when a proper dict was posted (keys and values forced to
        # strings).
        if isinstance(incoming.get("group_map"), dict):
            cur["group_map"] = {str(k): str(v) for k, v in incoming["group_map"].items()}
        # A blank secret on save = keep the existing one (the GET never returns it).
        new_secret = incoming.get("client_secret")
        if new_secret:
            cur["client_secret"] = str(new_secret)

        # Look up the hub's Entra settings and, only when enabling, load its cert/key to share.
        oidc = get_oidc_config(hub)
        cert_pem, key_pem = _hub_cert(oidc) if cur["enabled"] else ("", "")
        # Enabling needs: hub Entra SSO configured, a cert or a client secret, and a picked NetBox
        # host.
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
        # Everything checks out (or SSO is being disabled): save the config.
        _save(cur)

        # Build the NETBOX_APPLY_SSO payload with the hub's tenant/client id and the effective group
        # settings.
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
        # Only the explicitly picked agent receives the config.
        targets = [cur["target_agent"]] if cur["target_agent"] else []
        if prev_target and prev_target != cur["target_agent"]:
            # Moved hosts: strip SSO (and the key) from the old one.
            try:
                await hub.push_or_queue_to_spoke(prev_target, "NETBOX_APPLY_SSO", {"enabled": False})
            except Exception as e:  # noqa: BLE001
                logger.warning("netbox-sso: disable on previous host %s failed: %s", prev_target, e)
        # Push to the target (or queue it if offline) and sort the result into pushed/queued/failed.
        pushed, queued, failed = [], [], []
        for sid in targets:
            try:
                r = await hub.push_or_queue_to_spoke(sid, "NETBOX_APPLY_SSO", payload)
                (queued if r.get("queued") else pushed).append(sid)
            except Exception as e:  # noqa: BLE001
                logger.warning("netbox-sso: push to %s failed: %s", sid, e)
                failed.append(sid)
        # Log a one-line summary of the push.
        logger.info("netbox-sso: %s → %d pushed, %d queued, %d failed",
                    "enabled" if cur["enabled"] else "disabled", len(pushed), len(queued), len(failed))
        # Report the outcome; no_target warns the UI that nothing was configured.
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
        """Run the browserless SSO login test on the selected NetBox host and return its findings.
        """
        # Only test against the saved target when it is connected and approved.
        cfg = _cfg()
        targets = [cfg["target_agent"]] if _approved_connected(cfg["target_agent"]) else []
        if not targets:
            raise HTTPException(status_code=503, detail="the selected NetBox host is not connected")
        # Tell the agent which tenant, client id and redirect URI it should see in Entra's redirect.
        oidc = get_oidc_config(hub)
        payload = {"tenant": oidc.tenant_id, "client_id": oidc.client_id,
                   "redirect_uri": cfg["redirect_uri"]}
        # Ask the agent to run the probe; a transport failure becomes a 502.
        try:
            res = await hub.request_response(targets[0], "NETBOX_TEST_SSO", payload, timeout=15.0)
            data = res.get("payload", {}).get("data", res) if isinstance(res, dict) else res
        except Exception as e:  # noqa: BLE001
            raise HTTPException(status_code=502, detail=f"test failed: {e}")
        # Anything but a SUCCESS status from the agent is reported as a failed test.
        if not isinstance(data, dict) or data.get("status") != "SUCCESS":
            raise HTTPException(status_code=502,
                                detail=(data or {}).get("message", "test failed") if isinstance(data, dict) else "test failed")
        # Return the target host plus the probe details the agent reported.
        return {"status": "ok", "host": targets[0], **{k: data[k] for k in
                ("ok", "redirects_to_entra", "http_code", "found", "matches", "message") if k in data}}

    # Shared with the loopback /admin/ops/netbox-sso routes (admin_ops.py).
    hub.netbox_sso_apply = _apply
    hub.netbox_sso_test = _test
    hub.netbox_sso_status = get_netbox_sso
