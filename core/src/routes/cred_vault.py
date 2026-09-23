"""Credential Vault routes (``/tenant/cred-vault/*``).

The hub-side secret locker (see :mod:`cred_vault`). Lives under ``/tenant/`` so
the access-control middleware restricts the whole surface to **tenant-admins**
(and Global Admins); this module then enforces per-bucket reach on top of that:

* a **tenant-admin** may only touch buckets that are one of their own tenants;
* a **Global Admin** may touch ANY tenant bucket plus the non-tenant
  ``__admin__`` slot (infrastructure credentials).

Every secret read/write additionally requires the caller to supply the bucket
**pass-phrase (PSK)** — role decides *reach*, the PSK decides *decrypt*.

The reveal endpoint is a POST (PSK travels in the TLS-encrypted body, never a
URL/query) and is served with ``Cache-Control: no-store`` + friends so the
plaintext never lands in any browser/proxy cache, history, or bfcache — the
front-end purges it from memory immediately after showing it once.
"""
from __future__ import annotations

import functools

from fastapi.responses import JSONResponse

from api import HTTPException, Request, access, logger
import cred_vault as _cv

_NO_STORE = {
    "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
    "Pragma": "no-cache",
    "Expires": "0",
}


def register(app, hub, ctx):
    _session_user = ctx._session_user

    def _sess(request: Request):
        return _session_user(request) or {}

    def _actor(sess) -> str:
        # Sessions carry the login id as ``user_id`` (routes/auth.py); reading
        # only ``username``/``id`` logged every vault audit line as "?".
        sess = sess or {}
        u = sess.get("user", {}) or {}
        return (u.get("user_id") or sess.get("user_id")
                or u.get("username") or u.get("id") or "?")

    def _acting_tenants(sess):
        return (sess or {}).get("user", {}).get("tenants") or []

    def _all_tenants(hub):
        """Every known tenant → {tenant_id: label}. Global-Admin-only helper so
        the vault can list a bucket per tenant (even ones with no secrets yet),
        letting a Global Admin add credentials for any tenant.

        ``default`` is INCLUDED. It used to be excluded as "the unassigned/system
        bucket, not a real tenant", but ``default`` is a real tenant that owns
        real spokes (e.g. an nw agent bound to ``default``). Hiding it meant a
        Global Admin could not create a vault entry for that tenant, so they
        could not build a scan-credential set for it either, and the Scan tab
        correctly-but-uselessly reported "no scan credential sets belong to this
        tenant" with no way to fix it. The non-tenant Global Admin slot is
        ``__admin__`` and is listed separately."""
        try:
            tenants = (hub.state.tenant_state or {}).get("tenants", {}) or {}
        except Exception:  # noqa: BLE001
            return {}
        out = {}
        for tid, meta in tenants.items():
            if not tid:
                continue
            meta = meta or {}
            out[tid] = meta.get("display_name") or meta.get("name") or tid
        return out

    def _is_global_admin(sess) -> bool:
        return access.is_admin(sess)

    def _reachable(sess, bucket: str) -> bool:
        """Can this session reach ``bucket``? Global Admin → any bucket + the
        admin slot; tenant-admin → only their own tenant buckets."""
        if not bucket:
            return False
        if _is_global_admin(sess):
            return True
        if bucket == _cv.ADMIN_BUCKET:
            return False
        return bucket in _acting_tenants(sess)

    def _require_reach(sess, bucket: str):
        # A record in an unreachable bucket is indistinguishable from missing
        # (404) so bucket existence never leaks across tenants.
        if not _reachable(sess, bucket):
            raise HTTPException(status_code=404, detail="bucket not found")

    async def _body(request: Request) -> dict:
        try:
            return await request.json() or {}
        except Exception:
            return {}

    def _guard(fn):
        """Map domain/vault errors to clean HTTP codes."""
        @functools.wraps(fn)
        async def _wrapped(*a, **k):
            try:
                return await fn(*a, **k)
            except HTTPException:
                raise
            except _cv.CredVaultEngineError as e:
                # Crypto-engine / resource failure — not a client mistake. Surface
                # a meaningful 503 (with the safe message) instead of a 400 that
                # would read as "incorrect pass-phrase".
                logger.error("cred-vault: PSK engine failure: %s", e)
                raise HTTPException(status_code=503, detail=str(e))
            except _cv.CredVaultError as e:
                raise HTTPException(status_code=400, detail=str(e))
            except Exception as e:  # noqa: BLE001 — Key Vault / network
                logger.warning("cred-vault: %s", e)
                raise HTTPException(status_code=502, detail=f"credential vault error: {e}")
        return _wrapped

    # ── discovery ───────────────────────────────────────────────────────────
    @app.get("/tenant/cred-vault/buckets")
    async def cv_buckets(request: Request):
        """Buckets the caller may reach, with pass-phrase + count status. A
        Global Admin sees EVERY tenant bucket (even empty ones with no secrets
        yet) plus the ``__admin__`` slot, so they can add/remove credentials for
        any tenant when they hold that tenant's pass-phrase."""
        sess = _sess(request)
        existing = {b["bucket"]: b for b in _cv.list_buckets(hub)}
        labels = {}
        if _is_global_admin(sess):
            labels = _all_tenants(hub)
            reach = set(existing) | set(labels) | {_cv.ADMIN_BUCKET}
        else:
            reach = set(_acting_tenants(sess))
        out = []
        for b in sorted(reach):
            rec = existing.get(b, {"bucket": b, "has_psk": False, "secret_count": 0})
            is_admin_slot = b == _cv.ADMIN_BUCKET
            # A bucket that is neither the Global Admin slot nor a known tenant
            # is ORPHANED: it only shows up because it holds secrets. Nothing
            # tenant-scoped can ever reference it (credential sets are matched by
            # tenant_id), and a tenant-admin can never reach it. Flag it so the
            # UI can say so instead of rendering a bare id like "admin" right
            # next to "Global Admin slot" — which reads like two admin scopes.
            is_orphan = not is_admin_slot and b not in labels
            name = ("Global Admin slot" if is_admin_slot else labels.get(b, b))
            out.append({**rec, "name": name, "is_admin_slot": is_admin_slot,
                        "is_orphan": is_orphan,
                        # Secrets encrypted under the bucket pass-phrase — these
                        # are what a pass-phrase reset would have to discard.
                        "psk_secret_count": _cv.count_psk_secrets(hub, b)})
        return {"buckets": out, "is_global_admin": _is_global_admin(sess),
                "admin_slot": _cv.ADMIN_BUCKET, "vault_available": _cv._vault_available(hub)}

    @app.post("/tenant/cred-vault/reset-psk")
    @_guard
    async def cv_reset_psk(request: Request):
        """Recover a bucket whose pass-phrase was lost (Global Admin only).

        ``/psk`` can only ROTATE — it verifies the old pass-phrase first — so a
        forgotten pass-phrase previously bricked the bucket permanently through
        the UI. This resets the verifier without the old pass-phrase.

        ``hub``-mode secrets are keyed on the hub Fernet key, NOT the
        pass-phrase, so they survive untouched (and keep serving automation). A
        bucket holding only ``hub``-mode secrets therefore resets with zero data
        loss. Any ``psk``-mode secret is already undecryptable and can only be
        discarded, which is refused unless ``confirm_destroy`` is sent."""
        sess = _sess(request)
        if not _is_global_admin(sess):
            # Not 403: a tenant-admin must not learn that this door exists.
            raise HTTPException(status_code=404, detail="bucket not found")
        body = await _body(request)
        bucket = (body.get("bucket") or "").strip()
        _require_reach(sess, bucket)
        res = await _cv.reset_bucket_psk(
            hub, bucket, body.get("new_psk") or "",
            destroy_psk_secrets=bool(body.get("confirm_destroy")),
            actor=_actor(sess))
        return {"status": "ok", **res}

    @app.post("/tenant/cred-vault/move-secret")
    @_guard
    async def cv_move_secret(request: Request):
        """Move a secret to another bucket (Global Admin only).

        The rescue path for a credential stranded in an orphaned bucket: move it
        somewhere tenant-scoped code can actually reference, then delete the
        orphan. ``hub``-mode secrets need no pass-phrase (they are keyed on the
        hub Fernet key, not the bucket); ``psk``-mode secrets need both the
        source ``psk`` and the destination ``to_psk``."""
        sess = _sess(request)
        if not _is_global_admin(sess):
            raise HTTPException(status_code=404, detail="bucket not found")
        body = await _body(request)
        bucket = (body.get("bucket") or "").strip()
        to_bucket = (body.get("to_bucket") or "").strip()
        _require_reach(sess, bucket)
        _require_reach(sess, to_bucket)
        res = await _cv.move_secret(
            hub, bucket, (body.get("name") or "").strip(), to_bucket,
            psk=body.get("psk") or "", to_psk=body.get("to_psk") or "",
            actor=_actor(sess))
        return {"status": "ok", **res}

    @app.post("/tenant/cred-vault/delete-bucket")
    @_guard
    async def cv_delete_bucket(request: Request):
        """Delete a bucket outright (Global Admin only).

        Buckets could be created by typing a free-text name but never removed —
        ``list_buckets`` derives from the pass-phrase records UNION the secret
        records — so a mistyped bucket lingered in every Global Admin's picker
        forever, inviting credentials to be stored somewhere no tenant-scoped
        code can reference and no tenant-admin can reach.

        Refused for the ``__admin__`` slot (infrastructure) and for any bucket
        that belongs to a LIVE tenant — those follow the tenant lifecycle, and
        this endpoint exists to clear up orphans. Destroying leftover secrets
        requires ``confirm_destroy``."""
        sess = _sess(request)
        if not _is_global_admin(sess):
            raise HTTPException(status_code=404, detail="bucket not found")
        body = await _body(request)
        bucket = (body.get("bucket") or "").strip()
        _require_reach(sess, bucket)
        if bucket in _all_tenants(hub):
            raise HTTPException(
                status_code=400,
                detail=f"'{bucket}' is a live tenant's bucket — delete the tenant "
                       "instead. This action is for buckets that match no tenant.")
        res = await _cv.delete_bucket(hub, bucket,
                                      confirm_destroy=bool(body.get("confirm_destroy")),
                                      actor=_actor(sess))
        return {"status": "ok", **res}

    @app.get("/tenant/cred-vault/secrets")
    async def cv_secrets(request: Request):
        sess = _sess(request)
        bucket = (request.query_params.get("bucket") or "").strip()
        _require_reach(sess, bucket)
        return {"bucket": bucket, "has_psk": _cv.bucket_has_psk(hub, bucket),
                "secrets": _cv.list_secrets(hub, bucket)}

    @app.get("/tenant/cred-vault/automation-secrets")
    async def cv_automation_secrets(request: Request):
        """Picker source for module credential references (LE, Console): every
        AUTOMATION-READABLE (``hub``-mode) secret in the buckets the caller can
        reach — names + non-secret metadata ONLY, never a value. A module stores
        just the ``{bucket, name}`` reference and resolves the value unattended
        via :func:`cred_vault.automation_get` at use-time, so the plaintext is
        never exposed to the browser. Optional ``?type=`` filters by secret type
        (e.g. ``console`` / ``dns`` / ``henet``)."""
        sess = _sess(request)
        want_type = (request.query_params.get("type") or "").strip()
        if _is_global_admin(sess):
            reach = set(b["bucket"] for b in _cv.list_buckets(hub)) | {_cv.ADMIN_BUCKET}
        else:
            reach = set(_acting_tenants(sess))
        out = []
        for b in sorted(reach):
            for s in _cv.list_secrets(hub, b):
                if not s.get("automation"):
                    continue  # psk-only secrets can't be read unattended
                if want_type and s.get("type") != want_type:
                    continue
                out.append({"bucket": b, "name": s["name"], "type": s.get("type", "generic"),
                            "fields": s.get("fields", []), "description": s.get("description", ""),
                            "is_admin_slot": b == _cv.ADMIN_BUCKET})
        return {"secrets": out, "is_global_admin": _is_global_admin(sess)}

    # ── pass-phrase ─────────────────────────────────────────────────────────
    @app.post("/tenant/cred-vault/psk")
    @_guard
    async def cv_set_psk(request: Request):
        sess = _sess(request)
        body = await _body(request)
        bucket = (body.get("bucket") or "").strip()
        _require_reach(sess, bucket)
        await _cv.set_bucket_psk(hub, bucket, body.get("new_psk") or "",
                                 old_psk=body.get("old_psk"))
        logger.info("cred-vault: pass-phrase set for bucket %s by %s", bucket, _actor(sess))
        return {"status": "ok", "bucket": bucket}

    # ── secret CRUD ─────────────────────────────────────────────────────────
    @app.post("/tenant/cred-vault/secret")
    @_guard
    async def cv_put_secret(request: Request):
        sess = _sess(request)
        body = await _body(request)
        bucket = (body.get("bucket") or "").strip()
        _require_reach(sess, bucket)
        value = body.get("value")
        if not isinstance(value, dict):
            raise HTTPException(status_code=400, detail="value must be an object")
        # Guard against a blank re-save silently STRIPPING a provider credential:
        # a DNS secret always carries a non-secret ``provider`` marker, so a form
        # that skips the (never-prefilled) password would otherwise overwrite the
        # stored secret with empty fields. Reject when every non-marker field is
        # blank — the caller must re-enter the secret rather than erase it.
        if value.get("provider"):
            cred_keys = [k for k in value if k not in ("provider",)]
            if not cred_keys or all(not str(value[k]).strip() for k in cred_keys):
                raise HTTPException(
                    status_code=400,
                    detail="credential fields are empty — re-enter the secret "
                           "(a blank save would erase the stored credential)")
        res = await _cv.put_secret(
            hub, bucket, body.get("name") or "", value,
            mode=(body.get("mode") or "psk"), sec_type=(body.get("type") or "generic"),
            description=(body.get("description") or ""), psk=body.get("psk") or "",
            actor=_actor(sess))
        logger.info("cred-vault: secret %r stored in %s (mode=%s) by %s",
                    res["name"], bucket, res["mode"], _actor(sess))
        return {"status": "ok", **res}

    @app.post("/tenant/cred-vault/reveal")
    @_guard
    async def cv_reveal(request: Request):
        """Reveal ONE secret's plaintext. PSK required; response is no-store so
        the value is never cached — the UI shows it once then purges it."""
        sess = _sess(request)
        body = await _body(request)
        bucket = (body.get("bucket") or "").strip()
        _require_reach(sess, bucket)
        value = await _cv.reveal_secret(hub, bucket, body.get("name") or "",
                                        psk=body.get("psk") or "", actor=_actor(sess))
        logger.info("cred-vault: secret %r REVEALED from %s by %s",
                    body.get("name"), bucket, _actor(sess))
        return JSONResponse(content={"status": "ok", "value": value}, headers=_NO_STORE)

    @app.post("/tenant/cred-vault/delete")
    @_guard
    async def cv_delete(request: Request):
        sess = _sess(request)
        body = await _body(request)
        bucket = (body.get("bucket") or "").strip()
        _require_reach(sess, bucket)
        await _cv.delete_secret(hub, bucket, body.get("name") or "",
                                psk=body.get("psk") or "", actor=_actor(sess))
        logger.info("cred-vault: secret %r DELETED from %s by %s",
                    body.get("name"), bucket, _actor(sess))
        return {"status": "ok"}
