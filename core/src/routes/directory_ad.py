"""Directory → Active Directory routes: a tenant's AD accounts (read-only).

An AD connection belongs to one tenant. The Global Admin stores it under
Setup (``global_config.ad_connections``, the admin-only ``/setup/ad-connections``
CRUD in ``routes/nw.py``), with the bind password as a Credential Vault
reference. Nothing is pushed to a spoke: every AD_* command carries the
connection as its ``ad`` field, with the password filled from the vault at
send time, and goes to the tenant's directory spoke
(``hub.get_directory_spoke_for_tenant``), which must be able to reach the
tenant's DNS and domain controllers.

* ``GET /api/ldap/ad`` — the tenant's AD accounts, one block per connection,
  served from the hub cache (Directory middleware: reads need the ``ldap``
  right or admin; the tenant comes from :func:`routes.ldap.directory_resolve`).
* ``POST /setup/ad-connections/{id}/test`` and ``.../discover`` — admin checks
  of one connection (bind test; which DCs/global catalogs DNS finds).

A connection matches a tenant only by its own ``tenant_id`` (never "shared"):
one tenant's AD users are never shown to another.
"""
# Postpone evaluation of type hints.
from __future__ import annotations

# Read the tenant's connections side by side.
import asyncio

# Shared Hub helpers: HTTP error type, request object, logger.
from api import HTTPException, Request, logger
# Spoke reply unwrapping and exact tenant matching.
import access
# The Global Admin vault slot, which is never a connection's tenant.
import cred_vault
# Credential Vault overlay for the bind password.
import instance_vault
# Hub data-cache job description.
from warm_cache import CacheJob
# The shared Directory tenant resolver (tenant guard + read/write scope).
from routes.ldap import directory_resolve

# Where the connections are stored (also the instance_vault product key).
STORAGE_KEY = "ad_connections"
# Cache namespace for one connection's account list (key = "<tenant>|<id>").
CACHE_NS = "ldap_ad"
# Background refresh floor for that list (fleet rule 4.8: minutes, not per view).
REFRESH_S = 300
# Accounts listed per connection (the spoke caps a search at 1000).
LIST_LIMIT = 1000
# DNS discovery plus a bind attempt per server can take a while.
AD_TIMEOUT_S = 45.0
# At most this many connections are read at once.
READ_CONCURRENCY = 4
# Shown when the directory spoke predates the AD commands.
_OLD_SPOKE_DETAIL = ("The directory spoke does not support Active Directory yet; "
                     "update the directory spoke and try again.")


def connections_for(hub, tid: str) -> list:
    """The AD connections that belong to tenant ``tid`` (exact match only)."""
    conns = hub.state.system_state.get("global_config", {}).get(STORAGE_KEY) or []
    return [c for c in conns if isinstance(c, dict) and c.get("tenant_id")
            and access.same_tenant(c["tenant_id"], tid)]


def check_connection(conn: dict) -> None:
    """Refuse an AD connection that could cross tenants (400). It must name
    its tenant, and its vault credential must sit in that tenant's own
    bucket: never another tenant's and never the Global Admin slot, so a
    tenant's directory spoke only ever receives that tenant's password."""
    tid = conn.get("tenant_id")
    if not tid:
        raise HTTPException(status_code=400, detail="Pick the tenant this AD connection "
                            "belongs to first")
    # The Global Admin slot is not a tenant: a connection "owned" by it would
    # pass the same-bucket check below with the admin's own credential.
    if access.same_tenant(tid, cred_vault.ADMIN_BUCKET):
        raise HTTPException(status_code=400, detail="An AD connection must belong to "
                            "a tenant, not the Global Admin slot")
    ref = conn.get("vault_credential")
    bucket = ref.get("bucket") if isinstance(ref, dict) else ""
    if bucket and not access.same_tenant(bucket, tid):
        raise HTTPException(status_code=400, detail="The AD connection's vault credential "
                            "must be stored in the same tenant as the connection")


def server_label(server) -> str:
    """The spoke reports the server it used as ``{host, port, ssl, source}``;
    the UI shows it as ``host:port``. A bare string (older reply) passes
    through, and nothing is ``""``."""
    if isinstance(server, dict):
        host, port = server.get("host") or "", server.get("port")
        return f"{host}:{port}" if host and port else host
    return str(server or "")


def present(conn: dict) -> dict:
    """A stored connection as the Setup list shows it: the vault credential
    by name only, plus ``bind_password_set``. The bucket is not returned; it
    is always the connection's own tenant (:func:`check_connection`), so the
    edit form rebuilds it from ``tenant_id``."""
    out = dict(conn)
    ref = out.pop("vault_credential", None)
    name = ref.get("name") if isinstance(ref, dict) else ""
    if name:
        out["vault_credential"] = {"name": name}
    out["bind_password_set"] = bool(name)
    return out


def _servers(conn: dict) -> list:
    """The configured primary and backup servers, in that order."""
    return [str(conn.get(k) or "").strip() for k in ("primary_server", "backup_server")
            if str(conn.get(k) or "").strip()]


def spoke_config(conn: dict) -> dict:
    """The ``ad`` block the spoke reads (``AdDirectory`` config) from a stored
    connection. Only known fields are sent: never the tenant, id or the vault
    reference. ``dns_servers`` is typed as a comma-separated list."""
    out = {k: conn.get(k) for k in ("domain", "forest", "site", "base_dn", "bind_user",
                                    "bind_password", "discover", "use_global_catalog",
                                    "use_ssl", "timeout")
           if conn.get(k) not in (None, "")}
    out["servers"] = _servers(conn)
    out["dns_servers"] = [s.strip() for s in str(conn.get("dns_servers") or "").split(",")
                          if s.strip()]
    return out


def register(app, hub, ctx):
    """Register the Directory → Active Directory routes on the Hub app."""
    _session_user = ctx._session_user

    async def _send(conn: dict, cmd: str, extra: dict | None = None) -> dict:
        """Send one AD_* command for ``conn`` to its tenant's directory spoke
        and return the spoke's result. Errors are HTTP errors, never a 200:
        503 no spoke / no password from the vault, 501 an older spoke, 502 the
        spoke's own ERROR (AD unreachable, bad bind)."""
        # The tenant's directory spoke: its own, else the shared/unassigned
        # one. The resolver returns ANY directory spoke for "default", so the
        # spoke's tenant is checked again: the bind password must never reach
        # another tenant's spoke. A record saved before check_connection
        # existed is checked again here too.
        check_connection(conn)
        tid = conn.get("tenant_id") or ""
        spoke_id = hub.get_directory_spoke_for_tenant(tid)
        if not spoke_id:
            raise HTTPException(status_code=503, detail="No directory spoke connected")
        owner = hub.state.get_spoke_tenant(spoke_id) or ""
        if owner and not access.tenant_is_shared(owner) and not access.same_tenant(owner, tid):
            raise HTTPException(status_code=503, detail="No directory spoke for this "
                                "tenant is connected")
        # Fill the bind password from the vault. A vault miss leaves it empty:
        # say so here instead of sending a bind that is bound to fail.
        resolved = await instance_vault.overlay(hub, conn, STORAGE_KEY)
        if not resolved.get("bind_password"):
            raise HTTPException(status_code=503, detail="The AD bind password could not "
                                "be read from the Credential Vault")
        payload = {"ad": spoke_config(resolved), **(extra or {})}
        # Ask the spoke and unwrap its reply.
        result = await hub.request_response(spoke_id, cmd, payload, timeout=AD_TIMEOUT_S)
        body = access.unwrap_spoke(result)
        if not isinstance(body, dict):
            raise HTTPException(status_code=502, detail=f"{cmd}: no reply from the spoke")
        # Only an explicit SUCCESS is a success. A reply with no status or an
        # unknown one is a 502, so it can't show as "no accounts" or "connected".
        status = str(body.get("status", "")).upper()
        if status != "SUCCESS":
            message = str(body.get("message") or "")
            if message.startswith("Unknown command"):
                raise HTTPException(status_code=501, detail=_OLD_SPOKE_DETAIL)
            raise HTTPException(status_code=502, detail=message or f"{cmd} failed")
        return body

    def ad_cache_job(tid: str, conn_id: str) -> CacheJob:
        """Cache job for one connection's account list. The connection is
        looked up again at fetch time, so an edit or delete takes effect."""
        async def fetch():
            """List the accounts (raises on error, so an outage keeps the
            last list instead of showing none)."""
            conn = next((c for c in connections_for(hub, tid) if c.get("id") == conn_id), None)
            if conn is None:
                raise HTTPException(status_code=404, detail="AD connection not found")
            body = await _send(conn, "AD_SEARCH_USERS", {"q": "", "limit": LIST_LIMIT})
            return {"users": body.get("data") or [], "truncated": bool(body.get("truncated")),
                    "server": server_label(body.get("server"))}
        return CacheJob(CACHE_NS, f"{tid}|{conn_id}", fetch, (tid,), lane="ad",
                        refresh_s=REFRESH_S)

    def ad_cache_feed(_hub):
        """Feed: every stored AD connection that has a tenant."""
        for conn in hub.state.system_state.get("global_config", {}).get(STORAGE_KEY) or []:
            if isinstance(conn, dict) and conn.get("tenant_id") and conn.get("id"):
                yield ad_cache_job(conn["tenant_id"], conn["id"])

    if hasattr(hub, "cache_register_feed"):
        hub.cache_register_feed(CACHE_NS, ad_cache_feed)

    def _require_admin(request: Request) -> None:
        """403 unless a Global Admin is logged in. The /setup/* middleware
        already enforces this; repeated here so the route is safe on its own."""
        sess = _session_user(request)
        if not sess or not ctx._is_admin(sess):
            raise HTTPException(status_code=403, detail="Global Admin only")

    def _admin_conn(conn_id: str) -> dict:
        """One stored connection by id (admin routes), or 404. Its tenant and
        vault bucket are checked by _send (check_connection)."""
        conns = hub.state.system_state.get("global_config", {}).get(STORAGE_KEY) or []
        conn = next((c for c in conns if isinstance(c, dict) and c.get("id") == conn_id), None)
        if conn is None:
            raise HTTPException(status_code=404, detail="AD connection not found")
        return conn

    # ── Read ────────────────────────────────────────────────────────────────
    @app.get("/api/ldap/ad")
    async def get_ad(request: Request):
        """The tenant's AD accounts, one block per AD connection, from the
        cache. ``configured`` is false when the tenant has no AD connection.
        A connection that can't be read reports its ``error`` (and no users)
        rather than an empty list, so "no accounts" and "couldn't ask" differ;
        the other connections still show."""
        tid, _slug, _scope = directory_resolve(hub, _session_user(request), request)
        # Connections are read side by side (bounded), so a cold cache with
        # several unreachable ADs waits about one timeout, not one each.
        gate = asyncio.Semaphore(READ_CONCURRENCY)

        async def read(conn: dict) -> dict:
            """One connection's block: its accounts, or its own error."""
            job = ad_cache_job(tid, conn.get("id") or "")
            block = {"name": conn.get("name") or conn.get("domain") or "",
                     "domain": conn.get("domain") or ""}
            try:
                async with gate:
                    data = await hub.cache_read(job.ns, job.key, job.fetch,
                                                tenants=job.tenants, lane=job.lane)
                return hub.cache_annotate({**block, **data}, job.ns, job.key)
            except HTTPException as e:
                return {**block, "users": [], "error": str(e.detail)}
            except Exception as e:  # noqa: BLE001 — e.g. the spoke dropped mid-send
                # One connection failing must not 500 the whole tab.
                logger.warning("AD read for %s failed: %s", block["name"], type(e).__name__)
                return {**block, "users": [], "error": "The directory spoke did not answer"}

        blocks = await asyncio.gather(*(read(c) for c in connections_for(hub, tid)))
        return {"configured": bool(blocks), "connections": list(blocks)}

    # ── Admin checks (Setup; /setup/* is admin-only in api.py) ─────────────
    @app.post("/setup/ad-connections/{conn_id}/test")
    async def test_ad(conn_id: str, request: Request):
        """Bind to the connection's AD (failing over primary → backup) and
        report which server answered."""
        _require_admin(request)
        body = await _send(_admin_conn(conn_id), "AD_TEST")
        return {**{k: v for k, v in body.items() if k != "status"},
                "server": server_label(body.get("server"))}

    @app.post("/setup/ad-connections/{conn_id}/discover")
    async def discover_ad(conn_id: str, request: Request):
        """List the domain controllers / global catalogs the spoke would use,
        in order (DNS discovery first, then the configured servers)."""
        _require_admin(request)
        body = await _send(_admin_conn(conn_id), "AD_DISCOVER")
        return {k: v for k, v in body.items() if k != "status"}
