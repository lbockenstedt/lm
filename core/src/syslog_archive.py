"""Per-tenant syslog settings, the archive record, and the syslog role hooks.

The syslog feature has three parts (docs/syslog.md):

* ``syslog-collector`` deploy role: rsyslog on an agent, with a 24 h local
  store. The hub then loads the ``syslog`` spoke role (module_type
  ``logging``) on the same agent to manage and query it.
* An optional long-term archive. Today the only LM-installed one is the
  ``syslog-graylog`` deploy role; an external server can be connected instead.
  Everything here is backend-neutral except ``ARCHIVE_ROLES``.
* Per-tenant settings: drop rules, local retention hours and a size cap.

Stored in the encrypted hub state as
``system_state["syslog"][<tenant>] = {"settings": {...}, "archive": {...},
"managed_secrets": {...}}``. Passwords are never in that record: they live in
``hub_secret_store`` (cloud vault or encrypted blob) or the operator's
Credential Vault (external archive), and are only resolved when a config is
pushed to a collector. Everything a browser sees goes through
``public_archive`` (``password_set`` only).
"""

import asyncio
import ipaddress
import logging
import re
import secrets
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

import hub_secret_store
import instance_vault
from display_names import node_name

logger = logging.getLogger("Hub")

# Hub state keys and the cloud-vault name prefix for generated passwords.
SYSLOG_KEY = "syslog"
SECRETS_KEY = "syslog_secrets"
_KV_PREFIX = "syslog-"
# instance_vault storage key for the external archive's vault credential.
VAULT_STORAGE_KEY = "syslog_archive"

# Roles. An archive role is any "syslog-<backend>" deploy role except the
# collector; ARCHIVE_ROLES is the ONE place that maps a role to its backend.
COLLECTOR_ROLE = "syslog-collector"
SPOKE_ROLE = "syslog"
ARCHIVE_ROLES = {"syslog-graylog": "graylog"}

# Backends an operator may pick for an external archive ("syslog" = forward only).
EXTERNAL_BACKENDS = ("graylog", "syslog")

# What the LM-installed Graylog listens on, and the read-only API user.
GRAYLOG_INPUT_PORT = 1514
GRAYLOG_API_PORT = 9000
GRAYLOG_READER_USER = "lm-reader"

# Settings defaults and limits.
DEFAULT_SETTINGS = {"drop_rules": [], "retention_hours": 24, "max_mb": 2048}
MAX_DROP_RULES = 50
RULE_FIELDS = ("host", "program", "msg", "severity")
RULE_OPS = ("equals", "contains", "regex", "gte")
_RETENTION_RANGE = (1, 168)
_MAX_MB_RANGE = (64, 1048576)
_HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")

# Timeout for one push to one collector.
PUSH_TIMEOUT_S = 30.0


class ArchiveConflict(ValueError):
    """The tenant already has an archive that this change would replace."""


# ── role helpers ─────────────────────────────────────────────────────────────

def is_archive_role(role) -> bool:
    """True for an LM-installed archive deploy role (``syslog-<backend>``)."""
    role = str(role or "")
    return role.startswith("syslog-") and role != COLLECTOR_ROLE


def archive_backend(role) -> Optional[str]:
    """The archive backend a deploy role installs, or None."""
    return ARCHIVE_ROLES.get(str(role or ""))


# ── storage ──────────────────────────────────────────────────────────────────

def _tkey(tenant) -> str:
    """Canonical storage key for a tenant (case-insensitive)."""
    return str(tenant or "").strip().casefold()


def _all(hub) -> Dict[str, Any]:
    """The ``{tenant: record}`` map in hub state (created on first use)."""
    return hub.state.system_state.setdefault(SYSLOG_KEY, {})


def _blobs(hub) -> Dict[str, str]:
    """The local encrypted-password map used when no cloud vault is enabled."""
    return hub.state.system_state.setdefault(SECRETS_KEY, {})


def _tenant_rec(hub, tenant) -> Dict[str, Any]:
    """The tenant's syslog record (created on first use)."""
    return _all(hub).setdefault(_tkey(tenant), {})


def _dirty(hub) -> None:
    """Mark hub state dirty so it is persisted on the next flush."""
    try:
        hub.state._mark_dirty()
    except Exception:  # noqa: BLE001 - persistence hiccups are retried on the next write
        pass


def get_settings(hub, tenant) -> Dict[str, Any]:
    """The tenant's settings with defaults filled in (a copy)."""
    saved = (_all(hub).get(_tkey(tenant)) or {}).get("settings") or {}
    out = {**DEFAULT_SETTINGS, **saved}
    out["drop_rules"] = [dict(r) for r in out.get("drop_rules") or []]
    return out


def save_settings(hub, tenant, settings: Dict[str, Any]) -> None:
    """Store already-validated settings for the tenant."""
    _tenant_rec(hub, tenant)["settings"] = settings
    _dirty(hub)


def get_archive(hub, tenant) -> Optional[Dict[str, Any]]:
    """The tenant's archive record (internal, with secret refs), or None."""
    return (_all(hub).get(_tkey(tenant)) or {}).get("archive") or None


def _set_archive(hub, tenant, record: Optional[Dict[str, Any]]) -> None:
    """Store or clear the tenant's archive record."""
    rec = _tenant_rec(hub, tenant)
    if record:
        rec["archive"] = record
    else:
        rec.pop("archive", None)
    _dirty(hub)


def tenants(hub) -> List[str]:
    """Tenant keys that have any syslog record."""
    return sorted(_all(hub))


# ── validation ───────────────────────────────────────────────────────────────

def validate_drop_rules(rules) -> List[Dict[str, Any]]:
    """Return clean drop rules or raise ValueError with a readable message.

    A rule is ``{field, op, value, enabled, note}``: field is host, program,
    msg or severity; op is equals, contains, regex or gte. Regex rules must
    compile; severity values are 0-7 (``gte`` only makes sense for severity)."""
    # Shape and count.
    if rules is None:
        return []
    if not isinstance(rules, list):
        raise ValueError("drop_rules must be a list")
    if len(rules) > MAX_DROP_RULES:
        raise ValueError(f"at most {MAX_DROP_RULES} drop rules are allowed")
    out = []
    # Check each rule.
    for i, r in enumerate(rules, 1):
        if not isinstance(r, dict):
            raise ValueError(f"rule {i}: must be an object")
        field, op = str(r.get("field") or ""), str(r.get("op") or "")
        value = str(r.get("value") if r.get("value") is not None else "").strip()
        if field not in RULE_FIELDS:
            raise ValueError(f"rule {i}: field must be one of {', '.join(RULE_FIELDS)}")
        if op not in RULE_OPS:
            raise ValueError(f"rule {i}: op must be one of {', '.join(RULE_OPS)}")
        if not value:
            raise ValueError(f"rule {i}: value is required")
        if len(value) > 512:
            raise ValueError(f"rule {i}: value is longer than 512 characters")
        # Severity is a number 0-7; only severity can use gte.
        if field == "severity":
            if not value.isdigit() or not 0 <= int(value) <= 7:
                raise ValueError(f"rule {i}: severity must be 0-7")
        elif op == "gte":
            raise ValueError(f"rule {i}: 'gte' only applies to severity")
        if op == "regex":
            try:
                re.compile(value)
            except re.error as e:
                raise ValueError(f"rule {i}: invalid regex: {e}") from None
        out.append({"field": field, "op": op,
                    "value": int(value) if field == "severity" else value,
                    "enabled": r.get("enabled", True) is not False,
                    "note": str(r.get("note") or "")[:200]})
    return out


def _int_in(body, key, default, lo, hi) -> int:
    """Read an integer setting in [lo, hi] or raise ValueError."""
    raw = body.get(key, default)
    try:
        val = int(raw)
    except (TypeError, ValueError):
        raise ValueError(f"{key} must be a whole number") from None
    if not lo <= val <= hi:
        raise ValueError(f"{key} must be between {lo} and {hi}")
    return val


def validate_settings(body, current: Dict[str, Any]) -> Dict[str, Any]:
    """Merge a settings update onto ``current`` and validate it (ValueError)."""
    if not isinstance(body, dict):
        raise ValueError("settings must be an object")
    return {
        "drop_rules": validate_drop_rules(body.get("drop_rules", current.get("drop_rules"))),
        "retention_hours": _int_in(body, "retention_hours", current.get("retention_hours"),
                                   *_RETENTION_RANGE),
        "max_mb": _int_in(body, "max_mb", current.get("max_mb"), *_MAX_MB_RANGE),
    }


def _is_ip(host) -> bool:
    """True when ``host`` is an IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(str(host or "").strip())
        return True
    except ValueError:
        return False


def _valid_host(host) -> bool:
    """True for an IP address or a plain DNS name (no scheme, port or path)."""
    return _is_ip(host) or bool(_HOST_RE.match(str(host or "").strip()))


# ── views and spoke projection ───────────────────────────────────────────────

def public_archive(record: Optional[Dict[str, Any]], *, include_ui: bool = False):
    """The archive as the browser may see it: no secret or secret reference,
    only ``password_set``. ``ui_url`` (the Graylog web UI) is only added for
    Global Admins (``include_ui``)."""
    if not record:
        return None
    # Copy the non-secret fields.
    out = {k: record.get(k) for k in ("backend", "managed_by_role", "host", "input_port",
                                      "tls", "tls_name", "api_url", "user", "created_at")}
    out["spoke_name"] = record.get("spoke_name")
    out["ca_pem_set"] = bool(record.get("ca_pem"))
    out["password_set"] = bool(record.get("password_ref") or record.get("vault_credential"))
    out["vault_credential"] = record.get("vault_credential")
    out["query_supported"] = record.get("backend") in ("graylog",)
    # Graylog's own UI, for Global Admin troubleshooting and upgrades only.
    if include_ui and record.get("backend") == "graylog" and record.get("api_url"):
        out["ui_url"] = re.sub(r"/api/?$", "/", str(record["api_url"]))
    return out


async def _archive_password(hub, tenant, record) -> Optional[str]:
    """Resolve the archive read password (vault credential or stored secret)."""
    # External archive with a Credential Vault reference.
    if record.get("vault_credential"):
        resolved = await instance_vault.overlay(hub, dict(record), VAULT_STORAGE_KEY)
        return resolved.get("password")
    # Hub-stored password (managed reader or inline external password).
    ref = record.get("password_ref")
    if isinstance(ref, dict):
        return await hub_secret_store.get(hub, _blobs(hub), ref.get("key") or "", ref)
    return None


async def spoke_archive(hub, tenant) -> Optional[Dict[str, Any]]:
    """The archive dict sent to collectors, with the password resolved, or None.

    Only called while building a push; the result is never stored or logged."""
    record = get_archive(hub, tenant)
    if not record:
        return None
    # LM-managed archives are signed by the hub CA; external ones bring their own.
    ca_pem = record.get("ca_pem")
    if record.get("managed_by_role") and not ca_pem:
        from security import mtls_ca
        ca_pem = await asyncio.to_thread(mtls_ca.ca_cert_pem) or None
    return {"backend": record.get("backend"), "host": record.get("host"),
            "input_port": record.get("input_port"), "tls": bool(record.get("tls")),
            "api_url": record.get("api_url"), "user": record.get("user"),
            "password": await _archive_password(hub, tenant, record), "ca_pem": ca_pem,
            "tls_name": record.get("tls_name") or None}


async def spoke_config(hub, tenant) -> Dict[str, Any]:
    """The full config a tenant's logging spoke needs (UPDATE_CONFIG / LOAD_ROLE)."""
    return {"tenant": tenant, "archive": await spoke_archive(hub, tenant),
            **get_settings(hub, tenant)}


def parent_agent(hub, spoke_id) -> str:
    """The agent hosting a role sub-spoke (the id itself for a base agent)."""
    pk = hub._primary_key(spoke_id)
    parent = (getattr(hub, "spoke_parent_map", None) or {}).get(pk)
    if not parent:
        meta = (hub.state.system_state.get("module_metadata") or {}).get(pk) or {}
        parent = meta.get("parent_name")
    return hub._primary_key(parent) if parent else pk


def collector_name(hub, spoke_id) -> str:
    """Friendly name for a collector: its host agent's name (falls back to the id)."""
    return node_name(hub.state.system_state, parent_agent(hub, spoke_id),
                     getattr(hub, "agent_info", None))


def logging_spokes(hub, tenant) -> List[str]:
    """The tenant's connected logging spokes (never another tenant's)."""
    return list(hub.get_logging_spokes_for_tenant(tenant) or [])


def unwrap(res) -> Any:
    """The handler payload of a spoke reply (``payload.data``) or the reply itself."""
    if isinstance(res, dict) and isinstance(res.get("payload"), dict):
        res = res["payload"].get("data", res)
    # A COMMAND_RESULT envelope may nest the handler dict one level deeper.
    if isinstance(res, dict) and "status" not in res and isinstance(res.get("data"), dict):
        res = res["data"]
    return res


def reply_error(data) -> Optional[str]:
    """The error text of an ERROR reply, or None when the reply is usable."""
    if not isinstance(data, dict):
        return "no reply" if data is None else None
    if str(data.get("status") or "").upper() == "ERROR":
        return str(data.get("message") or data.get("error") or "spoke returned ERROR")
    return None


async def push_to_tenant(hub, tenant, data: Dict[str, Any], *, reason: str) -> List[Dict[str, Any]]:
    """Send SYSLOG_CONFIG ``data`` to each of the tenant's collectors.

    Returns one ``{collector, spoke_id, ok, error}`` row per collector and logs
    each outcome by collector name (``data`` itself is never logged: it may
    carry the archive password)."""
    sids = logging_spokes(hub, tenant)
    if not sids:
        logger.info("syslog: %s for tenant %s: no connected collectors to update", reason, tenant)
        return []

    async def one(sid):
        """Push to one collector and describe the outcome."""
        name = collector_name(hub, sid)
        try:
            res = unwrap(await hub.request_response(sid, "SYSLOG_CONFIG", data,
                                                    timeout=PUSH_TIMEOUT_S))
            err = reply_error(res)
        except Exception as e:  # noqa: BLE001 - one collector must not stop the rest
            err = str(e) or type(e).__name__
        # Log every collector's result by name.
        if err:
            logger.error("syslog: %s for tenant %s: push to collector %s failed: error %s",
                         reason, tenant, name, err)
        else:
            logger.info("syslog: %s for tenant %s: pushed to collector %s", reason, tenant, name)
        return {"collector": name, "spoke_id": sid, "ok": not err, "error": err}

    return list(await asyncio.gather(*(one(s) for s in sids)))


# ── generated (managed) secrets ──────────────────────────────────────────────

async def _store_secret(hub, tenant, which: str, value: str) -> Dict[str, Any]:
    """Store a generated password; returns its reference record (no value)."""
    key = f"{_tkey(tenant)}:{which}"
    rec = dict((_tenant_rec(hub, tenant).get("managed_secrets") or {}).get(which) or {})
    rec["key"] = key
    await hub_secret_store.put(hub, _blobs(hub), key, rec, value, _KV_PREFIX)
    _tenant_rec(hub, tenant).setdefault("managed_secrets", {})[which] = rec
    _dirty(hub)
    return rec


async def _read_secret(hub, tenant, which: str) -> Optional[str]:
    """Read a stored generated password, or None."""
    rec = (_tenant_rec(hub, tenant).get("managed_secrets") or {}).get(which)
    if not isinstance(rec, dict):
        return None
    return await hub_secret_store.get(hub, _blobs(hub), rec.get("key") or "", rec)


async def _drop_secret(hub, tenant, which: str) -> None:
    """Delete a stored generated password and its reference."""
    secrets_map = _tenant_rec(hub, tenant).get("managed_secrets") or {}
    rec = secrets_map.pop(which, None)
    if isinstance(rec, dict):
        await hub_secret_store.delete(hub, _blobs(hub), rec.get("key") or "", rec)
    _dirty(hub)


# ── role hooks (called from routes/agents.py) ────────────────────────────────

def agent_tenant(hub, spoke_id) -> str:
    """The tenant an agent is bound to ("default" when unbound)."""
    try:
        return hub.state.get_spoke_tenant(hub._primary_key(spoke_id)) or "default"
    except Exception:  # noqa: BLE001
        return "default"


def archive_tls_name(role, tenant) -> str:
    """The cert CN (and only DNS SAN) of an LM-installed archive; collectors
    verify the archive's TLS against this name while connecting to its IP."""
    return f"{role}-{_dns_label(tenant)}"


def _dns_label(text) -> str:
    """``text`` reduced to DNS-safe characters (for certificate names)."""
    return re.sub(r"[^A-Za-z0-9.-]+", "-", str(text or "")).strip("-.").lower() or "node"


async def _service_cert(cfg, common_name, sans=None) -> Dict[str, Any]:
    """Add a hub-CA client+server cert (and the CA) to a role config."""
    from security import mtls_ca
    # Only names that are valid DNS names can be SANs.
    sans = [n for n in (sans or [common_name]) if _HOST_RE.match(str(n))] or None
    leaf, key, ca = await asyncio.to_thread(mtls_ca.issue_service_cert, common_name, sans)
    return {**cfg, "tls_cert_pem": leaf, "tls_key_pem": key, "tls_ca_pem": ca,
            "tls_subject": common_name}


async def pre_load_role(hub, spoke_id, role, cfg) -> Dict[str, Any]:
    """Fill in a syslog deploy role's LOAD_ROLE config; other roles pass through.

    Collector: tenant slug + a hub-CA cert. Archive (graylog): generated admin
    and reader passwords (stored encrypted first) + a hub-CA cert. Raises
    ArchiveConflict when the tenant already has an archive elsewhere."""
    if role != COLLECTOR_ROLE and not is_archive_role(role):
        return cfg
    cfg = dict(cfg or {})
    tenant = agent_tenant(hub, spoke_id)
    name = collector_name(hub, spoke_id)
    # Collector: tenant + cert named after the host.
    if role == COLLECTOR_ROLE:
        logger.info("syslog: preparing collector install on %s for tenant %s", name, tenant)
        cfg["tenant"] = tenant
        cn = f"{COLLECTOR_ROLE}-{_dns_label(name)}"
        return await _service_cert(cfg, cn, [cn, name])
    # Archive role: refuse while another archive is connected for the tenant.
    if not archive_backend(role):
        raise ArchiveConflict(f"unknown syslog archive role '{role}'")
    existing = get_archive(hub, tenant)
    pk = hub._primary_key(spoke_id)
    same_node = bool(existing and existing.get("managed_by_role") == role
                     and existing.get("spoke_id") == pk)
    if existing and not same_node:
        where = existing.get("spoke_name") or existing.get("host") or "an external server"
        raise ArchiveConflict(
            f"Tenant '{tenant}' already has a syslog archive ({where}). Unload that "
            f"archive role or disconnect the external archive first.")
    # Reuse passwords on a re-install of the same node; otherwise generate new ones.
    admin_pw = await _read_secret(hub, tenant, "admin") if same_node else None
    reader_pw = await _read_secret(hub, tenant, "reader") if same_node else None
    if not admin_pw or not reader_pw:
        admin_pw, reader_pw = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
        await _store_secret(hub, tenant, "admin", admin_pw)
        await _store_secret(hub, tenant, "reader", reader_pw)
    logger.info("syslog: preparing %s install on %s for tenant %s (passwords stored: yes)",
                role, name, tenant)
    cfg.update({"admin_password": admin_pw, "reader_password": reader_pw})
    cn = archive_tls_name(role, tenant)
    return await _service_cert(cfg, cn, [cn, name])


def _load_ok(payload) -> bool:
    """True when a LOAD_ROLE reply reports SUCCESS."""
    return isinstance(payload, dict) and payload.get("status") == "SUCCESS"


async def post_load_role(hub, spoke_id, role, payload) -> None:
    """Follow-ups after a syslog deploy role LOAD_ROLE succeeded.

    Collector: load the ``syslog`` spoke role on the same agent with the
    tenant's config. Archive: save the archive record and push it to the
    tenant's collectors. Never raises: failures are logged with the names."""
    if not _load_ok(payload) or (role != COLLECTOR_ROLE and not is_archive_role(role)):
        return
    tenant = agent_tenant(hub, spoke_id)
    name = collector_name(hub, spoke_id)
    try:
        if role == COLLECTOR_ROLE:
            await _load_spoke_role(hub, spoke_id, tenant, name)
        else:
            await _register_managed_archive(hub, spoke_id, role, tenant, name)
    except Exception:  # noqa: BLE001 - the role itself loaded; report, don't fail it
        logger.exception("syslog: follow-up after loading %s on %s failed", role, name)


async def _load_spoke_role(hub, spoke_id, tenant, name) -> None:
    """LOAD_ROLE ``syslog`` on the collector's agent with the tenant config."""
    logger.info("syslog: loading the syslog spoke role on collector %s (tenant %s)", name, tenant)
    cfg = await spoke_config(hub, tenant)
    res = unwrap(await hub.request_response(spoke_id, "LOAD_ROLE",
                                            {"role": SPOKE_ROLE, "config": cfg}, timeout=120.0))
    err = reply_error(res) or (None if _load_ok(res) else "unexpected reply")
    if err:
        logger.error("syslog: loading the syslog spoke role on %s failed: error %s", name, err)
    else:
        logger.info("syslog: syslog spoke role loaded on collector %s", name)


async def _register_managed_archive(hub, spoke_id, role, tenant, name) -> None:
    """Save the LM-installed archive record and push it to the tenant's collectors."""
    # The archive's address is the agent's primary IP.
    res = unwrap(await hub.request_response(spoke_id, "GET_PRIMARY_IP", {}, timeout=15.0))
    ip = res.get("ip") if isinstance(res, dict) else None
    if not ip:
        logger.error("syslog: archive on %s not registered: error the agent did not report "
                     "its IP (reload the %s role to retry)", name, role)
        return
    record = {"backend": archive_backend(role), "managed_by_role": role,
              "spoke_id": hub._primary_key(spoke_id), "spoke_name": name, "host": ip,
              "input_port": GRAYLOG_INPUT_PORT, "tls": True,
              "api_url": f"https://{ip}:{GRAYLOG_API_PORT}/api",
              "user": GRAYLOG_READER_USER,
              "password_ref": (_tenant_rec(hub, tenant).get("managed_secrets") or {}).get("reader"),
              "ca_pem": None, "tls_name": archive_tls_name(role, tenant),
              "created_at": time.time()}
    _set_archive(hub, tenant, record)
    logger.info("syslog: archive saved for tenant %s: %s on %s (%s:%s)",
                tenant, record["backend"], name, ip, GRAYLOG_INPUT_PORT)
    await push_to_tenant(hub, tenant, {"archive": await spoke_archive(hub, tenant)},
                         reason="archive connected")


async def on_role_removed(hub, spoke_id, role, payload) -> None:
    """After UNLOAD_ROLE/UNINSTALL_ROLE of an archive role: drop the archive
    record (if it is this node's) and tell the tenant's collectors."""
    if not is_archive_role(role):
        return
    if isinstance(payload, dict) and str(payload.get("status") or "").upper() == "ERROR":
        return
    tenant = agent_tenant(hub, spoke_id)
    existing = get_archive(hub, tenant)
    # Only the node that registered the archive may remove it.
    if not existing or existing.get("managed_by_role") != role \
            or existing.get("spoke_id") != hub._primary_key(spoke_id):
        return
    try:
        _set_archive(hub, tenant, None)
        await _drop_secret(hub, tenant, "admin")
        await _drop_secret(hub, tenant, "reader")
        logger.info("syslog: archive removed for tenant %s (%s unloaded on %s)",
                    tenant, role, collector_name(hub, spoke_id))
        await push_to_tenant(hub, tenant, {"archive": None}, reason="archive disconnected")
    except Exception:  # noqa: BLE001 - the unload itself succeeded
        logger.exception("syslog: removing the archive for tenant %s failed", tenant)


# ── external archive ─────────────────────────────────────────────────────────

async def save_external_archive(hub, tenant, body, sess, *, is_admin: bool) -> Dict[str, Any]:
    """Validate and store an external archive, then push it to the collectors.

    Raises ValueError (400) on bad input and ArchiveConflict (409) when an
    LM-managed archive is connected. A blank password on re-save keeps the
    stored one. Returns the per-collector push results."""
    existing = get_archive(hub, tenant)
    if existing and existing.get("managed_by_role"):
        raise ArchiveConflict(
            f"This tenant's archive is LM-installed ({existing.get('managed_by_role')} on "
            f"{existing.get('spoke_name') or existing.get('host')}). Unload that role first.")
    if not isinstance(body, dict):
        raise ValueError("archive must be an object")
    # Backend, host, port and TLS.
    backend = str(body.get("backend") or "").strip().lower()
    if backend not in EXTERNAL_BACKENDS:
        raise ValueError(f"backend must be one of {', '.join(EXTERNAL_BACKENDS)}")
    host = str(body.get("host") or "").strip()
    if not _valid_host(host):
        raise ValueError("host must be an IP address or DNS name")
    # Archive traffic is always encrypted (fleet rule 5.4); the collector
    # refuses a plain-text forward too.
    if body.get("tls", True) is False:
        raise ValueError("the archive must use TLS: plain-text forwarding is not allowed")
    port = _int_in(body, "input_port", 6514, 1, 65535)
    ca_pem = str(body.get("ca_pem") or "").strip() or None
    if ca_pem and "BEGIN CERTIFICATE" not in ca_pem:
        raise ValueError("ca_pem must be a PEM certificate")
    # Optional name to verify the server cert against (blank = the host itself).
    tls_name = str(body.get("tls_name") or "").strip() or None
    if tls_name and not _HOST_RE.match(tls_name):
        raise ValueError("tls_name must be a DNS name")
    # The collector checks the cert's name (an IP alone would mean only the CA
    # chain is checked, so any cert from that CA could stand in); it refuses
    # an IP host with no tls_name too.
    if not tls_name and _is_ip(host):
        raise ValueError("host is an IP address: set tls_name to the name in its certificate")
    record = {"backend": backend, "managed_by_role": None, "spoke_id": None,
              "host": host, "input_port": port, "tls": True,
              "tls_name": tls_name, "api_url": None, "user": None, "ca_pem": ca_pem,
              "created_at": time.time()}
    # Graylog query access: API URL (SSRF-checked), user and password.
    if backend == "graylog":
        await _external_graylog_auth(hub, tenant, body, sess, record, existing, is_admin)
    elif existing and existing.get("password_ref"):
        await hub_secret_store.delete(hub, _blobs(hub), existing["password_ref"].get("key") or "",
                                      existing["password_ref"])
    _set_archive(hub, tenant, record)
    logger.info("syslog: external archive saved for tenant %s: %s at %s:%s (tls=%s, "
                "password set=%s)", tenant, backend, host, port, record["tls"],
                bool(record.get("password_ref") or record.get("vault_credential")))
    return await push_to_tenant(hub, tenant, {"archive": await spoke_archive(hub, tenant)},
                                reason="external archive saved")


def _archive_api_url_ok(url: str) -> bool:
    """True if ``url`` is an https URL the tenant's collector may call.

    Not ``access.safe_external_url``: the hub never calls this URL. Only the
    tenant's own collector does, inside the tenant network, like NetBox or
    TrueNAS instance URLs, so a lab-internal (private or loopback) Graylog is
    the normal case. Link-local and unspecified addresses (cloud metadata,
    0.0.0.0) are still refused.
    """
    # Scheme and host.
    parts = urlsplit(url or "")
    if parts.scheme != "https" or not parts.hostname:
        return False
    # Refuse link-local / unspecified IP literals; names are allowed.
    try:
        ip = ipaddress.ip_address(parts.hostname)
    except ValueError:
        return True
    return not (ip.is_link_local or ip.is_unspecified)


async def _external_graylog_auth(hub, tenant, body, sess, record, existing, is_admin) -> None:
    """Fill api_url/user and the password (vault ref or stored secret) on ``record``."""
    api_url = str(body.get("api_url") or "").strip()
    if not _archive_api_url_ok(api_url):
        raise ValueError("api_url must be an https URL with a host (not link-local)")
    record["api_url"] = api_url.rstrip("/")
    record["user"] = str(body.get("user") or "").strip() or None
    # A Credential Vault reference wins; it is validated and kept as the reference.
    candidate = {"vault_credential": body.get("vault_credential"),
                 "password": body.get("password") or ""}
    await instance_vault.validate_ref(hub, candidate, sess, is_admin=is_admin,
                                      storage_key=VAULT_STORAGE_KEY)
    old_ref = (existing or {}).get("password_ref")
    if instance_vault.has_vault_ref(candidate):
        record["vault_credential"] = instance_vault.strip_inline_secrets(
            candidate, VAULT_STORAGE_KEY)["vault_credential"]
        if old_ref:
            await hub_secret_store.delete(hub, _blobs(hub), old_ref.get("key") or "", old_ref)
        return
    # Inline password: store it encrypted; blank keeps the stored one.
    if candidate["password"]:
        ref = dict(old_ref or {})
        ref["key"] = f"{_tkey(tenant)}:external"
        await hub_secret_store.put(hub, _blobs(hub), ref["key"], ref,
                                   str(candidate["password"]), _KV_PREFIX)
        record["password_ref"] = ref
    elif old_ref:
        record["password_ref"] = old_ref
    elif (existing or {}).get("vault_credential"):
        record["vault_credential"] = existing["vault_credential"]


async def delete_external_archive(hub, tenant) -> List[Dict[str, Any]]:
    """Disconnect the external archive and tell the collectors (409 if managed)."""
    existing = get_archive(hub, tenant)
    if not existing:
        return []
    if existing.get("managed_by_role"):
        raise ArchiveConflict(
            f"This tenant's archive is LM-installed ({existing.get('managed_by_role')}). "
            f"Unload that role to disconnect it.")
    ref = existing.get("password_ref")
    if isinstance(ref, dict):
        await hub_secret_store.delete(hub, _blobs(hub), ref.get("key") or "", ref)
    _set_archive(hub, tenant, None)
    logger.info("syslog: external archive disconnected for tenant %s", tenant)
    return await push_to_tenant(hub, tenant, {"archive": None}, reason="archive disconnected")
