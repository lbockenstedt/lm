"""Azure Key Vault hook (hub broker) — disaster-recovery kit off-box.

Pushes to an Azure Key Vault, authenticated with the SAME SSO app certificate
(``security.oidc.fetch_app_token`` → ``https://vault.azure.net/.default``):

  * the local **admin password** (rotated on a schedule — break-glass: after
    rotation it exists ONLY in the vault),
  * the config **Fernet key** (``LM_FERNET_KEY`` — needed to decrypt a backup),
  * rolling **min backups** (gzip+base64), keeping the most recent ``retain``
    daily copies. A min backup is NOT the full config (that's >25 KB — it lives in
    the real backup source) — it's just enough to bring a fresh hub back online:
    users/logins, the OIDC + Azure connection config, the OIDC cert/key, and the
    Fernet key. Restore it → the hub can auth to Azure and let admins log in →
    then restore the full backup from source.

The app registration needs the **Key Vault Secrets Officer** RBAC role (or a Set
secret access policy) on the vault. Key Vault secrets are capped at 25 KB, so a
min backup that exceeds that (many local users) is refused with a clear error.

Pure REST (no azure SDK). Errors carry the vault response body.
"""
# Postpone evaluation of type hints so annotations stay cheap at import time.
from __future__ import annotations

# base64 + gzip encode backups compactly as Key Vault secret text.
import base64
import gzip
# logging reports vault failures.
import logging
# secrets/string generate cryptographically random passwords.
import secrets
import string
# Type hints for config dicts and optional values.
from typing import Any, Dict, List, Optional

# httpx is the async HTTP client used for Key Vault REST calls.
import httpx

# shared_client reuses a caller's HTTP client or creates a temporary one.
from http_client import shared_client

# App-token helpers: fetch (cached) and forget a token for the Azure vault scope.
from security.oidc import OidcConfig, fetch_app_token, forget_app_token

# Named logger for all Key Vault messages.
logger = logging.getLogger("KeyVault")

# OAuth scope that grants access to Azure Key Vault.
_SCOPE = "https://vault.azure.net/.default"
# Key Vault REST API version used in every request.
_API = "7.4"
_MAX_SECRET_BYTES = 25 * 1024  # Key Vault hard limit on secret value size


class KeyVaultError(Exception):
    """Raised for any Key Vault failure; message is safe to surface."""


def gen_password(n: int = 24) -> str:
    """Random password meeting complexity (all four classes), length ``n``."""
    # Character classes the password draws from.
    lo, up, dg = string.ascii_lowercase, string.ascii_uppercase, string.digits
    sy = "!@#$%^&*()-_=+"
    # Never generate fewer than 12 characters.
    n = max(12, n)
    # Guarantee at least one character from each class.
    pw = [secrets.choice(lo), secrets.choice(up), secrets.choice(dg), secrets.choice(sy)]
    # Fill the rest from all classes combined.
    allc = lo + up + dg + sy
    pw += [secrets.choice(allc) for _ in range(n - 4)]
    # Shuffle so the guaranteed characters are not always at the front.
    secrets.SystemRandom().shuffle(pw)
    return "".join(pw)


def encode_config_secret(raw: bytes) -> str:
    """gzip + base64 the (already-encrypted) state bytes for a Key Vault secret;
    raise if the result exceeds the 25 KB secret limit."""
    # Compress then base64-encode so the bytes are valid secret text.
    blob = base64.b64encode(gzip.compress(raw)).decode()
    # Refuse anything over the Key Vault size limit.
    if len(blob) > _MAX_SECRET_BYTES:
        raise KeyVaultError(
            f"config backup is {len(blob)} bytes compressed — over Key Vault's "
            f"{_MAX_SECRET_BYTES}-byte secret limit; use Azure Blob Storage for backups")
    return blob


def decode_config_secret(blob: str) -> bytes:
    """Reverse :func:`encode_config_secret`: base64-decode then gunzip."""
    return gzip.decompress(base64.b64decode(blob))


def _base(vault_url: str) -> str:
    """Normalise the vault URL by removing any trailing slash."""
    return str(vault_url or "").rstrip("/")


async def _send(cfg: OidcConfig, c: httpx.AsyncClient, method: str, url: str,
                **kwargs) -> httpx.Response:
    """Send one Key Vault request with the (cached) app token. On a 401 the
    cached token is dropped and the request retried once with a fresh one, so
    a revoked or stale token never sticks until it expires."""
    # Copy caller headers so we can add Authorization without mutating theirs.
    headers = dict(kwargs.pop("headers", {}) or {})
    # At most two attempts: the second only after a 401 with a fresh token.
    for attempt in (1, 2):
        # Get a (possibly cached) app token and attach it as a bearer token.
        token = await fetch_app_token(cfg, _SCOPE, http=c)
        headers["Authorization"] = f"Bearer {token}"
        # Send the request.
        resp = await c.request(method, url, headers=headers, **kwargs)
        # Return unless this was a 401 on the first attempt.
        if resp.status_code != 401 or attempt == 2:
            return resp
        # Drop the cached token so the retry fetches a new one.
        forget_app_token(cfg, _SCOPE)
    return resp


async def set_secret(cfg: OidcConfig, vault_url: str, name: str, value: str,
                     http: Optional[httpx.AsyncClient] = None) -> str:
    """PUT a secret (new version). Returns the secret id."""
    # Fail clearly when no vault is configured.
    if not vault_url:
        raise KeyVaultError("Key Vault URL not configured")
    # URL of the secret in the vault.
    url = f"{_base(vault_url)}/secrets/{name}?api-version={_API}"
    # PUT the new value (Key Vault creates a new version).
    async with shared_client(http, 20.0) as c:
        resp = await _send(cfg, c, "PUT", url,
                           headers={"Content-Type": "application/json"},
                           json={"value": value})
    # Anything but 200/201 is a failure; include part of the response body.
    if resp.status_code not in (200, 201):
        raise KeyVaultError(f"Key Vault PUT {name} failed: HTTP {resp.status_code} — {resp.text[:300]}")
    # Return the id of the stored secret version.
    return resp.json().get("id", "")


async def get_secret(cfg: OidcConfig, vault_url: str, name: str,
                     http: Optional[httpx.AsyncClient] = None) -> Optional[str]:
    """Fetch a secret's current value, or None if it does not exist."""
    # URL of the secret in the vault.
    url = f"{_base(vault_url)}/secrets/{name}?api-version={_API}"
    # GET the secret.
    async with shared_client(http, 20.0) as c:
        resp = await _send(cfg, c, "GET", url)
    # 404 means the secret does not exist.
    if resp.status_code == 404:
        return None
    # Any other non-200 is an error.
    if resp.status_code != 200:
        raise KeyVaultError(f"Key Vault GET {name} failed: HTTP {resp.status_code} — {resp.text[:200]}")
    return resp.json().get("value")


async def list_secret_names(cfg: OidcConfig, vault_url: str, prefix: str = "",
                            http: Optional[httpx.AsyncClient] = None) -> List[str]:
    """All secret names (optionally prefix-filtered), paged."""
    # Start with the first page of the secrets listing.
    url = f"{_base(vault_url)}/secrets?api-version={_API}"
    out: List[str] = []
    async with shared_client(http, 20.0) as c:
        # Follow nextLink until there are no more pages.
        while url:
            resp = await _send(cfg, c, "GET", url)
            # Abort on any failed page.
            if resp.status_code != 200:
                raise KeyVaultError(f"Key Vault list failed: HTTP {resp.status_code} — {resp.text[:200]}")
            # Secret names are the last path segment of each item's id.
            body = resp.json()
            for item in body.get("value", []):
                sid = item.get("id", "")
                nm = sid.rsplit("/", 1)[-1]
                # Keep names matching the optional prefix.
                if nm and (not prefix or nm.startswith(prefix)):
                    out.append(nm)
            # Advance to the next page (None ends the loop).
            url = body.get("nextLink")
    return out


async def delete_secret(cfg: OidcConfig, vault_url: str, name: str,
                        http: Optional[httpx.AsyncClient] = None) -> bool:
    """Delete a secret; an already-missing secret also counts as success."""
    # URL of the secret in the vault.
    url = f"{_base(vault_url)}/secrets/{name}?api-version={_API}"
    async with shared_client(http, 20.0) as c:
        resp = await _send(cfg, c, "DELETE", url)
    # 200/204 deleted, 404 already gone; anything else is an error.
    if resp.status_code not in (200, 204, 404):
        raise KeyVaultError(f"Key Vault DELETE {name} failed: HTTP {resp.status_code} — {resp.text[:200]}")
    return True


async def test_connection(cfg: OidcConfig, vault_url: str,
                          http: Optional[httpx.AsyncClient] = None) -> Dict[str, Any]:
    """List secrets to confirm the token + RBAC + URL resolve. Returns a count."""
    # Listing proves the token, permissions and URL all work.
    names = await list_secret_names(cfg, vault_url, http=http)
    return {"ok": True, "secret_count": len(names)}


async def resolve_ref(hub, ref: Optional[str],
                      http: Optional[httpx.AsyncClient] = None) -> Optional[str]:
    """Resolve a secret *reference* to its value, Key-Vault-optionally.

    ``kv:<name>`` → fetch secret ``<name>`` from the hub's configured vault via
    the app certificate (returns ``None`` when no vault is configured or the
    secret is absent — the caller decides how to degrade). Any other non-empty
    string is treated as an inline literal and returned unchanged, so a
    self-hosted deployment with no vault keeps working. Never raises."""
    # Empty reference resolves to nothing.
    if not ref:
        return None
    ref = str(ref)
    # Not a "kv:" reference: it is an inline value, returned as-is.
    if not ref.startswith("kv:"):
        return ref
    # Extract the secret name after the "kv:" prefix.
    name = ref[len("kv:"):].strip()
    if not name:
        return None
    # Look up the configured vault and fetch the secret; any failure yields None.
    try:
        from security.oidc import get_oidc_config
        vault_url = (get_config(hub) or {}).get("vault_url")
        if not vault_url:
            return None
        return await get_secret(get_oidc_config(hub), vault_url, name, http=http)
    except Exception as e:  # noqa: BLE001
        # Never raise: log and let the caller degrade.
        logger.warning("Key Vault: resolve_ref(%s) failed: %s", name, e)
        return None


# ---------------------------------------------------------------------------
# Hub-level operations (shared by the WebUI routes and the 7-day scheduler).
# These touch hub state and the api helpers; api is imported lazily to avoid a
# circular import at module load (api imports the route modules).
# ---------------------------------------------------------------------------

# Standard-library modules for the hub-level operations below (aliased to avoid name clashes).
import datetime as _dt
import json as _json
import os as _os
import time as _time


def _primary_fernet_key() -> str:
    """Raw primary Fernet key via the encryption singleton (env-drop safe).

    ``LM_FERNET_KEY`` is dropped from ``os.environ`` after load (root/LPE
    hardening), so the break-glass min-backup bundle and the push-to-Key-Vault
    path must source the key from ``security.encryption`` — which stashed it —
    rather than re-reading the (now absent) env var."""
    # Ask the encryption module, which kept the key after it was removed from the environment.
    try:
        from security.encryption import primary_fernet_key
        return primary_fernet_key() or ""
    except Exception:  # noqa: BLE001
        # Fall back to the environment variable if the encryption module is unavailable.
        return (_os.environ.get("LM_FERNET_KEY", "") or "").strip()


# Config keys accepted for the Key Vault settings.
CFG_FIELDS = ("enabled", "vault_url", "admin_secret", "fernet_secret",
              "backup_prefix", "retain", "rotate_days")
# Default settings: disabled, standard secret names, keep 7 backups, rotate every 7 days.
DEFAULTS = {"enabled": False, "vault_url": "", "admin_secret": "lm-admin-password",
            "fernet_secret": "lm-fernet-key", "backup_prefix": "lm-min-backup-",
            "retain": 7, "rotate_days": 7}


def get_config(hub) -> dict:
    """Return the Key Vault settings with defaults filled in."""
    # Start from defaults and overlay any saved settings.
    c = dict(DEFAULTS)
    c.update((hub.state.system_state.get("global_config", {}) or {}).get("key_vault", {}) or {})
    return c


def save_config(hub, cfg: dict) -> None:
    """Store the Key Vault settings in global config and mark state for saving."""
    gc = hub.state.system_state.get("global_config", {})
    gc["key_vault"] = cfg
    hub.state.system_state["global_config"] = gc
    hub.state._mark_dirty()


def admin_uid(hub) -> Optional[str]:
    """Return the user id of the protected local admin (or the first user as a fallback)."""
    # Look through users for the protected admin account.
    users = hub.state.system_state.get("users", {}) or {}
    for uid, u in users.items():
        if isinstance(u, dict) and u.get("protected"):
            return uid
    # No protected user: return the first user id, or None if there are none.
    return next(iter(users), None)


def build_min_backup(hub) -> bytes:
    """Bootstrap bundle: enough to bring a fresh hub online (Azure connection +
    logins + Fernet key + a pointer to the real backup source). NOT the full
    config (that's >25 KB — it lives in the backup source)."""
    # Imported lazily: OIDC config lookup and private-key loading (may be encrypted at rest).
    from security.oidc import get_oidc_config
    from security.credential_store import resolve_private_key_material
    # Shortcuts to hub state, global config and the OIDC settings.
    ss = hub.state.system_state
    gc = ss.get("global_config", {}) or {}
    oidc_cfg = get_oidc_config(hub)

    def _read(p):
        """Load private-key material from a path, returning "" when missing or unreadable."""
        try:
            # Decode the key bytes to text, or "" when the path is empty.
            b = resolve_private_key_material(p) if p else None
            return b.decode() if b else ""
        except Exception:  # noqa: BLE001
            # Unreadable key: leave it out of the bundle rather than failing the backup.
            return ""

    def _read_file(p):
        """Read a plain text file, returning "" when it cannot be read."""
        try:
            with open(p, "r") as f:
                return f.read()
        except Exception:  # noqa: BLE001
            # Missing or unreadable file: return empty text.
            return ""

    # Hub Local mTLS CA (mints the fleet's clientAuth client certs). DR-critical:
    # without it a rebuilt hub can't verify ANY spoke's mTLS cert until every spoke
    # is re-provisioned, and AppBuilder's HUB_REQUEST channel stays dead. Escrow the
    # cert + key so a restore re-establishes the same CA.
    _mtls_ca_cert = _mtls_ca_key = ""
    # Read the mTLS CA cert and key (key may be encrypted, so try the key loader first).
    try:
        from security import mtls_ca as _mca
        _mtls_ca_cert = _read_file(_mca.CA_CERT_PATH)
        _mtls_ca_key = _read(_mca.CA_KEY_PATH) or _read_file(_mca.CA_KEY_PATH)
    except Exception:  # noqa: BLE001
        # mTLS CA not present on this hub: leave those fields empty.
        pass

    # Assemble the bootstrap bundle.
    bundle = {
        "kind": "lm-min-backup", "version": 1,
        "created": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "users": ss.get("users", {}),
        "permission_groups": ss.get("permission_groups", {}),
        # Azure connection + the backup SOURCE (self_backup = where the full
        # backup lives), so a recovered hub can call home to Azure, let admins
        # in, and knows where to pull the real backup from.
        "global_config": {k: gc.get(k) for k in
                          ("oidc", "key_vault", "azure_nsg", "cloud_nac", "self_backup") if k in gc},
        "tenants": (ss.get("tenant_state", {}) or {}).get("tenants", {}),
        "oidc_cert_pem": _read(getattr(oidc_cfg, "cert_path", "")),
        "oidc_key_pem": _read(getattr(oidc_cfg, "key_path", "")),
        "mtls_ca_cert_pem": _mtls_ca_cert,
        "mtls_ca_key_pem": _mtls_ca_key,
        "fernet_key": _primary_fernet_key(),
    }
    # Serialise to JSON bytes.
    return _json.dumps(bundle).encode()


async def do_rotate_admin(hub) -> Dict[str, Any]:
    """Rotate the local admin password → push to the vault FIRST → then set the
    local hash + invalidate sessions. Break-glass: after this the password lives
    only in the vault. Raises KeyVaultError on vault failure (no local change)."""
    # Imported lazily to avoid a circular import with api.
    from api import _hash_password, _invalidate_user_sessions
    from security.oidc import get_oidc_config
    # Need a configured vault URL and a local admin account.
    cfg = get_config(hub)
    if not cfg.get("vault_url"):
        raise KeyVaultError("Key Vault URL not configured")
    uid = admin_uid(hub)
    if not uid:
        raise KeyVaultError("no local admin account found")
    # Generate the new password and store it in the vault first (no local change on failure).
    pw = gen_password()
    await set_secret(get_oidc_config(hub), cfg["vault_url"], cfg["admin_secret"], pw)
    # Then update the local password hash and timestamps.
    hub.state.system_state["users"][uid]["password_hash"] = _hash_password(pw)
    hub.state.system_state["users"][uid]["updated_at"] = _time.time()
    # Record when rotation happened so the scheduler knows when to rotate next.
    cfg["last_rotate"] = _dt.datetime.now(_dt.timezone.utc).isoformat()
    save_config(hub, cfg)
    # Log out existing sessions for the admin; failure is only logged.
    try:
        _invalidate_user_sessions(hub, uid)
    except Exception as e:  # noqa: BLE001
        logger.warning("Key Vault: session invalidation for '%s' failed: %s", uid, e)
    logger.info("Key Vault: rotated admin '%s' password → secret '%s'", uid, cfg["admin_secret"])
    return {"admin_user": uid, "secret": cfg["admin_secret"]}


async def do_push_fernet(hub) -> Dict[str, Any]:
    """Store the hub's Fernet key in the vault so encrypted backups can be decrypted after a rebuild.
    """
    from security.oidc import get_oidc_config
    # Read settings and the current Fernet key; refuse if no key is available.
    cfg = get_config(hub)
    fk = _primary_fernet_key().strip()
    if not fk:
        raise KeyVaultError("LM_FERNET_KEY is not set in the hub environment")
    # Push the key to its configured secret name.
    await set_secret(get_oidc_config(hub), cfg["vault_url"], cfg["fernet_secret"], fk)
    return {"secret": cfg["fernet_secret"]}


async def do_backup_min(hub) -> Dict[str, Any]:
    """Push a min backup as ``<prefix><YYYYMMDD>`` and prune to the newest
    ``retain`` daily copies."""
    # Imported lazily to avoid a circular import.
    from security.oidc import get_oidc_config
    # A vault URL is required.
    cfg = get_config(hub)
    if not cfg.get("vault_url"):
        raise KeyVaultError("Key Vault URL not configured")
    # Build and encode the bundle (raises if it is too large).
    oidc = get_oidc_config(hub)
    blob = encode_config_secret(build_min_backup(hub))
    # Name the secret by today's UTC date so each day has one copy.
    day = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%d")
    name = f"{cfg['backup_prefix']}{day}"
    # Store today's copy.
    await set_secret(oidc, cfg["vault_url"], name, blob)
    # List all backup copies (date names sort chronologically).
    names = sorted(await list_secret_names(oidc, cfg["vault_url"], prefix=cfg["backup_prefix"]))
    # Keep at least one, and the newest "retain" copies.
    retain = max(1, int(cfg.get("retain", 7) or 7))
    pruned = names[:-retain] if len(names) > retain else []
    # Delete everything older than the retention window.
    for old in pruned:
        await delete_secret(oidc, cfg["vault_url"], old)
    # Record when the backup ran and save settings.
    cfg["last_backup"] = _dt.datetime.now(_dt.timezone.utc).isoformat()
    save_config(hub, cfg)
    logger.info("Key Vault: min backup '%s' pushed (%d bytes), pruned %d old", name, len(blob), len(pruned))
    return {"secret": name, "size": len(blob), "pruned": pruned}


def apply_min_backup(hub, bundle: dict) -> Dict[str, Any]:
    """Restore a min bootstrap bundle onto THIS hub: replace users, permission
    groups, the bootstrap global_config subset and tenants, and write the OIDC
    cert/key back to disk so SSO/Azure work again. Returns a summary including
    the Fernet key + the backup-source pointer so the operator can then pull the
    full backup. Does NOT swap LM_FERNET_KEY (that's an env var / process-level)."""
    # Refuse anything that is not a min backup bundle.
    if not isinstance(bundle, dict) or bundle.get("kind") != "lm-min-backup":
        raise KeyVaultError("not a Lab Manager min backup (missing kind=lm-min-backup)")
    # Imported lazily for the OIDC cert/key paths.
    from security.oidc import get_oidc_config
    ss = hub.state.system_state
    # Replace users and permission groups when present.
    if isinstance(bundle.get("users"), dict):
        ss["users"] = bundle["users"]
    if isinstance(bundle.get("permission_groups"), dict):
        ss["permission_groups"] = bundle["permission_groups"]
    # Overlay the saved global_config subset onto the current config.
    gc = ss.setdefault("global_config", {})
    for k, v in (bundle.get("global_config") or {}).items():
        gc[k] = v
    # Replace the tenant list when present.
    if isinstance(bundle.get("tenants"), dict):
        ts = ss.setdefault("tenant_state", {})
        ts["tenants"] = bundle["tenants"]
    # Paths of cert/key files written back to disk.
    wrote = []
    oidc_cfg = get_oidc_config(hub)
    # Write the OIDC cert and key back to their configured paths.
    for pem_key, path_attr in (("oidc_cert_pem", "cert_path"), ("oidc_key_pem", "key_path")):
        pem = bundle.get(pem_key)
        path = getattr(oidc_cfg, path_attr, "")
        if pem and path:
            # Create the directory and write the PEM; the key file is owner-only.
            try:
                _os.makedirs(_os.path.dirname(path), exist_ok=True)
                with open(path, "w") as f:
                    f.write(pem)
                if path_attr == "key_path":
                    _os.chmod(path, 0o600)
                wrote.append(path)
            except Exception as e:  # noqa: BLE001
                # A failed write is logged; the rest of the restore continues.
                logger.warning("Key Vault restore: could not write %s: %s", path, e)
    # Restore the Hub Local mTLS CA so the rebuilt hub keeps issuing/verifying the
    # fleet's clientAuth certs without re-provisioning every spoke.
    try:
        # Write the CA cert (world-readable) and key (owner-only) back to their paths.
        from security import mtls_ca as _mca
        for pem_key, path, mode in (("mtls_ca_cert_pem", _mca.CA_CERT_PATH, 0o644),
                                    ("mtls_ca_key_pem", _mca.CA_KEY_PATH, 0o600)):
            pem = bundle.get(pem_key)
            if pem and path:
                _os.makedirs(_os.path.dirname(path), exist_ok=True)
                with open(path, "w") as f:
                    f.write(pem)
                # Tighten permissions; ignore filesystems that do not support chmod.
                try:
                    _os.chmod(path, mode)
                except OSError:
                    pass
                wrote.append(path)
    except Exception as e:  # noqa: BLE001
        # A failed CA write is logged; the rest of the restore continues.
        logger.warning("Key Vault restore: could not write mTLS CA: %s", e)
    # Persist the restored state immediately.
    hub.state.save_state()
    logger.info("Key Vault: restored min backup (users=%d, wrote %d cert files)",
                len(bundle.get("users", {}) or {}), len(wrote))
    # Pointer to where the full backup lives, returned so the operator can fetch it.
    self_backup = (bundle.get("global_config") or {}).get("self_backup") or {}
    # Summary for the operator, including the Fernet key needed to decrypt the full backup.
    return {
        "users": len(bundle.get("users", {}) or {}),
        "permission_groups": len(bundle.get("permission_groups", {}) or {}),
        "tenants": len(bundle.get("tenants", {}) or {}),
        "cert_files": wrote,
        "fernet_key_present": bool(bundle.get("fernet_key")),
        "fernet_key": bundle.get("fernet_key", ""),
        "backup_source": {k: self_backup.get(k) for k in
                          ("ssh_host", "ssh_user", "ssh_path", "ssh_port")
                          if k in self_backup},
        "created": bundle.get("created", ""),
    }


def _iso_age_days(iso: str) -> float:
    """Days since an ISO timestamp; a large number if unparseable/empty."""
    # Empty timestamp counts as "very old" so the action runs.
    if not iso:
        return 1e9
    # Parse the timestamp, assuming UTC when no zone is given.
    try:
        t = _dt.datetime.fromisoformat(iso)
        if t.tzinfo is None:
            t = t.replace(tzinfo=_dt.timezone.utc)
        # Convert the elapsed seconds into days.
        return (_dt.datetime.now(_dt.timezone.utc) - t).total_seconds() / 86400.0
    except Exception:  # noqa: BLE001
        # Unparseable timestamp counts as "very old".
        return 1e9


class KeyVaultSchedulerMixin:
    """Drives the DR automation: rotate the admin password every ``rotate_days``
    and push a min backup daily. Mixed into the hub; started from startup."""

    async def run_key_vault_loop(self):
        """Background loop: rotate the admin password and push daily min backups when due."""
        # Stagger well past boot syncs; the cadence is day-scale so a ~10 min
        # poll is plenty responsive to a config change.
        await __import__("asyncio").sleep(180)
        # asyncio imported inline (this module does not import it at top level).
        asyncio = __import__("asyncio")
        # Run forever; each pass checks whether rotation or backup is due.
        while True:
            try:
                # Re-read settings each pass so changes take effect without restart.
                cfg = get_config(self)
                # Disabled or no vault: check again in 10 minutes.
                if not cfg.get("enabled", False) or not cfg.get("vault_url"):
                    await asyncio.sleep(600)
                    continue
                # Rotate the admin password once it is at least rotate_days old.
                rotate_days = max(1, int(cfg.get("rotate_days", 7) or 7))
                if _iso_age_days(cfg.get("last_rotate", "")) >= rotate_days:
                    try:
                        await do_rotate_admin(self)
                    except Exception as e:  # noqa: BLE001
                        # A failed rotation is logged and retried on a later pass.
                        logger.warning("Key Vault: scheduled admin rotation failed: %s", e)
                # Daily min backup (the prefix carries a per-day name, so a repeat
                # within the same day just overwrites that day's secret).
                if _iso_age_days(cfg.get("last_backup", "")) >= 1.0:
                    try:
                        await do_backup_min(self)
                    except Exception as e:  # noqa: BLE001
                        # A failed backup is logged and retried on a later pass.
                        logger.warning("Key Vault: scheduled min backup failed: %s", e)
                # Wait 10 minutes before the next check.
                await asyncio.sleep(600)
            except Exception as e:  # noqa: BLE001
                # Unexpected failure: log and retry sooner.
                logger.warning("[sync-error] key-vault loop cycle failed: %s", e)
                await asyncio.sleep(120)
