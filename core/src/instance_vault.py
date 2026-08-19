"""Per-instance Credential Vault linkage for module connection secrets.

Network-device (``nw_devices``) and NAC/ClearPass (``nac_instances``) records
may carry a **non-secret** ``vault_credential`` = ``{"bucket": ..., "name": ...}``
reference INSTEAD of an inline plaintext secret (client secret / device
password / API token). The hub resolves the secret VALUE unattended via
:func:`cred_vault.automation_get` and overlays it onto the config **only at the
moment it is pushed to the bound spoke**, so:

* the plaintext secret is never persisted in ``global_config`` (only the
  ``{bucket, name}`` reference is stored), and
* it is never returned to the browser by the ``list`` endpoints.

This mirrors the LE / HE.NET vault pattern
(``net_services._henet_resolve_vault_cred``): a module stores a reference and
resolves the value on demand. The spoke still receives the resolved secret (it
must, to authenticate to ClearPass / the device) — the vault simply keeps the
plaintext out of the hub's on-disk config.

Backward-compatible by construction: when a record has **no** ``vault_credential``
every helper here is a no-op and the inline fields flow exactly as before.
"""
import copy
import logging

from fastapi import HTTPException

import cred_vault

logger = logging.getLogger(__name__)


# Per-storage-key map of the record's SECRET fields → the resolved-value field
# names each may be pulled from (first non-empty wins). NON-secret fields (host,
# url, address, port, …) always stay inline on the record and are never sourced
# from the vault. The one exception is ``nac_instances["client_id"]``: an
# OAuth2 vault secret stores client_id + client_secret as one identity, so
# client_id is sourced from the vault there too (see below). Keyed by the
# ``global_config`` list name.
SECRET_FIELDS = {
    "nac_instances": {
        # A ClearPass connection authenticates EITHER as an OAuth2 API client
        # (client_id + client_secret, grant_type=client_credentials) OR with a
        # username/password fallback login (grant_type=password). A vault
        # "Login" secret marked as an OAuth account (Credential Vault checkbox)
        # carries client_id + client_secret together; a plain login carries
        # user/username + password. Only the field(s) the resolved secret
        # actually carries are overlaid, so the spoke picks the grant from
        # what is present. client_id IS sourced from the vault like the
        # other fields here (an OAuth secret is one identity — id and secret
        # travel together): it is stripped from the inline record at save
        # time and re-filled from the vault at push time, same as
        # client_secret below.
        "client_id":     ("client_id", "clientid"),
        "client_secret": ("client_secret", "secret", "apikey", "api_key", "token"),
        "user":          ("user", "username"),
        "password":      ("password", "fallback_password"),
    },
    "nw_devices": {
        # Network-device login password / enable secret / REST token / SNMP
        # community — a device uses whichever its transport needs; only the
        # field(s) the resolved secret actually carries are overlaid.
        "password":       ("password", "secret", "apikey", "api_key", "key", "value"),
        "enable_secret":  ("enable_secret", "enable", "enable_password"),
        "api_token":      ("api_token", "token", "apikey", "api_key", "key", "value"),
        "snmp_community": ("snmp_community", "community"),
    },
}


def secret_field_names(storage_key):
    """The record fields that a vault credential may supply for this product."""
    return tuple((SECRET_FIELDS.get(storage_key) or {}).keys())


def _normalize_ref(record):
    """Return a clean ``{"bucket","name"}`` dict for the record's
    ``vault_credential`` reference, or ``None`` when absent/blank."""
    ref = (record or {}).get("vault_credential")
    if not isinstance(ref, dict):
        return None
    bucket = (ref.get("bucket") or "").strip()
    name = (ref.get("name") or "").strip()
    if not bucket or not name:
        return None
    return {"bucket": bucket, "name": name}


def has_vault_ref(record):
    """True when the record carries a usable ``vault_credential`` reference."""
    return _normalize_ref(record) is not None


def _extract(value, aliases):
    """Pull the first non-empty string among ``aliases`` from a resolved
    vault-secret ``value`` dict."""
    if not isinstance(value, dict):
        return None
    for a in aliases:
        v = value.get(a)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None


def strip_inline_secrets(record, storage_key):
    """When a ``vault_credential`` is present, drop the inline secret fields so
    the plaintext is never persisted in ``global_config``. Mutates and returns
    ``record``. Non-secret fields and the reference itself are kept. No-op when
    the record has no vault reference (inline secrets stay, as today)."""
    if not has_vault_ref(record):
        return record
    record["vault_credential"] = _normalize_ref(record)
    for f in secret_field_names(storage_key):
        record.pop(f, None)
    return record


async def resolve_value(hub, record):
    """Resolve the record's referenced vault secret to its value dict, or
    ``None`` when the record carries no reference. Raises nothing on a resolve
    failure — returns ``None`` and logs — so a transient vault miss degrades to
    'push whatever inline remains' rather than crashing the push loop."""
    ref = _normalize_ref(record)
    if ref is None:
        return None
    try:
        return await cred_vault.automation_get(hub, ref["bucket"], ref["name"])
    except Exception as e:  # noqa: BLE001 — vault/network/decrypt
        logger.warning("instance_vault: could not resolve %s/%s: %s",
                       ref["bucket"], ref["name"], e)
        return None


async def overlay(hub, record, storage_key):
    """Return the record with its secret fields filled from the vault.

    When the record has no ``vault_credential`` the SAME object is returned
    unchanged (no copy, no vault call). Otherwise a deep copy is returned with
    each mapped secret field set from the resolved value (only fields the secret
    actually carries are overlaid; the ``vault_credential`` marker is dropped
    from the pushed copy so it never reaches the spoke)."""
    if not has_vault_ref(record):
        return record
    value = await resolve_value(hub, record)
    out = copy.deepcopy(record)
    out.pop("vault_credential", None)
    if isinstance(value, dict):
        for field, aliases in (SECRET_FIELDS.get(storage_key) or {}).items():
            got = _extract(value, aliases)
            if got:
                out[field] = got
    return out


async def overlay_many(hub, records, storage_key):
    """:func:`overlay` for a list of records (e.g. an nw fleet slice)."""
    out = []
    for r in records or []:
        out.append(await overlay(hub, r, storage_key) if isinstance(r, dict) else r)
    return out


async def validate_ref(hub, record, sess, *, is_admin, storage_key):
    """Save-time validation of a record's ``vault_credential`` (if any):

    * reach — a non-admin may only reference a bucket for one of their own
      tenants (a mismatch is a 404 so bucket existence never leaks);
    * resolvable — the reference must resolve to an automation-readable secret;
    * usable — the secret must carry at least one field this product can use.

    Raises :class:`fastapi.HTTPException` on failure; returns ``None`` (and does
    nothing) when the record carries no reference."""
    spec = SECRET_FIELDS.get(storage_key) or {}
    if not spec:
        return  # product has no vault-backed secret fields — nothing to validate
    ref = _normalize_ref(record)
    if ref is None:
        return
    if not is_admin:
        reach = set((sess or {}).get("user", {}).get("tenants") or [])
        if ref["bucket"] not in reach:
            raise HTTPException(status_code=404, detail="vault credential not found")
    try:
        value = await cred_vault.automation_get(hub, ref["bucket"], ref["name"])
    except Exception as e:  # noqa: BLE001 — vault/network/decrypt
        raise HTTPException(status_code=404,
                            detail=f"vault credential not found or not "
                                   f"automation-readable: {e}")
    if not any(_extract(value, aliases) for aliases in spec.values()):
        raise HTTPException(
            status_code=400,
            detail="the selected Credential Vault secret carries no usable "
                   "field for this connection (expected one of: "
                   + ", ".join(sorted({a for al in spec.values() for a in al})) + ")")
