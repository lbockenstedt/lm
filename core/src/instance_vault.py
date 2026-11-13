"""Per-instance Credential Vault linkage for module connection secrets.

Network-device (``nw_devices``), NAC/ClearPass (``nac_instances``) and
NetBox/IPAM (``ipam_instances``) records may carry a **non-secret**
``vault_credential`` = ``{"bucket": ..., "name": ...}`` reference INSTEAD of an
inline plaintext secret (client secret / device password / NetBox API token).
The hub resolves the secret VALUE unattended via
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
# copy makes deep copies so the stored record is never mutated with secrets.
import copy
# logging reports vault resolve failures.
import logging

# HTTPException turns validation failures into API error responses.
from fastapi import HTTPException

# cred_vault resolves vault references to secret values and reports vault availability.
import cred_vault

# Module-level logger named after this module.
logger = logging.getLogger(__name__)


# Per-storage-key map of the record's SECRET fields → the resolved-value field
# names each may be pulled from (first non-empty wins). NON-secret fields (host,
# client_id, url, user, address, port, …) always stay inline on the record and
# are never sourced from the vault. Keyed by the ``global_config`` list name.
SECRET_FIELDS = {
    # External syslog archive (Syslog -> Settings -> Archive): the read-only
    # API password for an external Graylog. One record per tenant.
    "syslog_archive": {
        "password": ("password", "secret", "token"),
    },
    "nac_instances": {
        # A ClearPass connection authenticates EITHER as an OAuth2 API client
        # (client_id + client_secret, grant_type=client_credentials) OR with a
        # username/password fallback login (grant_type=password). A vault
        # "Login" secret marked as an OAuth account (Credential Vault checkbox)
        # carries client_secret; a plain login carries user/username + password.
        # Only the field(s) the resolved secret actually carries are overlaid, so
        # the spoke picks the grant from what is present. client_id is NON-secret
        # and is overlaid via NONSECRET_VAULT_FIELDS (below) — not stripped here —
        # so a Credential Vault "OAuth account" secret can supply it too.
        "client_secret": ("client_secret", "secret", "apikey", "api_key", "token"),
        "user":          ("user", "username"),
        "password":      ("password", "fallback_password"),
    },
    "ipam_instances": {
        # A NetBox (IPAM) connection authenticates with a single API token. The
        # token may be stored as a Credential Vault "Token" secret ({token}),
        # an "API key" secret ({apikey}), or a "Generic" key/value secret — so
        # accept the same aliases as the nw_devices REST token below. The
        # NetBox URL + verify_ssl are NON-secret and always stay inline on the
        # record. Mirrors the ipam_instances projection in nw.py/tenant_devices.py
        # (record field `api_token`).
        "api_token": ("api_token", "token", "apikey", "api_key", "key", "value"),
    },
    "firewalls": {
        # OPNsense (and future models) authenticate with a REST API key +
        # secret pair. Store them as a Credential Vault "Generic" secret
        # ({api_key, api_secret}) or reuse a "Login" secret (username/password
        # map onto key/secret) — only the field(s) the resolved secret actually
        # carries are overlaid. Host/port/model stay inline (non-secret).
        "api_key":    ("api_key", "username", "key", "apikey"),
        "api_secret": ("api_secret", "password", "secret", "token"),
    },
    "truenas_appliances": {
        # A TrueNAS appliance authenticates with a single API key (plus the
        # non-secret key-owner username that stays inline). Store it as a
        # Credential Vault "API key" ({apikey}), "Token" ({token}) or "Generic"
        # secret.
        "api_key": ("api_key", "apikey", "token", "key", "value", "password"),
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
    "nw_scan_credentials": {
        # A per-tenant network-scan credential set: the candidate SSH login
        # password + enable secret + SNMP community the fingerprint scanner
        # tries against discovered IPs. Same secret aliases as nw_devices so a
        # Credential Vault "Console"/"Generic" secret supplies the password and a
        # separate community can be typed inline or vaulted.
        "password":       ("password", "secret", "apikey", "api_key", "key", "value"),
        "enable_secret":  ("enable_secret", "enable", "enable_password"),
        "snmp_community": ("snmp_community", "community"),
    },
}


# Per-storage-key map of NON-secret fields that a vault credential MAY also
# carry and that should be overlaid from it when present. Unlike SECRET_FIELDS
# these fields are NOT stripped from the inline record on save (they are not
# secrets) — the inline value is preserved and only *overridden* when the
# resolved vault secret actually provides the field. This lets a Credential
# Vault "OAuth account" secret supply BOTH client_id and client_secret for a
# ClearPass API client (grant_type=client_credentials needs both) even though
# client_id itself is not a secret. When the referenced secret is a plain
# username/password login (no client_id), the inline client_id is kept as-is.
# Products whose connection only works with a secret: once the hub's cloud
# vault is available, a record must reference a vault credential.
VAULT_REQUIRED = {"firewalls", "truenas_appliances"}


NONSECRET_VAULT_FIELDS = {
    "nac_instances": {
        "client_id": ("client_id", "clientid", "client"),
    },
    "nw_devices": {
        # A network device's SSH/CLI login username lives WITH the password in a
        # Credential Vault "Console" secret ({username, password}). It is not a
        # secret, so it is overlaid here (not stripped inline on save): a
        # manually-typed username is preserved and only overridden when the
        # resolved vault credential actually carries one. Without this, a
        # vault-backed SSH device gets its password but an empty username, and
        # every poll fails with "device address/username not configured".
        "username": ("username", "user"),
    },
    "nw_scan_credentials": {
        # The scan credential set's SSH login username — same rationale as
        # nw_devices: overlaid (not stripped) so a vault "Console" secret can
        # supply both username + password for the scanner.
        "username": ("username", "user"),
    },
}


def secret_field_names(storage_key):
    """The record fields that a vault credential may supply for this product."""
    # The secret field names configured for this product (empty for unknown products).
    return tuple((SECRET_FIELDS.get(storage_key) or {}).keys())


def _vault_overlay_fields(storage_key):
    """Merged map of all fields (secret + non-secret) that may be overlaid from
    a resolved vault secret for this product."""
    # Start from the secret fields, then add the non-secret overlay fields.
    merged = dict(SECRET_FIELDS.get(storage_key) or {})
    merged.update(NONSECRET_VAULT_FIELDS.get(storage_key) or {})
    return merged


def _normalize_ref(record):
    """Return a clean ``{"bucket","name"}`` dict for the record's
    ``vault_credential`` reference, or ``None`` when absent/blank."""
    # Read the reference; anything other than a dict is not a reference.
    ref = (record or {}).get("vault_credential")
    if not isinstance(ref, dict):
        return None
    # Both bucket and name must be non-blank.
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
    # Only a dict value can carry fields.
    if not isinstance(value, dict):
        return None
    # Return the first alias holding a non-blank string.
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
    # Without a reference there is nothing to strip.
    if not has_vault_ref(record):
        return record
    # Store the cleaned reference and drop every inline secret field.
    record["vault_credential"] = _normalize_ref(record)
    for f in secret_field_names(storage_key):
        record.pop(f, None)
    return record


async def resolve_value(hub, record):
    """Resolve the record's referenced vault secret to its value dict, or
    ``None`` when the record carries no reference. Raises nothing on a resolve
    failure — returns ``None`` and logs — so a transient vault miss degrades to
    'push whatever inline remains' rather than crashing the push loop."""
    # No reference means nothing to resolve.
    ref = _normalize_ref(record)
    if ref is None:
        return None
    # Fetch the secret value unattended from the vault.
    try:
        return await cred_vault.automation_get(hub, ref["bucket"], ref["name"])
    except Exception as e:  # noqa: BLE001 — vault/network/decrypt
        # Any vault, network or decryption failure is logged and treated as "no value".
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
    # No reference: return the record untouched (no copy, no vault call).
    if not has_vault_ref(record):
        return record
    # Resolve the secret and work on a copy with the vault marker removed.
    value = await resolve_value(hub, record)
    out = copy.deepcopy(record)
    out.pop("vault_credential", None)
    # Overlay each mapped field the resolved secret actually provides.
    if isinstance(value, dict):
        for field, aliases in _vault_overlay_fields(storage_key).items():
            got = _extract(value, aliases)
            if got:
                out[field] = got
    return out


async def overlay_many(hub, records, storage_key):
    """:func:`overlay` for a list of records (e.g. an nw fleet slice)."""
    # Overlay each dict record in turn; non-dict entries pass through unchanged.
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

    When NO reference is present, also enforces the operator's vault-only
    policy: once a cloud vault is configured for this hub, a record must not
    carry one of its secret fields inline — see :func:`_vault_only_violation`.
    This mirrors the console module's pre-existing ``_vault_enabled`` gate
    (routes/console.py) so the same "vault enabled → no local secrets" rule
    applies uniformly across every vault-integrated product.

    Raises :class:`fastapi.HTTPException` on failure; returns ``None`` (and does
    nothing further) when the record carries no reference and no violation."""
    # The product's vault-backed secret fields; none means nothing to validate.
    spec = SECRET_FIELDS.get(storage_key) or {}
    if not spec:
        return  # product has no vault-backed secret fields — nothing to validate
    # Records without a reference only need the vault-only policy checks.
    ref = _normalize_ref(record)
    if ref is None:
        # Products that require a vault reference reject records without one.
        if storage_key in VAULT_REQUIRED and cred_vault._vault_available(hub):
            raise HTTPException(
                status_code=400,
                detail="Credential Vault is enabled for this hub — select a Credential "
                       "Vault credential (e.g. an 'API key + secret' secret) for this "
                       "connection.")
        # Reject inline secrets while the vault is available.
        if _vault_only_violation(hub, record, spec):
            raise HTTPException(
                status_code=400,
                detail="Credential Vault is enabled for this hub — save this secret "
                       "as a Credential Vault reference (select it from the vault) "
                       "instead of entering it inline. Locally-stored secrets are "
                       "not permitted while the vault is available.")
        return
    # Non-admins may only reference buckets of their own tenants (404 hides existence).
    if not is_admin:
        reach = set((sess or {}).get("user", {}).get("tenants") or [])
        if ref["bucket"] not in reach:
            raise HTTPException(status_code=404, detail="vault credential not found")
    # The reference must resolve to an automation-readable secret.
    try:
        value = await cred_vault.automation_get(hub, ref["bucket"], ref["name"])
    except Exception as e:  # noqa: BLE001 — vault/network/decrypt
        # Report resolve failures as "not found" so details of other buckets are not leaked.
        raise HTTPException(status_code=404,
                            detail=f"vault credential not found or not "
                                   f"automation-readable: {e}")
    # The secret must carry at least one field this product can use.
    if not any(_extract(value, aliases) for aliases in spec.values()):
        raise HTTPException(
            status_code=400,
            detail="the selected Credential Vault secret carries no usable "
                   "field for this connection (expected one of: "
                   + ", ".join(sorted({a for al in spec.values() for a in al})) + ")")


def _vault_only_violation(hub, record, spec) -> bool:
    """True when the hub's cloud vault is available, this product has
    vault-backed secret fields, and ``record`` carries a non-empty value in one
    of them WITHOUT a ``vault_credential`` reference — i.e. an inline/local
    secret being saved while the operator directive says it must come from the
    vault instead."""
    # No vault configured means inline secrets are allowed.
    if not cred_vault._vault_available(hub):
        return False
    # Violation if any secret field has an inline value.
    return any(record.get(field) for field in spec)

