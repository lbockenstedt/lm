"""Per-certificate tenant ownership + shared-tenant deploy authorization (LE).

A managed certificate carries an explicit list of **owning tenant ids**, stored
hub-side in ``global_config['le_cert_tenants'][domain]`` (secret-free, durable —
mirrors ``le_vault_dns_creds``). Semantics:

* **Auto-assign on create.** When a cert is issued, the creator's current
  (logged-in) tenant is added as an owner.
* **Owner may change; never removes self.** An *owner* — a Global Admin, or a
  user one of whose tenants is on the cert — may CHANGE the cert (renew / revoke /
  targets / the tenant list itself). A non-admin owner may add other tenants but
  may **never remove their own tenant** from a cert they own.
* **Shared-tenant certs deploy anywhere (own devices), but are read-only.** A
  cert whose owner list includes the **shared tenant** is DEPLOYABLE by any user
  to a device in *their own* tenant, but such a user may **not** change it.
* **Legacy certs are not newly restricted.** A cert with no explicit owners
  (issued before this feature) keeps its pre-feature behavior: change ops stay
  governed by the module's existing DNS-subnet view filter, and visibility falls
  back to that filter (``visible_to`` returns ``None`` to signal "defer").

All functions are pure helpers over ``(hub, sess, domain)`` so they can be unit
tested with a fake hub + monkeypatched ``access``; ``net_services`` wires thin
route closures onto them.
"""
import access

STORE_KEY = "le_cert_tenants"


def _global_config(hub):
    return hub.state.system_state.setdefault("global_config", {})


def get_tenants(hub, domain):
    """The cleaned, de-duplicated owner-tenant id list for ``domain`` (possibly
    empty). Order-stable."""
    m = (hub.state.system_state.get("global_config", {}) or {}).get(STORE_KEY) or {}
    v = m.get(domain)
    if not isinstance(v, list):
        return []
    out = []
    for t in v:
        if isinstance(t, str) and t.strip() and t.strip() not in out:
            out.append(t.strip())
    return out


def set_tenants(hub, domain, tenants):
    """Persist ``domain``'s owner list (cleaned/deduped). An empty list removes
    the entry entirely. Returns the stored list."""
    m = _global_config(hub).setdefault(STORE_KEY, {})
    clean = []
    for t in tenants or []:
        t = t.strip() if isinstance(t, str) else ""
        if t and t not in clean:
            clean.append(t)
    if clean:
        m[domain] = clean
    else:
        m.pop(domain, None)
    return clean


def add_tenant(hub, domain, tid):
    """Add ``tid`` as an owner of ``domain`` (idempotent). Returns the list."""
    tid = (tid or "").strip() if isinstance(tid, str) else ""
    if not (domain and tid):
        return get_tenants(hub, domain)
    cur = get_tenants(hub, domain)
    if tid not in cur:
        cur.append(tid)
        set_tenants(hub, domain, cur)
    return cur


def forget(hub, domain):
    """Drop all ownership for ``domain`` (e.g. on revoke). Returns True if any
    entry was removed."""
    m = (hub.state.system_state.get("global_config", {}) or {}).get(STORE_KEY)
    if isinstance(m, dict) and domain in m:
        m.pop(domain, None)
        return True
    return False


def user_tenants(sess):
    """The tenant ids the session user belongs to."""
    return [t for t in ((sess or {}).get("user", {}).get("tenants") or [])
            if isinstance(t, str) and t]


def current_tenant(sess):
    """The user's active/primary tenant id ("myself" — the one auto-assigned on
    create and never removable)."""
    u = (sess or {}).get("user", {}) or {}
    tid = u.get("tenant_id")
    if isinstance(tid, str) and tid.strip():
        return tid.strip()
    mine = user_tenants(sess)
    return mine[0] if mine else "default"


def has_owners(hub, domain):
    return bool(get_tenants(hub, domain))


def is_shared(hub, domain):
    """True when the shared tenant is one of the cert's owners → deployable by
    any user to their own devices."""
    sid = access.shared_tenant_id()
    return bool(sid) and sid in get_tenants(hub, domain)


def is_owner(hub, sess, domain):
    """True if the session may CHANGE the cert by virtue of ownership: a Global
    Admin, or a user one of whose tenants is explicitly on the cert."""
    if access.is_admin(sess):
        return True
    return bool(set(get_tenants(hub, domain)) & set(user_tenants(sess)))


def visible_to(hub, sess, domain, want_tenants, admin_all=True):
    """Explicit-ownership visibility test for the cert list.

    Returns ``True`` / ``False`` when the cert HAS explicit owners (visible to an
    owner whose tenant intersects ``want_tenants``, to anyone when shared, or —
    when ``admin_all`` — to any Global Admin). Returns ``None`` when the cert has
    NO explicit owners, signalling the caller to fall back to the legacy
    DNS-subnet match.

    ``admin_all`` (default True) grants a Global Admin the see-everything pass.
    The cert-list filter turns it OFF when the caller has selected an EXPLICIT
    tenant (the tenant picker): in that case even an admin is scoped to the
    picked tenant — matching the ``nw``/``ipam``/``firewall`` modules — so an
    admin viewing tenant LRB does NOT see certs owned solely by ``default`` or
    another tenant."""
    owners = get_tenants(hub, domain)
    if not owners:
        return None
    if admin_all and access.is_admin(sess):
        return True
    if set(owners) & set(want_tenants or []):
        return True
    sid = access.shared_tenant_id()
    return bool(sid and sid in owners)


def can_change(hub, sess, domain):
    """Owner-or-admin gate for change ops (renew / revoke / targets / tenant
    list). A legacy cert with no explicit owners is NOT newly restricted (returns
    True) so pre-feature workflows keep working."""
    if access.is_admin(sess):
        return True
    if not has_owners(hub, domain):
        return True
    return bool(set(get_tenants(hub, domain)) & set(user_tenants(sess)))


def can_deploy(hub, sess, domain, device_tenant):
    """May the session deploy this cert to a device owned by ``device_tenant``?

    Admin or an owner may deploy (owner deploy is unchanged from before). A
    non-owner may deploy ONLY a shared cert, and ONLY to a device in one of their
    own tenants."""
    if access.is_admin(sess):
        return True
    if is_owner(hub, sess, domain):
        return True
    return bool(is_shared(hub, domain) and device_tenant
                and device_tenant in user_tenants(sess))


def meta(hub, sess, domain):
    """UI/tagging metadata for a cert: its owner list + the caller's rights."""
    return {
        "tenants": get_tenants(hub, domain),
        "shared": is_shared(hub, domain),
        "owned": is_owner(hub, sess, domain),
        "can_edit": can_change(hub, sess, domain),
    }


class TenantEditError(ValueError):
    """Raised by :func:`validate_tenant_edit` for a rejected tenant-list edit."""


def validate_tenant_edit(hub, sess, domain, new_tenants, tenant_exists):
    """Validate + normalize a requested new owner list, returning the list to
    store. Raises :class:`TenantEditError` when:

    * a requested tenant does not exist (``tenant_exists(tid)`` is falsy), or
    * a non-admin caller would drop their OWN tenant (their active tenant must
      remain, and no currently-owned tenant of theirs may be removed).

    Admins may set any existing-tenant list, including removing themselves."""
    clean = []
    for t in new_tenants or []:
        t = t.strip() if isinstance(t, str) else ""
        if not t:
            continue
        if not tenant_exists(t):
            raise TenantEditError(f"unknown tenant '{t}'")
        if t not in clean:
            clean.append(t)
    if not access.is_admin(sess):
        mine = set(user_tenants(sess))
        cur = set(get_tenants(hub, domain))
        if (cur & mine) - set(clean):
            raise TenantEditError(
                "You cannot remove your own tenant from a certificate you own.")
        if current_tenant(sess) not in clean:
            raise TenantEditError(
                "You cannot remove your own tenant from a certificate you own.")
    return clean
