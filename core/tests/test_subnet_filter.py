"""Critical path 1/4 — tenant subnet filter (server-side tenant isolation gate).

The toggle ↔ backend ↔ filter read-path wiring is the security boundary that
stops one tenant seeing another's subnet-scoped data. These tests lock in the
resolution semantics of ``access.filter_config`` / ``filter_enabled``
— the single source of truth every server-side filter reads
(``filter_enabled`` → ``filter_config`` → ``system_state["subnet_filter_modules"]``
merged with the defaults). The actual prefix-matching lives in
``simulations/tenant_filter.py`` and is exercised by an integration test (TODO).
"""

import itertools

import pytest

from access import (
    filter_config,
    filter_enabled,
    _FILTER_MODULES,
    _FILTER_DEFAULTS,
)
from _fakes import FakeHub, FakeState


def test_defaults_when_no_stored_state():
    """No stored overrides → every module resolves to its documented default
    (nac/firewall/netbox/dhcp ON, cs OFF — cs is tenant-ID-scoped, not subnet)."""
    hub = FakeHub(FakeState(system_state={}))
    cfg = filter_config(hub)
    assert set(cfg) == set(_FILTER_MODULES)
    for m in _FILTER_MODULES:
        assert cfg[m] == _FILTER_DEFAULTS[m]


def test_stored_override_flips_a_module():
    hub = FakeHub(FakeState(system_state={"subnet_filter_modules": {"cs": True, "firewall": False}}))
    cfg = filter_config(hub)
    assert cfg["cs"] is True           # override ON (default OFF)
    assert cfg["firewall"] is False    # override OFF (default ON)
    # untouched modules keep their defaults
    assert cfg["nac"] is _FILTER_DEFAULTS["nac"]
    assert cfg["netbox"] is _FILTER_DEFAULTS["netbox"]
    assert cfg["dhcp"] is _FILTER_DEFAULTS["dhcp"]


def test_filter_enabled_per_module_and_unknown():
    hub = FakeHub(FakeState(system_state={"subnet_filter_modules": {"dhcp": False}}))
    assert filter_enabled(hub, "dhcp") is False   # overridden off
    assert filter_enabled(hub, "nac") is True      # default on
    assert filter_enabled(hub, "cs") is False      # default off
    assert filter_enabled(hub, "nonexistent") is False  # unknown module → False


def test_stored_values_are_coerced_to_bool():
    """``filter_config`` bool-coerces stored values (the PUT handler
    stores real bools, but the reader must tolerate any JSON-ish value)."""
    hub = FakeHub(FakeState(system_state={"subnet_filter_modules": {"nac": 0, "firewall": 1}}))
    cfg = filter_config(hub)
    assert cfg["nac"] is False
    assert cfg["firewall"] is True


# ── Tenant-aware firewall filter (admin acting as tenant) ─────────────────────
#
# filter_fw is tenant-aware: an admin selecting a tenant via the switcher
# (explicit_tenant) is filtered by THAT tenant's prefixes — previously admins
# bypassed the filter entirely and saw every tenant's firewall data. These lock
# in both halves: explicit tenant → filter (even for admin); no explicit tenant
# → admin bypass preserved (regression guard).

import asyncio
from access import filter_fw, filter_tenant, filter_session


class _FakeRequest:
    """Minimal stand-in for fastapi.Request — only .cookies is read."""
    def __init__(self, cookie):
        self.cookies = {"lm_session": cookie} if cookie else {}


class _PrefixHub(FakeHub):
    """FakeHub with a connected IPAM spoke that returns tenant prefixes."""
    def __init__(self, state):
        super().__init__(state)
        self._ipam_spoke = "ipam-spoke-1"

    def get_spoke_by_type(self, module_type):
        return self._ipam_spoke if module_type == "ipam" else None

    async def request_response(self, spoke_id, command, payload, **kwargs):
        assert spoke_id == self._ipam_spoke
        assert command == "NETBOX_GET_PREFIXES"
        # Prefixes for the requested tenant slug (payload["tenant"]).
        return {"payload": {"data": {"prefixes": [
            {"prefix": "10.20.0.0/16"},
            {"prefix": "192.168.5.0/24"},
        ]}}}


def _admin_session():
    return {"user": {"permissions": {"admin": True}}, "expires": 2 ** 31,
            "tenant_id": None}


def _rules_env():
    return {"rules": [
        {"source": "10.20.0.5", "destination": "8.8.8.8"},  # src in prefix → keep
        {"source": "8.8.8.8", "destination": "1.1.1.1"},    # both outside → drop
        {"source": "any", "destination": "10.20.0.5"},      # dst in prefix → keep (any side doesn't drop)
    ]}


def test_admin_with_explicit_tenant_is_filtered():
    """An admin selecting a tenant (?tenant=acme) gets that tenant's prefixes
    applied to firewall rules — a rule is kept when EITHER side carries an
    address in the tenant's subnets; a wildcard on one side no longer drops it
    (the other side can still qualify it). The both-outside rule drops."""
    hub = _PrefixHub(FakeState(system_state={}, tenants={
        "acme": {"netbox_tenant_slug": "acme"},
    }))
    sessions = {"admin-cookie": _admin_session()}
    req = _FakeRequest("admin-cookie")
    out = asyncio.run(filter_fw(
        hub, sessions, req, _rules_env(), "rules",
        firewall_id=None, explicit_tenant="acme"))
    assert len(out["rules"]) == 2  # src-in-prefix + dst-in-prefix kept; both-outside dropped


def test_admin_without_explicit_tenant_bypasses():
    """Regression guard: an admin with no selected tenant still sees everything
    (the switcher wasn't used) — the legacy admin bypass is preserved."""
    hub = _PrefixHub(FakeState(system_state={}, tenants={
        "acme": {"netbox_tenant_slug": "acme"},
    }))
    sessions = {"admin-cookie": _admin_session()}
    req = _FakeRequest("admin-cookie")
    env = _rules_env()
    out = asyncio.run(filter_fw(
        hub, sessions, req, env, "rules", firewall_id=None))
    assert out is env  # unchanged — all 3 rules visible


def test_aliases_tab_filters_on_content():
    """The aliases tab now filters on its ``content`` IPs (previously skipped as
    "no IP to filter"). An alias whose content is outside the tenant prefixes is
    hidden; one with content inside is kept; a content-less alias is dropped
    (no IP to attribute to a tenant — err on hiding)."""
    hub = _PrefixHub(FakeState(system_state={}, tenants={
        "acme": {"netbox_tenant_slug": "acme"},
    }))
    sessions = {"admin-cookie": _admin_session()}
    req = _FakeRequest("admin-cookie")
    aliases = {"data": [
        {"name": "TENANT_NET", "type": "network", "content": "10.20.0.0/24"},   # in → keep
        {"name": "EXT",        "type": "network", "content": "8.8.8.8"},         # out → drop
        {"name": "EMPTY",      "type": "urltable", "content": ""},               # no IP → drop
    ]}
    out = asyncio.run(filter_fw(
        hub, sessions, req, aliases, "aliases",
        firewall_id=None, explicit_tenant="acme"))
    names = [a["name"] for a in out["data"]]
    assert "TENANT_NET" in names
    assert "EXT" not in names
    assert "EMPTY" not in names


# ── OPNsense category attribution (rules / nat / aliases) ──────────────────────
#
# An OPNsense record whose `category` config field equals the tenant's DISPLAY
# NAME is shown to that tenant regardless of subnet match — an alternate
# attribution path the admin sets explicitly (e.g. an alias with no IP content,
# or a rule whose source/dst are outside the tenant prefix). dhcp/dns/interfaces
# don't carry categories and don't get this path.

def _named_tenant_hub():
    """_PrefixHub whose tenant has a display name ('Acme') — the value that must
    match an OPNsense record's `category` field."""
    return _PrefixHub(FakeState(system_state={}, tenants={
        "acme": {"netbox_tenant_slug": "acme", "name": "Acme"},
    }))


def test_firewall_rule_category_overrides_subnet_drop():
    """An out-of-prefix rule whose category == the tenant display name is kept;
    the same rule with a different (or absent) category is dropped."""
    hub = _named_tenant_hub()
    sessions = {"admin-cookie": _admin_session()}
    req = _FakeRequest("admin-cookie")
    rules = {"rules": [
        {"source": "8.8.8.8", "destination": "1.1.1.1", "category": "Acme"},    # cat match → keep
        {"source": "8.8.8.8", "destination": "1.1.1.1", "category": "Other"},    # drop
        {"source": "8.8.8.8", "destination": "1.1.1.1"},                          # no category → drop
    ]}
    out = asyncio.run(filter_fw(
        hub, sessions, req, rules, "rules", firewall_id=None, explicit_tenant="acme"))
    assert len(out["rules"]) == 1
    assert out["rules"][0]["category"] == "Acme"


def test_alias_category_overrides_no_ip_drop():
    """An alias with no IP content but category == tenant is kept (category
    overrides the drop-no-IP rule); a content-less alias with no/other category
    is dropped; an out-of-prefix alias with the tenant category is kept."""
    hub = _named_tenant_hub()
    sessions = {"admin-cookie": _admin_session()}
    req = _FakeRequest("admin-cookie")
    aliases = {"data": [
        {"name": "OUT_CAT",  "type": "network", "content": "8.8.8.8", "category": "Acme"},  # keep (cat)
        {"name": "EMPTY_CAT", "type": "urltable", "content": "", "category": "Acme"},       # keep (cat, no IP)
        {"name": "NO_CAT",   "type": "urltable", "content": ""},                             # drop (no IP, no cat)
        {"name": "OTHER_CAT", "type": "network", "content": "8.8.8.8", "category": "Other"}, # drop
    ]}
    out = asyncio.run(filter_fw(
        hub, sessions, req, aliases, "aliases", firewall_id=None, explicit_tenant="acme"))
    names = [a["name"] for a in out["data"]]
    assert "OUT_CAT" in names and "EMPTY_CAT" in names
    assert "NO_CAT" not in names and "OTHER_CAT" not in names


def test_category_does_not_leak_to_other_tenant():
    """A record categorized for a different tenant must NOT show just because it
    has a category — only an exact match to THIS tenant's display name keeps it."""
    hub = _named_tenant_hub()
    sessions = {"admin-cookie": _admin_session()}
    req = _FakeRequest("admin-cookie")
    aliases = {"data": [
        {"name": "RIVAL", "type": "urltable", "content": "", "category": "NotAcme"},  # not ours → drop
    ]}
    out = asyncio.run(filter_fw(
        hub, sessions, req, aliases, "aliases", firewall_id=None, explicit_tenant="acme"))
    assert [a["name"] for a in out["data"]] == []


# ── Hypervisor VM filter (tenant-aware, admin acting as tenant) ────────────────
#
# /api/pxmx/vms previously had NO subnet filter at all — an admin saw every
# tenant's VMs. The route now applies filter_tenant (module "hypervisor",
# ip_fields ["ips"]) on all three return paths so an admin selecting a tenant
# sees only that tenant's VMs. The hypervisor filter adds two overrides on top
# of the subnet match: VMs in a configured template pool are visible to ALL
# tenants, and VMs whose Proxmox tag matches the tenant are shown to that
# tenant regardless of subnet. These lock in the base filter, the overrides,
# and the legacy admin bypass when no tenant is selected.

def _vms_env():
    # VM records carry an `ips` list (bare IPv4, no CIDR) — stopped VMs have [].
    return {"vms": [
        {"name": "in-tenant",   "status": "running", "ips": ["10.20.0.5"]},
        {"name": "out-tenant",  "status": "running", "ips": ["8.8.8.8"]},
        {"name": "stopped",     "status": "stopped",  "ips": []},           # no IP → dropped
    ]}


def test_hypervisor_admin_with_explicit_tenant_is_filtered():
    """An admin selecting a tenant gets that tenant's prefixes applied to VMs
    (ips field); out-of-tenant VMs are dropped. A stopped VM with no IPs is
    dropped too (can't attribute it to a tenant — err on hiding)."""
    hub = _PrefixHub(FakeState(system_state={}, tenants={
        "acme": {"netbox_tenant_slug": "acme"},
    }))
    sessions = {"admin-cookie": _admin_session()}
    req = _FakeRequest("admin-cookie")
    out = asyncio.run(filter_tenant(
        hub, sessions, req, _vms_env(), "hypervisor", ["ips"], explicit_tenant="acme"))
    names = [v["name"] for v in out["vms"]]
    assert "in-tenant" in names
    assert "out-tenant" not in names
    assert "stopped" not in names


def test_hypervisor_admin_without_explicit_tenant_bypasses():
    """Regression guard: an admin with no selected tenant sees every VM
    (legacy admin bypass preserved)."""
    hub = _PrefixHub(FakeState(system_state={}, tenants={
        "acme": {"netbox_tenant_slug": "acme"},
    }))
    sessions = {"admin-cookie": _admin_session()}
    req = _FakeRequest("admin-cookie")
    env = _vms_env()
    out = asyncio.run(filter_tenant(
        hub, sessions, req, env, "hypervisor", ["ips"]))
    assert out is env  # unchanged — all 3 VMs visible


def _override_vms_env():
    # in-tenant (IP in prefix), off-prefix template, off-prefix tenant-tagged,
    # off-prefix other-tenant-tagged, stopped no-IP template.
    return {"vms": [
        {"name": "in-tenant",     "ips": ["10.20.0.5"]},
        {"name": "tmpl",          "ips": ["8.8.8.8"], "pool": "Templates"},          # template pool → all
        {"name": "tagged-acme",    "ips": ["8.8.8.8"], "tags": ["acme"]},            # tag == tenant → show
        {"name": "tagged-other",   "ips": ["8.8.8.8"], "tags": ["other"]},          # not this tenant → drop
        {"name": "tmpl-stopped",   "ips": [],          "pool": "Templates"},        # template, no IP → show
    ]}


def test_hypervisor_template_pool_visible_to_all_tenants():
    """A VM in a configured template pool is shown to every tenant regardless of
    its IPs — including a stopped template with no IPs (templates are shared)."""
    hub = _PrefixHub(FakeState(system_state={}, tenants={
        "acme": {"netbox_tenant_slug": "acme"},
    }))
    sessions = {"admin-cookie": _admin_session()}
    req = _FakeRequest("admin-cookie")
    out = asyncio.run(filter_tenant(
        hub, sessions, req, _override_vms_env(), "hypervisor", ["ips"], explicit_tenant="acme"))
    names = [v["name"] for v in out["vms"]]
    assert "tmpl" in names            # off-prefix but template pool → show
    assert "tmpl-stopped" in names    # no-IP template → show
    assert "in-tenant" in names       # normal subnet match → show
    assert "tagged-other" not in names
    assert "out-tenant" not in names


def test_hypervisor_tag_match_shows_to_that_tenant():
    """A VM whose Proxmox tag matches the tenant is shown to that tenant even
    when its IPs are off the tenant's subnet; a VM tagged for another tenant
    is not shown."""
    hub = _PrefixHub(FakeState(system_state={}, tenants={
        "acme": {"netbox_tenant_slug": "acme", "proxmox_tag": "acme-prod"},
    }))
    sessions = {"admin-cookie": _admin_session()}
    req = _FakeRequest("admin-cookie")
    env = {"vms": [
        {"name": "tagged-slug",  "ips": ["8.8.8.8"], "tags": ["acme"]},          # == netbox slug / id → show
        {"name": "tagged-ptag",  "ips": ["8.8.8.8"], "tags": ["acme-prod"]},     # == proxmox_tag → show
        {"name": "tagged-other", "ips": ["8.8.8.8"], "tags": ["other"]},         # not ours → drop
    ]}
    out = asyncio.run(filter_tenant(
        hub, sessions, req, env, "hypervisor", ["ips"], explicit_tenant="acme"))
    names = [v["name"] for v in out["vms"]]
    assert "tagged-slug" in names
    assert "tagged-ptag" in names
    assert "tagged-other" not in names


def test_hypervisor_module_in_toggle_set_and_default_on():
    """The 'hypervisor' module is registered in the subnet-filter toggle set
    and defaults ON (VM IPs are tenant-scoped data)."""
    from access import _FILTER_MODULES, _FILTER_DEFAULTS
    assert "hypervisor" in _FILTER_MODULES
    assert _FILTER_DEFAULTS["hypervisor"] is True

# ── Fail-closed on empty prefixes (unconfigured tenant) ─────────────────────
#
# A tenant with NO NetBox prefixes sees NOTHING in a purely subnet-filtered
# module, not the whole fleet. The old return data fail-open was a cross-
# tenant leak for unconfigured tenants. Hypervisor is exempt (it also
# attributes by tag + template pool).


class _NoPrefixHub(_PrefixHub):
    """_PrefixHub whose tenant has NO NetBox prefixes (unconfigured)."""
    async def request_response(self, spoke_id, command, payload, **kwargs):
        assert spoke_id == self._ipam_spoke
        assert command == "NETBOX_GET_PREFIXES"
        return {"payload": {"data": {"prefixes": []}}}


def _user_session(tenant):
    return {"user": {"tenants": [tenant], "tenant_id": tenant,
                     "permissions": {"nac": True}}, "expires": 2 ** 31}


def test_filter_fw_fails_closed_for_no_prefix_tenant():
    """An admin acting-as a tenant with no prefixes sees nothing, not the
    whole fleet (the old fail-open leaked every tenant's rules)."""
    hub = _NoPrefixHub(FakeState(system_state={}, tenants={
        "ghost": {"netbox_tenant_slug": "ghost"},
    }))
    sessions = {"admin-cookie": _admin_session()}
    req = _FakeRequest("admin-cookie")
    env = _rules_env()
    out = asyncio.run(filter_fw(hub, sessions, req, env, "rules",
                                firewall_id=None, explicit_tenant="ghost"))
    assert out is not env          # a NEW envelope, not the unfiltered input
    assert out["rules"] == []     # fail-closed empty
    assert env["rules"]           # the caller's original is NOT mutated (still 3)


def test_filter_session_fails_closed_for_no_prefix_non_admin():
    """A non-admin whose tenant has no prefixes sees nothing (fail-closed),
    not the unfiltered fleet."""
    hub = _NoPrefixHub(FakeState(system_state={}, tenants={
        "ghost": {"netbox_tenant_slug": "ghost"},
    }))
    sessions = {"user-cookie": _user_session("ghost")}
    req = _FakeRequest("user-cookie")
    data = {"data": [{"ip": "10.20.0.5"}, {"ip": "8.8.8.8"}]}
    out = asyncio.run(filter_session(hub, sessions, req, data, "nac", ["ip"]))
    assert out["data"] == []      # fail-closed: no prefixes → nothing


def test_filter_tenant_fails_closed_for_no_prefix_non_hypervisor():
    """A purely subnet-filtered module (nac) for a no-prefix tenant → empty."""
    hub = _NoPrefixHub(FakeState(system_state={}, tenants={
        "ghost": {"netbox_tenant_slug": "ghost"},
    }))
    sessions = {"admin-cookie": _admin_session()}
    req = _FakeRequest("admin-cookie")
    data = {"data": [{"ip": "10.20.0.5"}, {"ip": "8.8.8.8"}]}
    out = asyncio.run(filter_tenant(hub, sessions, req, data, "nac", ["ip"],
                                explicit_tenant="ghost"))
    assert out["data"] == []


def test_filter_tenant_hypervisor_exempt_from_fail_close():
    """Hypervisor also attributes by tag + template pool, so a no-prefix tenant
    is NOT blanked — the unfiltered VM list is returned (current behavior
    preserved; tag/template attribution is a separate path)."""
    hub = _NoPrefixHub(FakeState(system_state={}, tenants={
        "ghost": {"netbox_tenant_slug": "ghost"},
    }))
    sessions = {"admin-cookie": _admin_session()}
    req = _FakeRequest("admin-cookie")
    vms = {"data": [{"name": "vm1", "ips": ["10.20.0.5"]}]}
    out = asyncio.run(filter_tenant(hub, sessions, req, vms, "hypervisor", ["ips"],
                                explicit_tenant="ghost"))
    assert out is vms             # hypervisor no-prefix → unchanged


# ── Multi-tenant user switching tenants (server-side filter honors ?tenant=) ──
#
# A non-admin who belongs to several tenants (tenants=[A, B]; login derives the
# session tenant_id from tenants[0]=A) must, when they SELECT tenant B in the UI
# (?tenant=B), have B's data filtered by B's prefixes — not A's. The old
# filter_session read ONLY the session-default tenant's prefixes, so switching
# to B filtered B's items against A's subnets and showed nothing (the "DXP
# tenant sees no IPAM prefixes" bug — the list endpoint already scopes the spoke
# query to B, then this redundant server-side filter wrongly dropped every row).
# A crafted ?tenant= for an UNOWNED tenant still falls back to the session
# tenant, so it can never widen the filter to another tenant's data.

class _PerTenantPrefixHub(_PrefixHub):
    """IPAM spoke returning DIFFERENT prefixes per requested tenant slug."""
    _BY_SLUG = {
        "lrb": [{"prefix": "10.10.0.0/16"}],
        "dxp": [{"prefix": "10.79.0.0/16"}, {"prefix": "10.79.254.0/24"}],
    }

    async def request_response(self, spoke_id, command, payload, **kwargs):
        assert command == "NETBOX_GET_PREFIXES"
        rows = self._BY_SLUG.get(payload.get("tenant"), [])
        return {"payload": {"data": {"prefixes": rows}}}


class _QSRequest(_FakeRequest):
    """_FakeRequest that also exposes ?tenant= via .query_params."""
    def __init__(self, cookie, tenant=None):
        super().__init__(cookie)
        self.query_params = {"tenant": tenant} if tenant else {}


def _multi_tenant_session():
    # tenants=[lrb, dxp]; login derives tenant_id from tenants[0]=lrb.
    return {"user": {"tenants": ["lrb", "dxp"], "tenant_id": "lrb",
                     "permissions": {"netbox": True}}, "expires": 2 ** 31}


def _multi_hub():
    return _PerTenantPrefixHub(FakeState(system_state={}, tenants={
        "lrb": {"netbox_tenant_slug": "lrb"},
        "dxp": {"netbox_tenant_slug": "dxp"},
    }))


def _dxp_prefix_rows():
    # The list endpoint already tenant-scoped the spoke query to dxp, so the
    # rows ARE dxp's — the redundant server-side filter must not drop them.
    return {"prefixes": [
        {"prefix": "10.79.0.0/16"},
        {"prefix": "10.79.254.0/24"},
    ]}


def test_filter_session_honors_selected_tenant_for_multi_tenant_user():
    """Multi-tenant user (session default lrb) selecting dxp (?tenant=dxp) sees
    dxp's prefixes — filtered by dxp's subnets, not the session-default lrb."""
    hub = _multi_hub()
    sessions = {"u": _multi_tenant_session()}
    req = _QSRequest("u", tenant="dxp")
    out = asyncio.run(filter_session(hub, sessions, req, _dxp_prefix_rows(), "netbox", ["prefix"]))
    got = [p["prefix"] for p in out["prefixes"]]
    assert got == ["10.79.0.0/16", "10.79.254.0/24"]  # dxp rows kept


def test_filter_session_default_tenant_when_no_selection():
    """No ?tenant= → session-default tenant (lrb) prefixes; dxp rows are dropped
    (the pre-switch view), proving the default path is unchanged."""
    hub = _multi_hub()
    sessions = {"u": _multi_tenant_session()}
    req = _QSRequest("u")  # no ?tenant=
    out = asyncio.run(filter_session(hub, sessions, req, _dxp_prefix_rows(), "netbox", ["prefix"]))
    assert out["prefixes"] == []  # dxp rows don't match lrb's 10.10.0.0/16


def test_filter_session_unowned_tenant_falls_back_to_session():
    """A crafted ?tenant= for a tenant the user does NOT own falls back to the
    session tenant (lrb) — no cross-tenant widening."""
    hub = _multi_hub()
    sessions = {"u": _multi_tenant_session()}
    req = _QSRequest("u", tenant="ra")  # not in user's [lrb, dxp]
    out = asyncio.run(filter_session(hub, sessions, req, _dxp_prefix_rows(), "netbox", ["prefix"]))
    assert out["prefixes"] == []  # filtered by lrb (fallback), dxp rows dropped


class _VrfPrefixHub(_PrefixHub):
    """Overlapping tenants: dxp owns broad containers, central a specific /24."""
    _PREFIXES = {"dxp": ["10.0.0.0/8", "172.16.0.0/12"],
                 "central": ["10.21.16.0/24"], "default": []}

    async def request_response(self, spoke_id, command, payload, **kwargs):
        return {"payload": {"data": {"prefixes": [
            {"prefix": p} for p in self._PREFIXES.get(payload.get("tenant"), [])]}}}


def _vrf_hub():
    return _VrfPrefixHub(FakeState(system_state={}, tenants={
        "dxp": {"netbox_tenant_slug": "dxp"},
        "central": {"netbox_tenant_slug": "central"},
    }))


def test_shared_dhcp_scopes_go_to_their_most_specific_tenant():
    # DXP's 10.0.0.0/8 overlaps central's scope on the shared Kea; the scope is
    # central's, so DXP must not see it (it did: "DXP sees all scopes").
    data = {"subnets": [{"subnet": "10.21.16.0/24"}, {"subnet": "10.99.0.0/24"}]}
    req = _FakeRequest("admin-cookie")
    sessions = {"admin-cookie": _admin_session()}
    out = asyncio.run(filter_tenant(_vrf_hub(), sessions, req, data, "dhcp", ["subnet"],
                                    explicit_tenant="dxp", shared_source=True))
    assert out["subnets"] == [{"subnet": "10.99.0.0/24"}]
    out = asyncio.run(filter_tenant(_vrf_hub(), sessions, req, data, "dhcp", ["subnet"],
                                    explicit_tenant="central", shared_source=True))
    assert out["subnets"] == [{"subnet": "10.21.16.0/24"}]


def test_tenant_own_dhcp_server_keeps_overlap_matching():
    # A tenant's own server only sees its own VRF: no ownership narrowing.
    data = {"subnets": [{"subnet": "10.21.16.0/24"}]}
    out = asyncio.run(filter_tenant(_vrf_hub(), {"a": _admin_session()}, _FakeRequest("a"),
                                    data, "dhcp", ["subnet"], explicit_tenant="dxp"))
    assert out["subnets"] == [{"subnet": "10.21.16.0/24"}]


# ── Tenant-dedicated spokes: data is the owner's, never IP filtered ─────────
# The same IP can live in several tenants' VRFs, so when the source spoke is
# bound to a (non-shared) tenant its data belongs to that tenant outright.

import access as _access


def _owned_hub():
    hub = _vrf_hub()
    hub.state._spoke_tenants = {"cen-spoke": "central", "shr-spoke": "shared"}
    return hub


def _owned_data():
    # 10.5.0.1 lies in dxp's 10.0.0.0/8, NOT in central's 10.21.16.0/24.
    return {"sessions": [{"ip": "10.5.0.1"}, {"ip": "10.21.16.9"}]}


def _filter_as(hub, tenant, spoke):
    return asyncio.run(filter_tenant(hub, {"a": _admin_session()}, _QSRequest("a"),
                                     _owned_data(), "nac", ["ip"],
                                     explicit_tenant=tenant, spoke_id=spoke))


def test_owned_spoke_data_shown_unfiltered_to_its_tenant():
    out = _filter_as(_owned_hub(), "central", "cen-spoke")
    assert out == _owned_data()


def test_owned_spoke_data_hidden_from_other_tenant():
    out = _filter_as(_owned_hub(), "dxp", "cen-spoke")
    assert out["sessions"] == []


def test_owned_spoke_data_shown_under_group_containing_owner(monkeypatch):
    monkeypatch.setitem(_access._GROUP_MEMBERS, "group:g1", {"central"})
    out = _filter_as(_owned_hub(), "group:g1", "cen-spoke")
    assert out == _owned_data()


def test_owned_spoke_data_shown_to_admin_without_selection():
    out = _filter_as(_owned_hub(), None, "cen-spoke")
    assert out == _owned_data()


def test_shared_spoke_data_still_ip_filtered():
    out = _filter_as(_owned_hub(), "central", "shr-spoke")
    assert out["sessions"] == [{"ip": "10.21.16.9"}]


def test_aggregated_list_scoped_per_source_spoke():
    data = {"vms": [{"ip": "10.5.0.1", "s": "cen-spoke"}, {"ip": "10.5.0.2", "s": "shr-spoke"}]}
    out = asyncio.run(filter_tenant(_owned_hub(), {"a": _admin_session()}, _QSRequest("a"),
                                    data, "nac", ["ip"], explicit_tenant="central",
                                    spoke_of=lambda r: r["s"]))
    assert out["vms"] == [{"ip": "10.5.0.1", "s": "cen-spoke"}]


def test_owned_record_attributed_to_owner_not_prefix(monkeypatch):
    import ipaddress
    nets = {t: [ipaddress.ip_network(p)] for t, p in
            (("dxp", "10.0.0.0/8"), ("central", "10.21.16.0/24"))}

    async def _nets(_hub):
        return nets
    monkeypatch.setattr(_access, "_tenant_networks", _nets)
    owned = {"ip": "10.5.0.1", "owner_tenant_id": "central"}
    plain = {"ip": "10.5.0.2"}
    buckets, dropped = asyncio.run(_access.attribute_by_prefix(None, [owned, plain]))
    assert buckets == {"central": [owned], "dxp": [plain]} and dropped == 0


# ── Own spoke of a module type → out of the shared environment ──────────────
# Once a tenant owns a spoke of a type, the shared spokes of that type are
# hidden from it entirely (never IP-routed). Others keep IP routing.

def _left_shared_hub(**tenants):
    hub = _owned_hub()
    hub.state._spoke_tenants.update(tenants)
    hub.spoke_module_types = {"cen-spoke": "nac", "shr-spoke": "cppm",
                              **{sid: "nac" for sid in tenants}}
    return hub


def test_own_spoke_hides_shared_spoke_of_same_type_even_when_ip_matches():
    out = _filter_as(_left_shared_hub(), "central", "shr-spoke")
    assert out["sessions"] == []


def _filter_rows(hub, tenant, spoke):
    data = {"sessions": [{"ip": "10.5.0.1"}, {"ip": "192.0.2.1"}]}
    return asyncio.run(filter_tenant(hub, {"a": _admin_session()}, _QSRequest("a"),
                                     data, "nac", ["ip"],
                                     explicit_tenant=tenant, spoke_id=spoke))["sessions"]


def test_tenant_without_own_spoke_still_sees_ip_routed_shared_data():
    assert _filter_rows(_left_shared_hub(), "dxp", "shr-spoke") == [{"ip": "10.5.0.1"}]


def test_shared_spoke_of_other_type_still_ip_filtered_for_owner():
    hub = _left_shared_hub()
    hub.spoke_module_types["shr-spoke"] = "nw"
    assert _filter_as(hub, "central", "shr-spoke")["sessions"] == [{"ip": "10.21.16.9"}]


def test_offline_own_spoke_counts_via_module_metadata():
    hub = _owned_hub()
    hub.spoke_module_types = {"shr-spoke": "nac"}
    hub.state.system_state["module_metadata"] = {
        "cen-spoke": {"tenant_id": "central", "module_type": "cppm"}}
    assert _filter_as(hub, "central", "shr-spoke")["sessions"] == []


def test_admin_without_selection_sees_shared_spoke_data():
    assert _filter_as(_left_shared_hub(), None, "shr-spoke") == _owned_data()


def test_group_member_owning_type_does_not_cut_group_or_other_members(monkeypatch):
    monkeypatch.setitem(_access._GROUP_MEMBERS, "group:g1", {"central", "dxp"})
    hub = _left_shared_hub()
    assert _access.tenant_has_own_spoke(hub, "central", "nac")
    assert not _access.tenant_has_own_spoke(hub, "group:g1", "nac")
    assert not _access.tenant_has_own_spoke(hub, "dxp", "nac")
    assert _filter_rows(hub, "dxp", "shr-spoke") == [{"ip": "10.5.0.1"}]
    assert _access.tenant_has_own_spoke(_left_shared_hub(**{"g-spoke": "group:g1"}),
                                        "group:g1", "nac")


def test_own_firewall_hides_shared_firewalls():
    hub = _left_shared_hub()
    hub.state.system_state["global_config"] = {"firewalls": [
        {"id": "fw-c", "tenant_id": "central", "spoke_id": "shr-spoke"},
        {"id": "fw-s", "tenant_id": "shared", "spoke_id": "shr-spoke"}]}
    assert _access.tenant_has_own_firewall(hub, "central")
    assert not _access.tenant_has_own_firewall(hub, "dxp")
    assert _access._shared_spoke_masked(hub, "shr-spoke", "central", firewall_id="fw-s")
    assert not _access._shared_spoke_masked(hub, "shr-spoke", "dxp", firewall_id="fw-s")


def test_scoped_spoke_of_type_never_falls_back_to_shared():
    hub = _left_shared_hub()
    hub.active_connections = {"shr-spoke"}
    hub.approved_modules = {"shr-spoke": True, "cen-spoke": True}
    hub.get_spoke_by_type = lambda t: "shr-spoke"
    assert _access.scoped_spoke_of_type(hub, "central", "nac") is None
    assert _access.scoped_spoke_of_type(hub, "dxp", "nac") == "shr-spoke"
    hub.active_connections.add("cen-spoke")
    assert _access.scoped_spoke_of_type(hub, "central", "nac") == "cen-spoke"



def test_scoped_firewall_pick_follows_own_firewall_record():
    # central's firewall is a firewalls record on an unbound spoke: the pick
    # (global search's SEARCH_DHCP leg) goes to that spoke, not to None.
    hub = _left_shared_hub()
    hub.state.system_state["global_config"] = {"firewalls": [
        {"id": "fw-c", "tenant_id": "central", "spoke_id": "opn-1"}]}
    hub.spoke_module_types = {"opn-1": "firewall"}
    hub.active_connections = {"opn-1"}
    hub.approved_modules = {"opn-1": True}
    hub.get_spoke_by_type = lambda t: "opn-1"
    assert _access.scoped_spoke_of_type(hub, "central", "firewall") == "opn-1"
    hub.active_connections = set()
    assert _access.scoped_spoke_of_type(hub, "central", "firewall") is None


def test_own_firewall_keeps_vrf_prefixes_and_search_leg_never_goes_shared():
    # Even with shared access "allow", a tenant with its own firewall record
    # keeps every prefix for the firewall DHCP leg and that leg goes only to
    # its own spoke, so no shared firewall is queried with the VRF prefixes.
    hub = _left_shared_hub()
    hub.state.tenant_state = {"tenants": {"central": {"shared_access": "allow"}}}
    hub.state.system_state["global_config"] = {"firewalls": [
        {"id": "fw-c", "tenant_id": "central", "spoke_id": "opn-1"}]}
    hub.spoke_module_types = {"opn-1": "firewall", "opn-shared": "firewall"}
    hub.active_connections = {"opn-1", "opn-shared"}
    hub.approved_modules = {"opn-1": True, "opn-shared": True}
    hub.get_spoke_by_type = lambda t: "opn-shared"
    prefixes = ["10.0.0.0/8", "192.168.5.0/24"]
    assert _access.firewall_dhcp_prefixes(hub, "central", prefixes) == prefixes
    assert _access.scoped_spoke_of_type(hub, "central", "firewall") == "opn-1"
    hub.active_connections = {"opn-shared"}
    assert _access.scoped_spoke_of_type(hub, "central", "firewall") is None


# ── A tenant in its own VRF cannot use shared infrastructure ────────────────
# Shared infra serves the common routing domain: the global table or a VRF
# several tenants share. A prefix that NetBox puts only in the tenant's own
# VRF (one no other tenant uses) must not match a shared firewall/Kea/Proxmox
# record with the same address. NetBox itself stays shared.

class _OwnVrfPrefixHub(_PrefixHub):
    """dxp: 10.0.0.0/8 only in its own VRF (id 7), 192.168.5.0/24 global;
    vrfonly: 10.0.0.0/8 only in its own VRF (id 8)."""
    _ROWS = {"dxp": [{"prefix": "10.0.0.0/8", "vrf_id": 7},
                     {"prefix": "192.168.5.0/24", "vrf_id": None}],
             "vrfonly": [{"prefix": "10.0.0.0/8", "vrf_id": 8}]}

    async def request_response(self, spoke_id, command, payload, **kwargs):
        key = payload.get("tenant") or "group:" + str(payload.get("tenant_group"))
        return {"payload": {"data": {"prefixes": self._ROWS.get(key, [])}}}


def _own_vrf_hub():
    return _OwnVrfPrefixHub(FakeState(system_state={}, tenants={
        "dxp": {"netbox_tenant_slug": "dxp"},
        "vrfonly": {"netbox_tenant_slug": "vrfonly"},
    }))


def test_shared_firewall_rules_ignore_own_vrf_prefixes():
    rules = {"rules": [{"source": "10.20.0.5", "destination": "8.8.8.8"},
                       {"source": "192.168.5.9", "destination": "8.8.8.8"}]}
    out = asyncio.run(filter_fw(_own_vrf_hub(), {"a": _admin_session()}, _FakeRequest("a"),
                                rules, "rules", explicit_tenant="dxp"))
    assert out["rules"] == [{"source": "192.168.5.9", "destination": "8.8.8.8"}]


def test_vrf_only_tenant_sees_nothing_on_shared_firewall():
    rules = {"rules": [{"source": "10.20.0.5", "destination": "8.8.8.8"}]}
    out = asyncio.run(filter_fw(_own_vrf_hub(), {"a": _admin_session()}, _FakeRequest("a"),
                                rules, "rules", explicit_tenant="vrfonly"))
    assert out["rules"] == []


def test_vrf_only_tenant_keeps_category_tagged_firewall_records():
    # The admin tagged some shared-firewall records with the tenant's category:
    # they stay visible even though no address matches; untagged ones stay hidden.
    def _fw(data, endpoint):
        return asyncio.run(filter_fw(_own_vrf_hub(), {"a": _admin_session()}, _FakeRequest("a"),
                                     data, endpoint, explicit_tenant="vrfonly"))

    rules = {"rules": [{"source": "10.20.0.5", "destination": "8.8.8.8"},
                       {"source": "any", "destination": "any", "category": "vrfonly"}]}
    nat = {"nat": [{"target": "webhost"}, {"target": "dxphost", "category": "vrfonly"}]}
    aliases = {"aliases": [{"content": "10.20.0.5"},
                           {"content": "10.20.0.6", "category": "vrfonly"}]}
    assert _fw(rules, "rules")["rules"] == [rules["rules"][1]]
    assert _fw(nat, "nat")["nat"] == [nat["nat"][1]]
    assert _fw(aliases, "aliases")["aliases"] == [aliases["aliases"][1]]


def test_vrf_only_tenant_single_record_gate_keeps_own_source():
    from simulations.tenant_filter import OWN_SOURCE_MARKER
    hub = _own_vrf_hub()
    own, shared = {"ip": "10.20.0.5", OWN_SOURCE_MARKER: True}, {"ip": "10.20.0.6"}

    def _gate(rec):
        return asyncio.run(_access.gate_record_tenant(
            hub, {"a": _admin_session()}, _FakeRequest("a"), rec, "nac", ["ip"],
            explicit_tenant="vrfonly"))

    assert _gate(own) == own
    assert _gate(shared) is None


def test_vrf_only_tenant_cannot_write_shared_firewall_rule():
    hub, sess = _own_vrf_hub(), _user_session("vrfonly")
    rule = {"source": "10.20.0.5", "destination": "8.8.8.8"}
    assert not asyncio.run(_access.fw_rule_in_tenant_scope(hub, sess, "rules", None, rule))
    assert not asyncio.run(_access.record_in_tenant_scope(hub, sess, {"ip": "10.20.0.5"}, ["ip"]))


def test_netbox_view_keeps_own_vrf_prefixes():
    rows = {"prefixes": [{"prefix": "10.0.0.0/8"}]}
    out = asyncio.run(filter_session(_own_vrf_hub(), {"u": _user_session("vrfonly")},
                                     _QSRequest("u"), rows, "netbox", ["prefix"]))
    assert out["prefixes"] == [{"prefix": "10.0.0.0/8"}]


def test_vrf_only_tenant_on_shared_hypervisor_keeps_only_overrides():
    vms = {"vms": [{"name": "in-vrf", "ips": ["10.20.0.5"]},
                   {"name": "tmpl", "ips": ["10.20.0.6"], "pool": "Templates"},
                   {"name": "tagged", "ips": ["10.20.0.7"], "tags": ["vrfonly"]}]}
    out = asyncio.run(filter_tenant(_own_vrf_hub(), {"a": _admin_session()}, _FakeRequest("a"),
                                    vms, "hypervisor", ["ips"], explicit_tenant="vrfonly"))
    assert [v["name"] for v in out["vms"]] == ["tmpl", "tagged"]


def test_vrf_only_tenant_keeps_own_clearpass_rows_in_merged_nac_list():
    # CPPM routes merge the tenant's own ClearPass rows (marked) with the shared
    # ClearPass's rows, without a spoke id. A VRF-only tenant matches none of
    # the shared rows but must still see its own.
    from simulations.tenant_filter import OWN_SOURCE_MARKER
    rows = {"endpoints": [{"ip": "10.20.0.5", OWN_SOURCE_MARKER: True, "name": "own"},
                          {"ip": "10.20.0.6", "name": "shared"}]}
    explicit = asyncio.run(filter_tenant(
        _own_vrf_hub(), {"a": _admin_session()}, _FakeRequest("a"), rows, "nac", ["ip"],
        explicit_tenant="vrfonly"))
    session = asyncio.run(filter_session(
        _own_vrf_hub(), {"u": _user_session("vrfonly")}, _QSRequest("u"), rows, "nac", ["ip"]))
    assert [r["name"] for r in explicit["endpoints"]] == ["own"]
    assert [r["name"] for r in session["endpoints"]] == ["own"]


def test_vrf_tenant_reads_its_own_instance_spoke_uncut():
    # vrfonly configured its own Kea as a dhcp_instances record on a spoke
    # with no tenant binding. Its records are in its VRF, so neither the
    # selected-tenant nor the session read path may cut them; a spoke that
    # also serves a shared (blank-tenant) record stays shared.
    hub = _own_vrf_hub()
    gc = hub.state.system_state.setdefault("global_config", {})
    gc["dhcp_instances"] = [{"tenant_id": "vrfonly", "spoke_id": "kea-own"},
                           {"tenant_id": "vrfonly", "spoke_id": "kea-mixed"},
                           {"tenant_id": "", "spoke_id": "kea-mixed"}]
    rows = {"records": [{"ip": "10.20.0.5", "name": "own"}]}

    def _read(spoke_id):
        explicit = asyncio.run(filter_tenant(
            hub, {"a": _admin_session()}, _FakeRequest("a"), rows, "dhcp", ["ip"],
            explicit_tenant="vrfonly", spoke_id=spoke_id))
        session = asyncio.run(filter_session(
            hub, {"u": _user_session("vrfonly")}, _QSRequest("u"), rows, "dhcp", ["ip"],
            spoke_id=spoke_id))
        return explicit["records"], session["records"]

    assert _read("kea-own") == (rows["records"], rows["records"])
    assert _read("kea-mixed") == ([], [])


def test_vrf_tenant_keeps_own_instance_rows_in_a_merged_multi_spoke_list():
    # A list merged from several spokes is filtered one source spoke at a time:
    # rows from the tenant's own unbound Kea stay, rows from a shared Kea in
    # the same list are still cut, and the original order is kept.
    hub = _own_vrf_hub()
    hub.state.system_state.setdefault("global_config", {})["dhcp_instances"] = [
        {"tenant_id": "vrfonly", "spoke_id": "kea-own"}]
    rows = {"records": [{"ip": "10.20.0.5", "s": "kea-shared"}, {"ip": "10.20.0.6", "s": "kea-own"},
                        {"ip": "10.20.0.7", "s": "kea-shared"}, {"ip": "10.20.0.8", "s": "kea-own"}]}
    explicit = asyncio.run(filter_tenant(
        hub, {"a": _admin_session()}, _FakeRequest("a"), rows, "dhcp", ["ip"],
        explicit_tenant="vrfonly", spoke_of=lambda r: r["s"]))
    session = asyncio.run(filter_session(
        hub, {"u": _user_session("vrfonly")}, _QSRequest("u"), rows, "dhcp", ["ip"],
        spoke_of=lambda r: r["s"]))
    own_only = [r for r in rows["records"] if r["s"] == "kea-own"]
    assert explicit["records"] == own_only
    assert session["records"] == own_only


class _WarmOwnVrfHub(_OwnVrfPrefixHub):
    """Own-VRF hub with a dict-backed warm cache shared across "restarts".
    Each write is stamped from a counter rather than the wall clock, so a
    later write always reads as newer."""

    def __init__(self, state, warm):
        super().__init__(state)
        self._warm = warm

    def warm_get(self, ns, key="_"):
        return self._warm.get((ns, key))

    def warm_last_fetched_at(self, ns, key="_"):
        return self._warm.get(("fetched_at", ns, key))

    async def warm_set(self, ns, key, data, **kwargs):
        self._warm[(ns, key)] = data
        self._warm[("fetched_at", ns, key)] = next(_WARM_CLOCK)


_WARM_CLOCK = itertools.count(1)


def test_vrf_cut_holds_after_hub_restart_without_netbox_fetch():
    # A session keeps its cached prefixes across a hub restart, so the first
    # shared read after the restart can run before any NetBox fetch. The VRFs
    # saved with the hub cache must still cut the own-VRF prefix.
    warm = {}
    state = _own_vrf_hub().state
    before = _WarmOwnVrfHub(state, warm)
    asyncio.run(_access.fetch_tenant_prefixes(before, "vrfonly"))
    restarted = _WarmOwnVrfHub(state, warm)
    assert _access.shared_slice_prefixes(restarted, "vrfonly", ["10.0.0.0/8"]) == []
    # Rows without vrf_id (an older spoke's warm list) must not forget known VRFs.
    _access._note_prefix_vrfs(restarted, "vrfonly", [{"prefix": "10.0.0.0/8"}])
    assert _access.shared_slice_prefixes(restarted, "vrfonly", ["10.0.0.0/8"]) == []


# ── A VRF several tenants share is common, not anyone's own ─────────────────
# Every tenant can sit in a VRF: here lab1 and lab2 share VRF 3, which the
# shared DNS/DHCP serve, lab1 also has a VRF of its own (1) and dxp sits alone
# in VRF 2. Cutting every non-global VRF emptied lab1's and lab2's shared views.

_COMMON_VRF_ROWS = {
    "lab1": [{"prefix": "172.16.0.0/23", "vrf_id": 1}, {"prefix": "172.31.200.0/22", "vrf_id": 3}],
    "lab2": [{"prefix": "172.21.0.0/24", "vrf_id": 3}],
    "dxp": [{"prefix": "10.0.0.0/8", "vrf_id": 2}],
    "group:g": [{"prefix": "172.16.0.0/23", "vrf_id": 1}, {"prefix": "172.31.200.0/22", "vrf_id": 3},
                {"prefix": "10.0.0.0/8", "vrf_id": 2}],
}


def _common_vrf_hub(warm=None, fetch=True, **extra_tenants):
    """A hub with lab1, lab2 and dxp (plus ``extra_tenants``), each tenant's
    prefixes read from NetBox once unless ``fetch`` is False."""
    tenants = {t: {"netbox_tenant_slug": t} for t in ("lab1", "lab2", "dxp")}
    tenants.update(extra_tenants)
    state = FakeState(system_state={"subnet_filter_modules": {"dns": True}}, tenants=tenants)
    hub = _WarmOwnVrfHub(state, {} if warm is None else warm)
    hub._ROWS = _COMMON_VRF_ROWS
    for tid in tenants if fetch else ():
        asyncio.run(_access.fetch_tenant_prefixes(hub, tid))
    return hub


def test_tenants_sharing_a_vrf_keep_shared_dns_and_dhcp_rows():
    rows = {"records": [{"ip": "172.21.0.5", "name": "lab2-host"},
                        {"ip": "172.31.200.9", "name": "lab1-host"},
                        {"ip": "172.16.0.9", "name": "lab1-own-vrf"},
                        {"ip": "10.1.2.3", "name": "dxp-host"}]}
    hub = _common_vrf_hub()

    def _names(module, tenant):
        out = asyncio.run(filter_tenant(hub, {"a": _admin_session()}, _FakeRequest("a"),
                                        rows, module, ["ip"], explicit_tenant=tenant))
        return [r["name"] for r in out["records"]]

    for module in ("dns", "dhcp"):
        assert _names(module, "lab2") == ["lab2-host"]
        assert _names(module, "lab1") == ["lab1-host"]  # its own VRF 1 is still cut
        assert _names(module, "dxp") == []  # alone in VRF 2: still cut


def test_common_vrf_is_known_right_after_a_hub_restart():
    # After a restart only the selected tenant's VRFs would be in memory; the
    # other tenants' saved copies must still mark VRF 3 as common.
    warm = {}
    _common_vrf_hub(warm)
    restarted = _common_vrf_hub(warm, fetch=False)
    assert _access.shared_slice_prefixes(restarted, "lab2", ["172.21.0.0/24"]) == ["172.21.0.0/24"]
    assert _access.shared_slice_prefixes(restarted, "dxp", ["10.0.0.0/8"]) == []


def test_one_netbox_tenant_and_tenant_groups_do_not_make_a_vrf_common():
    # A second hub tenant on dxp's NetBox tenant, and a group whose prefixes
    # include dxp's, are not other users of dxp's VRF. The group itself is cut
    # on its members' own VRFs and keeps the common one.
    hub = _common_vrf_hub(**{"dxp-lab": {"netbox_tenant_slug": "dxp"},
                             "group:g": {"is_tenant_group": True,
                                         "netbox_tenant_group_slug": "g"}})
    assert _access.shared_slice_prefixes(hub, "dxp", ["10.0.0.0/8"]) == []
    assert _access.shared_slice_prefixes(
        hub, "group:g", ["172.16.0.0/23", "172.31.200.0/22", "10.0.0.0/8"]) == ["172.31.200.0/22"]


def _reread(hub, tid, reply):
    """Read ``tid``'s prefixes again, with the spoke answering ``reply``."""
    async def _reply(*args, **kwargs):
        return {"payload": {"data": reply}}
    hub.request_response = _reply
    _access.clear_prefix_cache(hub)
    return asyncio.run(_access.fetch_tenant_prefixes(hub, tid))


def _feed(warm, key, rows):
    """Store ``rows`` as the NetBox cache feed's copy of scope ``key``'s prefixes."""
    warm[("nb_prefixes", key)] = {"status": "SUCCESS", "prefixes": rows}
    warm[("fetched_at", "nb_prefixes", key)] = next(_WARM_CLOCK)


def test_a_tenant_that_leaves_a_shared_vrf_stops_making_it_common():
    # lab2 removes its last prefix, which leaves lab1 alone in VRF 3. Once
    # NetBox answers that lab2 has no prefixes, VRF 3 is lab1's own and is cut,
    # also after a restart. A failed read is not that answer: it changes nothing.
    warm, lab1 = {}, ["172.31.200.0/22"]
    hub = _common_vrf_hub(warm)
    _reread(hub, "lab2", {"status": "ERROR", "message": "NetBox timed out"})
    assert _access.shared_slice_prefixes(hub, "lab1", lab1) == lab1
    _reread(hub, "lab2", {"status": "SUCCESS", "prefixes": []})
    assert _access.shared_slice_prefixes(hub, "lab1", lab1) == []
    assert _access.shared_slice_prefixes(_common_vrf_hub(warm, fetch=False), "lab1", lab1) == []


def test_common_vrf_does_not_depend_on_which_tenants_were_read():
    # Since the hub started, a page has read only lab1. lab2's and dxp's VRFs
    # come from the NetBox cache feed's copies of their prefixes, so VRF 3 is
    # still common to lab1 and lab2, and lab1's own VRF 1 is still cut.
    warm = {}
    for tid in ("lab2", "dxp"):
        _feed(warm, tid, _COMMON_VRF_ROWS[tid])
    hub = _common_vrf_hub(warm, fetch=False)
    asyncio.run(_access.fetch_tenant_prefixes(hub, "lab1"))
    assert _access.shared_slice_prefixes(
        hub, "lab1", ["172.31.200.0/22", "172.16.0.0/23"]) == ["172.31.200.0/22"]


def test_feed_copy_of_a_tenants_prefixes_beats_an_older_read():
    # lab2 moved its prefix out of VRF 3 after the hub read it: the feed's newer
    # copy says so, and VRF 3 is lab1's own. An empty copy is lab2 with no
    # prefixes. A copy from an older netbox spoke (no vrf_id) says nothing
    # about VRFs, so the read still counts.
    warm, lab1 = {}, ["172.31.200.0/22"]
    hub = _common_vrf_hub(warm)
    _feed(warm, "lab2", [{"prefix": "172.21.0.0/24", "vrf_id": 9}])
    assert _access.shared_slice_prefixes(hub, "lab1", lab1) == []
    _feed(warm, "lab2", [])
    assert _access.shared_slice_prefixes(hub, "lab1", lab1) == []
    _feed(warm, "lab2", [{"prefix": "172.21.0.0/24"}])
    assert _access.shared_slice_prefixes(hub, "lab1", lab1) == lab1


def test_a_read_newer_than_the_feed_copy_beats_it():
    # The feed copied lab2's prefix in VRF 3, then NetBox answered a newer
    # read that lab2 has no prefixes left: VRF 3 is lab1's own from that
    # answer on, not from the feed's next copy, and after a restart too
    # (lm#1992). A failed read, which falls back to the feed's copy for
    # lab2's own list, does not bring the older copy back. A read that finds
    # lab2 back in VRF 3 after a newer feed copy said it had none counts,
    # although an older read had saved the same VRFs.
    warm, lab1 = {}, ["172.31.200.0/22"]
    _feed(warm, "lab2", _COMMON_VRF_ROWS["lab2"])
    hub = _common_vrf_hub(warm, fetch=False)
    asyncio.run(_access.fetch_tenant_prefixes(hub, "lab1"))
    assert _access.shared_slice_prefixes(hub, "lab1", lab1) == lab1
    _reread(hub, "lab2", {"status": "SUCCESS", "prefixes": []})
    assert _access.shared_slice_prefixes(hub, "lab1", lab1) == []
    assert _access.shared_slice_prefixes(_common_vrf_hub(warm, fetch=False), "lab1", lab1) == []
    _reread(hub, "lab2", {"status": "ERROR", "message": "NetBox timed out"})
    assert _access.shared_slice_prefixes(hub, "lab1", lab1) == []
    _reread(hub, "lab2", {"status": "SUCCESS", "prefixes": _COMMON_VRF_ROWS["lab2"]})
    _feed(warm, "lab2", [])
    assert _access.shared_slice_prefixes(hub, "lab1", lab1) == []
    _reread(hub, "lab2", {"status": "SUCCESS", "prefixes": _COMMON_VRF_ROWS["lab2"]})
    assert _access.shared_slice_prefixes(hub, "lab1", lab1) == lab1


def test_a_read_without_vrf_ids_does_not_beat_the_feed_copy():
    # An older netbox spoke's read carries no vrf_id, so it says nothing about
    # VRFs: the VRFs an earlier read found must not be saved again as this
    # read's answer and beat the feed's newer copy (lab2 moved to VRF 9).
    warm, lab1 = {}, ["172.31.200.0/22"]
    hub = _common_vrf_hub(warm)
    _feed(warm, "lab2", [{"prefix": "172.21.0.0/24", "vrf_id": 9}])
    _reread(hub, "lab2", {"status": "SUCCESS", "prefixes": [{"prefix": "172.21.0.0/24"}]})
    assert _access.shared_slice_prefixes(hub, "lab1", lab1) == []


def test_prefix_reads_ignore_the_pre_unified_hub_cache_copies():
    # Before the unified hub cache, the NetBox page kept prefixes under
    # "nb_netbox_prefixes", and a hub can still hold those copies, never
    # refreshed. NetBox answering that lab2 has no prefixes beats lab2's old
    # copy, and a failed read falls back to the feed's copy, not the old one.
    warm, lab1 = {}, ["172.31.200.0/22"]
    hub = _common_vrf_hub(warm)
    warm[("nb_netbox_prefixes", "lab2")] = {"status": "SUCCESS", "prefixes": _COMMON_VRF_ROWS["lab2"]}
    assert _reread(hub, "lab2", {"status": "SUCCESS", "prefixes": []}) == []
    assert _access.shared_slice_prefixes(hub, "lab1", lab1) == []
    warm[("nb_netbox_prefixes", "lab1")] = {"status": "SUCCESS",
                                            "prefixes": [{"prefix": "192.0.2.0/24", "vrf_id": 5}]}
    _feed(warm, "lab1", _COMMON_VRF_ROWS["lab1"])
    assert _reread(hub, "lab1", {"status": "ERROR", "message": "NetBox timed out"}) == [
        "172.16.0.0/23", "172.31.200.0/22"]


# ── A Global Admin can name the common VRFs (lm#1992) ───────────────────────
# The inference counts any VRF two tenants use, even one shared infrastructure
# does not serve. VRFs named under System → General → Common VRFs replace it;
# an empty list, no list, or a hand-edited bad value leaves the inference.

def _name_common_vrfs(hub, value):
    """Store ``value`` as the hub's named common VRFs, where the routes do."""
    hub.state.system_state.setdefault("global_config", {})[_access.COMMON_VRF_SETTING] = value


def test_named_common_vrfs_replace_the_inferred_ones():
    # VRF 2 is dxp's alone and VRF 3 is lab1's and lab2's. With VRF 2 named,
    # dxp keeps it and lab1 and lab2 lose VRF 3; the global table stays common.
    hub, dxp = _common_vrf_hub(), ["10.0.0.0/8", "192.168.5.0/24"]
    _reread(hub, "dxp", {"status": "SUCCESS", "prefixes": [
        {"prefix": "10.0.0.0/8", "vrf_id": 2}, {"prefix": "192.168.5.0/24", "vrf_id": None}]})
    _name_common_vrfs(hub, ["2"])
    assert _access.shared_slice_prefixes(hub, "dxp", dxp) == dxp
    assert _access.shared_slice_prefixes(hub, "lab2", ["172.21.0.0/24"]) == []
    assert _access.shared_slice_prefixes(hub, "lab1", ["172.16.0.0/23", "172.31.200.0/22"]) == []
    _name_common_vrfs(hub, ["3"])
    assert _access.shared_slice_prefixes(hub, "dxp", dxp) == ["192.168.5.0/24"]
    assert _access.shared_slice_prefixes(hub, "lab2", ["172.21.0.0/24"]) == ["172.21.0.0/24"]


def test_a_change_to_the_named_vrfs_applies_at_the_next_slice():
    # Read on every slice: no restart, and clearing the list infers again.
    hub, lab2 = _common_vrf_hub(), ["172.21.0.0/24"]
    assert _access.shared_slice_prefixes(hub, "lab2", lab2) == lab2
    _name_common_vrfs(hub, ["2"])
    assert _access.shared_slice_prefixes(hub, "lab2", lab2) == []
    _name_common_vrfs(hub, [])
    assert _access.shared_slice_prefixes(hub, "lab2", lab2) == lab2


@pytest.mark.parametrize("value", [[], None, "2", ["x"], [True], ["2", "x"], {"2": True}])
def test_no_named_vrfs_or_a_hand_edited_bad_value_keeps_the_inference(value):
    hub = _common_vrf_hub()
    _name_common_vrfs(hub, value)
    assert _access.shared_slice_prefixes(hub, "lab2", ["172.21.0.0/24"]) == ["172.21.0.0/24"]
    assert _access.shared_slice_prefixes(hub, "dxp", ["10.0.0.0/8"]) == []


def test_named_vrf_ids_are_stored_as_unique_strings_in_numeric_order():
    assert _access.normalize_common_vrf_ids([3, "7", " 2 ", "007", 3, "10"]) == ["2", "3", "7", "10"]
    assert _access.normalize_common_vrf_ids([]) == []


@pytest.mark.parametrize("value", ["3", None, {"3": True}, [None], [True], [1.5], [""], ["abc"],
                                   ["0"], [0], ["-1"], ["\u0661"], [[1]], ["1" * 19]])
def test_a_bad_named_vrf_value_is_refused(value):
    with pytest.raises(ValueError):
        _access.normalize_common_vrf_ids(value)


def test_common_vrf_card_shows_cached_vrf_names_and_the_mode():
    # Names come from the NetBox cache feed's copies of the tenants' prefixes.
    # A named VRF no cached row names is still listed, with no name, so it can
    # be unticked; the global table is not a VRF to pick.
    warm = {}
    _feed(warm, "lab1", [{"prefix": "172.16.0.0/23", "vrf_id": 1, "vrf": "LAB1-OWN"},
                         {"prefix": "172.31.200.0/22", "vrf_id": 3, "vrf": "Shared"}])
    _feed(warm, "lab2", [{"prefix": "172.21.0.0/24", "vrf_id": 3, "vrf": "Shared"},
                         {"prefix": "192.168.5.0/24", "vrf_id": None, "vrf": ""}])
    _feed(warm, "dxp", [{"prefix": "10.0.0.0/8", "vrf_id": 2, "vrf": "dxp"}])
    hub = _common_vrf_hub(warm, fetch=False)
    vrfs = [{"id": "2", "name": "dxp"}, {"id": "1", "name": "LAB1-OWN"}, {"id": "3", "name": "Shared"}]
    assert _access.common_vrf_settings(hub) == {
        "vrf_ids": [], "mode": "automatic", "common": ["3"], "vrfs": vrfs}
    _name_common_vrfs(hub, ["12", "2"])
    assert _access.common_vrf_settings(hub) == {
        "vrf_ids": ["2", "12"], "mode": "configured", "common": ["2", "12"],
        "vrfs": vrfs + [{"id": "12", "name": ""}]}


# ── Shared-source ownership: nested common prefixes ─────────────────────────
# The shared ClearPass and the shared Kea serve every tenant's common
# prefixes, and those can nest. A shared row belongs to the tenant with the
# most specific served prefix holding it, so a tenant with a broad container
# does not see a nested tenant's rows. A prefix in a tenant's own VRF is not
# served by shared infrastructure and claims nothing; the shared tenant sees
# shared infrastructure whole and claims nothing either (rule 6.2).

from simulations.tenant_filter import OWN_SOURCE_MARKER


class _NestedHub(_PrefixHub):
    """a's 10.0.0.0/8 holds b's 10.1.0.0/16 (global table); b2 is a second hub
    tenant on NetBox tenant b; c's 10.1.5.0/24 is in c's own VRF 7; group g1
    is a; the shared tenant has 10.1.0.0/24 and 172.16.0.0/12, which holds
    d's 172.16.1.0/24."""
    _ROWS = {"a": [("10.0.0.0/8", None)], "g1": [("10.0.0.0/8", None)],
             "b": [("10.1.0.0/16", None)], "c": [("10.1.5.0/24", 7)],
             "d": [("172.16.1.0/24", None)],
             "shared": [("10.1.0.0/24", None), ("172.16.0.0/12", None)]}

    async def request_response(self, spoke_id, command, payload, **kwargs):
        rows = self._ROWS.get(payload.get("tenant") or payload.get("tenant_group"), [])
        return {"payload": {"data": {"status": "SUCCESS", "prefixes": [
            {"prefix": p, "vrf_id": v} for p, v in rows]}}}


def _nested_hub():
    tenants = {t: {"netbox_tenant_slug": t} for t in ("a", "b", "c", "d", "shared")}
    tenants["b2"] = {"netbox_tenant_slug": "b"}
    tenants["group:g1"] = {"is_tenant_group": True, "netbox_tenant_group_slug": "g1",
                           "member_tenant_slugs": ["a"]}
    return _NestedHub(FakeState(system_state={}, tenants=tenants))


_NESTED_ROWS = [{"ip": "10.1.0.5", "n": "b"},        # b's /16 is the most specific
                {"ip": "10.2.0.5", "n": "a"},        # only a's /8 holds it
                {"ip": "10.1.5.9", "n": "b-in-c"},   # c's own-VRF /24 claims nothing
                {"ip": "172.16.1.5", "n": "d"},      # d's /24, inside the shared tenant's /12
                {"ip": "10.1.0.7", "n": "own", OWN_SOURCE_MARKER: True}]


def _nested(tenant):
    out = asyncio.run(filter_tenant(_nested_hub(), {"x": _admin_session()}, _FakeRequest("x"),
                                    {"sessions": list(_NESTED_ROWS)}, "nac", ["ip"],
                                    explicit_tenant=tenant))
    return [r["n"] for r in out["sessions"]]


def test_shared_clearpass_rows_go_to_the_most_specific_tenant():
    assert _nested("a") == ["a", "own"]
    assert _nested("b") == ["b", "b-in-c", "own"]
    assert _nested("b2") == ["b", "b-in-c", "own"]  # a tie keeps the row for both


def test_tenant_group_is_narrowed_like_its_members():
    assert _nested("group:g1") == ["a", "own"]


def test_shared_tenant_sees_shared_infrastructure_whole():
    # d's /24 is more specific than the shared tenant's /12, yet the shared
    # tenant keeps d's row; d keeps it too.
    assert _nested("shared") == ["b", "d", "own"]
    assert _nested("d") == ["d", "own"]


def test_non_admin_without_selection_is_narrowed_too():
    # No ?tenant=: filter_tenant falls back to filter_session, which narrows
    # NAC rows, and the shared Kea's scopes (shared_source) but not a tenant's
    # own DHCP server's.
    hub, sessions = _nested_hub(), {"u": _user_session("a")}
    nac = asyncio.run(filter_session(hub, sessions, _QSRequest("u"),
                                     {"sessions": list(_NESTED_ROWS)}, "nac", ["ip"]))
    assert [r["n"] for r in nac["sessions"]] == ["a", "own"]
    scopes = {"subnets": [{"subnet": "10.1.0.0/24"}, {"subnet": "10.2.0.0/24"}]}
    for shared_source, want in ((True, ["10.2.0.0/24"]),
                                (False, ["10.1.0.0/24", "10.2.0.0/24"])):
        out = asyncio.run(filter_tenant(hub, sessions, _QSRequest("u"), scopes, "dhcp",
                                        ["subnet"], shared_source=shared_source))
        assert [s["subnet"] for s in out["subnets"]] == want


def test_single_record_gates_apply_ownership():
    hub = _nested_hub()
    b_row, a_row = _NESTED_ROWS[0], _NESTED_ROWS[1]
    for rec, want in ((b_row, None), (a_row, a_row)):
        assert asyncio.run(_access.gate_record_tenant(
            hub, {"x": _admin_session()}, _FakeRequest("x"), rec, "nac", ["ip"],
            explicit_tenant="a")) == want
        assert asyncio.run(_access.gate_record(
            hub, {"u": _user_session("a")}, _FakeRequest("u"), rec, "nac", ["ip"])) == want
