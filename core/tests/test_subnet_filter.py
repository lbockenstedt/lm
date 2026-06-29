"""Critical path 1/4 — tenant subnet filter (server-side tenant isolation gate).

The toggle ↔ backend ↔ filter read-path wiring is the security boundary that
stops one tenant seeing another's subnet-scoped data. These tests lock in the
resolution semantics of ``access.subnet_filter_config`` / ``subnet_filter_enabled``
— the single source of truth every server-side filter reads
(``subnet_filter_enabled`` → ``subnet_filter_config`` → ``system_state["subnet_filter_modules"]``
merged with the defaults). The actual prefix-matching lives in
``simulations/tenant_filter.py`` and is exercised by an integration test (TODO).
"""

from access import (
    subnet_filter_config,
    subnet_filter_enabled,
    _SUBNET_FILTER_MODULES,
    _SUBNET_FILTER_DEFAULTS,
)
from _fakes import FakeHub, FakeState


def test_defaults_when_no_stored_state():
    """No stored overrides → every module resolves to its documented default
    (nac/firewall/netbox/dhcp ON, cs OFF — cs is tenant-ID-scoped, not subnet)."""
    hub = FakeHub(FakeState(system_state={}))
    cfg = subnet_filter_config(hub)
    assert set(cfg) == set(_SUBNET_FILTER_MODULES)
    for m in _SUBNET_FILTER_MODULES:
        assert cfg[m] == _SUBNET_FILTER_DEFAULTS[m]


def test_stored_override_flips_a_module():
    hub = FakeHub(FakeState(system_state={"subnet_filter_modules": {"cs": True, "firewall": False}}))
    cfg = subnet_filter_config(hub)
    assert cfg["cs"] is True           # override ON (default OFF)
    assert cfg["firewall"] is False    # override OFF (default ON)
    # untouched modules keep their defaults
    assert cfg["nac"] is _SUBNET_FILTER_DEFAULTS["nac"]
    assert cfg["netbox"] is _SUBNET_FILTER_DEFAULTS["netbox"]
    assert cfg["dhcp"] is _SUBNET_FILTER_DEFAULTS["dhcp"]


def test_subnet_filter_enabled_per_module_and_unknown():
    hub = FakeHub(FakeState(system_state={"subnet_filter_modules": {"dhcp": False}}))
    assert subnet_filter_enabled(hub, "dhcp") is False   # overridden off
    assert subnet_filter_enabled(hub, "nac") is True      # default on
    assert subnet_filter_enabled(hub, "cs") is False      # default off
    assert subnet_filter_enabled(hub, "nonexistent") is False  # unknown module → False


def test_stored_values_are_coerced_to_bool():
    """``subnet_filter_config`` bool-coerces stored values (the PUT handler
    stores real bools, but the reader must tolerate any JSON-ish value)."""
    hub = FakeHub(FakeState(system_state={"subnet_filter_modules": {"nac": 0, "firewall": 1}}))
    cfg = subnet_filter_config(hub)
    assert cfg["nac"] is False
    assert cfg["firewall"] is True


# ── Tenant-aware firewall filter (admin acting as tenant) ─────────────────────
#
# subnet_filter_fw is tenant-aware: an admin selecting a tenant via the switcher
# (explicit_tenant) is filtered by THAT tenant's prefixes — previously admins
# bypassed the filter entirely and saw every tenant's firewall data. These lock
# in both halves: explicit tenant → filter (even for admin); no explicit tenant
# → admin bypass preserved (regression guard).

import asyncio
from access import subnet_filter_fw, subnet_filter_tenant


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

    async def request_response(self, spoke_id, command, payload):
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
        {"source": "any", "destination": "any"},          # global → keep
        {"source": "8.8.8.8", "destination": "1.1.1.1"},   # both outside → drop
        {"source": "any", "destination": "10.20.0.5"},    # dst in prefix → keep
    ]}


def test_admin_with_explicit_tenant_is_filtered():
    """An admin selecting a tenant (?tenant=acme) gets that tenant's prefixes
    applied to firewall rules — the out-of-prefix rule is dropped. Without this
    path the admin bypass at access.subnet_filter_fw left all rules visible."""
    hub = _PrefixHub(FakeState(system_state={}, tenants={
        "acme": {"netbox_tenant_slug": "acme"},
    }))
    sessions = {"admin-cookie": _admin_session()}
    req = _FakeRequest("admin-cookie")
    out = asyncio.run(subnet_filter_fw(
        hub, sessions, req, _rules_env(), "rules",
        firewall_id=None, explicit_tenant="acme"))
    assert len(out["rules"]) == 2  # global + dst-in-prefix kept; 8.8.8.8→1.1.1.1 dropped


def test_admin_without_explicit_tenant_bypasses():
    """Regression guard: an admin with no selected tenant still sees everything
    (the switcher wasn't used) — the legacy admin bypass is preserved."""
    hub = _PrefixHub(FakeState(system_state={}, tenants={
        "acme": {"netbox_tenant_slug": "acme"},
    }))
    sessions = {"admin-cookie": _admin_session()}
    req = _FakeRequest("admin-cookie")
    env = _rules_env()
    out = asyncio.run(subnet_filter_fw(
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
    out = asyncio.run(subnet_filter_fw(
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
    out = asyncio.run(subnet_filter_fw(
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
    out = asyncio.run(subnet_filter_fw(
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
    out = asyncio.run(subnet_filter_fw(
        hub, sessions, req, aliases, "aliases", firewall_id=None, explicit_tenant="acme"))
    assert [a["name"] for a in out["data"]] == []


# ── Hypervisor VM filter (tenant-aware, admin acting as tenant) ────────────────
#
# /api/pxmx/vms previously had NO subnet filter at all — an admin saw every
# tenant's VMs. The route now applies subnet_filter_tenant (module "hypervisor",
# ip_fields ["ips"]) on all three return paths so an admin selecting a tenant
# sees only that tenant's VMs. These lock in the admin-as-tenant filter and the
# legacy admin bypass when no tenant is selected.

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
    out = asyncio.run(subnet_filter_tenant(
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
    out = asyncio.run(subnet_filter_tenant(
        hub, sessions, req, env, "hypervisor", ["ips"]))
    assert out is env  # unchanged — all 3 VMs visible


def test_hypervisor_module_in_toggle_set_and_default_on():
    """The 'hypervisor' module is registered in the subnet-filter toggle set
    and defaults ON (VM IPs are tenant-scoped data)."""
    from access import _SUBNET_FILTER_MODULES, _SUBNET_FILTER_DEFAULTS
    assert "hypervisor" in _SUBNET_FILTER_MODULES
    assert _SUBNET_FILTER_DEFAULTS["hypervisor"] is True