"""Tenant ids are compared as stored, never stripped first.

Two tenants can be stored as legacy twins that differ only by surrounding
spaces ("ACME" and " ACME "), and access then matches each by its exact
spelling (_AMBIGUOUS_TENANT_IDS). A gate that stripped a stored grant,
binding or owner before comparing turned " ACME " into "ACME", so one twin
passed the other's ownership checks. These tests hold every converted site
to the exact spelling while twins exist, and to the canonical compare
(any case or spaces) while they don't.
"""
from types import SimpleNamespace

import pytest

import access
import cert_distribution
import henet_sync
from hub_identity import HubIdentityMixin
from hub_vnc_console import HubVncConsoleMixin


@pytest.fixture(autouse=True)
def _twins(monkeypatch):
    """"ACME" and " ACME " are both stored, so each is matched exactly."""
    monkeypatch.setattr(access, "_AMBIGUOUS_TENANT_IDS", frozenset({"acme"}))
    monkeypatch.setattr(access, "_SHARED_TENANT_ID", None)
    monkeypatch.setattr(access, "_GROUP_MEMBERS", {})


def _tenant_admin(*tenants):
    """A tenant admin's session granted ``tenants``."""
    return {"user": {"user_id": "u", "tenants": list(tenants), "tenant_id": tenants[0],
                     "permissions": {"role": "tenant_admin"}}}


class _Store:
    """Every hypervisor is opted into tenant-admin console access."""

    async def get_hypervisors_config(self, _tenant):
        return {"tenant_console_enabled": True}


def _hub(bindings=None, **system_state):
    """A hub whose spokes are bound as ``bindings`` (spoke id -> tenant)."""
    bindings = bindings or {}
    state = SimpleNamespace(get_spoke_tenant=lambda sid: bindings.get(sid, ""),
                            system_state=system_state)
    return SimpleNamespace(state=state, simulations_store=_Store())


@pytest.mark.parametrize("user, own, other", [
    (" ACME ", "s2", "s1"),
    ("ACME", "s1", "s2"),
])
async def test_hypervisor_gates_tell_padded_twins_apart(user, own, other):
    """A host bound to one twin is never owned, consoled or controlled by the
    other twin's tenant admin."""
    hub = _hub({"s1": "ACME", "s2": " ACME "})
    sess = _tenant_admin(user)
    assert access.hypervisor_owned_by_caller(hub, sess, own)
    assert not access.hypervisor_owned_by_caller(hub, sess, other)
    assert await access.tenant_admin_console_allowed(hub, sess, own)
    assert not await access.tenant_admin_console_allowed(hub, sess, other)
    assert await access.vm_in_tenant_scope(hub, sess, {"tags": []}, own)
    assert not await access.vm_in_tenant_scope(hub, sess, {"tags": []}, other)


def _instances(*tenants):
    """DNS instance records on spoke "s", one per tenant."""
    return {"global_config": {"dns_instances": [
        {"spoke_id": "s", "tenant_id": t} for t in tenants]}}


def test_source_owner_keeps_the_stored_spelling():
    """A padded owner is its own tenant, two twins on one spoke make it
    shared, and spellings of one tenant without a twin still name it."""
    assert access.source_owner_tenant(_hub(**_instances(" ACME ")), "s") == " ACME "
    assert access.source_owner_tenant(_hub(**_instances(" ACME ", "ACME")), "s") is None
    got = access.source_owner_tenant(_hub(**_instances("other", "OTHER")), "s")
    assert access.same_tenant(got, "other")
    fw = {"global_config": {"firewalls": [{"id": "fw1", "tenant_id": " ACME "}]}}
    assert access.firewall_owner_tenant(_hub(**fw), "fw1") == " ACME "


def test_directory_groups_grant_the_stored_tenant():
    """A group granting " ACME " never grants its twin "ACME"."""
    hub = _hub(permission_groups={
        "g1": {"ldap_group": "cn=ops", "tenants": [" ACME "]},
        "g2": {"ldap_group": "cn=net", "tenants": ["ACME"]}})
    assert access.groups_and_tenants_for_membership(hub, ["CN=ops"]) == (["g1"], [" ACME "])
    assert access.groups_and_tenants_for_membership(hub, ["cn=ops", "cn=net"]) == (
        ["g1", "g2"], [" ACME ", "ACME"])


def test_cert_target_owner_is_the_stored_tenant():
    """A cert target on a spoke or node bound to " ACME " belongs to it."""
    spoke_tenant = {"fw-spoke": " ACME "}.get
    fw = {"module_type": "firewall", "spoke_id": "fw-spoke"}
    assert cert_distribution.target_owner_tenant(fw, spoke_tenant, lambda a: "") == " ACME "
    node = {"module_type": "hypervisor", "agent_id": "node1"}
    assert cert_distribution.target_owner_tenant(
        node, lambda s: "", lambda a: "", agent_tenant={"node1": " ACME "}.get) == " ACME "


def test_henet_slot_is_the_tenants_own():
    """A twin never borrows the other twin's HE.NET login; another case of a
    tenant without a twin finds that tenant's slot."""
    acme, other = {"bucket": "b", "name": "acme"}, {"bucket": "b", "name": "other"}
    hub = _hub(global_config={"henet": {"tenant_credentials": {"ACME": acme, "other": other}}})
    assert henet_sync.cred_ref_for_scope(hub, "ACME") == acme
    assert henet_sync.cred_ref_for_scope(hub, " ACME ") is None
    assert henet_sync.cred_ref_for_scope(hub, "OTHER") == other


async def test_console_probe_claim_resolves_to_the_stored_tenant(monkeypatch):
    """A probe from a shared console spoke may claim a tenant only when the
    device IP is in that tenant's prefixes, and a twin's claim never takes
    the other twin's attribution."""
    async def _attr(_hub, _records):
        return {"ACME": [{}], "Other": [{}]}, []
    monkeypatch.setattr(access, "attribute_by_prefix", _attr)
    hub = SimpleNamespace(state=SimpleNamespace(get_spoke_tenant=lambda sid: ""))
    probe = HubVncConsoleMixin._authorized_probe_tenant
    assert await probe(hub, "con-1", " ACME ", "10.0.0.5") == ""
    assert await probe(hub, "con-1", "ACME", "10.0.0.5") == "ACME"
    assert await probe(hub, "con-1", "other", "10.0.0.5") == "Other"


@pytest.mark.parametrize("old, new, collision", [
    ("ACME", " ACME ", True),
    ("other", "OTHER", True),
    ("ACME", "ACME", False),
])
def test_uuid_claim_across_spellings_fails_closed(old, new, collision):
    """Two ids on one install uuid bound to tenants spelt differently are a
    cross-tenant clone claim: compared exactly, so no key is handed over."""
    bindings = {"old-id": old, "new-id": new}
    hub = SimpleNamespace(_primary_key=lambda s: s, active_connections={},
                          state=SimpleNamespace(get_spoke_last_seen=dict,
                                                get_spoke_tenant=bindings.get))
    assert HubIdentityMixin._is_uuid_collision(hub, "old-id", "new-id") is collision


@pytest.mark.parametrize("fetched", [True, False])
async def test_dedicated_owner_naming_neither_twin_is_dropped(monkeypatch, fetched):
    """A dedicated spoke's owner tag goes to the stored tenant it names; a
    third spelling of the twins (" ACME", "Acme") names neither and is
    dropped, since bucketed under its own spelling get_tenant would find
    "ACME" and two replace=True pushes would delete each other's devices.
    An unknown tenant keeps its own spelling, as before. ``fetched`` False:
    no prefixes were fetched, so every owner takes the stored-id lookup."""
    import ipaddress
    nets = {t: [ipaddress.ip_network("10.1.0.0/16")] for t in ("ACME", " ACME ", "default")}

    async def _networks(_hub):
        return nets if fetched else {}

    monkeypatch.setattr(access, "_tenant_networks", _networks)
    state = SimpleNamespace(tenant_state={"tenants": {"ACME": {}, " ACME ": {}}})
    owners = ["ACME", " ACME ", " ACME", "Acme", "ghost"]
    records = [{"ip": f"10.1.0.{i}", "owner_tenant_id": o} for i, o in enumerate(owners, 5)]
    buckets, dropped = await access.attribute_by_prefix(SimpleNamespace(state=state), records)
    assert {t: [r["ip"] for r in rs] for t, rs in buckets.items()} == {
        "ACME": ["10.1.0.5"], " ACME ": ["10.1.0.6"], "ghost": ["10.1.0.9"]}
    assert dropped == 2


async def test_a_deleted_twins_owner_tag_is_dropped(monkeypatch):
    """A record a dedicated spoke still owns as the deleted twin "ACME"
    (retired beside the surviving "acme") is dropped, not bucketed for the
    survivor, whose replace=True push would take the deleted tenant's
    devices."""
    async def _no_networks(_hub):
        """No tenant prefixes fetched, so the owner takes the stored-id lookup."""
        return {}

    monkeypatch.setattr(access, "_tenant_networks", _no_networks)
    state = SimpleNamespace(tenant_state={"tenants": {"acme": {}}, "retired_twin_ids": ["ACME"]})
    records = [{"ip": "10.1.0.5", "owner_tenant_id": "ACME"},
               {"ip": "10.1.0.6", "owner_tenant_id": "acme"}]
    buckets, dropped = await access.attribute_by_prefix(SimpleNamespace(state=state), records)
    assert {t: [r["ip"] for r in rs] for t, rs in buckets.items()} == {"acme": ["10.1.0.6"]}
    assert dropped == 1


def test_directory_ou_is_the_twins_own():
    """Each twin gets its own directory OU (the Directory routes, the LDAP
    cache feed, OU provisioning and the dot1x accounts use it). Stripped
    first, " ACME " got "ACME"'s OU, so its admin read and wrote ACME's
    directory users."""
    from _fakes import FakeState, bind_state_tenant_lookups
    hub = SimpleNamespace(state=bind_state_tenant_lookups(FakeState(tenants={
        "ACME": {"netbox_tenant_slug": "acme"},
        " ACME ": {"netbox_tenant_slug": "acme-old"}})))
    assert access.ldap_tenant_slug(hub, " ACME ") == "acme-old"
    assert access.ldap_tenant_slug(hub, "ACME") == "acme"
    assert access.ldap_tenant_slug(hub, "   ") == ""
