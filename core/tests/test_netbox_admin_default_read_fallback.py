"""Read-side counterpart to ``test_netbox_admin_default_tenant_link.py``.

That fix taught the NetBox *write* guard (``_enforce_body_tenant``) that the
built-in Admin tenant ("default") maps to NetBox's real "default" tenant when
no ``netbox_tenant_slug`` is configured. But every *read* path that resolves a
tenant to its NetBox scope went through ``netbox_tenant_scope`` /
``fetch_tenant_prefixes`` directly, which had no equivalent fallback: viewing
the IPAM screen (or discovering devices) while "in" the Admin tenant resolved
to "no tenant filter" (``tenant=None``) instead of "the default tenant" —  so
DHCP/ARP-discovered addresses that the write path correctly stamped
``tenant=default`` onto never matched Admin's own prefixes during
attribution, and silently vanished (dropped, or attributed to some other
tenant whose prefix happened to be broader).

This locks in the fallback in all three functions: ``netbox_tenant_scope``,
``fetch_tenant_prefixes``, and ``attribute_by_prefix`` (which must consider
the Admin tenant a candidate even when tenant_state has no explicit "default"
record at all — the common case, since ``/setup/tenants`` only synthesizes it
for display).
"""
import pytest

import access
from access import (
    ADMIN_TENANT_ID,
    attribute_by_prefix,
    fetch_tenant_prefixes,
    netbox_tenant_scope,
)
from _fakes import FakeState


class _FakeHub:
    def __init__(self, tenants=None, prefixes_by_tenant=None):
        self.state = FakeState(tenants=tenants or {})
        self._prefixes_by_tenant = prefixes_by_tenant or {}
        self.sent_payloads = []

    def get_spoke_by_type(self, module_type):
        return "netbox-spoke-1" if module_type == "ipam" else None

    async def request_response(self, spoke_id, command, payload, timeout=30.0):
        self.sent_payloads.append(payload)
        slug = payload.get("tenant")
        prefixes = self._prefixes_by_tenant.get(slug, [])
        return {"payload": {"data": {"status": "SUCCESS",
                                     "prefixes": [{"prefix": p} for p in prefixes]}}}

    def warm_get(self, *a, **k):
        return None


def test_netbox_tenant_scope_falls_back_to_literal_default_for_admin_tenant():
    hub = _FakeHub()  # no tenant record at all for "default"
    scope = netbox_tenant_scope(hub, ADMIN_TENANT_ID)
    assert scope["tenant"] == "default"
    assert scope["tenant_group"] is None
    assert scope["slugs"] == ["default"]
    assert scope["key"] == "default"


def test_netbox_tenant_scope_respects_explicit_slug_override_for_admin():
    hub = _FakeHub(tenants={"default": {"netbox_tenant_slug": "global-admin"}})
    scope = netbox_tenant_scope(hub, ADMIN_TENANT_ID)
    assert scope["tenant"] == "global-admin"


def test_netbox_tenant_scope_other_tenants_unaffected_when_unconfigured():
    # A regular (non-Admin) tenant with no netbox_tenant_slug still resolves
    # to "no scope" — the Admin fallback must not leak to other tenants.
    hub = _FakeHub(tenants={"acme": {"name": "Acme"}})
    scope = netbox_tenant_scope(hub, "acme")
    assert scope["tenant"] is None
    assert scope["key"] == "_all_"


@pytest.mark.asyncio
async def test_fetch_tenant_prefixes_sends_literal_default_slug_for_admin():
    hub = _FakeHub(prefixes_by_tenant={"default": ["10.20.0.0/24"]})
    prefixes = await fetch_tenant_prefixes(hub, ADMIN_TENANT_ID)
    assert prefixes == ["10.20.0.0/24"]
    assert hub.sent_payloads[-1] == {"tenant": "default"}


@pytest.mark.asyncio
async def test_attribute_by_prefix_matches_admin_tenant_prefix_without_explicit_record():
    # tenant_state carries only "acme" -- "default" has no record (the common
    # out-of-the-box shape) -- yet an Admin-owned NetBox prefix exists and
    # must still claim a matching IP instead of dropping it.
    hub = _FakeHub(
        tenants={"acme": {"name": "Acme", "netbox_tenant_slug": "acme"}},
        prefixes_by_tenant={"acme": ["10.30.0.0/24"], "default": ["10.20.0.0/24"]},
    )
    records = [{"ip": "10.20.0.5"}, {"ip": "10.30.0.9"}, {"ip": "10.99.0.1"}]
    buckets, dropped = await attribute_by_prefix(hub, records)
    assert buckets[ADMIN_TENANT_ID] == [{"ip": "10.20.0.5"}]
    assert buckets["acme"] == [{"ip": "10.30.0.9"}]
    assert dropped == 1  # 10.99.0.1 matches no tenant's prefix


@pytest.mark.asyncio
async def test_attribute_by_prefix_does_not_duplicate_explicit_default_record():
    # If "default" DOES have an explicit tenant_state record, it must be used
    # as-is (not appended a second time) and still resolve correctly.
    hub = _FakeHub(
        tenants={ADMIN_TENANT_ID: {"netbox_tenant_slug": "global-admin"}},
        prefixes_by_tenant={"global-admin": ["10.20.0.0/24"]},
    )
    records = [{"ip": "10.20.0.5"}]
    buckets, dropped = await attribute_by_prefix(hub, records)
    assert buckets[ADMIN_TENANT_ID] == [{"ip": "10.20.0.5"}]
    assert dropped == 0
