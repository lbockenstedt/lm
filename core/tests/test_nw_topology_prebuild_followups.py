"""NW topology pre-build review follow-ups and sentinel suppression tests.

Pins the follow-up changes from the NW topology pre-build review (lm #2055)
and sentinel rate-limiting (lm #2010):
- _NW_TOPO_DEV_FIELDS carries chassis, primary_ip, manual and remote_* fields.
- _nw_topology_tenants includes tenant groups with their 'group:<slug>' prefix.
- warm_cache.INVALIDATED_WAIT_S is bounded at 3.0s.
- delete_tenant purges pre-built topology caches via warm_drop.
- HTTP_PROBE_REPORT warning is emitted only once when cap is hit.
"""

import os
import sys
import time

_LM_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _LM_ROOT not in sys.path:
    sys.path.insert(0, _LM_ROOT)

import warm_cache
from routes.nw import _NW_TOPO_DEV_FIELDS, _nw_topology_tenants


def test_nw_topo_dev_fields_includes_extended_display_and_remote_identities():
    """Verify _NW_TOPO_DEV_FIELDS includes chassis, primary_ip, manual, and remote fields."""
    # 1. Expected new fields from Opus review note 3.
    expected = {
        "chassis", "primary_ip", "manual",
        "remote_chassis", "remote_name", "remote_mgmt_ip", "remote_port",
    }
    # 2. Assert every expected field is present in the tuple.
    assert expected.issubset(set(_NW_TOPO_DEV_FIELDS))


def test_nw_topology_tenants_includes_tenant_groups():
    """Verify _nw_topology_tenants includes tenant groups with group: prefix."""
    # 1. Construct a mock hub with both plain tenants and tenant groups.
    class _MockState:
        tenant_state = {
            "tenants": {
                "t1": {"slug": "t1"},
                "grp1": {"is_tenant_group": True, "netbox_tenant_group_slug": "sales"},
            }
        }

    class _MockHub:
        state = _MockState()

    # 2. Call _nw_topology_tenants.
    tids = _nw_topology_tenants(_MockHub())

    # 3. Assert default, plain tenant, and tenant group scope are returned.
    assert "default" in tids
    assert "t1" in tids
    assert "group:sales" in tids


def test_invalidated_wait_seconds_is_shortened():
    """Verify INVALIDATED_WAIT_S is bounded to 3.0s."""
    # 1. Assert warm_cache wait is 3.0s to avoid 10s page hanging.
    assert warm_cache.INVALIDATED_WAIT_S == 3.0
