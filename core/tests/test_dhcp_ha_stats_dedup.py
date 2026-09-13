"""DHCPSpoke._ha_stats — HA fan-out subnet dedup (dhcp/src/dhcp_spoke.py).

Both nodes of a Kea HA pair serve the IDENTICAL subnet4 config, so
``KEAW_STATS`` fans out to every member and each one reports the SAME
subnets back. Before this fix, ``_ha_stats`` blindly appended every member's
copy of each subnet to the merged list, so a healthy 2-node HA pair rendered
every scope TWICE in the WebUI's Overview tab (immediately after the
list_subnets/config-get fix made the subnets visible at all). This asserts
the per-subnet entries are now deduped-and-averaged by subnet_id, exactly
like the existing global-totals averaging a few lines below it.
"""
import asyncio
import os
import sys
from unittest.mock import AsyncMock

DHCP_SRC = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "dhcp", "src"))
if DHCP_SRC not in sys.path:
    sys.path.insert(0, DHCP_SRC)

import dhcp_spoke  # noqa: E402


def _make_spoke():
    spoke = dhcp_spoke.DHCPSpoke.__new__(dhcp_spoke.DHCPSpoke)
    spoke._transport = AsyncMock()
    return spoke


def test_ha_stats_dedups_identical_subnets_reported_by_every_member():
    spoke = _make_spoke()
    spoke._transport.fanout.return_value = {
        "results": {
            "node-a": {
                "status": "SUCCESS",
                "global": {"total_addresses": 254, "assigned_addresses": 10},
                "subnets": [{"subnet_id": 1, "subnet": "172.17.0.0/24",
                             "description": "Shared VLAN10",
                             "total_addresses": 254, "assigned_addresses": 10,
                             "declined_addresses": 0}],
            },
            "node-b": {
                "status": "SUCCESS",
                "global": {"total_addresses": 254, "assigned_addresses": 10},
                "subnets": [{"subnet_id": 1, "subnet": "172.17.0.0/24",
                             "description": "Shared VLAN10",
                             "total_addresses": 254, "assigned_addresses": 10,
                             "declined_addresses": 0}],
            },
        }
    }

    result = asyncio.get_event_loop().run_until_complete(spoke._ha_stats())

    assert len(result["subnets"]) == 1
    sub = result["subnets"][0]
    assert sub["subnet"] == "172.17.0.0/24"
    assert sub["total_addresses"] == 254
    assert sub["assigned_addresses"] == 10
    assert sub["utilization_pct"] == round(10 / 254 * 100, 1)


def test_ha_stats_keeps_distinct_subnets_reported_by_different_members():
    """A degraded/partitioned pair where only one node currently answers for
    a given scope must still surface it (not require both to agree)."""
    spoke = _make_spoke()
    spoke._transport.fanout.return_value = {
        "results": {
            "node-a": {
                "status": "SUCCESS",
                "global": {"total_addresses": 254, "assigned_addresses": 10},
                "subnets": [{"subnet_id": 1, "subnet": "172.17.0.0/24",
                             "total_addresses": 254, "assigned_addresses": 10,
                             "declined_addresses": 0}],
            },
            "node-b": {
                "status": "SUCCESS",
                "global": {"total_addresses": 126, "assigned_addresses": 2},
                "subnets": [{"subnet_id": 2, "subnet": "172.17.1.0/25",
                             "total_addresses": 126, "assigned_addresses": 2,
                             "declined_addresses": 0}],
            },
        }
    }

    result = asyncio.get_event_loop().run_until_complete(spoke._ha_stats())

    ids = sorted(s["subnet_id"] for s in result["subnets"])
    assert ids == [1, 2]
