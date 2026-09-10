"""DNS Management must never fall back to a local Unbound service."""
import os
import sys

import pytest


DNS_SRC = os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", "..", "dns", "src"))
if DNS_SRC not in sys.path:
    sys.path.insert(0, DNS_SRC)

from dns_cluster import DnsClusterCoordinator  # noqa: E402
from dns_spoke import DNSSpoke  # noqa: E402


class _Transport:
    def __init__(self, members):
        self._members = members

    def member_ids(self):
        return list(self._members)


class _Desired:
    broken = ""

    def snapshot(self):
        return {"record_count": 0}


class _Cluster:
    enabled = False
    state_error = ""


def test_one_dns_server_worker_enables_remote_management():
    cluster = DnsClusterCoordinator(_Transport(["dns-1"]), _Desired())
    assert cluster.enabled is True


@pytest.mark.asyncio
async def test_management_without_workers_never_calls_local_unbound():
    spoke = DNSSpoke.__new__(DNSSpoke)
    spoke.spoke_id = "dns-management"
    spoke.cluster = _Cluster()
    spoke.desired = _Desired()

    result = await spoke.handle_command("DNS_STATUS", {})
    assert result == {
        "status": "ERROR",
        "message": ("No DNS Server workers configured. Install the DNS Server "
                    "role and add it to DNS Management."),
    }

    status = await spoke.get_status()
    assert status["unbound"] == "not-configured"
    assert status["status"] == "DEGRADED"
