"""DNS Management must never fall back to a local Unbound service."""
import os
import sys
from pathlib import Path

import pytest


DNS_SRC = os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", "..", "dns", "src"))
if DNS_SRC not in sys.path:
    sys.path.insert(0, DNS_SRC)

from dns_cluster import DnsClusterCoordinator, DnsDesiredState  # noqa: E402
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


@pytest.mark.asyncio
async def test_discovered_worker_gets_ephemeral_bootstrap(tmp_path, monkeypatch):
    cert = tmp_path / "coordinator.crt"
    cert.write_text(
        "-----BEGIN CERTIFICATE-----\npublic\n-----END CERTIFICATE-----\n")

    class _Plane:
        _listener_cert = str(cert)

        def snapshot_agent_secret(self):
            return "stored-worker-secret"

    spoke = DNSSpoke.__new__(DNSSpoke)
    spoke.control_plane = _Plane()
    spoke._transport = type("_Members", (), {"members": []})()

    class _Transaction:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

    spoke.cluster = type(
        "_Cluster", (), {"transaction": lambda self: _Transaction()})()

    async def _apply(members, data, *, defer_seed=False):
        assert defer_seed is True
        spoke._transport.members = members
        return {"status": "SUCCESS"}

    spoke._apply_cluster_config_locked = _apply
    monkeypatch.setattr("dns_spoke.socket.getfqdn",
                        lambda: "dns-management.example")

    result = await spoke.handle_command("DNS_CLUSTER_ENROLL_WORKER", {
        "member": {"id": "dns-a", "host": "10.0.0.11"},
    })

    assert result["status"] == "SUCCESS"
    assert result["worker_secret"] == "stored-worker-secret"
    assert result["coordinator"] == "dns-management.example"
    assert "BEGIN CERTIFICATE" in result["coordinator_ca_pem"]
    assert spoke._transport.members[0]["id"] == "dns-a"


@pytest.mark.asyncio
async def test_dns_mutations_fail_closed_until_enrollment_adopts_worker_records():
    spoke = DNSSpoke.__new__(DNSSpoke)
    spoke.cluster = type("_Cluster", (), {"enabled": True})()
    spoke.desired = type("_Desired", (), {"version": 0})()

    result = await spoke.handle_command("DNS_ADD", {
        "name": "host.example", "value": "10.0.0.5",
    })

    assert result["status"] == "ERROR"
    assert result["initializing"] is True


@pytest.mark.asyncio
async def test_enrollment_seed_requires_state_from_every_worker(tmp_path):
    class _PartialTransport:
        def member_ids(self):
            return ["dns-a", "dns-b"]

        async def fanout(self, command, data, timeout=15.0):
            return {
                "results": {
                    "dns-a": {"status": "SUCCESS", "records": []},
                    "dns-b": {"status": "ERROR", "message": "timeout"},
                },
            }

    desired = DnsDesiredState(str(tmp_path / "desired.json"))
    cluster = DnsClusterCoordinator(_PartialTransport(), desired)

    result = await cluster.seed([], require_all_members=True)

    assert result["status"] == "ERROR"
    assert result["failed_members"] == ["dns-b"]
    assert desired.version == 0
