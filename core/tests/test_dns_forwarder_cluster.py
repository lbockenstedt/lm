"""Cluster-level DNS forwarder write and rollback behavior."""

import asyncio
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "dns" / "src"))
sys.path.insert(0, str(ROOT / "core" / "src"))

from dns_spoke import DNSSpoke  # noqa: E402


class FakeTransport:
    def __init__(self, add_result):
        self.add_result = add_result
        self.calls = []

    async def fanout(self, command, data, timeout=20.0, member_ids=None):
        self.calls.append((command, data, member_ids))
        if command == "DNSW_FORWARDER_ADD":
            return self.add_result
        targets = list(member_ids or [])
        return {
            "status": "SUCCESS",
            "results": {member: {"status": "SUCCESS"} for member in targets},
            "ok": targets,
            "failed": [],
        }


def _spoke(add_result):
    spoke = DNSSpoke.__new__(DNSSpoke)
    spoke._transport = FakeTransport(add_result)
    return spoke


def test_duplicate_rejection_does_not_remove_existing_forwarder():
    spoke = _spoke({
        "status": "ERROR",
        "results": {
            "dns-a": {
                "status": "ERROR",
                "message": "forwarder zone . already exists",
                "changed": False,
            },
        },
        "ok": [],
        "failed": ["dns-a"],
    })

    result = asyncio.run(spoke._cluster_add_forwarder(
        {"zone": ".", "upstreams": ["1.1.1.1"]}))

    assert result["status"] == "ERROR"
    assert [call[0] for call in spoke._transport.calls] == [
        "DNSW_FORWARDER_ADD",
    ]


def test_partial_add_rolls_back_success_and_ambiguous_timeout():
    spoke = _spoke({
        "status": "PARTIAL",
        "results": {
            "dns-a": {"status": "SUCCESS", "changed": True},
            "dns-b": {"status": "ERROR", "message": "response timeout"},
            "dns-c": {"status": "ERROR", "message": "invalid", "changed": False},
        },
        "ok": ["dns-a"],
        "failed": ["dns-b", "dns-c"],
    })

    result = asyncio.run(spoke._cluster_add_forwarder(
        {"zone": ".", "upstreams": ["1.1.1.1"]}))

    assert result["status"] == "ERROR"
    assert spoke._transport.calls[1] == (
        "DNSW_FORWARDER_REMOVE",
        {"zone": "."},
        ["dns-a", "dns-b"],
    )
