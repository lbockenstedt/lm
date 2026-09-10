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


class FakeListTransport:
    """Canned ``DNSW_FORWARDERS`` fanout reply, one member per entry."""

    def __init__(self, results):
        self.results = results

    async def fanout(self, command, data, timeout=20.0, member_ids=None):
        assert command == "DNSW_FORWARDERS"
        ok = [m for m, r in self.results.items()
              if isinstance(r, dict) and r.get("status") == "SUCCESS"]
        failed = [m for m in self.results if m not in ok]
        return {"status": "SUCCESS" if not failed else ("PARTIAL" if ok else "ERROR"),
                "results": self.results, "ok": ok, "failed": failed}


def _list_spoke(results):
    spoke = DNSSpoke.__new__(DNSSpoke)
    spoke._transport = FakeListTransport(results)
    return spoke


class StatefulTransport:
    """Round-trips a real add through to a real list for N members, so the
    success path (not just the failure/rollback paths the tests above cover)
    has a regression test. Each member keeps its own forwarder list, mirroring
    one Unbound instance per cluster member."""

    def __init__(self, member_ids):
        self.member_ids = list(member_ids)
        self.state = {m: [] for m in member_ids}

    async def fanout(self, command, data, timeout=20.0, member_ids=None):
        targets = list(member_ids) if member_ids is not None else self.member_ids
        results = {}
        for m in targets:
            if command == "DNSW_FORWARDER_ADD":
                zone, upstreams = data["zone"], data["upstreams"]
                if any(f["zone"] == zone for f in self.state[m]):
                    results[m] = {"status": "ERROR",
                                  "message": f"forwarder zone {zone} already exists",
                                  "changed": False}
                    continue
                self.state[m].append({"zone": zone, "class": "IN", "upstreams": upstreams})
                results[m] = {"status": "SUCCESS", "reloaded": True, "changed": True}
            elif command == "DNSW_FORWARDERS":
                results[m] = {"status": "SUCCESS", "forwarders": list(self.state[m])}
            elif command == "DNSW_FORWARDER_REMOVE":
                zone = data["zone"]
                self.state[m] = [f for f in self.state[m] if f["zone"] != zone]
                results[m] = {"status": "SUCCESS", "changed": True}
        ok = [m for m, r in results.items() if r.get("status") == "SUCCESS"]
        failed = [m for m in targets if m not in ok]
        status = "SUCCESS" if not failed else ("PARTIAL" if ok else "ERROR")
        return {"status": status, "results": results, "ok": ok, "failed": failed}


def test_successful_add_is_visible_in_the_very_next_list_for_every_member():
    """The success round trip other tests here never exercised: add a
    forwarder to a healthy 2-member cluster, then list — both members must
    report it, with no ``member_errors``."""
    spoke = DNSSpoke.__new__(DNSSpoke)
    spoke._transport = StatefulTransport(["dns-a", "dns-b"])

    add_result = asyncio.run(spoke._cluster_add_forwarder(
        {"zone": ".", "upstreams": ["8.8.8.8", "8.8.4.4"]}))
    assert add_result["status"] == "SUCCESS"

    list_result = asyncio.run(spoke._cluster_forwarders())
    assert list_result["status"] == "SUCCESS"
    assert list_result["member_errors"] == {}
    zones_by_member = {f["member_id"]: f["zone"] for f in list_result["forwarders"]}
    assert zones_by_member == {"dns-a": ".", "dns-b": "."}


def test_list_surfaces_member_errors_without_dropping_healthy_members_silently():
    """Regression for the WebUI gap: dns_spoke.py already buckets a member
    that failed to answer DNSW_FORWARDERS into ``member_errors`` rather than
    just shrinking ``forwarders`` — pin that contract so the newly-added
    WebUI rendering of ``member_errors`` has something real to depend on."""
    spoke = _list_spoke({
        "dns-a": {"status": "SUCCESS",
                  "forwarders": [{"zone": ".", "class": "IN", "upstreams": ["8.8.8.8"]}]},
        "dns-b": {"status": "ERROR", "message": "response timeout"},
    })

    result = asyncio.run(spoke._cluster_forwarders())

    assert result["status"] == "SUCCESS"  # degraded, not surfaced as a hard error
    assert [f["member_id"] for f in result["forwarders"]] == ["dns-a"]
    assert result["member_errors"] == {"dns-b": "response timeout"}


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
