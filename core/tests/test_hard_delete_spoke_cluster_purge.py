"""Tests for the ghost-member cleanup added to ``hard_delete_spoke``
(routes/setup.py): deleting a spoke that is (or was) a member of a Kea HA
pair / DNS resolver cluster on another, still-connected DHCP/DNS spoke used
to leave that id in the surviving node's persisted cluster config forever —
diagnostics/HA-status kept reporting it as a permanently unreachable "ghost"
member with no UI action able to clear it, even after the underlying agent
was fully removed via Force Delete.

``hard_delete_spoke`` now best-effort asks every OTHER connected DHCP/DNS
spoke whether it lists the deleted id as a member and, if so, re-declares its
topology without that id — using the exact same *_HA_STATUS/*_CLUSTER_STATUS
read + *_HA_CONFIG/*_CLUSTER_CONFIG write RPCs the Edit Cluster UI already
uses, so no new spoke-side surface is introduced.
"""

from types import SimpleNamespace

import pytest

from routes.setup import hard_delete_spoke


class _FakeMailbox:
    async def clear_spoke(self, pk):
        return None


class _FakeKeyManager:
    def delete_spoke_key(self, pk):
        return None


class _FakeState:
    def __init__(self):
        self.removed = []

    def remove_module(self, spoke_id):
        self.removed.append(spoke_id)


class _FakeHub:
    """Minimal hub: one DHCP spoke (member of a 2-node HA pair including the
    spoke being deleted) and one DNS spoke (does NOT reference the deleted
    id at all — must be left untouched)."""

    def __init__(self):
        self.active_connections = {}
        self.approved_modules = {}
        self.state = _FakeState()
        self.key_manager = _FakeKeyManager()
        self.mailbox = _FakeMailbox()
        self.spoke_module_types = {"kea-node-1": "dhcp", "dns-node-1": "dns"}
        self.dhcp_config_calls = []
        self.dns_config_calls = []

    def _primary_key(self, spoke_id):
        return spoke_id

    def _evict_spoke(self, spoke_id):
        return None

    def get_all_spokes_by_type(self, module_type):
        return [sid for sid, mt in self.spoke_module_types.items()
                if mt == module_type]

    async def request_response(self, spoke_id, cmd, payload, timeout=None,
                               signing_secret=None):
        if spoke_id == "kea-node-1":
            if cmd == "DHCP_HA_STATUS":
                return {"payload": {"data": {"status": "SUCCESS", "members": [
                    {"id": "kea-node-1", "host": "10.0.0.1"},
                    {"id": "removed-spoke", "host": "10.0.0.2"},
                ]}}}
            if cmd == "DHCP_HA_CONFIG":
                self.dhcp_config_calls.append(payload)
                return {"payload": {"data": {"status": "SUCCESS"}}}
        if spoke_id == "dns-node-1":
            if cmd == "DNS_CLUSTER_STATUS":
                return {"payload": {"data": {"status": "SUCCESS", "members": [
                    {"id": "dns-node-1", "host": "10.0.0.3"},
                ]}}}
            if cmd == "DNS_CLUSTER_CONFIG":
                self.dns_config_calls.append(payload)
                return {"payload": {"data": {"status": "SUCCESS"}}}
        raise AssertionError(f"unexpected call: {spoke_id} {cmd}")


@pytest.mark.asyncio
async def test_hard_delete_spoke_purges_ghost_member_from_dhcp_cluster():
    hub = _FakeHub()
    await hard_delete_spoke(hub, "removed-spoke")

    assert len(hub.dhcp_config_calls) == 1
    remaining_ids = {m["id"] for m in hub.dhcp_config_calls[0]["members"]}
    assert remaining_ids == {"kea-node-1"}
    # The DNS cluster never referenced the deleted spoke — must not be
    # rewritten at all.
    assert hub.dns_config_calls == []
    assert hub.state.removed == ["removed-spoke"]


@pytest.mark.asyncio
async def test_hard_delete_spoke_skips_clusters_without_membership():
    hub = _FakeHub()
    # Deleting a spoke no cluster references should touch neither DHCP nor
    # DNS config RPCs.
    await hard_delete_spoke(hub, "some-unrelated-agent")

    assert hub.dhcp_config_calls == []
    assert hub.dns_config_calls == []


@pytest.mark.asyncio
async def test_hard_delete_spoke_purge_failure_does_not_block_delete():
    class _FailingHub(_FakeHub):
        async def request_response(self, spoke_id, cmd, payload, timeout=None,
                                    signing_secret=None):
            raise RuntimeError("spoke unreachable")

    hub = _FailingHub()
    # Must not raise even though every cluster RPC fails — the delete itself
    # (state.remove_module) still has to complete.
    await hard_delete_spoke(hub, "removed-spoke")
    assert hub.state.removed == ["removed-spoke"]
