"""Strict DHCPv4 lease reads: a failed read is an ERROR, never "no leases".

The hub's static-IP reservation pass must tell "this host holds no lease" from
"Kea could not be read", so ``DHCP_LIST_LEASES {"strict": true}`` surfaces
failures and echoes ``strict`` only when every node honoured it.
"""

import asyncio

import pytest

from dhcp_spoke import DHCPSpoke
from dhcp_worker import DhcpWorkerOps
from kea_manager import KeaManager

LEASE = {"ip-address": "10.20.0.60", "hw-address": "02:00:00:00:00:0a"}


def _mgr(monkeypatch, fail=False):
    """A KeaManager whose config/RPC calls are canned (or fail)."""
    mgr = KeaManager()

    def _get_config():
        """Running config with one subnet, or a failure."""
        if fail:
            raise RuntimeError("kea unreachable")
        return {"subnet4": [{"id": 1, "subnet": "10.20.0.0/24"}]}

    def _rpc(*_args, **_kwargs):
        """Lease RPC reply, or a failure."""
        if fail:
            raise RuntimeError("kea unreachable")
        return {"leases": [LEASE]}

    monkeypatch.setattr(mgr, "get_config", _get_config)
    monkeypatch.setattr(mgr, "_rpc", _rpc)
    return mgr


def test_manager_strict_raises_but_default_still_returns_empty(monkeypatch):
    mgr = _mgr(monkeypatch, fail=True)
    assert mgr.list_leases() == []
    with pytest.raises(RuntimeError):
        mgr.list_leases(strict=True)
    assert _mgr(monkeypatch).list_leases(strict=True) == [LEASE]


def test_worker_strict_reply_errors_or_echoes_strict(monkeypatch):
    bad = DhcpWorkerOps(_mgr(monkeypatch, fail=True)).list_leases({"strict": True})
    assert bad["status"] == "ERROR"
    good = DhcpWorkerOps(_mgr(monkeypatch)).list_leases({"strict": True})
    assert good == {"status": "SUCCESS", "leases": [LEASE], "strict": True}
    # Without strict the old reply shape is unchanged.
    assert "strict" not in DhcpWorkerOps(_mgr(monkeypatch)).list_leases({})


class _Transport:
    """Fan-out stand-in returning canned per-node replies."""

    def __init__(self, results, members=None):
        self._results = results
        self._members = members if members is not None else list(results)

    def member_ids(self):
        """The configured HA members."""
        return list(self._members)

    async def fanout(self, command, data, timeout=20.0, member_ids=None):
        """Return the canned replies."""
        return {"results": self._results}


def _ha(results, payload, members=None):
    """Run DHCPSpoke._ha_list over canned node replies."""
    spoke = object.__new__(DHCPSpoke)
    spoke._transport = _Transport(results, members)
    return asyncio.run(spoke._ha_list("KEAW_LIST_LEASES", payload, "leases"))


def test_ha_strict_only_when_every_node_honoured_it():
    ok = {"status": "SUCCESS", "leases": [LEASE], "strict": True}
    assert _ha({"a": ok, "b": ok}, {"strict": True})["strict"] is True
    # An old worker that ignores strict, or a failed node, is not strict.
    old = {"status": "SUCCESS", "leases": []}
    assert _ha({"a": ok, "b": old}, {"strict": True})["strict"] is False
    down = {"status": "ERROR", "message": "lease read failed"}
    reply = _ha({"a": ok, "b": down}, {"strict": True})
    assert reply["strict"] is False and reply["member_errors"]
    # A configured member missing from the fan-out results is not strict.
    reply = _ha({"a": ok}, {"strict": True}, members=["a", "b"])
    assert reply["strict"] is False and reply["member_errors"] == {"b": "no response"}
    # Non-strict callers see no new key.
    assert "strict" not in _ha({"a": ok}, {})


def test_subnet_reads_are_strict_on_request(monkeypatch):
    """``KEAW_LIST_SUBNETS {"strict": true}`` errors instead of reading an
    unreachable Kea as "no subnets" (the hub needs real pools)."""
    mgr = _mgr(monkeypatch, fail=True)
    assert mgr.list_subnets() == []
    with pytest.raises(RuntimeError):
        mgr.list_subnets(strict=True)
    assert DhcpWorkerOps(mgr).list_subnets({"strict": True})["status"] == "ERROR"
    good = DhcpWorkerOps(_mgr(monkeypatch)).list_subnets({"strict": True})
    assert good["status"] == "SUCCESS" and good["strict"] is True and good["subnets"]
    assert "strict" not in DhcpWorkerOps(_mgr(monkeypatch)).list_subnets({})


def test_ha_strict_needs_a_real_list_from_every_node():
    """A strict SUCCESS reply whose list is missing, null or not a list is a
    failed node, not an empty Kea."""
    ok = {"status": "SUCCESS", "leases": [LEASE], "strict": True}
    for bad in ({"status": "SUCCESS", "strict": True},
                {"status": "SUCCESS", "strict": True, "leases": None},
                {"status": "SUCCESS", "strict": True, "leases": "x"}):
        reply = _ha({"a": ok, "b": bad}, {"strict": True})
        assert reply["strict"] is False
        assert reply["member_errors"] == {"b": "no leases list"}
        assert reply["leases"] == [LEASE]
    # Both nodes with an honest empty list stay strict.
    empty = {"status": "SUCCESS", "leases": [], "strict": True}
    assert _ha({"a": empty, "b": empty}, {"strict": True})["strict"] is True
