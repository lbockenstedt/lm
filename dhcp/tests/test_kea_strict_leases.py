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

    def __init__(self, results):
        self._results = results

    async def fanout(self, command, data, timeout=20.0, member_ids=None):
        """Return the canned replies."""
        return {"results": self._results}


def _ha(results, payload):
    """Run DHCPSpoke._ha_list over canned node replies."""
    spoke = object.__new__(DHCPSpoke)
    spoke._transport = _Transport(results)
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
    # Non-strict callers see no new key.
    assert "strict" not in _ha({"a": ok}, {})
