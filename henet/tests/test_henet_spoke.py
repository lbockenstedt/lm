"""Dispatch + event-loop offload tests for ``HENetSpoke``.

The henet role may share one event loop with sibling sub-spokes, and the HE
dyndns push is a synchronous HTTP round-trip, so every manager call must be
offloaded via ``asyncio.to_thread``. These tests use a fake manager that records
the thread it ran on and assert (a) the command→manager dispatch + response
wrapping is correct and (b) each manager call ran in a DIFFERENT thread than the
event loop (i.e. it was offloaded, not called inline).
"""

import asyncio
import threading

import pytest

from henet_spoke import HENetSpoke


class FakeMgr:
    def __init__(self):
        self.calls = []
        self.thread_ids = []

    def _tid(self):
        self.thread_ids.append(threading.get_ident())

    def list_records(self):
        self.calls.append(("list_records",)); self._tid()
        return [{"name": "h.example.com", "type": "A", "value": "203.0.113.1", "ttl": 300}]

    def sync(self, records, ddns_key=""):
        self.calls.append(("sync", len(records), ddns_key)); self._tid()
        return {"status": "SUCCESS", "records_written": len(records), "pushed": len(records)}

    def add_record(self, name, rtype, value, ttl, ddns_key="", key=""):
        self.calls.append(("add_record", name, rtype, value, ttl, ddns_key, key)); self._tid()
        return {"status": "SUCCESS", "pushed": 1}

    def update_record(self, name, rtype, value, ttl, ddns_key="", key=""):
        self.calls.append(("update_record", name, rtype, value, ttl, ddns_key, key)); self._tid()
        return {"status": "SUCCESS", "pushed": 1}

    def delete_record(self, name, rtype=None):
        self.calls.append(("delete_record", name, rtype)); self._tid()
        return {"status": "SUCCESS", "records_written": 0}

    def status(self):
        self.calls.append(("status",)); self._tid()
        return {"reachable": True, "record_count": 1, "endpoint": "x", "state_path": "y"}


def _spoke():
    s = HENetSpoke("henet-spoke-1", {"henet_state": "/tmp/does-not-matter.json"})
    s.mgr = FakeMgr()
    return s


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def test_list_dispatch_and_offload():
    s = _spoke()
    loop_tid = threading.get_ident()
    res = _run(s.handle_command("HENET_LIST", {}))
    assert res["status"] == "SUCCESS"
    assert res["records"][0]["name"] == "h.example.com"
    assert s.mgr.thread_ids and all(t != loop_tid for t in s.mgr.thread_ids)


def test_add_passes_credential_fields():
    s = _spoke()
    _run(s.handle_command("HENET_ADD", {"name": "h.example.com", "type": "A",
                                        "value": "203.0.113.5", "ddns_key": "K", "key": "P"}))
    assert s.mgr.calls[0] == ("add_record", "h.example.com", "A", "203.0.113.5", 300, "K", "P")


def test_update_routes_to_update_record():
    s = _spoke()
    _run(s.handle_command("HENET_UPDATE", {"name": "h.example.com", "type": "A",
                                           "value": "203.0.113.6", "ddns_key": "K"}))
    assert s.mgr.calls[0][0] == "update_record"


def test_sync_passes_key():
    s = _spoke()
    _run(s.handle_command("HENET_SYNC", {"records": [{"name": "h", "type": "A", "value": "1.1.1.1"}],
                                         "ddns_key": "KK"}))
    assert s.mgr.calls[0] == ("sync", 1, "KK")


def test_add_requires_name_and_value():
    s = _spoke()
    res = _run(s.handle_command("HENET_ADD", {"type": "A", "value": "1.1.1.1"}))
    assert res["status"] == "ERROR"
    assert not s.mgr.calls


def test_delete_requires_name():
    s = _spoke()
    res = _run(s.handle_command("HENET_DELETE", {"type": "A"}))
    assert res["status"] == "ERROR"
    assert not s.mgr.calls


def test_status_command():
    s = _spoke()
    res = _run(s.handle_command("HENET_STATUS", {}))
    assert res["status"] == "SUCCESS" and res["reachable"] is True


def test_get_status_shape():
    s = _spoke()
    st = _run(s.get_status())
    assert st["module"] == "henet"
    assert st["status"] == "HEALTHY"
    assert st["record_count"] == 1


def test_unknown_command():
    s = _spoke()
    res = _run(s.handle_command("BOGUS", {}))
    assert res["status"] == "ERROR"
    assert "Unknown command" in res["error"]
