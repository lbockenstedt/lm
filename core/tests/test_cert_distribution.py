"""Tests for hub-brokered certificate distribution (core/src/cert_distribution.py).

The hub is the transport for cert material from the le spoke to target spokes.
These tests exercise the pure helpers with fake request_response / get_spoke_by_type
callables — no LabManagerHub construction (which would pull in at-rest encryption).
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import cert_distribution as cd  # noqa: E402


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


_LE = "le-spoke-1"
_FW = "opn-spoke-1"
_H = "sha256:abc"
_H2 = "sha256:def"
_PEM = "-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----\n"


def _fake_rr(responses):
    """``responses`` maps (spoke_id, command) → returned dict (the raw
    request_response result shape: {payload:{data: <spoke return>}}). Records
    every call so tests can assert on the INSTALL_CERT payload."""
    calls = []

    async def rr(spoke_id, command, data=None, timeout=None):
        calls.append({"spoke": spoke_id, "cmd": command, "data": data})
        return responses.get((spoke_id, command),
                             {"payload": {"data": {"status": "ERROR",
                                                   "message": "no stub"}}})

    return rr, calls


def _le_get_cert_ok():
    return {"payload": {"data": {"status": "SUCCESS", "data": {
        "fullchain": _PEM, "privkey": "KEY", "chain": "",
        "material_hash": _H, "not_after": "2099-01-01T00:00:00+00:00"}}}}


def _install_ok():
    return {"payload": {"data": {"status": "SUCCESS", "message": "imported"}}}


# ── distribute_cert_to_targets ───────────────────────────────────────────────

def test_distribute_pushes_to_capable_target():
    rr, calls = _fake_rr({
        (_LE, "LE_GET_CERT"): _le_get_cert_ok(),
        (_FW, "INSTALL_CERT"): _install_ok(),
    })
    get_by_type = lambda mt: _FW if mt == "firewall" else None
    targets = [{"module_type": "firewall", "identifier": "edge-1"}]
    summary = _run(cd.distribute_cert_to_targets(
        rr, get_by_type, cd.CERT_CAPABLE_MODULES, _LE, "example.com", targets))
    assert summary[0]["status"] == "SUCCESS"
    assert summary[0]["message"] == "imported"
    # INSTALL_CERT carried the cert material + identifier.
    installs = [c for c in calls if c["cmd"] == "INSTALL_CERT"]
    assert len(installs) == 1
    assert installs[0]["data"]["domain"] == "example.com"
    assert installs[0]["data"]["fullchain"] == _PEM
    assert installs[0]["data"]["privkey"] == "KEY"
    assert installs[0]["data"]["identifier"] == "edge-1"
    # LE_MARK_DISTRIBUTED recorded the successful push.
    marks = [c for c in calls if c["cmd"] == "LE_MARK_DISTRIBUTED"]
    assert len(marks) == 1
    assert marks[0]["data"]["status"] == "SUCCESS"
    assert marks[0]["data"]["hash"] == _H


def test_distribute_skips_up_to_date_target():
    rr, calls = _fake_rr({(_LE, "LE_GET_CERT"): _le_get_cert_ok()})
    get_by_type = lambda mt: _FW
    targets = [{"module_type": "firewall", "identifier": "edge-1",
                "last_pushed_hash": _H, "last_status": "SUCCESS"}]
    summary = _run(cd.distribute_cert_to_targets(
        rr, get_by_type, cd.CERT_CAPABLE_MODULES, _LE, "example.com", targets))
    assert summary[0]["status"] == "SUCCESS"
    assert summary[0].get("skipped") is True
    # No INSTALL_CERT, no LE_MARK_DISTRIBUTED for an up-to-date target.
    assert not [c for c in calls if c["cmd"] == "INSTALL_CERT"]
    assert not [c for c in calls if c["cmd"] == "LE_MARK_DISTRIBUTED"]


def test_distribute_unsupported_module_records_error():
    rr, calls = _fake_rr({(_LE, "LE_GET_CERT"): _le_get_cert_ok()})
    get_by_type = lambda mt: None
    targets = [{"module_type": "ipam"}]
    summary = _run(cd.distribute_cert_to_targets(
        rr, get_by_type, cd.CERT_CAPABLE_MODULES, _LE, "example.com", targets))
    assert summary[0]["status"] == "ERROR"
    assert "does not support cert install" in summary[0]["message"]
    # No INSTALL_CERT attempted for an unsupported module_type.
    assert not [c for c in calls if c["cmd"] == "INSTALL_CERT"]
    # But the ERROR is recorded on the ledger.
    marks = [c for c in calls if c["cmd"] == "LE_MARK_DISTRIBUTED"]
    assert len(marks) == 1 and marks[0]["data"]["status"] == "ERROR"


def test_distribute_no_connected_target_spoke():
    rr, calls = _fake_rr({(_LE, "LE_GET_CERT"): _le_get_cert_ok()})
    get_by_type = lambda mt: None  # firewall capable but none connected
    targets = [{"module_type": "firewall"}]
    summary = _run(cd.distribute_cert_to_targets(
        rr, get_by_type, cd.CERT_CAPABLE_MODULES, _LE, "example.com", targets))
    assert summary[0]["status"] == "ERROR"
    assert "no connected firewall spoke" in summary[0]["message"]


def test_distribute_get_cert_failure_returns_error():
    rr, calls = _fake_rr({(_LE, "LE_GET_CERT"): {
        "payload": {"data": {"status": "ERROR", "message": "no live cert"}}}})
    get_by_type = lambda mt: _FW
    summary = _run(cd.distribute_cert_to_targets(
        rr, get_by_type, cd.CERT_CAPABLE_MODULES, _LE, "example.com",
        [{"module_type": "firewall"}]))
    assert summary[0]["status"] == "ERROR"
    assert "no live cert" in summary[0]["message"]
    # No INSTALL_CERT push when material couldn't be pulled.
    assert not [c for c in calls if c["cmd"] == "INSTALL_CERT"]


def test_distribute_install_failure_records_error():
    rr, calls = _fake_rr({
        (_LE, "LE_GET_CERT"): _le_get_cert_ok(),
        (_FW, "INSTALL_CERT"): {"payload": {"data": {
            "status": "ERROR", "message": "missing CA key"}}},
    })
    get_by_type = lambda mt: _FW
    summary = _run(cd.distribute_cert_to_targets(
        rr, get_by_type, cd.CERT_CAPABLE_MODULES, _LE, "example.com",
        [{"module_type": "firewall"}]))
    assert summary[0]["status"] == "ERROR"
    assert "missing CA key" in summary[0]["message"]
    marks = [c for c in calls if c["cmd"] == "LE_MARK_DISTRIBUTED"]
    assert marks[0]["data"]["status"] == "ERROR"


def test_distribute_empty_targets_returns_empty():
    rr, _ = _fake_rr({})
    summary = _run(cd.distribute_cert_to_targets(
        rr, lambda mt: None, cd.CERT_CAPABLE_MODULES, _LE, "example.com", []))
    assert summary == []


# ── distribute_all_certs ─────────────────────────────────────────────────────

def test_distribute_all_skips_current_and_pushes_stale():
    list_resp = {"payload": {"data": {"status": "SUCCESS", "certs": [
        # current — every target up to date → no LE_GET_CERT pull
        {"domain": "current.com", "material_hash": _H, "targets": [
            {"module_type": "firewall", "last_pushed_hash": _H,
             "last_status": "SUCCESS"}]},
        # stale — needs a push
        {"domain": "stale.com", "material_hash": _H2, "targets": [
            {"module_type": "firewall", "last_pushed_hash": "old",
             "last_status": "SUCCESS"}]},
    ]}}}
    rr, calls = _fake_rr({
        (_LE, "LE_LIST_CERTS"): list_resp,
        (_LE, "LE_GET_CERT"): _le_get_cert_ok(),
        (_FW, "INSTALL_CERT"): _install_ok(),
    })
    get_by_type = lambda mt: _FW
    _run(cd.distribute_all_certs(rr, get_by_type, cd.CERT_CAPABLE_MODULES, _LE))
    # Only the stale cert's domain is pulled + installed.
    gets = [c for c in calls if c["cmd"] == "LE_GET_CERT"]
    assert [g["data"]["domain"] for g in gets] == ["stale.com"]
    installs = [c for c in calls if c["cmd"] == "INSTALL_CERT"]
    assert len(installs) == 1 and installs[0]["data"]["domain"] == "stale.com"


def test_distribute_all_no_certs_no_calls():
    rr, calls = _fake_rr({(_LE, "LE_LIST_CERTS"): {
        "payload": {"data": {"status": "SUCCESS", "certs": []}}}})
    _run(cd.distribute_all_certs(rr, lambda mt: None,
                                 cd.CERT_CAPABLE_MODULES, _LE))
    assert not [c for c in calls if c["cmd"] != "LE_LIST_CERTS"]


def test_distribute_all_list_error_is_noop():
    rr, calls = _fake_rr({(_LE, "LE_LIST_CERTS"): {
        "payload": {"data": {"status": "ERROR", "message": "down"}}}})
    _run(cd.distribute_all_certs(rr, lambda mt: None,
                                 cd.CERT_CAPABLE_MODULES, _LE))
    assert not [c for c in calls if c["cmd"] == "LE_GET_CERT"]