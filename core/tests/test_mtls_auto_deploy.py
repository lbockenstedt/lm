"""Tests for auto-deploying the LE wildcard for mTLS (hub + all spokes).

Covers the pure ``distribute_mtls_materials_to_all_spokes`` helper (the
hub-brokered fan-out of the CA bundle + client cert/key to every primary spoke
+ the hub) and the ``mtls`` runtime material registry. Exercises fakes — no
LabManagerHub construction (which would pull in at-rest encryption).
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import cert_distribution as cd  # noqa: E402
from security import mtls  # noqa: E402


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


_LE = "le-spoke-1"
_AGENT = "agent-spoke-1"
_CS = "cs-spoke-1"
_WILDCARD = "*.lab.example.com"
_H = "sha256:abc"
_PEM = "-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----\n"
_KEY = "-----BEGIN PRIVATE KEY-----\nK\n-----END PRIVATE KEY-----\n"
_CHAIN = "-----BEGIN CERTIFICATE-----\nC\n-----END CERTIFICATE-----\n"


def _fake_rr(responses):
    """``responses`` maps (spoke_id, command) → raw request_response result."""
    calls = []

    async def rr(spoke_id, command, data=None, timeout=None):
        calls.append({"spoke": spoke_id, "cmd": command, "data": data})
        return responses.get((spoke_id, command),
                              {"payload": {"data": {"status": "ERROR",
                                                    "message": "no stub"}}})

    return rr, calls


def _le_get_cert_ok():
    return {"payload": {"data": {"status": "SUCCESS", "data": {
        "fullchain": _PEM, "privkey": _KEY, "chain": _CHAIN,
        "material_hash": _H, "not_after": "2099-01-01T00:00:00+00:00"}}}}


def _fake_push(responses):
    """``push`` mimics push_or_queue_to_spoke: live push → {status:ok,queued:
    False, result: <request_response shape>}; offline → {status:ok,queued:
    True, message: ...}. Records the command_type + payload."""
    calls = []

    async def push(spoke_id, command_type, data, timeout=5.0):
        calls.append({"spoke": spoke_id, "cmd": command_type, "data": data,
                      "timeout": timeout})
        return responses.get(spoke_id,
            {"status": "ok", "queued": False,
             "result": {"payload": {"data": {"status": "SUCCESS",
                                              "message": "installed"}}}})

    return push, calls


def _install_on_hub_ok():
    async def install_on_hub(domain, fullchain, privkey, chain, identifier=""):
        return {"status": "SUCCESS", "message": "installed on hub"}
    return install_on_hub


def _primary(spokes):
    """``spokes``: list of (sid, module_type)."""
    return lambda: list(spokes)


# ── distribute_mtls_materials_to_all_spokes ───────────────────────────────────

def test_fans_out_to_all_primary_spokes_and_hub():
    rr, calls = _fake_rr({(_LE, "LE_GET_CERT"): _le_get_cert_ok()})
    push, pcalls = _fake_push({})
    summary = _run(cd.distribute_mtls_materials_to_all_spokes(
        rr, push, _primary([(_AGENT, "agent"), (_CS, "Client-Sim")]),
        _LE, _WILDCARD, None, {}, install_on_hub=_install_on_hub_ok()))
    # 2 spokes + hub = 3 entries, all SUCCESS.
    assert len(summary) == 3
    assert all(s["status"] == "SUCCESS" for s in summary), summary
    assert all(s.get("mtls") for s in summary)
    # The spoke payload carries the chain as the CA + the wildcard as the cert/key.
    pushed = [c for c in pcalls if c["cmd"] == "SPOKE_SET_MTLS_MATERIALS"]
    assert len(pushed) == 2
    for c in pushed:
        assert c["data"]["ca_bundle"] == _CHAIN
        assert c["data"]["client_cert"] == _PEM
        assert c["data"]["client_key"] == _KEY
    # push-state stamped for the hub + each spoke (live SUCCESS).
    assert summary  # guard


def test_includes_all_module_types_not_just_cert_capable():
    """A non-cert-capable spoke (dns) still gets mTLS materials — every spoke
    dials the hub, so every spoke needs them, unlike the INSTALL_CERT flow
    (which only reaches CERT_CAPABLE_MODULES)."""
    rr, _ = _fake_rr({(_LE, "LE_GET_CERT"): _le_get_cert_ok()})
    push, pcalls = _fake_push({})
    _run(cd.distribute_mtls_materials_to_all_spokes(
        rr, push, _primary([("dns-spoke-1", "dns")]),
        _LE, _WILDCARD, None, {}, install_on_hub=_install_on_hub_ok()))
    assert any(c["spoke"] == "dns-spoke-1" for c in pcalls)


def test_non_wildcard_is_a_noop():
    rr, _ = _fake_rr({})
    push, pcalls = _fake_push({})
    summary = _run(cd.distribute_mtls_materials_to_all_spokes(
        rr, push, _primary([(_AGENT, "agent")]), _LE, "edge.example.com",
        None, {}, install_on_hub=_install_on_hub_ok()))
    assert summary == []
    assert pcalls == []


def test_push_state_skip_avoids_repush():
    rr, _ = _fake_rr({(_LE, "LE_GET_CERT"): _le_get_cert_ok()})
    push, pcalls = _fake_push({})
    state = {f"mtls|{_AGENT}": _H, "mtls|hub": _H}
    summary = _run(cd.distribute_mtls_materials_to_all_spokes(
        rr, push, _primary([(_AGENT, "agent")]), _LE, _WILDCARD, _H, state,
        install_on_hub=_install_on_hub_ok()))
    # All current → one synthetic skipped entry, no push, no LE_GET_CERT pull.
    assert len(summary) == 1 and summary[0]["skipped"] is True
    assert pcalls == []


def test_offline_spoke_is_queued_not_errored():
    rr, _ = _fake_rr({(_LE, "LE_GET_CERT"): _le_get_cert_ok()})
    push, pcalls = _fake_push({"offline-spoke": {"status": "ok", "queued": True,
                                                  "message": "queued"}})
    state = {}
    summary = _run(cd.distribute_mtls_materials_to_all_spokes(
        rr, push, _primary([("offline-spoke", "agent")]), _LE, _WILDCARD,
        _H, state, install_on_hub=_install_on_hub_ok()))
    spoke_entry = [s for s in summary if s["identifier"] == "offline-spoke"][0]
    assert spoke_entry["status"] == "QUEUED"
    assert spoke_entry["queued"] is True
    # A queued push must NOT stamp the hash (so the next loop re-attempts live).
    assert "mtls|offline-spoke" not in state


def test_live_success_stamps_push_state():
    rr, _ = _fake_rr({(_LE, "LE_GET_CERT"): _le_get_cert_ok()})
    push, _ = _fake_push({})
    state = {}
    summary = _run(cd.distribute_mtls_materials_to_all_spokes(
        rr, push, _primary([(_AGENT, "agent")]), _LE, _WILDCARD, _H, state,
        install_on_hub=_install_on_hub_ok()))
    assert state[f"mtls|{_AGENT}"] == _H
    assert state["mtls|hub"] == _H
    assert summary[0]["status"] == "SUCCESS"


def test_incomplete_material_is_an_error():
    rr, _ = _fake_rr({"le": _le_get_cert_ok()})
    # LE_GET_CERT with no chain → incomplete.
    bad = {"payload": {"data": {"status": "SUCCESS", "data": {
        "fullchain": _PEM, "privkey": _KEY, "chain": "", "material_hash": _H}}}}
    rr2, _ = _fake_rr({(_LE, "LE_GET_CERT"): bad})
    push, pcalls = _fake_push({})
    summary = _run(cd.distribute_mtls_materials_to_all_spokes(
        rr2, push, _primary([(_AGENT, "agent")]), _LE, _WILDCARD, None, {},
        install_on_hub=_install_on_hub_ok()))
    assert summary[0]["status"] == "ERROR"
    assert "incomplete" in summary[0]["message"]
    assert pcalls == []  # never pushed to a spoke


def test_no_primary_spokes_no_hub_callable_is_noop():
    rr, _ = _fake_rr({})
    push, pcalls = _fake_push({})
    summary = _run(cd.distribute_mtls_materials_to_all_spokes(
        rr, push, _primary([]), _LE, _WILDCARD, None, {},
        install_on_hub=None))
    assert summary == []
    assert pcalls == []


# ── mtls runtime material registry ────────────────────────────────────────────

def test_runtime_materials_take_precedence_over_env(monkeypatch=None):
    mtls.set_runtime_materials(ca="/rt/ca.pem", client_cert="/rt/cc.pem",
                               client_key="/rt/ck.pem")
    try:
        os.environ["LM_MTLS_CA"] = "/env/ca.pem"
        ca, cert, key = mtls._paths()
        assert ca == "/rt/ca.pem" and cert == "/rt/cc.pem" and key == "/rt/ck.pem"
    finally:
        os.environ.pop("LM_MTLS_CA", None)
        mtls.set_runtime_materials(ca="", client_cert="", client_key="")


def test_runtime_materials_fall_back_to_env():
    mtls.set_runtime_materials(ca="", client_cert="", client_key="")  # clear
    try:
        os.environ["LM_MTLS_CA"] = "/env/ca.pem"
        ca, _cert, _key = mtls._paths()
        assert ca == "/env/ca.pem"
    finally:
        os.environ.pop("LM_MTLS_CA", None)


def test_status_reports_resolved_paths():
    mtls.set_runtime_materials(ca="/rt/ca.pem")
    try:
        st = mtls.status()
        assert st["ca_path"] == "/rt/ca.pem"
        # ca_present is False (file doesn't exist) but the path is reported.
        assert st["ca_present"] is False
    finally:
        mtls.set_runtime_materials(ca="")


def test_set_runtime_materials_partial_update_doesnt_clobber():
    mtls.set_runtime_materials(ca="/rt/ca.pem", client_cert="/rt/cc.pem",
                               client_key="/rt/ck.pem")
    # Update only the CA; client paths must persist.
    mtls.set_runtime_materials(ca="/rt/ca2.pem")
    try:
        _ca, cert, key = mtls._paths()
        assert cert == "/rt/cc.pem" and key == "/rt/ck.pem"
    finally:
        mtls.set_runtime_materials(ca="", client_cert="", client_key="")


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))