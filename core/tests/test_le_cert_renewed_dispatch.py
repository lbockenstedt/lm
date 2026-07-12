"""Tests for the hub's event-driven cert distribution dispatch:
``LabManagerHub._on_le_cert_renewed`` — invoked when a le spoke emits
``LE_CERT_RENEWED`` so the hub re-pushes the renewed material to its targets
immediately instead of waiting up to 1h for run_cert_distribution_loop.

These test the hub-side wrapper wiring (the spoke→hub event → _distribute_one_cert
→ pure transport helper) with a fake hub whose transport callables are stubbed.
The pure transport helper itself is covered by test_cert_distribution.py; the
le-side emit (LE_CERT_RENEWED payload) is covered by le/tests/test_le_spoke.py.
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import cert_distribution as cd  # noqa: E402
import main  # noqa: E402  (core/src on sys.path; heavy imports OK in dev/CI)


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


_LE = "le-spoke-1"
_FW = "opn-spoke-1"
_H = "sha256:abc"
_PEM = "-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----\n"


def _fake_rr(responses):
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
    return {"payload": {"data": {"status": "SUCCESS", "message": "installed"}}}


class _Hub:
    """Minimal stub: the attributes _on_le_cert_renewed / _distribute_one_cert
    touch (request_response, get_spoke_by_type, CERT_CAPABLE_MODULES). The real
    _distribute_one_cert is bound to it so the wrapper wiring is exercised
    end-to-end with stubbed transport."""
    def __init__(self, rr, get_by_type):
        self._rr = rr
        self._get = get_by_type
        self.CERT_CAPABLE_MODULES = cd.CERT_CAPABLE_MODULES
        # Bind the REAL _distribute_one_cert (only uses the 3 attrs above) +
        # _install_cert_on_hub (referenced by _distribute_one_cert for the
        # module_type=="hub" target branch; never CALLED for firewall targets
        # in these tests, just attribute-accessed, so binding the real method
        # is harmless).
        self._distribute_one_cert = main.LabManagerHub._distribute_one_cert.__get__(self)
        self._install_cert_on_hub = main.LabManagerHub._install_cert_on_hub.__get__(self)
        # _distribute_one_cert wraps request_response via _inflight_rr (so the
        # WebUI can show a yellow in-flight badge); bind both it + the lazy
        # in-flight dict helper it uses (no other hub attrs needed).
        self._inflight_rr = main.LabManagerHub._inflight_rr.__get__(self)
        self._cert_inflight = main.LabManagerHub._cert_inflight.__get__(self)

    async def request_response(self, spoke_id, cmd, data, timeout=5.0):
        return await self._rr(spoke_id, cmd, data, timeout)

    def get_spoke_by_type(self, mt):
        return self._get(mt)


def test_on_le_cert_renewed_pushes_to_targets():
    rr, calls = _fake_rr({
        (_LE, "LE_GET_CERT"): _le_get_cert_ok(),
        (_FW, "INSTALL_CERT"): _install_ok(),
    })
    hub = _Hub(rr, lambda mt: _FW if mt == "firewall" else None)
    # _on_le_cert_renewed returns None (it logs the summary); verify via the
    # side effect that INSTALL_CERT was pushed with the renewed material.
    _run(main.LabManagerHub._on_le_cert_renewed(
        hub, _LE, "example.com",
        [{"module_type": "firewall", "identifier": "edge-1"}]))
    installs = [c for c in calls if c["cmd"] == "INSTALL_CERT"]
    assert len(installs) == 1
    assert installs[0]["data"]["domain"] == "example.com"
    assert installs[0]["data"]["fullchain"] == _PEM
    assert installs[0]["data"]["identifier"] == "edge-1"
    # LE_MARK_DISTRIBUTED recorded the push on the le ledger.
    marks = [c for c in calls if c["cmd"] == "LE_MARK_DISTRIBUTED"]
    assert len(marks) == 1 and marks[0]["data"]["status"] == "SUCCESS"


def test_on_le_cert_renewed_no_targets_makes_no_install_call():
    rr, calls = _fake_rr({(_LE, "LE_GET_CERT"): _le_get_cert_ok()})
    hub = _Hub(rr, lambda mt: _FW)
    _run(main.LabManagerHub._on_le_cert_renewed(hub, _LE, "example.com", []))
    # Empty targets → distribute_cert_to_targets returns [] with no INSTALL_CERT.
    assert not [c for c in calls if c["cmd"] == "INSTALL_CERT"]


def test_on_le_cert_renewed_install_failure_does_not_raise():
    """A target INSTALL_CERT error must surface on the ledger (LE_MARK_DISTRIBUTED
    ERROR) but NOT raise out of _on_le_cert_renewed — the hourly loop is the
    fallback and a thrown exception would only log a warning."""
    rr, calls = _fake_rr({
        (_LE, "LE_GET_CERT"): _le_get_cert_ok(),
        (_FW, "INSTALL_CERT"): {"payload": {"data": {
            "status": "ERROR", "message": "missing CA key"}}},
    })
    hub = _Hub(rr, lambda mt: _FW)
    _run(main.LabManagerHub._on_le_cert_renewed(
        hub, _LE, "example.com", [{"module_type": "firewall"}]))
    marks = [c for c in calls if c["cmd"] == "LE_MARK_DISTRIBUTED"]
    assert len(marks) == 1 and marks[0]["data"]["status"] == "ERROR"