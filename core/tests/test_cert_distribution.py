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
        calls.append({"spoke": spoke_id, "cmd": command, "data": data,
                      "timeout": timeout})
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


def _le_list_certs(certs):
    """LE_LIST_CERTS spoke return — certs nested under the spoke's ``data``
    wrapper, mirroring the real le spoke (``{"status":"SUCCESS","data":{
    "certs":[...]}}``). ``_unwrap`` only strips the request_response payload
    envelope, NOT the spoke's own ``data`` wrapper, so this is the shape that
    exercises the distributor's data-unwrap. (Tests previously used a flat
    ``{"status","certs"}`` → passed while production saw ``ret.get("certs")``
    == None → "no certs to distribute".)"""
    return {"payload": {"data": {"status": "SUCCESS", "data": {
        "certs": certs, "count": len(certs), "certbot_present": True}}}}


# ── distribute_cert_to_targets ───────────────────────────────────────────────

def test_distribute_pushes_to_capable_target():
    rr, calls = _fake_rr({
        (_LE, "LE_GET_CERT"): _le_get_cert_ok(),
        (_FW, "INSTALL_CERT"): _install_ok(),
    })
    get_by_type = lambda mt, ident="": _FW if mt == "firewall" else None
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
    # INSTALL_CERT allows 120s — the hypervisor path relays to a per-node agent
    # that runs `pvenode cert set` + restarts pveproxy (the pxmx spoke's own
    # relay timeout is 120s). 20s (the old value) timed out the hub while the
    # spoke was still waiting on the agent → "Timed out waiting for spoke
    # response" even though the cert install was still in progress.
    assert installs[0]["timeout"] == 120.0


def test_distribute_hypervisor_uses_generous_640s_timeout():
    """The hypervisor path relays INSTALL_CERT to a per-node pxmx agent that
    runs `pvenode cert set` + restarts pveproxy (the agent's pvenode wait is
    600s, the pxmx spoke's relay 620s). The hub must NOT time out first and
    mask an in-progress deploy, so it uses 640s — > both downstream windows."""
    _HV = "pxmx-spoke-1"
    rr, calls = _fake_rr({
        (_LE, "LE_GET_CERT"): _le_get_cert_ok(),
        (_HV, "INSTALL_CERT"): _install_ok(),
    })
    get_by_type = lambda mt, ident="": _HV if mt == "hypervisor" else None
    targets = [{"module_type": "hypervisor", "identifier": "node-1"}]
    summary = _run(cd.distribute_cert_to_targets(
        rr, get_by_type, cd.CERT_CAPABLE_MODULES, _LE, "example.com", targets))
    assert summary[0]["status"] == "SUCCESS"
    installs = [c for c in calls if c["cmd"] == "INSTALL_CERT"]
    assert len(installs) == 1 and installs[0]["timeout"] == 640.0
    assert installs[0]["data"]["module_type"] == "hypervisor"


def test_distribute_threads_identifier_to_resolver():
    """The hub resolver receives the target identifier (not just module_type)
    so agent-hosting types can route to the spoke that owns the target agent
    (split topology: a 'hypervisor' target's agent dials the cs spoke). The
    pure helper passes ``identifier`` through to ``get_by_type``."""
    _CS = "cs-spoke-1"
    rr, calls = _fake_rr({
        (_LE, "LE_GET_CERT"): _le_get_cert_ok(),
        (_CS, "INSTALL_CERT"): _install_ok(),
    })
    seen = []
    def get_by_type(mt, ident=""):
        seen.append((mt, ident))
        return _CS if mt == "hypervisor" else None
    targets = [{"module_type": "hypervisor", "identifier": "pxmx-agent-7"}]
    _run(cd.distribute_cert_to_targets(
        rr, get_by_type, cd.CERT_CAPABLE_MODULES, _LE, "example.com", targets))
    # The resolver was called with BOTH the module_type and the identifier,
    # so the hub can route a hypervisor target to the agent-owning spoke.
    assert ("hypervisor", "pxmx-agent-7") in seen


def test_distribute_simulation_is_cert_capable_and_uses_640s_timeout():
    """simulation (cs/lm-spoke) is cert-capable: in the split topology it owns
    the pxmx agents directly and relays INSTALL_CERT to each → pvenode cert set,
    exactly like the hypervisor path. So it (a) is in CERT_CAPABLE_MODULES
    (else the gate ERRORs "does not support cert install yet" — the red state
    the user saw), (b) resolves to the connected simulation spoke, and (c) uses
    the same generous 640s hub window as hypervisor (the cs spoke's 620s
    send_to_agent relay > the agent's 600s pvenode wait). The cs spoke
    aggregates per-node results itself; the hub just sees one INSTALL_CERT to
    the simulation spoke."""
    assert "simulation" in cd.CERT_CAPABLE_MODULES
    _CS = "cs-spoke-1"
    rr, calls = _fake_rr({
        (_LE, "LE_GET_CERT"): _le_get_cert_ok(),
        (_CS, "INSTALL_CERT"): _install_ok(),
    })
    get_by_type = lambda mt, ident="": _CS if mt == "simulation" else None
    targets = [{"module_type": "simulation", "identifier": ""}]
    summary = _run(cd.distribute_cert_to_targets(
        rr, get_by_type, cd.CERT_CAPABLE_MODULES, _LE, "example.com", targets))
    assert summary[0]["status"] == "SUCCESS"
    installs = [c for c in calls if c["cmd"] == "INSTALL_CERT"]
    assert len(installs) == 1
    assert installs[0]["data"]["module_type"] == "simulation"
    assert installs[0]["timeout"] == 640.0  # shares the hypervisor window


def test_distribute_nac_is_cert_capable_and_routes_to_spoke():
    """nac (ClearPass) is cert-capable: the cppm spoke installs the cert via
    ClearPass's REST server-cert API (PKCS12 hosted at a URL ClearPass fetches
    — see cppm spoke import_cert). It's a fast REST target, so it stays on the
    120s install tier (no pvenode wait). Verifies (a) it's in
    CERT_CAPABLE_MODULES, (b) INSTALL_CERT routes to the connected nac spoke
    with the cert material + identifier, (c) 120s timeout."""
    assert "nac" in cd.CERT_CAPABLE_MODULES
    _NAC = "cppm-spoke-1"
    rr, calls = _fake_rr({
        (_LE, "LE_GET_CERT"): _le_get_cert_ok(),
        (_NAC, "INSTALL_CERT"): _install_ok(),
    })
    get_by_type = lambda mt, ident="": _NAC if mt == "nac" else None
    targets = [{"module_type": "nac", "identifier": "clearpass-1"}]
    summary = _run(cd.distribute_cert_to_targets(
        rr, get_by_type, cd.CERT_CAPABLE_MODULES, _LE, "example.com", targets))
    assert summary[0]["status"] == "SUCCESS"
    installs = [c for c in calls if c["cmd"] == "INSTALL_CERT"]
    assert len(installs) == 1
    assert installs[0]["data"]["module_type"] == "nac"
    assert installs[0]["data"]["identifier"] == "clearpass-1"
    assert installs[0]["timeout"] == 120.0  # fast REST tier


def test_distribute_nw_is_cert_capable_and_routes_to_spoke():
    """nw (network devices) is cert-capable: the nw spoke resolves the target
    device by identifier and installs the cert (cx_switch via AOS-CX REST v10
    today; other families return a clear ERROR from the spoke). Fast REST →
    120s install tier. Verifies (a) it's in CERT_CAPABLE_MODULES, (b)
    INSTALL_CERT routes to the connected nw spoke carrying identifier (the
    device id) + cert material, (c) 120s timeout."""
    assert "nw" in cd.CERT_CAPABLE_MODULES
    _NW = "nw-spoke-1"
    rr, calls = _fake_rr({
        (_LE, "LE_GET_CERT"): _le_get_cert_ok(),
        (_NW, "INSTALL_CERT"): _install_ok(),
    })
    get_by_type = lambda mt, ident="": _NW if mt == "nw" else None
    targets = [{"module_type": "nw", "identifier": "edge-sw-1"}]
    summary = _run(cd.distribute_cert_to_targets(
        rr, get_by_type, cd.CERT_CAPABLE_MODULES, _LE, "example.com", targets))
    assert summary[0]["status"] == "SUCCESS"
    installs = [c for c in calls if c["cmd"] == "INSTALL_CERT"]
    assert len(installs) == 1
    assert installs[0]["data"]["module_type"] == "nw"
    assert installs[0]["data"]["identifier"] == "edge-sw-1"
    assert installs[0]["timeout"] == 120.0  # fast REST tier


def test_distribute_skips_up_to_date_target():
    rr, calls = _fake_rr({(_LE, "LE_GET_CERT"): _le_get_cert_ok()})
    get_by_type = lambda mt, ident="": _FW
    targets = [{"module_type": "firewall", "identifier": "edge-1",
                "last_pushed_hash": _H, "last_status": "SUCCESS"}]
    summary = _run(cd.distribute_cert_to_targets(
        rr, get_by_type, cd.CERT_CAPABLE_MODULES, _LE, "example.com", targets))
    assert summary[0]["status"] == "SUCCESS"
    assert summary[0].get("skipped") is True
    # No INSTALL_CERT, no LE_MARK_DISTRIBUTED for an up-to-date target.
    assert not [c for c in calls if c["cmd"] == "INSTALL_CERT"]
    assert not [c for c in calls if c["cmd"] == "LE_MARK_DISTRIBUTED"]


def test_distribute_single_target_without_ledger_always_pushes():
    """Click-to-deploy: the per-target route builds the target WITHOUT
    ``last_pushed_hash``/``last_status`` (the operator clicked a badge, not the
    hourly sweep). The skip-check needs BOTH ``last_pushed_hash == material_hash``
    AND ``last_status == "SUCCESS"`` — a target fresh from the route has neither,
    so it always pushes (a click is an explicit re-deploy, even on a target that
    was already green). Guards against the click-to-deploy silently no-op'ing."""
    rr, calls = _fake_rr({
        (_LE, "LE_GET_CERT"): _le_get_cert_ok(),
        (_FW, "INSTALL_CERT"): _install_ok(),
    })
    get_by_type = lambda mt, ident="": _FW if mt == "firewall" else None
    # No last_pushed_hash / last_status — exactly what the route sends.
    targets = [{"module_type": "firewall", "identifier": "edge-1"}]
    summary = _run(cd.distribute_cert_to_targets(
        rr, get_by_type, cd.CERT_CAPABLE_MODULES, _LE, "example.com", targets))
    assert summary[0]["status"] == "SUCCESS"
    assert summary[0].get("skipped") is not True
    installs = [c for c in calls if c["cmd"] == "INSTALL_CERT"]
    assert len(installs) == 1
    assert installs[0]["data"]["identifier"] == "edge-1"
    marks = [c for c in calls if c["cmd"] == "LE_MARK_DISTRIBUTED"]
    assert len(marks) == 1


def test_distribute_unsupported_module_records_error():
    rr, calls = _fake_rr({(_LE, "LE_GET_CERT"): _le_get_cert_ok()})
    get_by_type = lambda mt, ident="": None
    targets = [{"module_type": "dns"}]  # dns is NOT cert-capable (no INSTALL_CERT)
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
    get_by_type = lambda mt, ident="": None  # firewall capable but none connected
    targets = [{"module_type": "firewall"}]
    summary = _run(cd.distribute_cert_to_targets(
        rr, get_by_type, cd.CERT_CAPABLE_MODULES, _LE, "example.com", targets))
    assert summary[0]["status"] == "ERROR"
    assert "no connected firewall spoke" in summary[0]["message"]


def test_distribute_get_cert_failure_returns_error():
    rr, calls = _fake_rr({(_LE, "LE_GET_CERT"): {
        "payload": {"data": {"status": "ERROR", "message": "no live cert"}}}})
    get_by_type = lambda mt, ident="": _FW
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
    get_by_type = lambda mt, ident="": _FW
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
        rr, lambda mt, ident="": None, cd.CERT_CAPABLE_MODULES, _LE, "example.com", []))
    assert summary == []


# ── hub self-install target (module_type == "hub") ────────────────────────────

def test_distribute_hub_target_calls_install_on_hub():
    """A "hub" target is handled by the install_on_hub callable (the hub
    installing a cert on itself), NOT by get_spoke_by_type / INSTALL_CERT."""
    rr, calls = _fake_rr({(_LE, "LE_GET_CERT"): _le_get_cert_ok()})
    get_by_type = lambda mt, ident="": (_FW if mt == "firewall" else None)
    installs = []

    async def install_on_hub(domain, fullchain, privkey, chain, identifier):
        installs.append({"domain": domain, "fullchain": fullchain,
                         "privkey": privkey, "chain": chain, "identifier": identifier})
        return {"status": "SUCCESS", "message": "installed to /opt/lm/tls/fullchain.pem"}

    summary = _run(cd.distribute_cert_to_targets(
        rr, get_by_type, cd.CERT_CAPABLE_MODULES, _LE, "hub.example.com",
        [{"module_type": "hub"}], install_on_hub=install_on_hub))
    assert summary[0]["status"] == "SUCCESS"
    assert "installed to /opt/lm/tls/fullchain.pem" in summary[0]["message"]
    # install_on_hub received the material pulled from the le spoke.
    assert installs and installs[0]["fullchain"] == _PEM and installs[0]["privkey"] == "KEY"
    # No INSTALL_CERT relay + no get_spoke_by_type("hub") resolution happened.
    assert not [c for c in calls if c["cmd"] == "INSTALL_CERT"]
    # The push is recorded on the ledger like any other target.
    marks = [c for c in calls if c["cmd"] == "LE_MARK_DISTRIBUTED"]
    assert len(marks) == 1 and marks[0]["data"]["module_type"] == "hub" \
        and marks[0]["data"]["status"] == "SUCCESS"


def test_distribute_hub_target_without_callable_records_error():
    """No install_on_hub wired → a hub target records a clear ERROR (visible,
    not silently dropped). "hub" is in CERT_CAPABLE_MODULES so it does NOT take
    the 'does not support cert install' branch."""
    rr, calls = _fake_rr({(_LE, "LE_GET_CERT"): _le_get_cert_ok()})
    get_by_type = lambda mt, ident="": None
    summary = _run(cd.distribute_cert_to_targets(
        rr, get_by_type, cd.CERT_CAPABLE_MODULES, _LE, "hub.example.com",
        [{"module_type": "hub"}]))
    assert summary[0]["status"] == "ERROR"
    assert "hub self-install not wired" in summary[0]["message"]
    assert "does not support" not in summary[0]["message"]


def test_distribute_hub_target_install_error_surfaces_message():
    async def install_on_hub(domain, fullchain, privkey, chain, identifier):
        return {"status": "ERROR", "message": "permission denied writing /opt/lm/tls"}
    rr, _ = _fake_rr({(_LE, "LE_GET_CERT"): _le_get_cert_ok()})
    summary = _run(cd.distribute_cert_to_targets(
        rr, lambda mt, ident="": None, cd.CERT_CAPABLE_MODULES, _LE, "hub.example.com",
        [{"module_type": "hub"}], install_on_hub=install_on_hub))
    assert summary[0]["status"] == "ERROR"
    assert "permission denied" in summary[0]["message"]


def test_distribute_hub_target_callable_raise_is_caught():
    async def install_on_hub(domain, fullchain, privkey, chain, identifier):
        raise RuntimeError("boom")
    rr, _ = _fake_rr({(_LE, "LE_GET_CERT"): _le_get_cert_ok()})
    summary = _run(cd.distribute_cert_to_targets(
        rr, lambda mt, ident="": None, cd.CERT_CAPABLE_MODULES, _LE, "hub.example.com",
        [{"module_type": "hub"}], install_on_hub=install_on_hub))
    assert summary[0]["status"] == "ERROR"
    assert "boom" in summary[0]["message"]


# ── distribute_all_certs ─────────────────────────────────────────────────────

def test_distribute_all_skips_current_and_pushes_stale():
    list_resp = _le_list_certs([
        # current — every target up to date → no LE_GET_CERT pull
        {"domain": "current.com", "material_hash": _H, "targets": [
            {"module_type": "firewall", "last_pushed_hash": _H,
             "last_status": "SUCCESS"}]},
        # stale — needs a push
        {"domain": "stale.com", "material_hash": _H2, "targets": [
            {"module_type": "firewall", "last_pushed_hash": "old",
             "last_status": "SUCCESS"}]},
    ])
    rr, calls = _fake_rr({
        (_LE, "LE_LIST_CERTS"): list_resp,
        (_LE, "LE_GET_CERT"): _le_get_cert_ok(),
        (_FW, "INSTALL_CERT"): _install_ok(),
    })
    get_by_type = lambda mt, ident="": _FW
    _run(cd.distribute_all_certs(rr, get_by_type, cd.CERT_CAPABLE_MODULES, _LE))
    # Only the stale cert's domain is pulled + installed.
    gets = [c for c in calls if c["cmd"] == "LE_GET_CERT"]
    assert [g["data"]["domain"] for g in gets] == ["stale.com"]
    installs = [c for c in calls if c["cmd"] == "INSTALL_CERT"]
    assert len(installs) == 1 and installs[0]["data"]["domain"] == "stale.com"


def test_distribute_all_no_certs_no_calls():
    rr, calls = _fake_rr({(_LE, "LE_LIST_CERTS"): _le_list_certs([])})
    _run(cd.distribute_all_certs(rr, lambda mt, ident="": None,
                                 cd.CERT_CAPABLE_MODULES, _LE))
    assert not [c for c in calls if c["cmd"] != "LE_LIST_CERTS"]


def test_distribute_all_list_error_is_noop():
    rr, calls = _fake_rr({(_LE, "LE_LIST_CERTS"): {
        "payload": {"data": {"status": "ERROR", "message": "down"}}}})
    _run(cd.distribute_all_certs(rr, lambda mt, ident="": None,
                                 cd.CERT_CAPABLE_MODULES, _LE))
    assert not [c for c in calls if c["cmd"] == "LE_GET_CERT"]


def test_distribute_all_no_targets_logs_skip_not_silence(caplog):
    """A cert with no targets is a no-op but must NOT be silent — the operator
    sees 'no targets configured' so they know distribution was skipped (not
    broken). Was a silent skip before the fix."""
    list_resp = _le_list_certs([
        {"domain": "orphan.com", "material_hash": _H, "targets": []},
    ])
    rr, calls = _fake_rr({(_LE, "LE_LIST_CERTS"): list_resp})
    with caplog.at_level("INFO", logger="le.distribution"):
        _run(cd.distribute_all_certs(rr, lambda mt, ident="": None,
                                     cd.CERT_CAPABLE_MODULES, _LE))
    assert any("no targets configured" in r.message for r in caplog.records)
    assert not [c for c in calls if c["cmd"] == "LE_GET_CERT"]


def test_distribute_all_all_current_logs_skip_not_silence(caplog):
    """A cert whose every target is current is a no-op but must NOT be silent
    — 'all N target(s) current' tells the operator the cert IS deployed (not
    missing). Was a silent skip before the fix."""
    list_resp = _le_list_certs([
        {"domain": "fresh.com", "material_hash": _H, "targets": [
            {"module_type": "firewall", "last_pushed_hash": _H,
             "last_status": "SUCCESS"}]},
    ])
    rr, calls = _fake_rr({(_LE, "LE_LIST_CERTS"): list_resp})
    with caplog.at_level("INFO", logger="le.distribution"):
        _run(cd.distribute_all_certs(rr, lambda mt, ident="": _FW,
                                     cd.CERT_CAPABLE_MODULES, _LE))
    assert any("all 1 target(s) current" in r.message for r in caplog.records)
    assert not [c for c in calls if c["cmd"] == "LE_GET_CERT"]


def test_distribute_cert_no_targets_logs_skip(caplog):
    """distribute_cert_to_targets (the per-cert path) must also surface a
    no-targets skip, not a silent empty return."""
    rr, calls = _fake_rr({})
    with caplog.at_level("INFO", logger="le.distribution"):
        summary = _run(cd.distribute_cert_to_targets(
            rr, lambda mt, ident="": None, cd.CERT_CAPABLE_MODULES,
            _LE, "solo.com", []))
    assert summary == []
    assert any("no targets configured" in r.message for r in caplog.records)
    assert not [c for c in calls if c["cmd"] == "LE_GET_CERT"]


# ── distribute_wildcard_to_all_spokes ─────────────────────────────────────────
# Fan-out is gated hub-side (only invoked when global_config["certs"]
# ["wildcard_all_spokes"] is ON + domain is a wildcard); these tests exercise
# the pure fan-out helper directly. push_state is a mutable dict the hub owns.

def _wc_all_by_type(spokes):
    """get_all_spokes_by_type: returns the list of connected spoke_ids for a
    module_type (vs get_spoke_by_type which returns one)."""
    def f(mt):
        return spokes.get(mt, [])
    return f


def test_wildcard_fans_out_to_every_capable_spoke():
    """Every connected cert-capable spoke (by spoke_id, so multiple per
    module_type) gets the cert; each push is recorded on the ledger."""
    rr, calls = _fake_rr({
        (_LE, "LE_GET_CERT"): _le_get_cert_ok(),
        ("opn-1", "INSTALL_CERT"): _install_ok(),
        ("opn-2", "INSTALL_CERT"): _install_ok(),
        ("hv-1", "INSTALL_CERT"): _install_ok(),
    })
    get_all = _wc_all_by_type({"firewall": ["opn-1", "opn-2"],
                               "hypervisor": ["hv-1"]})
    push_state = {}
    summary = _run(cd.distribute_wildcard_to_all_spokes(
        rr, get_all, cd.CERT_CAPABLE_MODULES, _LE, "*.lab.example.com",
        None, push_state, install_on_hub=None))
    installs = [c for c in calls if c["cmd"] == "INSTALL_CERT"]
    assert {c["spoke"] for c in installs} == {"opn-1", "opn-2", "hv-1"}
    assert all(s["status"] == "SUCCESS" and s.get("wildcard") for s in summary)
    # push_state records the current hash for each pushed spoke (no re-push).
    assert push_state["*.lab.example.com|opn-1"] == _H
    assert push_state["*.lab.example.com|hv-1"] == _H
    # Each push is acked on the le ledger with wildcard: True.
    marks = [c for c in calls if c["cmd"] == "LE_MARK_DISTRIBUTED"]
    assert len(marks) == 3 and all(m["data"].get("wildcard") for m in marks)


def test_build_claimed_targets_ignores_wildcard_cert():
    """_build_claimed_targets: a non-wildcard cert claims its targets (by
    identifier, or wholesale by module_type when the identifier is blank); a
    WILDCARD cert claims nothing (it doesn't exclude against itself)."""
    ids, groups = cd._build_claimed_targets([
        {"domain": "*.lab.example.com", "targets": [{"module_type": "firewall", "identifier": "opn-9"}]},
        {"domain": "hub.lab.example.com", "targets": [{"module_type": "hub", "identifier": "hub"}]},
        {"domain": "dns1.lab.example.com", "targets": [{"module_type": "dns", "identifier": ""}]},
    ])
    assert ids == {"hub"} and groups == {"dns"}


def test_wildcard_skips_spokes_with_unique_cert():
    """A spoke/agent that already owns a unique (non-wildcard) LE cert is excluded
    from the wildcard fan-out — by spoke_id (claimed_ids) or wholesale by
    module_type (claimed_group_types)."""
    rr, calls = _fake_rr({
        (_LE, "LE_GET_CERT"): _le_get_cert_ok(),
        ("opn-1", "INSTALL_CERT"): _install_ok(),
    })
    get_all = _wc_all_by_type({"firewall": ["opn-1", "opn-2"],
                               "hypervisor": ["hv-1"]})
    push_state = {}
    summary = _run(cd.distribute_wildcard_to_all_spokes(
        rr, get_all, cd.CERT_CAPABLE_MODULES, _LE, "*.lab.example.com",
        None, push_state, install_on_hub=None,
        claimed_ids={"opn-2"}, claimed_group_types={"hypervisor"}))
    installs = [c["spoke"] for c in calls if c["cmd"] == "INSTALL_CERT"]
    assert installs == ["opn-1"]  # opn-2 (claimed id) + hv-1 (claimed type) skipped
    assert "*.lab.example.com|opn-2" not in push_state
    assert "*.lab.example.com|hv-1" not in push_state
    assert all(s.get("wildcard") for s in summary)


def test_wildcard_skips_all_current_no_pull(caplog):
    """When push_state shows every spoke at the current hash, no LE_GET_CERT
    pull + no INSTALL_CERT — the operator sees 'all N current' (not silence)."""
    get_all = _wc_all_by_type({"firewall": ["opn-1"]})
    push_state = {"*.lab.example.com|opn-1": _H}
    rr, calls = _fake_rr({})  # no stubs needed — nothing should be called
    with caplog.at_level("INFO", logger="le.distribution"):
        summary = _run(cd.distribute_wildcard_to_all_spokes(
            rr, get_all, cd.CERT_CAPABLE_MODULES, _LE, "*.lab.example.com",
            _H, push_state, install_on_hub=None))
    assert not [c for c in calls if c["cmd"] == "LE_GET_CERT"]
    assert not [c for c in calls if c["cmd"] == "INSTALL_CERT"]
    assert summary and summary[0].get("skipped") and summary[0].get("wildcard")
    assert any("wildcard" in r.message and "all 1 target(s) current" in r.message
               for r in caplog.records)


def test_wildcard_no_connected_spokes_noop(caplog):
    """No cert-capable spokes connected + no hub self-install → surfaced
    'nothing to fan out', not a silent empty return."""
    get_all = _wc_all_by_type({})
    rr, calls = _fake_rr({})
    with caplog.at_level("INFO", logger="le.distribution"):
        summary = _run(cd.distribute_wildcard_to_all_spokes(
            rr, get_all, cd.CERT_CAPABLE_MODULES, _LE, "*.lab.example.com",
            _H, {}, install_on_hub=None))
    assert summary == []
    assert any("nothing to fan out" in r.message for r in caplog.records)
    assert not [c for c in calls if c["cmd"] == "LE_GET_CERT"]


def test_wildcard_install_failure_records_error_keeps_going():
    """One spoke failing doesn't abort the fan-out; the failure is recorded on
    the ledger and push_state is NOT advanced for that spoke (retry next loop)."""
    rr, calls = _fake_rr({
        (_LE, "LE_GET_CERT"): _le_get_cert_ok(),
        ("opn-1", "INSTALL_CERT"): {"payload": {"data": {
            "status": "ERROR", "message": "scp refused"}}},
        ("hv-1", "INSTALL_CERT"): _install_ok(),
    })
    get_all = _wc_all_by_type({"firewall": ["opn-1"], "hypervisor": ["hv-1"]})
    push_state = {}
    summary = _run(cd.distribute_wildcard_to_all_spokes(
        rr, get_all, cd.CERT_CAPABLE_MODULES, _LE, "*.lab.example.com",
        None, push_state, install_on_hub=None))
    by_spoke = {s["identifier"]: s for s in summary}
    assert by_spoke["opn-1"]["status"] == "ERROR"
    assert "scp refused" in by_spoke["opn-1"]["message"]
    assert by_spoke["hv-1"]["status"] == "SUCCESS"
    # Failed spoke NOT advanced in push_state (retry); successful one is.
    assert "*.lab.example.com|opn-1" not in push_state
    assert push_state["*.lab.example.com|hv-1"] == _H
    marks = [c for c in calls if c["cmd"] == "LE_MARK_DISTRIBUTED"]
    assert {m["data"]["status"] for m in marks} == {"SUCCESS", "ERROR"}


def test_wildcard_get_cert_failure_returns_error():
    """If the le spoke can't produce the wildcard material, the whole fan-out
    is a single ERROR entry (no INSTALL_CERT attempted on stale spokes)."""
    rr, calls = _fake_rr({(_LE, "LE_GET_CERT"): {
        "payload": {"data": {"status": "ERROR", "message": "no live wildcard"}}}})
    get_all = _wc_all_by_type({"firewall": ["opn-1"]})
    summary = _run(cd.distribute_wildcard_to_all_spokes(
        rr, get_all, cd.CERT_CAPABLE_MODULES, _LE, "*.lab.example.com",
        None, {}, install_on_hub=None))
    assert len(summary) == 1 and summary[0]["status"] == "ERROR"
    assert "no live wildcard" in summary[0]["message"]
    assert not [c for c in calls if c["cmd"] == "INSTALL_CERT"]


def test_wildcard_includes_hub_self_install():
    """The hub (one TLS endpoint) gets the cert via install_on_hub, tagged
    module_type 'hub', and is tracked in push_state under '<domain>|hub'."""
    rr, calls = _fake_rr({(_LE, "LE_GET_CERT"): _le_get_cert_ok(),
                           ("opn-1", "INSTALL_CERT"): _install_ok()})
    get_all = _wc_all_by_type({"firewall": ["opn-1"]})
    hub_installs = []

    async def install_on_hub(domain, fullchain, privkey, chain, identifier):
        hub_installs.append(identifier)
        return {"status": "SUCCESS", "message": "installed on hub"}

    push_state = {}
    summary = _run(cd.distribute_wildcard_to_all_spokes(
        rr, get_all, cd.CERT_CAPABLE_MODULES, _LE, "*.lab.example.com",
        None, push_state, install_on_hub=install_on_hub))
    hub_entries = [s for s in summary if s["module_type"] == "hub"]
    assert len(hub_entries) == 1 and hub_entries[0]["status"] == "SUCCESS"
    assert hub_installs == ["hub"]  # identifier "hub" for the single TLS endpoint
    assert push_state["*.lab.example.com|hub"] == _H
    # hub is NOT treated as a spoke — no INSTALL_CERT relay for it.
    assert not [c for c in calls if c["cmd"] == "INSTALL_CERT"
                and c["spoke"] not in ("opn-1",)]


def test_wildcard_non_wildcard_domain_is_noop():
    """A non-wildcard domain short-circuits (the hub only calls this for
    wildcards, but the helper defends)."""
    rr, calls = _fake_rr({})
    get_all = _wc_all_by_type({"firewall": ["opn-1"]})
    summary = _run(cd.distribute_wildcard_to_all_spokes(
        rr, get_all, cd.CERT_CAPABLE_MODULES, _LE, "plain.example.com",
        None, {}, install_on_hub=None))
    assert summary == []
    assert not [c for c in calls if c["cmd"] != ""]  # no calls at all

# ── build_available_targets (LE modal click-to-add list) ─────────────────────

def test_available_targets_lists_cert_capable_connected_spokes():
    """One entry per cert-capable CONNECTED spoke (by module_type); offline +
    non-capable spokes are omitted (they'd only ERROR on distribute)."""
    smt = {"opn-1": "firewall", "netbox-1": "ipam", "ldap-1": "directory",
           "nw-1": "nw", "nac-1": "nac", "dns-1": "dns", "pxmx-1": "hypervisor"}
    active = {"opn-1", "netbox-1", "ldap-1", "nw-1", "nac-1"}  # dns-1 + pxmx-1 offline
    names = {"opn-1": "edge-fw", "netbox-1": "netbox", "nac-1": "clearpass"}
    out = cd.build_available_targets(smt, active, names, cd.CERT_CAPABLE_MODULES, [])
    by_mt = {t["module_type"]: t for t in out if not t["identifier"]}
    # cert-capable + connected: firewall, ipam, directory, nw, nac — PLUS the
    # always-present hub self-install entry.
    assert set(by_mt) == {"firewall", "ipam", "directory", "nw", "nac", "hub"}
    # Offline spokes (dns-1, pxmx-1) absent; non-capable dns absent.
    assert "dns" not in by_mt and "hypervisor" not in by_mt
    assert by_mt["firewall"]["label"] == "firewall — edge-fw"
    assert by_mt["ipam"]["label"] == "ipam — netbox"
    assert by_mt["nac"]["label"] == "nac — clearpass"
    # Falls back to spoke_id when no display name.
    assert by_mt["directory"]["label"] == "directory — ldap-1"
    # nw reads "Network Devices" (not the spoke's raw display name).
    assert by_mt["nw"]["label"] == "Network Devices"
    # identifier empty for spoke-level targets.
    assert all(t["identifier"] == "" for t in by_mt.values())


def test_available_targets_nw_friendly_label_disambiguates_multi_spoke():
    """Two connected nw spokes → each gets 'Network Devices — <spoke name>' so the
    rows are distinct; a single nw spoke stays the bare 'Network Devices'."""
    smt = {"nw-1": "nw", "nw-2": "nw"}
    active = {"nw-1", "nw-2"}
    names = {"nw-1": "site-a-fleet", "nw-2": "site-b-fleet"}
    out = cd.build_available_targets(smt, active, names, cd.CERT_CAPABLE_MODULES, [])
    nw = [t for t in out if t["module_type"] == "nw" and not t["identifier"]]
    labels = sorted(t["label"] for t in nw)
    assert labels == ["Network Devices — site-a-fleet", "Network Devices — site-b-fleet"]
    # Single spoke → bare friendly label.
    single = cd.build_available_targets({"nw-1": "nw"}, {"nw-1"},
                                        {"nw-1": "All Devices"},
                                        cd.CERT_CAPABLE_MODULES, [])
    assert [t for t in single if t["module_type"] == "nw"][0]["label"] == "Network Devices"


def test_available_targets_lists_each_pxmx_agent_as_per_node_target():
    """Agent-hosting types (hypervisor/simulation) list EACH connected pxmx
    agent as a per-node target (identifier = agent_id) — the click-a-specific-
    node UX — PLUS an 'all nodes' broadcast entry per connected spoke."""
    smt = {"pxmx-1": "hypervisor", "cs-1": "simulation", "opn-1": "firewall"}
    active = {"pxmx-1", "cs-1", "opn-1"}
    agents = [
        {"agent_id": "node-a", "spoke_id": "pxmx-1", "hostname": "pve01"},
        {"agent_id": "node-b", "spoke_id": "pxmx-1", "display_name": "pve02"},
        {"agent_id": "node-c", "spoke_id": "cs-1", "hostname": "pve03"},
    ]
    out = cd.build_available_targets(smt, active, {}, cd.CERT_CAPABLE_MODULES, agents)
    per_node = {t["identifier"]: t for t in out if t["identifier"]}
    assert per_node["node-a"]["module_type"] == "hypervisor"
    assert per_node["node-a"]["label"] == "hypervisor/pve01"
    assert per_node["node-b"]["label"] == "hypervisor/pve02"  # display_name wins
    assert per_node["node-c"]["module_type"] == "simulation"
    allnodes = [t for t in out if t["module_type"] in ("hypervisor", "simulation")
                and not t["identifier"]]
    assert {t["module_type"] for t in allnodes} == {"hypervisor", "simulation"}
    assert all("all nodes" in t["label"] for t in allnodes)


def test_available_targets_omits_agents_whose_parent_spoke_not_cert_capable():
    """An agent whose parent spoke's module_type isn't cert-capable is skipped
    (e.g. a future agent-hosting type that isn't wired) — defensive guard."""
    smt = {"foo-1": "foo"}  # 'foo' is not a cert-capable module_type
    active = {"foo-1"}
    agents = [{"agent_id": "x-1", "spoke_id": "foo-1", "hostname": "x"}]
    out = cd.build_available_targets(smt, active, {}, cd.CERT_CAPABLE_MODULES, agents)
    # No foo entry (non-capable); only the always-present hub self-install entry.
    assert [t for t in out if t["module_type"] != "hub"] == []


def test_available_targets_omits_agent_hosting_spoke_with_zero_agents():
    """A CONNECTED agent-hosting spoke (hypervisor/simulation) that has NO agents
    added emits NO entry — neither per-node nor the 'all nodes' broadcast — so
    it can't be selected as a cert target (the 'module has no device added' case).
    """
    smt = {"pxmx-1": "hypervisor", "cs-1": "simulation", "opn-1": "firewall"}
    active = {"pxmx-1", "cs-1", "opn-1"}  # both agent-hosting spokes connected
    agents = []  # but ZERO agents under any of them
    out = cd.build_available_targets(smt, active, {}, cd.CERT_CAPABLE_MODULES, agents)
    non_hub = [t for t in out if t["module_type"] != "hub"]
    # firewall (a real device — the spoke itself) is still selectable; the two
    # agent-hosting spokes have no devices, so they're gone entirely.
    assert {t["module_type"] for t in non_hub} == {"firewall"}
    assert not any(t["module_type"] in ("hypervisor", "simulation") for t in out)
    assert not any("all nodes" in t["label"] for t in out)


def test_available_targets_always_includes_hub_self_install():
    """The hub is always installed, so its self-install target is always
    selectable — even with an empty spoke registry and no agents."""
    out = cd.build_available_targets({}, set(), {}, cd.CERT_CAPABLE_MODULES, [])
    hub_entries = [t for t in out if t["module_type"] == "hub"]
    assert len(hub_entries) == 1
    assert hub_entries[0]["identifier"] == ""
    assert hub_entries[0]["label"] == "hub (LM WebUI)"
