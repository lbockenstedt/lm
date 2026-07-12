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
    # INSTALL_CERT allows 120s — the hypervisor path relays to a per-node agent
    # that runs `pvenode cert set` + restarts pveproxy (the pxmx spoke's own
    # relay timeout is 120s). 20s (the old value) timed out the hub while the
    # spoke was still waiting on the agent → "Timed out waiting for spoke
    # response" even though the cert install was still in progress.
    assert installs[0]["timeout"] == 120.0


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


# ── hub self-install target (module_type == "hub") ────────────────────────────

def test_distribute_hub_target_calls_install_on_hub():
    """A "hub" target is handled by the install_on_hub callable (the hub
    installing a cert on itself), NOT by get_spoke_by_type / INSTALL_CERT."""
    rr, calls = _fake_rr({(_LE, "LE_GET_CERT"): _le_get_cert_ok()})
    get_by_type = lambda mt: (_FW if mt == "firewall" else None)
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
    get_by_type = lambda mt: None
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
        rr, lambda mt: None, cd.CERT_CAPABLE_MODULES, _LE, "hub.example.com",
        [{"module_type": "hub"}], install_on_hub=install_on_hub))
    assert summary[0]["status"] == "ERROR"
    assert "permission denied" in summary[0]["message"]


def test_distribute_hub_target_callable_raise_is_caught():
    async def install_on_hub(domain, fullchain, privkey, chain, identifier):
        raise RuntimeError("boom")
    rr, _ = _fake_rr({(_LE, "LE_GET_CERT"): _le_get_cert_ok()})
    summary = _run(cd.distribute_cert_to_targets(
        rr, lambda mt: None, cd.CERT_CAPABLE_MODULES, _LE, "hub.example.com",
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
    get_by_type = lambda mt: _FW
    _run(cd.distribute_all_certs(rr, get_by_type, cd.CERT_CAPABLE_MODULES, _LE))
    # Only the stale cert's domain is pulled + installed.
    gets = [c for c in calls if c["cmd"] == "LE_GET_CERT"]
    assert [g["data"]["domain"] for g in gets] == ["stale.com"]
    installs = [c for c in calls if c["cmd"] == "INSTALL_CERT"]
    assert len(installs) == 1 and installs[0]["data"]["domain"] == "stale.com"


def test_distribute_all_no_certs_no_calls():
    rr, calls = _fake_rr({(_LE, "LE_LIST_CERTS"): _le_list_certs([])})
    _run(cd.distribute_all_certs(rr, lambda mt: None,
                                 cd.CERT_CAPABLE_MODULES, _LE))
    assert not [c for c in calls if c["cmd"] != "LE_LIST_CERTS"]


def test_distribute_all_list_error_is_noop():
    rr, calls = _fake_rr({(_LE, "LE_LIST_CERTS"): {
        "payload": {"data": {"status": "ERROR", "message": "down"}}}})
    _run(cd.distribute_all_certs(rr, lambda mt: None,
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
        _run(cd.distribute_all_certs(rr, lambda mt: None,
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
        _run(cd.distribute_all_certs(rr, lambda mt: _FW,
                                     cd.CERT_CAPABLE_MODULES, _LE))
    assert any("all 1 target(s) current" in r.message for r in caplog.records)
    assert not [c for c in calls if c["cmd"] == "LE_GET_CERT"]


def test_distribute_cert_no_targets_logs_skip(caplog):
    """distribute_cert_to_targets (the per-cert path) must also surface a
    no-targets skip, not a silent empty return."""
    rr, calls = _fake_rr({})
    with caplog.at_level("INFO", logger="le.distribution"):
        summary = _run(cd.distribute_cert_to_targets(
            rr, lambda mt: None, cd.CERT_CAPABLE_MODULES,
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