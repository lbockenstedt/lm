"""Adversarial test for F-K4: self-asserted AppBuilder identity must not hand a
spoke the pinned *fleet-authority* mTLS SANs.

A cert bearing the ``ab_cert_identities`` SANs passes ``_hub_request_authorized``
(H1) and thereby unlocks the fleet-wide reverse HUB_REQUEST channel (fleet RCE +
cross-tenant log/roster harvest). The recipient of that cert is decided in
``_provision_spoke_mtls_cert`` from ``is_bf`` — which is derived from the spoke's
SELF-REPORTED ``module_type`` (and the spoofable ``spoke_id``). So an
approved-but-ordinary spoke that merely claims ``module_type == "ab"`` would
otherwise be minted the fleet-authority cert.

These tests drive the REAL method (with a bare hub instance + fakes) and capture
the ``sans`` handed to the CA, asserting:

* TOFU default (no ``ab_spoke_ids`` configured) → the FIRST self-declared ``ab``
  is auto-designated by its UUID/pk (persisted to ``ab_spoke_ids``) and granted
  the pinned SANs, surfaced as an ``ab_identity_autodesignated`` anomaly;
* a LATER different spoke claiming ``ab`` is then REFUSED the pinned SANs;
* enforced (``ab_spoke_ids`` set) → a designated spoke gets the pinned SANs;
* enforced → a NON-designated spoke claiming ``module_type == "ab"`` is REFUSED
  the pinned SANs (it still gets an ordinary self-identity cert) and flagged.
"""
import asyncio
import os
import sys
import types

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

# _provision_spoke_mtls_cert lives in main.py, whose import chain builds
# HubEncryption at module load and requires a Fernet key. Provide an ephemeral
# one so the import (and thus the real method under test) is available offline.
os.environ.setdefault("LM_FERNET_KEY", __import__("cryptography.fernet",
                      fromlist=["Fernet"]).Fernet.generate_key().decode())

import main  # noqa: E402
from security import mtls_ca as _mtls_ca  # noqa: E402

_PINNED = ["ab.example.com"]


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


class _Threat:
    def __init__(self):
        self.events = []

    def note_anomaly(self, kind, detail, ip=None, severity="warning"):
        self.events.append((kind, severity, detail))


def _make_hub(global_config):
    h = main.LabManagerHub.__new__(main.LabManagerHub)
    h._is_loopback_spoke = lambda sid: False
    h._primary_key = lambda sid: sid
    h.spoke_module_types = {}
    h.spoke_telemetry = {}
    h.threat_monitor = _Threat()
    h.record_spoke_event = lambda *a, **k: None

    async def _send(_msg):
        return None

    async def _save():
        return None

    h.send_to_spoke = _send
    # A LIVE global-config dict + a real update_global_config so the TOFU
    # auto-designation (which persists ab_spoke_ids) is observable in-test.
    _gc = dict(global_config)

    def _update(cfg):
        _gc.update(cfg)

    h.state = types.SimpleNamespace(
        system_state={"mtls_revoked": {}, "mtls_client_certs": {}},
        get_global_config=lambda: _gc,
        update_global_config=_update,
        get_spoke_tenant=lambda pk: "t-acme",
        save_state_now=_save,
    )
    h._gc = _gc  # test-visible handle onto the live config
    return h


def _capture_sans(monkey_target=_mtls_ca):
    captured = {}

    def _issue(common_name, sans=None, days=397):
        captured["cn"] = common_name
        captured["sans"] = list(sans or [])
        # A syntactically empty cert — the method's x509 parse is best-effort and
        # wrapped, so a non-PEM value simply leaves the metadata blank.
        return ("-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----", "KEY")

    monkey_target.issue_client_cert = _issue
    return captured


def _provision(hub, spoke_id, module_type):
    hub.spoke_module_types[spoke_id] = module_type
    return _run(hub._provision_spoke_mtls_cert(spoke_id, force=True))


# ── TOFU default: the first self-declared ab is auto-designated by UUID ──────
def test_tofu_first_ab_is_autodesignated_and_gets_pinned_sans():
    orig = _mtls_ca.issue_client_cert
    try:
        cap = _capture_sans()
        hub = _make_hub({"ab_cert_identities": _PINNED})  # no ab_spoke_ids yet
        res = _provision(hub, "the-real-ab", "ab")
        assert res["status"] == "SUCCESS"
        assert "ab.example.com" in cap["sans"]              # first-use: granted
        kinds = [e[0] for e in hub.threat_monitor.events]
        assert "ab_identity_autodesignated" in kinds        # TOFU lock recorded
        assert all(e[1] == "warning" for e in hub.threat_monitor.events)  # never auto-blocks
        # ...and the spoke's UUID/pk is now persisted as the designated AppBuilder.
        assert hub._gc.get("ab_spoke_ids") == ["the-real-ab"]
    finally:
        _mtls_ca.issue_client_cert = orig


# ── TOFU then lock-out: a LATER different ab claimant is refused ─────────────
def test_tofu_locks_out_a_later_impostor():
    orig = _mtls_ca.issue_client_cert
    try:
        hub = _make_hub({"ab_cert_identities": _PINNED})
        # First-use: the real AppBuilder connects and is auto-designated.
        cap1 = _capture_sans()
        _provision(hub, "the-real-ab", "ab")
        assert "ab.example.com" in cap1["sans"]
        # Later: a different box claims module_type ab — must be REFUSED the SANs.
        cap2 = _capture_sans()
        res = _provision(hub, "impostor-box", "ab")
        assert res["status"] == "SUCCESS"                   # ordinary cert only
        assert cap2["sans"] == ["impostor-box"]
        assert "ab.example.com" not in cap2["sans"]
        assert any(e[0] == "ab_identity_spoof" for e in hub.threat_monitor.events)
    finally:
        _mtls_ca.issue_client_cert = orig


# ── enforced: explicitly-designated spoke is granted ────────────────────────
def test_enforced_designated_spoke_gets_pinned_sans():
    orig = _mtls_ca.issue_client_cert
    try:
        cap = _capture_sans()
        hub = _make_hub({"ab_cert_identities": _PINNED, "ab_spoke_ids": ["ab"]})
        res = _provision(hub, "ab", "ab")
        assert res["status"] == "SUCCESS"
        assert "ab.example.com" in cap["sans"]
        assert any(e[0] == "ab_identity_grant" for e in hub.threat_monitor.events)
    finally:
        _mtls_ca.issue_client_cert = orig


# ── enforced: the attack — a non-designated spoke claiming ab is REFUSED ─────
def test_enforced_non_designated_ab_claim_is_refused_and_flagged():
    orig = _mtls_ca.issue_client_cert
    try:
        cap = _capture_sans()
        hub = _make_hub({"ab_cert_identities": _PINNED, "ab_spoke_ids": ["ab"]})
        res = _provision(hub, "attacker-box", "ab")     # claims module_type ab
        assert res["status"] == "SUCCESS"               # gets an ORDINARY cert
        assert cap["sans"] == ["attacker-box"]          # but NOT the pinned SANs
        assert "ab.example.com" not in cap["sans"]
        kinds = [e[0] for e in hub.threat_monitor.events]
        assert "ab_identity_spoof" in kinds             # attempt is flagged
    finally:
        _mtls_ca.issue_client_cert = orig
