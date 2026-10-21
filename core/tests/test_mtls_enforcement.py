"""mTLS enforcement: spoke-held keys (CSR), cert↔spoke binding, revocation,
enrollment-only gating, the bound-spoke ratchet, and the spoke's hub-TLS
verify ratchet."""
import asyncio
import datetime
import os
import ssl
import sys
import time
import types

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

os.environ.setdefault("LM_FERNET_KEY", __import__("cryptography.fernet",
                      fromlist=["Fernet"]).Fernet.generate_key().decode())

import main  # noqa: E402
import hub_mtls_enforcement as enf  # noqa: E402
from security import mtls as _mtls  # noqa: E402
from security import mtls_ca as _mtls_ca  # noqa: E402
from security.frame_crypto import ENCRYPTED_TYPES  # noqa: E402

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, rsa  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


@pytest.fixture
def ca(tmp_path, monkeypatch):
    monkeypatch.setattr(_mtls_ca, "_CA_DIR", str(tmp_path))
    monkeypatch.setattr(_mtls_ca, "CA_CERT_PATH", str(tmp_path / "ca.pem"))
    monkeypatch.setattr(_mtls_ca, "CA_KEY_PATH", str(tmp_path / "ca.key"))
    monkeypatch.setattr(_mtls_ca, "RETIRED_CA_PATH", str(tmp_path / "retired.pem"))
    _mtls_ca.ensure_ca()
    return tmp_path


def _csr(cn="attacker-chosen", key=None):
    key = key or ec.generate_private_key(ec.SECP256R1())
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
           .sign(key, hashes.SHA256()))
    return csr.public_bytes(serialization.Encoding.PEM).decode(), key


def _leaf(fullchain):
    end = "-----END CERTIFICATE-----"
    return x509.load_pem_x509_certificate((fullchain.split(end)[0] + end).encode())


def _der(fullchain):
    return _leaf(fullchain).public_bytes(serialization.Encoding.DER)


def _foreign_cert_der(cn="spoke-1"):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, _mtls_ca._CA_CN)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
            .issuer_name(name)  # claims the hub CA's NAME, but isn't signed by it
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.DER)


# ── CA: CSR signing + cert inspection ───────────────────────────────────────

def test_sign_csr_uses_only_the_public_key_and_hub_chosen_identity(ca):
    pem, key = _csr("attacker-chosen")
    chain = _mtls_ca.sign_csr(pem, "spoke-1", sans=["spoke-1"])
    leaf = _leaf(chain)
    assert leaf.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "spoke-1"
    san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.DNSName) == ["spoke-1"]
    assert (leaf.public_key().public_bytes(serialization.Encoding.DER,
                                           serialization.PublicFormat.SubjectPublicKeyInfo)
            == key.public_key().public_bytes(serialization.Encoding.DER,
                                             serialization.PublicFormat.SubjectPublicKeyInfo))


def test_sign_csr_rejects_weak_key_and_garbage(ca):
    weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    pem, _ = _csr(key=weak)
    with pytest.raises(ValueError):
        _mtls_ca.sign_csr(pem, "spoke-1")
    with pytest.raises(ValueError):
        _mtls_ca.sign_csr("not a csr", "spoke-1")


def test_inspect_distinguishes_hub_ca_from_lookalike_issuer(ca):
    chain, _ = _mtls_ca.issue_client_cert("spoke-1", sans=["spoke-1"])
    info = _mtls_ca.inspect_client_cert(_der(chain))
    assert info["hub_ca"] is True
    assert info["sans"] == ("spoke-1",)
    assert info["serial"] == format(_leaf(chain).serial_number, "x")
    fake = _mtls_ca.inspect_client_cert(_foreign_cert_der())
    assert fake["hub_ca"] is False
    assert _mtls_ca.inspect_client_cert(b"") is None


def test_inspect_trusts_retired_ca_after_rollover(ca):
    chain, _ = _mtls_ca.issue_client_cert("spoke-1")
    _mtls_ca.rollover_ca()
    assert _mtls_ca.inspect_client_cert(_der(chain))["hub_ca"] is True


def test_client_cert_frame_is_app_layer_encrypted():
    assert "SPOKE_SET_MTLS_CLIENT_CERT" in ENCRYPTED_TYPES


# ── hub connect gate ────────────────────────────────────────────────────────

class _WS:
    def __init__(self, der=None):
        self.peer_cert_der = der
        self.closed = None

    async def close(self, code=1000, reason=""):
        self.closed = (code, reason)


def _hub(gc=None, loopback=False, parent_of=None):
    h = main.LabManagerHub.__new__(main.LabManagerHub)
    h._primary_key = lambda sid: sid
    h._is_loopback_spoke = lambda sid: loopback
    h.spoke_parent_map = dict(parent_of or {})
    h.spoke_telemetry = {}
    h.threat_monitor = None
    h.events = []
    h.record_spoke_event = lambda sid, kind, detail="": h.events.append((sid, kind, detail))
    cfg = {"mtls_enabled": True}
    cfg.update(gc or {})
    h.state = types.SimpleNamespace(
        system_state={"mtls_revoked": {}, "mtls_client_certs": {}},
        get_global_config=lambda: cfg,
        _mark_dirty=lambda: None,
    )
    return h


@pytest.fixture
def mtls_on(monkeypatch):
    monkeypatch.delenv("LM_MTLS_ENFORCE", raising=False)
    monkeypatch.delenv("LM_MTLS_DISABLE", raising=False)
    _mtls.set_runtime_enabled(True)
    monkeypatch.setattr(_mtls, "_listener_armed", True)
    yield
    _mtls.set_runtime_enabled(None)


def test_own_hub_ca_cert_is_accepted_and_binds(ca, mtls_on):
    h = _hub()
    chain, _ = _mtls_ca.issue_client_cert("spoke-1", sans=["spoke-1"])
    assert h._mtls_connect_gate("spoke-1", "spoke-1", _WS(_der(chain))) == ("ok", "verified")
    assert h.state.system_state["mtls_bound"]["spoke-1"]["serial"]


def test_another_spokes_cert_is_rejected(ca, mtls_on):
    h = _hub()
    chain, _ = _mtls_ca.issue_client_cert("spoke-2", sans=["spoke-2"])
    assert h._mtls_connect_gate("spoke-1", "spoke-1", _WS(_der(chain))) == \
        ("reject", "cert-identity-mismatch")


def test_renamed_spoke_keeps_working_via_registered_serial(ca, mtls_on):
    h = _hub()
    chain, _ = _mtls_ca.issue_client_cert("old-name", sans=["old-name"])
    h.state.system_state["mtls_client_certs"]["guid-1"] = {
        "serial": format(_leaf(chain).serial_number, "x")}
    assert h._mtls_connect_gate("new-name", "guid-1", _WS(_der(chain)))[0] == "ok"


def test_role_subspoke_may_present_parent_cert(ca, mtls_on):
    h = _hub(parent_of={"agent-x-netbox": "agent-x"})
    chain, _ = _mtls_ca.issue_client_cert("agent-x", sans=["agent-x"])
    assert h._mtls_connect_gate("agent-x-netbox", "agent-x-netbox",
                                _WS(_der(chain)))[0] == "ok"


def test_revoked_serial_is_rejected(ca, mtls_on):
    h = _hub()
    chain, _ = _mtls_ca.issue_client_cert("spoke-1", sans=["spoke-1"])
    h._mtls_record_revoked_serial("spoke-1", format(_leaf(chain).serial_number, "x"),
                                  time.time() + 86400)
    assert h._mtls_connect_gate("spoke-1", "spoke-1", _WS(_der(chain))) == \
        ("reject", "revoked-cert")


def test_certless_unbound_spoke_enrolls_then_falls_back_after_budget(ca, mtls_on):
    h = _hub()
    assert h._mtls_connect_gate("spoke-1", "spoke-1", _WS()) == ("enroll", "no-cert")
    h.state.system_state["mtls_enroll"] = {"spoke-1": {"attempts": enf._MTLS_ENROLL_MAX}}
    assert h._mtls_connect_gate("spoke-1", "spoke-1", _WS()) == ("ok", "enroll-exhausted")


def test_strict_mode_never_falls_back(ca, mtls_on):
    h = _hub(gc={"mtls_require_cert": True})
    h.state.system_state["mtls_enroll"] = {"spoke-1": {"attempts": 99}}
    assert h._mtls_connect_gate("spoke-1", "spoke-1", _WS())[0] == "enroll"


def test_bound_spoke_without_cert_is_refused_until_admin_reenroll(ca, mtls_on):
    h = _hub()
    chain, _ = _mtls_ca.issue_client_cert("spoke-1", sans=["spoke-1"])
    h._mtls_connect_gate("spoke-1", "spoke-1", _WS(_der(chain)))
    assert h._mtls_connect_gate("spoke-1", "spoke-1", _WS()) == ("reject", "cert-required")
    h._mtls_allow_reenroll("spoke-1")
    assert h._mtls_connect_gate("spoke-1", "spoke-1", _WS())[0] == "enroll"


def test_revoked_identity_without_cert_is_refused(ca, mtls_on):
    h = _hub()
    h.state.system_state["mtls_revoked"]["spoke-1"] = {"serial": "ab"}
    assert h._mtls_connect_gate("spoke-1", "spoke-1", _WS()) == ("reject", "revoked-identity")


def test_exemptions_and_kill_switches(ca, mtls_on, monkeypatch):
    assert _hub(loopback=True)._mtls_connect_gate("s", "s", _WS()) == ("ok", "exempt:loopback")
    assert _hub()._mtls_connect_gate("s", "s", _WS(), "ab") == ("ok", "exempt:client-only-type")
    assert _hub(gc={"mtls_enforce": False})._mtls_connect_gate("s", "s", _WS())[1] == "not-enforcing"
    monkeypatch.setenv("LM_MTLS_ENFORCE", "0")
    assert _hub()._mtls_connect_gate("s", "s", _WS())[1] == "not-enforcing"


def test_runtime_enable_without_armed_listener_does_not_enforce(ca, mtls_on, monkeypatch):
    monkeypatch.setattr(_mtls, "_listener_armed", False)
    h = _hub()
    h.state.system_state["mtls_bound"] = {"spoke-1": {"serial": "aa"}}
    assert h._mtls_connect_gate("spoke-1", "spoke-1", _WS()) == ("ok", "not-enforcing")


def test_admin_reenroll_replaces_a_rejected_presented_cert(ca, mtls_on):
    h = _hub()
    chain, _ = _mtls_ca.issue_client_cert("spoke-1", sans=["spoke-1"])
    h._mtls_record_revoked_serial("spoke-1", format(_leaf(chain).serial_number, "x"),
                                  time.time() + 86400)
    h.state.system_state["mtls_revoked"]["spoke-1"] = {}
    assert h._mtls_connect_gate("spoke-1", "spoke-1", _WS(_der(chain)))[0] == "reject"
    h._mtls_allow_reenroll("spoke-1")
    assert "spoke-1" not in h.state.system_state["mtls_revoked"]
    assert h._mtls_connect_gate("spoke-1", "spoke-1", _WS(_der(chain))) == \
        ("enroll", "reenroll:revoked-cert")
    other, _ = _mtls_ca.issue_client_cert("old-name", sans=["old-name"])
    assert h._mtls_connect_gate("spoke-1", "spoke-1", _WS(_der(other))) == \
        ("enroll", "reenroll:cert-identity-mismatch")


def test_identity_migration_carries_mtls_records():
    from hub_identity import HubIdentityMixin
    ss = {"mtls_client_certs": {"old": {"serial": "aa"}}, "mtls_bound": {"old": {}},
          "mtls_enroll": {"old": {"attempts": 1}}}
    km = types.SimpleNamespace(rename_spoke_keys=lambda a, b: None)
    h = types.SimpleNamespace(
        state=types.SimpleNamespace(system_state=ss, rename_module=lambda a, b: None,
                                    _mark_dirty=lambda: None),
        spoke_module_types={}, spoke_versions={}, spoke_telemetry={}, spoke_events={},
        spoke_recovery={}, rate_limiters={}, active_connections={},
        active_connection_key_ids={}, key_manager=km,
        heartbeat=types.SimpleNamespace(last_seen={}))
    HubIdentityMixin._migrate_spoke_identity(h, "old", "new")
    for k in ("mtls_client_certs", "mtls_bound", "mtls_enroll"):
        assert "new" in ss[k] and "old" not in ss[k]


def test_mtls_off_never_enforces(ca):
    _mtls.set_runtime_enabled(False)
    try:
        assert _hub()._mtls_connect_gate("s", "s", _WS()) == ("ok", "not-enforcing")
    finally:
        _mtls.set_runtime_enabled(None)


def test_reject_closes_with_cert_required_code(mtls_on):
    h = _hub()
    ws = _WS()
    _run(h._mtls_reject("spoke-1", "spoke-1", ws, "cert-required"))
    assert ws.closed[0] == enf.CLOSE_CERT_REQUIRED
    assert ("spoke-1", "mtls_rejected", "cert-required") in h.events


# ── hub provisioning via CSR ────────────────────────────────────────────────

def _prov_hub(csr_capable):
    h = _hub()
    h.spoke_module_types = {}
    h.active_connections = {}
    h.spoke_mtls_csr_capable = {"spoke-1": csr_capable}
    h._is_role_subspoke = lambda sid: False
    h.sent = []
    h.requests = []

    async def _send(msg):
        h.sent.append(msg)

    async def _save():
        return None

    h.send_to_spoke = _send
    h.state.update_global_config = lambda c: None
    h.state.get_spoke_tenant = lambda pk: ""
    h.state.save_state_now = _save
    return h


def test_csr_capable_spoke_never_receives_a_private_key(ca):
    h = _prov_hub(True)
    pem, key = _csr()

    async def _rr(sid, cmd, data, timeout=None, signing_secret=None):
        h.requests.append(cmd)
        return {"status": "SUCCESS", "csr": pem}

    h.request_response = _rr
    out = _run(h._provision_spoke_mtls_cert("spoke-1", force=True))
    assert out["status"] == "SUCCESS"
    assert h.requests == ["SPOKE_MTLS_CSR"]
    data = h.sent[-1].payload.data
    assert "key" not in data and data["cert"]
    reg = h.state.system_state["mtls_client_certs"]["spoke-1"]
    assert reg["key_custody"] == "spoke-csr"


def test_legacy_spoke_still_gets_cert_and_key(ca):
    h = _prov_hub(False)
    out = _run(h._provision_spoke_mtls_cert("spoke-1", force=True))
    assert out["status"] == "SUCCESS"
    assert h.sent[-1].payload.data.get("key")


def test_revoke_records_serials_and_unbinds(ca):
    h = _prov_hub(False)
    _run(h._provision_spoke_mtls_cert("spoke-1", force=True))
    serial = h.state.system_state["mtls_client_certs"]["spoke-1"]["serial"]
    h.state.system_state["mtls_bound"] = {"spoke-1": {"serial": serial}}
    _run(h._revoke_spoke_mtls_cert("spoke-1"))
    assert serial.lstrip("0") in h.state.system_state["mtls_revoked_serials"]
    assert "spoke-1" not in h.state.system_state["mtls_bound"]


# ── spoke side: CSR + keyless cert install ──────────────────────────────────

from messaging.control_plane import BaseControlPlane  # noqa: E402


class _Spoke:
    _pubkey_fingerprint = staticmethod(BaseControlPlane._pubkey_fingerprint)
    _mtls_write_if_changed = staticmethod(BaseControlPlane._mtls_write_if_changed)
    _handle_mtls_csr = BaseControlPlane._handle_mtls_csr
    _mtls_key_for_cert = BaseControlPlane._mtls_key_for_cert
    _handle_set_mtls_client_cert = BaseControlPlane._handle_set_mtls_client_cert

    def __init__(self, d):
        self.d = str(d)
        self.spoke_id = "spoke-1"
        self.parent_spoke_id = ""
        self.env = {}
        self.restarted = False

    def _mtls_material_dir(self):
        return self.d

    def _persist_secret_to_env(self, k, v):
        self.env[k] = v

    async def _deferred_restart_exit(self):
        self.restarted = True


def test_spoke_generates_key_locally_and_installs_keyless_cert(ca, tmp_path):
    sp = _Spoke(tmp_path)

    async def flow():
        r = await sp._handle_mtls_csr({"cn": "spoke-1"})
        assert r["status"] == "SUCCESS"
        chain = _mtls_ca.sign_csr(r["csr"], "spoke-1")
        out = await sp._handle_set_mtls_client_cert({"cert": chain})
        await asyncio.sleep(0)
        return out

    out = _run(flow())
    assert out["status"] == "SUCCESS"
    key_path = tmp_path / "mtls-hub-client.key"
    assert key_path.exists() and oct(key_path.stat().st_mode & 0o777) == "0o600"
    assert not (tmp_path / "mtls-hub-client.key.pending").exists()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_cert_chain(str(tmp_path / "mtls-hub-client.crt"), str(key_path))


def test_spoke_refuses_cert_for_a_key_it_did_not_generate(ca, tmp_path):
    sp = _Spoke(tmp_path)
    chain, _ = _mtls_ca.issue_client_cert("spoke-1")
    out = _run(sp._handle_set_mtls_client_cert({"cert": chain}))
    assert out["status"] == "ERROR"


def test_pending_key_survives_restart_via_file(ca, tmp_path):
    sp = _Spoke(tmp_path)
    r = _run(sp._handle_mtls_csr({}))
    chain = _mtls_ca.sign_csr(r["csr"], "spoke-1")
    sp2 = _Spoke(tmp_path)  # fresh process: no in-memory pending keys
    assert _run(sp2._handle_set_mtls_client_cert({"cert": chain}))["status"] == "SUCCESS"


# ── spoke side: hub TLS verify ratchet ──────────────────────────────────────

class _Dialer:
    _resolve_auto_tls_verify = BaseControlPlane._resolve_auto_tls_verify
    _hub_tls_marker_path = BaseControlPlane._hub_tls_marker_path
    _hub_host_port = BaseControlPlane._hub_host_port
    _mtls_write_if_changed = staticmethod(BaseControlPlane._mtls_write_if_changed)

    def __init__(self, d, probe):
        self.d = str(d)
        self.hub_url = "wss://hub.example.com:443"
        self._tls_ca_cert = ""
        self._tls_verify = False
        self._tls_auto_neg_until = 0.0
        self._probe = probe
        self.probes = 0

    def _mtls_material_dir(self):
        return self.d

    async def _probe_hub_tls_verify(self):
        self.probes += 1
        return self._probe


def test_auto_verify_ratchets_on_after_first_success(tmp_path):
    d = _Dialer(tmp_path, True)
    _run(d._resolve_auto_tls_verify())
    assert d._tls_verify is True
    assert (tmp_path / "hub-tls-verified").read_text().strip() == "hub.example.com"
    d2 = _Dialer(tmp_path, False)  # later the hub cert stops verifying
    _run(d2._resolve_auto_tls_verify())
    assert d2._tls_verify is True and d2.probes == 0  # still required: no downgrade


def test_auto_verify_stays_off_for_unverifiable_hub_and_backs_off(tmp_path):
    d = _Dialer(tmp_path, False)
    _run(d._resolve_auto_tls_verify())
    assert d._tls_verify is False and not (tmp_path / "hub-tls-verified").exists()
    _run(d._resolve_auto_tls_verify())
    assert d.probes == 1


def test_ratchet_marker_is_bound_to_the_hub_host(tmp_path):
    (tmp_path / "hub-tls-verified").write_text("other-hub.example.com\n")
    d = _Dialer(tmp_path, False)
    _run(d._resolve_auto_tls_verify())
    assert d._tls_verify is False


# ── fleet hub-TLS-verify policy (SPOKE_SET_TLS_VERIFY) ──────────────────────

class _PolicySpoke:
    _handle_set_tls_verify = BaseControlPlane._handle_set_tls_verify
    _tls_mode_from_env = staticmethod(BaseControlPlane._tls_mode_from_env)
    _hub_tls_policy_path = BaseControlPlane._hub_tls_policy_path
    _read_hub_tls_policy = BaseControlPlane._read_hub_tls_policy
    _hub_url_is_loopback = staticmethod(BaseControlPlane._hub_url_is_loopback)
    _mtls_write_if_changed = staticmethod(BaseControlPlane._mtls_write_if_changed)

    def __init__(self, d, mode="auto", probe=True, url="wss://hub.example.com:443"):
        self.d = str(d)
        self.hub_url = url
        self.parent_spoke_id = ""
        self._tls_verify_mode = mode
        self._probe = probe
        self.restarts = 0

    def _mtls_material_dir(self):
        return self.d

    async def _probe_hub_tls_verify(self):
        return self._probe

    async def _deferred_restart_exit(self):
        self.restarts += 1


def _apply(sp, mode):
    async def go():
        r = await sp._handle_set_tls_verify({"mode": mode})
        await asyncio.sleep(0)
        return r
    return _run(go())


def test_policy_on_persists_and_restarts_once(tmp_path):
    sp = _PolicySpoke(tmp_path)
    assert _apply(sp, "on")["effective"] == "on"
    assert (tmp_path / "hub-tls-policy").read_text().strip() == "on"
    assert sp.restarts == 1
    assert _apply(sp, "on")["message"] == "already current"
    assert sp.restarts == 1


def test_policy_on_refused_when_hub_cert_does_not_verify(tmp_path):
    sp = _PolicySpoke(tmp_path, probe=False)
    r = _apply(sp, "on")
    assert r["status"] == "ERROR" and r["effective"] == "auto"
    assert not (tmp_path / "hub-tls-policy").exists() and sp.restarts == 0


def test_policy_install_clears_override(tmp_path, monkeypatch):
    monkeypatch.setenv("LM_HUB_TLS_VERIFY", "0")
    sp = _PolicySpoke(tmp_path, mode="on")
    (tmp_path / "hub-tls-policy").write_text("on\n")
    r = _apply(sp, "install")
    assert r["effective"] == "auto" and sp.restarts == 1
    assert not (tmp_path / "hub-tls-policy").exists()


def test_policy_skips_loopback_and_role_subspokes(tmp_path):
    sp = _PolicySpoke(tmp_path, url="wss://127.0.0.1:443")
    assert "skipped" in _apply(sp, "on")["message"]
    sp2 = _PolicySpoke(tmp_path)
    sp2.parent_spoke_id = "agent-x"
    assert "skipped" in _apply(sp2, "off")["message"]
    assert sp.restarts == sp2.restarts == 0


def test_policy_file_overrides_env_at_startup(tmp_path, monkeypatch):
    monkeypatch.setenv("LM_HUB_TLS_VERIFY", "0")
    sp = _PolicySpoke(tmp_path)
    (tmp_path / "hub-tls-policy").write_text("on\n")
    assert sp._read_hub_tls_policy() == "on"
    (tmp_path / "hub-tls-policy").write_text("bogus\n")
    assert sp._read_hub_tls_policy() == ""


def test_hub_fanout_reports_refusals_and_skips_role_subspokes():
    h = main.LabManagerHub.__new__(main.LabManagerHub)
    h.approved_modules = {"a": True, "b": True, "a-netbox": True, "c": False}
    h._is_role_subspoke = lambda sid: sid == "a-netbox"
    sent = []

    async def _poq(sid, cmd, data):
        sent.append((sid, cmd, data))
        if sid == "b":
            return {"status": "ok", "queued": False,
                    "result": {"payload": {"data": {"status": "ERROR", "message": "no verify"}}}}
        return {"status": "ok", "queued": False, "result": {"status": "SUCCESS"}}

    h.push_or_queue_to_spoke = _poq
    out = _run(h.push_tls_verify_to_all_spokes("on"))
    assert out["pushed"] == ["a"]
    assert out["refused"] == [{"spoke_id": "b", "message": "no verify"}]
    assert {s for s, _, _ in sent} == {"a", "b"}
    assert all(c == "SPOKE_SET_TLS_VERIFY" and d == {"mode": "on"} for _, c, d in sent)
