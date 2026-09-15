"""The hub must not restart a spoke forever trying to heal an mTLS cert.

``_provision_spoke_mtls_cert`` has a self-heal: if a spoke is connected but the
hub cannot see a verified client cert on the TLS leg, the registry cert is
assumed missing/stale on the spoke, so the hub mints a fresh one and pushes it.
The spoke-side handler writes it and **restarts to present it**.

Two ways that turned into a fleet-wide restart loop, both observed live:

1. **Role sub-spokes can never present a cert at all.** They share the parent
   agent's process and TLS connection, and the spoke-side handler returns early
   for anything with a ``parent_spoke_id`` ("parent carries the mTLS client
   cert"). So the hub could never observe an identity for them and re-issued
   every 10 minutes forever.

2. **Nothing bounded the retry.** The 10-minute minimum interval *paces* the
   heal, it does not stop it, and because every re-issue mints a fresh serial
   the spoke always sees a changed file and always restarts. Any spoke whose
   cert genuinely cannot reach the hub (TLS terminated by an intermediary, for
   instance) was therefore restarted every 10 minutes indefinitely, taking down
   every role it hosted.

Live hub logs showed 22-24 such re-pushes each for ``mipbe-lmagent`` and every
one of its role sub-spokes, plus other hosts fleet-wide.
"""
import asyncio
import os
import sys
import time
import types

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

os.environ.setdefault("LM_FERNET_KEY", __import__("cryptography.fernet",
                      fromlist=["Fernet"]).Fernet.generate_key().decode())

import main  # noqa: E402
from security import mtls_ca as _mtls_ca  # noqa: E402


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


class _WS:
    """A live websocket. ``peer_cert_identity`` None == connected cert-less."""

    def __init__(self, identity=None):
        self.peer_cert_identity = identity


def _make_hub(entry=None, ws=None, parent_of=None):
    h = main.LabManagerHub.__new__(main.LabManagerHub)
    h._is_loopback_spoke = lambda sid: False
    h._primary_key = lambda sid: sid
    h.spoke_module_types = {}
    h.spoke_telemetry = {}
    h.spoke_parent_map = dict(parent_of or {})
    h.threat_monitor = None
    h.events = []
    h.record_spoke_event = lambda sid, kind, detail="": h.events.append((sid, kind))
    h.active_connections = {"spoke-1": ws} if ws is not None else {}

    async def _send(_msg):
        return None

    async def _save():
        return None

    h.send_to_spoke = _send
    h.state = types.SimpleNamespace(
        system_state={"mtls_revoked": {},
                      "mtls_client_certs": ({"spoke-1": dict(entry)} if entry else {})},
        get_global_config=lambda: {},
        update_global_config=lambda cfg: None,
        get_spoke_tenant=lambda pk: "t-acme",
        save_state_now=_save,
        _mark_dirty=lambda: None,
    )
    return h


def _fake_cert_pem():
    """A real, parseable, far-future cert so the method's expiry bookkeeping
    behaves exactly as it does in production (a dummy PEM would leave
    not_after_ts at 0 and silently disable the self-heal branch under test)."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    import datetime

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "spoke-1")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=397))
            .sign(key, hashes.SHA256()))
    return (cert.public_bytes(serialization.Encoding.PEM).decode(),
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()).decode())


def _count_issues(monkeypatch):
    """Replace the CA so a test can count how many certs were actually minted
    without touching the real on-disk CA."""
    calls = []

    def _issue(cn, sans=None, days=397):
        calls.append(cn)
        return _fake_cert_pem()

    monkeypatch.setattr(_mtls_ca, "issue_client_cert", _issue)
    return calls


def _current_entry(**over):
    """A registry cert with plenty of life left, so only the self-heal can
    trigger a re-issue."""
    e = {"spoke_id": "spoke-1", "not_after_ts": time.time() + 300 * 86400,
         "not_after": "2027-01-01T00:00:00+00:00",
         "issued_at": time.time() - 4000, "serial": "aa"}
    e.update(over)
    return e


# ── 1. role sub-spokes ──────────────────────────────────────────────────────

def test_role_subspoke_is_never_issued_a_cert_it_cannot_present(monkeypatch):
    calls = _count_issues(monkeypatch)
    hub = _make_hub(parent_of={"spoke-1": "parent-agent"})

    out = _run(hub._provision_spoke_mtls_cert("spoke-1"))

    assert out["status"] == "skipped"
    assert out["reason"] == "role-subspoke"
    assert calls == [], "no cert should be minted for a role sub-spoke"


def test_role_subspoke_skip_holds_even_when_the_heal_would_have_fired(monkeypatch):
    """The exact live case: sub-spoke, current registry cert, connected without
    a visible identity -- previously an unbounded re-issue every 10 minutes."""
    calls = _count_issues(monkeypatch)
    hub = _make_hub(entry=_current_entry(), ws=_WS(None),
                    parent_of={"spoke-1": "parent-agent"})

    out = _run(hub._provision_spoke_mtls_cert("spoke-1"))

    assert out["status"] == "skipped"
    assert calls == []


def test_a_normal_spoke_is_still_issued_a_cert(monkeypatch):
    """Guard the guard: the sub-spoke skip must not suppress real spokes."""
    calls = _count_issues(monkeypatch)
    hub = _make_hub()

    out = _run(hub._provision_spoke_mtls_cert("spoke-1"))

    assert out["status"] == "SUCCESS"
    assert len(calls) == 1


# ── 2. the heal must give up ────────────────────────────────────────────────

def test_the_first_certless_heal_still_re_pushes(monkeypatch):
    calls = _count_issues(monkeypatch)
    hub = _make_hub(entry=_current_entry(), ws=_WS(None))

    out = _run(hub._provision_spoke_mtls_cert("spoke-1"))

    assert out["status"] == "SUCCESS"
    assert len(calls) == 1
    assert hub.state.system_state["mtls_client_certs"]["spoke-1"]["heal_attempts"] == 1


def test_repeated_certless_heals_stop_instead_of_restarting_forever(monkeypatch):
    """Each re-push restarts the spoke. Without a ceiling this never ends."""
    calls = _count_issues(monkeypatch)
    hub = _make_hub(entry=_current_entry(), ws=_WS(None))

    for _ in range(8):
        # The spoke reconnects still cert-less, and enough time has passed that
        # the 10-minute pacing interval is not what is holding us back.
        reg = hub.state.system_state["mtls_client_certs"].get("spoke-1")
        if reg:
            reg["issued_at"] = time.time() - 4000
        _run(hub._provision_spoke_mtls_cert("spoke-1"))

    assert len(calls) == main.LabManagerHub._MTLS_HEAL_MAX_ATTEMPTS, (
        "the hub must stop re-issuing once the heal is clearly not working")


def test_the_exhausted_answer_explains_itself(monkeypatch):
    _count_issues(monkeypatch)
    hub = _make_hub(
        entry=_current_entry(
            heal_attempts=main.LabManagerHub._MTLS_HEAL_MAX_ATTEMPTS),
        ws=_WS(None))

    out = _run(hub._provision_spoke_mtls_cert("spoke-1"))

    assert out["status"] == "heal-exhausted"
    assert out["attempts"] == main.LabManagerHub._MTLS_HEAL_MAX_ATTEMPTS
    assert "TLS termination" in out["message"]


def test_a_spoke_presenting_a_verified_cert_gets_its_budget_back(monkeypatch):
    calls = _count_issues(monkeypatch)
    hub = _make_hub(entry=_current_entry(heal_attempts=2), ws=_WS("spoke-1"))

    out = _run(hub._provision_spoke_mtls_cert("spoke-1"))

    assert out["status"] == "current"
    assert calls == [], "a spoke presenting a cert needs no re-issue"
    assert hub.state.system_state["mtls_client_certs"]["spoke-1"]["heal_attempts"] == 0


def test_an_explicit_force_restores_the_budget(monkeypatch):
    """An operator re-issue / the <7d expiry renewal is a deliberate 'try
    again' -- it must not be refused by an exhausted heal counter."""
    calls = _count_issues(monkeypatch)
    hub = _make_hub(
        entry=_current_entry(
            heal_attempts=main.LabManagerHub._MTLS_HEAL_MAX_ATTEMPTS),
        ws=_WS(None))

    out = _run(hub._provision_spoke_mtls_cert("spoke-1", force=True))

    assert out["status"] == "SUCCESS"
    assert len(calls) == 1
    assert hub.state.system_state["mtls_client_certs"]["spoke-1"]["heal_attempts"] == 0


def test_the_pacing_interval_is_still_respected(monkeypatch):
    """A freshly issued cert must not be re-issued on the very next connect."""
    calls = _count_issues(monkeypatch)
    hub = _make_hub(entry=_current_entry(issued_at=time.time() - 5), ws=_WS(None))

    out = _run(hub._provision_spoke_mtls_cert("spoke-1"))

    assert out["status"] == "current"
    assert calls == []
