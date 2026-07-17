"""H4 hub inbound: AEAD-decrypt of inbound secret-bearing frames.

Exercises the REAL ``LabManagerHub._decrypt_inbound_payload`` (the top-level
inbound decrypt) and ``_handle_agent_relay_up`` (the nested CS_TOKEN_RESULT
decrypt, refinement #2), both called unbound on a minimal stand-in holding
only the attributes they touch (pattern from
``test_signature_rotation_window.py``).

Covers: current-key and history-key top-level decrypt; drop on tamper; drop on
encrypted-frame-with-no-decrypt-key; plaintext passthrough (returns the secret
without dropping); nested CS_TOKEN_RESULT inside AGENT_RELAY_UP decrypts and
relays; nested tamper → dropped (returns True, no fall-through).
"""

import asyncio
import os
import time

import main  # noqa: E402
from security.key_manager import KeyManager, ManagedKey  # noqa: E402
from security.signer import MessageSigner, encode_frame  # noqa: E402
from security import frame_crypto as fc  # noqa: E402


def _make_km():
    km = KeyManager("keys_h4_in.json", "hub_secret_h4_in.json")
    km.storage_path = os.path.join("/tmp", "lm_keys_h4_in.json")
    km.hub_secret_path = os.path.join("/tmp", "lm_hub_secret_h4_in.json")
    data_dir = os.path.join(os.path.dirname(__file__), "..", "data")
    for name in ("keys_h4_in.json", "hub_secret_h4_in.json"):
        try:
            os.remove(os.path.join(data_dir, name))
        except OSError:
            pass
    return km


def _key(secret):
    return ManagedKey(key_id="k-" + secret[:6], secret=secret,
                      created_at=time.time(), expires_at=time.time() + 3600)


class _Hub:
    """Holds only what _decrypt_inbound_payload + _handle_agent_relay_up touch."""

    def __init__(self, km):
        self.key_manager = km
        self.spoke_telemetry = {}
        self.agent_info = {}
        self.agent_logs = {}
        self.max_log_size = 100
        self.heartbeat = type("HB", (), {"update_heartbeat": lambda *a, **k: None})()

    def _reconcile_spoke_identity(self, *a, **k):
        pass

    def _inherit_agent_tenant(self, *a, **k):
        pass

    def record_spoke_event(self, *a, **k):
        pass

    async def _relay_cs_event(self, *a, **k):
        # replaced per-test with a capturing stub
        return None


def _body(ptype, data):
    return {"header": {"sender_id": "s1", "destination_id": "hub"},
            "payload": {"type": ptype, "data": data}}


def _frame(secret, ptype, data, encrypted=True):
    """Build a signed <sig>.<body> wire frame; if encrypted, wrap data first."""
    body = _body(ptype, data)
    payload = body["payload"]
    if encrypted:
        fc.wrap(secret, payload)
    wire = encode_frame(MessageSigner(secret), body)
    import json
    sig, b = wire.split(".", 1)
    return json.loads(b)  # the msg_data the hub decodes


# ── _decrypt_inbound_payload: top-level ──────────────────────────────────────

def test_decrypts_current_key_encrypted_payload():
    km = _make_km()
    km.keys["s1"] = _key("current-secret")
    hub = _Hub(km)
    msg_data = _frame("current-secret", "INSTALL_CERT",
                      {"privkey": "PEM"}, encrypted=True)
    ret = asyncio.new_event_loop().run_until_complete(
        main.LabManagerHub._decrypt_inbound_payload(hub, "s1", "current", msg_data))
    assert ret is not main._H4_DROP
    assert ret == "current-secret"
    # data is now plaintext again.
    assert msg_data["payload"]["data"] == {"privkey": "PEM"}
    assert not fc.is_encrypted(msg_data["payload"])


def test_decrypts_history_key_encrypted_payload():
    km = _make_km()
    km.keys["s1"] = _key("current-secret")
    km.history["s1"] = [_key("prev-secret")]
    hub = _Hub(km)
    # Spoke signed+encrypted with its OLD (prev) key — hub verifies via history.
    msg_data = _frame("prev-secret", "INSTALL_CERT",
                      {"privkey": "PEM"}, encrypted=True)
    ret = asyncio.new_event_loop().run_until_complete(
        main.LabManagerHub._decrypt_inbound_payload(hub, "s1", "history", msg_data))
    assert ret == "prev-secret"
    assert msg_data["payload"]["data"] == {"privkey": "PEM"}


def test_drops_tampered_encrypted_payload():
    km = _make_km()
    km.keys["s1"] = _key("current-secret")
    hub = _Hub(km)
    msg_data = _frame("current-secret", "INSTALL_CERT",
                      {"privkey": "PEM"}, encrypted=True)
    # Corrupt the ciphertext (flip last b64 char).
    d = msg_data["payload"]["data"]
    msg_data["payload"]["data"] = d[:-1] + ("A" if d[-1] != "A" else "B")
    ret = asyncio.new_event_loop().run_until_complete(
        main.LabManagerHub._decrypt_inbound_payload(hub, "s1", "current", msg_data))
    assert ret is main._H4_DROP


def test_drops_encrypted_payload_with_no_decrypt_key():
    """A verified frame marked encrypted but the hub has no secret for the
    spoke → drop (can't decrypt, must not dispatch ciphertext)."""
    km = _make_km()
    # spoke "s1" has no key recorded at all
    hub = _Hub(km)
    msg_data = _frame("some-secret", "INSTALL_CERT",
                      {"privkey": "PEM"}, encrypted=True)
    ret = asyncio.new_event_loop().run_until_complete(
        main.LabManagerHub._decrypt_inbound_payload(hub, "s1", "current", msg_data))
    assert ret is main._H4_DROP


def test_plaintext_payload_passes_through_and_returns_secret():
    """An unmarked (plaintext / non-secret) frame passes through untouched;
    the resolved decrypt secret is still returned (for nested decrypt)."""
    km = _make_km()
    km.keys["s1"] = _key("current-secret")
    hub = _Hub(km)
    msg_data = _frame("current-secret", "GET_VERSION",
                      {"want": "v"}, encrypted=False)
    ret = asyncio.new_event_loop().run_until_complete(
        main.LabManagerHub._decrypt_inbound_payload(hub, "s1", "current", msg_data))
    assert ret == "current-secret"
    assert msg_data["payload"]["data"] == {"want": "v"}


# ── _handle_agent_relay_up: nested CS_TOKEN_RESULT (refinement #2) ────────────

def _relay_body(inner_type, inner_data, secret=None, encrypt_inner=False):
    """Build an AGENT_RELAY_UP msg_data whose inner payload is optionally
    encrypted (the spoke's _encode_frame does this when hub_enc_capable)."""
    inner = {"type": inner_type, "data": inner_data}
    if encrypt_inner:
        fc.wrap(secret, inner)
    return {"header": {"sender_id": "s1"},
            "payload": {"type": "AGENT_RELAY_UP", "data": {
                "agent_id": "a1", "install_uuid": "u1", "hostname": "h1",
                "original_payload": {"payload": inner}}}}


def test_nested_cs_token_result_decrypts_before_relay():
    """The AGENT_RELAY_UP envelope is plaintext; the nested CS_TOKEN_RESULT is
    encrypted. The hub decrypts the inner payload (with the verify-source
    secret) BEFORE the CS_* branch reads it, then relays plaintext to the cs
    spoke via _relay_cs_event (a fire-and-forget create_task)."""
    km = _make_km()
    km.keys["s1"] = _key("current-secret")
    hub = _Hub(km)
    msg_data = _relay_body("CS_TOKEN_RESULT", {"token": "TOK-SECRET"},
                           secret="current-secret", encrypt_inner=True)

    relayed = []
    async def _relay_cs_event(spoke_id, agent_id, otype, data):
        relayed.append((spoke_id, agent_id, otype, data))
        return None
    hub._relay_cs_event = _relay_cs_event

    payload = msg_data["payload"]

    async def _drive():
        ok = await main.LabManagerHub._handle_agent_relay_up(
            hub, "s1", msg_data, payload, _dec_secret="current-secret")
        # The CS_* branch detached a create_task — drain it so the stub records
        # the relay before we assert.
        await asyncio.gather(*asyncio.all_tasks() - {asyncio.current_task()})
        return ok

    ok = asyncio.new_event_loop().run_until_complete(_drive())
    assert ok is True
    # Inner payload was decrypted in place.
    inner = payload["data"]["original_payload"]["payload"]
    assert not fc.is_encrypted(inner)
    assert inner["type"] == "CS_TOKEN_RESULT"
    # The CS_* branch read the decrypted data and dispatched a relay with the
    # plaintext token.
    assert relayed, "expected a _relay_cs_event dispatch"
    assert relayed[0][2] == "CS_TOKEN_RESULT"
    assert relayed[0][3] == {"token": "TOK-SECRET"}


def test_nested_tampered_is_dropped_not_relaid():
    km = _make_km()
    km.keys["s1"] = _key("current-secret")
    hub = _Hub(km)
    msg_data = _relay_body("CS_TOKEN_RESULT", {"token": "TOK"},
                           secret="current-secret", encrypt_inner=True)
    # Corrupt the inner ciphertext.
    inner = msg_data["payload"]["data"]["original_payload"]["payload"]
    d = inner["data"]
    inner["data"] = d[:-1] + ("A" if d[-1] != "A" else "B")

    relayed = []
    async def _relay_cs_event(spoke_id, agent_id, otype, data):
        relayed.append((otype, data))
        return None
    hub._relay_cs_event = _relay_cs_event

    payload = msg_data["payload"]

    async def _drive():
        ok = await main.LabManagerHub._handle_agent_relay_up(
            hub, "s1", msg_data, payload, _dec_secret="current-secret")
        await asyncio.gather(*asyncio.all_tasks() - {asyncio.current_task()})
        return ok

    ok = asyncio.new_event_loop().run_until_complete(_drive())
    assert ok is True  # matched AGENT_RELAY_UP; did not fall through
    assert not relayed, "tampered nested payload must not be relayed"


def test_nested_encrypted_with_no_decrypt_key_dropped():
    km = _make_km()
    km.keys["s1"] = _key("current-secret")
    hub = _Hub(km)
    msg_data = _relay_body("CS_TOKEN_RESULT", {"token": "TOK"},
                           secret="current-secret", encrypt_inner=True)
    relayed = []
    async def _relay_cs_event(*a, **k):
        relayed.append(a)
        return None
    hub._relay_cs_event = _relay_cs_event

    payload = msg_data["payload"]

    async def _drive():
        ok = await main.LabManagerHub._handle_agent_relay_up(
            hub, "s1", msg_data, payload, _dec_secret=None)
        await asyncio.gather(*asyncio.all_tasks() - {asyncio.current_task()})
        return ok

    ok = asyncio.new_event_loop().run_until_complete(_drive())
    assert ok is True
    assert not relayed


def test_plaintext_agent_relay_up_unchanged():
    """A legacy spoke sends AGENT_RELAY_UP with a plaintext inner payload — no
    decrypt attempted, normal relay."""
    km = _make_km()
    km.keys["s1"] = _key("current-secret")
    hub = _Hub(km)
    msg_data = _relay_body("AGENT_LOG", {"message": "hi"},
                           encrypt_inner=False)
    relayed = []
    async def _relay_cs_event(*a, **k):
        relayed.append(a)
        return None
    hub._relay_cs_event = _relay_cs_event

    payload = msg_data["payload"]

    async def _drive():
        ok = await main.LabManagerHub._handle_agent_relay_up(
            hub, "s1", msg_data, payload, _dec_secret="current-secret")
        await asyncio.gather(*asyncio.all_tasks() - {asyncio.current_task()})
        return ok

    ok = asyncio.new_event_loop().run_until_complete(_drive())
    assert ok is True
    # AGENT_LOG is handled (logged), not relayed to cs — relayed stays empty.
    assert not relayed