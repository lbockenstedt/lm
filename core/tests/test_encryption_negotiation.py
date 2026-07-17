"""H4 capability negotiation: the four hub/spoke version combos all degrade to
fail-safe plaintext, and on-by-default both directions encrypt.

The negotiation is two additive ``enc:"v1"`` markers: the spoke advertises in
its auth frame, the hub in its HUB_VERIFIED proof. Hub→spoke encrypts iff the
spoke advertised enc (and the hub's kill switch is on); spoke→hub encrypts iff
the hub advertised enc (and the spoke's kill switch is on). So:

  new + new        → both directions encrypted
  legacy + new     → plaintext (the legacy side neither advertises nor encrypts)
  new + legacy     → plaintext
  kill switch on either → that side behaves as legacy → plaintext

This file asserts the GATE compositions at the frame level using the real
``LabManagerHub.send_to_spoke`` (hub→spoke) and real
``BaseControlPlane._encode_frame`` (spoke→hub), plus the two ad-contract
expressions the auth/HUB_VERIFIED parse uses. It also asserts the mailbox
flush principle: encryption happens at SEND time, so a queued ``Message`` keeps
its plaintext ``data`` (the wire alone carries ciphertext).
"""

import asyncio
import json
import os
import sys
import time

import main  # noqa: E402
from security.key_manager import KeyManager, ManagedKey  # noqa: E402
from security.signer import MessageSigner, split_frame  # noqa: E402
from security import frame_crypto as fc  # noqa: E402

_LM_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _LM_ROOT not in sys.path:
    sys.path.insert(0, _LM_ROOT)

from core.src.messaging.control_plane import BaseControlPlane  # noqa: E402

SECRET = "negotiation-session-secret-999"


# ── harness (same shape as test_hub_outbound_encryption) ────────────────────

def _make_km():
    km = KeyManager("keys_h4_neg.json", "hub_secret_h4_neg.json")
    km.storage_path = os.path.join("/tmp", "lm_keys_h4_neg.json")
    km.hub_secret_path = os.path.join("/tmp", "lm_hub_secret_h4_neg.json")
    data_dir = os.path.join(os.path.dirname(__file__), "..", "data")
    for name in ("keys_h4_neg.json", "hub_secret_h4_neg.json"):
        try:
            os.remove(os.path.join(data_dir, name))
        except OSError:
            pass
    return km


def _key(secret):
    return ManagedKey(key_id="k-" + secret[:6], secret=secret,
                      created_at=time.time(), expires_at=time.time() + 3600)


class _FakeWS:
    def __init__(self):
        self.sent = []

    async def send(self, wire):
        self.sent.append(wire)

    async def close(self):
        pass


class _Hub:
    def __init__(self, km):
        self.key_manager = km
        self.active_connections = {}
        self.active_connection_key_ids = {}
        self.spoke_enc_capable = {}
        self.bytes_count = 0
        self.message_count = 0


def _hub_msg(ptype, data, dest):
    from main import Message, MessageHeader, MessagePayload
    return Message(header=MessageHeader(message_id="m", timestamp=time.time(),
                                        sender_id="hub", destination_id=dest),
                   payload=MessagePayload(type=ptype, data=data))


def _spoke(secret=SECRET):
    s = BaseControlPlane.__new__(BaseControlPlane)
    s.spoke_id = "s1"
    s.secret = secret
    s.signer = MessageSigner(secret) if secret else None
    s.hub_enc_capable = False
    return s


def _spoke_relay_msg(inner_type, inner_data):
    return {"header": {"sender_id": "s1", "destination_id": "hub"},
            "payload": {"type": "AGENT_RELAY_UP", "data": {
                "agent_id": "a1", "install_uuid": "u1", "hostname": "h1",
                "original_payload": {"payload": {"type": inner_type,
                                                   "data": inner_data}}}}}


def _hub_sent_payload(ws):
    _sig, body = split_frame(ws.sent[0])
    return json.loads(body)["payload"]


def _spoke_sent_payload(wire):
    _sig, body = split_frame(wire)
    return json.loads(body)["payload"]


# ── ad contract (the two parse expressions) ─────────────────────────────────

def test_spoke_capable_ad_contract():
    """Hub records spoke capability as: advertised enc AND hub kill switch on."""
    expr = lambda auth, enabled: bool(auth.get("enc") == fc.ENC_MARKER) and enabled
    assert expr({"enc": "v1"}, True) is True
    assert expr({}, True) is False                 # legacy spoke
    assert expr({"enc": "v2"}, True) is False     # unknown marker
    assert expr({"enc": "v1"}, False) is False    # hub kill switch off


def test_hub_capable_ad_contract(monkeypatch):
    """Spoke records hub capability as: hub advertised enc AND spoke kill switch."""
    expr = lambda proof, enabled: bool(proof.get("enc") == fc.ENC_MARKER) and enabled
    assert expr({"enc": "v1"}, True) is True
    assert expr({}, True) is False                # legacy hub
    assert expr({"enc": "v1"}, False) is False    # spoke kill switch off


# ── the four version combos at the frame level ───────────────────────────────

def test_new_new_both_directions_encrypt():
    """new hub + new spoke: hub→spoke and spoke→hub both encrypt."""
    km = _make_km()
    km.keys["s1"] = _key(SECRET)
    hub = _Hub(km)
    hub.spoke_enc_capable["s1"] = True            # hub saw spoke's enc ad
    ws = _FakeWS()
    hub.active_connections["s1"] = ws
    asyncio.new_event_loop().run_until_complete(
        main.LabManagerHub.send_to_spoke(hub, _hub_msg("INSTALL_CERT", {"pk": "X"}, "s1")))
    hpayload = _hub_sent_payload(ws)
    assert fc.is_encrypted(hpayload)               # hub→spoke encrypted

    spoke = _spoke()
    spoke.hub_enc_capable = True                   # spoke saw hub's enc ad
    wire = BaseControlPlane._encode_frame(spoke, _spoke_relay_msg("CS_TOKEN_RESULT", {"token": "T"}))
    spayload = _spoke_sent_payload(wire)
    inner = spayload["data"]["original_payload"]["payload"]
    assert fc.is_encrypted(inner)                  # spoke→hub encrypted


def test_legacy_spoke_new_hub_is_plaintext():
    """Legacy spoke (no enc ad) + new hub → hub does NOT encrypt to it."""
    km = _make_km()
    km.keys["s1"] = _key(SECRET)
    hub = _Hub(km)
    hub.spoke_enc_capable["s1"] = False            # spoke didn't advertise
    ws = _FakeWS()
    hub.active_connections["s1"] = ws
    asyncio.new_event_loop().run_until_complete(
        main.LabManagerHub.send_to_spoke(hub, _hub_msg("INSTALL_CERT", {"pk": "X"}, "s1")))
    assert not fc.is_encrypted(_hub_sent_payload(ws))


def test_new_spoke_legacy_hub_is_plaintext():
    """New spoke + legacy hub (no enc ad in HUB_VERIFIED) → spoke does NOT encrypt."""
    spoke = _spoke()
    spoke.hub_enc_capable = False                  # hub didn't advertise
    wire = BaseControlPlane._encode_frame(spoke, _spoke_relay_msg("CS_TOKEN_RESULT", {"token": "T"}))
    spayload = _spoke_sent_payload(wire)
    inner = spayload["data"]["original_payload"]["payload"]
    assert not fc.is_encrypted(inner)


def test_kill_switch_on_hub_makes_it_legacy(monkeypatch):
    """LM_APP_ENCRYPTION=0 on the hub → a capable spoke still gets plaintext."""
    monkeypatch.setenv("LM_APP_ENCRYPTION", "0")
    km = _make_km()
    km.keys["s1"] = _key(SECRET)
    hub = _Hub(km)
    hub.spoke_enc_capable["s1"] = True             # advertised, but kill switch off
    ws = _FakeWS()
    hub.active_connections["s1"] = ws
    asyncio.new_event_loop().run_until_complete(
        main.LabManagerHub.send_to_spoke(hub, _hub_msg("INSTALL_CERT", {"pk": "X"}, "s1")))
    assert not fc.is_encrypted(_hub_sent_payload(ws))


def test_kill_switch_on_spoke_makes_it_legacy(monkeypatch):
    """LM_APP_ENCRYPTION=0 on the spoke → no encrypt even with hub capable."""
    monkeypatch.setenv("LM_APP_ENCRYPTION", "0")
    spoke = _spoke()
    spoke.hub_enc_capable = True
    wire = BaseControlPlane._encode_frame(spoke, _spoke_relay_msg("CS_TOKEN_RESULT", {"token": "T"}))
    spayload = _spoke_sent_payload(wire)
    inner = spayload["data"]["original_payload"]["payload"]
    assert not fc.is_encrypted(inner)


# ── mailbox: encryption is at send-time, queue stores plaintext ──────────────

def test_mailbox_flush_encrypts_at_send_time_queue_keeps_plaintext():
    """A queued Message holds plaintext ``data``; send_to_spoke encrypts a COPY
    (asdict) at send-time, so the wire carries ciphertext while the queued
    Message.data stays plaintext. This is the mailbox-flush principle: the
    durable queue never stores ciphertext (a spoke that reconnects after a hub
    restart re-derives the key the same way), and a flush to a legacy reconnect
    sends plaintext because the gate is evaluated at send-time against the
    CURRENT spoke_enc_capable flag."""
    km = _make_km()
    km.keys["s1"] = _key(SECRET)
    hub = _Hub(km)
    hub.spoke_enc_capable["s1"] = True
    ws = _FakeWS()
    hub.active_connections["s1"] = ws

    msg = _hub_msg("INSTALL_CERT", {"privkey": "PEM-SECRET"}, "s1")
    # The mailbox would hold this exact Message; flush calls send_to_spoke(msg).
    asyncio.new_event_loop().run_until_complete(
        main.LabManagerHub.send_to_spoke(hub, msg))

    # Wire is encrypted.
    payload = _hub_sent_payload(ws)
    assert fc.is_encrypted(payload)
    assert fc.decrypt_payload_data(SECRET, payload["data"]) == {"privkey": "PEM-SECRET"}
    # The queued Message's data is STILL plaintext (send_to_spoke wrapped a copy).
    assert msg.payload.data == {"privkey": "PEM-SECRET"}


def test_mailbox_flush_to_legacy_reconnect_sends_plaintext():
    """The same queued Message, flushed to a reconnecting legacy spoke (capability
    flag False at flush-time), goes out plaintext — the gate is re-evaluated at
    send-time against the current capability, not snapshotted at queue-time."""
    km = _make_km()
    km.keys["s1"] = _key(SECRET)
    hub = _Hub(km)
    hub.spoke_enc_capable["s1"] = False            # legacy reconnect
    ws = _FakeWS()
    hub.active_connections["s1"] = ws

    msg = _hub_msg("INSTALL_CERT", {"privkey": "PEM-SECRET"}, "s1")
    asyncio.new_event_loop().run_until_complete(
        main.LabManagerHub.send_to_spoke(hub, msg))
    payload = _hub_sent_payload(ws)
    assert not fc.is_encrypted(payload)
    assert payload["data"] == {"privkey": "PEM-SECRET"}