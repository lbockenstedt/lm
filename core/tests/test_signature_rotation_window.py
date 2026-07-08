"""Signature rotation window + duplicate-connection eviction.

Two related fixes for the recurring ``Invalid signature from spoke cs-spoke-1``
where command responses verified but a separate stream of unsolicited frames
failed:

1. ``KeyManager.verify_signature`` now accepts the rotation *history* window,
   mirroring ``get_valid_key``'s auth-time acceptance — otherwise a frame
   signed with the just-rotated-out key (in flight when ``rotate_key`` pushed
   the new secret) wrongly fails, an auth/verify asymmetry.

2. ``LabManagerHub._install_active_connection`` evicts a pre-existing
   connection on reconnect (closes a zombie left from a prior outage) and
   rejects a stale (history-key) reconnect that would displace a live
   current-key connection (prevents zombie takeover + reconnect ping-pong).
"""

import asyncio
import os
import time

import main  # noqa: E402  (core/src on sys.path via conftest)
from security.key_manager import KeyManager, ManagedKey  # noqa: E402
from security.signer import MessageSigner  # noqa: E402


# ── helpers ──────────────────────────────────────────────────────────────────

def _make_km():
    """Build a KeyManager whose persistence lives in tmp, not core/data.

    The constructor resolves its data dir from ``__file__`` and writes a hub
    secret file there on first init; redirect the paths afterward and remove
    the throwaway files so no test artifacts pollute core/data.
    """
    km = KeyManager("keys_unit_test.json", "hub_secret_unit_test.json")
    km.storage_path = os.path.join("/tmp", "lm_keys_unit_test.json")
    km.hub_secret_path = os.path.join("/tmp", "lm_hub_secret_unit_test.json")
    data_dir = os.path.join(os.path.dirname(__file__), "..", "data")
    for name in ("keys_unit_test.json", "hub_secret_unit_test.json"):
        try:
            os.remove(os.path.join(data_dir, name))
        except OSError:
            pass
    return km


def _key(kid: str, secret: str) -> ManagedKey:
    return ManagedKey(key_id=kid, secret=secret, created_at=time.time(),
                      expires_at=time.time() + 3600)


class _FakeWS:
    """Minimal stand-in for a websocket: identity + an async close() + ping().

    ``alive`` controls the liveness probe ``_install_active_connection`` pings
    the existing connection with before deciding whether to evict: an alive
    socket pongs (ping() returns a resolved pong_waiter), a dead/zombie socket
    doesn't (ping() raises). Defaults to dead (the zombie-reconnect case).
    ``ping_count`` lets a test assert whether the probe ran at all."""

    def __init__(self, alive=False):
        self.closed = False
        self.close_code = None
        self.close_reason = None
        self._alive = alive
        self.ping_count = 0

    async def close(self, code, reason):
        self.closed = True
        self.close_code = code
        self.close_reason = reason

    async def ping(self):
        self.ping_count += 1
        if not self._alive:
            raise ConnectionError("dead socket — no pong")
        # alive: return a pong_waiter future that resolves immediately. The real
        # websockets API returns a future the caller must await to confirm the
        # pong actually came back (awaiting only ping() returns the instant the
        # frame is BUFFERED — false-alive on a half-open socket).
        fut = asyncio.get_running_loop().create_future()
        fut.set_result(None)
        return fut


class _ConnHub:
    """Just the attributes ``_install_active_connection`` touches."""

    def __init__(self, km):
        self.key_manager = km
        self.active_connections = {}
        self.active_connection_key_ids = {}
        self.events = []
        # last_seen freshness is the primary half-open signal: a live spoke
        # updates it every authenticated frame; a half-open (dead-peer) socket
        # stops receiving frames so it goes stale.
        self.heartbeat = type("HB", (), {"last_seen": {}})()

    def record_spoke_event(self, spoke_id, event_type, detail=""):
        self.events.append((spoke_id, event_type, detail))


def _install(hub, spoke_id, ws, key_id):
    return main.LabManagerHub._install_active_connection(hub, spoke_id, ws, key_id)


# ── KeyManager.verify_signature: rotation history window ─────────────────────

async def test_verify_signature_accepts_current_key():
    import json
    km = _make_km()
    km.keys["s1"] = _key("cur", "current-secret")
    # The hub serializes with sort_keys + compact separators; mirror that.
    msg = {"hello": "world"}
    msg_bytes = json.dumps(msg, sort_keys=True, separators=(",", ":")).encode()
    sig = MessageSigner("current-secret").sign(msg)
    assert km.verify_signature("s1", msg_bytes, sig) is True


async def test_verify_signature_accepts_history_key_after_rotation():
    """A frame signed with the just-rotated-out key must still verify."""
    import json
    km = _make_km()
    km.keys["s1"] = _key("cur", "current-secret")
    km.history["s1"] = [_key("old", "previous-secret")]
    # Spoke signs with the OLD key (frame in flight right after rotation).
    msg = {"cmd": "POLL", "ts": 1}
    msg_bytes = json.dumps(msg, sort_keys=True, separators=(",", ":")).encode()
    sig = MessageSigner("previous-secret").sign(msg)
    assert km.verify_signature("s1", msg_bytes, sig) is True


async def test_verify_signature_rejects_unknown_key():
    import json
    km = _make_km()
    km.keys["s1"] = _key("cur", "current-secret")
    km.history["s1"] = [_key("old", "previous-secret")]
    msg_bytes = json.dumps({"x": 1}, sort_keys=True, separators=(",", ":")).encode()
    sig = MessageSigner("totally-different-secret").sign({"x": 1})
    assert km.verify_signature("s1", msg_bytes, sig) is False


async def test_verify_signature_no_key_returns_false():
    import json
    km = _make_km()
    msg_bytes = json.dumps({"x": 1}, sort_keys=True, separators=(",", ":")).encode()
    assert km.verify_signature("unknown-spoke", msg_bytes, "deadbeef") is False


# ── _install_active_connection: eviction + stale-key rejection ───────────────

async def test_install_evicts_zombie_on_current_key_reconnect():
    """Live process (current key) reconnecting over a zombie (history key)
    closes the zombie and takes over."""
    km = _make_km()
    km.keys["s1"] = _key("cur", "current-secret")
    km.history["s1"] = [_key("old", "previous-secret")]
    hub = _ConnHub(km)

    zombie = _FakeWS()
    hub.active_connections["s1"] = zombie
    hub.active_connection_key_ids["s1"] = "old"  # zombie auth'd with history key

    live = _FakeWS()
    ok = await _install(hub, "s1", live, "cur")
    assert ok is True
    assert zombie.closed is True            # zombie evicted
    assert zombie.close_code == 1008
    assert hub.active_connections["s1"] is live
    assert hub.active_connection_key_ids["s1"] == "cur"


async def test_install_rejects_stale_key_reconnect_over_live_current():
    """A zombie (history key) reconnecting while a live current-key connection
    is active is REJECTED — it must not displace the live process."""
    km = _make_km()
    km.keys["s1"] = _key("cur", "current-secret")
    km.history["s1"] = [_key("old", "previous-secret")]
    hub = _ConnHub(km)

    live = _FakeWS()
    hub.active_connections["s1"] = live
    hub.active_connection_key_ids["s1"] = "cur"  # live auth'd with current key

    zombie = _FakeWS()
    ok = await _install(hub, "s1", zombie, "old")  # stale history key
    assert ok is False
    assert zombie.closed is True                  # rejected, not registered
    assert hub.active_connections["s1"] is live   # live connection untouched
    assert hub.active_connection_key_ids["s1"] == "cur"


async def test_install_registers_when_no_existing():
    km = _make_km()
    km.keys["s1"] = _key("cur", "current-secret")
    hub = _ConnHub(km)
    ws = _FakeWS()
    ok = await _install(hub, "s1", ws, "cur")
    assert ok is True
    assert hub.active_connections["s1"] is ws
    assert hub.active_connection_key_ids["s1"] == "cur"


async def test_install_same_websocket_no_close():
    """Re-registering the same websocket (e.g. second auth step) must not
    close itself."""
    km = _make_km()
    km.keys["s1"] = _key("cur", "current-secret")
    hub = _ConnHub(km)
    ws = _FakeWS()
    hub.active_connections["s1"] = ws
    hub.active_connection_key_ids["s1"] = "cur"
    ok = await _install(hub, "s1", ws, "cur")
    assert ok is True
    assert ws.closed is False
    assert hub.active_connection_key_ids["s1"] == "cur"


async def test_install_rejects_duplicate_when_existing_alive():
    """A second process (same current key) connecting while the existing
    connection is LIVE (responds to ping) is REJECTED — this is the duplicate-
    spoke-process case that caused the cs-svr-02 mutual-eviction flap. The
    live connection is kept untouched; the duplicate is closed with 1008."""
    km = _make_km()
    km.keys["s1"] = _key("cur", "current-secret")
    hub = _ConnHub(km)

    live = _FakeWS(alive=True)  # pongs → existing is alive
    hub.active_connections["s1"] = live
    hub.active_connection_key_ids["s1"] = "cur"

    dup = _FakeWS()
    ok = await _install(hub, "s1", dup, "cur")  # same current key
    assert ok is False
    assert dup.closed is True                    # duplicate rejected
    assert dup.close_code == 1008
    assert live.closed is False                   # existing untouched
    assert hub.active_connections["s1"] is live
    assert hub.active_connection_key_ids["s1"] == "cur"
    # A duplicate_rejected event is recorded so the operator can see the flap.
    assert any(ev[1] == "duplicate_rejected" for ev in hub.events)


async def test_install_evicts_zombie_when_existing_unresponsive():
    """A reconnect over an existing connection that does NOT respond to ping
    (zombie — socket still in the table but the peer is gone, e.g. after a
    crash) evicts the zombie and installs the new connection BEFORE closing
    the old (closes the TOCTOU window where a stale socket could briefly be
    the registered one)."""
    km = _make_km()
    km.keys["s1"] = _key("cur", "current-secret")
    hub = _ConnHub(km)

    zombie = _FakeWS(alive=False)  # no pong → dead
    hub.active_connections["s1"] = zombie
    hub.active_connection_key_ids["s1"] = "cur"

    fresh = _FakeWS()
    ok = await _install(hub, "s1", fresh, "cur")
    assert ok is True
    assert hub.active_connections["s1"] is fresh  # installed BEFORE close
    assert hub.active_connection_key_ids["s1"] == "cur"
    assert zombie.closed is True                  # zombie closed after install
    assert zombie.close_code == 1008


async def test_install_keeps_existing_when_last_seen_fresh_no_probe():
    """A reconnect while the existing connection has a FRESH last_seen (it's
    actively sending frames — a live duplicate) is REJECTED without even
    probing ping. This is the half-open vs. live-duplicate discriminator: a
    fresh last_seen can only happen if a frame arrived recently, which requires
    a live peer, so the existing connection is alive and the new one is a
    duplicate that must not evict it (the mutual-eviction flap the earlier
    pong-only probe caused under hub freezes). No ping is sent — last_seen
    short-circuits the probe."""
    km = _make_km()
    km.keys["s1"] = _key("cur", "current-secret")
    hub = _ConnHub(km)

    live = _FakeWS(alive=False)  # would NOT pong — but the probe must not run
    hub.active_connections["s1"] = live
    hub.active_connection_key_ids["s1"] = "cur"
    hub.heartbeat.last_seen["s1"] = time.time()  # fresh → alive by frame recency

    dup = _FakeWS()
    ok = await _install(hub, "s1", dup, "cur")
    assert ok is False
    assert dup.closed is True
    assert dup.close_code == 1008
    assert live.closed is False
    assert hub.active_connections["s1"] is live
    assert live.ping_count == 0  # last_seen fresh → no probe needed


async def test_install_evicts_halfopen_when_last_seen_stale_and_pong_dead():
    """The half-open case: last_seen is STALE (no frames for a while → the peer
    is gone) AND the pong probe fails (no pong within 2s) → the existing is a
    half-open zombie; evict it and let the real reconnect take over. This is
    the root-cause fix for the Request-Timeout flood: a keepalive drop leaves
    a TCP-ESTABLISHED but dead socket that the OLD false-alive probe (awaiting
    only ping(), which returns when buffered) wrongly kept, so the spoke's
    reconnect was rejected and the hub kept routing into the black hole."""
    km = _make_km()
    km.keys["s1"] = _key("cur", "current-secret")
    hub = _ConnHub(km)

    zombie = _FakeWS(alive=False)  # no pong
    hub.active_connections["s1"] = zombie
    hub.active_connection_key_ids["s1"] = "cur"
    hub.heartbeat.last_seen["s1"] = time.time() - 120  # stale → probe

    fresh = _FakeWS()
    ok = await _install(hub, "s1", fresh, "cur")
    assert ok is True
    assert hub.active_connections["s1"] is fresh
    assert zombie.closed is True
    assert zombie.ping_count == 1  # stale → probed


async def test_install_keeps_existing_when_last_seen_stale_but_pongs():
    """Stale last_seen alone does NOT evict: a live spoke that paused telemetry
    >30s (e.g. a brief event-loop stall) but is still up still pongs, so the
    pong-confirm keeps it and rejects the new connection. Eviction requires
    BOTH stale last_seen AND a failed pong — the half-open signature. This
    stops a momentary telemetry gap from false-evicting a live spoke."""
    km = _make_km()
    km.keys["s1"] = _key("cur", "current-secret")
    hub = _ConnHub(km)

    live = _FakeWS(alive=True)  # pongs
    hub.active_connections["s1"] = live
    hub.active_connection_key_ids["s1"] = "cur"
    hub.heartbeat.last_seen["s1"] = time.time() - 120  # stale → probe runs

    dup = _FakeWS()
    ok = await _install(hub, "s1", dup, "cur")
    assert ok is False
    assert dup.closed is True
    assert live.closed is False  # stale but pongs → kept
    assert hub.active_connections["s1"] is live
    assert live.ping_count == 1  # stale → probed, and it answered

# ── key-delivery signing (sign SPOKE_UPDATE_SESSION_KEY with the PRE-rotation
#    secret so the spoke can verify it before installing the new key) ──────────

def test_key_delivery_signed_with_prev_secret_verifies_on_spoke():
    """The SPOKE_UPDATE_SESSION_KEY push must be signed with the PRE-rotation
    secret the spoke still holds. A spoke holding the OLD secret verifies it
    (and so dispatches + installs the new secret); a spoke holding the NEW
    secret does NOT — proving the delivery cannot be signed with the new key
    (the original desync: the spoke dropped the push before dispatch)."""
    km = _make_km()
    old = km.generate_first_secret("s1")                # the secret the spoke holds
    prev = km.current_session_secret("s1")
    assert prev == old

    new_key = km.rotate_key("s1")                       # hub flips current -> new
    new = new_key.secret
    assert new != old
    assert km.current_session_secret("s1") == new

    body = {"header": {"sender_id": "hub", "destination_id": "s1"},
            "payload": {"type": "SPOKE_UPDATE_SESSION_KEY", "data": {"secret": new}}}

    # Hub signs the delivery with the PRE-rotation secret (the fix).
    sig = km.sign_with_secret(prev, body)
    frame = {**body, "signature": sig}

    # Spoke still holding the OLD secret verifies -> dispatches -> installs new.
    assert MessageSigner(old).verify(frame) is True
    # A spoke that already had the NEW secret would NOT verify a prev-signed
    # frame (and vice-versa) — the signature is bound to the secret used.
    assert MessageSigner(new).verify(frame) is False

    # After the spoke installs the new secret, a normal command signed with the
    # new (current) key verifies on the spoke's new signer.
    cmd = {"header": {"sender_id": "hub", "destination_id": "s1"},
           "payload": {"type": "GET_VERSION", "data": {}}}
    cmd_sig = km.sign_message("s1", cmd)                # signs with current = new
    assert MessageSigner(new).verify({**cmd, "signature": cmd_sig}) is True


def test_current_session_secret_none_for_pending_spoke():
    """A spoke with no key (pending / zero-touch) has no current secret, so the
    delivery is signed with None -> send_to_spoke falls back to the current
    (new) key, which the pending spoke accepts unauthenticated."""
    km = _make_km()
    assert km.current_session_secret("never-seen") is None
