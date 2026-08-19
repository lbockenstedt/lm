"""Multiuser VNC console: connected-session TTL exemption + presence roster.

Multiuser works because each viewer opens their OWN VNC session (distinct
session_id → its own Proxmox vncwebsocket); QEMU's VNC server multiplexes the
clients so everyone shares one screen. Two behaviors make that robust:

* A ``connected`` VNC session must NOT be reaped by the 60s TTL — a viewer sits
  on a console for minutes and every upstream frame re-reads the session by id,
  so reaping mid-view silently freezes the screen. (The TTL only guards an
  unclaimed session the browser never connected to.)
* ``vnc_viewers(unique_id)`` returns the connected roster for a VM so the UI can
  show a live viewer count.
"""

import time

from hub_vnc_console import HubVncConsoleMixin


class _Hub(HubVncConsoleMixin):
    def __init__(self):
        self.vnc_sessions = {}


def test_unconnected_vnc_session_reaped_on_ttl():
    hub = _Hub()
    hub.register_vnc_session("s1", {"ws_token": "t", "unique_id": "c/n/1"})
    hub.vnc_sessions["s1"]["expires"] = time.time() - 1  # past TTL, never connected
    assert hub.get_vnc_session("s1") is None
    assert "s1" not in hub.vnc_sessions


def test_connected_vnc_session_survives_ttl():
    hub = _Hub()
    hub.register_vnc_session("s1", {"ws_token": "t", "unique_id": "c/n/1"})
    hub.vnc_sessions["s1"]["connected"] = True
    hub.vnc_sessions["s1"]["expires"] = time.time() - 1  # long past TTL
    # A connected session is exempt: still live so upstream frames keep flowing.
    assert hub.get_vnc_session("s1") is not None


def test_vnc_viewers_lists_only_connected_matching_vm():
    hub = _Hub()
    # Two viewers on VM A (both connected), one still-connecting on A, one on B.
    hub.register_vnc_session("a1", {"unique_id": "c/n/1", "username": "alice",
                                    "tenant_id": "10"})
    hub.register_vnc_session("a2", {"unique_id": "c/n/1", "username": "bob",
                                    "tenant_id": "10"})
    hub.register_vnc_session("a3", {"unique_id": "c/n/1", "username": "carol",
                                    "tenant_id": "10"})
    hub.register_vnc_session("b1", {"unique_id": "c/n/9", "username": "dave",
                                    "tenant_id": "10"})
    for sid in ("a1", "a2", "b1"):
        hub.vnc_sessions[sid]["connected"] = True
        hub.vnc_sessions[sid]["connected_at"] = time.time()
    # a3 never connected → excluded; b1 is a different VM → excluded.
    viewers = hub.vnc_viewers("c/n/1")
    names = sorted(v["username"] for v in viewers)
    assert names == ["alice", "bob"]
    assert hub.vnc_viewers("c/n/9") == [
        {"session_id": "b1", "username": "dave", "tenant_id": "10", "is_writer": False,
         "since": hub.vnc_sessions["b1"]["connected_at"]}
    ]


def test_vnc_viewers_empty_when_nobody_connected():
    hub = _Hub()
    hub.register_vnc_session("a1", {"unique_id": "c/n/1", "username": "alice"})
    assert hub.vnc_viewers("c/n/1") == []


# ── Write-lock: first viewer wins, force-takeover evicts them ────────────────

def test_vnc_attach_first_viewer_becomes_writer():
    hub = _Hub()
    assert hub.vnc_attach("c/n/1", "s1") is True
    assert hub.vnc_is_writer("c/n/1", "s1") is True


def test_vnc_attach_second_viewer_is_read_only():
    hub = _Hub()
    hub.vnc_attach("c/n/1", "s1")
    assert hub.vnc_attach("c/n/1", "s2") is False
    assert hub.vnc_is_writer("c/n/1", "s1") is True
    assert hub.vnc_is_writer("c/n/1", "s2") is False


def test_vnc_takeover_evicts_current_writer():
    hub = _Hub()
    hub.vnc_attach("c/n/1", "s1")
    hub.vnc_attach("c/n/1", "s2")
    prev = hub.vnc_takeover("c/n/1", "s2")
    assert prev == "s1"
    assert hub.vnc_is_writer("c/n/1", "s2") is True
    assert hub.vnc_is_writer("c/n/1", "s1") is False


def test_vnc_takeover_noop_when_caller_already_writer():
    hub = _Hub()
    hub.vnc_attach("c/n/1", "s1")
    assert hub.vnc_takeover("c/n/1", "s1") is None
    assert hub.vnc_is_writer("c/n/1", "s1") is True


def test_vnc_writer_released_on_unregister_and_reclaimable():
    hub = _Hub()
    hub.register_vnc_session("s1", {"unique_id": "c/n/1"})
    hub.vnc_attach("c/n/1", "s1")
    hub.unregister_vnc_session("s1")
    assert hub.vnc_is_writer("c/n/1", "s1") is False
    # Released, not promoted to anyone automatically — the next opener wins it.
    assert hub.vnc_attach("c/n/1", "s2") is True


def test_vnc_unregister_of_non_writer_does_not_release_lock():
    hub = _Hub()
    hub.register_vnc_session("s1", {"unique_id": "c/n/1"})
    hub.register_vnc_session("s2", {"unique_id": "c/n/1"})
    hub.vnc_attach("c/n/1", "s1")
    hub.vnc_attach("c/n/1", "s2")  # read-only observer
    hub.unregister_vnc_session("s2")
    assert hub.vnc_is_writer("c/n/1", "s1") is True


def test_vnc_viewers_reports_is_writer_flag():
    hub = _Hub()
    hub.register_vnc_session("s1", {"unique_id": "c/n/1", "username": "alice"})
    hub.register_vnc_session("s2", {"unique_id": "c/n/1", "username": "bob"})
    for sid in ("s1", "s2"):
        hub.vnc_sessions[sid]["connected"] = True
        hub.vnc_sessions[sid]["connected_at"] = time.time()
    hub.vnc_attach("c/n/1", "s1")
    hub.vnc_attach("c/n/1", "s2")
    by_id = {v["session_id"]: v["is_writer"] for v in hub.vnc_viewers("c/n/1")}
    assert by_id == {"s1": True, "s2": False}


async def test_notify_vnc_downgraded_pushes_control_tuple():
    hub = _Hub()
    hub.register_vnc_session("s1", {"unique_id": "c/n/1"})
    await hub.notify_vnc_downgraded("s1")
    item = hub.vnc_sessions["s1"]["queue"].get_nowait()
    assert item == ("downgraded",)


async def test_notify_vnc_downgraded_noop_for_closed_session():
    hub = _Hub()
    # Must not raise even though the session was never registered.
    await hub.notify_vnc_downgraded("never-existed")
