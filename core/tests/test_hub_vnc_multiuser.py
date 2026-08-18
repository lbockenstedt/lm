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
        {"session_id": "b1", "username": "dave", "tenant_id": "10",
         "since": hub.vnc_sessions["b1"]["connected_at"]}
    ]


def test_vnc_viewers_empty_when_nobody_connected():
    hub = _Hub()
    hub.register_vnc_session("a1", {"unique_id": "c/n/1", "username": "alice"})
    assert hub.vnc_viewers("c/n/1") == []
