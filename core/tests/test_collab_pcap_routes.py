"""routes/collab.py — collab replay-capture (pcap) upload / serve / delete plus
responder config. A capture holds BOTH directions of a Teams/Zoom/WebEx call;
the sim client replays the client->server frames and the hub sink replays the
server->client frames back. Admin gates the /setup endpoints; the client pulls
the blob from the unauthenticated /sim/collab/pcap path.
"""
import os
import sys
import tempfile
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

from routes.collab import register

# The parser used to synthesize a valid capture fixture lives beside the sink.
_SINK_DIR = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "..", "collab_sink"))
if _SINK_DIR not in sys.path:
    sys.path.insert(0, _SINK_DIR)
import collab_pcap  # noqa: E402


class _FakeState:
    def __init__(self, data_dir):
        self.data_dir = data_dir
        self.system_state = {"global_config": {}}
        self.dirty = 0

    def _mark_dirty(self):
        self.dirty += 1


class FakeHub:
    def __init__(self, data_dir):
        self.state = _FakeState(data_dir)


def _build(sess, data_dir):
    app = FastAPI()
    hub = FakeHub(data_dir)
    ctx = SimpleNamespace(
        _session_user=lambda request: sess,
        _is_admin=lambda s: bool(s and s.get("user", {}).get("is_admin")),
    )
    register(app, hub, ctx)
    return TestClient(app), hub


def _admin():
    return {"user": {"is_admin": True}}


def _valid_pcap_bytes(tmp):
    p = os.path.join(tmp, "fixture.pcap")
    collab_pcap.write_synthetic_pcap(p, app="teams", seconds=1.0, hz=50)
    with open(p, "rb") as f:
        return f.read()


def test_upload_serve_and_delete_roundtrip():
    with tempfile.TemporaryDirectory() as tmp:
        c, hub = _build(_admin(), tmp)
        data = _valid_pcap_bytes(tmp)

        r = c.post("/setup/collab/pcap?name=call.pcap", content=data)
        assert r.status_code == 200, r.text
        meta = r.json()["pcap"]
        assert meta["filename"] == "call.pcap"
        assert meta["size"] == len(data)
        assert meta["stats"]["c2s_packets"] > 0
        assert meta["stats"]["s2c_packets"] > 0
        # file persisted under <data_dir>/collab/replay.pcap
        assert os.path.isfile(os.path.join(tmp, "collab", "replay.pcap"))

        # GET /setup/collab exposes the metadata
        cfg = c.get("/setup/collab").json()["config"]
        assert cfg["pcap"]["filename"] == "call.pcap"

        # client-facing serve returns the raw bytes
        r = c.get("/sim/collab/pcap")
        assert r.status_code == 200
        assert r.content == data

        # admin download returns the raw bytes too
        r = c.get("/setup/collab/pcap")
        assert r.status_code == 200
        assert r.content == data

        # delete clears file + metadata
        r = c.delete("/setup/collab/pcap")
        assert r.status_code == 200
        assert not os.path.isfile(os.path.join(tmp, "collab", "replay.pcap"))
        assert c.get("/setup/collab").json()["config"]["pcap"] is None
        assert c.get("/sim/collab/pcap").status_code == 404


def test_upload_rejects_non_pcap():
    with tempfile.TemporaryDirectory() as tmp:
        c, _ = _build(_admin(), tmp)
        r = c.post("/setup/collab/pcap?name=x.pcap", content=b"not a capture")
        assert r.status_code == 400
        # a bad upload must not replace/create the stored capture
        assert not os.path.isfile(os.path.join(tmp, "collab", "replay.pcap"))


def test_upload_requires_admin():
    with tempfile.TemporaryDirectory() as tmp:
        c, _ = _build({"user": {"is_admin": False}}, tmp)
        r = c.post("/setup/collab/pcap?name=x.pcap", content=b"data")
        assert r.status_code == 403


def test_config_post_preserves_pcap_and_responder_flag():
    with tempfile.TemporaryDirectory() as tmp:
        c, _ = _build(_admin(), tmp)
        c.post("/setup/collab/pcap?name=call.pcap", content=_valid_pcap_bytes(tmp))
        # a plain config save must not wipe the uploaded capture metadata
        r = c.post("/setup/collab", json={"config": {"enabled": True,
                                                     "responder_enabled": False}})
        assert r.status_code == 200
        cfg = r.json()["config"]
        assert cfg["enabled"] is True
        assert cfg["responder_enabled"] is False
        assert cfg["pcap"] is not None
