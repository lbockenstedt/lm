"""collab_sink/collab_pcap.py + sink.py — capture parsing and the responder's
server->client payload loader. The client replays c2s; the hub sink replays
s2c. These tests pin the direction split and the loader without opening sockets.
"""
import importlib
import os
import sys
import tempfile

_SINK_DIR = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "..", "collab_sink"))
if _SINK_DIR not in sys.path:
    sys.path.insert(0, _SINK_DIR)
import collab_pcap  # noqa: E402


def _fixture(tmp, app="teams", seconds=1.0, hz=50):
    p = os.path.join(tmp, "f.pcap")
    collab_pcap.write_synthetic_pcap(p, app=app, seconds=seconds, hz=hz)
    return p


def test_parse_and_split_directions():
    with tempfile.TemporaryDirectory() as tmp:
        p = _fixture(tmp, hz=50, seconds=1.0)
        packets = collab_pcap.parse_udp_packets(p)
        assert packets, "expected UDP packets"
        client, server, c2s, s2c = collab_pcap.split_directions(packets)
        assert client and server and client != server
        assert c2s and s2c
        # both directions roughly balanced for a synthetic call
        assert abs(len(c2s) - len(s2c)) <= 2
        # s2c source ports are the app's real media ports (teams)
        s2c_ports = {port for _, port, _ in s2c}
        assert s2c_ports.issubset({3478, 3481, 3479})


def test_summarize_keys():
    with tempfile.TemporaryDirectory() as tmp:
        stats = collab_pcap.summarize(_fixture(tmp))
        for k in ("udp_packets", "c2s_packets", "s2c_packets",
                  "duration_s", "server_ports"):
            assert k in stats
        assert stats["c2s_packets"] > 0 and stats["s2c_packets"] > 0


def test_bad_file_raises():
    with tempfile.TemporaryDirectory() as tmp:
        bad = os.path.join(tmp, "bad.pcap")
        with open(bad, "wb") as f:
            f.write(b"this is not a capture")
        try:
            collab_pcap.parse_udp_packets(bad)
            raised = False
        except Exception:
            raised = True
        assert raised


def test_sink_loads_s2c_as_responses():
    os.environ["LM_COLLAB_RESPOND"] = "1"
    with tempfile.TemporaryDirectory() as tmp:
        p = _fixture(tmp)
        os.environ["LM_COLLAB_PCAP"] = p
        import sink
        importlib.reload(sink)
        payloads, deltas = sink._load_response_stream(p)
        assert payloads, "sink should load server->client payloads to replay"
        assert len(payloads) == len(deltas)
        assert all(len(pl) <= sink.MAX_RESP_BYTES for pl in payloads)


def test_sink_loader_handles_missing_pcap():
    import sink
    importlib.reload(sink)
    assert sink._load_response_stream("/nonexistent/replay.pcap") == ([], [])
