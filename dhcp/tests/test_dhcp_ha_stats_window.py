"""HA DHCP Overview time window: the spoke asks every node for the window and
reports how much of it the pair covers."""
import asyncio

from dhcp_spoke import DHCPSpoke


def _node(received, window):
    reply = {"status": "SUCCESS", "global": {"pkt4_received": received}, "subnets": []}
    if window is not None:
        reply["window"] = window
    return reply


class _Transport:
    def __init__(self, results):
        self.results = results
        self.sent = []

    async def fanout(self, command, data, timeout=20.0, member_ids=None):
        self.sent.append((command, data))
        return {"results": self.results}


def _stats(results, range_seconds):
    spoke = object.__new__(DHCPSpoke)
    spoke._transport = _Transport(results)
    return spoke._transport, asyncio.run(spoke._ha_stats(range_seconds))


def test_window_is_asked_of_every_node_and_combined():
    transport, out = _stats({
        "a": _node(10, {"seconds": 3600, "covered_seconds": 3600, "partial": False}),
        "b": _node(5, {"seconds": 3600, "covered_seconds": 1200, "partial": True}),
    }, 3600)

    assert transport.sent == [("KEAW_STATS", {"range_seconds": 3600})]
    assert out["global"]["pkt4_received"] == 15
    assert out["window"]["partial"] is True
    assert out["window"]["covered_seconds"] == 1200


def test_node_on_older_code_marks_the_window_partial():
    _t, out = _stats({
        "a": _node(10, {"seconds": 3600, "covered_seconds": 3600, "partial": False}),
        "b": _node(900, None),
    }, 3600)

    assert out["window"]["partial"] is True
    assert out["window"]["unsupported_members"] == 1


def test_no_range_sends_no_window_and_reports_none():
    transport, out = _stats({"a": _node(10, None)}, None)

    assert transport.sent == [("KEAW_STATS", {})]
    assert "window" not in out
