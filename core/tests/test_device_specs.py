"""device_specs: a model's spec is asked from the LLM once, recorded, then reused."""
import asyncio
import json
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
import device_specs  # noqa: E402

_ANSWER = {"identified": True, "manufacturer": "Aruba", "model": "8325-48Y8C",
           "role": "switch", "u_height": 1,
           "ports": [{"prefix": "1/1/", "start": 1, "count": 48, "type": "25gbase-x-sfp28"},
                     {"prefix": "1/1/", "start": 49, "count": "lots", "type": "x"}]}


class _Hub:
    def __init__(self, data_dir, replies):
        self.state = SimpleNamespace(data_dir=str(data_dir))
        self.active_connections = {"ab": object()}
        self.replies = list(replies)
        self.asks = []

    def _primary_key(self, sid):
        return sid

    async def request_response(self, target, cmd, payload, timeout=None):
        assert cmd == "HELP_ASK"
        self.asks.append(payload["messages"][0]["content"])
        return {"payload": {"data": {"status": "SUCCESS",
                                     "assistant": {"content": self.replies.pop(0)}}}}


def _get(hub, model="JL635A"):
    return asyncio.run(device_specs.get_spec(hub, model, "cx_switch", ["1/1/1", "vlan1"]))


def test_unknown_model_is_asked_once_then_recorded(tmp_path):
    device_specs._CACHE.clear()
    hub = _Hub(tmp_path, [json.dumps(_ANSWER)])
    spec = _get(hub)
    assert spec["model"] == "8325-48Y8C"
    assert spec["ports"] == [{"prefix": "1/1/", "start": 1, "count": 48,
                              "type": "25gbase-x-sfp28"}]   # bad port group dropped
    assert "JL635A" in hub.asks[0] and "1/1/1" in hub.asks[0]

    device_specs._CACHE.clear()                  # survives a hub restart
    assert _get(hub)["model"] == "8325-48Y8C"
    assert len(hub.asks) == 1
    saved = json.loads((tmp_path / "device_specs.json").read_text())
    assert saved["models"]["cx_switch|jl635a"]["spec"]["manufacturer"] == "Aruba"


def test_unidentified_model_is_not_re_asked_every_poll(tmp_path):
    device_specs._CACHE.clear()
    hub = _Hub(tmp_path, ['{"identified": false}'])
    assert _get(hub, "MYSTERY-1") is None
    assert _get(hub, "MYSTERY-1") is None
    assert len(hub.asks) == 1


def test_no_llm_connected_is_not_recorded(tmp_path):
    device_specs._CACHE.clear()
    hub = _Hub(tmp_path, [json.dumps(_ANSWER)])
    hub.active_connections = {}
    assert _get(hub) is None
    hub.active_connections = {"ab": object()}
    assert _get(hub)["model"] == "8325-48Y8C"
