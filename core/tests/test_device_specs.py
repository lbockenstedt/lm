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
        self.roles = getattr(self, "roles", []) + [payload.get("role")]
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


def test_prose_reply_is_retried_once_then_not_recorded(tmp_path):
    device_specs._CACHE.clear()
    hub = _Hub(tmp_path, ["Sorry, I am not sure.", json.dumps(_ANSWER)])
    assert _get(hub)["model"] == "8325-48Y8C"    # the retry answered in JSON
    assert len(hub.asks) == 2
    device_specs._CACHE.clear()
    hub = _Hub(tmp_path / "x", ["prose", "more prose", json.dumps(_ANSWER)])
    (tmp_path / "x").mkdir()
    assert _get(hub) is None                     # still prose: not recorded
    assert _get(hub)["model"] == "8325-48Y8C"    # asked again on the next poll
    assert hub.roles == ["final"] * 3            # catalog answers use the strongest model


def test_legacy_null_record_without_an_explicit_unknown_is_asked_again(tmp_path):
    device_specs._CACHE.clear()
    (tmp_path / "device_specs.json").write_text(json.dumps(
        {"models": {"cx_switch|jl635a": {"spec": None, "asked": 9e12}}}))
    hub = _Hub(tmp_path, [json.dumps(_ANSWER)])
    assert _get(hub)["model"] == "8325-48Y8C"
