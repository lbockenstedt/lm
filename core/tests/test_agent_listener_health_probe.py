"""The ``/ws/agent`` listener must answer NON-WebSocket requests (health checks,
TCP/port scanners, a browser hitting the wss port) with a plain ``200 OK``
instead of letting websockets raise ``InvalidUpgrade`` ("missing Connection
header") and log a full-traceback ``opening handshake failed`` ERROR on every
probe.

Drives ``AgentHostingControlPlane._agent_health_process_request`` directly:

* a real ``Upgrade: websocket`` handshake  → returns ``None`` (library accepts)
* a plain GET (no upgrade headers)          → returns a Response (short-circuit)
* an ``Upgrade: h2c`` non-ws upgrade         → returns a Response
* a missing-``Connection`` but ``Upgrade: websocket`` request is LEFT to fail
  (returns ``None``) — a real proxy bug worth surfacing, not a benign probe.
"""
import os
import sys
from http import HTTPStatus

from websockets.datastructures import Headers

_LM_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _LM_ROOT not in sys.path:
    sys.path.insert(0, _LM_ROOT)

from core.src.messaging.agent_hosting import AgentHostingControlPlane  # noqa: E402


class _Req:
    def __init__(self, headers):
        self.headers = Headers(headers)


class _Conn:
    """Stand-in for the websockets ServerConnection — only ``respond`` is used."""
    def __init__(self):
        self.responded = None

    def respond(self, status, text):
        self.responded = (status, text)
        return ("RESPONSE", status, text)


def _cp():
    # The hook uses no instance state, so skip the heavy __init__.
    return object.__new__(AgentHostingControlPlane)


def _run(headers):
    cp, conn = _cp(), _Conn()
    out = cp._agent_health_process_request(conn, _Req(headers))
    return out, conn


def test_real_websocket_handshake_passes_through():
    out, conn = _run([("Upgrade", "websocket"), ("Connection", "Upgrade"),
                      ("Sec-WebSocket-Key", "x"), ("Sec-WebSocket-Version", "13")])
    assert out is None                 # None → library runs the real accept()
    assert conn.responded is None


def test_plain_get_probe_gets_200():
    out, conn = _run([("Host", "spoke:443"), ("User-Agent", "curl/8")])
    assert out is not None             # short-circuited, no InvalidUpgrade
    assert conn.responded[0] == HTTPStatus.OK


def test_non_websocket_upgrade_gets_200():
    out, conn = _run([("Upgrade", "h2c"), ("Connection", "Upgrade")])
    assert out is not None
    assert conn.responded[0] == HTTPStatus.OK


def test_case_insensitive_upgrade_value():
    out, _ = _run([("Upgrade", "WebSocket"), ("Connection", "Upgrade")])
    assert out is None                 # value compare is case-insensitive


def test_missing_connection_header_still_fails_loudly():
    # Upgrade: websocket present but no Connection header — a real proxy bug.
    # We must NOT mask it with a 200; return None so the library reports it.
    out, conn = _run([("Upgrade", "websocket"),
                      ("Sec-WebSocket-Key", "x"), ("Sec-WebSocket-Version", "13")])
    assert out is None
    assert conn.responded is None
