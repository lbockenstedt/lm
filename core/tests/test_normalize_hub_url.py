"""BaseControlPlane._normalize_hub_url — pinned hub URL defaulting.

Covers the unified-443 migrations (ws://:443 -> wss://:443, pathless :443 pin
-> /ws/spoke) plus the newer bare-host/no-port defaulting ("assume wss:// and
443 unless otherwise stated" — parity with the pxmx agent's
_normalize_spoke_url). The legacy loopback :8765 listener has no path
routing, so a pin to it must NOT get /ws/spoke appended.
"""

import os
import sys

# control_plane.py uses relative imports (``from ..security.signer``) that only
# resolve when imported as ``core.src.messaging.control_plane`` — so put the lm
# repo root (parent of core/) on sys.path too (mirrors test_ws_tls.py).
_LM_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _LM_ROOT not in sys.path:
    sys.path.insert(0, _LM_ROOT)

from core.src.messaging import control_plane as cp  # noqa: E402

_norm = cp.BaseControlPlane._normalize_hub_url


def test_sentinels_pass_through():
    assert _norm(None) is None
    assert _norm("") == ""
    assert _norm("auto") == "auto"


def test_bare_host_defaults_scheme_port_and_path():
    assert _norm("172.16.1.31") == "wss://172.16.1.31:443/ws/spoke"


def test_bare_host_with_explicit_nondefault_port_gets_no_path():
    # A non-443 port is assumed to be the legacy raw-socket listener — no
    # path routing there, so /ws/spoke must NOT be appended.
    assert _norm("172.16.1.31:8765") == "wss://172.16.1.31:8765"


def test_wss_no_port_defaults_to_443_and_appends_path():
    assert _norm("wss://172.16.1.31") == "wss://172.16.1.31:443/ws/spoke"


def test_wss_pathless_443_appends_ws_spoke():
    assert _norm("wss://172.16.1.31:443") == "wss://172.16.1.31:443/ws/spoke"


def test_already_correct_url_is_unchanged():
    assert (_norm("wss://172.16.1.31:443/ws/spoke")
            == "wss://172.16.1.31:443/ws/spoke")


def test_ws_on_443_upgrades_to_wss():
    assert _norm("ws://172.16.1.31:443") == "wss://172.16.1.31:443/ws/spoke"


def test_ws_on_legacy_loopback_port_is_left_alone():
    assert _norm("ws://127.0.0.1:8765") == "ws://127.0.0.1:8765"


def test_ws_on_legacy_loopback_port_with_path_is_unchanged():
    assert (_norm("ws://127.0.0.1:8765/ws/spoke")
            == "ws://127.0.0.1:8765/ws/spoke")


def test_trailing_slash_path_is_stripped():
    assert (_norm("wss://172.16.1.31:443/ws/spoke/")
            == "wss://172.16.1.31:443/ws/spoke")
