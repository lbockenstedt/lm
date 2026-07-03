"""Generic leaf agent hub-URL handling — the two connection-failure gates.

1. ``_normalize_url``: under the unified-443 merge the spoke-WS lives at
   ``/ws/spoke`` on the single :443 listener. Two best-effort migrations so
   operators don't have to re-edit stale pre-unified pins:
   - **ws://…:443 → wss://…:443**: port 443 is the TLS (wss) listener; a ``ws://``
     pin (or a discovery result that missed the ``tls_port`` TXT behind a
     reverse proxy) is plaintext-to-TLS → ``InvalidMessage``. Upgrade to wss.
   - **append ``/ws/spoke`` to a pathless :443 pin**: a pre-unified pin like
     ``wss://host:443`` (no path) hits the WebUI root ``/`` → ``HTTP 403``. A pin
     that already carries a path is left alone.
   ``ws://`` on any other port (e.g. 8765 on a not-yet-upgraded hub) and the
   ``auto`` sentinel are left untouched.

2. ``run()`` sentinel guard: when auto-discovery can't find a hub yet, the loop
   must back off and re-discover — it must NOT call ``websockets.connect("auto")``
   (``auto`` is not a URI → ``InvalidURI`` spam every 5s).
"""
import asyncio
import importlib.util
import sys
from pathlib import Path

# Load generic_agent/src/agent.py under a unique module name. A bare
# `import agent` collides with the lm/agent namespace package under pytest's
# rootdir (lm/), which shadows the leaf agent file.
_SRC = Path(__file__).parent.parent / "src"  # generic_agent/src (tests/ is a sibling)
sys.path.insert(0, str(_SRC))  # so agent.py's `from hub_discovery import …` resolves
_spec = importlib.util.spec_from_file_location("leaf_agent_module", _SRC / "agent.py")
agent = importlib.util.module_from_spec(_spec)
sys.modules["leaf_agent_module"] = agent
_spec.loader.exec_module(agent)
GenericLeafAgent = agent.GenericLeafAgent


# ── 1. _normalize_url ────────────────────────────────────────────────────────

def test_normalize_upgrades_ws_to_wss_on_443():
    """Port 443 is the hub's TLS listener AND the unified spoke-WS surface. A
    ws://...:443 pin (stale, or a discovery result that missed the tls_port TXT)
    is upgraded to wss:// AND gets /ws/spoke appended (pathless :443 → WebUI
    root → HTTP 403)."""
    assert GenericLeafAgent._normalize_url("ws://172.16.1.30:443") == "wss://172.16.1.30:443/ws/spoke"
    assert GenericLeafAgent._normalize_url("ws://lm-hub.example.com:443") == "wss://lm-hub.example.com:443/ws/spoke"
    # wss:// + no path: scheme is already right, just append the spoke path.
    assert GenericLeafAgent._normalize_url("wss://172.16.1.30:443") == "wss://172.16.1.30:443/ws/spoke"


def test_normalize_appends_spoke_path_to_pathless_443():
    """A pre-unified wss://host:443 pin (no path) 403s on the unified hub; append
    /ws/spoke. Covers the operator's stale-pin case."""
    assert GenericLeafAgent._normalize_url("wss://172.16.1.30:443") == "wss://172.16.1.30:443/ws/spoke"
    assert GenericLeafAgent._normalize_url("wss://172.16.1.30:443/") == "wss://172.16.1.30:443/ws/spoke"


def test_normalize_leaves_explicit_path_alone():
    """A pin that already carries a path (/ws/spoke, /ws/agent) is NOT rewritten."""
    assert GenericLeafAgent._normalize_url("wss://172.16.1.30:443/ws/spoke") == "wss://172.16.1.30:443/ws/spoke"
    assert GenericLeafAgent._normalize_url("wss://172.16.1.30:443/ws/agent") == "wss://172.16.1.30:443/ws/agent"


def test_normalize_leaves_loopback_and_non_443_alone():
    """8765 is the legacy loopback plaintext listener (a not-yet-upgraded hub may
    still serve it); ws:// there is correct — don't migrate to 443 mid-transition.
    A portless ws:// and the auto sentinel are untouched."""
    assert GenericLeafAgent._normalize_url("ws://127.0.0.1:8765") == "ws://127.0.0.1:8765"
    assert GenericLeafAgent._normalize_url("ws://172.16.1.30:8765") == "ws://172.16.1.30:8765"
    assert GenericLeafAgent._normalize_url("ws://172.16.1.30") == "ws://172.16.1.30"
    assert GenericLeafAgent._normalize_url("auto") == "auto"
    assert GenericLeafAgent._normalize_url("") == ""


def test_normalize_applied_in_constructor():
    """The constructor normalizes the pinned URL so _connect_once arms TLS and
    dials /ws/spoke."""
    a = GenericLeafAgent("ws://172.16.1.30:443", "agent-1", secret="s")
    assert a.spoke_url == "wss://172.16.1.30:443/ws/spoke"
    b = GenericLeafAgent("auto", "agent-2", secret="s")
    assert b.spoke_url == "auto"


# ── 2. run() sentinel guard ──────────────────────────────────────────────────

class _StopLoop(Exception):
    """Raised from the fake asyncio.sleep to break run()'s infinite loop."""


def test_run_does_not_connect_to_literal_auto_when_discovery_fails(monkeypatch):
    """When discover_hub_url returns None, spoke_url stays "auto". run() must
    back off + re-discover, NOT call websockets.connect("auto") (InvalidURI)."""
    a = GenericLeafAgent("auto", "agent-1", secret="s")
    assert a.spoke_url == "auto"

    # Discovery finds nothing → _resolve_spoke_url leaves spoke_url == "auto".
    monkeypatch.setattr(agent, "discover_hub_url", lambda timeout=5.0: None)

    # websockets.connect must never be reached. If it is, fail loud.
    import websockets
    def _boom(*args, **kwargs):
        raise AssertionError("websockets.connect was called with the 'auto' "
                             f"sentinel: args={args}")
    monkeypatch.setattr(websockets, "connect", _boom)

    # Let the loop back off a few passes, then break out of the infinite loop.
    calls = {"n": 0}
    real_sleep = asyncio.sleep
    async def _counting_sleep(d):
        calls["n"] += 1
        if calls["n"] >= 3:
            raise _StopLoop()
        await real_sleep(0)
    monkeypatch.setattr(agent.asyncio, "sleep", _counting_sleep)

    try:
        asyncio.run(a.run())
    except _StopLoop:
        pass
    # It looped (backing off + re-discovering) without ever connecting.
    assert calls["n"] >= 3, "run() did not enter the backoff/re-discover loop"


def test_run_connects_when_discovery_succeeds(monkeypatch):
    """Sanity: when discovery resolves the sentinel to a real URL, run() proceeds
    to _connect_once (websockets.connect) rather than spinning on the sentinel."""
    a = GenericLeafAgent("auto", "agent-1", secret="s")
    monkeypatch.setattr(agent, "discover_hub_url",
                        lambda timeout=5.0: "wss://172.16.1.30:443/ws/spoke")

    import websockets
    connected = {"yes": False}

    class _FakeWS:
        async def __aenter__(self):
            # Proves run() reached websockets.connect; then break _connect_once.
            connected["yes"] = True
            raise _StopLoop()
        async def __aexit__(self, *exc): return False
    monkeypatch.setattr(websockets, "connect", lambda *a, **k: _FakeWS())

    # run() catches the _StopLoop from __aenter__ in its `except Exception`; break
    # out of the infinite loop from the trailing sleep after that handler.
    calls = {"n": 0}
    real_sleep = asyncio.sleep

    async def _sleep(d):
        calls["n"] += 1
        if calls["n"] >= 2:
            raise _StopLoop()
        await real_sleep(0)
    monkeypatch.setattr(agent.asyncio, "sleep", _sleep)

    try:
        asyncio.run(a.run())
    except _StopLoop:
        pass
    assert connected["yes"], "run() never reached websockets.connect"
    assert a.spoke_url == "wss://172.16.1.30:443/ws/spoke"