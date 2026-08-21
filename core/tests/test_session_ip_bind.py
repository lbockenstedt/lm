"""Session source-IP bind + admin session-cookie hijack response (surface H).

Covers the deterministic close of the stolen-admin-cookie vuln:
  1. ``access.session_user`` rejects a cookie presented from an IP other than
     the one the session was minted for (bind), pops the token, and uses the
     registered trusted-proxy-aware resolver — while a matched IP (or an
     unbound/legacy session) is honored.
  2. ``ThreatMonitor.block_ip_unless_trusted`` blocks a non-trusted source but
     SPARES an allow-listed/trusted IP (the ambiguous two-IP hijack response
     must not nuke the legit admin's allow-listed IP).
  3. The ``session_hijack`` reason label is wired into ``_reason``.
"""
import importlib.util
import os
import sys
import time

import pytest  # noqa: F401

_SRC = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))


def _load_from_src(modname, relpath):
    target = os.path.join(_SRC, relpath)
    cached = sys.modules.get(modname)
    if cached is not None and getattr(cached, "__file__", None) \
            and os.path.abspath(cached.__file__) == target:
        return cached
    spec = importlib.util.spec_from_file_location(modname, target)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[modname] = mod
    spec.loader.exec_module(mod)
    return mod


# access.py imports ``simulations.tenant_filter`` by name → src must be importable.
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)
import access  # noqa: E402

_load_from_src("azure_nsg", "azure_nsg.py")
_tm = _load_from_src("security.threat_monitor", os.path.join("security", "threat_monitor.py"))
ThreatMonitor = _tm.ThreatMonitor


# ── fakes ────────────────────────────────────────────────────────────────────

class _FakeClient:
    def __init__(self, host):
        self.host = host


class _FakeRequest:
    """Minimal duck-type for access.session_user / the resolver."""
    def __init__(self, token, host):
        self.cookies = {"lm_session": token} if token else {}
        self.client = _FakeClient(host)
        self.headers = {}


class _State:
    def __init__(self, data_dir, global_config=None):
        self.data_dir = data_dir
        self.system_state = {"global_config": global_config or {}}

    def _mark_dirty(self):
        pass


class _Hub:
    def __init__(self, state):
        self.state = state


def _mk_session(bound_ip):
    now = time.time()
    return {
        "user_id": "u1", "sid": "s1",
        "expires": now + 3600, "created": now, "last_seen": now,
        "user": {"permissions": {"admin": True}},
        "client_ip": bound_ip,
        "ip_seen": {bound_ip: now} if bound_ip else {},
    }


# ── 1. session_user IP bind ──────────────────────────────────────────────────

def _peer_resolver(request):
    return request.client.host if request.client else None


def test_bind_rejects_mismatched_ip(monkeypatch):
    access.set_client_ip_resolver(_peer_resolver)
    sessions = {"tok": _mk_session("1.1.1.1")}
    # Same IP → honored.
    assert access.session_user(sessions, _FakeRequest("tok", "1.1.1.1")) is not None
    # Different IP → rejected + popped.
    assert access.session_user(sessions, _FakeRequest("tok", "9.9.9.9")) is None
    assert "tok" not in sessions


def test_bind_absent_is_not_enforced(monkeypatch):
    access.set_client_ip_resolver(_peer_resolver)
    sessions = {"tok": _mk_session(None)}
    # Unbound (legacy / rehydrated) session → no IP enforcement, still valid.
    assert access.session_user(sessions, _FakeRequest("tok", "9.9.9.9")) is not None
    assert "tok" in sessions


def test_bind_uses_registered_resolver():
    # The resolver, not the raw peer, decides the IP (trusted-proxy XFF path).
    access.set_client_ip_resolver(lambda req: "1.1.1.1")
    sessions = {"tok": _mk_session("1.1.1.1")}
    # Raw peer is an untrusted proxy address, but resolver returns the real
    # client 1.1.1.1 → matches bind → honored.
    assert access.session_user(sessions, _FakeRequest("tok", "10.0.0.9")) is not None
    access.set_client_ip_resolver(None)


# ── 2. block_ip_unless_trusted ───────────────────────────────────────────────

def test_block_unless_trusted_spares_allowlisted(tmp_path):
    gc = {"azure_nsg": {"entries": [{"ip": "1.2.3.4/32", "description": "Lance Home"}]}}
    tm = ThreatMonitor(_Hub(_State(str(tmp_path), gc)))
    tm._cfg["enabled"] = True

    spared = tm.block_ip_unless_trusted("1.2.3.4", reason="hijack")
    assert spared.get("spared") == "1.2.3.4"
    assert "1.2.3.4" not in tm._blocks

    blocked = tm.block_ip_unless_trusted("5.6.7.8", reason="hijack")
    assert blocked.get("block") is not None
    assert "5.6.7.8" in tm._blocks
    assert tm._blocks["5.6.7.8"]["kind"] == "session_hijack"


def test_session_hijack_reason_label(tmp_path):
    tm = ThreatMonitor(_Hub(_State(str(tmp_path), {"azure_nsg": {"entries": []}})))
    reason = tm._reason("6.6.6.6", "session_hijack", None, 1)
    assert "concurrent admin session-cookie use" in reason
