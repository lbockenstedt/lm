"""Same-subnet session re-bind + non-routable never-auto-block.

Regression cover for a real self-lockout: an admin behind a corporate egress
proxy had one cookie arrive from 170.85.10.124 and 170.85.10.96 within the
120s hijack window. The proxy pool hands consecutive requests to different
egress nodes, so both addresses were genuinely live at once — indistinguishable
from theft by timing alone. The hijack response NSG-blocked BOTH, which locked
the operator out of their own hub (the deny rule sits above the default allow).

Two independent defects are covered here:

  1. An IP move INSIDE the bound address's subnet is a benign egress change
     (proxy/CGNAT fan-out or a DHCP roll), not a stolen cookie. It must re-bind
     and keep the session — on the HTTP middleware path AND the
     ``access.session_user`` path that WebSocket callers funnel through. A move
     ACROSS subnets must still be the deterministic hijack close.
  2. Loopback sources must never be AUTO-blocked: the hub's own self-calls
     arrive as 127.0.0.1, a cloud NSG never sees loopback traffic, and one such
     entry was recorded PERMANENT. Deliberately scoped to loopback only —
     RFC1918/CGNAT peers stay blockable because an Azure NSG does filter
     intra-VNet traffic.
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


def _peer_resolver(request):
    return request.client.host if request.client else None


def _mk_tm(tmp_path, entries=None):
    gc = {"azure_nsg": {"entries": entries or []}}
    tm = ThreatMonitor(_Hub(_State(str(tmp_path), gc)))
    tm._cfg["enabled"] = True
    return tm


# ── 1. same_bind_subnet semantics ────────────────────────────────────────────

@pytest.mark.parametrize("a,b", [
    ("170.85.10.124", "170.85.10.96"),   # the real incident pair
    ("10.1.2.3", "10.1.2.250"),
    ("1.1.1.1", "1.1.1.1"),              # identical
    ("45.33.32.1", "45.33.32.255"),
])
def test_same_subnet_pairs_are_same_client(a, b):
    assert access.same_bind_subnet(a, b) is True
    assert access.same_bind_subnet(b, a) is True   # symmetric


@pytest.mark.parametrize("a,b", [
    ("170.85.10.124", "170.85.11.96"),   # adjacent /24 → still a hijack
    ("1.1.1.1", "9.9.9.9"),
    ("45.33.32.1", "45.33.40.1"),
])
def test_cross_subnet_pairs_are_not_same_client(a, b):
    assert access.same_bind_subnet(a, b) is False
    assert access.same_bind_subnet(b, a) is False


@pytest.mark.parametrize("a,b", [
    ("", "1.1.1.1"), ("1.1.1.1", ""), (None, None), ("", ""),
    ("not-an-ip", "1.1.1.1"), ("1.1.1.1", "not-an-ip"),
    ("1.1.1.1", "2001:db8::1"),          # mixed family never matches
])
def test_blank_bad_and_mixed_family_are_never_same(a, b):
    assert access.same_bind_subnet(a, b) is False


def test_ipv6_uses_64_bit_prefix():
    assert access.same_bind_subnet("2001:db8:0:1::5", "2001:db8:0:1::99") is True
    assert access.same_bind_subnet("2001:db8:0:1::5", "2001:db8:0:2::5") is False


def test_prefix_is_configurable(monkeypatch):
    # Widen to /16 → a neighbouring /24 becomes the same client.
    monkeypatch.setattr(access, "_IP_BIND_PREFIX4", 16)
    assert access.same_bind_subnet("170.85.10.124", "170.85.11.96") is True
    # Full width restores strict per-address binding (the old behaviour).
    monkeypatch.setattr(access, "_IP_BIND_PREFIX4", 32)
    assert access.same_bind_subnet("170.85.10.124", "170.85.10.96") is False
    assert access.same_bind_subnet("170.85.10.124", "170.85.10.124") is True


# ── 2. access.session_user (the WebSocket / universal funnel) ────────────────

def test_session_survives_same_subnet_egress_change():
    access.set_client_ip_resolver(_peer_resolver)
    sessions = {"tok": _mk_session("170.85.10.124")}
    sess = access.session_user(sessions, _FakeRequest("tok", "170.85.10.96"))
    assert sess is not None, "same-subnet egress change must not log the user out"
    assert "tok" in sessions
    # ...and the session re-binds to the address actually in use.
    assert sessions["tok"]["client_ip"] == "170.85.10.96"
    access.set_client_ip_resolver(None)


def test_session_still_rejected_across_subnets():
    access.set_client_ip_resolver(_peer_resolver)
    sessions = {"tok": _mk_session("170.85.10.124")}
    assert access.session_user(sessions, _FakeRequest("tok", "45.33.32.156")) is None
    assert "tok" not in sessions, "cross-subnet replay must still invalidate"
    access.set_client_ip_resolver(None)


def test_rebind_then_reject_from_original_far_ip():
    """After a legitimate re-bind the new address is authoritative, and a
    far-away replay is still closed out."""
    access.set_client_ip_resolver(_peer_resolver)
    sessions = {"tok": _mk_session("170.85.10.124")}
    assert access.session_user(sessions, _FakeRequest("tok", "170.85.10.96")) is not None
    assert access.session_user(sessions, _FakeRequest("tok", "170.85.10.7")) is not None
    assert access.session_user(sessions, _FakeRequest("tok", "8.8.8.8")) is None
    access.set_client_ip_resolver(None)


# ── 3. non-routable sources are never AUTO-blocked ───────────────────────────

@pytest.mark.parametrize("ip", [
    "127.0.0.1",        # the hub's own self-calls (was blocked PERMANENTLY)
    "127.0.0.53",
    "::1",
    "0.0.0.0",
])
def test_loopback_sources_are_spared(tmp_path, ip):
    tm = _mk_tm(tmp_path)
    res = tm.block_ip_unless_trusted(ip, reason="admin session-cookie hijack")
    assert res.get("spared") == ip
    assert ip not in tm._blocks


def test_public_source_is_still_blocked(tmp_path):
    tm = _mk_tm(tmp_path)
    res = tm.block_ip_unless_trusted("45.33.32.156", reason="admin session-cookie hijack")
    assert res.get("block") is not None
    assert "45.33.32.156" in tm._blocks


@pytest.mark.parametrize("ip", ["10.0.0.5", "192.168.1.10", "172.16.0.9",
                                "100.127.255.4", "169.254.1.1"])
def test_vnet_internal_sources_are_still_blockable(tmp_path, ip):
    """Scope check: an Azure NSG DOES filter intra-VNet traffic, so blocking a
    compromised private/CGNAT peer stays available. Only loopback is exempt."""
    tm = _mk_tm(tmp_path)
    res = tm.block_ip_unless_trusted(ip, reason="admin session-cookie hijack")
    assert res.get("block") is not None
    assert ip in tm._blocks


def test_unparseable_source_is_still_blockable(tmp_path):
    """Fail closed: junk input must not be mistaken for loopback."""
    tm = _mk_tm(tmp_path)
    assert tm._is_loopback("not-an-ip") is False


def test_manual_block_still_works_for_loopback(tmp_path):
    """The guard covers AUTO-blocks only — operators keep manual control."""
    tm = _mk_tm(tmp_path)
    res = tm.block_manual("127.0.0.1", reason="operator decision")
    assert res.get("status") == "SUCCESS"
    assert "127.0.0.1" in tm._blocks


def test_threshold_path_also_spares_loopback(tmp_path):
    """record_failure must not accumulate a block against the hub itself."""
    tm = _mk_tm(tmp_path)
    tm._cfg["threshold"] = 2
    for _ in range(10):
        tm.record_failure("127.0.0.1", "login", username="u1")
    assert "127.0.0.1" not in tm._blocks


def test_threshold_path_still_blocks_public(tmp_path):
    tm = _mk_tm(tmp_path)
    tm._cfg["threshold"] = 2
    for _ in range(10):
        tm.record_failure("8.8.8.8", "login", username="u1")
    assert "8.8.8.8" in tm._blocks


# ── 4. the incident, end to end ──────────────────────────────────────────────

def test_incident_regression_proxy_pool_does_not_lock_admin_out(tmp_path):
    """170.85.10.124 + 170.85.10.96 are one operator behind an egress proxy.
    Neither may end up in the NSG deny rule."""
    access.set_client_ip_resolver(_peer_resolver)
    sessions = {"tok": _mk_session("170.85.10.124")}

    # The second egress node presents the same cookie → session kept.
    assert access.session_user(sessions, _FakeRequest("tok", "170.85.10.96")) is not None

    # And even if the hijack response were reached for these two addresses,
    # the same-subnet filter keeps the owner's own pool out of the block set.
    tm = _mk_tm(tmp_path)
    involved = sorted(
        o for o in {"170.85.10.124", "170.85.10.96"}
        if not access.same_bind_subnet(o, "170.85.10.124"))
    assert involved == [], "owner's own egress pool must never be blocked"
    for ip in ("170.85.10.124", "170.85.10.96"):
        assert ip not in tm._blocks
    access.set_client_ip_resolver(None)


# ── 5. IPv4-mapped IPv6 must not collapse the whole IPv4 space ───────────────

def test_ipv4_mapped_addresses_do_not_all_share_a_64():
    """``::ffff:a.b.c.d`` is an IPv6 address, so a naive /64 comparison makes
    EVERY IPv4 client look like the same subnet — which would defeat the bind
    entirely. The embedded IPv4 address must be unwrapped first."""
    assert access.same_bind_subnet("::ffff:170.85.10.124", "::ffff:45.33.32.156") is False
    assert access.same_bind_subnet("::ffff:170.85.10.124", "::ffff:170.85.11.5") is False
    # ...while a genuine same-/24 pair still matches through the mapped form.
    assert access.same_bind_subnet("::ffff:170.85.10.124", "::ffff:170.85.10.96") is True


def test_mapped_and_native_ipv4_are_the_same_client():
    assert access.same_bind_subnet("::ffff:170.85.10.124", "170.85.10.96") is True
    assert access.same_bind_subnet("170.85.10.124", "::ffff:45.33.32.156") is False


def test_mapped_ipv4_session_is_rejected_across_subnets():
    access.set_client_ip_resolver(_peer_resolver)
    sessions = {"tok": _mk_session("::ffff:170.85.10.124")}
    assert access.session_user(sessions, _FakeRequest("tok", "::ffff:45.33.32.156")) is None
    assert "tok" not in sessions
    access.set_client_ip_resolver(None)


# ── 6. prefix override validation ────────────────────────────────────────────

@pytest.mark.parametrize("raw,expected", [
    ("28", 28),          # valid narrowing
    ("32", 32),          # strict per-address binding
    ("0", 24),           # /0 would disable the control → fall back
    ("1", 24),           # absurdly wide → fall back
    ("-5", 24),          # negative → fall back
    ("99", 24),          # wider than the family width → fall back
    ("abc", 24),         # not a number → fall back (must NOT raise)
    ("", 24),            # blank → default
])
def test_prefix_override_falls_back_to_secure_default(monkeypatch, raw, expected):
    monkeypatch.setenv("LM_SESSION_IP_BIND_PREFIX4", raw)
    assert access._bind_prefix("LM_SESSION_IP_BIND_PREFIX4", 24, 8, 32) == expected


def test_prefix_override_unset_uses_default(monkeypatch):
    monkeypatch.delenv("LM_SESSION_IP_BIND_PREFIX4", raising=False)
    assert access._bind_prefix("LM_SESSION_IP_BIND_PREFIX4", 24, 8, 32) == 24


def test_rebind_keeps_ip_seen_in_step():
    """access.py and the api.py middleware must not disagree about live IPs."""
    access.set_client_ip_resolver(_peer_resolver)
    sessions = {"tok": _mk_session("170.85.10.124")}
    assert access.session_user(sessions, _FakeRequest("tok", "170.85.10.96")) is not None
    assert "170.85.10.96" in sessions["tok"]["ip_seen"]
    access.set_client_ip_resolver(None)
