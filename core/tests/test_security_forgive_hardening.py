"""Hardening around strike forgiveness — the skeptical-review follow-ups to the
original ``unblock(forgive=...)`` work.

Three separate defects, all of which make a *policy-relaxing* action fire when
the operator did not ask for it, or let attacker-controlled text into state:

1. ``forgive=body.get("forgive", True) is not False`` treats every value that
   is not the literal ``False`` as true — so a client sending the JSON string
   ``"false"``, ``"0"`` or the integer ``0`` silently forgives the strike it
   explicitly asked to keep. Parsing must be strict.

2. ``forgive()`` clears strikes with nothing but a log line. Every other policy
   action in the threat monitor lands in the ``_events`` feed that the Security
   view renders and that is persisted with state; forgiveness — which shortens
   the path to a permanent ban — must be auditable the same way.

3. ``_block()`` took the ``ip`` string on trust. It arrives from request headers
   (``X-Forwarded-For`` and friends), i.e. it is attacker-controlled, and it
   becomes a persisted ``_offense``/``_blocks`` key that is rendered in the UI.
   Anything that is not a real address must be refused before it reaches state.
"""
import importlib.util
import os
import sys

_SRC = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))


def _load_from_src(modname, relpath):
    target = os.path.join(_SRC, relpath)
    spec = importlib.util.spec_from_file_location(modname, target)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[modname] = mod
    spec.loader.exec_module(mod)
    return mod


if _SRC not in sys.path:
    sys.path.insert(0, _SRC)
_load_from_src("azure_nsg", "azure_nsg.py")
_tm = _load_from_src("security.threat_monitor", os.path.join("security", "threat_monitor.py"))
ThreatMonitor = _tm.ThreatMonitor


class _State:
    def __init__(self, data_dir, global_config=None):
        self.data_dir = data_dir
        self.system_state = {"global_config": global_config or {}}

    def _mark_dirty(self):
        pass


class _Hub:
    def __init__(self, state):
        self.state = state


def _tm_for(tmp_path, entries=None):
    return ThreatMonitor(_Hub(_State(str(tmp_path), {"azure_nsg": {"entries": entries or []}})))


def _trip(tm, ip):
    tm.record_failure(ip, "login")
    tm.record_failure(ip, "login")


# ── 1. strict boolean parsing of the `forgive` flag ──────────────────────────
def _as_bool_from_route():
    """Pull the route module's ``_as_bool`` out without standing up FastAPI.

    ``security.py``'s helpers are defined inside ``register()``, so grab the
    source of the nested function and exec just that.
    """
    import ast
    import textwrap

    src = open(os.path.join(_SRC, "routes", "security.py")).read()
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "_as_bool":
            ns = {}
            exec(compile(ast.Module(body=[node], type_ignores=[]), "<_as_bool>", "exec"), ns)
            return ns["_as_bool"]
    raise AssertionError("_as_bool not found in routes/security.py")


def test_as_bool_honours_falsey_strings_and_zero():
    """The whole point: these must NOT be read as 'forgive the strike'."""
    _as_bool = _as_bool_from_route()
    for falsey in (False, "false", "False", "  FALSE  ", "0", "no", "off", "", 0):
        assert _as_bool(falsey, True) is False, falsey


def test_as_bool_accepts_truthy_forms():
    _as_bool = _as_bool_from_route()
    for truthy in (True, "true", "True", "1", "yes", "on", 1):
        assert _as_bool(truthy, False) is True, truthy


def test_as_bool_falls_back_to_default_when_absent_or_unparseable():
    _as_bool = _as_bool_from_route()
    assert _as_bool(None, True) is True
    assert _as_bool(None, False) is False
    assert _as_bool({"weird": 1}, True) is True
    assert _as_bool(["nope"], False) is False


def test_string_false_keeps_the_strike_end_to_end(tmp_path):
    """Before the fix, ``"false"`` took the forgive path and zeroed the strike."""
    _as_bool = _as_bool_from_route()
    tm = _tm_for(tmp_path)
    tm.set_config({"threshold": 1, "window_s": 600})
    _trip(tm, "203.0.113.9")
    assert tm._offense["203.0.113.9"] == 1

    res = tm.unblock("203.0.113.9", forgive=_as_bool("false", True))

    assert res["forgiven"] is False
    assert tm._offense["203.0.113.9"] == 1


# ── 2. forgive() leaves an audit record ──────────────────────────────────────
def test_forgive_records_an_audit_event(tmp_path):
    tm = _tm_for(tmp_path)
    tm._offense["203.0.113.9"] = 4

    tm.forgive("203.0.113.9")

    evts = [e for e in tm._events if e.get("kind") == "forgive"]
    assert len(evts) == 1
    assert evts[0]["ip"] == "203.0.113.9"
    assert "4 strike" in evts[0]["detail"]
    assert evts[0]["anomaly"] is False


def test_forgive_noop_records_nothing(tmp_path):
    """No strikes to clear → no state change, so nothing to audit."""
    tm = _tm_for(tmp_path)

    res = tm.forgive("203.0.113.9")

    assert res["cleared"] == 0
    assert not [e for e in tm._events if e.get("kind") == "forgive"]


def test_forgive_audit_event_survives_persistence(tmp_path):
    """The event feed is persisted with state — the record must be durable."""
    tm = _tm_for(tmp_path)
    tm._offense["203.0.113.9"] = 2
    tm.forgive("203.0.113.9")

    tm2 = _tm_for(tmp_path)

    assert [e for e in tm2._events if e.get("kind") == "forgive"]


# ── 3. _block() refuses non-addresses ────────────────────────────────────────
def test_block_refuses_hostile_ip_strings(tmp_path):
    """``ip`` is attacker-controlled header text and becomes a rendered,
    persisted state key — never let a non-address in."""
    tm = _tm_for(tmp_path)
    for hostile in ("<img src=x onerror=alert(1)>", "'); alert(1); //",
                    "not-an-ip", "", "   ", "203.0.113.9 extra"):
        tm._block(hostile, "reason", "login", "manual")
        assert hostile not in tm._blocks
        assert hostile not in tm._offense
        assert hostile.strip() not in tm._blocks


def test_block_still_accepts_real_addresses(tmp_path):
    tm = _tm_for(tmp_path)
    for good in ("203.0.113.9", "198.51.100.96", "::1", "2001:db8::1"):
        tm._block(good, "reason", "login", "manual")
        assert good in tm._blocks


def test_block_trims_surrounding_whitespace(tmp_path):
    tm = _tm_for(tmp_path)
    tm._block("  203.0.113.9  ", "reason", "login", "manual")
    assert "203.0.113.9" in tm._blocks
