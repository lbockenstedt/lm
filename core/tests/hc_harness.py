"""Scriptable fakes for driving ``LabManagerHub.handle_connection`` end to end.

handle_connection is the hub's security-critical front door, and it calls
~60 collaborators. This harness replaces every collaborator with a
*recording stub* whose outcome is chosen by a ``Script``. A test can then
drive the REAL handle_connection (and every phase method under it) over a
fake websocket and assert on:

* ``run.calls``     — every collaborator call, in order, with its arguments
* ``run.logs``      — every log record emitted
* ``run.closes`` / ``run.sends`` — what went back over the socket
* ``run.hub``       — the hub's state afterwards
* ``run.error``     — anything that escaped handle_connection

A ``Script`` either picks outcomes from a seeded RNG (fuzzing) or takes
explicit ``overrides`` (targeted tests): ``Script(overrides={"get_valid_key":
"k1"})`` makes every secret check succeed with key id ``k1``.

Everything non-deterministic (time, uuid4, token_urlsafe, create_task, the
rate-limiter bucket) is patched for the duration of a run so two runs of
the same scenario are byte-for-byte comparable.
"""
import asyncio
import contextlib
import dataclasses
import inspect
import json
import logging
import random
import types

import websockets
from websockets.frames import Close
from starlette.websockets import WebSocketDisconnect

import main as main_mod
from main import LabManagerHub

RAISE = object()  # Script outcome: the stub raises RuntimeError


class By:
    """An override computed from the stub's positional args:
    ``By(lambda pk, secret: "k1" if pk == "oldspk" else None)``."""

    def __init__(self, fn):
        self.fn = fn


class Script:
    """Chooses every stub outcome.

    ``overrides[name]`` wins; else a seeded RNG picks from the stub's option
    list. Both are consumed in call order, so two implementations that make
    the same calls in the same order see the same outcomes.
    """

    def __init__(self, seed=0, overrides=None):
        self.rng = random.Random(seed)
        self.overrides = dict(overrides or {})

    def pick(self, name, options, args=()):
        if name in self.overrides:
            value = self.overrides[name]
            return value.fn(*args) if isinstance(value, By) else value
        return self.rng.choice(options)


# ── canonical, comparable rendering of arbitrary values ─────────────────

def canon(x):
    if isinstance(x, FakeWS):
        return f"<ws:{x.tag}>"
    if isinstance(x, FakeQueue):
        return "<queue>"
    if isinstance(x, FakeBucket):
        return ("bucket", x.capacity, x.fill_rate)
    if inspect.iscoroutine(x):
        return f"<coro {x.__qualname__}>"
    if isinstance(x, dict):
        return sorted(((repr(canon(k)), canon(v)) for k, v in x.items()), key=lambda kv: kv[0])
    if isinstance(x, (set, frozenset)):
        return sorted(repr(canon(v)) for v in x)
    if isinstance(x, (list, tuple)):
        return [canon(v) for v in x]
    if isinstance(x, BaseException):
        return repr(x)
    if dataclasses.is_dataclass(x) and not isinstance(x, type):
        d = dataclasses.asdict(x)
        # Acknowledgement stamps its own wall-clock default — not ours.
        if type(x).__name__ == "Acknowledgement":
            d.pop("timestamp", None)
        return [type(x).__name__, canon(d)]
    if isinstance(x, LabManagerHub):
        return "<hub>"
    for attr in ("model_dump", "dict"):
        fn = getattr(x, attr, None)
        if callable(fn):
            try:
                d = dict(fn())
                # Acknowledgement stamps its own wall-clock default — not ours.
                if type(x).__name__ == "Acknowledgement":
                    d.pop("timestamp", None)
                return [type(x).__name__, canon(d)]
            except Exception:  # noqa: BLE001
                pass
    if isinstance(x, (str, int, float, bool, type(None), bytes)):
        return x
    if hasattr(x, "key_id"):
        return ("key", x.key_id)
    if callable(x) and hasattr(x, "__name__"):
        return f"<fn {getattr(x, '__qualname__', x.__name__)}>"
    return repr(x)


# ── fakes ────────────────────────────────────────────────────────────────

class FakeQueue:
    def __init__(self, run):
        self.run = run

    async def put(self, item):
        self.run.record("console_queue.put", (item,), {})
        if self.run.script.pick("console_queue.put", [None, None, RAISE]) is RAISE:
            raise RuntimeError("queue boom")


class FakeWS:
    """A spoke's websocket. ``recv_items`` answer ``recv()`` (auth frame,
    then the hub-proof reply); ``frames`` feed ``async for``; ``end`` is the
    exception raised when the frames run out (None = clean end)."""

    def __init__(self, run, tag, recv_items=(), frames=(), end=None,
                 remote_address=("192.0.2.10", 5555), peer_cert_identity=None):
        self.run, self.tag = run, tag
        self.recv_items = list(recv_items)
        self.frames, self.end = list(frames), end
        self.remote_address = remote_address
        self.peer_cert_identity = peer_cert_identity

    async def recv(self):
        if not self.recv_items:
            raise websockets.ConnectionClosed(None, None)
        item = self.recv_items.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item

    async def send(self, data):
        self.run.sends.append((self.tag, data))
        if self.run.script.pick("ws.send", [None] * 9 + [RAISE]) is RAISE:
            raise websockets.ConnectionClosed(None, None)

    async def close(self, code=1000, reason=""):
        self.run.closes.append((self.tag, code, reason))
        if self.run.script.pick("ws.close", [None] * 19 + [RAISE]) is RAISE:
            raise websockets.ConnectionClosed(None, None)

    def resolve_pong(self, corr_id):
        self.run.record("ws.resolve_pong", (corr_id,), {})

    def __aiter__(self):
        return self._iter()

    async def _iter(self):
        for f in self.frames:
            yield f
        if self.end is not None:
            raise self.end


class FakeBucket:
    """Stands in for TokenBucket; consume()/tokens come from the Script."""
    run = None

    def __init__(self, capacity, fill_rate):
        self.capacity, self.fill_rate = capacity, fill_rate
        self.tokens = capacity

    def consume(self):
        ok = self.run.script.pick("bucket.consume", [True, True, False])
        self.tokens = self.run.script.pick("bucket.tokens",
                                           [0, self.capacity * 0.1, self.capacity])
        self.run.record("bucket.consume", (), {})
        return ok


class _Proxy:
    """A module stand-in: overridden attributes, everything else real."""

    def __init__(self, real, **over):
        self._real, self._over = real, over

    def __getattr__(self, name):
        if name in self._over:
            return self._over[name]
        return getattr(self._real, name)


# ── stub specs: name → outcome options (RAISE = raise RuntimeError) ──────

HUB_STUBS = {
    "_record_spoke_auth_failure": [None],
    "record_spoke_event": [None],
    "_is_quarantined": [False] * 5 + [True],
    "_recorded_install_uuid": [None, "u1", "u2"],
    "_verify_install_uuid_binding": [True, False],
    "_reconcile_spoke_identity": ["noop", "noop", "alias"],
    "_is_approved_install_reconnect": [True, False],
    "_within_reconnect_exemption_budget": [True, False],
    "_note_known_ip": [None, RAISE],
    "_record_hub_identity_rejection": [True, False],
    "_rate_limit_params": [(400, 200), (0, 0)],
    "_mtls_connect_gate": [("ok", "fine")] * 4 + [("reject", "bad"), ("enroll", "nocert"),
                                                  ("ok", "enroll-exhausted"), RAISE],
    "_spawn_cs_push": [None],
    "_maybe_log_unauthenticated_agent": [None],
    "_check_freshness_and_replay": [True, True, True, False],
    "_handle_edge_probe_report": [None],
    "_handle_app_login_failure": [None],
    "_handle_node_canary_hit": [None],
    "get_console_session": [None, "sess", "sess"],
    "_relay_session_owner_ok": [True, True, False],
    "_vm_live_set": [None, RAISE],
    "_mtls_enrollment_done": [None, None, RAISE],
    "_mark_spoke_disconnected": [None],
    "clear_draining": [None],
    "mark_draining": [None],
    # async
    "_install_active_connection": [True, True, False],
    "_install_pending_connection": ["take", "take", "keep"],
    "_psk_is_valid": [True, False, RAISE],
    "_maybe_reprovision_hub_secret": [None, RAISE],
    "_try_psk_self_provision": [True, False],
    "_parent_vouches": [(True, "ok"), (False, "nope")],
    "approve_and_bind_spoke": [None],
    "_mtls_reject": [None],
    "_mtls_begin_enrollment": [None],
    "push_config_to_spoke": [False, True],
    "_readopt_agent_roles": [None],
    "_provision_spoke_mtls_cert_safe": [None],
    "send_to_spoke": [None, None, None, RAISE],
    "_maybe_redeliver_session_key": [None],
    "_decrypt_inbound_payload": [None, None, "dsec", main_mod._H4_DROP],
    "_handle_cs_telemetry": [None],
    "_handle_cs_config_request": [None],
    "_handle_spoke_log": [None],
    "_handle_cs_debug_log": [None],
    "_handle_console_probe": [None],
    "apply_nw_auto_poll": [None],
    "nw_cache_set_reachability": [None],
    "truenas_cache_set_poll": [None],
    "_on_le_cert_renewed": [None],
    "_handle_status_run_demo": [None],
    "_handle_agent_onboarding_psk": [None],
    "_handle_hub_request": [None],
    "push_cs_full_config": [None],
    "_handle_agent_relay_up": [True, False, None],
}

SUB_STUBS = {  # (object attr, method) → (is_async, options)
    ("key_manager", "get_valid_key"): (False, [None, "k1", "k2"]),
    ("key_manager", "sign_hub_challenge"): (False, ["sig"]),
    ("key_manager", "sign_hub_challenge_all"): (False, [["s0", "s1"], RAISE]),
    ("key_manager", "sign_hub_challenge_recovery"): (False, ["rsig", RAISE]),
    ("key_manager", "sign_message"): (False, ["msig", RAISE]),
    ("key_manager", "generate_first_secret"): (False, ["newsec"]),
    ("key_manager", "verify_signature_source"): (False, [None, "current", "current", "history"]),
    ("state", "register_module"): (False, [None]),
    ("state", "update_module_metadata"): (False, [None]),
    ("state", "get_spoke_tenant"): (False, ["t1", "t1", None, "", RAISE]),
    ("state", "set_spoke_last_seen"): (False, [None]),
    ("mailbox", "flush_mailbox"): (True, [None]),
    ("mailbox", "acknowledge"): (True, [None]),
    ("heartbeat", "update_heartbeat"): (False, [None]),
    ("threat_monitor", "record_success"): (False, [None, RAISE]),
    ("alert_engine", "evaluate"): (True, [None]),
    ("simulations_broadcaster", "broadcast"): (True, [None, RAISE]),
    ("dot1x_jit", "handle_spoke_message"): (True, [None]),
}


class Run:
    """One handle_connection execution against a freshly-built hub."""

    def __init__(self, script):
        self.script = script
        self.calls, self.logs, self.sends, self.closes = [], [], [], []
        self.error = None
        self._clock = 1000.0
        self._uuid = 0
        FakeBucket.run = self
        self.hub = self._build_hub()

    def record(self, name, args, kwargs):
        self.calls.append((name, canon(list(args)), canon(kwargs)))

    # outcome + side effects for a stub call ------------------------------
    def _outcome(self, name, options, args):
        value = self.script.pick(name, options, args)
        if value is RAISE:
            raise RuntimeError(f"{name} boom")
        hub = self.hub
        if name == "_reconcile_spoke_identity":
            if value == "alias" and isinstance(args[0], str):
                hub.spoke_id_alias[args[0]] = "guid-1"
            return None
        if name == "_install_active_connection":
            if value:
                hub.active_connections[hub._primary_key(args[0])] = args[1]
            return value
        if name == "_install_pending_connection":
            if value == "take":
                hub.active_connections[hub._primary_key(args[0])] = args[1]
            return None
        if name in ("_try_psk_self_provision", "approve_and_bind_spoke"):
            if value is not False:
                hub.approved_modules[hub._primary_key(args[0])] = True
            return value
        if name == "push_config_to_spoke":
            defer = hub._cs_connect_defer.get(args[0])
            if value and defer:
                defer[1] = True
            return None
        if name == "get_console_session":
            return {"queue": FakeQueue(self)} if value == "sess" else None
        if name == "register_module":
            hub.state.system_state["known_modules"][args[0]] = {"approved": kw_or(args, 1)}
            return None
        if name == "update_module_metadata":
            hub.state.system_state["module_metadata"].setdefault(args[0], {}).update(args[1])
            return None
        if name == "update_heartbeat":
            hub.heartbeat.last_seen[args[0]] = self._tick()
            return None
        return value

    def _make_stub(self, label, name, options, is_async):
        def sync_stub(*args, **kwargs):
            self.record(label, args, kwargs)
            return self._outcome(name, options, args)

        def async_stub(*args, **kwargs):
            # Record at CALL time (not await time): coroutines handed to
            # create_task/_spawn_cs_push are never awaited here.
            self.record(label, args, kwargs)
            try:
                value, exc = self._outcome(name, options, args), None
            except Exception as e:  # noqa: BLE001
                value, exc = None, e

            async def _await():
                if exc is not None:
                    raise exc
                return value
            return _await()
        return async_stub if is_async else sync_stub

    def _tick(self):
        self._clock += 0.5
        return self._clock

    def _next_uuid(self):
        self._uuid += 1
        return f"uuid-{self._uuid}"

    def _create_task(self, coro, *a, **k):
        self.record("create_task", (coro,), {})
        coro.close()
        return None

    def _build_hub(self):
        hub = LabManagerHub.__new__(LabManagerHub)
        for name, options in HUB_STUBS.items():
            is_async = inspect.iscoroutinefunction(getattr(LabManagerHub, name))
            setattr(hub, name, self._make_stub(name, name, options, is_async))
        subs = {}
        for (obj, meth), (is_async, options) in SUB_STUBS.items():
            ns = subs.setdefault(obj, types.SimpleNamespace())
            setattr(ns, meth, self._make_stub(f"{obj}.{meth}", meth, options, is_async))
        hub.key_manager = subs["key_manager"]
        hub.key_manager.keys = {}
        hub.state = subs["state"]
        hub.state.system_state = {"known_modules": {}, "module_metadata": {},
                                  "global_config": {}, "mtls_revoked": {}}
        hub.mailbox = subs["mailbox"]
        hub.heartbeat = subs["heartbeat"]
        hub.heartbeat.last_seen = {}
        hub.threat_monitor = subs["threat_monitor"]
        hub.alert_engine = subs["alert_engine"]
        hub.simulations_broadcaster = subs["simulations_broadcaster"]
        self.dot1x = subs["dot1x_jit"]

        hub.spoke_id_alias = {}
        hub.known_modules = hub.state.system_state["known_modules"]
        hub.approved_modules = {}
        hub.install_uuid_index = {}
        hub.active_connections = {}
        hub.active_connection_key_ids = {}
        hub.spoke_telemetry = {}
        hub.spoke_authenticated = {}
        hub._unauth_warned_spokes = set()
        hub.rate_limiters = {}
        hub.spoke_module_types = {}
        hub.spoke_parent_map = {}
        hub.netbox_server_agents = set()
        hub.ldap_server_agents = set()
        hub.spoke_enc_capable = {}
        hub.spoke_mtls_csr_capable = {}
        hub.agent_info = {}
        hub._cs_connect_defer = {}
        hub._spoke_recv = {}
        hub._protect_mode = False
        hub._protect_shed_bytes = 60
        hub._protect_shed_min_mps = 10
        hub._spoke_offered = {}
        hub.rate_limit_drops = {}
        hub.bytes_count = 0
        hub.spoke_msg_count = {}
        hub.message_count = 0
        hub._spoke_absent_since = {}
        hub._outstanding_requests = {}
        hub._progress_deadlines = {}
        hub._pending_liveness_nonces = set()
        hub._recent_request_timeouts = {}
        hub._pending_broadcast_ids = {}
        hub.response_cache = {}
        hub.spoke_versions = {}
        hub.spoke_commits = {}
        hub._probe_state = {}
        hub._rl_soft_frac = 0.8
        hub._rl_breached = set()
        hub._rl_harddrops = {}
        hub._telemetry_received = 0
        hub._telemetry_processed = 0
        hub._telemetry_coalesced = 0
        hub._spoke_backoff = set()
        hub._coalesce_pending = {}
        return hub

    STUB_NAMES = set(HUB_STUBS) | {"key_manager", "state", "mailbox", "heartbeat",
                                   "threat_monitor", "alert_engine",
                                   "simulations_broadcaster"}

    def snapshot(self):
        hub = self.hub
        data = {k: v for k, v in vars(hub).items() if k not in self.STUB_NAMES}
        data["~system_state"] = hub.state.system_state
        data["~keys"] = hub.key_manager.keys
        data["~last_seen"] = hub.heartbeat.last_seen
        return canon(data)

    def result(self):
        return {"calls": self.calls, "logs": self.logs, "sends": self.sends,
                "closes": self.closes, "error": self.error, "state": self.snapshot()}

    # execution -------------------------------------------------------------
    @contextlib.contextmanager
    def _patched(self):
        run = self

        class _Capture(logging.Handler):
            def emit(self, record):
                run.logs.append((record.name, record.levelno, record.getMessage(),
                                 bool(record.exc_info)))

        patches = {
            "time": _Proxy(main_mod.time, time=self._tick),
            "uuid": _Proxy(main_mod.uuid, uuid4=self._next_uuid),
            "secrets": _Proxy(main_mod.secrets, token_urlsafe=lambda n=32: "challenge"),
            "asyncio": _Proxy(asyncio, create_task=self._create_task),
            "TokenBucket": FakeBucket,
            "encryption_enabled": lambda: self.script.pick("encryption_enabled", [True, False]),
            "dot1x_jit": _Proxy(main_mod.dot1x_jit, handle_spoke_message=self.dot1x.handle_spoke_message),
        }
        saved = {k: main_mod.__dict__[k] for k in patches}
        main_mod.__dict__.update(patches)
        handler = _Capture(level=logging.DEBUG)
        root = logging.getLogger()
        hub_logger = logging.getLogger("Hub")
        old_levels = (root.level, hub_logger.level)
        root.addHandler(handler)
        root.setLevel(logging.DEBUG)
        hub_logger.setLevel(logging.DEBUG)
        try:
            yield
        finally:
            root.removeHandler(handler)
            root.setLevel(old_levels[0])
            hub_logger.setLevel(old_levels[1])
            main_mod.__dict__.update(saved)

    def execute(self, websocket, fn=None):
        """Run ``fn`` (default: the real handle_connection) on ``websocket``."""
        fn = fn or LabManagerHub.handle_connection
        with self._patched():
            try:
                asyncio.run(fn(self.hub, websocket))
            except BaseException as e:  # noqa: BLE001
                self.error = repr(e)
        return self


def kw_or(args, i, default=False):
    return args[i] if len(args) > i else default


# ── scenario building helpers ────────────────────────────────────────────

def hub_ok(index=None):
    body = {"status": "HUB_OK"}
    if index is not None:
        body["hub_secret_index"] = index
    return json.dumps(body)


def closed(code=None, reason=""):
    return websockets.ConnectionClosed(Close(code, reason) if code else None, None)


def signed(body, sig="s1"):
    """A signed wire frame ``<sig>.<json body>``."""
    return f"{sig}.{json.dumps(body)}"


def unsigned(body):
    return "." + json.dumps(body)


def msg(mtype, data=None, **extra):
    body = {"payload": {"type": mtype, "data": {} if data is None else data}}
    body.update(extra)
    return body


__all__ = ["RAISE", "By", "Script", "Run", "FakeWS", "canon", "hub_ok", "closed",
           "signed", "unsigned", "msg", "WebSocketDisconnect"]
