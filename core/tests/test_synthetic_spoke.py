"""Synthetic spokes (Test Data Feed, load test) have no host of their own.

The Test Data Feed runs as a child process of the Dev/QA hub, in the hub's
working directory and environment. A base handler that acts on "this host"
would patch, reboot or run commands on the hub's box under a production
spoke's name, and a base persister would write the hub's own ``.env``.
``messaging/synthetic_spoke.py`` sorts every base command into pass-through,
skipped or refused; these tests pin that sorting, the host isolation, the
auth-frame marker the hub reads, and Remote Console leaving such spokes out.
"""
import ast
import asyncio
import http.server
import inspect
import itertools
import json
import logging
import os
import signal
import subprocess
import sys
import textwrap
import threading
import time
import types

import pytest
from fastapi import HTTPException

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "scripts"))

import hub_feed  # noqa: E402
from messaging import control_plane as cp  # noqa: E402
from messaging import synthetic_spoke as ss  # noqa: E402


def _run(coro):
    return asyncio.run(coro)


class _Bare(ss.SyntheticSpoke):
    """Only what the dispatch needs; the base handler is patched out."""

    def __init__(self):
        self.spoke_id = "feed-cs-01"


@pytest.fixture
def base_calls(monkeypatch):
    """Replace the base handler with a recorder; returns the commands it got."""
    calls = []

    async def _base(self, cmd_type, data):
        calls.append(cmd_type)
        return {"status": "SUCCESS", "message": "base"}

    monkeypatch.setattr(cp.BaseControlPlane, "handle_system_command", _base)
    return calls


def _base_commands():
    """Every literal the base handle_system_command compares ``cmd_type`` with."""
    src = textwrap.dedent(inspect.getsource(cp.BaseControlPlane.handle_system_command))
    found = set()
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Compare) and getattr(node.left, "id", "") == "cmd_type":
            for comp in node.comparators:
                elts = getattr(comp, "elts", [comp])
                found |= {e.value for e in elts if isinstance(e, ast.Constant)}
    return found


def test_every_base_command_is_in_exactly_one_group():
    # A base command added later must be classified before it can run here.
    groups = (ss.PASS_THROUGH, ss.SKIPPED, ss.REFUSED)
    assert sum(len(g) for g in groups) == len(set().union(*groups))
    assert set().union(*groups) == _base_commands()


def test_host_commands_are_refused_without_reaching_the_base(base_calls):
    for cmd in sorted(ss.REFUSED):
        res = _run(_Bare().handle_system_command(cmd, {}))
        assert res["status"] == "ERROR" and "synthetic spoke" in res["message"], cmd
    assert base_calls == []


def test_hub_pushes_are_acknowledged_as_skipped(base_calls):
    # SUCCESS, so a fleet-wide fan-out does not list the feed's spokes as failed.
    for cmd in sorted(ss.SKIPPED):
        res = _run(_Bare().handle_system_command(cmd, {}))
        assert res["status"] == "SUCCESS" and res["message"].startswith("skipped"), cmd
    assert base_calls == []


def test_process_local_commands_run_and_module_commands_are_left_alone(base_calls):
    for cmd in sorted(ss.PASS_THROUGH):
        assert _run(_Bare().handle_system_command(cmd, {}))["message"] == "base"
    # Not a base command: None, as before, so the module layer answers it.
    assert _run(_Bare().handle_system_command("PXMX_START_VM", {})) is None
    assert base_calls == sorted(ss.PASS_THROUGH)


def test_a_refusal_never_logs_the_command_data(base_calls, caplog):
    # OS_FIX_ACCESS carries a sudo password.
    with caplog.at_level(logging.WARNING, logger="SyntheticSpoke"):
        _run(_Bare().handle_system_command("OS_FIX_ACCESS", {"password": "hunter2"}))
    assert "OS_FIX_ACCESS" in caplog.text and "hunter2" not in caplog.text


# ── host isolation, with the real base handlers ─────────────────────────

@pytest.fixture
def host(tmp_path, monkeypatch):
    """A fake host: the working directory (so ``.env``) and the cert dir,
    holding the host spoke's own mTLS client cert."""
    certs = tmp_path / "certs"
    certs.mkdir()
    for name in ("server.crt", "mtls-hub-client.crt", "mtls-hub-client.key"):
        (certs / name).write_text("x")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("LM_TLS_CERT", str(certs / "server.crt"))
    monkeypatch.setenv("LM_MTLS_HUB_CLIENT_CERT", str(certs / "mtls-hub-client.crt"))
    monkeypatch.setenv("LM_MTLS_HUB_CLIENT_KEY", str(certs / "mtls-hub-client.key"))
    monkeypatch.delenv("LM_RECOVERY_PSK", raising=False)
    return tmp_path


def _plain(**kw):
    s = ss.SyntheticSpoke(spoke_id="cs-01", **kw)
    logging.getLogger().removeHandler(s._log_relay_handler)
    return s


def _feed(**kw):
    return hub_feed._load_feed_spoke()(spoke_id="cs-01", payload={}, stats={}, **kw)


def _loadtest(**kw):
    import loadtest_spokes
    return loadtest_spokes.LoadSpoke("cs-01", stats={}, rate=1, payload_bytes=0, **kw)


class _Ctx:
    """SSL context stand-in that records any client cert loaded into it."""

    def __init__(self):
        self.loaded = []

    def load_cert_chain(self, *args, **kw):
        self.loaded.append(args)


def _tree(root):
    return sorted(str(p.relative_to(root)) for p in root.rglob("*"))


@pytest.mark.parametrize("make", [_plain, _feed, _loadtest], ids=["base", "feed", "loadtest"])
def test_secrets_markers_and_certs_stay_off_the_host(make, host, monkeypatch):
    # loadtest: LoadSpoke used to write the recovery PSK into the host's .env.
    before = _tree(host)
    s = make(hub_url="wss://127.0.0.1:443")
    monkeypatch.setattr(s, "_spoke_state_dir", lambda: str(host / "state"))
    for cmd, data in (("SPOKE_SET_HUB_SECRET", {"hub_secret": "hs"}),
                      ("SPOKE_SET_RECOVERY_PSK", {"recovery_psk": "psk"}),
                      ("SPOKE_UPDATE_SESSION_KEY", {"secret": "sk"})):
        assert _run(s.handle_system_command(cmd, data))["status"] == "SUCCESS", cmd
    s._touch_healthy_marker()
    assert (s.hub_secrets[0], s.recovery_psk, s.secret) == ("hs", "psk", "sk")
    assert _tree(host) == before
    # The TLS ratchet lives in a private dir, and the host's client cert is never presented.
    assert not s._hub_tls_marker_path().startswith(str(host))
    ctx = _Ctx()
    assert s._present_client_cert(ctx) is ctx and ctx.loaded == []


@pytest.mark.parametrize("make", [_plain, _feed, _loadtest], ids=["base", "feed", "loadtest"])
def test_each_client_is_marked_and_refuses_host_commands(make, host):
    # Catches a subclass override that drops the marker or bypasses the refusal.
    s = make(hub_url="wss://127.0.0.1:443")
    assert s._extra_auth_fields()["synthetic"] == 1
    # The read-only member of REFUSED, so it is safe to send for real.
    assert _run(s.handle_system_command("SPOKE_GET_MTLS_STATUS", {}))["status"] == "ERROR"


@pytest.mark.parametrize("make", [_plain, _feed, _loadtest], ids=["base", "feed", "loadtest"])
def test_run_refuses_before_starting_any_host_watchdog(make, host, monkeypatch):
    # The base run() reaches _resolve_hub_url before it starts the code-drift
    # and hub-contact watchdogs. Patch the instance: the scripts import their
    # own copy of the base class (core.src.messaging), which a patch on cp's
    # class would miss.
    s = make(hub_url="wss://127.0.0.1:443")

    async def _started():
        raise AssertionError("the base run() loop started")

    monkeypatch.setattr(s, "_resolve_hub_url", _started)
    with pytest.raises(RuntimeError, match="synthetic spoke"):
        _run(s.run())


def test_the_auth_frame_marker_is_what_the_hub_reads():
    import main
    frame = {"spoke_id": "cs-01", "secret": "s"}
    marked = {**frame, **_Bare()._extra_auth_fields()}
    assert main._SpokeHello.from_auth_frame(marked).synthetic is True
    assert main._SpokeHello.from_auth_frame(frame).synthetic is False


# ── hub: Remote Console leaves synthetic spokes out ─────────────────────

class _App:
    """Captures the handlers register() attaches, keyed by method and path."""

    def __init__(self):
        self.routes = {}
        self.router = types.SimpleNamespace(on_startup=[])

    def _route(self, method, path):
        def deco(fn):
            self.routes[(method, path)] = fn
            return fn
        return deco

    def get(self, path):
        return self._route("GET", path)

    def post(self, path):
        return self._route("POST", path)


class _Req:
    def __init__(self, body=None):
        self._body = body or {}

    async def json(self):
        return self._body


def test_remote_console_neither_lists_nor_runs_on_a_synthetic_spoke():
    from routes import exec as exec_routes
    sent = []

    async def _rr(*args, **kw):
        sent.append(args)
        return {}

    hub = types.SimpleNamespace(
        state=types.SimpleNamespace(get_global_config=lambda: {"remote_exec": {"enabled": True}}),
        active_connections={"real-1": object(), "feed-1": object()}, agent_info={},
        synthetic_spokes={"feed-1"}, _primary_key=lambda s: s, request_response=_rr)
    ctx = types.SimpleNamespace(_session_user=lambda r: {"user": "admin"}, _is_admin=lambda s: True)
    app = _App()
    exec_routes.register(app, hub, ctx)
    targets = _run(app.routes[("GET", "/api/exec/targets")](_Req()))["targets"]
    assert [t["id"] for t in targets] == ["hub", "real-1"]
    with pytest.raises(HTTPException) as ei:
        _run(app.routes[("POST", "/api/exec")](_Req({"target": "feed-1", "command": "uptime"})))
    assert ei.value.status_code == 400 and sent == []


# ── stopping: SIGTERM (what Stop feed sends) is a clean exit ────────────

_SCRIPTS = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "scripts"))
_ONE_SPOKE = {"cs-01": {"module_type": "simulation", "name": "cs-01",
                        "clients": [{"hostname": "h"}]}}
# Runs the script named in argv[1] with every spoke losing its first cancel, as
# Python 3.11's asyncio.wait_for can make it (see SyntheticSpoke.stop_all). The
# spoke makes the scratch dir, then serves until it is cancelled again. The
# import order is the scripts' own, so they get this patched module.
_LOSE_FIRST_CANCEL = textwrap.dedent("""
    import asyncio, importlib, os, runpy, sys
    script = sys.argv[1]
    repo = os.path.dirname(os.path.dirname(script))
    sys.path[:0] = [os.path.join(repo, "core", "src"), repo]
    for name in ("core.src.messaging.synthetic_spoke", "messaging.synthetic_spoke"):
        try:
            ss = importlib.import_module(name)
            break
        except Exception:
            pass
    ss._RECANCEL_S = 0.2

    async def _serve(self):
        self._mtls_material_dir()
        lost = False
        while True:
            try:
                await asyncio.sleep(3600)
            except asyncio.CancelledError:
                if lost:
                    raise
                lost = True

    ss.SyntheticSpoke._connect_and_serve = _serve
    sys.argv = sys.argv[1:]
    runpy.run_path(script, run_name="__main__")
""")


def _spawn(script, argv, tmp_path, driver=None):
    """Start a script with its own TMPDIR; returns (process, that TMPDIR, log path).

    With ``driver``, runs ``python -c driver <script> <argv>`` instead."""
    tmp = tmp_path / "tmp"
    tmp.mkdir()
    log = tmp_path / "out.log"
    pre = ["-c", driver] if driver else []
    with open(log, "w") as out:
        proc = subprocess.Popen([sys.executable, *pre, os.path.join(_SCRIPTS, script), *argv],
                                cwd=tmp_path, env={**os.environ, "TMPDIR": str(tmp)},
                                stdout=out, stderr=subprocess.STDOUT)
    return proc, tmp, log


def _wait_for(cond, proc, timeout=30):
    """Poll cond() until it holds, the process exits or timeout seconds pass."""
    deadline = time.monotonic() + timeout
    while not cond() and proc.poll() is None and time.monotonic() < deadline:
        time.sleep(0.1)
    return cond()


def _serve(handler):
    """Serve handler on a free local port; returns the server, already running."""
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


@pytest.fixture
def source():
    """A source hub whose feed snapshot holds one spoke."""
    body = json.dumps({"spokes": _ONE_SPOKE}).encode()

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    srv = _serve(_Handler)
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()
    srv.server_close()


@pytest.mark.parametrize("driver", [None, _LOSE_FIRST_CANCEL], ids=["as-is", "first-cancel-lost"])
@pytest.mark.parametrize("script, ramp", [("hub_feed.py", "0"), ("hub_feed.py", "3600"),
                                          ("loadtest_spokes.py", "0")],
                         ids=["feed", "feed-in-ramp", "loadtest"])
def test_sigterm_exits_cleanly_and_removes_the_scratch_dir(script, ramp, driver, source, tmp_path):
    # SIGTERM's default action skips atexit, so every Stop left the dir behind.
    # A long ramp holds the feeder in its ramp, before the main loop.
    # Nothing listens on port 1, so the spokes retry until stopped.
    # first-cancel-lost: with one cancel per spoke, every variant waited forever.
    if script == "hub_feed.py":
        argv = ["--source", source, "--token", "t", "--target", "wss://127.0.0.1:1",
                "--ramp", ramp, "--interval", "3600"]
    else:
        argv = ["--hub", "wss://127.0.0.1:1", "--env-file", os.devnull, "--count", "1",
                "--ramp", ramp, "--duration", "3600", "--status-url", "http://127.0.0.1:1/status",
                "--sample-interval", "3600"]
    proc, tmp, log = _spawn(script, argv, tmp_path, driver)
    try:
        # The first spoke makes the dir, after the script has set its SIGTERM handler.
        assert _wait_for(lambda: list(tmp.glob("lm-synthetic-spoke-*")), proc), log.read_text()
        proc.send_signal(signal.SIGTERM)
        assert proc.wait(timeout=30) == 0, log.read_text()
        assert list(tmp.glob("lm-synthetic-spoke-*")) == [], log.read_text()
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()


@pytest.fixture
def stalling_source(request):
    """A source hub that answers its first N GETs, then holds every later GET open.

    ``request.param`` is (N, the spokes its snapshot holds). Yields the URL, an
    event that is set once a GET is being held, and whether a spoke is served."""
    answered, spokes = request.param
    body = json.dumps({"spokes": spokes}).encode()
    seen = itertools.count()
    stalled, release = threading.Event(), threading.Event()

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if next(seen) >= answered:
                stalled.set()
                release.wait(120)
                return
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    srv = _serve(_Handler)
    yield f"http://127.0.0.1:{srv.server_port}", stalled, bool(spokes)
    release.set()
    srv.shutdown()
    srv.server_close()


@pytest.mark.parametrize("stalling_source", [(0, {}), (1, {}), (1, _ONE_SPOKE)], indirect=True,
                         ids=["first-poll", "waiting-for-data", "re-poll"])
def test_sigterm_does_not_wait_for_a_stalled_source_poll(stalling_source, tmp_path):
    # A poll on the loop thread kept the SIGTERM handler from running for up to
    # four 30s GET timeouts, past the hub's SIGKILL, so Stop left the dir.
    url, stalled, has_spoke = stalling_source
    proc, tmp, log = _spawn("hub_feed.py", ["--source", url, "--token", "t",
                                            "--target", "wss://127.0.0.1:1",
                                            "--ramp", "0", "--interval", "0.2"], tmp_path)
    try:
        assert _wait_for(stalled.is_set, proc), log.read_text()
        # Re-poll: a spoke is up, so there is a scratch dir to remove.
        if has_spoke:
            assert _wait_for(lambda: list(tmp.glob("lm-synthetic-spoke-*")), proc), \
                log.read_text()
        proc.send_signal(signal.SIGTERM)
        # 15s: half the 30s a held GET takes to time out.
        assert proc.wait(timeout=15) == 0, log.read_text()
        assert list(tmp.glob("lm-synthetic-spoke-*")) == [], log.read_text()
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()


def test_stop_lets_a_token_rotation_in_flight_finish(tmp_path):
    # The refresh POST spends the old token, and the hub learns the new pair only
    # from the sentinel line, so exiting in between gets the token family revoked.
    posted, release = threading.Event(), threading.Event()
    pair = json.dumps({"access_token": "a2", "refresh_token": "r2"}).encode()
    empty = json.dumps({"spokes": {}}).encode()

    class _Handler(http.server.BaseHTTPRequestHandler):
        def _send(self, code, body=b""):
            self.send_response(code)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            # The first access token has expired; the rotated one works.
            if self.headers.get("Authorization") == "Bearer a2":
                self._send(200, empty)
            else:
                self._send(401)

        def do_POST(self):
            self.rfile.read(int(self.headers["Content-Length"]))
            posted.set()
            release.wait(30)
            self._send(200, pair)

        def log_message(self, *args):
            pass

    srv = _serve(_Handler)
    proc, _, log = _spawn("hub_feed.py", [
        "--source", f"http://127.0.0.1:{srv.server_port}", "--token", "a1",
        "--refresh-token", "r1", "--emit-token-rotations",
        "--target", "wss://127.0.0.1:1", "--ramp", "0", "--interval", "3600"], tmp_path)
    try:
        assert _wait_for(posted.is_set, proc), log.read_text()
        proc.send_signal(signal.SIGTERM)
        # A second Stop finds the feeder waiting in close(), where the closed
        # event loop has given SIGTERM back its default action (exit at once).
        time.sleep(5)
        proc.send_signal(signal.SIGTERM)
        # Answer the refresh 10s after the first SIGTERM, twice the 5s the
        # feeder used to wait before exiting without the new pair.
        time.sleep(5)
        assert proc.poll() is None, log.read_text()
        release.set()
        assert proc.wait(timeout=30) == 0, log.read_text()
        sentinel = hub_feed.TOKEN_ROTATION_SENTINEL + json.dumps({"access": "a2", "refresh": "r2"})
        assert sentinel in log.read_text().splitlines(), log.read_text()
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        release.set()
        srv.shutdown()
        srv.server_close()


def test_stop_does_not_kill_a_feeder_finishing_a_token_refresh(monkeypatch):
    # The feeder above exits only once the refresh has printed the new pair, and
    # each of the refresh's three network steps may take REFRESH_TIMEOUT. A
    # SIGKILL before then leaves the hub holding a spent refresh token, which
    # the old 10s grace did whenever the source took longer than that to answer.
    from routes import test_feed

    class _Feeder:
        """Exits once a refresh whose three steps each took the full timeout ends."""
        pid = 4242

        def poll(self):
            return None

        def wait(self, timeout=None):
            if timeout is not None and timeout < 3 * hub_feed.REFRESH_TIMEOUT:
                raise subprocess.TimeoutExpired("hub_feed.py", timeout)
            return 0

    sent = []
    monkeypatch.setattr(test_feed.os, "getpgid", lambda pid: pid)
    monkeypatch.setattr(test_feed.os, "killpg", lambda pgid, sig: sent.append(sig))
    monkeypatch.setitem(test_feed._proc, "p", _Feeder())
    monkeypatch.setitem(test_feed._proc, "psk", "")
    monkeypatch.setitem(test_feed._proc, "tenants", [])
    gc = {}
    hub = types.SimpleNamespace(state=types.SimpleNamespace(
        get_global_config=lambda: gc, system_state={}, _mark_dirty=lambda: None))
    ctx = types.SimpleNamespace(_session_user=lambda r: {"user": "admin"}, _is_admin=lambda s: True)
    app = _App()
    test_feed.register(app, hub, ctx)

    assert _run(app.routes[("POST", "/api/test-feed/stop")](_Req())) == {
        "status": "ok", "running": False}
    assert sent == [signal.SIGTERM]
    assert gc["test_feed"]["receiver_enabled"] is False
