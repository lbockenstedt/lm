"""``lm-watchdog`` must DIAGNOSE a wedged hub and stop hammering a hub that a
restart cannot fix.

Why this test exists — a real production incident: an event-loop deadlock in
``simulations/store.py`` wedged the hub. The watchdog did exactly what it was
told: three failed ``/status`` probes, SIGKILL, restart, then ``rm -f "$STATE"``
which reset the strike counter. The hub wedged again within a minute, so this
repeated every ~3 minutes for over half an hour. Two things made the outage far
worse than the bug itself:

1. **No evidence survived.** Every SIGKILL destroyed the wedged process, and
   with it the only record of *where* it was stuck. Diagnosis eventually
   required hand-installing ``py-spy`` and racing to attach between restarts.

2. **No loop detection.** Because the strike file was deleted after each
   force-restart, the watchdog could not tell its 1st restart from its 12th. It
   kept SIGKILLing a hub that restarting was never going to fix, and each kill
   stampeded the entire spoke fleet into reconnecting at once.

So the watchdog now (a) captures a full wedge report — including Python stacks
via ``SIGUSR1``/faulthandler, which works *even while deadlocked* because the
handler runs at the C level and needs no GIL — **before** the kill, and (b)
counts consecutive force-restarts, backing off on an escalating ladder and
dropping an operator-visible marker once it is clear restarting is not healing
anything.

These tests EXECUTE the generated shell (with systemd/curl stubbed) rather than
grepping it, so they pin real behaviour. The watchdog body is dual-copied into
``install_all.sh``; the parity test below runs everything against BOTH copies so
a fix cannot land in one and miss the other.
"""
import os
import re
import subprocess

import pytest

HERE = os.path.dirname(__file__)
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
SCRIPT = os.path.join(ROOT, "scripts", "install-lm-watchdog.sh")
INSTALLER = os.path.join(ROOT, "install_all.sh")

MARKER = "cat > /usr/local/bin/lm-watchdog <<'WD'\n"


def _body(path):
    """The exact text written to /usr/local/bin/lm-watchdog by ``path``."""
    with open(path) as fh:
        src = fh.read()
    assert MARKER in src, f"lm-watchdog heredoc not found in {path} (restructured?)"
    tail = src.split(MARKER, 1)[1]
    return tail[: tail.index("\nWD\n")]


def _func(text, name):
    m = re.search(rf"^{re.escape(name)}\(\)\{{\n(.*?)^\}}$", text, re.S | re.M)
    return m.group(1) if m else None


def _liveness(text):
    """The `if systemctl is-enabled ... esac / fi` hub-liveness block."""
    start = text.index("if systemctl is-enabled --quiet lm.service")
    end = text.index("\n  esac\nfi\n", start) + len("\n  esac\nfi\n")
    return text[start:end]


def _active_branch(text):
    """Just the `active)` arm — the wedge-handling logic these tests cover.

    Deliberately narrower than the whole liveness block: the sibling `failed)`
    arm carries pre-existing comment-only drift between the two copies, which
    is out of scope here and must not fail this test.
    """
    blk = _liveness(text)
    return blk[blk.index("    active)"): blk.index("    failed)")]


BODIES = {"install-lm-watchdog.sh": _body(SCRIPT), "install_all.sh": _body(INSTALLER)}
EVERY_COPY = pytest.mark.parametrize("copy_name", sorted(BODIES))


# ── the generated script must at least be valid shell ────────────────────────

@EVERY_COPY
def test_generated_watchdog_is_valid_shell(copy_name, tmp_path):
    p = tmp_path / "wd"
    p.write_text(BODIES[copy_name])
    r = subprocess.run(["bash", "-n", str(p)], capture_output=True, text=True)
    assert r.returncode == 0, f"{copy_name}: {r.stderr}"


# ── dual copy: install_all.sh embeds the same watchdog ───────────────────────

def test_wedge_healing_is_identical_in_both_copies():
    """``install_all.sh`` carries its own copy of the watchdog body.

    Historically these drifted, which half-ships a fix: hubs built by the
    installer keep the old behaviour. Pin the new logic byte-for-byte.
    """
    a, b = BODIES["install-lm-watchdog.sh"], BODIES["install_all.sh"]
    for name in ("restart_backoff", "capture_wedge_diag"):
        fa, fb = _func(a, name), _func(b, name)
        assert fa, f"{name}() missing from install-lm-watchdog.sh"
        assert fb, f"{name}() missing from install_all.sh"
        assert fa == fb, f"{name}() has drifted between the two watchdog copies"
    assert _active_branch(a) == _active_branch(b), "wedge-handling logic drifted between copies"


# ── the backoff ladder ───────────────────────────────────────────────────────

@EVERY_COPY
def test_restart_backoff_ladder_escalates_then_caps(copy_name, tmp_path):
    """First two restarts are immediate; then escalate, capped at 15 min.

    Immediate retries still handle the common transient wedge. The cap is
    deliberate too: a hub that IS recoverable must not be parked for an hour.
    """
    fn = _func(BODIES[copy_name], "restart_backoff")
    script = tmp_path / "s.sh"
    script.write_text(
        "restart_backoff(){\n%s}\nfor n in 0 1 2 3 4 9; do restart_backoff $n; done\n" % fn
    )
    out = subprocess.run(["bash", str(script)], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert out.stdout.split() == ["0", "0", "300", "600", "900", "900"], out.stdout


# ── behaviour: the liveness block, actually executed ─────────────────────────

def _harness(copy_name, tmp_path, restarts=None, healthy=False, wedge_age=0):
    """Run the real hub-liveness block with systemd/curl/diagnostics stubbed.

    Returns (log_text, dict_of_state_files).
    """
    body = BODIES[copy_name]
    var = tmp_path / "var"
    var.mkdir()
    state = var / "watchdog-fails"
    rfile = var / "watchdog-restarts"
    marker = var / "hub-wedge-loop"
    killed = var / "killed"
    diag = var / "diag-captured"

    if restarts is not None:
        n, age = restarts
        rfile.write_text("%d %d" % (n, int(__import__("time").time()) - age))

    helpers = _func(body, "restart_backoff")
    pre = f"""
set -uo pipefail
restart_backoff(){{
{helpers}}}
LOG={var}/log
STATE={state}
RESTARTS={rfile}
LOOP_MARKER={marker}
WEDGE_DIR={var}
MAX_FAILS=3
HEAL_GRACE=900
log(){{ printf '%s\\n' "$*" >> "$LOG"; }}
hub_healthy(){{ return {0 if healthy else 1}; }}
record_last_good(){{ :; }}
rollback_if_bad(){{ :; }}
capture_wedge_diag(){{ echo x >> {diag}; }}
sleep(){{ :; }}
timeout(){{ shift; "$@"; }}
systemctl(){{
  case "$1 $2" in
    "is-enabled --quiet") return 0 ;;
    "is-active lm.service") echo active ;;
    "kill -s") echo kill >> {killed} ;;
    *) : ;;
  esac
}}
"""
    # A hub that never wedged writes no strike file; one mid-incident has struck out.
    if not healthy:
        state.write_text("2")
    script = tmp_path / "run.sh"
    script.write_text(pre + _liveness(body))
    r = subprocess.run(["bash", str(script)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return (
        (var / "log").read_text() if (var / "log").exists() else "",
        {
            "restarts": rfile.read_text() if rfile.exists() else None,
            "marker": marker.exists(),
            "killed": killed.exists(),
            "diag": diag.exists(),
            "state": state.exists(),
        },
    )


@EVERY_COPY
def test_diagnostics_captured_before_the_kill(copy_name, tmp_path):
    """The wedge report must be taken while the wedged process still exists.

    This is the whole point: SIGKILL destroys the only copy of the stack that
    explains the wedge. Capturing after the restart samples a healthy process
    and tells you nothing.
    """
    body = BODIES[copy_name]
    blk = _liveness(body)
    i_diag = blk.index("capture_wedge_diag")
    i_kill = blk.index("systemctl kill -s KILL")
    assert i_diag < i_kill, "capture_wedge_diag must run BEFORE the SIGKILL"

    log, st = _harness(copy_name, tmp_path)
    assert st["diag"], "no diagnostics captured on force-restart"
    assert st["killed"], "hub was not force-restarted on the first wedge"


@EVERY_COPY
def test_first_wedge_restarts_and_records_the_attempt(copy_name, tmp_path):
    log, st = _harness(copy_name, tmp_path)
    assert st["killed"]
    assert st["restarts"] and st["restarts"].split()[0] == "1", st["restarts"]
    assert not st["marker"], "loop marker raised on the very first restart"
    assert "force-restart #1" in log, log


@EVERY_COPY
def test_repeat_wedge_backs_off_instead_of_hammering(copy_name, tmp_path):
    """Two restarts already tried, seconds ago ⇒ do NOT kill again.

    The regression this pins: the old code reset the strike file after every
    force-restart, so it re-struck and re-killed every ~3 minutes forever.
    """
    log, st = _harness(copy_name, tmp_path, restarts=(2, 10))
    assert not st["killed"], "watchdog SIGKILLed again while inside its backoff window"
    assert not st["diag"], "wasted a diagnostic capture during backoff"
    assert st["restarts"].split()[0] == "2", "restart count changed without a restart"
    assert "backing off" in log, log
    assert st["state"], "strike counter cleared during backoff (would re-arm the hammer)"


@EVERY_COPY
def test_backoff_expiry_allows_another_restart(copy_name, tmp_path):
    """Backing off is not giving up — once the window passes, try again."""
    log, st = _harness(copy_name, tmp_path, restarts=(2, 400))  # ladder for n=2 is 300s
    assert st["killed"], "watchdog never retried after its backoff window expired"
    assert st["restarts"].split()[0] == "3"


@EVERY_COPY
def test_persistent_loop_raises_operator_marker(copy_name, tmp_path):
    """After 3 consecutive wedges, say so loudly — this needs a human."""
    log, st = _harness(copy_name, tmp_path, restarts=(2, 400))
    assert st["marker"], "no operator-visible marker after a persistent wedge loop"
    assert "RESTART LOOP" in log, log


@EVERY_COPY
def test_loop_state_survives_a_single_good_probe(copy_name, tmp_path):
    """A wedging hub answers /status briefly after each restart.

    Clearing the ladder on that one good probe would rearm the hammer, which is
    precisely the loop we are trying to break — so require a sustained
    healthy run (HEAL_GRACE) before forgetting.
    """
    log, st = _harness(copy_name, tmp_path, restarts=(3, 5), healthy=True)
    assert st["restarts"] is not None, "restart ladder cleared after one healthy probe"
    assert not_cleared(log)


def not_cleared(log):
    return "wedge loop cleared" not in log


@EVERY_COPY
def test_sustained_health_clears_the_loop_state(copy_name, tmp_path):
    """...but a hub that has genuinely recovered must not stay flagged."""
    log, st = _harness(copy_name, tmp_path, restarts=(3, 5000), healthy=True)
    assert st["restarts"] is None, "restart ladder never cleared after sustained health"
    assert not st["marker"], "operator marker left behind after recovery"
    assert "wedge loop cleared" in log, log


# ── the hub half: SIGUSR1 must actually dump stacks ──────────────────────────

def test_hub_registers_sigusr1_stack_dump():
    """``capture_wedge_diag`` sends SIGUSR1; main.py must answer it.

    faulthandler is used specifically because it dumps from a C-level signal
    handler and does not need the GIL — so it still reports when the event loop
    is deadlocked, which is the only moment this matters.
    """
    src = open(os.path.join(ROOT, "core", "src", "main.py")).read()
    assert "faulthandler" in src, "main.py installs no faulthandler"
    assert "SIGUSR1" in src, "main.py does not register a SIGUSR1 stack dump"
    assert "all_threads=True" in src, "stack dump must cover every thread"
    assert "wedge-stacks.log" in src, "stack dump has no agreed-on destination"
    # The watchdog reads back exactly that file.
    for name, body in BODIES.items():
        fn = _func(body, "capture_wedge_diag")
        assert "kill -USR1" in fn, f"{name}: capture_wedge_diag never signals the hub"
        assert "wedge-stacks.log" in fn, f"{name}: does not collect the stack dump"


def test_sigusr1_dump_is_wired_into_startup():
    """Registered on the real startup path, not just defined."""
    import ast

    path = os.path.join(ROOT, "core", "src", "main.py")
    tree = ast.parse(open(path).read())
    fns = [n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]
    assert "_enable_wedge_stack_dumps" in fns
    src = open(path).read()
    main_block = src[src.rindex('if __name__ == "__main__":'):]
    assert "_enable_wedge_stack_dumps()" in main_block, "handler defined but never installed"
    assert main_block.index("_enable_wedge_stack_dumps()") < main_block.index(
        "asyncio.run"
    ), "stack dump must be armed before the loop starts"


def test_stack_dump_never_blocks_startup():
    """Diagnostics are best-effort — a hub that cannot open the log still boots."""
    import ast

    path = os.path.join(ROOT, "core", "src", "main.py")
    tree = ast.parse(open(path).read())
    fn = next(
        n for n in ast.walk(tree)
        if isinstance(n, ast.FunctionDef) and n.name == "_enable_wedge_stack_dumps"
    )
    handlers = [n for n in ast.walk(fn) if isinstance(n, ast.Try)]
    assert handlers, "_enable_wedge_stack_dumps must not be able to raise"
