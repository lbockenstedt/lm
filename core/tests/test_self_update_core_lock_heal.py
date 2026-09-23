"""Post-failure git-lock heal must cover the shared core checkout too.

WHY (ab#139): step 0 of ``_perform_self_update_sync`` pulls the shared
``/opt/lm`` core checkout BEFORE the component's own repo. So when a git
command fails on a leftover ``*.lock``, the command that failed may well have
been a core one. The post-failure heal cleared only ``cwd``:

    n = self._clear_stale_git_locks(cwd, max_age_s=0.0)

which left ``/opt/lm/.git`` wedged. The only thing that eventually freed it was
the pre-pull sweep at the top of step 0 -- and that uses the default 90s age
guard AND only runs once the host-wide core lock is acquired, so the core repo
stayed stuck for at least a further cycle.

The trap, and the reason this is not a one-word change: ``core_root`` cannot be
used in the handler. It is reset to ``None`` on three separate paths -- core
already converged by a sibling, all-in-one layout where core_root == cwd, and
core pull failed -- so by the time the exception handler runs it no longer
names the checkout whose lock is wedged. A fix that reads ``core_root`` there
would look right and silently heal nothing in exactly the cases that matter.
Hence the separate ``core_heal_root``, captured in the one branch that actually
runs git against core.

That capture point is also what keeps an age-0 force-clear of core's lock safe:
it happens inside ``_core_update_lock_safe()``, so no sibling component on the
host can be mid-pull holding a legitimately fresh lock.
"""
import ast
import os
import sys
import time

_LM_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _LM_ROOT not in sys.path:
    sys.path.insert(0, _LM_ROOT)

from messaging.self_update import SelfUpdateMixin  # noqa: E402

_SRC = os.path.join(_LM_ROOT, "src", "messaging", "self_update.py")
if not os.path.exists(_SRC):
    _SRC = os.path.join(os.path.dirname(__file__), "..", "src", "messaging", "self_update.py")
_SRC = os.path.abspath(_SRC)

_LOCK_MARKERS = ("unable to create", ".lock': file exists", "cannot lock ref",
                 "another git process seems to be running", "index.lock")


class _Repo(SelfUpdateMixin):
    """Minimal consumer: the mixin's _clear_stale_git_locks only needs a path."""

    def __init__(self, root):
        self._root = root

    def _repo_root(self):
        return self._root


def _method_src():
    tree = ast.parse(open(_SRC).read())
    return next(ast.get_source_segment(open(_SRC).read(), n)
                for n in ast.walk(tree)
                if isinstance(n, ast.FunctionDef) and n.name == "_perform_self_update_sync")


def _heal_fragment():
    """The real `if any(s in _dl ...)` heal block, lifted from the shipped source.

    Executing the actual code (rather than restating it) is the point: a test
    that re-implements the heal would keep passing if the heal were deleted.
    """
    src = open(_SRC).read()
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue
        seg = ast.get_source_segment(src, node) or ""
        if seg.startswith("if any(s in _dl") and "_clear_stale_git_locks" in seg:
            return seg
    raise AssertionError("post-failure lock-heal block not found in self_update.py")


def _make_repo_with_fresh_lock(root):
    git_dir = os.path.join(root, ".git")
    os.makedirs(git_dir, exist_ok=True)
    lock = os.path.join(git_dir, "index.lock")
    with open(lock, "w") as fh:
        fh.write("")
    os.utime(lock, (time.time(), time.time()))  # deliberately FRESH
    return lock


class _Recorder:
    def __init__(self):
        self.warnings = []

    def warning(self, fmt, *args):
        self.warnings.append(fmt % args if args else fmt)

    def __getattr__(self, _):
        return lambda *a, **k: None


def _run_heal(cwd, core_heal_root, detail="cannot lock ref 'HEAD'"):
    log = _Recorder()
    ns = {"self": _Repo(cwd), "cwd": cwd, "core_heal_root": core_heal_root,
          "_dl": detail.lower(), "logger": log}
    exec(compile(ast.parse(_heal_fragment()), "<heal>", "exec"), ns)
    return log


# ── the actual defect ────────────────────────────────────────────────────────

def test_core_checkout_lock_is_cleared_too(tmp_path):
    """The regression in ab#139: a wedged /opt/lm/.git survived the heal."""
    cwd = str(tmp_path / "component")
    core = str(tmp_path / "opt-lm")
    own_lock = _make_repo_with_fresh_lock(cwd)
    core_lock = _make_repo_with_fresh_lock(core)

    _run_heal(cwd, core)

    assert not os.path.exists(own_lock), "component repo lock should be cleared"
    assert not os.path.exists(core_lock), "shared core repo lock should be cleared"


def test_core_lock_survives_when_core_was_never_touched(tmp_path):
    """core_heal_root is None when this cycle never ran git against core, and a
    lock we did not cause must not be force-removed at age 0 — another process
    may legitimately own it."""
    cwd = str(tmp_path / "component")
    core = str(tmp_path / "opt-lm")
    own_lock = _make_repo_with_fresh_lock(cwd)
    core_lock = _make_repo_with_fresh_lock(core)

    _run_heal(cwd, None)

    assert not os.path.exists(own_lock)
    assert os.path.exists(core_lock), "untouched core repo must be left alone"


def test_all_in_one_layout_heals_once(tmp_path):
    """core_root == cwd on an all-in-one install; it must not be healed twice."""
    cwd = str(tmp_path / "solo")
    lock = _make_repo_with_fresh_lock(cwd)

    log = _run_heal(cwd, cwd)

    assert not os.path.exists(lock)
    assert len(log.warnings) == 1, log.warnings


def test_failure_healing_one_repo_still_heals_the_other(tmp_path):
    """Per-root try/except: core must still be healed when cwd blows up.

    A single try around the whole loop would abort on the first failure, so the
    repo that actually holds the wedged lock could go unhealed.
    """
    cwd = str(tmp_path / "component")
    core = str(tmp_path / "opt-lm")
    core_lock = _make_repo_with_fresh_lock(core)

    class _Boom(_Repo):
        def _clear_stale_git_locks(self, root, max_age_s=90.0):
            if root == cwd:
                raise RuntimeError("permission denied")
            return super()._clear_stale_git_locks(root, max_age_s=max_age_s)

    log = _Recorder()
    ns = {"self": _Boom(cwd), "cwd": cwd, "core_heal_root": core,
          "_dl": "another git process seems to be running", "logger": log}
    exec(compile(ast.parse(_heal_fragment()), "<heal>", "exec"), ns)

    assert not os.path.exists(core_lock), "core must be healed despite cwd failing"


def test_heal_is_silent_when_nothing_was_locked(tmp_path):
    """n == 0 must not log — otherwise every lock failure prints a line about
    the repo that was fine."""
    cwd = str(tmp_path / "component")
    core = str(tmp_path / "opt-lm")
    os.makedirs(os.path.join(cwd, ".git"))
    _make_repo_with_fresh_lock(core)

    log = _run_heal(cwd, core)

    assert len(log.warnings) == 1, log.warnings
    assert core in log.warnings[0]
    assert cwd not in log.warnings[0]


def test_non_lock_failure_heals_nothing(tmp_path):
    """A DNS or auth failure must not trigger a force-clear."""
    cwd = str(tmp_path / "component")
    core = str(tmp_path / "opt-lm")
    own_lock = _make_repo_with_fresh_lock(cwd)
    core_lock = _make_repo_with_fresh_lock(core)

    _run_heal(cwd, core, detail="could not resolve host github.com")

    assert os.path.exists(own_lock)
    assert os.path.exists(core_lock)


def test_every_lock_marker_still_triggers_the_heal():
    """The condition must keep matching all five git lock phrasings."""
    frag = _heal_fragment()
    for marker in _LOCK_MARKERS:
        assert repr(marker)[1:-1] in frag or marker in frag, marker


# ── the scoping trap ─────────────────────────────────────────────────────────

def test_core_heal_root_is_initialised_before_the_git_work():
    """It must be bound before anything can raise, or the handler that is meant
    to stop an error raises NameError instead."""
    body = _method_src()
    assert "core_heal_root = None" in body
    assert body.index("core_heal_root = None") < body.index("core_heal_root = core_root")


def test_handler_does_not_read_core_root():
    """core_root is reset to None on the converged / all-in-one / pull-failed
    paths, so reading it in the handler would heal nothing precisely when core
    IS the wedged repo. Pin that the heal uses core_heal_root instead."""
    frag = _heal_fragment()
    assert "core_heal_root" in frag
    assert "core_root" not in frag.replace("core_heal_root", "")


def test_capture_happens_inside_the_core_lock():
    """An age-0 force-clear of core's lock is only safe because the capture
    happens while the host-wide core lock is held — otherwise a sibling
    component's in-flight pull could have its legitimate lock deleted."""
    body = _method_src()
    assert "core_heal_root = core_root" in body
    lock_at = body.index("_core_update_lock_safe()")
    capture_at = body.index("core_heal_root = core_root")
    clear_at = body.index("self._clear_stale_git_locks(core_root)")
    assert lock_at < capture_at < clear_at
