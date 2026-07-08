"""lm/core propagation via SPOKE_UPDATE — ``BaseControlPlane``.

Pins the dual-repo update contract: a hub-driven ``SPOKE_UPDATE`` now pulls the
spoke's OWN repo AND the shared ``/opt/lm`` core checkout (the real lm.git
checkout the spoke imports ``core.src.*`` from at runtime) so lm/core changes
reach remote spokes via the WebUI Update button / auto-update — no CLI. A
restart fires if EITHER repo advanced (so a core-only change reloads the spoke).
The watchdog rolls BOTH repos back on boot failure; a known-bad core commit is
skipped (reset back) instead of crash-looping.

Uses a fake git keyed by cwd (each repo gets its own head_before/head_after),
a tmp state dir, a fake ``os._exit`` (raises), and a monkeypatched
``_resolve_core_root`` so no real ``/opt/lm`` is needed.
"""

import contextlib
import os
import sys

import pytest

# conftest puts core/src on sys.path (update_recovery). control_plane resolves
# only as core.src.messaging.control_plane, so also put the lm repo root on
# sys.path for that module.
_LM_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _LM_ROOT not in sys.path:
    sys.path.insert(0, _LM_ROOT)

import update_recovery  # noqa: E402
from core.src.messaging import control_plane as cp  # noqa: E402


# ── fakes ───────────────────────────────────────────────────────────────────

class _FakeCompleted:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class _FakeGit:
    """Canned git runner keyed by ``cwd``. Each repo is configured with a
    (before, after) HEAD pair; ``rev-parse HEAD`` returns before on the first
    call for that cwd and after on every subsequent call. Records reset/fetch/
    pull invocations per cwd so the core vs spoke paths are distinguishable."""

    def __init__(self, repos):
        # repos: {cwd: {"before": str, "after": str, "pull_rc": int=0,
        #               "fetch_rc": int=0}}
        self.repos = repos
        self.rev_parse_calls = {cwd: 0 for cwd in repos}
        self.reset_calls = []          # list of (cwd, args)
        self.fetch_called = []         # list of cwd
        self.pull_called = []          # list of cwd
        self.calls = []                # list of (cwd, args)

    def run(self, cmd, *a, **k):
        args = cmd[1:] if cmd and cmd[0] == "git" else cmd
        cwd = k.get("cwd")
        if cwd is None and len(a) >= 2:
            cwd = a[1]
        self.calls.append((cwd, args))
        repo = self.repos.get(cwd)
        if repo is None:
            # Unknown cwd (e.g. an unconfigured repo) → benign ok.
            return _FakeCompleted(0)
        if args[:2] == ["rev-parse", "HEAD"]:
            self.rev_parse_calls[cwd] = self.rev_parse_calls.get(cwd, 0) + 1
            head = repo["before"] if self.rev_parse_calls[cwd] == 1 else repo["after"]
            return _FakeCompleted(0, stdout=head + "\n")
        if args[:2] == ["rev-parse", "--abbrev-ref"]:
            return _FakeCompleted(0, stdout="main\n")
        if args[:1] == ["fetch"]:
            self.fetch_called.append(cwd)
            return _FakeCompleted(repo.get("fetch_rc", 0))
        if args[:1] == ["pull"]:
            self.pull_called.append(cwd)
            return _FakeCompleted(repo.get("pull_rc", 0))
        if args[:1] == ["reset"]:
            self.reset_calls.append((cwd, args[1:]))
            return _FakeCompleted(0)
        # remote set-url / config / rebase --abort → ok
        return _FakeCompleted(0)


class _FakePopen:
    def __init__(self):
        self.calls = []
    def __call__(self, cmd, *a, **k):
        self.calls.append(list(cmd))
        return self
    def wait(self, *a, **k):
        return 0


class _Exited(BaseException):
    """Fake os._exit (inherits BaseException so broad ``except Exception``
    can't swallow it — the real os._exit never returns)."""
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def _fake_exit(code):
    raise _Exited(code)


class _TestSpoke(cp.BaseControlPlane):
    """Minimal spoke for core-propagation tests — tmp state dir, no .env I/O."""
    def __init__(self, spoke_id, state_dir, cwd):
        self._test_state_dir = state_dir
        self._test_cwd = cwd
        self.spoke_id = spoke_id
        self.secret = "x"
        self.hub_secrets = []
        self.hub_url = "ws://h"
        self.onboarding_psk = ""
        self.tenant_id_hint = ""
        self.modules = {}
        self.signer = None
        self.module_type = "test"
        self._updater_stop = None
        self._updater_thread = None
        self._log_relay_queue = None
        self._log_relay_handler = None
        self._hub_ws = None
        self._loop = None
        self._hub_secret_warned = False
        self.hostname = "testhost"
        self.install_uuid = "uuid-test"

    def _spoke_state_dir(self):
        return self._test_state_dir
    def _repo_root(self):
        return self._test_cwd
    def get_service_name(self):
        return "lm-test"
    def _flush_log_relay_sync(self):
        pass
    async def _flush_log_relay_async(self):
        pass


@pytest.fixture
def spoke(tmp_path):
    cwd = str(tmp_path / "spoke-repo")
    os.makedirs(cwd, exist_ok=True)
    return _TestSpoke("test-spoke-1", str(tmp_path / "state"), cwd)


@contextlib.contextmanager
def _fake_lock():
    yield True


def _patch_runner(monkeypatch, fake_git, spoke, core_root=None):
    monkeypatch.setattr(cp.subprocess, "run", fake_git.run)
    monkeypatch.setattr(cp.subprocess, "Popen", _FakePopen())
    monkeypatch.setattr("os._exit", _fake_exit)
    monkeypatch.setattr(spoke, "_core_update_lock", _fake_lock)
    # _perform_spoke_update_sync derives the spoke-repo cwd from os.getcwd(); make
    # it match the fake-git key so the spoke pull hits the canned repo.
    monkeypatch.setattr(cp.os, "getcwd", lambda: spoke._test_cwd)
    if core_root is None:
        monkeypatch.setattr(spoke, "_resolve_core_root", lambda: None)
    else:
        monkeypatch.setattr(spoke, "_resolve_core_root", lambda: core_root)
    fake_snapshot_calls = []
    def _fake_snapshot_code(hub_root, ts, tree_list=None, state_dir=None):
        bd = os.path.join(state_dir, "update-backup", ts)
        os.makedirs(bd, exist_ok=True)
        return bd
    monkeypatch.setattr(update_recovery, "snapshot_code", _fake_snapshot_code)
    return fake_snapshot_calls


# ── (a) core pull happens + watchdog gets core_repo ──────────────────────────

@pytest.mark.asyncio
async def test_core_pull_happens_and_watchdog_gets_core_repo(spoke, tmp_path, monkeypatch):
    core_root = str(tmp_path / "opt-lm")
    os.makedirs(core_root, exist_ok=True)
    cwd = spoke._test_cwd
    fake_git = _FakeGit({
        core_root: {"before": "core_aaa", "after": "core_bbb"},
        cwd: {"before": "spoke_aaa", "after": "spoke_bbb"},
    })
    _patch_runner(monkeypatch, fake_git, spoke, core_root=core_root)
    fake_popen = cp.subprocess.Popen

    with pytest.raises(_Exited) as ei:
        await spoke.handle_system_command("SPOKE_UPDATE", {
            "repo_url": "https://example/spoke.git",
            "core_repo_url": "https://example/lm.git",
            "core_branch": "main",
        })
    assert ei.value.code == 3

    # core repo was fetched + pulled (set-url/config/fetch/pull on core_root).
    assert core_root in fake_git.fetch_called
    assert core_root in fake_git.pull_called
    # spoke repo was fetched + pulled too.
    assert cwd in fake_git.fetch_called
    assert cwd in fake_git.pull_called
    # manifest carries BOTH repos' commits.
    pending = update_recovery.read_pending(state_dir=spoke._spoke_state_dir())
    assert pending is not None
    assert pending["from_commit"] == "spoke_aaa"
    assert pending["to_commit"] == "spoke_bbb"
    assert pending["core_from_commit"] == "core_aaa"
    assert pending["core_to_commit"] == "core_bbb"
    assert pending["core_root"] == core_root
    # watchdog scheduled with --core-repo-root.
    assert len(fake_popen.calls) == 1
    cmd = fake_popen.calls[0]
    assert "--core-repo-root" in cmd
    assert core_root in cmd


# ── (b) graceful skip when _resolve_core_root → None ─────────────────────────

@pytest.mark.asyncio
async def test_no_core_root_skips_core_gracefully(spoke, tmp_path, monkeypatch):
    cwd = spoke._test_cwd
    fake_git = _FakeGit({cwd: {"before": "spoke_aaa", "after": "spoke_bbb"}})
    _patch_runner(monkeypatch, fake_git, spoke, core_root=None)
    fake_popen = cp.subprocess.Popen

    with pytest.raises(_Exited):
        await spoke.handle_system_command("SPOKE_UPDATE", {
            "repo_url": "https://example/spoke.git",
            "core_repo_url": "https://example/lm.git",
        })
    # No core fetch/pull (only the spoke repo was touched). The spoke-only repos
    # list is exactly {cwd}; core_root was None so no other cwd appears.
    assert fake_git.fetch_called == [cwd]
    assert fake_git.pull_called == [cwd]
    # manifest has NO core fields (single-repo behavior).
    pending = update_recovery.read_pending(state_dir=spoke._spoke_state_dir())
    assert pending is not None
    assert "core_root" not in pending
    assert "core_from_commit" not in pending
    # watchdog has no --core-repo-root.
    cmd = fake_popen.calls[0]
    assert "--core-repo-root" not in cmd


# ── (c) restart fires on core-only change (spoke unchanged) ──────────────────

@pytest.mark.asyncio
async def test_core_only_change_restarts(spoke, tmp_path, monkeypatch):
    core_root = str(tmp_path / "opt-lm")
    os.makedirs(core_root, exist_ok=True)
    cwd = spoke._test_cwd
    fake_git = _FakeGit({
        core_root: {"before": "core_aaa", "after": "core_bbb"},  # core moved
        cwd: {"before": "spoke_aaa", "after": "spoke_aaa"},       # spoke unchanged
    })
    _patch_runner(monkeypatch, fake_git, spoke, core_root=core_root)
    fake_popen = cp.subprocess.Popen

    with pytest.raises(_Exited) as ei:
        await spoke.handle_system_command("SPOKE_UPDATE", {
            "repo_url": "https://example/spoke.git",
            "core_repo_url": "https://example/lm.git",
            "core_branch": "main",
        })
    assert ei.value.code == 3  # restart fired even though only core advanced
    pending = update_recovery.read_pending(state_dir=spoke._spoke_state_dir())
    assert pending is not None
    # Spoke unchanged → from==to; core moved → recorded.
    assert pending["core_from_commit"] == "core_aaa"
    assert pending["core_to_commit"] == "core_bbb"
    assert "--core-repo-root" in fake_popen.calls[0]


# ── (d) pending_update.json carries core fields ──────────────────────────────
# (covered structurally by test (a); this asserts the exact schema keys the
# watchdog `jq`s, independent of the run path.)

@pytest.mark.asyncio
async def test_manifest_core_schema_matches_watchdog(spoke, tmp_path, monkeypatch):
    core_root = str(tmp_path / "opt-lm")
    os.makedirs(core_root, exist_ok=True)
    cwd = spoke._test_cwd
    fake_git = _FakeGit({
        core_root: {"before": "core_aaa", "after": "core_bbb"},
        cwd: {"before": "spoke_aaa", "after": "spoke_bbb"},
    })
    _patch_runner(monkeypatch, fake_git, spoke, core_root=core_root)

    with pytest.raises(_Exited):
        await spoke.handle_system_command("SPOKE_UPDATE", {
            "repo_url": "https://example/spoke.git",
            "core_repo_url": "https://example/lm.git",
            "core_branch": "main",
        })
    pending = update_recovery.read_pending(state_dir=spoke._spoke_state_dir())
    # The watchdog reads these exact keys via jq (".core_from_commit // empty"
    # etc.). Pin them so a rename here can't silently break rollback.
    for key in ("core_root", "core_from_commit", "core_to_commit",
                "from_commit", "to_commit", "service_unit", "deadline"):
        assert key in pending, f"missing manifest key: {key}"


# ── (e) known-bad core commit → reset back, no restart solely from core ───────

@pytest.mark.asyncio
async def test_known_bad_core_commit_resets_and_skips(spoke, tmp_path, monkeypatch):
    core_root = str(tmp_path / "opt-lm")
    os.makedirs(core_root, exist_ok=True)
    cwd = spoke._test_cwd
    fake_git = _FakeGit({
        core_root: {"before": "core_aaa", "after": "core_bad"},
        cwd: {"before": "spoke_aaa", "after": "spoke_aaa"},  # spoke unchanged
    })
    _patch_runner(monkeypatch, fake_git, spoke, core_root=core_root)
    # Pre-mark the post-pull core commit bad.
    update_recovery.add_bad_commit("core_bad", state_dir=spoke._spoke_state_dir())
    fake_popen = cp.subprocess.Popen

    result = await spoke.handle_system_command("SPOKE_UPDATE", {
        "repo_url": "https://example/spoke.git",
        "core_repo_url": "https://example/lm.git",
        "core_branch": "main",
    })
    # Core was bad AND spoke unchanged → no restart.
    assert result["status"] == "SUCCESS"
    assert "Already up to date" in result["message"]
    # Core reset back to its pre-pull HEAD.
    assert any(cwd_ == core_root and r == ["--hard", "core_aaa"]
               for cwd_, r in fake_git.reset_calls)
    # No watchdog scheduled (no restart).
    assert fake_popen.calls == []
    pending = update_recovery.read_pending(state_dir=spoke._spoke_state_dir())
    assert pending is None


# ── core_root == cwd (agent all-in-one) → skip duplicate core fetch ──────────

@pytest.mark.asyncio
async def test_core_root_equals_cwd_skips_duplicate(spoke, tmp_path, monkeypatch):
    cwd = spoke._test_cwd
    # _resolve_core_root returns the SAME dir as the spoke's own repo → the
    # spoke-repo pull already covers /opt/lm; no separate core fetch.
    fake_git = _FakeGit({cwd: {"before": "spoke_aaa", "after": "spoke_bbb"}})
    _patch_runner(monkeypatch, fake_git, spoke, core_root=cwd)
    fake_popen = cp.subprocess.Popen

    with pytest.raises(_Exited):
        await spoke.handle_system_command("SPOKE_UPDATE", {
            "repo_url": "https://example/lm.git",
            "core_repo_url": "https://example/lm.git",
            "core_branch": "main",
        })
    # Only one repo (cwd) was fetched/pulled — no duplicate.
    assert fake_git.fetch_called == [cwd]
    assert fake_git.pull_called == [cwd]
    # No core fields in manifest (the core path was skipped).
    pending = update_recovery.read_pending(state_dir=spoke._spoke_state_dir())
    assert "core_root" not in pending
    assert "--core-repo-root" not in fake_popen.calls[0]


# ── no core_repo_url in payload → core skipped entirely (backward compat) ───

@pytest.mark.asyncio
async def test_no_core_repo_url_skips_core(spoke, tmp_path, monkeypatch):
    cwd = spoke._test_cwd
    fake_git = _FakeGit({cwd: {"before": "spoke_aaa", "after": "spoke_bbb"}})
    # Even if a core root existed, absence of core_repo_url means no core pull.
    core_root = str(tmp_path / "opt-lm")
    os.makedirs(core_root, exist_ok=True)
    _patch_runner(monkeypatch, fake_git, spoke, core_root=core_root)
    fake_popen = cp.subprocess.Popen

    with pytest.raises(_Exited):
        await spoke.handle_system_command("SPOKE_UPDATE", {
            "repo_url": "https://example/spoke.git",
        })
    # Only the spoke repo touched.
    assert fake_git.fetch_called == [cwd]
    assert core_root not in fake_git.fetch_called
    pending = update_recovery.read_pending(state_dir=spoke._spoke_state_dir())
    assert "core_root" not in pending
    assert "--core-repo-root" not in fake_popen.calls[0]