"""A role-repo update reloads ONE role instead of restarting every role.

A role-hosting agent runs the base agent plus a ``RoleConnection`` per loaded
role in a single process (``mipbe-lmagent`` hosts 9). Both paths that reacted to
a role's repo advancing — the code-drift watchdog and the role's own
``SPOKE_UPDATE`` handler — called ``os._exit(3)``, so updating one role dropped
every other role on the box and they only came back after the whole boot
sequence re-ran.

Pins: the dir->role classification (and the cases that must stay a full
restart), the module purge that makes an in-place reload actually load NEW code,
the reload itself, and the fail-safe that still restarts when a targeted reload
cannot be completed.
"""
import asyncio
import os
import sys
import types

import pytest

import control_plane as cp_module


def _agent_cp(tmp_path, roles=(), repo=None, core=None):
    """An AgentControlPlane with only the attributes these methods touch —
    __init__ dials a hub and reads installer state."""
    cp = object.__new__(cp_module.AgentControlPlane)
    agent = types.SimpleNamespace(_roles={r: {} for r in roles})
    cp.modules = {"agent": agent}
    cp._lm_root = lambda: tmp_path
    cp._repo_root = lambda: str(repo or (tmp_path / "lm"))
    cp._resolve_core_root = lambda: str(core) if core else None
    return cp, agent


def _mkgit(p):
    p.mkdir(parents=True, exist_ok=True)
    (p / ".git").mkdir(exist_ok=True)
    return p


# ── classifying a drifted directory ─────────────────────────────────────────

def test_role_repo_is_classified_as_reloadable(tmp_path):
    """``dns`` maps to the ``dns/`` sibling clone, so drift there names the role."""
    _mkgit(tmp_path / "dns")
    cp, _ = _agent_cp(tmp_path, roles=("dns",))
    assert cp._drift_role_for_dir(str(tmp_path / "dns")) == "dns"


def test_core_and_own_repo_still_force_a_full_restart(tmp_path):
    """``/opt/lm`` and the agent's own checkout are imported by the running
    process — only a restart reloads them. This is the case that produced every
    observed drift exit on the live agent."""
    repo = _mkgit(tmp_path / "lm")
    core = _mkgit(tmp_path / "opt-lm")
    _mkgit(tmp_path / "dns")
    cp, _ = _agent_cp(tmp_path, roles=("dns",), repo=repo, core=core)
    assert cp._drift_role_for_dir(str(core)) is None
    assert cp._drift_role_for_dir(str(repo)) is None
    assert cp._drift_role_for_dir(str(tmp_path / "dns")) == "dns"


def test_a_role_clone_that_overlaps_core_still_forces_a_full_restart(
        tmp_path, monkeypatch):
    """The base-set exclusion is what makes the check above safe in the case
    that can actually bite: a role whose clone resolves to the SAME path as the
    shared core checkout. Reloading "just that role" there would leave the
    process running stale core code it had already imported."""
    core = _mkgit(tmp_path / "core")
    monkeypatch.setitem(cp_module._ROLE_MAP, "dns",
                        ("core/src/dns_spoke.py", "DNSSpoke", "dns", None))
    cp, _ = _agent_cp(tmp_path, roles=("dns",), core=core)
    # The role genuinely resolves to this directory...
    assert cp._role_repo_dirs()["dns"] == os.path.abspath(str(core))
    # ...but it is core, so it must NOT be treated as an in-place reload.
    assert cp._drift_role_for_dir(str(core)) is None


def test_a_role_clone_that_overlaps_the_agents_own_repo_forces_a_restart(
        tmp_path, monkeypatch):
    """Same guard, against the agent's own checkout."""
    repo = _mkgit(tmp_path / "selfrepo")
    monkeypatch.setitem(cp_module._ROLE_MAP, "dns",
                        ("selfrepo/src/dns_spoke.py", "DNSSpoke", "dns", None))
    cp, _ = _agent_cp(tmp_path, roles=("dns",), repo=repo)
    assert cp._role_repo_dirs()["dns"] == os.path.abspath(str(repo))
    assert cp._drift_role_for_dir(str(repo)) is None


def test_unloaded_role_dir_is_not_reloadable(tmp_path):
    """A directory belonging to no loaded role falls back to a restart."""
    _mkgit(tmp_path / "dns")
    cp, _ = _agent_cp(tmp_path, roles=())
    assert cp._drift_role_for_dir(str(tmp_path / "dns")) is None


def test_two_roles_sharing_one_repo_force_a_full_restart(tmp_path, monkeypatch):
    """Reloading one of two roles backed by the SAME repo would purge modules
    the other is still using — the safe answer is the historical restart."""
    _mkgit(tmp_path / "shared")
    monkeypatch.setitem(cp_module._ROLE_MAP, "dns",
                        ("shared/src/a.py", "A", "dns", None))
    monkeypatch.setitem(cp_module._ROLE_MAP, "dhcp",
                        ("shared/src/b.py", "B", "dhcp", None))
    cp, _ = _agent_cp(tmp_path, roles=("dns", "dhcp"))
    assert cp._drift_role_for_dir(str(tmp_path / "shared")) is None


def test_watched_dirs_still_include_loaded_role_repos(tmp_path):
    """The watch set must keep covering role repos, or nothing detects the drift
    in the first place."""
    repo = _mkgit(tmp_path / "lm")
    _mkgit(tmp_path / "dns")
    cp, _ = _agent_cp(tmp_path, roles=("dns",), repo=repo)
    watched = {os.path.abspath(d) for d in cp._drift_watched_dirs()}
    assert os.path.abspath(str(tmp_path / "dns")) in watched


# ── the module purge that makes a reload real ───────────────────────────────

def test_purge_drops_only_modules_from_that_repo(tmp_path):
    """``_load_role_class`` re-execs the role's ENTRY file, but its imported
    siblings stay cached — without the purge an in-place reload would splice new
    entry code onto stale submodules. Core and other roles must be untouched."""
    role_dir = tmp_path / "dns"
    role_dir.mkdir()
    other = tmp_path / "netbox"
    other.mkdir()

    stale = types.ModuleType("dns_helper")
    stale.__file__ = str(role_dir / "src" / "helper.py")
    keep = types.ModuleType("netbox_helper")
    keep.__file__ = str(other / "src" / "helper.py")
    nofile = types.ModuleType("builtin_like")  # no __file__ → must not explode
    sys.modules["dns_helper"] = stale
    sys.modules["netbox_helper"] = keep
    sys.modules["builtin_like"] = nofile
    try:
        cp, _ = _agent_cp(tmp_path)
        cp._purge_role_modules(str(role_dir))
        assert "dns_helper" not in sys.modules, "stale role submodule survived"
        assert "netbox_helper" in sys.modules, "purged another role's module"
        assert "builtin_like" in sys.modules
    finally:
        for name in ("dns_helper", "netbox_helper", "builtin_like"):
            sys.modules.pop(name, None)


# ── the reload itself ───────────────────────────────────────────────────────

class _Agent:
    def __init__(self, roles, load_status="SUCCESS"):
        self._roles = {r: {} for r in roles}
        self.stopped = []
        self.loaded = []
        self.load_status = load_status

    async def _stop_role(self, role):
        self.stopped.append(role)
        self._roles.pop(role, None)

    async def handle_command(self, cmd, data):
        self.loaded.append((cmd, data.get("role")))
        if self.load_status == "RAISE":
            raise RuntimeError("load blew up")
        if self.load_status == "SUCCESS":
            self._roles[data["role"]] = {}
        return {"status": self.load_status}


@pytest.mark.asyncio
async def test_reload_stops_purges_and_reloads_one_role(tmp_path):
    role_dir = _mkgit(tmp_path / "dns")
    cp, _ = _agent_cp(tmp_path, roles=("dns", "dhcp"))
    agent = _Agent(["dns", "dhcp"])
    cp.modules["agent"] = agent
    purged = []
    cp._purge_role_modules = purged.append

    assert await cp._reload_role_for_drift("dns", str(role_dir)) is True
    assert agent.stopped == ["dns"]
    assert agent.loaded == [("LOAD_ROLE", "dns")]
    assert purged == [str(role_dir)], "reload did not purge stale modules"
    assert "dhcp" in agent._roles, "an unrelated role was disturbed"


@pytest.mark.asyncio
async def test_reload_reports_failure_when_load_fails(tmp_path):
    """Returning False is what makes the watchdog fall back to a restart."""
    role_dir = _mkgit(tmp_path / "dns")
    cp, _ = _agent_cp(tmp_path, roles=("dns",))
    cp.modules["agent"] = _Agent(["dns"], load_status="ERROR")
    cp._purge_role_modules = lambda d: None
    assert await cp._reload_role_for_drift("dns", str(role_dir)) is False


@pytest.mark.asyncio
async def test_reload_reports_failure_when_load_raises(tmp_path):
    role_dir = _mkgit(tmp_path / "dns")
    cp, _ = _agent_cp(tmp_path, roles=("dns",))
    cp.modules["agent"] = _Agent(["dns"], load_status="RAISE")
    cp._purge_role_modules = lambda d: None
    assert await cp._reload_role_for_drift("dns", str(role_dir)) is False


@pytest.mark.asyncio
async def test_reload_of_an_unloaded_role_is_refused(tmp_path):
    role_dir = _mkgit(tmp_path / "dns")
    cp, _ = _agent_cp(tmp_path, roles=())
    cp.modules["agent"] = _Agent([])
    assert await cp._reload_role_for_drift("dns", str(role_dir)) is False


# ── deferred reload + fail-safe restart ─────────────────────────────────────

@pytest.mark.asyncio
async def test_scheduled_reload_does_not_exit_on_success(tmp_path, monkeypatch):
    exits = []
    monkeypatch.setattr(cp_module.os, "_exit", lambda c: exits.append(c))
    cp, _ = _agent_cp(tmp_path)

    async def _ok(role, d):
        return True

    cp._reload_role_for_drift = _ok
    cp._flush_log_relay_async = lambda *a, **k: asyncio.sleep(0)
    await cp._schedule_role_reload("dns", str(tmp_path), delay_s=0)
    assert exits == []


@pytest.mark.asyncio
async def test_scheduled_reload_falls_back_to_exit_on_failure(tmp_path, monkeypatch):
    """Fail-safe: freshly-pulled code must never keep running under the old
    class, so a failed targeted reload still restarts the process."""
    exits = []
    monkeypatch.setattr(cp_module.os, "_exit", lambda c: exits.append(c))
    cp, _ = _agent_cp(tmp_path)

    async def _fail(role, d):
        return False

    cp._reload_role_for_drift = _fail
    cp._flush_log_relay_async = lambda *a, **k: asyncio.sleep(0)
    await cp._schedule_role_reload("dns", str(tmp_path), delay_s=0)
    assert exits == [3]


@pytest.mark.asyncio
async def test_scheduled_reload_falls_back_to_exit_when_it_raises(
        tmp_path, monkeypatch):
    exits = []
    monkeypatch.setattr(cp_module.os, "_exit", lambda c: exits.append(c))
    cp, _ = _agent_cp(tmp_path)

    async def _boom(role, d):
        raise RuntimeError("nope")

    cp._reload_role_for_drift = _boom
    cp._flush_log_relay_async = lambda *a, **k: asyncio.sleep(0)
    await cp._schedule_role_reload("dns", str(tmp_path), delay_s=0)
    assert exits == [3]


# ── the role's own SPOKE_UPDATE handler ─────────────────────────────────────

@pytest.mark.asyncio
async def test_sibling_update_reloads_the_role_instead_of_exiting(
        tmp_path, monkeypatch):
    """The path the user hit: updating one role's repo used to os._exit(3) and
    take all 9 sub-spokes down with it."""
    exits = []
    monkeypatch.setattr(cp_module.os, "_exit", lambda c: exits.append(c))
    repo = _mkgit(tmp_path / "dns")

    conn = object.__new__(cp_module.RoleConnection)
    conn.role_name = "dns"
    scheduled = []
    conn.agent_control_plane = types.SimpleNamespace(
        _schedule_role_reload=lambda role, d: scheduled.append((role, d)))
    conn._flush_log_relay_async = lambda *a, **k: asyncio.sleep(0)
    conn._prepare_service_restart = lambda reason=None: True

    heads = iter(["aaaa", "bbbb"])  # HEAD before -> after (an actual advance)
    conn._run_git = lambda args, cwd: types.SimpleNamespace(
        returncode=0,
        stdout=(next(heads) if args[:1] == ["rev-parse"] else ""))
    monkeypatch.setattr(cp_module.subprocess, "run",
                        lambda *a, **k: types.SimpleNamespace(returncode=0))

    res = await conn._update_sibling_repo("https://example.invalid/dns.git", repo)
    assert res["status"] == "SUCCESS"
    assert scheduled == [("dns", str(repo))], "did not schedule a targeted reload"
    assert exits == [], "restarted the whole process for a single role's update"


@pytest.mark.asyncio
async def test_sibling_update_still_exits_without_a_control_plane(
        tmp_path, monkeypatch):
    """No back-reference (an older/partial wiring) → historical behaviour."""
    exits = []
    monkeypatch.setattr(cp_module.os, "_exit", lambda c: exits.append(c))
    repo = _mkgit(tmp_path / "dns")

    conn = object.__new__(cp_module.RoleConnection)
    conn.role_name = "dns"
    conn._flush_log_relay_async = lambda *a, **k: asyncio.sleep(0)
    conn._prepare_service_restart = lambda reason=None: True
    heads = iter(["aaaa", "bbbb"])
    conn._run_git = lambda args, cwd: types.SimpleNamespace(
        returncode=0,
        stdout=(next(heads) if args[:1] == ["rev-parse"] else ""))
    monkeypatch.setattr(cp_module.subprocess, "run",
                        lambda *a, **k: types.SimpleNamespace(returncode=0))

    await conn._update_sibling_repo("https://example.invalid/dns.git", repo)
    assert exits == [3]


@pytest.mark.asyncio
async def test_sibling_update_with_no_change_neither_reloads_nor_exits(
        tmp_path, monkeypatch):
    """An up-to-date repo must not churn the role at all."""
    exits = []
    monkeypatch.setattr(cp_module.os, "_exit", lambda c: exits.append(c))
    repo = _mkgit(tmp_path / "dns")

    conn = object.__new__(cp_module.RoleConnection)
    conn.role_name = "dns"
    scheduled = []
    conn.agent_control_plane = types.SimpleNamespace(
        _schedule_role_reload=lambda role, d: scheduled.append((role, d)))
    conn._flush_log_relay_async = lambda *a, **k: asyncio.sleep(0)
    conn._prepare_service_restart = lambda reason=None: True
    conn._run_git = lambda args, cwd: types.SimpleNamespace(
        returncode=0, stdout=("same" if args[:1] == ["rev-parse"] else ""))
    monkeypatch.setattr(cp_module.subprocess, "run",
                        lambda *a, **k: types.SimpleNamespace(returncode=0))

    res = await conn._update_sibling_repo("https://example.invalid/dns.git", repo)
    assert res["status"] == "SUCCESS"
    assert scheduled == [] and exits == []
