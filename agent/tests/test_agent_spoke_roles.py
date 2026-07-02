"""Role-loading for the morphable agent-spoke (``GenericAgent``).

Covers the three blockers fixed when extending ``_ROLE_MAP`` from 2 → 8 roles:
  1. the role map is complete with the right module_types;
  2. the package-aware loader resolves RELATIVE imports without an
     ``__init__.py`` (ldap's ``from .ldap_manager import LdapManager``);
  3. the ``_RoleAdapter`` wraps a non-BaseSpoke spoke (cppm's ``CPPMSpoke``),
     delegating handle_command/get_version and supplying a get_status fallback;
  4. ``_install_role`` shallow-clones a missing sibling repo, skips when present
     / for in-repo roles, and finds requirements.txt at role_file.parent.parent
     (incl. simulation's ``cs/lm-spoke/`` subdir).
"""
import asyncio
import importlib
import sys
from pathlib import Path

import agent_spoke
import control_plane as cp_module
from agent_spoke import GenericAgent, _RoleAdapter, _ROLE_MAP
from control_plane import AgentControlPlane
from core.src.messaging.control_plane import BaseControlPlane


# ── 1. role map completeness ─────────────────────────────────────────────────

def test_role_map_has_all_eight_roles_with_correct_module_types():
    expected = {
        "dns":        "dns",
        "dhcp":       "dhcp",
        "network":    "nw",
        "netbox":     "ipam",
        "opnsense":   "firewall",
        "ldap":       "directory",
        "simulation": "simulation",
        "cppm":       "nac",
        "proxmox":    "hypervisor",
    }
    assert set(_ROLE_MAP.keys()) == set(expected.keys()), \
        f"missing/extra roles: {set(_ROLE_MAP.keys()) ^ set(expected.keys())}"
    for role, mtype in expected.items():
        rel_path, cls_name, got_mtype, repo_url = _ROLE_MAP[role]
        assert got_mtype == mtype, f"{role}: module_type {got_mtype!r} != {mtype!r}"
        assert cls_name, f"{role}: empty class name"
        # in-repo roles have no clone URL; the six siblings do.
        if role in ("dns", "dhcp"):
            assert repo_url is None, f"{role} should be in-repo (no repo_url)"
        else:
            assert isinstance(repo_url, str) and repo_url.startswith("https://"), \
                f"{role}: expected a GitHub clone URL, got {repo_url!r}"


# ── 2. package-aware loader (relative import, no __init__.py) ────────────────

def test_load_role_class_resolves_relative_import_without_init(tmp_path, monkeypatch):
    """Mirrors ldap: src/ has no __init__.py and the spoke does
    `from .ldap_manager import LdapManager`. The old loader (no package context)
    raised ImportError; the package-aware loader must succeed."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "helper.py").write_text("HELLO = 'from-helper'\n")
    (src / "fake_spoke.py").write_text(
        "from .helper import HELLO\n"
        "class FakeSpoke:\n"
        "    def __init__(self, spoke_id, config):\n"
        "        self.spoke_id = spoke_id; self.config = config; self.hello = HELLO\n"
    )
    # NO __init__.py — that's the whole point.
    assert not (src / "__init__.py").exists()

    monkeypatch.setitem(_ROLE_MAP, "fake",
                        ("src/fake_spoke.py", "FakeSpoke", "fake", None))
    agent = GenericAgent("agent-fake", {})
    monkeypatch.setattr(agent, "_lm_root", lambda: tmp_path)

    cls = agent._load_role_class("fake")
    assert cls is not None, "relative-import load failed (returned None)"
    inst = cls("agent-fake", {})
    assert inst.hello == "from-helper"   # proves `from .helper` resolved

    # cleanup: drop the registered package so it doesn't leak into other tests
    sys.modules.pop("lm_role_fake", None)


def test_load_role_class_returns_none_for_unknown_role():
    agent = GenericAgent("agent-x", {})
    assert agent._load_role_class("does-not-exist") is None


# ── 3. _RoleAdapter (cppm-class wrapper) ─────────────────────────────────────

class _FakeNonBaseSpoke:
    """Stands in for cppm's CPPMSpoke: handle_command + get_version + spoke_id,
    but NOT a BaseSpoke subclass and NO get_status."""
    def __init__(self, spoke_id, config):
        self.spoke_id = spoke_id
        self.config = config

    async def handle_command(self, command_type, data):
        return {"status": "SUCCESS", "echo": command_type}

    def get_version(self):
        return "9.9.9"


def test_role_adapter_is_basespoke_and_falls_back_for_get_status():
    inner = _FakeNonBaseSpoke("agent-cppm", {})
    from base_spoke import BaseSpoke
    assert not isinstance(inner, BaseSpoke)
    adapter = _RoleAdapter(inner)
    assert isinstance(adapter, BaseSpoke)          # now usable wherever a BaseSpoke is

    status = asyncio.run(adapter.get_status())
    # No get_status on inner → fallback READY dict, no AttributeError.
    assert status["status"] == "READY"
    assert status["spoke_id"] == "agent-cppm"


def test_role_adapter_delegates_handle_command_and_version():
    inner = _FakeNonBaseSpoke("agent-cppm", {})
    adapter = _RoleAdapter(inner)
    res = asyncio.run(adapter.handle_command("CPPM_GET_NAC_STATUS", {}))
    assert res == {"status": "SUCCESS", "echo": "CPPM_GET_NAC_STATUS"}
    assert adapter.get_version() == "9.9.9"


def test_role_adapter_passes_through_get_status_when_inner_has_it():
    class WithStatus(_FakeNonBaseSpoke):
        async def get_status(self):
            return {"status": "SUCCESS", "devices": 7}
    adapter = _RoleAdapter(WithStatus("a", {}))
    assert asyncio.run(adapter.get_status()) == {"status": "SUCCESS", "devices": 7}


# ── 4. _install_role clone logic ─────────────────────────────────────────────

def _agent_with_tmp_root(tmp_path, monkeypatch):
    agent = GenericAgent("agent-tmp", {})
    monkeypatch.setattr(agent, "_lm_root", lambda: tmp_path)
    return agent


def _fake_subprocess_run(monkeypatch, calls):
    import subprocess
    def _run(cmd, *args, **kwargs):
        calls.append(list(cmd))
        return subprocess.CompletedProcess(args=cmd, returncode=0)
    monkeypatch.setattr(agent_spoke.subprocess, "run", _run)


def test_install_role_clones_missing_sibling_repo(tmp_path, monkeypatch):
    calls = []
    _fake_subprocess_run(monkeypatch, calls)
    agent = _agent_with_tmp_root(tmp_path, monkeypatch)
    # network → clone into tmp_path/nw; do NOT create it; no requirements.txt.
    res = asyncio.run(agent._install_role("network"))
    assert res["status"] == "SUCCESS"
    clones = [c for c in calls if c[:2] == ["git", "clone"]]
    assert len(clones) == 1, f"expected one git clone, got {clones}"
    assert clones[0][2:4] == ["--depth", "1"]
    assert clones[0][-1].endswith("/nw")
    assert any("github.com/lbockenstedt/nw.git" in a for a in clones[0])


def test_install_role_skips_clone_when_repo_present(tmp_path, monkeypatch):
    (tmp_path / "nw").mkdir()        # repo already staged
    calls = []
    _fake_subprocess_run(monkeypatch, calls)
    agent = _agent_with_tmp_root(tmp_path, monkeypatch)
    asyncio.run(agent._install_role("network"))
    assert not [c for c in calls if c[:2] == ["git", "clone"]], "should not re-clone"


def test_install_role_no_clone_for_inrepo_role(tmp_path, monkeypatch):
    """dns ships inside the lm repo → repo_url None → never clones (apt only)."""
    (tmp_path / "dns").mkdir()
    calls = []
    _fake_subprocess_run(monkeypatch, calls)
    agent = _agent_with_tmp_root(tmp_path, monkeypatch)
    asyncio.run(agent._install_role("dns"))
    assert not [c for c in calls if c[:2] == ["git", "clone"]], "dns must not clone"


def test_install_role_requirements_path_for_simulation_subdir(tmp_path, monkeypatch):
    """simulation's requirements live at cs/lm-spoke/ (role_file.parent.parent),
    not the cs/ repo root — confirm the pip install targets that exact path."""
    (tmp_path / "cs" / "lm-spoke").mkdir(parents=True)
    req = tmp_path / "cs" / "lm-spoke" / "requirements.txt"
    req.write_text("# fake\n")
    calls = []
    _fake_subprocess_run(monkeypatch, calls)
    agent = _agent_with_tmp_root(tmp_path, monkeypatch)
    asyncio.run(agent._install_role("simulation"))
    pip_calls = [c for c in calls if c and c[0].endswith("/pip")]
    assert pip_calls, "expected a pip install call"
    # pip install --quiet -r <req>; the -r arg must be the lm-spoke requirements.
    assert any(str(req) == arg for c in pip_calls for arg in c), \
        f"pip did not target {req}; calls={pip_calls}"


# ── 5. morph: agent can be a spoke or an agent ───────────────────────────────

class _FakeControlPlane:
    """Records request_morph calls (no real reconnect)."""
    def __init__(self):
        self.morphs = []
    async def request_morph(self, module_type):
        self.morphs.append(module_type)


def test_load_role_calls_request_morph_with_role_module_type(monkeypatch):
    agent = GenericAgent("agent-1", {})
    cp = _FakeControlPlane()
    agent.control_plane = cp
    # Avoid real install/load: stub _install_role + _load_role_class.
    async def _fake_install(role_name):
        return {"status": "SUCCESS"}
    class _FakeRole:
        def __init__(self, spoke_id, config):
            pass
    monkeypatch.setattr(agent, "_install_role", _fake_install)
    monkeypatch.setattr(agent, "_load_role_class", lambda rn: _FakeRole)
    res = asyncio.run(agent.handle_command(
        "LOAD_ROLE", {"role": "network"}))
    assert res["status"] == "SUCCESS"
    assert res["module_type"] == "nw"
    assert cp.morphs == ["nw"], f"expected request_morph('nw'), got {cp.morphs}"


def test_unload_role_morphs_back_to_agent():
    agent = GenericAgent("agent-1", {})
    cp = _FakeControlPlane()
    agent.control_plane = cp
    agent._role = _FakeControlPlane()   # truthy placeholder
    agent._role_name = "network"
    res = asyncio.run(agent.handle_command("UNLOAD_ROLE", {}))
    assert res["status"] == "SUCCESS"
    assert agent._role is None and agent._role_name is None
    assert cp.morphs == ["agent"], f"expected request_morph('agent'), got {cp.morphs}"


def test_request_morph_updates_module_type_and_closes_ws(monkeypatch):
    cp = AgentControlPlane("agent-1", "s", "", "ws://hub:8765", "")
    assert cp.module_type == "agent"
    closed = {"yes": False}
    class _FakeWS:
        async def close(self):
            closed["yes"] = True
    cp._hub_ws = _FakeWS()

    # Speed up the 0.2s reconnect delay without breaking scheduler yields.
    _real_sleep = asyncio.sleep
    async def _fast_sleep(*a, **k):
        await _real_sleep(0)
    monkeypatch.setattr(cp_module.asyncio, "sleep", _fast_sleep)

    async def _run():
        await cp.request_morph("firewall")
        await cp._morph_task       # drain the scheduled reconnect
    asyncio.run(_run())
    assert cp.module_type == "firewall"
    assert closed["yes"] is True, "request_morph did not close the hub WS"


def test_spoke_update_for_sibling_role_pulls_sibling_repo(tmp_path, monkeypatch):
    """Morphed to a sibling role (network) → SPOKE_UPDATE must pull /opt/lm/nw,
    NOT /opt/lm (the lm repo). Verifies the corruption-prevention override."""
    cp = AgentControlPlane("agent-1", "s", "", "ws://hub:8765", "")
    class _Ag:
        _role_name = "network"
    cp.modules["agent"] = _Ag()
    monkeypatch.setattr(cp, "_lm_root", lambda: tmp_path)
    (tmp_path / "nw").mkdir()       # role repo dir present

    calls = []
    import subprocess as _sp
    def _fake_run(cmd, *a, **k):
        calls.append({"cmd": list(cmd), "cwd": k.get("cwd")})
        return _sp.CompletedProcess(args=cmd, returncode=0, stdout="abc", stderr="")
    monkeypatch.setattr(cp_module.subprocess, "run", _fake_run)
    def _fake_rungit(args, cwd):
        calls.append({"cmd": ["git"] + list(args), "cwd": cwd})
        return _sp.CompletedProcess(args=args, returncode=0, stdout="abc", stderr="")
    monkeypatch.setattr(cp, "_run_git", _fake_rungit)

    res = asyncio.run(cp.handle_system_command(
        "SPOKE_UPDATE", {"repo_url": "https://github.com/lbockenstedt/nw.git"}))
    assert res["status"] == "SUCCESS", res
    # Every git op targeted the sibling dir, never /opt/lm itself.
    cwds = [str(c["cwd"]) for c in calls if c.get("cwd")]
    assert cwds, "no git calls recorded"
    assert all(c.endswith("/nw") for c in cwds), f"pull targeted wrong dir: {cwds}"
    # remote set-url used the nw repo URL (from _ROLE_MAP, not the payload).
    seturl = [c for c in calls if "set-url" in c["cmd"]]
    assert seturl and any("github.com/lbockenstedt/nw.git" in a for a in seturl[0]["cmd"]), \
        f"set-url did not use the nw URL: {seturl}"


def test_spoke_update_unmorphed_delegates_to_base_handler(monkeypatch):
    """No active role → SPOKE_UPDATE delegates to BaseControlPlane (pulls /opt/lm,
    the lm repo / agent code) — existing behavior preserved."""
    cp = AgentControlPlane("agent-1", "s", "", "ws://hub:8765", "")
    class _Ag:
        _role_name = None
    cp.modules["agent"] = _Ag()

    sentinel = {"status": "SUCCESS", "message": "base-handled"}
    recorded = {}
    async def _fake_super(self_, cmd_type, data):
        recorded["called"] = (cmd_type, data)
        return sentinel
    monkeypatch.setattr(BaseControlPlane, "handle_system_command", _fake_super)

    res = asyncio.run(cp.handle_system_command(
        "SPOKE_UPDATE", {"repo_url": "https://github.com/lbockenstedt/lm.git"}))
    assert res == sentinel
    assert recorded.get("called")[0] == "SPOKE_UPDATE", "super not invoked"

    # Non-SPOKE_UPDATE system commands also pass through to base.
    async def _fake_super2(self_, cmd_type, data):
        return {"status": "SUCCESS", "message": "passthrough"}
    monkeypatch.setattr(BaseControlPlane, "handle_system_command", _fake_super2)
    res2 = asyncio.run(cp.handle_system_command("SPOKE_GET_STATUS", {}))
    assert res2["message"] == "passthrough"