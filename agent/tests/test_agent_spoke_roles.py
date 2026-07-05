"""Role-loading for the morphable agent-spoke (``GenericAgent``).

Covers the blockers fixed when extending ``_ROLE_MAP`` from 2 → 10 roles:
  1. the role map is complete with the right module_types (incl. le →
     certificates, a sibling repo the agent shallow-clones on LOAD_ROLE);
  2. the package-aware loader resolves RELATIVE imports without an
     ``__init__.py`` (ldap's ``from .ldap_manager import LdapManager``);
  3. the ``_RoleAdapter`` wraps a non-BaseSpoke spoke (cppm's ``CPPMSpoke``),
     delegating handle_command/get_version and supplying a get_status fallback;
  4. ``_install_role`` shallow-clones a missing sibling repo, skips when present
     / for in-repo roles, finds requirements.txt at role_file.parent.parent
     (incl. simulation's ``cs/lm-spoke/`` subdir), and installs the system
     packages a role needs (certbot + DNS-01 plugins for le).
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

def test_role_map_has_all_roles_with_correct_module_types():
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
        "le":         "certificates",
        "console":    "console",
    }
    assert set(_ROLE_MAP.keys()) == set(expected.keys()), \
        f"missing/extra roles: {set(_ROLE_MAP.keys()) ^ set(expected.keys())}"
    for role, mtype in expected.items():
        rel_path, cls_name, got_mtype, repo_url = _ROLE_MAP[role]
        assert got_mtype == mtype, f"{role}: module_type {got_mtype!r} != {mtype!r}"
        assert cls_name, f"{role}: empty class name"
        # in-repo roles have no clone URL; the siblings do (incl. le).
        if role in ("dns", "dhcp", "console"):
            assert repo_url is None, f"{role} should be in-repo (no repo_url)"
        else:
            assert isinstance(repo_url, str) and repo_url.startswith("https://"), \
                f"{role}: expected a GitHub clone URL, got {repo_url!r}"
    # le points at its sibling repo + the LESpoke class.
    rel_path, cls_name, _, _ = _ROLE_MAP["le"]
    assert rel_path == "le/src/le_spoke.py"
    assert cls_name == "LESpoke"


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


def test_install_role_le_installs_certbot(tmp_path, monkeypatch):
    """le is the one sibling that needs a SYSTEM package (certbot, plus the
    common DNS-01 plugins) — the others are pip-only. A LOAD_ROLE le must
    apt-install certbot so the spoke can actually issue certs (it runs as root
    via the generic-agent unit and creates /etc/lm-le + its ledger dir itself)."""
    (tmp_path / "le").mkdir()        # repo already staged → skip clone
    calls = []
    _fake_subprocess_run(monkeypatch, calls)
    agent = _agent_with_tmp_root(tmp_path, monkeypatch)
    res = asyncio.run(agent._install_role("le"))
    assert res["status"] == "SUCCESS"
    apt_calls = [c for c in calls if c[:2] == ["apt-get", "install"]]
    assert apt_calls, "expected an apt-get install for le (certbot)"
    flat = " ".join(a for c in apt_calls for a in c)
    assert "certbot" in flat, f"certbot missing from apt install: {apt_calls}"
    assert "python3-certbot-dns-cloudflare" in flat
    # le is a sibling repo → must not be treated as in-repo (no clone here only
    # because the dir was pre-created; the role map URL is checked separately).
    _, _, _, repo_url = _ROLE_MAP["le"]
    assert repo_url and repo_url.endswith("/le.git")


# ── 5. multi-role: one agent hosts many role sub-spokes ─────────────────────

class _FakeControlPlane:
    """Stands in for AgentControlPlane during LOAD/UNLOAD_ROLE: supplies hub_url
    + a no-op .env persister so GenericAgent can spawn RoleConnection sub-spokes
    without a real hub connection. Records nothing — the base no longer morphs."""
    def __init__(self):
        self.env = {}
    hub_url = "ws://hub:8765"
    def _persist_secret_to_env(self, key, val):
        self.env[key] = val


class _FakeRoleConn:
    """Replaces RoleConnection so LOAD_ROLE doesn't open a real WS. Records
    construction args; run() completes immediately so the spawned task finishes
    without connecting. Mirrors the real RoleConnection's identity rules."""
    instances = []
    def __init__(self, role_name, base_id, hub_url, role_instance, secret=None):
        self.role_name = role_name
        self.base_id = base_id
        self.hub_url = hub_url
        self.role_instance = role_instance
        self.spoke_id = f"{base_id}-{role_name}"
        self.module_type = _ROLE_MAP[role_name][2]
        self._hub_ws = None
        _FakeRoleConn.instances.append(self)
    async def run(self):
        return None


def _stub_role_load(agent, monkeypatch):
    """Avoid real install/load: _install_role → SUCCESS, _load_role_class → a
    trivial class. RoleConnection is patched separately per test."""
    async def _fake_install(role_name):
        return {"status": "SUCCESS"}
    class _FakeRole:
        def __init__(self, spoke_id, config):
            self.spoke_id = spoke_id
            self.config = config
    monkeypatch.setattr(agent, "_install_role", _fake_install)
    monkeypatch.setattr(agent, "_load_role_class", lambda rn: _FakeRole)


def _patch_role_conn(monkeypatch):
    _FakeRoleConn.instances = []
    # agent_spoke.handle_command's LOAD_ROLE reads agent_spoke.RoleConnection
    # (a back-reference control_plane.py sets once at import time), NOT a bare
    # `from control_plane import RoleConnection` at call time — see the comment
    # on agent_spoke.RoleConnection for why. Patch both names so any direct
    # cp_module.RoleConnection(...) construction in other tests still works.
    monkeypatch.setattr(cp_module, "RoleConnection", _FakeRoleConn)
    monkeypatch.setattr(agent_spoke, "RoleConnection", _FakeRoleConn)


def test_base_module_type_stays_agent():
    """The base AgentControlPlane connection never morphs — it stays 'agent' so
    it can host role sub-spokes. The old request_morph/_reconnect_after_morph
    path is gone."""
    cp = AgentControlPlane("agent-1", "s", "", "ws://hub:8765")
    assert cp.module_type == "agent"
    assert not hasattr(cp, "request_morph")
    assert not hasattr(cp, "_reconnect_after_morph")


def test_load_role_spawns_roleconnection_subspoke(monkeypatch):
    """LOAD_ROLE hosts a RoleConnection sub-spoke under {base}-{role} with the
    role's module_type. No morph — the base stays 'agent'."""
    agent = GenericAgent("agent-1", {})
    cp = _FakeControlPlane()
    agent.control_plane = cp
    _stub_role_load(agent, monkeypatch)
    _patch_role_conn(monkeypatch)

    async def _run():
        res = await agent.handle_command("LOAD_ROLE", {"role": "network"})
        await asyncio.sleep(0)          # let the spawned sub-spoke task settle
        return res
    res = asyncio.run(_run())

    assert res["status"] == "SUCCESS"
    assert res["module_type"] == "nw"
    assert res["sub_spoke_id"] == "agent-1-network"
    # Exactly one RoleConnection spawned, identity-correct.
    assert len(_FakeRoleConn.instances) == 1
    conn = _FakeRoleConn.instances[0]
    assert conn.spoke_id == "agent-1-network"
    assert conn.module_type == "nw"
    assert conn.base_id == "agent-1"
    # The role is registered on the agent + persisted to LOADED_ROLES for boot.
    assert "network" in agent._roles
    assert cp.env.get("LOADED_ROLES") == "network"


def test_load_multiple_roles_hosts_all_concurrently(monkeypatch):
    """dns + dhcp on one agent → both hosted; GET_AVAILABLE_ROLES lists both with
    their sub_spoke_ids + module_types."""
    agent = GenericAgent("agent-1", {})
    cp = _FakeControlPlane()
    agent.control_plane = cp
    _stub_role_load(agent, monkeypatch)
    _patch_role_conn(monkeypatch)

    async def _run():
        r1 = await agent.handle_command("LOAD_ROLE", {"role": "dns"})
        r2 = await agent.handle_command("LOAD_ROLE", {"role": "dhcp"})
        await asyncio.sleep(0)
        avail = await agent.handle_command("GET_AVAILABLE_ROLES", {})
        return r1, r2, avail
    r1, r2, avail = asyncio.run(_run())

    assert r1["sub_spoke_id"] == "agent-1-dns"
    assert r2["sub_spoke_id"] == "agent-1-dhcp"
    assert set(agent._roles.keys()) == {"dns", "dhcp"}
    active = {a["role"]: a for a in avail["active"]}
    assert active["dns"] == {"role": "dns", "sub_spoke_id": "agent-1-dns",
                             "module_type": "dns"}
    assert active["dhcp"] == {"role": "dhcp", "sub_spoke_id": "agent-1-dhcp",
                              "module_type": "dhcp"}
    # LOADED_ROLES persisted as a sorted comma-list of both roles.
    assert cp.env.get("LOADED_ROLES") == "dhcp,dns"


def test_load_role_is_idempotent(monkeypatch):
    """Re-loading an already-hosted role is a no-op success — boot _seed + a
    runtime LOAD could otherwise double-spawn a sub-spoke."""
    agent = GenericAgent("agent-1", {})
    agent.control_plane = _FakeControlPlane()
    _stub_role_load(agent, monkeypatch)
    _patch_role_conn(monkeypatch)

    async def _run():
        first = await agent.handle_command("LOAD_ROLE", {"role": "dns"})
        await asyncio.sleep(0)
        second = await agent.handle_command("LOAD_ROLE", {"role": "dns"})
        return first, second
    first, second = asyncio.run(_run())

    assert first["status"] == "SUCCESS" and second["status"] == "SUCCESS"
    assert second["sub_spoke_id"] == "agent-1-dns"
    # Only one RoleConnection was ever spawned.
    assert len(_FakeRoleConn.instances) == 1


def test_unload_role_removes_only_that_role(monkeypatch):
    """UNLOAD_ROLE {role} tears down that sub-spoke only; siblings stay loaded."""
    agent = GenericAgent("agent-1", {})
    cp = _FakeControlPlane()
    agent.control_plane = cp
    _stub_role_load(agent, monkeypatch)
    _patch_role_conn(monkeypatch)

    async def _run():
        await agent.handle_command("LOAD_ROLE", {"role": "dns"})
        await agent.handle_command("LOAD_ROLE", {"role": "dhcp"})
        await asyncio.sleep(0)
        res = await agent.handle_command("UNLOAD_ROLE", {"role": "dns"})
        return res
    res = asyncio.run(_run())

    assert res["status"] == "SUCCESS"
    assert res["role"] == "dns"
    assert "dns" not in agent._roles and "dhcp" in agent._roles
    # LOADED_ROLES updated to the remaining role only.
    assert cp.env.get("LOADED_ROLES") == "dhcp"


def test_unload_role_without_arg_unloads_the_one_loaded(monkeypatch):
    """Backward-compat: no role arg + exactly one loaded role → unload that one."""
    agent = GenericAgent("agent-1", {})
    agent.control_plane = _FakeControlPlane()
    _stub_role_load(agent, monkeypatch)
    _patch_role_conn(monkeypatch)

    async def _run():
        await agent.handle_command("LOAD_ROLE", {"role": "dns"})
        await asyncio.sleep(0)
        return await agent.handle_command("UNLOAD_ROLE", {})
    res = asyncio.run(_run())

    assert res["status"] == "SUCCESS"
    assert agent._roles == {}


def test_unload_role_without_arg_errors_when_multiple_loaded(monkeypatch):
    """No role arg + >1 loaded role → ERROR listing active roles (ambiguous)."""
    agent = GenericAgent("agent-1", {})
    agent.control_plane = _FakeControlPlane()
    _stub_role_load(agent, monkeypatch)
    _patch_role_conn(monkeypatch)

    async def _run():
        await agent.handle_command("LOAD_ROLE", {"role": "dns"})
        await agent.handle_command("LOAD_ROLE", {"role": "dhcp"})
        await asyncio.sleep(0)
        return await agent.handle_command("UNLOAD_ROLE", {})
    res = asyncio.run(_run())

    assert res["status"] == "ERROR"
    assert set(res["active"]) == {"dns", "dhcp"}


# ── 6. RoleConnection: identity, auth, per-role SPOKE_UPDATE ─────────────────

class _FakeRoleInstance:
    """Minimal role instance for RoleConnection construction."""
    def __init__(self, spoke_id, config):
        self.spoke_id = spoke_id
        self.config = config


def test_role_connection_identity_and_auth_fields():
    """A RoleConnection speaks as {base}-{role}, claims parent_spoke_id, and
    sends NO install_uuid (so the clone-rename reconciler won't clobber the
    base). Its module_type is the role's; secret persistence + updater are no-ops."""
    inst = _FakeRoleInstance("agent-1-network", {})
    conn = cp_module.RoleConnection(
        "network", base_id="agent-1", hub_url="ws://hub:8765",
        role_instance=inst)
    assert conn.spoke_id == "agent-1-network"
    assert conn.module_type == "nw"
    assert conn.parent_spoke_id == "agent-1"
    assert conn.install_uuid == ""               # critical: no install_uuid
    assert conn._extra_auth_fields() == {"parent_spoke_id": "agent-1"}
    # Sub-spokes re-provision via parent-auto-approve each boot — persist + the
    # redundant per-role updater are suppressed (base agent handles self-update).
    assert conn.start_updater_worker() is None
    assert conn._persist_session_secret("x") is None
    assert conn._persist_hub_secret("x") is None


def test_role_connection_spoke_update_pulls_its_sibling_repo(tmp_path, monkeypatch):
    """A RoleConnection for network → SPOKE_UPDATE pulls /opt/lm/nw (ITS sibling
    repo), never /opt/lm (the lm repo). Verifies the per-role override."""
    inst = _FakeRoleInstance("agent-1-network", {})
    conn = cp_module.RoleConnection(
        "network", base_id="agent-1", hub_url="ws://hub:8765",
        role_instance=inst)
    monkeypatch.setattr(conn, "_lm_root", lambda: tmp_path)
    (tmp_path / "nw").mkdir()                   # sibling repo dir present

    calls = []
    import subprocess as _sp
    def _fake_run(cmd, *a, **k):
        calls.append({"cmd": list(cmd), "cwd": k.get("cwd")})
        return _sp.CompletedProcess(args=cmd, returncode=0, stdout="abc", stderr="")
    monkeypatch.setattr(cp_module.subprocess, "run", _fake_run)
    def _fake_rungit(args, cwd):
        calls.append({"cmd": ["git"] + list(args), "cwd": cwd})
        return _sp.CompletedProcess(args=args, returncode=0, stdout="abc", stderr="")
    monkeypatch.setattr(conn, "_run_git", _fake_rungit)

    res = asyncio.run(conn.handle_system_command(
        "SPOKE_UPDATE", {"repo_url": "https://github.com/lbockenstedt/nw.git"}))
    assert res["status"] == "SUCCESS", res
    cwds = [str(c["cwd"]) for c in calls if c.get("cwd")]
    assert cwds and all(c.endswith("/nw") for c in cwds), \
        f"pull targeted wrong dir: {cwds}"
    seturl = [c for c in calls if "set-url" in c["cmd"]]
    assert seturl and any("github.com/lbockenstedt/nw.git" in a for a in seturl[0]["cmd"]), \
        f"set-url did not use the nw URL: {seturl}"


def test_role_connection_inrepo_role_delegates_spoke_update_to_base(monkeypatch):
    """dns ships in the lm repo (repo_url None) → RoleConnection SPOKE_UPDATE
    delegates to the BaseControlPlane handler (pulls /opt/lm), not a sibling."""
    inst = _FakeRoleInstance("agent-1-dns", {})
    conn = cp_module.RoleConnection(
        "dns", base_id="agent-1", hub_url="ws://hub:8765", role_instance=inst)

    sentinel = {"status": "SUCCESS", "message": "base-handled"}
    recorded = {}
    async def _fake_super(self_, cmd_type, data):
        recorded["called"] = (cmd_type, data)
        return sentinel
    monkeypatch.setattr(BaseControlPlane, "handle_system_command", _fake_super)

    res = asyncio.run(conn.handle_system_command("SPOKE_UPDATE", {}))
    assert res == sentinel
    assert recorded["called"][0] == "SPOKE_UPDATE"


def test_role_connection_spoke_update_errors_when_repo_absent(tmp_path, monkeypatch):
    """Sibling repo dir missing → SPOKE_UPDATE returns ERROR (no git ops on a
    nonexistent cwd), instead of crashing or pulling the wrong tree."""
    inst = _FakeRoleInstance("agent-1-network", {})
    conn = cp_module.RoleConnection(
        "network", base_id="agent-1", hub_url="ws://hub:8765",
        role_instance=inst)
    monkeypatch.setattr(conn, "_lm_root", lambda: tmp_path)
    # NOTE: no (tmp_path / "nw").mkdir() — repo absent.
    res = asyncio.run(conn.handle_system_command("SPOKE_UPDATE", {}))
    assert res["status"] == "ERROR"
    assert "nw" in res["message"]