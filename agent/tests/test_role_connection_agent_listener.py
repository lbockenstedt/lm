"""RoleConnection agent-hosting regression (pxmx role listens on /ws/agent).

Locks in the correction to the connected_agents/pending_agents/
broadcast_to_agents shims: the pxmx (hypervisor) role sub-spoke IS supposed to
host a /ws/agent listener (a pxmx node-agent dials the box running the pxmx
role). RoleConnection now subclasses AgentHostingControlPlane, gates the
listener to the proxmox role, self-provisions + persists an agent_secret, and
mirrors telemetry into the role module under self.role_name.

Covers:
  1. RoleConnection is an AgentHostingControlPlane subclass (MRO) and inherits
     the real broadcast_to_agents (not the old no-op shim).
  2. _agent_listener_enabled is True only for proxmox; dns/ldap/etc. are gated
     off (no port bound).
  3. Non-pxmx roles keep empty connected_agents/pending_agents (inherited init)
     — no AttributeError, same empty-degrade behavior the shims provided.
  4. The proxmox role self-provisions an agent_secret and persists it to
     AGENT_CONFIG_PATH (chmod 600); a second init reuses the SAME secret (no
     regen), so already-approved agents reconnect cleanly after a restart.
  5. The proxmox telemetry hook mirrors into the role module under
     self.role_name (not the standalone's hardcoded "pxmx").
"""
import json
import os
import types

import control_plane as cp_module
from core.src.messaging.agent_hosting import AgentHostingControlPlane
from core.src.messaging.control_plane import BaseControlPlane


def _make_role_instance():
    return types.SimpleNamespace(
        telemetry_cache={}, agent_configs={})


def test_role_connection_is_agent_hosting_subclass():
    rc = cp_module.RoleConnection
    assert issubclass(rc, AgentHostingControlPlane)
    assert issubclass(rc, BaseControlPlane)
    # broadcast_to_agents is the REAL inherited fan-out, not the old no-op shim.
    assert rc.broadcast_to_agents.__qualname__.startswith(
        "AgentHostingControlPlane"), \
        "broadcast_to_agents must be inherited (no-op shim removed)"
    assert hasattr(rc, "run")
    assert hasattr(rc, "_agent_listener_enabled")
    assert hasattr(rc, "_on_agent_telemetry")
    assert hasattr(rc, "_on_agent_registered")
    assert hasattr(rc, "_save_disk_cache")


def test_listener_gated_to_proxmox_only(monkeypatch, tmp_path):
    # Point AGENT_CONFIG_PATH at a temp path so the proxmox init can write.
    monkeypatch.setattr(cp_module.RoleConnection, "AGENT_CONFIG_PATH",
                       str(tmp_path / "agent-config.json"))
    for role, expected in [("proxmox", True), ("dns", False), ("ldap", False)]:
        conn = cp_module.RoleConnection(
            role, "lm-agent", "wss://127.0.0.1:443", _make_role_instance())
        assert conn._agent_listener_enabled() is expected, \
            f"{role}: listener should be {expected}"
        assert conn.module_type == {
            "proxmox": "hypervisor", "dns": "dns", "ldap": "directory",
        }[role]


def test_non_pxmx_roles_empty_degrade_no_attributeerror(monkeypatch, tmp_path):
    monkeypatch.setattr(cp_module.RoleConnection, "AGENT_CONFIG_PATH",
                       str(tmp_path / "agent-config.json"))
    inst = _make_role_instance()
    conn = cp_module.RoleConnection(
        "dns", "lm-agent", "wss://127.0.0.1:443", inst)
    # Inherited agent-hosting state exists and is empty — the shim behavior,
    # now via the real base class.
    assert conn.connected_agents == {}
    assert conn.pending_agents == {}
    # role_instance back-ref wired.
    assert inst.control_plane is conn
    # No agent_secret provisioned for a non-pxmx role.
    assert conn.agent_secret is None
    # _agent_listener_enabled False → run() would NOT start the server task.
    assert conn._agent_listener_enabled() is False


def test_proxmox_self_provisions_and_persists_agent_secret(monkeypatch, tmp_path):
    cfg = tmp_path / "agent-config.json"
    monkeypatch.setattr(cp_module.RoleConnection, "AGENT_CONFIG_PATH", str(cfg))
    inst = _make_role_instance()
    conn = cp_module.RoleConnection(
        "proxmox", "lm-agent", "wss://127.0.0.1:443", inst)
    assert conn.agent_secret, "proxmox role must self-provision an agent_secret"
    assert cfg.exists(), "agent_secret must be persisted to AGENT_CONFIG_PATH"
    assert (cfg.stat().st_mode & 0o777) == 0o600, "config must be chmod 600"
    persisted = json.loads(cfg.read_text())
    assert persisted.get("agent_secret") == conn.agent_secret

    # Second init reuses the SAME secret (no regen) — already-approved agents
    # reconnect cleanly after a restart.
    conn2 = cp_module.RoleConnection(
        "proxmox", "lm-agent", "wss://127.0.0.1:443", _make_role_instance())
    assert conn2.agent_secret == conn.agent_secret, \
        "restart must reuse the persisted agent_secret, not regen"


def test_proxmox_preserves_existing_agent_secret(monkeypatch, tmp_path):
    cfg = tmp_path / "agent-config.json"
    cfg.write_text(json.dumps({"agent_secret": "pre-existing", "other": 1}))
    monkeypatch.setattr(cp_module.RoleConnection, "AGENT_CONFIG_PATH", str(cfg))
    conn = cp_module.RoleConnection(
        "proxmox", "lm-agent", "wss://127.0.0.1:443", _make_role_instance())
    assert conn.agent_secret == "pre-existing", \
        "an existing agent_secret (e.g. from install_pxmx.sh) must be preserved"
    # Other keys are preserved too.
    assert json.loads(cfg.read_text()).get("other") == 1


def test_on_agent_telemetry_mirrors_under_role_name(monkeypatch, tmp_path):
    monkeypatch.setattr(cp_module.RoleConnection, "AGENT_CONFIG_PATH",
                       str(tmp_path / "agent-config.json"))
    inst = _make_role_instance()
    conn = cp_module.RoleConnection(
        "proxmox", "lm-agent", "wss://127.0.0.1:443", inst)
    rec = {}
    data = {"cluster_name": "px-cluster",
            "nodes": {"nodes": [{"name": "n1"}]},
            "vms": {"vms": [{"vmid": 100}]},
            "metrics": {"cpu": 0.1}}
    import asyncio
    asyncio.run(conn._on_agent_telemetry("agent-1", rec, data))
    # Mirrored into the role module under self.role_name ("proxmox"), NOT "pxmx".
    assert inst.telemetry_cache.get("agent-1") is data
    # rec enriched with cached fields.
    assert rec["cluster_name"] == "px-cluster"
    assert rec["nodes"] == [{"name": "n1"}]
    assert rec["vms"] == [{"vmid": 100}]
    assert rec["agent_metrics"] == {"cpu": 0.1}


def test_on_agent_registered_repushes_stored_config(monkeypatch, tmp_path):
    monkeypatch.setattr(cp_module.RoleConnection, "AGENT_CONFIG_PATH",
                       str(tmp_path / "agent-config.json"))
    inst = _make_role_instance()
    inst.agent_configs = {"agent-1": {"pve": "creds"}}
    conn = cp_module.RoleConnection(
        "proxmox", "lm-agent", "wss://127.0.0.1:443", inst)
    sent = []

    async def fake_send(cmd, data, agent_id=None):
        sent.append((cmd, data, agent_id))

    conn.send_to_agent = fake_send
    import asyncio
    asyncio.run(conn._on_agent_registered("agent-1"))
    assert sent == [("UPDATE_CONFIG", {"pve": "creds"}, "agent-1")]
    # Unknown agent → no send.
    asyncio.run(conn._on_agent_registered("agent-unknown"))
    assert len(sent) == 1