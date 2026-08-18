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
    # No explicit LM_CS_AGENT_LISTENER — exercise the DEFAULT gating. The hub URL
    # here is loopback (127.0.0.1), i.e. co-located/all-in-one, so the simulation
    # default is OFF (the hub owns :443); dns/ldap never bind.
    monkeypatch.delenv("LM_CS_AGENT_LISTENER", raising=False)
    for role, expected in [
        ("proxmox", True), ("simulation", False), ("dns", False),
        ("ldap", False),
    ]:
        conn = cp_module.RoleConnection(
            role, "lm-agent", "wss://127.0.0.1:443", _make_role_instance())
        assert conn._agent_listener_enabled() is expected, \
            f"{role}: listener should be {expected}"
        assert conn.module_type == {
            "proxmox": "hypervisor", "simulation": "simulation", "dns": "dns",
            "ldap": "directory",
        }[role]


def test_simulation_listener_default_on_standalone(monkeypatch, tmp_path):
    """The simulation (cs) role hosts its OWN /ws/agent listener by DEFAULT on a
    standalone agent — one that dials a REMOTE hub (non-loopback hub URL). This
    is the WebUI-load / boot-load / --roles path: loading the simulation role is
    enough for a Proxmox/unified node-agent to dial THIS box and have the hub
    relay CS_COMMANDs to it (no separate cs/pxmx spoke, no .env edit). It is
    suppressed only when co-located with the hub (loopback hub URL → the hub
    owns :443). LM_CS_AGENT_LISTENER still explicitly overrides either way."""
    monkeypatch.setattr(cp_module.RoleConnection, "AGENT_CONFIG_PATH",
                       str(tmp_path / "agent-config.json"))
    monkeypatch.delenv("LM_CS_AGENT_LISTENER", raising=False)

    # Standalone (remote hub) → listener ON by default; self-provisions a secret.
    for hub in ("wss://10.0.0.5:443", "wss://hub.example.com:443",
                "wss://172.16.1.10:8443/ws/spoke"):
        on = cp_module.RoleConnection(
            "simulation", "lm-agent", hub, _make_role_instance())
        assert on._agent_listener_enabled() is True, \
            f"standalone simulation (hub={hub}) should default the listener ON"
        assert on.agent_secret, \
            "standalone simulation must self-provision an agent_secret"

    # Co-located (loopback hub) → default OFF (hub owns :443).
    for hub in ("wss://127.0.0.1:443", "wss://localhost:443/ws/spoke",
                "wss://[::1]:443", "ws://0.0.0.0:443"):
        off = cp_module.RoleConnection(
            "simulation", "lm-agent", hub, _make_role_instance())
        assert off._agent_listener_enabled() is False, \
            f"co-located simulation (hub={hub}) should default the listener OFF"

    # Explicit override wins over the co-location default (both directions).
    monkeypatch.setenv("LM_CS_AGENT_LISTENER", "1")
    forced_on = cp_module.RoleConnection(
        "simulation", "lm-agent", "wss://127.0.0.1:443", _make_role_instance())
    assert forced_on._agent_listener_enabled() is True, \
        "LM_CS_AGENT_LISTENER=1 must force the listener on even when co-located"
    monkeypatch.setenv("LM_CS_AGENT_LISTENER", "0")
    forced_off = cp_module.RoleConnection(
        "simulation", "lm-agent", "wss://10.0.0.5:443", _make_role_instance())
    assert forced_off._agent_listener_enabled() is False, \
        "LM_CS_AGENT_LISTENER=0 must force the listener off even when standalone"


def test_simulation_listener_opt_in(monkeypatch, tmp_path):
    """The simulation (cs) role hosts its OWN /ws/agent listener when opted in
    via LM_CS_AGENT_LISTENER=1 — so a unified agent that loaded the simulation
    role can host the client-sim node-agent (no separate cs/pxmx spoke). Mirrors
    the standalone cs spoke (install_cs.sh --agent-listener). When on, it uses
    the cs listener PORT knobs (443/8767) so it can't collide with a co-loaded
    pxmx role (8443/8766), sharing the base agent_secret for approval. Uses a
    loopback (co-located) hub so the default is OFF and the ENV opt-in is what's
    exercised."""
    monkeypatch.setattr(cp_module.RoleConnection, "AGENT_CONFIG_PATH",
                       str(tmp_path / "agent-config.json"))

    # Opt-out (default) on a co-located box: no listener.
    monkeypatch.delenv("LM_CS_AGENT_LISTENER", raising=False)
    off = cp_module.RoleConnection(
        "simulation", "lm-agent", "wss://127.0.0.1:443", _make_role_instance())
    assert off._agent_listener_enabled() is False
    # cs listener PORT knobs are wired regardless (only the gate is opt-in).
    assert off.AGENT_LISTENER_ENV == "LM_CS_AGENT_LISTENER"
    assert off.AGENT_WSS_PORT == 443
    assert off.AGENT_FALLBACK_PORT == 8767
    assert off.module_type == "simulation"

    # Opt-in: listener enabled and the agent_secret self-provisions.
    for val in ("1", "true", "yes", "on"):
        monkeypatch.setenv("LM_CS_AGENT_LISTENER", val)
        on = cp_module.RoleConnection(
            "simulation", "lm-agent", "wss://127.0.0.1:443",
            _make_role_instance())
        assert on._agent_listener_enabled() is True, \
            f"LM_CS_AGENT_LISTENER={val} should enable the cs listener"
        assert on.agent_secret, \
            "opted-in simulation role must self-provision an agent_secret"


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

def test_on_agent_registered_tolerates_module_without_agent_configs(monkeypatch, tmp_path):
    """Regression: a non-proxmox hosting role module (e.g. the "simulation"
    CSSpoke) has no ``agent_configs`` attribute. The post-register hook must
    no-op instead of raising AttributeError — otherwise the agent handler treats
    it as connection-fatal and the hosted agent hot-reconnect-flaps, never
    finishing provisioning."""
    monkeypatch.setattr(cp_module.RoleConnection, "AGENT_CONFIG_PATH",
                       str(tmp_path / "agent-config.json"))
    # Role module deliberately lacks agent_configs (only telemetry_cache).
    inst = types.SimpleNamespace(telemetry_cache={})
    conn = cp_module.RoleConnection(
        "simulation", "lm-agent", "wss://127.0.0.1:443", inst)
    sent = []

    async def fake_send(cmd, data, agent_id=None):
        sent.append((cmd, data, agent_id))

    conn.send_to_agent = fake_send
    import asyncio
    # Must NOT raise, and must NOT push any config (nothing stored).
    asyncio.run(conn._on_agent_registered("pxmx-cs-svr-06"))
    assert sent == []

def test_role_connection_persists_session_secret_per_role(monkeypatch, tmp_path):
    """H4: a RoleConnection persists its session secret under a per-role .env
    key (SPOKE_SECRET_<ROLE>) — NOT SPOKE_SECRET (the base agent's line in the
    shared .env) — and reloads it on construction so the sub-spoke reconnects
    AUTHENTICATED (like cs) instead of zero-touch every boot. That lets the hub
    skip the SPOKE_UPDATE_SESSION_KEY provisioning push on reconnects and re-key
    via AEAD-encrypted rotation (new key encrypted with the pre-rotation key the
    sub-spoke holds), keeping H4 app-layer encryption intact. First boot, or a
    blanked key (the 1008-fallback), → no persisted secret → zero-touch → the
    hub re-provisions (plaintext on the true first keying only — inherent to
    H4, since you can't encrypt the first key with a key that doesn't exist)."""
    monkeypatch.setattr(cp_module.RoleConnection, "AGENT_CONFIG_PATH",
                       str(tmp_path / "agent-config.json"))
    monkeypatch.setattr(cp_module.RoleConnection, "_repo_root",
                        lambda self: str(tmp_path))

    # First boot: no persisted secret → zero-touch (self.secret / signer None).
    conn = cp_module.RoleConnection(
        "netbox", "lm-agent", "wss://127.0.0.1:443", _make_role_instance())
    assert conn.secret is None
    assert conn.signer is None
    assert conn._role_env_key() == "SPOKE_SECRET_NETBOX"

    # The hub provisions a key; the sub-spoke persists it under the per-role key.
    conn._persist_session_secret("netbox-session-secret-abc")
    env = (tmp_path / ".env").read_text()
    assert "SPOKE_SECRET_NETBOX=netbox-session-secret-abc" in env
    # The base agent's SPOKE_SECRET line is NOT written/clobbered.
    assert "SPOKE_SECRET=" not in env.replace("SPOKE_SECRET_NETBOX=", "X")

    # Restart: a fresh RoleConnection loads the persisted secret → authenticated.
    conn2 = cp_module.RoleConnection(
        "netbox", "lm-agent", "wss://127.0.0.1:443", _make_role_instance())
    assert conn2.secret == "netbox-session-secret-abc"
    assert conn2.signer is not None

    # A different role uses a different key — no cross-role clobber.
    conn3 = cp_module.RoleConnection(
        "dns", "lm-agent", "wss://127.0.0.1:443", _make_role_instance())
    assert conn3._role_env_key() == "SPOKE_SECRET_DNS"
    assert conn3.secret is None  # dns has no persisted secret

    # Blanking (the connect-path 1008-fallback) writes empty → next boot zero-touch.
    conn2._persist_session_secret("")
    conn4 = cp_module.RoleConnection(
        "netbox", "lm-agent", "wss://127.0.0.1:443", _make_role_instance())
    assert conn4.secret is None
