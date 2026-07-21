# Agent (lm/agent)

The **agent-spoke** — a spoke of the hub that, on `LOAD_ROLE`, clones a sibling repo and swaps in a real spoke class. Not a separate repo — lives under `lm/agent/`.

> **The legacy `generic_agent/` leaf was removed** (commit `3ddda2c` — "delete the legacy protocol-incompatible generic_agent leaf"). It could not adopt a session key or handle the current mutual-auth protocol. Everything below describes the current **agent-spoke** (`agent/src/agent_spoke.py::GenericAgent`, a `BaseSpoke` subclass); `install_menu.sh`'s "Agent" path now runs `agent/install_agent.sh`, not the deleted leaf.

## Role & module_type

- `agent/src/agent_spoke.py::GenericAgent` — a spoke of the hub that, on `LOAD_ROLE`, clones a sibling repo and swaps in a real spoke class. Its base connection registers `module_type="agent"`; each loaded role opens a separate sub-spoke connection under the role's real `module_type`.

## What it does

The agent is what you install on every managed node — one systemd unit per box
(`lm-agent`, spoke id `agent-<hostname>`). By itself it does nothing but phone the hub;
it becomes a DNS server, a DHCP server, a NetBox sync spoke, a firewall spoke, a
hypervisor spoke, a console server, etc. only when the hub tells it to **load a role**.
A single agent can host several roles at once (e.g. `dns` + `dhcp` on the same box).
You manage agents and their roles from the WebUI under **Setup → Agents**: that page
lists every connected agent, lets you Load Role / Unload Role, and shows each hosted
role's live status.

## Entrypoints

- **Agent-spoke:** `agent/src/control_plane.py` (argparse entrypoint). systemd unit `lm-agent` (built by `agent/install_agent.sh`), `--hub` (optional; omit/`auto` → auto-discover via mDNS/DNS), `--id` (default `agent-<hostname>`), `--secret`, `--hub-secret`, `--role <one>`/`--roles <csv>`, `--loopback`, `--clone`, `--tls-verify`/`--tls-ca-cert`.

## Ports

- Agent-spoke: none served; dials the hub over `wss://127.0.0.1:443/ws/spoke` (same-box, verify-off) or `wss://<hub>:443/ws/spoke` (remote).

## Environment variables

`LM_HUB_TLS_VERIFY`, `LM_HUB_CA_CERT` (client TLS verify), `STARTUP_ROLE` (agent-spoke default role), `LM_ONBOARDING_PSK`, `LM_TENANT_ID_HINT`.

## Install flags

- `agent/install_agent.sh`: `--hub` (optional; omit/`auto` → auto-discover), `--id` (default `agent-<hostname>`), `--secret`, `--hub-secret`, `--role <one>` / `--roles <csv>` (merged + de-duplicated; roles: `dns|dhcp|network|netbox|opnsense|ldap|simulation|cppm|proxmox|le|console|truenas`), `--loopback` (co-located with hub), `--clone` (stage + enable but leave stopped), `--tls-verify` (+ optional `--tls-ca-cert`). Roles persist in `.env` `LOADED_ROLES`. See [install-flags.md](install-flags.md) for the full canonical flag list.

## Key commands / handlers

- **Agent-spoke `_ROLE_MAP`** (13 hosted roles — rel_path, class, module_type, repo):
  - `dns` → `dns/src/dns_spoke.py::DNSSpoke` (`dns`, in-repo)
  - `dhcp` → `dhcp/src/dhcp_spoke.py::DHCPSpoke` (`dhcp`, in-repo)
  - `console` → `console/src/console_spoke.py::ConsoleSpoke` (`console`, in-repo)
  - `statuspage` → `statuspage/src/statuspage_spoke.py::StatusPageSpoke` (`statuspage`, in-repo) — one-tenant public status page; serves its own HTTPS page (fastapi/uvicorn), hub pushes the tenant's redacted `STATUS_SNAPSHOT`.
  - `network` → `nw/src/nw_spoke.py::NwSpoke` (`nw`, `lbockenstedt/nw.git`)
  - `netbox` → `netbox/src/netbox_spoke.py::NetboxSpoke` (`ipam`, `lbockenstedt/netbox.git`)
  - `opnsense` → `opnsense/src/opn_spoke.py::OpnSpoke` (`firewall`, `lbockenstedt/opnsense.git`)
  - `ldap` → `ldap/src/ldap_spoke.py::LdapSpoke` (`directory`, `lbockenstedt/ldap.git`)
  - `simulation` → `cs/lm-spoke/src/cs_spoke.py::CSSpoke` (`simulation`, `lbockenstedt/cs.git`)
  - `cppm` → `cppm/src/spoke.py::CPPMSpoke` (`nac`, `lbockenstedt/cppm.git`)
  - `proxmox` → `pxmx/src/proxmox_spoke.py::ProxmoxSpoke` (`hypervisor`, `lbockenstedt/pxmx.git`)
  - `le` → `le/src/le_spoke.py::LESpoke` (`certificates`, `lbockenstedt/le.git`)
  - `truenas` → `truenas/src/truenas_spoke.py::TruenasSpoke` (`storage`, `lbockenstedt/truenas.git`) — manages/reports on TrueNAS appliances over the official WebSocket JSON-RPC client (`truenas_api_client`); pools, datasets, shares (SMB/NFS), disks, alerts, services, capacity + gated writes (create/delete datasets, create shares, snapshots, scrubs). Mirrors `nw` (fleet-poll spoke + cache twin) and `le` (per-tenant API-key store).
  - `_DEPLOY_ROLES` (2 — run their own installer as a background subprocess, module_type `agent`, not hosted sub-spokes): `bugfixer` (curl|bash `lbockenstedt/bugfixer` `install.sh`), `netbox-server` (curl|bash `lbockenstedt/netbox` `install.sh --infra-only` — deploys the NetBox *application*; the separate `netbox` IPAM role sub-spoke talks to it).
  - `_RoleAdapter` wraps non-BaseSpoke roles (e.g. cppm). `LOAD_ROLE`/`UNLOAD_ROLE`/`UPDATE_CONFIG` handling; `_load_role_class`/`_sync_load_role`/`_install_role` (git clone + venv pip install).

## Key files

`agent/src/agent_spoke.py`, `agent/src/control_plane.py`, `agent/install_agent.sh`. (The legacy `generic_agent/` directory — leaf agent, its `install_github.sh`, and the 4th vendored `hub_discovery.py` copy — was removed in commit `3ddda2c`.)

## Notable behaviors & gotchas

- **Boot `--role` does NOT run `_install_role`** — `install_agent.sh` stages a boot `--role`/`--roles` but only pre-installs system packages; the role class loads on first `LOAD_ROLE` from the hub (staged roles auto-load at startup).
- **9 sibling repos auto-clone on `LOAD_ROLE`** — `dns`/`dhcp`/`console` ship in-repo (staged from the `/opt/lm` clone); the other 9 roles (`network`, `netbox`, `opnsense`, `ldap`, `simulation`, `cppm`, `proxmox`, `le`, `truenas`) clone from their own GitHub repos. Covers every canonical hub module type except `agent`.

## How it works

- **One base connection, many sub-spokes.** The agent's primary WebSocket connection to
  the hub always stays `module_type "agent"` — it never morphs. When a role is loaded,
  the agent opens a *second*, independent WebSocket connection (a `RoleConnection`,
  `agent/src/control_plane.py::RoleConnection`) under the sub-spoke id `{agent}-{role}`
  (e.g. `agent-svr-02-dns`) carrying the role's real `module_type` (`dns`, `dhcp`, `nw`,
  `ipam`, `firewall`, `directory`, `simulation`, `nac`, `hypervisor`, `certificates`,
  `console`, `storage`). The hub routes commands to that role purely by `module_type`/spoke id,
  exactly as it would to any dedicated spoke.
- **Parent-auto-approve.** A `RoleConnection` sends `parent_spoke_id` (the base agent's
  id) in its auth frame instead of an install UUID. Because the base agent is already
  admin-approved, the hub auto-approves the sub-spoke and binds it to the parent's
  tenant — no separate manual approval click per role. This is also why, in the WebUI,
  one physical box can show up as several entries: the base agent under **Setup →
  Agents**, plus one Spoke row per loaded role under that role's own module page (DNS,
  DHCP, NetBox, etc.) — they are the same box, split by connection.
- **`LOAD_ROLE` / `UNLOAD_ROLE`.** On `LOAD_ROLE {role: "dns"}` the agent (1) clones the
  sibling repo if the role isn't in-repo yet (`dns`/`dhcp`/`console` ship inside the `lm`
  clone; `network`, `netbox`, `opnsense`, `ldap`, `simulation`, `cppm`, `proxmox`, `le`,
  `truenas` are separate GitHub repos cloned into `/opt/lm/<dir>`), (2) installs any system
  packages the role needs (e.g. `unbound` for dns, `kea-dhcp4-server` for dhcp,
  `certbot` for le) and pip-installs the role's `requirements.txt` into the agent's
  shared venv, (3) instantiates the real spoke class and — for a role whose class isn't
  a `BaseSpoke` subclass (currently `cppm`) — wraps it in `_RoleAdapter` so command
  dispatch and status reporting stay uniform, and (4) spawns the `RoleConnection` and
  starts it as a background task. `UNLOAD_ROLE` cancels that task and closes its socket;
  the role stops appearing as a spoke but the base agent stays connected.
  **`bugfixer` is a *deploy* role**, not a hosted role: `LOAD_ROLE {role: "bugfixer"}`
  runs bugfixer's own `install.sh` as a background subprocess instead of hosting a
  sub-spoke — the deployed bugfixer service then connects to the hub independently
  under its own agent id.
- **Durability.** The set of currently-loaded roles is persisted to `.env` as
  `LOADED_ROLES` (comma list) every time a role is loaded/unloaded. A self-update
  (`SPOKE_UPDATE`) restarts the whole agent process; on the next boot `LOADED_ROLES` is
  read back and every role is re-loaded automatically, so a self-update or reboot never
  silently drops a role.
- **Mutual auth + reconnect.** Both the base connection and every `RoleConnection`
  perform the standard hub mutual-auth handshake (`HUB_VERIFIED`/`HUB_OK`) and
  reconnect with backoff on a dropped socket. If the hub is unreachable at boot, the
  agent (and any role connection) keeps retrying — including via mDNS/DNS
  re-discovery — instead of giving up.

## How to use it

1. **Install the agent on a new node** (as root on the target box):
   ```
   curl -sSL https://raw.githubusercontent.com/lbockenstedt/lm/main/agent/install_agent.sh \
     | sudo bash -s -- --hub wss://HUB_IP:443/ws/spoke [--id my-agent-1] [--roles dns,dhcp]
   ```
   Omit `--hub` (or pass `auto`) to let the box auto-discover the hub. Omit `--roles`
   entirely to install a bare agent and assign roles later from the WebUI — this is the
   normal path for a general-purpose node. If no `--secret` is given, the agent connects
   zero-touch and waits for an admin to approve it in **Setup → Spoke Approvals**.
2. **Load a role from the WebUI** (preferred over the boot flag for a running agent):
   go to **Setup → Agents**, find the agent, choose **Load Role**, pick the role (one of
   `dns`, `dhcp`, `network`, `netbox`, `opnsense`, `ldap`, `simulation`, `cppm`,
   `proxmox`, `le`, `console`, or the deploy role `bugfixer`). The agent installs deps
   and opens the sub-spoke; within a few seconds it shows up as a Spoke under that
   role's own module page.
3. **Unload a role:** same **Setup → Agents** panel, **Unload Role**. The sub-spoke
   disconnects immediately and is removed from `LOADED_ROLES`, so it will not come back
   on the next restart.
4. **Multi-role box:** repeat step 2 for each additional role — one agent can host
   `dns` + `dhcp`, or any other combination, simultaneously.

## Troubleshooting / common questions

- **"Load Role failed" / role won't load.** The most common causes are a failed
  `git clone` of the sibling repo (network/DNS access to github.com from that node) or a
  failed `pip install -r requirements.txt` for the role. Check `/var/log/lm/lm-agent.log`
  on the node — `_install_role` logs the exact clone or pip error and returns it in the
  `LOAD_ROLE` response shown in the WebUI.
- **Agent shows offline/red in the WebUI.** That's the base `agent` connection, not a
  role. Check that the `lm-agent` systemd unit is running on the node
  (`systemctl status lm-agent`) and that it can reach the hub's `wss://<hub>:443/ws/spoke`.
  A role can still show connected even if its parent looks briefly stale, but a role can
  never be approved before its parent agent is approved.
- **"Why does my one box show up as multiple entries?"** By design: the physical agent
  is one entry under **Setup → Agents** (`module_type "agent"`), and each loaded role is
  a *separate* Spoke entry under its own module type's page (e.g. a box running
  `dns`+`dhcp` shows one Agent row plus a DNS spoke row plus a DHCP spoke row). They
  share the same underlying process but are different hub connections.
- **"I passed `--roles` at install time but the role didn't actually load anything."**
  A boot-time `--role`/`--roles` on `install_agent.sh` only *stages* the role — it
  clones the sibling repo and installs its Python/system deps ahead of time so the
  agent can load quickly at boot. The role class itself is only instantiated and its
  `RoleConnection` opened on the first `LOAD_ROLE` the agent processes (which happens
  automatically at startup for staged roles, or later from the hub WebUI). If a staged
  role never shows up as a spoke, check the agent's boot log for the startup-role
  `LOAD_ROLE` result.
- **cppm role behaves oddly / missing status.** `cppm`'s spoke class isn't a
  `BaseSpoke` subclass, so it's wrapped in `_RoleAdapter`. If it's missing a
  `get_status()` implementation, `_RoleAdapter` supplies a minimal `READY` status so
  the hub still sees it as live — this is expected, not a bug.

## Related pages

[architecture-topology.md](architecture-topology.md), [lm-hub.md](lm-hub.md), [install-flags.md](install-flags.md).