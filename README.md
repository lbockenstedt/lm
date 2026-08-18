# 🌐 Lab Manager (LM) - Project Master Registry

This repository serves as the central orchestrator for a Hub-and-Spoke management system. It is designed to provide a "single pane of glass" for managing multitenant infrastructure across various specialized spokes.

<!-- INSTALLERS:START -->
## Installation

Every installer in this repo, with every flag and environment variable it accepts.
Installers are idempotent — re-running one updates code and preserves credentials.

### Every module, one table

Each module is its own repo with its own installer. Unless noted, they take the
same core flags: `--hub`, `--id`/`--name`, `--secret`, `--hub-secret`,
`--all-prereqs`, and accept a bare hostname for `--hub`.

| Module | Installer | One-liner |
| :--- | :--- | :--- |
| **lm** (hub) | `install_menu.sh` | `curl -sSL https://raw.githubusercontent.com/lbockenstedt/lm/main/install_menu.sh \| sudo bash` |
| **agent** (any role) | `lm/agent/install_agent.sh` | `curl -sSL https://raw.githubusercontent.com/lbockenstedt/lm/main/agent/install_agent.sh \| sudo bash -s -- --hub HUB` |
| **cs** (simulation) | `cs/install_cs.sh` | `curl -sSL https://raw.githubusercontent.com/lbockenstedt/cs/main/install_cs.sh \| sudo bash -s -- --hub HUB` |
| **pxmx** (hypervisor) | `pxmx/install_pxmx.sh` | `curl -sSL https://raw.githubusercontent.com/lbockenstedt/pxmx/main/install_pxmx.sh \| sudo bash -s -- --hub HUB` |
| **pxmx agent** (Proxmox host) | `pxmx/agent/install_agent.sh` | `curl -sSL https://raw.githubusercontent.com/lbockenstedt/pxmx/main/agent/install_agent.sh \| sudo bash` |
| **netbox** (IPAM) | `netbox/install.sh` | `curl -sSL https://raw.githubusercontent.com/lbockenstedt/netbox/main/install.sh \| sudo bash -s -- --hub HUB` |
| **opnsense** (firewall) | `opnsense/install_opnsense.sh` | `curl -sSL https://raw.githubusercontent.com/lbockenstedt/opnsense/main/install_opnsense.sh \| sudo bash -s -- --hub HUB` |
| **cppm** (NAC) | `cppm/install.sh` | `curl -sSL https://raw.githubusercontent.com/lbockenstedt/cppm/main/install.sh \| sudo bash -s -- --hub HUB` |
| **ldap** (directory) | `ldap/install_ldap.sh` | `curl -sSL https://raw.githubusercontent.com/lbockenstedt/ldap/main/install_ldap.sh \| sudo bash -s -- --hub HUB` |
| **nw** (network devices) | `nw/install_nw.sh` | `curl -sSL https://raw.githubusercontent.com/lbockenstedt/nw/main/install_nw.sh \| sudo bash -s -- --hub HUB` |
| **le** (certificates) | `le/install_le.sh` | `curl -sSL https://raw.githubusercontent.com/lbockenstedt/le/main/install_le.sh \| sudo bash -s -- --hub HUB` |
| **truenas** (storage) | `truenas/install_truenas.sh` | `curl -sSL https://raw.githubusercontent.com/lbockenstedt/truenas/main/install_truenas.sh \| sudo bash -s -- --hub HUB` |
| **kvm** | `kvm/install_kvm.sh` | `curl -sSL https://raw.githubusercontent.com/lbockenstedt/kvm/main/install_kvm.sh \| sudo bash -s -- --hub ws://HUB:8765` |
| **qa** (auditor) | `qa/install_qa.sh` | `curl -sSL https://raw.githubusercontent.com/lbockenstedt/qa/main/install_qa.sh \| sudo bash -s -- --hub ws://HUB:8765` |
| **bugfixer** | `bugfixer/install.sh` | `curl -sSL https://raw.githubusercontent.com/lbockenstedt/bugfixer/main/install.sh \| bash -s -- wss://HUB` |
| **tsa** | `tsa/install.sh` | `curl -fsSL https://raw.githubusercontent.com/lbockenstedt/tsa/main/install.sh \| bash -s -- azure` |
| **dns**, **dhcp**, **henet** | Agent roles with host-prep installers | Standard path is loading the agent roles `dns` / `dhcp` / `henet`; DNS/DHCP host prep is provided by `dns/install_dns.sh` and `dhcp/install_dhcp.sh` when a direct role install is needed. |

`kvm` and `qa` are the two exceptions: they do **not** normalize a bare hostname,
so give them a full `ws://`/`wss://` URL.

### `install_menu.sh` — the single master installer (start here)

The one interactive entry point that drives every other installer. Menu options:
**1) Hub** (this box → hub + WebUI, with a co-located-spoke checklist),
**2) Agent** (remote node → pick the module role(s) to run now, or none and load
them later), **3) Proxmox Host Agent** (install/uninstall the pxmx node-agent that
reports to a pxmx/sim spoke), **4) Uninstall**. No flags.

```bash
curl -sSL https://raw.githubusercontent.com/lbockenstedt/lm/main/install_menu.sh | sudo bash
```

### Hub — `install_all.sh` (non-interactive)

What the menu calls underneath. Installs the hub and every co-located module.

```bash
sudo bash /opt/lm/install_all.sh --hub-only
```

| Flag | Purpose |
| :--- | :--- |
| `--reinstall` | Full reinstall rather than an in-place update. |
| `--reset-secrets` | Regenerate spoke secrets. |
| `--reset-users` | Reset WebUI user accounts. |
| `--exclude a,b,c` | Comma-separated modules to skip. |
| `--hub-only` | Hub and its self-update/watchdog/restart machinery only — shorthand for `--exclude cs,pxmx,opnsense,cppm,netbox,ldap,dns,dhcp,nw,le,henet`. Those then onboard as remote spokes. |
| `--tls-verify` | Verify TLS to the hub. |
| `--tls-ca-cert PATH` | CA certificate for that verification. |
| `--no-setup-token` | Leave first-run `/auth/setup` open instead of gating it behind `LM_SETUP_TOKEN`. Dev/loopback only. |

### Hub — `install_production.sh`

Hub plus the full spoke set (CS, NetBox, Proxmox, OPNsense, ClearPass, LDAP). No flags.

### Generic agent — `agent/install_agent.sh`

One agent **hosts many roles at once**: each loaded role opens its own sub-spoke
(`{spoke_id}-{role}`) that auto-approves through the agent. Assign roles from
the hub WebUI, or pre-load them here.

```bash
curl -sSL https://raw.githubusercontent.com/lbockenstedt/lm/main/agent/install_agent.sh \
  | sudo bash -s -- --hub lm-hub.lrbtechnologies.com --roles dns,dhcp
```

| Flag | Purpose |
| :--- | :--- |
| `--hub URL` | Hub WebSocket URL. |
| `--id` | Pin the agent id. |
| `--secret` | Pre-shared agent secret. |
| `--hub-secret` | Hub PSK for auto-approval. |
| `--role NAME` | Load a single role at boot. |
| `--roles a,b,c` | Load several roles at boot. |
| `--spoke-ip IP` | Address of the spoke this agent serves. |
| `--spoke-url URL` | Full spoke URL. |
| `--clone` | Golden-image prep — install without minting identity. |
| `--loopback` | Agent is co-located with the hub. |
| `--tls-verify` | Verify the hub certificate. |
| `--tls-ca-cert PATH` | CA certificate for that verification. |

Valid roles: `dns`, `dhcp`, `henet`, `network`, `netbox`, `opnsense`, `ldap`,
`simulation`, `cppm`, `proxmox`, `le`, `console`, `statuspage`, `proxy`,
`truenas`.

**Environment overrides:** `HUB_URL`, `SPOKE_ID`, `STARTUP_ROLES_CSV`, `LM_BRANCH`.

### Hub-native extras

| Installer | Purpose |
| :--- | :--- |
| `collab_sink/install_collab_sink.sh` | Hub-side UDP listener for Teams/Zoom/WebEx traffic simulation. Hub-native, not an agent role; stdlib-only, no venv. Called by `install_all.sh`. |
| `scripts/install-lm-watchdog.sh` | The hub auto-heal watchdog. Idempotent; run as root on the hub box: `sudo bash install-lm-watchdog.sh`. |
| `dns/install_dns.sh`, `dhcp/install_dhcp.sh` | Co-located Unbound DNS / Kea DHCP spokes. Flags: `--hub`, `--id`, `--secret`, `--infra-only`. |
| `henet/install_henet.sh` | Hurricane Electric public-DNS (`henet`) spoke — pure HE dyndns API client (no local server). Flags: `--hub`, `--id`, `--secret`. |

### Proxmox host agent — `pxmx/agent/install_agent.sh`

Runs on each Proxmox host. It reports to the **pxmx spoke** (not the hub
directly): pass the spoke's IP with `--spoke-ip` and the agent works out the
scheme/port/`/ws/agent` path by probing; omit it to auto-discover the box via
DNS (`lm-hub.<suffix>`) then mDNS. The id defaults to the hostname, so a
cloned+renamed node reconnects under its new name (correlated to the old id by
its install UUID).

```bash
curl -sSL https://raw.githubusercontent.com/lbockenstedt/pxmx/main/agent/install_agent.sh \
  | sudo bash -s -- --spoke-ip <pxmx-spoke-ip>
```

| Flag | Purpose |
| :--- | :--- |
| `--spoke-ip IP` | Address of the pxmx spoke this agent serves (preferred — agent auto-determines scheme/port/path). |
| `--spoke-url URL` | Fully-pinned `ws(s)://host:port/ws/agent` (legacy/advanced; wins over `--spoke-ip`). |
| `--id` | Pin the agent id (default: OS hostname). |
| `--secret` | Pre-shared agent secret. |

### Uninstall — `uninstall.sh` (master uninstaller)

Removes **every** LM-owned component on this box — hub, watchdog, generic agent,
all spoke roles, the pxmx host agent, the client-sim agents/dashboard, collab
sink, and BugFixer — plus their dirs, `/usr/local/bin` helpers, sudoers,
systemd drop-ins, and LM env values. Discovery-first and guarded: it prints
exactly what it will remove and requires a typed `REMOVE` confirmation. Shared
infrastructure (postgresql/redis/nginx/unbound/kea/slapd/certbot/ollama/…) and
host networking are **never** touched unless you opt in below. Destructive and
irreversible.

```bash
curl -sSL https://raw.githubusercontent.com/lbockenstedt/lm/main/uninstall.sh | sudo bash -s -- --yes
```

| Flag | Purpose |
| :--- | :--- |
| `--yes` / `-y` | Non-interactive — skip the typed confirmation (required when piped, no TTY). |
| `--dry-run` / `-n` | Preview only — change nothing. |
| `--ollama` | Also remove `ollama.service` + its override (BugFixer). |
| `--letsencrypt` | Also remove `/etc/letsencrypt` + its `var/lib`/`var/log` dirs. |
| `--netbox-db` | Also DROP the NetBox Postgres database + role. |
| `--nginx-site` | Also remove the NetBox nginx site (LM-owned file). |
| `--keep-bugfixer` | Do **not** remove BugFixer (it is removed by default here). |

> For a full single-host identity/state wipe (so a clone can **never** reconnect
> under an old id), `uninstall_lm.sh` is the universal per-host variant:
> `bash uninstall_lm.sh [--yes] [--dry-run] [--keep-logs] [--keep-crontab]`.
<!-- INSTALLERS:END -->

## 🗺️ Repository & Directory Map

The project is consolidated under the `/opt/lm` (on server) or local directory structure:

| Directory | Component | Description |
| :--- | :--- | :--- |
| `lm/core` | **Hub Backend** | Core API Server, State Management, WebSocket Control Plane, and Security (HMAC/Auth). Installed flat under `/opt/lm/core` (not nested `lm/core/src/main.py`). |
| `lm/WebUI` | **Web Interface** | Dynamic dashboard, theme engine, and module configuration pages. Installed flat under `/opt/lm/WebUI`. |
| `pxmx` | **Proxmox Spoke** | Bridge between Hub and Proxmox cluster; manages the Local Agent. Cloned from the sibling `pxmx` repo into `/opt/lm/pxmx` by `install_pxmx.sh`. |
| `pxmx/agent` | **Proxmox Agent** | Lightweight host-level service for real-time telemetry and API execution. |
| `opnsense` | **OPNsense Spoke** | Firewall rule management and interface status reporting. |
| `cs` | **Client Sim Spoke** | Traffic and DNS simulation engine for network testing. |
| `cppm` | **CPPM Spoke** | ClearPass Policy Manager integration for endpoint and session auditing. Spoke source not in this repo — see [docs/cppm.md](docs/cppm.md). |

---

## 🚀 Current Implementation State

### ✅ Completed Features
- **Hub Core**:
    - [x] WebSocket control plane for real-time Hub $\leftrightarrow$ Spoke communication.
    - [x] Persistent JSON state management for global config and approvals.
    - [x] Mutual authentication via First-Secret exchange.
    - [x] **Deterministic HMAC-SHA256 signing** to prevent serialization-driven signature mismatches.
    - [x] **Multi-tenant configuration model** for isolated resource quotas and settings.
    - [x] Dynamic Spoke Approval workflow (`Pending` $\rightarrow$ `Approved`).
    - [x] **System Diagnostics** providing real-time spoke health, versions, and authentication state.
- **WebUI**:
    - [x] Theme Engine (HPE Default, LCARS, Imperial) with CSS variables.
    - [x] Configurable logos (left/right) and primary colors via UI.
    - [x] Dynamic Menu rendering based on approved spokes.
    - [x] Configuration pages for all modules (Proxmox, OPNsense, CS, CPPM).
    - [x] Tenant management interface for creating and switching tenants.
- **Proxmox Integration**:
    - [x] Real API-based VM list and node telemetry gathering via Local Agent.
    - [x] Command bridging: `WebUI` $\rightarrow$ `Hub` $\rightarrow$ `Spoke` $\rightarrow$ `Agent` $\rightarrow$ `Proxmox API`.
- **Deployment**:
    - [x] `install_all.sh` for full-stack native installation.
    - [x] **Secure non-root service user (`svc_lm`)** for all Hub and Spoke processes.
    - [x] Standardized modular installers for individual spokes.
    - [x] Rebranded from `lm-manager` to `lm`.

### 🛠️ Active / Pending Tasks
- [ ] **OPNsense Deep Dive**: Implement full rule creation/deletion via UI (currently supports query).
- [ ] **Client Sim Controls**: Build out the UI components for triggering and managing simulation profiles.
- [ ] **CPPM Advanced Reporting**: Expand CPPM queries to include detailed session and endpoint analytics.
- [ ] **Telemetry Dashboards**: Create visual real-time graphs for the metrics pushed by the Proxmox Agent.

---

## 📝 Session Continuity Guide (For Claude)

**When resuming this project, always start by reading this file and the following:**
1. **`core/src/main.py`**: To understand the current Hub logic and state (installed flat under `/opt/lm/core`, not nested `lm/core/src/...`).
2. **`WebUI/main.js`**: To review the frontend routing and dynamic menu logic (installed flat under `/opt/lm/WebUI`).
3. **`pxmx/src/proxmox_spoke.py`**: To see how the agent-bridge is implemented (sibling `pxmx` repo, cloned into `/opt/lm/pxmx`).
4.	**`docs/`**: For technical specifications and user guides — start with [docs/README.md](docs/README.md) and [docs/architecture-topology.md](docs/architecture-topology.md).

**Key Architectural Constraints:**
- **No CLI for Users**: All configuration must be handled via the WebUI.
- **Security First**: No message is processed without a valid HMAC signature.
- **LXC-Native**: Avoid Docker nesting; use native Python venvs and systemd units.
- **Stateful**: Hub is the source of truth; spokes are stateless executors.

---

## 🛠️ Maintenance Commands
- **Start All**: `./start_all.sh` (from root) — for dev. Production uses systemd: `sudo systemctl start lm`.
- **Stop All**: `sudo systemctl stop lm lm-pxmx lm-cs lm-opnsense lm-netbox lm-dhcp lm-dns` (stop the hub + every `lm-*` spoke unit that is enabled on this host).
- **Update / recover**: see [docs/architecture-topology.md](docs/architecture-topology.md) for the update/rollback watchdog + self-update pipeline, and [docs/lm-hub.md](docs/lm-hub.md) for the spoke-recovery watchdog. The root helpers (`lm-self-restart`, `lm-update-restart`, `lm-spoke-recover`) are installed by `install_all.sh` into `/usr/local/bin/`.

> **Never** use `pkill -f python` to stop Lab Manager. It kills every `lm-*`
> service in one shot — hub, spokes, and agents alike — which is exactly the
> ungraceful outage the installer's per-unit `ExecStop` was fixed to avoid
> (see `install_all.sh` systemd unit `ExecStop` rationale). Use the systemd
> commands above so each unit tears down cleanly and its state is flushed.

---

## 📖 User Documentation

### 📖 Help: firewall-config
**Firewall Configuration**
- **Name**: A friendly label for the firewall (e.g., "Core-Edge-01").
- **Model**: The firewall vendor (currently supports `opnsense`).
- **Host/IP**: The management IP address of the firewall.
- **Port**: The API port (default for OPNsense is usually 8443).
- **API Key/Secret**: Generated from the firewall's administrative interface under System $\rightarrow$ Access $\rightarrow$ Users.

### 📖 Help: ldap-config
**LDAP Integration**
- **Server URL**: The full LDAP provider URL (e.g., `ldap://corp-dc.local:389`).
- **Base DN**: The starting point for user searches (e.g., `dc=example,dc=com`).
- **Admin DN**: The distinguished name of the user used to bind to the LDAP server.
- **Admin Password**: The password for the bind user.

### 📖 Help: tenant-quotas
**Resource Quotas**
- **VM Quota**: Maximum number of Virtual Machines this tenant can associate.
- **CPPM Quota**: Maximum number of endpoints allowed in the Policy Manager.
- **OPNsense Quota**: Maximum number of firewall instances mapped to this tenant.
