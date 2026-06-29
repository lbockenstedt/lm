# 🌐 Lab Manager (LM) - Project Master Registry

This repository serves as the central orchestrator for a Hub-and-Spoke management system. It is designed to provide a "single pane of glass" for managing multitenant infrastructure across various specialized spokes.

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
| `cppm` | **CPPM Spoke** | ClearPass Policy Manager integration for endpoint and session auditing. Spoke source not in this repo — see [docs/modules/cppm.md](docs/modules/cppm.md). |

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
- [ la-manager ] **Client Sim Controls**: Build out the UI components for triggering and managing simulation profiles.
- [ ] **CPPM Advanced Reporting**: Expand CPPM queries to include detailed session and endpoint analytics.
- [ ] **Telemetry Dashboards**: Create visual real-time graphs for the metrics pushed by the Proxmox Agent.

---

## 📝 Session Continuity Guide (For Claude)

**When resuming this project, always start by reading this file and the following:**
1. **`core/src/main.py`**: To understand the current Hub logic and state (installed flat under `/opt/lm/core`, not nested `lm/core/src/...`).
2. **`WebUI/main.js`**: To review the frontend routing and dynamic menu logic (installed flat under `/opt/lm/WebUI`).
3. **`pxmx/src/proxmox_spoke.py`**: To see how the agent-bridge is implemented (sibling `pxmx` repo, cloned into `/opt/lm/pxmx`).
4.	**`docs/`**: For technical specifications and user guides — start with [docs/README.md](docs/README.md) and [docs/operations.md](docs/operations.md).

**Key Architectural Constraints:**
- **No CLI for Users**: All configuration must be handled via the WebUI.
- **Security First**: No message is processed without a valid HMAC signature.
- **LXC-Native**: Avoid Docker nesting; use native Python venvs and systemd units.
- **Stateful**: Hub is the source of truth; spokes are stateless executors.

---

## 🛠️ Maintenance Commands
- **Start All**: `./start_all.sh` (from root) — for dev. Production uses systemd: `sudo systemctl start lm`.
- **Stop All**: `sudo systemctl stop lm lm-pxmx lm-cs lm-opnsense lm-netbox lm-dhcp lm-dns` (stop the hub + every `lm-*` spoke unit that is enabled on this host).
- **Update / recover**: see [docs/operations.md](docs/operations.md) for the root helpers (`lm-self-restart`, `lm-update-restart`, `lm-spoke-recover`) and runbooks.

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
