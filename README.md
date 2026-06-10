# 🌐 Lab Manager (LM) - Project Master Registry

This repository serves as the central orchestrator for a Hub-and-Spoke management system. It is designed to provide a "single pane of glass" for managing multitenant infrastructure across various specialized spokes.

## 🗺️ Repository & Directory Map

The project is consolidated under the `/opt/lm` (on server) or local directory structure:

| Directory | Component | Description |
| :--- | :--- | :--- |
| `lm/core` | **Hub Backend** | Core API Server, State Management, WebSocket Control Plane, and Security (HMAC/Auth). |
| `lm/WebUI` | **Web Interface** | Dynamic dashboard, theme engine, and module configuration pages. |
| `pxmx` | **Proxmox Spoke** | Bridge between Hub and Proxmox cluster; manages the Local Agent. |
| `pxmx/agent` | **Proxmox Agent** | Lightweight host-level service for real-time telemetry and API execution. |
| `opnsense` | **OPNsense Spoke** | Firewall rule management and interface status reporting. |
| `cs` | **Client Sim Spoke** | Traffic and DNS simulation engine for network testing. |
| `cppm` | **CPPM Spoke** | ClearPass Policy Manager integration for endpoint and session auditing. |
| `audit/` | **Audit Suite** | Static analysis tools for imports, syntax, and dependency verification. |

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
- [ ] **CPPM Advanced Reporting**: Expand CPPM queries to include detailed session and endpoint analytics.
- [ la-manager ] **Client Sim Controls**: Build out the UI components for triggering and managing simulation profiles.
- [ ] **Telemetry Dashboards**: Create visual real-time graphs for the metrics pushed by the Proxmox Agent.

---

## 📝 Session Continuity Guide (For Claude)

**When resuming this project, always start by reading this file and the following:**
1. **`lm/core/src/main.py`**: To understand the current Hub logic and state.
2. **`lm/WebUI/main.js`**: To review the frontend routing and dynamic menu logic.
3. **`pxmx/src/proxmox_spoke.py`**: To see how the agent-bridge is implemented.
4.	**`audit/audit_all.sh`**: To verify the current build integrity before pushing changes.
5.	**`docs/`**: For technical specifications and user guides.

**Key Architectural Constraints:**
- **No CLI for Users**: All configuration must be handled via the WebUI.
- **Security First**: No message is processed without a valid HMAC signature.
- **LXC-Native**: Avoid Docker nesting; use native Python venvs and systemd units.
- **Stateful**: Hub is the source of truth; spokes are stateless executors.

---

## 🛠️ Maintenance Commands
- **Start All**: `./start_all.sh` (from root)
- **Audit System**: `bash audit/audit_all.sh`
- **Stop All**: `pkill -f python`
