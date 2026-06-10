# 📖 Lab Manager User Manual

## 🌟 Introduction
Lab Manager is a Hub-and-Spoke orchestration system designed to provide a single pane of glass for managing infrastructure like Proxmox, OPNsense, and Client Simulation tools.

## 🚀 Getting Started

### Installation
The system is designed for native LXC deployment. To install the entire stack:
```bash
curl -sSL https://raw.githubusercontent.com/lbockenstedt/lm/main/install_all.sh | bash
```
The installer creates a secure non-root system user, `svc_lm`, to run the Hub and Spoke processes, ensuring that the orchestrator does not run with unnecessary root privileges.

### Accessing the Interface
Once installed, the WebUI is available at:
`http://<HUB_IP>:8000`

## 🛠️ Administration

### Spoke Approval
New spokes are not allowed to communicate with the Hub until they are approved by an administrator.
1. Navigate to the **Setup** tab in the WebUI.
2. Locate the **Spoke Approvals** section.
3. Review pending spokes and click **Approve**.

### Tenant Management
Lab Manager supports multi-tenancy to provide isolated resource quotas and settings.
1. Navigate to **Setup** $\rightarrow$ **Tenant Config**.
2. **Create Tenant**: Use the "Add" field to create a new Tenant ID.
3. **Configure Tenant**: Select a tenant from the list to edit its display name and set resource quotas (VMs, Firewall Rules, CPPM Policies).
4. **Switch Active Tenant**: Use the "Active Tenant" checkbox in the editor or the selector in the General setup page to change which tenant is currently active on the Hub.

### System Diagnostics
The **System** $\rightarrow$ **Diagnostics** tab provides a real-time health check of all known spokes.
- **Authentication**: Verifies if the spoke has successfully completed the handshake.
- **Approval**: Shows if the spoke has been approved by an administrator.
- **State**: Displays the current WebSocket connection state (e.g., `CONNECTED`, `OFFLINE`).
- **Version**: Reports the current software version of the spoke.
- **Last Error**: Shows the last recorded error for spokes in an `ERROR` or `OFFLINE` state.

### Theme & Branding
You can customize the visual identity of your Lab Manager instance via the UI:
*   Change primary colors.
*   Upload a custom logo (Left/Right).
*   Switch between themes (e.g., HPE Default, LCARS, Imperial).

## 📡 Architecture Overview
*   **Hub**: The central control plane. Manages state and routing.
*   **Spokes**: Specialized modules that bridge the Hub to specific hardware/APIs.
*   **Agents**: Local services (like the Proxmox Agent) that gather telemetry and execute low-level commands on the target host.

## 🔍 Troubleshooting
*   **Logs**: Hub and Spoke logs are now centrally located in `/var/log/lm/`. Use `cat /var/log/lm/hub.log` or `journalctl -u lm` to diagnose issues.
*   **Connectivity**: Ensure port `8765` (WebSocket) and `8000` (REST API) are open between the Hub and Spokes.
*   **Auth Failures**: If a spoke fails to authenticate, verify the `first-secret` used during installation.
