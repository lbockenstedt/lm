# 📖 Lab Manager User Manual

## 🌟 Introduction
Lab Manager is a Hub-and-Spoke orchestration system designed to provide a single pane of glass for managing infrastructure like Proxmox, OPNsense, and Client Simulation tools.

## 🚀 Getting Started

### Installation
The system is designed for native LXC deployment. To install the entire stack:
```bash
curl -sSL https://raw.githubusercontent.com/lbockenstedt/lm/main/install_all.sh | bash
```

### Accessing the Interface
Once installed, the WebUI is available at:
`http://<HUB_IP>:8000`

## 🛠️ Administration

### Spoke Approval
New spokes are not allowed to communicate with the Hub until they are approved by an administrator.
1. Navigate to the **Setup** tab in the WebUI.
2. Locate the **Spoke Approvals** section.
3. Review pending spokes and click **Approve**.

### Theme & Branding
You can customize the visual identity of your Lab Manager instance via the UI:
*   Change primary colors.
*   Upload a custom logo (Left/Right).
*   Switch between themes (e.g., HPE, LCARS).

## 📡 Architecture Overview
*   **Hub**: The central control plane. Manages state and routing.
*   **Spokes**: Specialized modules that bridge the Hub to specific hardware/APIs.
*   **Agents**: Local services (like the Proxmox Agent) that gather telemetry and execute low-level commands on the target host.

## 🔍 Troubleshooting
*   **Logs**: Hub logs are available in `/root/lm/hub.log`.
*   **Connectivity**: Ensure port `8765` (WebSocket) and `8000` (REST API) are open between the Hub and Spokes.
*   **Auth Failures**: If a spoke fails to authenticate, verify the `first-secret` used during installation.
