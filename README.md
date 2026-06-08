# 🌐 Lab Manager (LM)

Lab Manager is a centralized orchestrator for remote node management, designed as a hub-and-spoke architecture. It provides a "single pane of glass" interface for managing multitenant infrastructure across various specialized spokes.

## 🚀 Deployment Overview

The system is optimized for **Proxmox LXC containers** and **Azure VMs** using a lean, native Python installation. It removes the need for Docker nesting and minimizes system overhead.

### ⚡ Quick Start (Full Stack)
To deploy the Hub, WebUI, and all default spokes on a single server:
```bash
curl -sSL https://raw.githubusercontent.com/lbockenstedt/lm/main/install_all.sh | bash
```

### 🧩 Modular Installation (Separate Containers)
For high-availability or distributed deployments, install components on separate LXC instances:

| Component | Installation Command | Role |
| :--- | :--- | :--- |
| **Hub Backend** | `curl -sSL https://raw.githubusercontent.com/lbockenstedt/lm/main/install_hub.sh \| bash` | Central API, State, & Messaging |
| **WebUI** | `curl -sSL https://raw.githubusercontent.com/lbockenstedt/lm/main/install_ui.sh \| bash` | Static Dashboard (via Hub) |
| **Client Sim** | `curl -sSL https://raw.githubusercontent.com/lbockenstedt/cs/main/install_cs.sh \| bash` | Traffic & DNS Simulation |
| **Proxmox** | `curl -sSL https://raw.githubusercontent.com/lbockenstedt/pxmx/main/install_pxmx.sh \| bash` | VM Lifecycle & Agent Server |
| **OPNsense** | `curl -sSL https://raw.githubusercontent.com/lbockenstedt/opnsense/main/install_opnsense.sh \| bash` | Firewall & Interface Mgmt |

#### 🤖 Proxmox Local Agent
The Proxmox module utilizes a local agent to gather real-time telemetry and execute host-level commands.
- **Installation**: `bash /root/lm/pxmx/agent/install_agent.sh --spoke-url ws://<SPOKE_IP>:8766`
- **Purpose**: Pushes CPU/RAM/Disk metrics and VM lists to the Spoke every 60s.
- **Connectivity**: Uses a persistent WebSocket session on port **8766**.

---

## 🖥️ Accessing the Dashboard

The Hub serves the WebUI natively. No separate build or installation is required.
- **Dashboard**: `http://<HUB_IP>:8000`
- **REST API**: `http://<HUB_IP>:8000/status`

---

## 🛠️ Management & Maintenance

### Starting the System
Navigate to the `lm` directory and launch the orchestrator:
```bash
cd /root/lm/lm
./start_all.sh
```

### Health & Regression Audits
Before pushing changes to GitHub, run the comprehensive static audit to ensure no broken imports or syntax errors:
```bash
/root/lm/audit/audit_all.sh
```
This tool verifies:
- ✅ **Import Integrity**: Checks for legacy paths (e.g., the old spoke source structure).
- ✅ **Dependency Alignment**: Ensures `requirements.txt` matches the code.
- ✅ **Python Syntax**: Compiles all files to detect runtime crashes.

### Stopping Services
```bash
pkill -f python
```

---

## 🛡️ Architecture Highlights
- **LXC-Native**: No Docker nesting required; runs directly on the OS.
- **Hub-and-Spoke**: Hub manages state; Spokes execute hardware-specific logic.
- **HMAC Security**: Every message between Hub and Spoke is signed for authenticity.
- **Multitenancy**: Native support for tenant-scoped resource mapping and quotas.

## 📖 Developer Guide
To build a new plugin module:
1. Inherit from `BaseSpoke` in `lm/hub/src/base_spoke.py`.
2. Implement the `handle_command` and `get_status` methods.
3. Use `ControlPlane` to enable both Standalone and Connected modes.
