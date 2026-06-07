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
| **Hub & UI** | `curl -sSL https://raw.githubusercontent.com/lbockenstedt/lm/main/install_hub.sh \| bash` | Central API, State, & Dashboard |
| **Client Sim** | `curl -sSL https://raw.githubusercontent.com/lbockenstedt/cs/main/install_cs.sh \| bash` | Traffic & DNS Simulation |
| **Proxmox** | `curl -sSL https://raw.githubusercontent.com/lbockenstedt/pxmx/main/install_pxmx.sh \| bash` | VM Lifecycle Management |
| **OPNsense** | `curl -sSL https://raw.githubusercontent.com/lbockenstedt/opnsense/main/install_opnsense.sh \| bash` | Firewall & Interface Mgmt |

---

## 🖥️ The WebUI (Static Deployment)

To maintain a zero-dependency footprint on the server, the WebUI is served as a **static build**. 

**1. Build the UI (on a Dev machine with Node.js):**
```bash
cd lm/ui
npm install
npm run build
```

**2. Deploy the Build:**
Upload the resulting `dist` folder to the Hub server at: `/root/lab-manager/lm/ui/dist`

**3. Access the Dashboard:**
The Hub uses Nginx to serve the UI on port 80.
- **Dashboard**: `http://<HUB_IP>/`
- **REST API**: `http://<HUB_IP>:8000`

---

## 🛠️ Management & Maintenance

### Starting the System
Navigate to the `lm` directory and launch the orchestrator:
```bash
cd /root/lab-manager/lm
./start_all.sh
```

### Health & Regression Audits
Before pushing changes to GitHub, run the comprehensive static audit to ensure no broken imports or syntax errors:
```bash
/root/lab-manager/audit/audit_all.sh
```
This tool verifies:
- ✅ **Import Integrity**: Checks for legacy `lm.spoke.src` paths.
- ✅ **Dependency Alignment**: Ensures `requirements.txt` matches the code.
- ✅ **Python Syntax**: Compiles all files to detect runtime crashes.

### Stopping Services
```bash
pkill -f python && pkill -f node
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
