# 🌐 Lab Manager (LM)

Lab Manager is a centralized orchestrator for remote node management, designed as a hub-and-spoke architecture. It allows for the centralized control of various "Spokes"—specialized plugins that manage different infrastructure components.

## 🚀 Quick Start

### Single Line Installation (Native/LXC)
Launch the entire stack (Hub, WebUI, CS, PXMX, and OPNsense) as native processes:

```bash
curl -sSL https://raw.githubusercontent.com/lbockenstedt/lm/main/install_all.sh | bash
```

#### Modular Installation (Native)
Prefer to install only specific components? These installers can be run on separate LXC containers:

**Core Hub & UI** (Runs the API and serves the Dashboard)
```bash
curl -sSL https://raw.githubusercontent.com/lbockenstedt/lm/main/install_hub.sh | bash
```

**Client Simulator**
```bash
curl -sSL https://raw.githubusercontent.com/lbockenstedt/cs/main/install_cs.sh | bash
```

**Proxmox Manager**
```bash
curl -sSL https://raw.githubusercontent.com/lbockenstedt/pxmx/main/install_pxmx.sh | bash
```

**OPNsense Manager**
```bash
curl -sSL https://raw.githubusercontent.com/lbockenstedt/opnsense/main/install_opnsense.sh | bash
```

**Access Points:**
- **Web Dashboard**: `http://localhost:5173`
- **Hub WebSocket**: `ws://localhost:8765`
- **Hub API**: `http://localhost:8000`

---

## 📦 Architecture & Modules

Lab Manager is composed of several independent modules, each runnable as a container or an LXC guest.

### Core Components
- **Hub (`/hub`)**: The central logic queue and messaging center. Handles authentication (LDAP), message signing (HMAC), and global state management.
- **WebUI (`/ui`)**: A React-based dashboard for real-time monitoring and command issuance. Features an intuitive UI with native tooltips for deep-dive metadata.

### Plugin Modules (Spokes)
- **Client Simulator (`/cs`)**: Simulates network behaviors, DNS/DHCP failures, and traffic generation on client VMs.
- **Proxmox Manager (`/pxmx`)**: Direct integration with Proxmox VE for VM lifecycle management (cloning, snapshots, start/stop).
- **OPNsense Manager (`/opnsense`)**: Management of firewall rules and interface monitoring.

---

## 🛠️ Deployment Options

### Native/LXC Installation (Recommended for LXC)
The project is designed to run natively on Linux. The installation scripts automate the creation of Python virtual environments and Node.js setup.

**To start the system:**
Navigate to the `lm` directory and run:
```bash
./start_all.sh
```
This launches all components in the background.

**Managing the System:**
- **Monitoring**: Each module writes to a local log file (e.g., `hub.log`, `cs.log`). View them with:
  ```bash
  tail -f hub.log
  ```
- **Stopping Services**: To shut down the entire stack:
  ```bash
  pkill -f python && pkill -f node
  ```
- **Configuration**: To change Spoke secrets or Hub settings, edit the `keys.json` file in the `lm` directory and restart the services.

### Docker Compose
If you have a Docker environment with nesting enabled, you can still use Docker:
```bash
docker compose up -d
```

---

## 🛡️ Stability & Reliability
To ensure enterprise-grade stability, Lab Manager implements:
- **Exponential Backoff**: Spokes gracefully reconnect to avoid thundering herd issues.
- **Rate Limiting**: The Hub uses a token bucket algorithm to prevent telemetry floods from malfunctioning spokes.
- **Message Integrity**: Every command and status update is HMAC signed for security and authenticity.

## 📖 Developer Guide
To build a new plugin module:
1. Inherit from `BaseSpoke` in `lm/hub/src/base_spoke.py`.
2. Implement the `handle_command` and `get_status` methods.
3. Use `ControlPlane` to enable both Standalone (API) and Connected (WebSocket) modes.
