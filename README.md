# 🌐 Lab Manager (LM)

Lab Manager is a centralized orchestrator for remote node management, designed as a hub-and-spoke architecture. It allows for the centralized control of various "Spokes"—specialized plugins that manage different infrastructure components.

## 🚀 Quick Start

### Single Line Installation
Launch the entire stack (Hub, WebUI, CS, PXMX, and OPNsense) using Docker:

```bash
curl -sSL https://raw.githubusercontent.com/lbockenstedt/lm/main/install_all.sh | bash
```

#### Modular Installation
Prefer to install only specific components? Use these targeted installers:

**Core Hub & WebUI**
```bash
curl -sSL https://raw.githubusercontent.com/lbockenstedt/lm/main/install_hub.sh | bash
```

**Client Simulator**
```bash
curl -sSL https://raw.githubusercontent.com/lbockenstedt/lm/main/install_cs.sh | bash
```

**Proxmox Manager**
```bash
curl -sSL https://raw.githubusercontent.com/lbockenstedt/lm/main/install_pxmx.sh | bash
```

**OPNsense Manager**
```bash
curl -sSL https://raw.githubusercontent.com/lbockenstedt/lm/main/install_opnsense.sh | bash
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

### Docker Compose (Recommended)
If you have cloned the repositories manually, navigate to the `lm` directory and run:
```bash
docker compose up -d
```
This will launch all modules defined in the compose file, provided the other repositories (`cs`, `pxmx`, `opnsense`) are located in the parent directory of `lm`.

### Proxmox LXC
For bare-metal performance, use the provided LXC bootstrap scripts:
```bash
# Example for Hub
./scripts/setup-lxc-hub.sh
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
