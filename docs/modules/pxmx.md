# Proxmox Module Guide

The Proxmox module integrates the Hub with Proxmox VE clusters to provide a "Stitched View" of virtual machines, combining virtualization data with network security data from other spokes. It registers as `module_type="hypervisor"`. The Proxmox spoke source lives in the sibling `pxmx` repo and is cloned into `/opt/lm/pxmx` by `install_pxmx.sh`; this repo ships the installer and the Hub-side routing.

## 1. Capabilities
- **VM Inventory**: Listing all VMs across the cluster.
- **VM Details**: Fetching resources (CPU, RAM, Disk) and status.
- **Stitched View**: A unique feature that maps a VM's Proxmox ID to its current IP and then queries the OPNsense spoke to find all firewall rules currently applying to that specific IP.
- **USB Auto-Provisioning**: the auto-provisioning "brain" runs in the **pxmx host agent**, not the Hub — the Hub only configures/gates it via the `/sim/api/*tenant*/toggle-auto-provision` and `usb-provisioning-status` routes (see [api.md](../api.md) §Simulations).

## 2. Configuration
Configuration is managed via **Setup $\rightarrow$ Proxmox Configuration**.

### Required Fields
- **Default Node**: The Proxmox node to query by default.
- **Cluster ID**: The identifier for the PVE cluster.

## 3. Technical Implementation
The spoke communicates with the Proxmox API. The Hub orchestrates the "Stitched View" by:
1. Querying the Proxmox spoke for the VM's current IP.
2. Using that IP to query the OPNsense spoke for applicable firewall rules.
3. Aggregating the results into a single UI component.

## 4. Agent

The Proxmox host agent is a lightweight service that runs on each PVE node,
connects to the hub's **`/ws/agent` route on :443** (the hub byte-proxies the
frames to the co-located pxmx spoke's loopback agent listener), authenticates with a
shared `agent_secret`, and pushes telemetry (VM list, node stats) periodically.
The agent is installed from the sibling `pxmx` repo — see
[agent.md](agent.md) for the generic LM host-agent model and the
`pxmx/ARCHITECTURE.md` reference in [api.md](../api.md) §Simulations.

### Install command (printed by `install_pxmx.sh`)

Run on **each Proxmox node** after the spoke is installed:

```bash
curl -sSL https://raw.githubusercontent.com/lbockenstedt/pxmx/main/agent/install_agent.sh \
  | sudo bash -s -- \
  --spoke-url wss://<hub-ip>:443/ws/agent \
  --id pxmx-agent-$(hostname)
```

The agent appears as **Pending** in the WebUI (Setup → Spokes & Agents →
Agents tile); approve it there and the authentication secret is provisioned
automatically.

## 5. Commands

The spoke handles the following Hub commands (hypervisor contract — a KVM spoke
that ships later would implement the same set; see [installation.md](../installation.md)
§Co-Existence):

| Command | Description |
|---------|-------------|
| `PXMX_LIST_VMS` / `GET_VM_LIST` | VM list from all connected agents |
| `SEARCH_VMS` | Filter VMs by name or `unique_id` fragment |
| `GET_NODE_STATS` | CPU/RAM stats per node |
| `GET_AGENTS` | List connected agents |
| `GET_VM_INFO` | Details for a specific VM |
| `PXMX_VM_ACTION` | `start` / `stop` / `reboot` a VM |

Hub REST surface for these: see [api.md](../api.md) §"Proxmox / KVM (Hypervisor)"
(`/api/pxmx/*`).

## 6. Logging

Logger names: `ProxmoxSpoke` / `PxmxControlPlane`. Log file:
`/var/log/lm/lm-pxmx.log`. Format and full log table: see
[log_format.md](../log_format.md). The agent's `AGENT_LOG` messages are relayed
to the Hub and forwarded to BugFixer via the hub log relay.
