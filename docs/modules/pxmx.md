# Proxmox Module Guide

The Proxmox module integrates the Hub with Proxmox VE clusters to provide a "Stitched View" of virtual machines, combining virtualization data with network security data from other spokes.

## 1. Capabilities
- **VM Inventory**: Listing all VMs across the cluster.
- **VM Details**: Fetching resources (CPU, RAM, Disk) and status.
- **Stitched View**: A unique feature that maps a VM's Proxmox ID to its current IP and then queries the OPNsense spoke to find all firewall rules currently applying to that specific IP.

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
