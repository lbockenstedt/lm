# OPNsense Module Guide

The OPNsense module provides centralized management of firewall rules, interfaces, DHCP leases, and DNS overrides for OPNsense appliances.

## 1. Capabilities
- **Firewall Rule Management**: Read, create, and delete rules across all interfaces.
- **Interface Monitoring**: Real-time status of network interfaces.
- **DHCP Tracking**: Visibility into current Kea DHCP leases.
- **DNS Management**: Management of Unbound DNS host overrides.
- **NAT Policies**: View of outbound NAT rules.
- **System Health**: Monitoring of CPU and Memory usage.

## 2. Configuration
The module is configured via the Hub WebUI under **Setup $\rightarrow$ Firewall Configuration**.

### Required Fields
- **Host**: The IP address or hostname of the OPNsense appliance.
- **Port**: The API port (default: `8443`).
- **API Key**: The OPNsense API key.
- **API Secret**: The OPNsense API secret.

## 3. Technical Implementation
The module uses an `OpnsenseEngine` which wraps the OPNsense REST API.

### Key API Endpoints Used
- `/api/firewall/filter/search_rule`: For fetching firewall rules.
- `/api/interfaces/overview/interfaces_info`: For interface status.
- `/api/kea/leases4/search`: For DHCP leases.
- `/api/unbound/settings/searchHostOverride`: For DNS overrides.

## 4. Troubleshooting
- **Empty Data**: If firewall rules are not appearing, ensure the API key has sufficient permissions and the `show_all=1` parameter is being sent.
- **Connection Errors**: The engine uses `curl` via subprocess to avoid Python network stack issues with certain OPNsense SSL configurations.
