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
- `/api/diagnostics/interface/search_arp`: For the ARP table (device discovery sync).
- `/api/unbound/settings/searchHostOverride`: For DNS overrides.

### Firewall → NetBox Device Discovery Sync
OPNsense is the **source** for the hub-orchestrated Firewall → IPAM device-discovery
sync (Setup → Sync, third card). Each cycle the hub pulls what the firewall
knows is on the network and pushes it to NetBox:

- `OPNSENSE_GET_DHCP_LEASES` — current Kea leases (dynamic IPs + hostnames).
  Accepts `{limit: 0}` to bypass the interactive 200-row cap (the sync wants the
  full set). Response `{"status":"SUCCESS","data":[{ip,hostname,mac,lease_end}]}`.
- `OPNSENSE_GET_ARP_TABLE` — the ARP table: every IP↔MAC pair the firewall has
  recently spoken to, including **static-IP devices DHCP can't see** (the gap
  that left their NetBox IP records without a `mac_address` and broke the
  IPAM→CPPM endpoint sync's IP→MAC resolution). Response
  `{"status":"SUCCESS","data":[{ip,mac,hostname,interface}]}`.

The hub merges/dedups the two (MAC-normalized, DHCP hostnames preferred),
attributes each device to a tenant by prefix containment, and pushes per-tenant
to the NetBox spoke via `NETBOX_SYNC_DEVICES`. The pull subset is configurable
(`source_data`: `both` / `dhcp` / `arp`); a `firewall_id` pins the pull to one
firewall. See `core/src/fw_discovery_sync.py` (`FwDiscoverySyncMixin`).

## 4. Troubleshooting
- **Empty Data**: If firewall rules are not appearing, ensure the API key has sufficient permissions and the `show_all=1` parameter is being sent.
- **Connection Errors**: The engine uses `curl` via subprocess to avoid Python network stack issues with certain OPNsense SSL configurations.
