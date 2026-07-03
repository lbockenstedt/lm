# NetBox Module Guide

NetBox is a first-class Lab Manager spoke **and** the IPAM (IP Address
Management) source that feeds the IPAM → ClearPass endpoint sync. It registers
as `module_type="ipam"`. The spoke source lives in a sibling repository
(`github.com/lbockenstedt/netbox.git`); `install_all.sh` clones it under
`/opt/lm/netbox/` and runs `/opt/lm/netbox/install.sh` (with `--spoke-only`).
A local stub also exists at `provisioning_repos/netbox/install.sh` in this
tree, but the path actually invoked by the installer is the cloned one.

## 1. Roles

1. **IPAM spoke** — answers the Hub's NetBox/IPAM read commands (devices,
   prefixes, IPs, racks, tenants) for the WebUI and cross-system search.
2. **IPAM source for the CPPM endpoint sync** — when `source: "netbox"` is
   selected in the IPAM → ClearPass Endpoint Sync config, the Hub pulls
   per-tenant IP records from this spoke and pushes them to the CPPM spoke.
   The full sync contract (request/response shape, `replace: true` semantics,
   trigger model, per-tenant status) is documented in
   [cppm.md](cppm.md) §"IPAM → ClearPass Endpoint Sync (`CPPM_SYNC_ENDPOINTS`)"
   and the `Hub.IPAM_SOURCES` registry is defined in `core/src/main.py`.
3. **Sink for the Hypervisor → IPAM VM sync** — `NETBOX_SYNC_VMS` writes
   tenant-tagged virtualization records mirroring live Proxmox VMs (`replace:
   true`, matched by a `proxmox_unique_id` custom field). Driven by
   `Hub.HYPERVISOR_SOURCES` / `FwDiscoverySyncMixin`'s sibling `VmSyncMixin`
   (`core/src/vm_sync.py`); surfaced as the Setup → Sync "Hypervisor → IPAM
   Sync" card.
4. **Sink for the Firewall → IPAM device-discovery sync** — `NETBOX_SYNC_DEVICES`
   writes tenant-tagged DCIM devices + IP records for what the firewall
   (OPNsense) sees on the network (DHCP leases + ARP table, attributed to the
   tenant by prefix containment). Each created device carries
   `custom_fields.discovered_from = "opnsense"` (the replace-delete ownership
   marker) and its `mgmt` IP carries `custom_fields.mac_address` — which feeds
   the IPAM→CPPM endpoint sync so static-IP devices DHCP can't see reach
   ClearPass. `replace: true` + a tenant slug → the spoke overwrites that
   tenant's discovered-device set (stale ones deleted); global/unscoped sync
   skips delete. Driven by `Hub.FIREWALL_DISCOVERY_SOURCES` /
   `FwDiscoverySyncMixin` (`core/src/fw_discovery_sync.py`); surfaced as the
   Setup → Sync "Firewall → IPAM Sync" card. See
   [opnsense.md](opnsense.md) §"Firewall → NetBox Device Discovery Sync".

## 2. Commands

The spoke handles the following Hub commands (the `get_ips_command` for the
sync is `NETBOX_GET_IPS`; the Hub resolves it via `Hub.IPAM_SOURCES["netbox"]`):

| Command | Description |
|---------|-------------|
| `NETBOX_GET_DEVICES` | List devices (optional site / rack / tenant scope) |
| `NETBOX_GET_PREFIXES` | List IP prefixes (optional site / vrf / tenant scope) |
| `NETBOX_GET_IPS` | List IP addresses for a tenant — **the IPAM-sync pull command**. Response shape: `{"status": "SUCCESS", "ip_addresses": [{address, custom_fields.mac_address, dns_name}, ...]}` for `{"tenant": <netbox_tenant_slug>}`. |
| `NETBOX_GET_RACKS` | List racks |
| `NETBOX_GET_TENANTS` | List NetBox tenants (used by the Hub's tenant-import flow, `core/src/main.py`) |

Hub REST surface for these (caches under `core/src/api.py`):
`GET /api/netbox/devices`, `/api/netbox/prefixes`, `/api/netbox/ips` — see
[api.md](../api.md) §"NetBox / IPAM".

## 3. Configuration

NetBox is configured as one entry in the Hub's **`ipam_instances`** list
(migrated from the legacy single `global_config.netbox` key, which is cleared).
On spoke reconnect the Hub re-pushes the config derived from the list via
`push_config_to_spoke` (`core/src/main.py`, `_type_to_key` map:
`ipam → "netbox"`); the per-instance shape is normalized in `main.py` to:

```json
{
  "netbox_url":   "https://netbox.example.com",
  "netbox_token": "<read-only API token>",
  "tenant_slug":  "<per-tenant NetBox slug>"
}
```

Per-tenant scoping uses the tenant's `netbox_tenant_slug` field
(`GET /api/tenant/scoping?tenant=…`). If a spoke comes up `host not configured`
on reconnect despite the UI showing it configured, see
[operations.md](../operations.md) runbook (c) — the Hub must re-push from the
`ipam_instances` list on reconnect.

### ClearPass-side reference
ClearPass Context Server Actions that resolve an endpoint's NetBox tenant are in
`clearpass/netbox-tenant-context-server-action.json` (importable CSA bundle) —
see `clearpass/README.md` for the placeholder-replacement and import steps.

## 4. Installation

The spoke source is cloned from `github.com/lbockenstedt/netbox.git` by
`install_all.sh` (under `/opt/lm/netbox/`), which then runs its `install.sh`
with `--spoke-only`. To install just the NetBox spoke by hand, clone the
sibling repo first and run its installer:

```bash
git clone https://github.com/lbockenstedt/netbox.git /opt/lm/netbox
sudo bash /opt/lm/netbox/install.sh --spoke-only \
  --hub wss://<hub-ip>:443/ws/spoke \
  --id netbox-spoke-1 \
  --secret <first-secret>
```

Installs under `/opt/lm/netbox/` and provisions the `lm-netbox` systemd unit.
The installer requires `--hub`, `--id`, and `--secret` (no unauthenticated
zero-touch path for this spoke).

## 5. Logging

Logger names: `NetboxSpoke` / `NetboxControlPlane`. Log file:
`/var/log/lm/lm-netbox.log`. Format and full log table: see
[log_format.md](../log_format.md).