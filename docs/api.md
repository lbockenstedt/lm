# REST API Reference

The Lab Manager Hub provides a REST API for the WebUI and integrations.

## Authentication

All `/setup` POST, PUT, and DELETE endpoints require `X-Admin-Token` when `LM_ADMIN_TOKEN` is configured on the hub.

```
X-Admin-Token: <value-of-LM_ADMIN_TOKEN>
```

`/setup/generate-secret` is exempt (spokes call it at install time using `--admin-token`).

## 1. General

- **Base URL**: `https://<hub-ip>:443`
- **Format**: `application/json`

---

## 2. Setup & Configuration

### System Status
| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/status` | Hub status: connections, heartbeat health, system metrics |
| `GET` | `/setup/config` | Global configuration |
| `POST` | `/setup/config` | Update global configuration |
| `GET` | `/setup/diagnostics` | Detailed health report for all known spokes |
| `GET` | `/setup/api-probe?spoke_id=…&path=…` | Raw API probe against a spoke's local API |
| `GET` | `/setup/debug-mode` | Whether debug logging is enabled |
| `POST` | `/setup/debug-mode` | Toggle debug logging: `{ "enabled": true }` |

### Spoke Management
| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/setup/pending_spokes` | All spokes with approval status |
| `POST` | `/setup/approve_spoke` | Approve/unapprove a spoke: `{ "spoke_id": "…", "action": "approve"\|"unapprove" }` |
| `POST` | `/setup/spoke-name` | Rename a spoke: `{ "spoke_id": "…", "display_name": "…" }` |
| `GET` | `/setup/modules` | Available modules and install status |
| `POST` | `/setup/install-module` | Trigger module installation (background): `{ "module_id": "ldap", "spoke_id": "ldap-1", "display_name": "…" }` |
| `POST` | `/setup/spokes/{spoke_id}/reset-secret` | Delete spoke's stored secret (force re-onboard) |
| `POST` | `/setup/spokes/{spoke_id}/rotate-secret` | Rotate secret and return new value (spoke must reconnect) |
| `POST` | `/setup/rotate-key/{spoke_id}` | **Preferred**: rotate + push new key to live spoke over WS. Returns `{ "pushed": bool }` |
| `POST` | `/setup/generate-secret` | Allocate first secret for a spoke at install time: `{ "spoke_id": "…" }` |

### Key Rotation Flow (`POST /setup/rotate-key/{spoke_id}`)
1. Hub generates new secret via `key_manager.rotate_key()`.
2. If spoke is online: sends `SPOKE_UPDATE_SESSION_KEY` — spoke updates signer and persists to `.env`.
3. If offline: secret stored; spoke picks it up on next connect.
4. Response: `{ "status": "success", "pushed": true|false, "message": "…" }`

### Tenant Management
| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/setup/tenants` | List all tenants |
| `GET` | `/setup/tenants/{tenant_id}` | Get tenant config |
| `POST` | `/setup/tenants` | Create tenant: `{ "tenant_id": "…", "display_name": "…" }` |
| `POST` | `/setup/tenant` | Update tenant config / set active |
| `GET` | `/api/tenant/scoping?tenant=…` | Returns spoke-scoping config for a tenant: `{ "netbox_tenant_slug", "proxmox_tag", "ldap_base_dn" }` |

---

## 3. Functional APIs

All functional endpoints accept an optional `?tenant=<tenant_id>` query param to scope results.

### Cross-System Search
```
GET /api/search?q=<query>&tenant=<tenant_id>
```
Fans out in parallel to IPAM, hypervisor, NAC, directory, and firewall spokes.

**Response:**
```json
{
  "query": "10.0.1.5",
  "query_type": "ip",
  "total": 3,
  "results": [
    { "source": "netbox", "type": "device", "name": "switch-01", "id": "…" },
    { "source": "pxmx",   "type": "vm",     "name": "web-vm-1", "id": "cluster/node/100" },
    { "source": "cppm",   "type": "session", "name": "…" }
  ],
  "spokes_queried": { "ipam": true, "hypervisor": true, "nac": true, "directory": true, "firewall": true }
}
```
`query_type` is `ip`, `mac`, or `name` based on the query format.

### Dashboard Summary
```
GET /api/dashboard/summary?tenant=<tenant_id>
```
Returns aggregate counts from all spokes for a tenant.

**Response:**
```json
{ "tenant": "acme", "devices": 42, "vms": 17, "sessions": 5, "prefixes": 8, "ips_used": 120 }
```

### NetBox / IPAM
| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/netbox/devices?site=…&rack=…&tenant=…` | List devices |
| `GET` | `/api/netbox/prefixes?site=…&vrf=…&tenant=…` | List IP prefixes |
| `GET` | `/api/netbox/ips?prefix=…&device=…&tenant=…` | List IP addresses |

### Proxmox / KVM (Hypervisor)
| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/pxmx/vms?tenant=…` | List all VMs (with Proxmox tag filter if tenant has `proxmox_tag`) |
| `GET` | `/api/pxmx/nodes` | Node stats from connected agents |
| `GET` | `/api/pxmx/agents` | Connected Proxmox agents |
| `POST` | `/api/pxmx/vm/action` | VM action: `{ "unique_id": "cluster/node/vmid", "action": "start"\|"stop"\|"reboot" }` |

KVM spoke uses the same endpoints via `module_type="hypervisor"` — the hub routes to whichever spoke is connected.

### OPNsense / Firewall
| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/firewall/{firewall_id}/refresh` | Refresh rule cache |
| `GET` | `/api/firewall/{firewall_id}/rules` | Firewall rules |
| `GET` | `/api/firewall/{firewall_id}/dhcp` | DHCP leases |
| `GET` | `/api/firewall/{firewall_id}/interfaces` | Network interfaces |
| `POST` | `/setup/firewalls` | Register a firewall spoke |
| `PUT` | `/setup/firewalls/{firewall_id}` | Update firewall config |
| `DELETE` | `/setup/firewalls/{firewall_id}` | Remove firewall |

### LDAP / Directory
| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/ldap/ous` | List OUs |
| `POST` | `/api/ldap/ous` | Create OU |
| `GET` | `/api/ldap/users` | List users |
| `POST` | `/api/ldap/users` | Create user |
| `GET` | `/api/ldap/groups` | List groups |
| `POST` | `/api/ldap/groups` | Create group |
| `POST` | `/api/ldap/users/group` | Assign user to group |
| `DELETE` | `/api/ldap/users/group` | Remove user from group |
| `DELETE` | `/api/ldap/entity` | Delete any LDAP entity |

### ClearPass (NAC)
| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/cppm/access-tracker` | Active NAC sessions |
| `GET` | `/api/cppm/endpoints` | Registered endpoints |

### Generic / Agent Provisioning
| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/generic/provision` | Command a Generic Agent to clone + install a module: `{ "agent_id": "…", "module_id": "…", "repo_url": "…", "spoke_id": "…" }` |

### Simulations (cs) — `/sim/api/*`

The ported Client-Sim operator UI (see [modules/core.md](modules/core.md)). All `/sim/api/*` routes require a valid `lm_session`; superadmin routes additionally require an admin session. Telemetry is also streamed over a WebSocket. Representative endpoints by namespace:

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/sim/api/init` | Per-tenant sim init bundle. |
| `GET` | `/sim/api/health` | Sim module health. |
| `GET` | `/sim/api/auth/providers` | Cosmetic auth-provider list (LM owns auth). |
| `GET` | `/sim/api/auth/me` | Sim-scoped identity for the current session. |
| `GET` | `/sim/api/superadmin/tenants` | Admin: list all tenants. |
| `GET` | `/sim/api/superadmin/users` | Admin: list all users. |
| `GET` | `/sim/api/superadmin/global-usb-vidpids` | Admin: platform-wide certified USB device list. |
| `PUT` | `/sim/api/superadmin/global-usb-vidpids` | Admin: replace the platform-wide USB device list. |
| `GET` | `/sim/api/superadmin/global-usb-ignored-vidpids` | Admin: platform-wide ignored USB VID:PIDs. |
| `PUT` | `/sim/api/superadmin/global-usb-ignored-vidpids` | Admin: replace the ignored VID:PID list. |
| `GET` | `/sim/api/aggregate/{dashboard\|clients\|simulations\|proxmox\|central\|central-status\|api-server}` | Tenant-subnet-filtered view shapers (degrade to empty). |
| `GET` | `/sim/api/{tenant}/spokes` | List the tenant's cached cs spokes. |
| `GET` | `/sim/api/{tenant}/spokes/{spoke_id}/config` | One spoke's cached config + telemetry. |
| `GET`/`PUT` | `/sim/api/tenant/{tenant}/hub-config` | Read/write hub-owned USB-provisioning config. |
| `GET`/`POST`/`DELETE` | `/sim/api/tenant/{tenant}/onboarding-psk` | Manage the tenant's onboarding PSK. |
| `POST` | `/sim/api/{tenant}/toggle-auto-provision` | Toggle cs auto-provisioning (gates the pxmx brain). |
| `GET` | `/sim/api/{tenant}/usb-provisioning-status` | Live USB provisioning status from the agent. |
| `POST` | `/sim/api/{tenant}/usb-vidpids` | Set per-tenant USB VID:PIDs. |
| `POST` | `/sim/api/tenant/{tenant}/spokes/{spoke_id}/claim` | Claim a discovered spoke into a tenant. |
| `POST` | `/sim/api/{tenant}/spokes/{spoke_id}/approve` | Approve a pending spoke. |
| `DELETE` | `/sim/api/spokes/{spoke_id}` | Revoke/remove a spoke. |
| `POST` | `/sim/api/aggregate/config-push` | Push current config down to the cs spoke (`CS_CONFIG_UPDATE`). |
| `WS` | `/sim/ws` | Telemetry stream (per-tenant + admin fan-out via `SimulationsBroadcaster`). |

> Auto-provisioning itself runs in the **pxmx host agent**, not the Hub — these routes only configure/gate it. See [pxmx architecture](../../pxmx/ARCHITECTURE.md).

---

## 4. Log Relay

Agents send structured logs via `AGENT_LOG` messages; the hub relays them to BugFixer.

Log format (all modules):
```
%(asctime)s - %(name)s - %(levelname)s - %(message)s
```
`%(name)s` is the class-level logger name (e.g., `ProxmoxSpoke`, `LDAPManager`), which BugFixer uses to identify the failing module.

---

## 5. Updates

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/setup/update` | Trigger hub self-update (`?force=true` bypasses the bad-version skip) |
| `POST` | `/setup/update/spokes` | Broadcast update command to all spokes |

Both update paths snapshot the code before swapping and roll back automatically
if the new version fails to boot. A rolled-back version is appended to
`bad_versions.json` and skipped until a newer remote version ships; a **double
failure** (rollback also fails) leaves `update_failed.json` on disk for manual
recovery. See [installation.md](installation.md) §"Hub / WebUI Update Recovery"
and [operations.md](operations.md) runbook (b) for the full bad-version /
rollback behavior and the recovery state files under `/var/lib/lm/state/`.
