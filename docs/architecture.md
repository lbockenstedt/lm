# Lab Manager Architecture Overview

## 1. System Concept
Lab Manager (LM) is a centralized orchestration and management platform designed to control a fleet of network and security appliances (Spokes) from a single administrative Hub. It provides a unified WebUI for managing disparate systems like OPNsense firewalls, Proxmox hypervisors, and ClearPass (CPPM) NAC.

## 2. Hub-Spoke Model
The system follows a **Hub-and-Spoke architecture**:

- **The Hub**: Acts as the central control plane. It manages state, authentication, configuration, and API requests. It provides a REST API for the WebUI and a WebSocket server for the Spokes.
- **The Spokes**: Lightweight agents installed on target appliances. They handle the actual execution of commands (e.g., calling a local REST API on OPNsense) and report telemetry back to the Hub.

### Communication Flow
1. **Control Plane (WebSocket)**: The primary communication channel. All commands from the Hub to Spokes, and all heartbeats/results from Spokes to Hub, travel over an encrypted and signed WebSocket connection.
2. **Management Plane (REST API)**: The WebUI communicates with the Hub via a FastAPI-based REST server.
3. **Data Plane**: The Spokes interact with the underlying appliance's native API (e.g., OPNsense REST API) to perform actual configuration changes.

## 3. Component Breakdown

### Hub Core
- **`LabManagerHub`**: The main orchestrator managing active connections and the message loop.
- **`Mailbox`**: Implements an asynchronous queue for outgoing messages to spokes, including a retry mechanism for offline nodes.
- **`StateManager`**: Handles persistence of global configuration, tenant settings, and module registration.
- **`KeyManager`**: Manages the cryptographic lifecycle, including root secrets and per-spoke session keys.

### Spoke Core
- **`BaseControlPlane`**: The shared logic for all spokes, handling the WebSocket handshake, mutual authentication, and command routing.
- **`BaseSpoke`**: The abstract base class that defines how a module handles commands.
- **`MessageSigner`**: Ensures every message is signed using HMAC-SHA256 for authenticity and integrity.

## 4. Multi-Tier Agent Model

Some spokes act as mini-hubs for downstream leaf agents:

```
Hub ──WS──► Proxmox Spoke  ──WS :8766──► pxmx-agent (per Proxmox host)
        ──► KVM Spoke      ──WS :8767──► kvm-agent  (per KVM host)
        ──► CS Spoke       (simulation — no upstream agents)
```

- Each spoke aggregates telemetry from its agents into an in-memory cache.
- The hub fans out commands via `broadcast_to_agents()` when the cache is empty.
- Agent authentication uses `hmac.compare_digest` against a shared `agent_secret`.

## 5. Cross-System Search

`GET /api/search?q=<query>` fans out in parallel to all connected spoke types:

| Spoke type | Command | Returns |
|------------|---------|---------|
| `ipam` | `NETBOX_SEARCH` | Devices, IPs, prefixes |
| `hypervisor` | `SEARCH_VMS` | VMs by name / unique_id |
| `nac` | `SEARCH_SESSIONS` | NAC sessions by IP/MAC/user |
| `directory` | `SEARCH_USERS` | LDAP users/computers |
| `firewall` | `SEARCH_DHCP` | DHCP leases by IP/MAC/hostname |

Results are merged and returned with `source=` tags so the WebUI can link to the correct view.

## 6. Tenant Scoping

Each tenant config stores three scoping keys:

| Key | Used by |
|-----|---------|
| `netbox_tenant_slug` | Passed to pynetbox as `tenant=` filter |
| `proxmox_tag` | Filters VMs where `tags` list contains the value |
| `ldap_base_dn` | Overrides `base_dn` for LDAP searches |

Tenant context is passed via `?tenant=<id>` on all functional API calls.

## 7. Security Model

- **Admin endpoints**: `/setup` mutations require `X-Admin-Token` (env `LM_ADMIN_TOKEN`). Enforced by `AdminTokenMiddleware` at the app level.
- **Spoke auth**: HMAC-SHA256 signed messages; mutual auth (hub proves identity to spoke on connect).
- **Key rotation**: `POST /setup/rotate-key/{spoke_id}` — generates a new secret, pushes to live spoke via `SPOKE_UPDATE_SESSION_KEY`, spoke persists to `.env`. Offline spokes pick it up on reconnect.
- **Self-registration**: Spokes auto-fetch their first secret via `/setup/generate-secret` at install time using `--admin-token`.

## 8. Design Goals
- **Resilience**: Using a "Restore-Safe" key rotation window, ensuring that VM snapshots don't break authentication.
- **Security**: Mutual authentication prevents rogue hubs or spokes from joining the control plane.
- **Scalability**: The Generic Agent bootstrapper allows for rapid deployment of new modules without manual configuration of every instance.
- **Tenant Isolation**: Support for multi-tenancy via the `StateManager`, allowing different users to manage distinct sets of resources.
