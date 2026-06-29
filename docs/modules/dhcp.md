# DHCP Module Guide

The `dhcp/` package is the LM DHCP spoke. It manages Kea DHCP4 through the Kea Control Agent REST API and exposes subnet/scope + lease management to the Hub.

## 1. Capabilities
- **Subnet (scope) management** — list, add, update, and delete DHCP subnets via the Kea Control Agent.
- **Lease queries** — inspect active leases for a subnet or host.
- **Status & version** — report spoke health and version to the Hub.

## 2. Configuration
Deploy with `install_dhcp.sh`. The spoke talks to the Kea Control Agent at `http://localhost:8001` by default (port 8001 is used to avoid conflicting with the LM hub on 8000). Connection details (Hub URL, spoke ID, PSK for first-time onboarding) are written during install; thereafter the spoke uses its provisioned key.

## 3. Technical implementation (`dhcp/src/`)
| Path | Role |
|------|------|
| `dhcp_spoke.py` | Spoke lifecycle — connect, auth, dispatch `handle_command`, report status. Inherits `BaseSpoke`. |
| `kea_manager.py` | `KeaManager` — Kea Control Agent RPC client (subnet/lease operations). |
| `control_plane.py` | Hub-side control-plane handling for this spoke type. |

Commands arrive as signed messages on the Hub control plane; `handle_command` routes each to the matching `KeaManager` call and returns a structured result.