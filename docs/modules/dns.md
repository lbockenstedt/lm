# DNS Module Guide

The `dns/` package is the LM DNS spoke. It manages Unbound DNS records (A/AAAA/PTR) through a generated config file under `/etc/unbound/conf.d/` and reloads Unbound to apply changes.

## 1. Capabilities
- **Record management** — add, update, delete, and list A/AAAA/PTR records (PTR names derived from the IP automatically).
- **Bulk sync** — replace the full record set in one write + reload.
- **Status** — report Unbound health and the spoke version to the Hub.

## 2. Configuration
Deploy with `install_dns.sh`. The spoke writes `/etc/unbound/conf.d/lm-netbox.conf` and reloads Unbound. Connection details (Hub URL, spoke ID, PSK for first-time onboarding) are written during install; thereafter the spoke uses its provisioned key.

## 3. Technical implementation (`dns/src/`)
| Path | Role |
|------|------|
| `dns_spoke.py` | Spoke lifecycle — connect, auth, dispatch `handle_command`, report status. Inherits `BaseSpoke`. |
| `unbound_manager.py` | `UnboundManager` — config-file generation, record CRUD, PTR derivation, Unbound reload. |
| `control_plane.py` | Hub-side control-plane handling for this spoke type. |

Commands arrive as signed messages on the Hub control plane; `handle_command` routes each to the matching `UnboundManager` call and returns a structured result.