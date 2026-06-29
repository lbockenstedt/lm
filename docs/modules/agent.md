# Agent Module Guide

The `agent/` package is the LM **host agent** — a lightweight spoke that runs on a managed host and bridges it into the Hub control plane. (The Proxmox-specific agent that owns USB auto-provisioning is the **pxmx** agent; see [pxmx.md](pxmx.md) and the [pxmx architecture](../../pxmx/ARCHITECTURE.md).)

## 1. Capabilities
- **Hub registration** — connects to the Hub, authenticates via the mutual HMAC-SHA256 handshake, and registers as an agent.
- **Command relay** — receives `AGENT_*`/system commands from the Hub and returns structured results.
- **Log relay** — streams structured logs back to the Hub for BugFixer routing.

## 2. Configuration
Deploy with `install_agent.sh`. Connection details (Hub URL, spoke ID, PSK for first-time onboarding) are written during install; thereafter the agent uses its provisioned key.

## 3. Technical implementation (`agent/src/`)
| Path | Role |
|------|------|
| `agent_spoke.py` | The agent spoke lifecycle — connect, auth, dispatch, reconnect. |
| `control_plane.py` | Hub-side control-plane handling for this agent type. |

The agent inherits `BaseSpoke` (from `core/src/base_spoke.py`) for the common connect/auth/dispatch loop, then specializes its command set. `generic_agent/` is a more minimal variant used for generic provisioning hosts.