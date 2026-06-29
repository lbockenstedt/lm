# Core (Hub) Module Guide

The `core/` package is the LM Hub itself — the central node of the zero-trust Hub-Spoke mesh. Every other module (spoke or agent) connects to it. This guide covers the Hub backend; for deployment see [installation.md](../installation.md), for the REST surface see [api.md](../api.md), and for the security model see [security.md](../security.md).

## 1. Capabilities
- **WebSocket control plane** — accepts spoke/agent connections, performs mutual HMAC-SHA256 auth + challenge/response, and routes signed messages between peers.
- **JSON state store** — the single source of truth for tenants, modules, spokes, users, and global config; persisted out-of-tree (`/var/lib/lm/state`) so git-driven hub updates never overwrite it.
- **Multi-tenant cache** — per-tenant, per-module prefetched data with a background refresh loop, dropped automatically when no session for a tenant is active.
- **Auth & sessions** — cookie-based login with an in-memory token store persisted to `sessions.json` so a logged-in user survives a triggered update/restart (see [session persistence](#4-auth--sessions)).
- **Hub self-update** — pulls from GitHub, restarts itself via a transient systemd unit (`lm-self-restart`), and broadcasts update commands to spokes.

## 2. Package layout (`core/src/`)
| Path | Role |
|------|------|
| `main.py` | `LabManagerHub` orchestrator — control plane, spoke/agent plumbing, self-update. |
| `api.py` | FastAPI app factory (`create_app`) + uvicorn server; auth, sessions, cache, cs relay. |
| `state/manager.py` | `StateManager` — JSON state store + tenant/module registry. |
| `messaging/` | Protocol, mailbox, heartbeat, control-plane message routing. |
| `security/` | Key management, signing, encryption, auth providers (local + LDAP). |
| `simulations/` | The ported Client-Sim (cs) operator UI — store, service shapers, routes, broadcaster, tenant filter. |

## 3. Technical implementation
The Hub runs one `LabManagerHub` instance per process. `run_api_server` hosts the HTTP/WS surface (default port `8000`); the control plane listens on port `8765`. Spokes and the pxmx host agents connect, authenticate, and register; the Hub then routes signed messages between them (`send_to_spoke` / `send_to_agent` / `request_response`). Sensitive command types that transit a Proxmox token secret are redacted in logs (`_REDACT_COMMANDS`).

## 4. Auth & sessions
- Login mints a token stored in the in-memory `_sessions` map and sets an `lm_session` cookie (8h `max_age`, `httponly`, `same-site=lax`).
- The token→session map is persisted to `sessions.json` (0600) in the hub data dir on every login/logout/setup/admin-revoke and flushed before a self-restart, then rehydrated on startup. The cookie already survives a restart, so rehydrating the same mapping keeps users signed in across a triggered update — no re-login required.
- Logout and admin revocation still invalidate the token (the file is rewritten without it); an expired token is pruned on load and on the next mutation save. `auth/me` re-reads the live user record, so permission/tenant changes take effect without a re-login.

## 5. Auto-provisioning (cs) — where the brain lives
The cs auto-provisioning "brain" (toggle gate, resource thresholds, delete-gate + cooldown, `provision_halt`, `prov_run`, VMID-gap audit, slot cap) does **not** run in the Hub or the LM cs spoke (which is relay-only). It lives in the **pxmx host agent** (`pxmx/agent/src/usb_provision.py:run_provision_loop`), because only the agent has Proxmox clone/destroy. The Hub relays cs telemetry/events through to the spoke; see [pxmx.md](pxmx.md) and the [pxmx architecture](../../pxmx/ARCHITECTURE.md).