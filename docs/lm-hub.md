# lm — Hub

The LM hub: control plane, WebUI, REST API, state store, and the orchestration loops that keep every spoke/agent in sync. Repo: `lm`. See [architecture-topology.md](architecture-topology.md) for the mesh overview.

## Role & module_type

The hub is the central node — not a spoke, no `module_type`. It owns mutual-auth WebSocket connections to every spoke and agent, the FastAPI surface (WebUI + REST + WS), on-disk state, key rotation, cert distribution, discovery sweeps, and update orchestration.

## What it does

The hub is the single brain of the lab, and it is also the web app you log into — the WebUI is served directly by the hub process, not a separate server. Every spoke (opnsense, netbox, pxmx, dns, dhcp, cppm, ldap, cs, le, nw) and every generic agent connects outward to the hub over an authenticated WebSocket; the hub is the only thing any of them talk to (spokes never talk to each other directly).

It owns the state that ties the lab together — which spokes/agents exist and whether they're approved, per-tenant config, encrypted secrets and signing keys, cert distribution — and keeps that state consistent with reality on its own via a set of always-running background sync loops (NetBox↔CPPM, hypervisor↔NetBox, firewall/network discovery, staleness sweeps, and more). If a WebUI page shows spoke/device status, lets you approve or configure a module, or triggers a "Sync now", it's this hub doing the work underneath.

## Entrypoints

- **Hub process:** `core/src/main.py` — `LabManagerHub` → `asyncio.run(hub.start())`. systemd unit `lm.service`, `User=svc_lm`, single uvicorn server built by `core/src/api.py::build_server`/`create_app` on `0.0.0.0:LM_TLS_PORT` (443).
- **Installers:** `install_all.sh` (hub + co-located spokes), `install_menu.sh` (interactive bootstrap), plus `install_hub.sh`/`install_ui.sh`/`install_hub_ui.sh`/`install_production.sh`/`start.sh`/`start_all.sh`/`sync_secrets.sh`/`verify_auth.sh`.

## Ports

- `0.0.0.0:LM_TLS_PORT` (default **443**, wss when cert configured) — unified uvicorn: HTTP API + WebUI + `/ws/spoke` + `/ws/console/{session_id}` + `/sim/ws`.
- `127.0.0.1:443` — co-located spokes/agents dial `wss://127.0.0.1:443/ws/spoke` (verify-off) on the same unified listener.
- No-cert fallback: `0.0.0.0:443` plain (no cert).

## Environment variables

| Var | Purpose | Default |
|---|---|---|
| `LM_TLS_CERT` / `LM_TLS_KEY` | Hub TLS cert/key (enables wss) | — |
| `LM_TLS_PORT` | Unified listener port | 443 |
| `LM_PXMX_AGENT_PORT` | pxmx spoke's own agent-listener port. **443 (standalone DEFAULT)** — the spoke serves `wss://0.0.0.0:443` so a remote agent dials `wss://<spoke>:443/ws/agent` directly. `8443` only with `--loopback` (co-located all-in-one; the hub `/ws/agent` byte-proxy dials the loopback listener). mDNS advertises the **external** dial port `443`. | 443 |
| `LM_HUB_ADVERTISE_TLS` | Force mDNS `tls_port` TXT even with no cert (reverse-proxy) | — |
| `LM_HUB_TLS_VERIFY` / `LM_HUB_CA_CERT` | Co-located spoke/agent cert verification (set by `--tls-verify`) | off |
| `LM_FERNET_KEY` | Fernet at-rest key (REQUIRED, fail-closed) | — |
| `LM_STATE_DIR` | State directory | `/var/lib/lm/state` |
| `LM_HEARTBEAT_INTERVAL_S` | Hub/spoke heartbeat | 60 (min 10) |
| `LM_ONBOARDING_PSK` / `LM_TENANT_ID_HINT` | Spoke PSK self-provisioning | — |
| `LM_DEP_GUARD_DISABLE` | Skip dep self-heal | 0 |
| `LOG_LEVEL` | Boot log level (DEBUG/INFO/WARNING/ERROR) | INFO |
| `LM_CORS_ORIGINS` | Comma-separated credentialed CORS origins | — |

## Install flags

`install_all.sh`: `--reinstall`, `--reset-secrets`, `--reset-users`, `--exclude <csv>`, `--tls-verify` (optional `--tls-ca-cert <path>`; defaults CA to the hub's own `$TLS_CERT`). `install_menu.sh`: top menu `1) Hub` (spoke checklist → `install_all.sh --exclude …`) or `2) Generic agent` (→ `agent/install_agent.sh`). Env `LM_BRANCH` (default `main`).

## Key components (core/src/)

- **`main.py::LabManagerHub`** — the hub object. Mixins: `UpdatePipelineMixin, EndpointSyncMixin, VmSyncMixin, FwDiscoverySyncMixin, NwDiscoverySyncMixin, NwCacheMixin, RealtimeIpamNacSyncMixin, StalenessSweepMixin, SpokeAlertMixin, RepoSyncMixin`. Connection handshake (`handle_connection` — spoke sends `{spoke_id, secret, module_type, onboarding_psk, tenant_id_hint, install_uuid, hostname}`; hub sends `HUB_VERIFIED` signed challenge; spoke replies `HUB_OK`). `_install_active_connection`/`_evict_spoke`/`send_to_spoke`/`send_to_agent`/`request_response`/`send_to_spoke_command`. Identity reconciliation (`_rebuild_install_uuid_index`, `_reconcile_spoke_identity`, `_reconcile_agent_identity`). Background loops: retry, state persistence, repo sync, mps, opnsense polling, key rotation, tenant sync, endpoint sync, vm sync, fw-discovery sync, nw-discovery sync, realtime NAC, staleness sweep, pxmx diag, hub heartbeat, spoke recovery, spoke alert, cs bridge, cert distribution. mDNS broadcast (`_start_mdns_broadcast`).
- **`api.py`** — FastAPI app. Route groups: `/setup/*` (admin setup — spokes/pending/approve, agents, cppm/endpoint/vm/fw/nw/realtime-nac/staleness/repo sync, pxmx/ldap/dns/dhcp/netbox config, tenants, users, github-repos, config, update), `/api/firewall/{id}/*`, `/api/nw/*`, `/api/pxmx/*` (agent-install-cmd, agents, nodes, vms, console, vm-action, pools, isos, storages, create-vm, clone), `/api/dashboard/*`, `/api/search` (MAC normalize), `/api/agents` + `/api/agent/{id}/command|load-role`, `/api/generic/provision`, `/api/dns/*`, `/api/dhcp/*`, `/api/le/*`, `/api/netbox/*`, `/api/cppm/*` + `/cppm/*`, `/api/ldap/*`, `/api/tenant/scoping`, `/api/aggregate/*`, `/auth/*`, `/admin/*`, `/api/bug-report`. WS: `/ws/spoke`, `/ws/console/{session_id}`. Simulations sub-app mounted at `/sim` + `/sim/api/*` (`simulations/routes.py`).
- **`messaging/control_plane.py::BaseControlPlane`** — spoke-side base (see architecture page). `_connect_and_serve`, `_client_ssl_ctx`, log relay, self-update helpers, `_ensure_install_uuid`.
- **`messaging/hub_discovery.py`** — mDNS + DNS discovery (canonical; 4 vendored copies).
- **`messaging/`** `protocol.py` (Message/Ack dataclasses), `mailbox.py` (`Mailbox` + `retry_loop`), `heartbeat.py` (`HeartbeatManager` + `SpokeStatus`).
- **`security/`** — `signer.py` (`MessageSigner` HMAC-SHA256), `key_manager.py` (`KeyManager` per-spoke session + hub secrets, 30-day rotation + 1-prev history), `encryption.py` (`HubEncryption` Fernet), `auth_manager.py` (`AuthManager`/`LDAPAuthProvider`), `cert_distribution.py`, `rotate_fernet_key.py`, `decrypt_secret.py`.
- **`state/manager.py::StateManager`** — JSON state (`system.json`/`tenants.json`), 60s persistence, module registry, tenants, quotas, global config.
- **`update_pipeline.py`** + **`update_recovery.py`** — update orchestration + snapshot/rollback ledger.
- **`access.py`** — tenant scoping + subnet/tenant filters (server-side isolation gate).
- **`logging_setup.py`** — `configure_logging` / `set_log_level` (runtime DEBUG toggle).
- **`dep_guard.py`** — `ensure_requirements` dep self-heal.
- **`gateway/spoke_gateway.py::SpokeGateway`** (agent server :8767) + **`gateway/cs_bridge.py::CSBridgePoller`**.
- Sync mixins: `endpoint_sync.py`, `vm_sync.py`, `fw_discovery_sync.py`, `nw_discovery_sync.py`, `nw_cache.py`, `realtime_ipam_nac_sync.py`, `staleness_sweep.py`, `spoke_alert_sync.py`, `repo_sync.py`, `vmid_alloc.py`.

## Key files

`core/src/main.py`, `core/src/api.py`, `core/src/messaging/control_plane.py`, `core/src/messaging/hub_discovery.py`, `core/src/security/*`, `core/src/state/manager.py`, `core/src/update_pipeline.py`, `core/src/update_recovery.py`, `core/src/access.py`, `core/src/logging_setup.py`, `core/src/dep_guard.py`, `core/src/gateway/*`, `core/src/simulations/*`.

## Notable behaviors & gotchas

- **Unified 443 server** — one uvicorn process hosts HTTP + all WS routes (the older dual websockets.serve + Starlette adapter consolidated onto FastAPI/Starlette WS). Co-located spokes/agents dial `wss://127.0.0.1:443/ws/spoke` (or `/ws/agent`) with verify OFF on the same listener — there is no separate loopback port. (The pxmx spoke's own agent listener stays loopback `127.0.0.1:8443`, reached via the hub `/ws/agent` byte-proxy.)
- **Cert fail-fast** — broken cert load aborts the hub rather than silently serving plaintext on 443.
- **`request_response` vs `send_to_spoke_command`** — `request_response` is end-to-end (returns a spoke result; used for VNC ticket/RFB password). `send_to_spoke_command` is **fire-and-forget** (drops the ack) — do not use it when you need the spoke's reply.
- **VNC console** — `/ws/console/{session_id}` is a single-use `ws_token` byte relay; the Proxmox `vncwebsocket` ticket doubles as the RFB password and must reach the browser (noVNC `credentials.password`).
- **Spoke ERROR → HTTP 502** — relay routes raise `HTTPException(502, msg)` on a spoke `ERROR` status, with `except HTTPException: raise` before the generic 500 so the UI shows the real reason.
- **Tests:** `core/tests/` (pytest) — subnet filter, update gate, relay contract, endpoint/vm/fw/nw sync, tenant filter, state persistence, signature rotation window, cert distribution, logging, dep guard, hub discovery, mDNS broadcast, install-uuid identity, ws-tls, etc.

## How it works

**The connection handshake.** A spoke/agent dials `wss://<hub>:443/ws/spoke` and sends an auth frame: `spoke_id`, `secret`, `module_type`, plus optional `onboarding_psk` + `tenant_id_hint` (zero-touch PSK self-provisioning), `install_uuid` + `hostname` (identity tracking that survives a rename or clone), and — for a role sub-spoke of a multi-role generic agent — `parent_spoke_id`. The hub validates the secret via `KeyManager`, then proves its OWN identity back: it signs a random challenge and replies `{"status": "HUB_VERIFIED", "challenge": …, "signature": …}`; the spoke must verify that signature and answer `HUB_OK` within 2 seconds or the hub closes the socket. This is genuine mutual auth, not one-directional trust — which is why a hub restart with rotated/changed secret material can make an existing spoke reject the hub's identity (logged as `mutual_auth_failed`, "stale HUB_SECRET after hub restart").

A spoke that authenticates but isn't yet approved stays connected in a **pending** state — it can still send a heartbeat, but every other command is refused — until one of three things happens: an admin approves it, it self-provisions with a valid onboarding PSK + tenant hint, or (multi-role agents) its base agent parent is already approved, in which case it auto-approves through the parent.

**Two very different ways the hub talks to a spoke:**
- **`request_response(spoke_id, command_type, data, timeout=5.0)`** is end-to-end — it sends a signed command and actually waits for the spoke's reply, returning it to the caller. Used anywhere the caller needs the spoke's answer, e.g. issuing a VNC console ticket/RFB password. A timeout returns `{"status": "ERROR", "message": "Timed out waiting for spoke response"}` rather than raising.
- **`send_to_spoke_command(...)`** is fire-and-forget — it sends the message but never registers a pending request, so the spoke's ack is simply dropped. Used for latency-sensitive one-way traffic (VNC frame relay) where waiting for an ack would stall the browser.
- **`push_or_queue_to_spoke(...)`** is the middle ground config-push routes use: try `request_response` live first; if that times out (the spoke may just be mid-reconnect, not rejecting), fall back to a durable mailbox queue that's delivered the moment the spoke reconnects, instead of reporting a hard failure.

**Errors surface as real HTTP status, not a 200 with a buried error field.** A route that asks a spoke for something raises `HTTPException(503, …)` if the spoke isn't connected at all, and `HTTPException(502, …)` if the spoke IS connected but replied with an `ERROR` status — the 502's message body is the spoke's own error text. So "the spoke returned an error, read the message" is literal, actionable troubleshooting, and 502 vs 503 tells you whether the spoke was reachable at all.

**Background loops.** Once the unified uvicorn server (HTTP + WebUI + `/ws/spoke` + `/ws/console` + `/sim/ws`) is listening, the hub starts roughly twenty always-on asyncio tasks that keep the lab self-consistent without any operator action, including: mailbox retry/delivery, 60s state persistence, repo self-update sync, 30-day key rotation, tenant sync, NetBox↔CPPM endpoint sync, hypervisor↔NetBox VM sync, firewall- and network-device discovery→NetBox, NetBox↔DNS/DHCP reconciliation, realtime NAC↔IPAM reverse sync, a staleness sweep (7 days idle → offline, 30 days → deleted + IP freed), pxmx diagnostics, the hub's own health heartbeat, a spoke-recovery watchdog (restarts a stranded approved spoke's systemd unit), spoke out-of-contact alerting (5 min → warning, 30 min → error), the cs (Client-Sim) bridge, and certificate distribution from the le spoke to its target spokes. Most of these also have an on-demand "Sync now"/"Sweep now" button in the WebUI that runs the exact same code path immediately.

**Cert fail-fast.** If `LM_TLS_CERT`/`LM_TLS_KEY` are configured but the cert fails to load, the hub logs the error and refuses to start rather than silently falling back to serving plaintext on 443 — under systemd this shows up as a crash-loop, which is the intended signal to go fix the cert.

**`LM_FERNET_KEY` is fail-closed.** State is encrypted at rest with a Fernet key sourced only from this env var; if it's unset or invalid, the hub raises during startup and will not come up at all — there is no plaintext fallback.

## How to use it

- **Approve a pending spoke or agent** — Setup → Spokes & Agents. A newly-connected, not-yet-approved module shows up in the pending list; click **Approve** (`POST /setup/approve_spoke`) to bind it, push its session key, and query its version. The same route with `action: "unapprove"` revokes it again (and invalidates its session key).
- **Turn on debug logging** — the Debug Logging toggle in Setup (`POST /setup/debug-mode {"enabled": true|false}`). This flips the hub's own log level immediately AND broadcasts `SET_LOG_LEVEL` to every connected spoke/agent, so one switch raises (or lowers) verbosity fleet-wide.
- **Trigger an update** — `POST /setup/update` updates the hub itself (git pull + scheduled self-restart); `POST /setup/update/spokes` pushes `SPOKE_UPDATE` to every approved spoke without touching the hub (this is what BugFixer typically calls right after landing a fix). Agents have their own `update_agents_only` counterpart.
- **Force an out-of-cycle sync** — most sync cards (NetBox↔CPPM, hypervisor↔NetBox VM sync, firewall/network discovery, staleness sweep, realtime NAC) expose a "Sync now"/"Sweep now" button that runs the loop immediately instead of waiting for its interval.

## Troubleshooting / common questions

- **"Why does a spoke/agent show offline or red?"** Either it never connected — check its own logs and that it's dialing the right `--hub` URL/discovery — or it connected but isn't approved (Setup → Spokes & Agents shows it pending; approve it, or check its onboarding PSK/tenant hint if it was supposed to self-provision). Once approved and connected, a missed heartbeat window flips the status: ~5 minutes silent → warning, ~30 minutes → error (`SpokeAlertMixin`) — at that point check the spoke process itself is still running.
- **"An action / button returned a 502 error."** The spoke IS connected but returned `ERROR` for that specific command — the 502's message is the spoke's own error text, not a hub bug. (Contrast with a 503, which means the spoke wasn't connected at all.)
- **"The hub won't start / can't bind 443."** Two usual causes: (1) binding a port below 1024 as the non-root `svc_lm` user needs `CAP_NET_BIND_SERVICE` (the installers set `AmbientCapabilities=CAP_NET_BIND_SERVICE` in the systemd unit — check it's present if you hand-rolled the unit); (2) a configured `LM_TLS_CERT`/`LM_TLS_KEY` is broken — the hub fails fast rather than serving plaintext, so a crash-loop right after a "TLS cert load failed" log line means fix or unset the cert.
- **"The hub crashes on boot complaining about a Fernet key."** `LM_FERNET_KEY` is required and fail-closed by design. Generate one (`python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`) and set it — see `.env.example`.
- **"A spoke keeps rejecting the hub's identity (`mutual_auth_failed`)."** Usually a stale secret after a hub restart or key rotation — the spoke needs its session key refreshed/re-approved.

## Related pages

[architecture-topology.md](architecture-topology.md), [webui.md](webui.md), [generic-agent.md](generic-agent.md), [environment-variables.md](environment-variables.md), [install-flags.md](install-flags.md).