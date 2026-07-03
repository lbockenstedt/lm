# lm — Hub

The LM hub: control plane, WebUI, REST API, state store, and the orchestration loops that keep every spoke/agent in sync. Repo: `lm`. See [architecture-topology.md](architecture-topology.md) for the mesh overview.

## Role & module_type

The hub is the central node — not a spoke, no `module_type`. It owns mutual-auth WebSocket connections to every spoke and agent, the FastAPI surface (WebUI + REST + WS), on-disk state, key rotation, cert distribution, discovery sweeps, and update orchestration.

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
| `LM_PXMX_AGENT_PORT` | pxmx agent-listener port advertised in mDNS | 8443 |
| `LM_HUB_ADVERTISE_TLS` | Force mDNS `tls_port` TXT even with no cert (reverse-proxy) | — |
| `LM_HUB_TLS_VERIFY` / `LM_HUB_CA_CERT` | Co-located spoke/agent cert verification (set by `--tls-verify`) | off |
| `LM_FERNET_KEY` | Fernet at-rest key (REQUIRED, fail-closed) | — |
| `LM_STATE_DIR` | State directory | `/var/lib/lm/state` |
| `LM_HEARTBEAT_INTERVAL_S` | Hub/spoke heartbeat | 60 (min 10) |
| `LM_ONBOARDING_PSK` / `LM_TENANT_ID_HINT` | Spoke PSK self-provisioning | — |
| `LM_DEP_GUARD_DISABLE` | Skip dep self-heal | 0 |
| `LM_DEV_MODE` / `LM_DEV_SECRET` | Dev auth backdoor (lab only) | — |
| `LOG_LEVEL` | Boot log level (DEBUG/INFO/WARNING/ERROR) | INFO |
| `LM_CORS_ORIGINS` | Comma-separated credentialed CORS origins | — |

## Install flags

`install_all.sh`: `--reinstall`, `--reset-secrets`, `--reset-users`, `--exclude <csv>`, `--tls-verify` (optional `--tls-ca-cert <path>`; defaults CA to the hub's own `$TLS_CERT`). `install_menu.sh`: top menu `1) Hub` (spoke checklist → `install_all.sh --exclude …`) or `2) Generic agent` (→ `generic_agent/install_github.sh`). Env `LM_BRANCH` (default `main`).

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

## Related pages

[architecture-topology.md](architecture-topology.md), [webui.md](webui.md), [generic-agent.md](generic-agent.md), [environment-variables.md](environment-variables.md), [install-flags.md](install-flags.md).