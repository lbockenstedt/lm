# cs — Client Simulation

Client Simulation spoke. Repo: `cs`. `module_type = "simulation"`, label "Generic Agent"/"Client Simulator". See [architecture-topology.md](architecture-topology.md).

## Role & module_type

The active LM spoke is `lm-spoke/` (`CSSpoke`), **relay-only** for Proxmox/USB auto-provisioning (the gate/VMID audit runs in the pxmx agent). It owns: the sim engine, client registry, per-client override control panel, hub-config store, command queue, token store, demo scenarios, and the DHCP/client API for the isolated sim-client network. `webui-spoke/` is the **legacy/standalone** combined spoke+UI server (FastAPI :8000, Aruba Central, older relay) — a parallel path, not the LM-native active one. `clients/` holds sim-agent scripts that run on sim VMs (Linux/Windows/T3).

## Entrypoints

- **lm-spoke (native):** `python3 -m src.control_plane` (`CSControlPlane`), systemd `lm-cs.service`, `User=svc_lm`, `--port $CS_API_PORT --host $CS_API_HOST`. Installer `lm-spoke/install_cs.sh` (clones lm core `core/` to `/opt/lm/core`, cs to `/opt/lm/cs`, dnsmasq DHCP on 2nd NIC, `lm-cs.service`, rollback watchdog + sudoers). `--standalone` opts out of hub mode.
- **webui-spoke (legacy):** `uvicorn server:app` :8000. Installer `installers/install-lxc.sh`.
- **Sim agents:** `clients/linux/agent.sh` (systemd `client-sim-agent.service`), `clients/windows/*.ps1`, `clients/t3/*`.

## Ports

- lm-spoke client API: `CS_API_PORT` (default **8080**, not 8000 — the legacy webui-spoke used :8000; the unified LM hub owns :443). Bound `0.0.0.0`/`CS_API_HOST` so it also lands on the DHCP NIC `169.253.1.1`. Clients reach `169.253.1.1:8080`.
- Spoke dials hub on **443** (`/ws/spoke`, wss — verify-off same-box).
- webui-spoke legacy: **8000** HTTP + WS `/ws`.
- DHCP: dnsmasq on the auto-detected 2nd NIC, scope `169.253.1.11`–`169.253.1.254`, no default gateway, `port=0`.

## Environment variables

- `.env`: `HUB_URL`, `SPOKE_ID`, `SPOKE_SECRET`, `HUB_SECRET`, `CS_API_PORT`, `CS_API_HOST`, `LM_HUB_TLS_VERIFY`, `LM_HUB_CA_CERT`.
- Process: `LM_ONBOARDING_PSK`, `LM_TENANT_ID_HINT`, `CS_TELEMETRY_INTERVAL_S` (10), `LM_DEP_GUARD_DISABLE`.
- DHCP (installer): `DHCP_IFACE`, `DHCP_SUBNET`, `DHCP_PREFIX`, `DHCP_GATEWAY`, `DHCP_RANGE_START`, `DHCP_RANGE_END`, `DHCP_LEASE_TIME`, `DHCP_SKIP`.

## Install flags

`lm-spoke/install_cs.sh`: `--hub`, `--id`/`--name`, `--secret`, `--hub-secret`, `--dhcp-iface`, `--no-dhcp`, `--tls-verify` (+ `--tls-ca-cert`, **required**), `--admin-token` (deprecated no-op), `--all-prereqs` (no-op). A stale `CS_API_PORT=8000` is auto-migrated to 8080. `control_plane.py` CLI also accepts `--port`, `--host`, `--standalone`, `--onboarding-psk`, `--tenant-id-hint`.

## Key commands / handlers (`CSSpoke.handle_command`, `lm-spoke/src/cs_spoke.py`)

- Identity: `GET_VERSION`/`CS_GET_VERSION`.
- Simulation: `CS_TRIGGER_ITERATION` (legacy `TRIGGER_ITERATION`), `CS_GET_SIMULATION_STATE`, `CS_SET_SIMULATION_PROFILE`.
- Config: `CS_GET_CONFIG`, `CS_UPDATE_CONFIG`/`UPDATE_CONFIG`, `CS_UPDATE_USER_OVERRIDES`.
- Kill switch: `CS_KILL_SWITCH`, `CS_GET_KILL_SWITCH`.
- Demo scenarios (TTL + auto-expiry): `CS_DEMO_SCENARIO`, `CS_DEMO_CLEAR`, `CS_GET_DEMO_ACTIVE`, `CS_GET_DEMO_SCENARIOS`.
- Per-client override panel (11 toggles): `CS_GET/SET/CLEAR/SET_ALL_CLIENT_OVERRIDES`. Toggles: `kill_switch`, `dns_fail`, `iperf`, `download`, `www_traffic`, `ping_test`, `ssidpw_fail`, `auth_fail`, `dhcp_fail`, `port_flap`, `assoc_fail`.
- Per-host USB VMID overrides: `CS_GET/SET/CLEAR_HOST_USB_OVERRIDE`.
- CS ingest (unified pxmx agent → hub → here): `CS_INGEST_TELEMETRY/LOG/PROGRESS/WATCHDOG_EVENT/HW_RESET/COMMAND_RESULT`, `CS_STORE_PROXMOX_TOKEN`.
- Command queue: `CS_QUEUE_COMMAND`, `CS_POLL_AGENT_INBOX`, `CS_ACK_COMMAND`, `CS_GET_USB_CONFIG`, `CS_GET_COMMANDS`, `CS_CLEAR_COMMANDS`, `CS_DELETE_COMMAND`, `CS_UPDATE_SETTINGS`, `CS_CONFIG_UPDATE` (hub-pushed provisioning config; `_HUB_DIRECT_KEYS` + `_HUB_KEY_REMAP`; writes `hub-sim-overrides.conf`/`hub-user-overrides.conf`).
- Retired (hub no longer sends): `CS_START_SIMULATION`, `CS_STOP_SIMULATION`, `CS_GET_STATUS`, `CS_GET_TELEMETRY`, `CS_GET_CLIENTS`.

## Key files

- lm-spoke: `lm-spoke/src/cs_spoke.py`, `control_plane.py` (`CSControlPlane`, `module_type="simulation"`, CS telemetry relay, standalone), `client_api.py` (FastAPI :8080 — `/api/health`, `/api/kill-switch`, `POST /api/status`, `/api/client/key`, `/api/config`(+`/overrides`/`/parsed`), `/api/scripts/{platform}/*`, `/api/clients`(+`/{h}/control`), `/api/commands`, `/api/inbox`(/ack), `ws /ws/client`), `client_registry.py`, `command_queue.py`, `proxmox_deploy.py` (`ProxmoxDeploy` — telemetry ingest, `relay_payload` with `provision` diagnostic), `sim_config.py`, `simulation_engine.py`, `demo_scenarios.py`, `token_store.py`, `data_models.py`, `dhcp_status.py`, `sim_primitives.py`, `agent_role.py`; `lm-spoke/role.py`, `lm-spoke/API_SPEC.md`.
- webui-spoke legacy: `webui-spoke/server.py`, `lm_relay.py` (`CSBridge`/`LMControlPlane`), `acme.py`.
- Clients: `clients/linux/agent.sh` + scripts, `clients/windows/*.ps1`, `clients/t3/*`; configs `configs/simulation.conf`, `configs/user-overrides.conf`.

## Notable behaviors & gotchas

- **lm-spoke is relay-only for Proxmox** — `proxmox_deploy.py` ingests telemetry + builds `relay_payload` (per-host `provision` diagnostic with `cs_enabled`/`loop_running`/`auto_provision_on`/`reason`/`halt`); the brain is `pxmx/agent/src/usb_provision.py`.
- **Client API port 8080** (was 8000) — at the time, the hub owned :8000 in hub mode; a second bind failed with `[Errno 98]` and crash-looped `lm-cs`. The hub has since moved to unified :443, but cs stays on 8080. Installer migrates stale `.env`.
- **Two flags trap** — tenant `usb_auto_provision` toggle ≠ per-agent `client_simulation.enabled`; the provision loop only spawns on the latter (the "enabled but nothing provisions" root cause).
- **store.set_hub_config REPLACES** — both `csSaveHubConfig` and `csSaveAutoProvConfig` must GET-merge-PUT or the two cards wipe each other.
- **CS_CONFIG_UPDATE handler** is required for hub config pushes (usb_vidpids, templates, sim/user overrides) to land — without it they silently dropped to "Unknown command" and `usb_vidpids` stayed `[]`.

## Related pages

[architecture-topology.md](architecture-topology.md), [pxmx.md](pxmx.md), [lm-hub.md](lm-hub.md), [environment-variables.md](environment-variables.md), [install-flags.md](install-flags.md).