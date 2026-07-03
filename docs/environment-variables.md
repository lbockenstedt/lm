# Environment Variables Reference

Consolidated reference for every environment variable read across the LM system. Canonical copy in `lm/docs/`. See [architecture-topology.md](architecture-topology.md) for how these fit together.

## Hub (lm) — TLS / serving

| Var | Purpose | Default | Read by |
|---|---|---|---|
| `LM_TLS_CERT` | Path to hub TLS cert (enables wss) | — | `core/src/main.py`, `api.py` |
| `LM_TLS_KEY` | Path to hub TLS key | — | `core/src/main.py`, `api.py` |
| `LM_TLS_PORT` | Hub unified listener port | 443 | `core/src/main.py` |
| `LM_PXMX_AGENT_PORT` | pxmx spoke's own agent-listener port. **443 (standalone DEFAULT)** — the spoke serves `wss://0.0.0.0:443` so a remote agent dials `wss://<spoke>:443/ws/agent` directly (agent → spoke → hub). `8443` only with `--loopback` (co-located all-in-one; the hub `/ws/agent` byte-proxy dials it). mDNS advertises the **external** dial port `443`, not this. | 443 | `core/src/main.py`, `install_pxmx.sh` |
| `LM_PXMX_AGENT_LOOPBACK` | `1` binds the pxmx agent listener to loopback only (`127.0.0.1:8443` plaintext) so the hub `/ws/agent` byte-proxy dials it — co-located all-in-one only. **Unset by default** (standalone `agent → spoke → hub`); set only via `install_pxmx.sh --loopback`, which `install_all.sh` passes on the co-located path. | unset (standalone) | pxmx spoke |
| `LM_HUB_ADVERTISE_TLS` | Force mDNS `tls_port` TXT even with no cert (reverse-proxy/TLS-termination) | — | `core/src/main.py` |
| `LM_CORS_ORIGINS` | Comma-separated credentialed CORS origins | — | `core/src/api.py` |

## Spoke/agent client TLS (verify-off default)

| Var | Purpose | Default | Read by |
|---|---|---|---|
| `LM_HUB_TLS_VERIFY` | `1`/`true`/`yes` → spoke/agent verifies hub cert | off (0) | `core/src/messaging/control_plane.py`, `generic_agent/src/agent.py`, `pxmx/agent/src/agent.py`, cs/pxmx spokes |
| `LM_HUB_CA_CERT` | CA cert path for hub verification (set by `--tls-verify`) | — | same |

## Hub (lm) — security / state / runtime

| Var | Purpose | Default | Read by |
|---|---|---|---|
| `LM_FERNET_KEY` | Fernet at-rest key (REQUIRED, fail-closed) | — | `core/src/security/encryption.py`, `rotate_fernet_key.py` |
| `LM_STATE_DIR` | State directory | `/var/lib/lm/state` | `core/src/state/manager.py`, `update_recovery.py` |
| `LM_HEARTBEAT_INTERVAL_S` | Hub/spoke heartbeat interval | 60 (min 10) | `core/src/main.py`, `control_plane.py` |
| `LM_ONBOARDING_PSK` | Pre-shared key for spoke self-provisioning | — | `control_plane.py` |
| `LM_TENANT_ID_HINT` | Tenant hint for PSK self-provisioning | — | `control_plane.py` |
| `LM_DEP_GUARD_DISABLE` | `1` skips dep self-heal | 0 | `core/src/dep_guard.py` |
| `LM_DEV_MODE` / `LM_DEV_SECRET` | Dev auth backdoor (lab only) | — | `core/src/security/key_manager.py` |
| `LOG_LEVEL` | Boot log level (DEBUG/INFO/WARNING/ERROR) | INFO | `core/src/logging_setup.py` |
| `HUB_SECRET` | Hub-side secret for spoke mutual auth (legacy/compat) | — | `control_plane.py` |
| `STARTUP_ROLE` | Default role for agent spoke (`--role` fallback) | — | `agent/src/control_plane.py` |
| `LM_BRANCH` | lm branch for install_menu bootstrap | main | `install_menu.sh` |
| `CS_POLL_INTERVAL_S` / `CS_USB_CONFIG_INTERVAL_S` | CS bridge poll / USB-sync intervals | 5 / 60 | `gateway/cs_bridge.py` |
| `APP_VERSION` / `APP_BRANCH` | Simulations routes version stamps | — | `simulations/routes.py` |

## generic-agent / agent-spoke

| Var | Purpose | Default | Read by |
|---|---|---|---|
| `LM_HUB_TLS_VERIFY` / `LM_HUB_CA_CERT` | Client TLS verify | off | `generic_agent/src/agent.py` |
| `STARTUP_ROLE` | Default `--role` | — | `agent/src/control_plane.py` |
| `LM_ONBOARDING_PSK` / `LM_TENANT_ID_HINT` | PSK self-provisioning | — | (agent-spoke via BaseControlPlane) |

## pxmx

| Var | Purpose | Default | Read by |
|---|---|---|---|
| `HUB_URL`, `SPOKE_ID`, `SPOKE_SECRET`, `HUB_SECRET` | Spoke identity | — | spoke `.env` |
| `LM_TLS_CERT` / `LM_TLS_KEY` | Spoke cert (standalone: self-signed at `/opt/lm/pxmx/certs/hub.{crt,key}`; all-in-one reuses hub cert) | — | spoke |
| `LM_PXMX_AGENT_PORT` | Spoke's own agent listener — **443 standalone (default)**, `8443` with `--loopback` | 443 | spoke |
| `LM_PXMX_AGENT_LOOPBACK` | `1` = loopback `127.0.0.1:8443` (co-located all-in-one, `--loopback`/install_all only); unset = standalone `agent → spoke → hub` | unset | spoke |
| `LM_HUB_TLS_VERIFY` / `LM_HUB_CA_CERT` | Client TLS verify | off | spoke + agent |
| `LM_PXMX_STATE_DIR` | Update state | `/var/lib/pxmx/update-state` | spoke + agent |
| `LM_SD_NOTIFY_INTERVAL_S` | systemd notify | 20 | agent |
| `USB_PROVISION_INTERVAL_S` | Provision loop tick | 60 | agent |
| `NOTIFY_SOCKET` | systemd notify socket | — | agent |
| `SPOKE_URL`, `AGENT_ID`, `AGENT_SECRET` | Agent identity | — | agent `.env` |

## cs

| Var | Purpose | Default | Read by |
|---|---|---|---|
| `HUB_URL`, `SPOKE_ID`, `SPOKE_SECRET`, `HUB_SECRET` | Spoke identity | — | `.env` |
| `CS_API_PORT` | Client API port | 8080 | `client_api.py` |
| `CS_API_HOST` | Client API bind | `0.0.0.0` | `client_api.py` |
| `LM_HUB_TLS_VERIFY` / `LM_HUB_CA_CERT` | Client TLS verify | off | spoke |
| `CS_TELEMETRY_INTERVAL_S` | Telemetry relay tick | 10 | `control_plane.py` |
| `LM_ONBOARDING_PSK` / `LM_TENANT_ID_HINT` | PSK self-provisioning | — | spoke |
| `DHCP_IFACE`/`DHCP_SUBNET`/`DHCP_PREFIX`/`DHCP_GATEWAY`/`DHCP_RANGE_START`/`DHCP_RANGE_END`/`DHCP_LEASE_TIME`/`DHCP_SKIP` | dnsmasq DHCP (installer) | — | `lm-spoke/install_cs.sh` |

## le

| Var | Purpose | Default | Read by |
|---|---|---|---|
| `HUB_URL`, `SPOKE_ID`, `SPOKE_SECRET`, `HUB_SECRET` | Spoke identity | — | `.env` |
| `LM_LE_LIVE_DIR` | certbot live dir | `/etc/letsencrypt/live` | `acme.py` |
| `LM_LE_CONFIG_DIR` | certbot config dir | `/etc/letsencrypt` | `acme.py` |
| `LM_LE_DNS_CREDS_DIR` | DNS creds dir | `/etc/lm-le` | `acme.py` |
| `LM_LE_CERTBOT_BIN` | certbot binary | `certbot` | `acme.py` |
| `LM_LE_LEDGER` | Ledger path | `/var/lib/lm/<spoke_id>/certs.json` | `le_spoke.py` |

## netbox

| Var | Purpose | Default | Read by |
|---|---|---|---|
| `NETBOX_URL` | NetBox REST URL | `http://localhost:8000` | `netbox_engine.py` |
| `NETBOX_API_TOKEN` | NetBox API token (required) | — | `netbox_engine.py` |
| `KEA_CTRL_URL` | Kea Control Agent URL | `http://localhost:8000` (override to 8760) | `netbox_spoke.py` |
| `SPOKE_SECRET`, `HUB_SECRET` | Spoke identity | — | `control_plane.py` |

## opnsense

| Var | Purpose | Default | Read by |
|---|---|---|---|
| `SPOKE_ID`, `SPOKE_SECRET`, `HUB_SECRET`, `HUB_URL` | Spoke identity | — | `.env` |
| `LM_OPNSENSE_VERIFY_TLS` | `1` disables engine TLS verify off→on | off | `opnsense_engine.py` |

> Connection config (`opn_host`/`opn_port`/`api_key`/`api_secret`/`refresh_interval`) is **not** env-read — hub pushes via `UPDATE_CONFIG`.

## nw

| Var | Purpose | Default | Read by |
|---|---|---|---|
| `SPOKE_ID`, `SPOKE_SECRET`, `HUB_SECRET`, `HUB_URL` | Spoke identity | — | `.env` |
| `LM_NW_VERIFY_TLS` | REST TLS verify | off | `transports/rest_io.py` |

> Fleet is **not** env-driven — hub pushes `global_config["nw_devices"]` via `UPDATE_CONFIG`.

## dhcp

| Var | Purpose | Default | Read by |
|---|---|---|---|
| `SPOKE_ID`, `SPOKE_SECRET`, `HUB_SECRET`, `HUB_WS` | Spoke identity | — | `.env.template` |
| `KEA_URL` | Kea CA URL | `http://localhost:8000` | `dhcp_manager.py` |

## dns

| Var | Purpose | Default | Read by |
|---|---|---|---|
| `SPOKE_ID`, `SPOKE_SECRET`, `HUB_SECRET`, `HUB_WS` | Spoke identity | — | `.env.template` |
| `UNBOUND_CONTROL` | unbound-control binary | `unbound-control` | `dns_manager.py` |

## ldap

| Var | Purpose | Default | Read by |
|---|---|---|---|
| `SPOKE_ID`, `SPOKE_SECRET`, `HUB_SECRET`, `HUB_WS`, `HUB_API` | Spoke identity | — | `.env.template` |
| `LDAP_ADMIN_DN` | Bind DN | `cn=admin,dc=example,dc=org` | `ldap_manager.py` |
| `LDAP_ADMIN_PW` | Bind password (required) | — | `ldap_manager.py` |
| `LDAP_BASE_DN` | Base DN | `dc=example,dc=org` | `ldap_manager.py` |
| `LDAP_SERVER_URL` | LDAP URL | `ldap://localhost:389` | `ldap_manager.py` |

## cppm

| Var | Purpose | Default | Read by |
|---|---|---|---|
| `CPPM_HOST` | ClearPass host | — | `client.py` |
| `CPPM_CLIENT_ID` / `CPPM_CLIENT_SECRET` | OAuth client creds | — | `client.py` |
| `CPPM_USER` / `CPPM_PASS` | OAuth password grant (preferred) | — | `client.py` |
| `SPOKE_ID`, `SPOKE_SECRET`, `HUB_URL` | Spoke identity | — | `.env` |

## bugfixer

| Var | Purpose | Default | Read by |
|---|---|---|---|
| `GITHUB_TOKEN` | GitHub PAT | — | `.env` |
| `LOCAL_OLLAMA_MODEL`/`CLOUD_OLLAMA_MODEL`/`LOCAL_OLLAMA_URL`/`CLOUD_OLLAMA_URL` | Ollama models/URLs | — | `.env` |
| `POLL_INTERVAL_SECONDS` | Issue poll interval | — | `.env` |
| `UPDATE_API_URL` | External infra notify URL | — | `.env` |
| `LOG_FILE_PATH` | Log file | `/var/log/bugfixer.log` | `.env` |
| `HUB_WS_URL` / `HUB_AGENT_ID` / `HUB_AGENT_SECRET` / `HUB_SECRET` | Hub agent client | `bugfixer` | `config.json` |
| `LLM_PROVIDER_N` / `LLM_API_KEY_N` / `LLM_MODEL_N` / `LLM_BASE_URL_N` / `LLM_RPM_N` | LLM provider slots (1-based) | — | `config.json` |
| `monitored_labels` | Issue labels to fix | `["automated-fix"]` | `config.json` |

## Notes

- `SPOKE_SECRET`/`SPOKE_ID` appear as installer-script locals (written into `.env`); the Python code reads `HUB_SECRET` for mutual auth — there is no `SPOKE_*` env read by Python.
- All client TLS is verify-OFF by default; `--tls-verify` is the install-time opt-in (see [install-flags.md](install-flags.md)).