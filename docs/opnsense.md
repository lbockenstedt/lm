# opnsense — Firewall

OPNsense spoke. Repo: `opnsense`. `module_type = "firewall"`. See [architecture-topology.md](architecture-topology.md).

## Role & module_type

Firewall management + discovery spoke. Translates hub commands into OPNsense REST API calls for firewall aliases, rules, NAT policies, DNS overrides, DHCP leases, ARP, interface/health telemetry, and certificate import. Feeds the firewall→NetBox discovery sync (DHCP leases + ARP).

## Entrypoints

`python3 -m src.control_plane` (`OpnControlPlane`); spoke `OpnSpoke(BaseSpoke)`, module name `"opn"`. systemd `lm-opnsense.service`. Installer `install_opnsense.sh` (clones `lbockenstedt/opnsense.git` to `/opt/lm/opnsense`, venv, `.env`, unit).

> **Primarily a role now.** This module runs mainly as the **`opnsense`** role hosted by the generic agent (`agent-<hostname>`, unit `lm-agent`): the agent opens a sub-spoke `{agent}-opnsense` (module_type `firewall`, parent-auto-approved) and self-installs it via `agent/src/agent_spoke.py::_install_role` (clones `lbockenstedt/opnsense.git` + deps). The dedicated `lm-opnsense.service` / `install_opnsense.sh` `opnsense-spoke-1` path is the **legacy/standalone** alternative. Connection config (host/key/secret) comes from the hub push (WebUI), not a per-module `.env`.

## Ports / backends

OPNsense REST over HTTPS at `https://{host}:{port}` (`OpnsenseEngine`). Default `localhost:8443`. TLS verify **disabled** unless `LM_OPNSENSE_VERIFY_TLS=1`. No port served. Endpoints: `/api/interfaces/overview/interfaces_info`, `/api/diagnostics/systemhealth/get_system_health`, `/api/firewall/filter/*` (add/del/search/setRule/apply), `/api/firewall/alias/*` (+ `listCategories`), `/api/firewall/d_nat|source_nat|one_to_one/*`, `/api/unbound/settings/*` + `/api/unbound/service/reconfigure`, `/api/trust/cert/*`, `/api/kea/leases4/search` (DHCP), `/api/diagnostics/interface/search_arp` (ARP).

## Environment variables

`SPOKE_ID`, `SPOKE_SECRET`, `HUB_SECRET`, `HUB_URL`; `LM_OPNSENSE_VERIFY_TLS` (engine). Connection config (`opn_host`/`opn_port`/`api_key`/`api_secret`/`refresh_interval`) is **not** env-read at boot — the hub pushes it via `UPDATE_CONFIG`; `__init__` starts `config={}`.

## Install flags

`install_opnsense.sh`: `--hub`, `--id`/`--name`, `--secret`, `--hub-secret`, `--all-prereqs` (no-op). Keeps default PSK `lm-secret` for zero-touch.

## Key commands / handlers (`opn_spoke.handle_command`)

- Lifecycle: `UPDATE_CONFIG` (re-host/re-credential, update `refresh_interval` + restart loop), `GET_VERSION`, `OPNSENSE_REFRESH_CACHE`, `PROBE_API` (raw GET), `OPNSENSE_CURL_TEST`.
- Cached reads: `GET_INTERFACE_STATUS`, `GET_SYSTEM_HEALTH`, `OPNSENSE_GET_ARP_TABLE`, `OPNSENSE_GET_ALL_RULES`, `OPNSENSE_GET_FIREWALL_STATS`, `OPNSENSE_GET_NAT_POLICIES`, `OPNSENSE_GET_DNS_RECORDS`, `OPNSENSE_GET_ALIASES`.
- `OPNSENSE_GET_DHCP_LEASES` — **not cached** (leases volatile; a 1h-cached stale-empty list previously blanked the tab). With `{"limit": N}` bypasses the 200-cap (used by firewall→NetBox sync); without `limit` goes live, caps at 200. Hits `/api/kea/leases4/search`.
- `OPNSENSE_GET_RULES_BY_IP`, `SEARCH_DHCP`.
- Rules: `OPNSENSE_ADD/DEL/EDIT_RULE` (setRule/{uuid}); `add/delete_firewall_rule_and_apply` reconfigure after.
- Aliases: `OPNSENSE_ADD/DEL/EDIT/UPDATE_ALIAS`. Categories resolved to UUIDs (see below).
- NAT: `OPNSENSE_ADD/DEL/EDIT_NAT_RULE` (`nat_type` `d_nat`/`source_nat`/`one_to_one`/`nat_1to1` alias).
- DNS: `OPNSENSE_ADD/DEL/EDIT_DNS_RECORD` (Unbound host overrides).
- `OPNSENSE_INSTALL_CERT` — hub-brokered cert distribution: applies `fullchain`+`privkey` via `/api/trust/cert/add` or `set/{uuid}`. `privkey` masked.

## Key files

`src/opn_spoke.py` (cache + refresh loop, dispatch, sensitive masking), `src/opnsense_engine.py` (~789 lines — `_request`, per-feature methods, `_alias_category_map`/`_alias_category_uuids_for`/`_resolve_alias_category_uuids`, `_nat_source`, `import_cert` + `_split_leaf_cert` + `_find_cert_uuid`), `src/control_plane.py`, `install_opnsense.sh`, `API_SPEC.md`.

## Notable behaviors & gotchas

- **Categories-as-UUIDs** — OPNsense tags aliases by category UUID, not name. `_alias_category_map()` builds `{uuid: name}` from `/api/firewall/alias/listCategories`; reads resolve `categories`/`categories_uuid` back to names; writes resolve the comma-separated category **name** string the WebUI sends into the comma-separated **UUID** string OPNsense expects, dropping unknown names.
- **In-memory cache primed immediately on startup** — so a freshly-(re)started spoke doesn't serve a cold cache for the whole interval (NAT's 3-endpoint sequential probe previously blew the hub's request_response budget). Refresh interval default 3600s; `_cache_live` caches successful live fetches; only SUCCESS cached.
- **NAT policies** — `get_nat_policies` probes `d_nat`/`source_nat`/`one_to_one` sequentially; all-errored → loud ERROR naming OPNsense 26.1+ MVC NAT API requirement; partial → rules + warnings; truncates to 200. The MVC NAT controllers need OPNsense 26.1+ (issue #8401); the wrong controller `nat_1to1`→`one_to_one` was a bug. `_nat_source` @staticmethod must not be called bare.
- **Sensitive masking** — full-mask `{api_key, api_secret, password, privkey, private_key}` in logs (prior `[:4]…[-4:]` leaked both ends).
- **Kea DHCP** is the OPNsense DHCP backend (not dnsmasq) — leases via `/api/kea/leases4/search`; rows flattened from dict-or-list; MAC returned raw (hub/NetBox normalize).
- **1:1 NAT controller** is `one_to_one` (not `nat_1to1`); `nat_1to1` accepted as an alias.

## Related pages

[architecture-topology.md](architecture-topology.md), [netbox.md](netbox.md), [le.md](le.md) (cert target), [install-flags.md](install-flags.md).