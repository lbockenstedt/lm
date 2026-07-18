# opnsense — Firewall

OPNsense spoke. Repo: `opnsense`. `module_type = "firewall"`. See [architecture-topology.md](architecture-topology.md).

## Role & module_type

Firewall management + discovery spoke. Translates hub commands into OPNsense REST API calls for firewall aliases, rules, NAT policies, DNS overrides, DHCP leases, ARP, interface/health telemetry, and certificate import. Feeds the firewall→NetBox discovery sync (DHCP leases + ARP).

## What it does

This module lets an end user manage an OPNsense firewall from the Lab Manager WebUI without touching the firewall's own web GUI. In the WebUI it appears as a **Firewalls** entry in the main nav (per-tenant) with sub-tabs for **Firewall Rules**, **NAT Policies**, **DNS Records**, **Aliases**, **DHCP Leases**, and **Interfaces**; firewalls themselves are added/edited under **Setup → Firewalls**.

Day to day, it is used to: check whether the firewall is reachable and healthy, browse or edit filter rules and NAT policies, manage aliases (named, reusable groups of hosts/networks referenced by rules), add DNS host overrides, and look up DHCP leases or ARP entries for a device. It also quietly discovers devices from the firewall's DHCP leases and ARP table and hands them to NetBox so they show up in the IPAM inventory automatically.

A brand-new firewall entry has **no live connection** until its host/port/API key/secret are filled in and saved — until then its pages will show something like "no firewall configured" rather than an error, which is expected, not a bug.

## Entrypoints

`python3 -m src.control_plane` (`OpnControlPlane`); spoke `OpnSpoke(BaseSpoke)`, module name `"opn"`. systemd `lm-opnsense.service`. Installer `install_opnsense.sh` (clones `lbockenstedt/opnsense.git` to `/opt/lm/opnsense`, venv, `.env`, unit).

> **Primarily a role now.** This module runs mainly as the **`opnsense`** role hosted by the agent (`agent-<hostname>`, unit `lm-agent`): the agent opens a sub-spoke `{agent}-opnsense` (module_type `firewall`, parent-auto-approved) and self-installs it via `agent/src/agent_spoke.py::_install_role` (clones `lbockenstedt/opnsense.git` + deps). The dedicated `lm-opnsense.service` / `install_opnsense.sh` `opnsense-spoke-1` path is the **legacy/standalone** alternative. Connection config (host/key/secret) comes from the hub push (WebUI), not a per-module `.env`.

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

## How it works

**Command path.** Whether it runs standalone (`lm-opnsense.service`) or as the `opnsense` role on an agent, the module is a WebSocket spoke that dials the hub over `/ws/spoke`. Nothing in the WebUI talks to the firewall directly: every page action becomes a JSON command (the `OPNSENSE_*` / `GET_*` names listed under "Key commands" above), sent hub → spoke, dispatched by `opn_spoke.handle_command`, and turned into a real HTTPS call by `OpnsenseEngine` against `https://{host}:{port}` — the firewall itself never talks to the hub or the browser.

**How the connection gets configured.** `OpnSpoke.__init__` starts with `config={}` — no host, key, or secret — so `OpnsenseEngine.is_configured()` is `False` and every API call short-circuits to a (throttled, single-line-logged) `"no firewall configured"` error instead of ever trying `localhost:8443`. A firewall only becomes reachable once the hub sends an `UPDATE_CONFIG` command carrying `opn_host`/`opn_port`/`api_key`/`api_secret` (and optionally `refresh_interval`). That push happens when a user saves the firewall's connection details in the WebUI (**Setup → Firewalls**) — it is **not** read from a per-module `.env` file at boot, and it is not something you edit on the spoke's host. On reconnect, the hub re-sends the last-known config so the spoke doesn't come back up unconfigured.

**Caching and the refresh loop.** Most read-heavy commands (interface status, system health, ARP table, firewall rules, firewall stats, NAT policies, DNS records, aliases) are served from an in-memory cache refreshed on a timer — `_refresh_interval`, default **3600s (1 hour)**, changeable via the same `UPDATE_CONFIG` push. The refresh loop primes the cache once immediately at startup (so a just-restarted spoke isn't blank for up to an hour) and only overwrites a cache entry when the live fetch came back `SUCCESS`, so a single transient API hiccup doesn't blank a tab — the last-known-good data stays until the next successful refresh. **DHCP leases are the deliberate exception**: they are never served from that cache and every DHCP Leases read goes straight to OPNsense's Kea API live, because leases churn too fast for even a fresh hour-old snapshot to stay accurate (a cached snapshot previously showed an empty tab when Kea had rows).

**Data flow to NetBox.** The firewall→NetBox discovery sync pulls this spoke's DHCP leases (uncapped, via the `limit` parameter so it isn't capped at 200 like the interactive view) and its ARP table, then pushes them to the netbox spoke as a `NETBOX_SYNC_DEVICES` call tagged `source="opnsense"`. That's the mechanism by which a device that merely got a DHCP lease from the firewall shows up as a DCIM device/IP in NetBox with no manual entry — see [netbox.md](netbox.md) for what happens once it lands there (matching/dedup, staleness aging).

**Writes take effect immediately.** Alias/rule/NAT/DNS edits go straight to the live OPNsense API — there's no local staging queue — and firewall rule adds/deletes additionally trigger OPNsense's `apply`/reconfigure step so the change is live on the firewall right away, not just saved-but-inactive.

**Certificates are hub-brokered, not self-issued.** This module never runs an ACME client itself. When a cert needs installing on the firewall, the hub pulls the cert material from the `le` (Let's Encrypt) spoke and pushes it here as `OPNSENSE_INSTALL_CERT`; this module's only job is applying the supplied fullchain/private key to the OPNsense trust store.

## How to use it

- **Add a firewall connection.** Go to **Setup → Firewalls → + Add Firewall**, fill in the firewall's **Host**, **Port** (defaults to `8443`), **API Key**, and **API Secret** (create these under OPNsense's own System → Access → Users, an API key/secret pair), and save. The hub pushes them to the spoke as `UPDATE_CONFIG`; give it a few seconds, then reload the Firewalls page — it should stop saying "no firewall configured" and start showing interface/health data.
- **Add or edit an alias.** Firewalls → Aliases → add/edit. Give it a **Name**, a **Type** (host/network/etc.), the **Content** (the hosts/networks/values), and optionally a **Category** — type the category by its **name** (e.g. a tenant name), not a UUID; the spoke resolves the name to OPNsense's internal category UUID for you. If you mistype a category name that doesn't exist on the firewall, it's silently dropped rather than erroring — double-check the alias afterward if a category doesn't stick.
- **Add or edit a firewall rule.** Firewalls → Firewall Rules → add/edit; the rule is written and applied (reconfigured) on save, so it's live immediately.
- **Add a DNS override.** Firewalls → DNS Records → add: **Hostname**, **Domain**, **IP**, optional description. This creates an Unbound host override on the firewall — it does not touch the separate `dns`/`dhcp` modules if this lab also runs those.
- **Install a certificate on the firewall.** Certificates are managed from the `le` (Let's Encrypt) Certificate Management page, not from the Firewalls page directly — issue/renew the cert there and use its distribution/targets flow to push it to this firewall; this module only receives and applies the material. See [le.md](le.md).
- **Look up a device.** Firewalls → DHCP Leases (or ARP/Interfaces) to browse live data, or use the global device search to find a device by IP/MAC/hostname across all discovery sources at once.

## Troubleshooting / common questions

- **"No firewall configured" / the Firewalls page is empty.** The connection details were never saved (or a save failed to reach the spoke). Go to Setup → Firewalls and confirm the entry has a Host, Port, API Key, and API Secret filled in and saved. If they look right but nothing changes, check that the firewall's role/spoke is actually online (see next item) — an offline spoke can't receive the `UPDATE_CONFIG` push.
- **The firewall shows offline / red / not connected.** This means the `opnsense` role (or the standalone `opn` spoke) isn't currently connected to the hub — the agent on that host may not be running, the role may not have been approved yet, or the agent lost its WebSocket connection. Check the spoke/agent status in Setup (pending/approved spokes) before assuming the firewall itself is down.
- **DHCP Leases tab is empty even though clients are online.** Leases are always read live (never cached), so an empty tab reflects what OPNsense's Kea DHCP server currently reports, not a stale cache. Check that Kea (not dnsmasq — OPNsense's DHCP backend here is Kea, exposed at `/api/kea/leases4/search`) actually has active leases on that firewall, and that the API credentials have permission to read them.
- **NAT Policies tab is empty or shows a warning.** OPNsense's NAT REST controllers used here need **OPNsense 26.1 or newer**; on an older firewall the probe against all three NAT endpoints (destination/source/1:1) fails and the tab reports the version requirement instead of silently showing nothing. A partial result (some NAT types worked, others didn't) shows the rules that did work plus a warning for the ones that didn't.
- **An alias lost its category / category doesn't show up.** Category names are matched against OPNsense's existing alias categories by exact name; a name that doesn't exist on that firewall is dropped rather than auto-created. Check the category name for typos, or create the category on the firewall first.
- **Is the connection to the firewall encrypted/verified?** Yes over HTTPS, but certificate verification is **off by default** (OPNsense's default self-signed cert would otherwise fail every call) — set `LM_OPNSENSE_VERIFY_TLS=1` in the module's environment if the target firewall has a trusted certificate and you want strict verification.
- **A change I made on the firewall directly isn't showing up.** Non-lease/ARP data is cached for up to `refresh_interval` (default 1 hour); either wait for the next scheduled refresh or trigger `OPNSENSE_REFRESH_CACHE` (an admin/diagnostic action) to force an immediate re-fetch.

## Related pages

[architecture-topology.md](architecture-topology.md), [netbox.md](netbox.md), [le.md](le.md) (cert target), [install-flags.md](install-flags.md).