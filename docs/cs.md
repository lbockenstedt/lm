# cs — Client Simulation

Client Simulation spoke. Repo: `cs`. `module_type = "simulation"`, label "Agent"/"Client Simulator". See [architecture-topology.md](architecture-topology.md).

## Role & module_type

The active LM spoke is `lm-spoke/` (`CSSpoke`), **relay-only** for Proxmox/USB auto-provisioning (the gate/VMID audit runs in the pxmx agent). It owns: the sim engine, client registry, per-client override control panel, hub-config store, command queue, token store, demo scenarios, and the DHCP/client API for the isolated sim-client network. `webui-spoke/` is the **legacy/standalone** combined spoke+UI server (FastAPI :8000, Aruba Central, older relay) — a parallel path, not the LM-native active one. `clients/` holds sim-agent scripts that run on sim VMs (Linux/Windows/T3).

## What it does

Client Simulation drives a fleet of lightweight "fake client" VMs that pretend to be real end-user devices — they associate to Wi-Fi, pull DHCP, run DNS/ping/iperf/download/web traffic, and report health — so you can demo and exercise the lab (NAC, firewall, DHCP/DNS, monitoring) with realistic load and realistic failures without touching real hardware.

In the WebUI it is the left-nav **Simulations** page. From there you watch client health and hardware checks (Dashboard, Clients), then three product tabs — **Central**, **Central On-Prem**, and **Mist** — each with its own Sites / Alerts / Insights / Clients / Hardware / **Diagnostic** children (plus a per-product API subtab under Setup: Central API, Central On-Prem API, Mist API); you see the Proxmox hosts and VMs that back the sim clients (VM Server), edit the traffic profiles (Config), and turn on/tune auto-provisioning and the isolated sim network (Setup → Proxmox, plus the hub-level Setup → Simulations tile for the DHCP-server card).

The cs spoke itself owns the simulation "profile" logic, the per-client override/demo controls, the isolated sim-client DHCP network, and the client-facing API the sim VMs phone home to. It does **not** create Proxmox VMs itself — that brain lives in the pxmx agent (see below).

**Check-type icons.** Dashboard and Checks rows are tagged by type — 🔔 for an alert check, ℹ️ for an insight (earlier rendered as `(A)` / `(I)`) — keyed off the tenant's `monitored_checks` (`csCheckTypeTag` in `WebUI/sim-views.js`), so you can tell at a glance whether a row is an alert you're meant to keep firing or a softer insight.

## Entrypoints

- **lm-spoke (native):** `python3 -m src.control_plane` (`CSControlPlane`), systemd `lm-cs.service`, `User=svc_lm`, `--port $CS_API_PORT --host $CS_API_HOST`. Installer `lm-spoke/install_cs.sh` (clones lm core `core/` to `/opt/lm/core`, cs to `/opt/lm/cs`, a cs-OWNED Kea DHCP4 sim instance on the 2nd NIC, `lm-cs.service`, rollback watchdog + sudoers). `--standalone` opts out of hub mode.
- **webui-spoke (legacy):** `uvicorn server:app` :8000. Installer `installers/install-lxc.sh`.
- **Sim agents:** `clients/linux/agent.sh` (systemd `client-sim-agent.service`), `clients/windows/*.ps1`, `clients/t3/*`.

> **Primarily a role now.** cs runs mainly as the **`simulation`** role hosted by the agent (`agent-<hostname>`, unit `lm-agent`): the agent opens a sub-spoke `{agent}-simulation` (module_type `simulation`, parent-auto-approved) and self-installs the role via `agent/src/agent_spoke.py::_install_role` — cloning `lbockenstedt/cs.git` + deps and running `install_cs.sh --infra-only` for the idempotent host prep (cs-owned Kea + 2nd-NIC). The dedicated `lm-cs.service` / `install_cs.sh` `{module}-spoke-1` path below is the **legacy/standalone** alternative. Sim/provisioning config arrives via the hub push (WebUI), not a per-module `.env`.

## Ports

- lm-spoke client API: `CS_API_PORT` (default **8080**, not 8000 — the legacy webui-spoke used :8000; the unified LM hub owns :443). Bound `0.0.0.0`/`CS_API_HOST` so it also lands on the DHCP NIC `169.253.1.1`. Clients reach `169.253.1.1:8080`.
- Spoke dials hub on **443** (`/ws/spoke`, wss — verify-off same-box).
- webui-spoke legacy: **8000** HTTP + WS `/ws`.
- DHCP: a **cs-owned Kea** DHCP4 instance on the auto-detected 2nd NIC (SEPARATE from the `dhcp` module's Kea, which is ctrl-agent :8001), static subnet `169.253.1.0/24`, pool `169.253.1.11`–`169.253.1.254`, no default gateway/router option. Configs `/etc/kea/kea-dhcp4-sim.conf` + `/etc/kea/kea-ctrl-agent-sim.conf`; ctrl-agent on **127.0.0.1:8002**; control socket `/run/kea/kea4-ctrl-socket-sim`; memfile leases `/var/lib/kea/kea-leases4-sim.csv`; units `kea-dhcp4-sim.service` + `kea-ctrl-agent-sim.service`.

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
- **Auto-provision config fans out to ALL bound cs spokes** — the hub's `get_client_sim_spokes` (plural) pushes the auto-provision toggle, hub-config save, and USB approval merge to *every* approved, connected cs spoke for the tenant (a tenant may bind several — cs-svr-02 / -03 / -04), concurrently — not just one (with a singular fallback for older hub builds).
- **Setup/Proxmox list fields are comma- or space-delimited** in the WebUI (USB certified/ignored VID:PIDs, T1/T3 PCI VID:PIDs, ignored hostnames); the hub normalizes them to a list (`normalize_hub_config_lists`, split on `[,\s]+`) before storing/pushing — no raw JSON to paste.
- **Sim-client Site/PHY/Sim-ID is SERVER-resolved** — the bash client's `/api/status` beacon OMITS `wsite` and `sim_phy` entirely and may carry a stale `simulation_id` (the old character-position hashing produced values like `sl`). The cs relay (`control_plane.py` `CS_TELEMETRY` build) calls `sim_config.effective_client_fields`, which re-resolves the authoritative `simulation_id` + `wsite` + `sim_phy` from the hostname's bucket profile (`resolve_profile`: `crc32(hostname) % 10` → `s0`–`s9` + per-`[username]` override) and injects them into the client payload sent to the hub. So the WebUI Clients view shows the server-resolved Site/PHY/Sim-ID, not whatever the bash client reported — the local dashboard (`local_ui_routes.py`) uses the same shared helper so the two never diverge.

## How it works

**End-to-end, cs is a control + relay plane; the pxmx agent is the execution plane.**

**Proxmox is relay-only here.** The cs lm-spoke never talks to Proxmox directly. The unified **pxmx agent** (running on each Proxmox host) is where the auto-provisioning *brain* lives (`pxmx/agent/src/usb_provision.py::run_provision_loop`). That loop decides when to clone, reboot, reclone, or delete sim VMs. cs only: (a) ingests the agent's telemetry (`CS_INGEST_TELEMETRY` etc.), (b) stores per-host Proxmox state + rolling CPU/mem 1h averages (`proxmox_deploy.py`), (c) re-emits a `CS_TELEMETRY` frame to the hub every ~10s so the VM Server view has data, and (d) surfaces a per-host **`provision` diagnostic** (`cs_enabled` / `loop_running` / `auto_provision_on` / `reason` / `halt`) that reports *why* the agent's loop is or isn't provisioning. Commands the UI issues (start/stop/reclone a VM, push USB/dongle config) are queued on cs and relayed to the agent by the hub's `CSBridgePoller`.

**The sim engine + config resolver.** `simulation_engine.py` + `sim_config.py` compute each client's effective profile. A client is deterministically bucketed into one of ten profiles `s0`–`s9` by `crc32(hostname) % 10`, then layered: `[simulation]` globals → `[address]`/`[server]` targets → the `[sX]` bucket → a per-`[username]` override (username = hostname before the first `-`, e.g. `jsmith-1` → `jsmith`). All of this is edited in **Simulations → Config → Simulation** (`simulation.conf`) and user-overrides. Hub-pushed overrides are merged from `hub-sim-overrides.conf` / `hub-user-overrides.conf` on top.

**Client registry + per-client overrides.** Every sim VM that reports in is tracked in `client_registry.py` (persisted to `data/clients.json`): last-seen, SSID, gateway reachability, running sims, recent errors. The **per-client Control Panel** (11 fault toggles) writes *persisted* overrides into that registry. **Demo scenarios** (`demo_scenarios.py`) are the ephemeral counterpart: an in-memory, 120-minute-TTL override that flips one failure flag and auto-expires (or clears on reboot) back to whatever the operator had set — demos never mutate the persisted registry.

**Hub-config store + command queue.** Auto-provisioning knobs (templates, VMID range, thresholds, dongle VID:PIDs) live in a local store (`local_store.py`) and/or arrive from the hub via `CS_CONFIG_UPDATE`. The command queue (`command_queue.py`) holds VM actions (`pending → delivered → completed/failed/expired`) with an idempotent enqueue and a sim-VMID safeguard (refuses anything below VMID 90000 or in `protected_vmids`, default `{1001}`) so the UI can only ever touch sim VMs.

**The cs-owned sim DHCP.** cs owns its **own** Kea DHCP4 instance for the isolated sim-client network — this is **separate** from the `dhcp` module's Kea. `install_cs.sh` provisions it on an auto-detected **second NIC** at `169.253.1.1`, static subnet **`169.253.1.0/24`**, pool **`169.253.1.11`–`169.253.1.254`**, **no** router/gateway option (the network is deliberately isolated). Configs: `/etc/kea/kea-dhcp4-sim.conf` + `/etc/kea/kea-ctrl-agent-sim.conf`; the sim control agent listens on **127.0.0.1:8002** (the `dhcp` module's Kea control agent is on a different port); leases in `/var/lib/kea/kea-leases4-sim.csv`; units `kea-dhcp4-sim.service` + `kea-ctrl-agent-sim.service`. `dhcp_status.py` cheaply reads the lease CSV (not the ctrl-agent) and rides the 10s telemetry frame to the hub's DHCP-server card.

**How a sim client gets an address and phones home.** A sim VM boots on the isolated sim network → the cs-owned Kea leases it an address from `169.253.1.11`–`.254` → the client reaches the **client API at `169.253.1.1:8080`** (`client_api.py`, FastAPI). It fetches its profile from `GET /api/config?hostname=…` (bucket + overrides + any live demo flags baked in), POSTs status beacons to `/api/status` (upserting the registry), and opens `ws /ws/client` for live command push. When a client-api key is set, the linux agent fetches it from `/api/client/key` first; the t3 agent sends none (empty key = open).

## Sim Quotas (alert-driven auto-fill, multi-source)

**The idea.** A sim quota links a *monitored* vendor alert or insight to the simulation that produces it, plus a run policy: *keep N online clients in a site running that sim*. Example: "DNS Fail = 10 in site MIA" → the engine grabs 10 online clients in MIA and runs the DNS-failure sim on them; if one dies/goes offline, a substitute is picked up; if the original comes back, the over-N trim releases the substitute. The INVERTED-semantics poller (HEALTHY when the error IS present; the quota engine is what keeps it reliably present) is run **per source**.

**Three sources, each a first-class quota source.** Quotas are no longer Aruba-Central-only. There are now three sources — **`Central:`** (cloud Aruba Central), **`Central On-Prem:`** (a second, on-prem Aruba Central instance), and **`Mist:`** (Juniper Mist) — each with its own config, sites-config, poller, and telemetry bucket. The catalog alert-id prefix (`Central:` / `Central On-Prem:` / `Mist:`) is what binds a quota to its source, and the `SimQuotaEngine` routes each quota to its OWN source's telemetry (`data_key = source`, the canonical lowercase key) so an on-prem quota fires on on-prem telemetry, never on cloud Central's — the firing eval strips the prefix to a bare id, then reads only that source's status block (`_hub_block_for_source`: `central` → `_hub_central`, `mist` → `_hub_mist`, `central_on_prem` → `_hub_central_on_prem`). Each source is a separate poller instance (`core/src/main.py`: `central_on_prem_hub_poller` is a second `CentralHubPoller(instance="central_on_prem")` alongside cloud `central_hub_poller`, plus the Mist poller). See the dedicated per-source docs: [mist.md](mist.md) and [central-on-prem.md](central-on-prem.md).

**Central poll clock-boundary guard.** Aruba Central refreshes several metrics on the 5-minute wall clock (:00, :05, :10 …), so a query that lands within ~60s of a boundary reads transitional/half-updated values that present as a false positive. The Central poller (`core/src/simulations/central_hub_poller.py`, `_boundary_guard_delay`) therefore never polls within `_BOUNDARY_GUARD_S` (60) of a 5-minute boundary — if a scheduled poll would land in that window it sleeps past it first.

**Two layers of config.** Platform-wide **defaults** live in Setup → Simulations (superadmin); a tenant **overrides** per alert in Config → Sim Quotas. The hub merges them (`sim_quota.merge_effective_quotas`): if a tenant declares ANY row for an alert (enabled or disabled), the tenant OWNS that alert — its rows win and the global default for that alert is suppressed (so a tenant can explicitly turn an alert OFF with a disabled row). Alerts the tenant hasn't touched inherit the global default. The merged enabled-only list is pushed to the cs spoke (`CS_CONFIG_UPDATE` → `set_effective_sim_quotas`) and the `SimQuotaEngine` reconciles against it.

**The engine** (`sim_quota_engine.py`) owns a persisted ledger (`sim_quota_ledger.json`) and a 60s reconcile loop (plus an immediate reconcile on every effective-quota push). Per sweep, per quota: keep ledger clients still online + in-site + running the sim; keep an offline client in the ledger (the sim keeps running on the VM through a WS blip) and let a substitute fill the online gap; release only a client offline past `OFFLINE_TTL_S` (3600s); top up to N from the free-runner pool; trim over-N extras. Quotas that left the effective set release all their clients. Provenance: the engine only ever toggles the specific `sim_id` flag (+ `wsite`) it owns on a ledger client; a human manual pin on any other sim flag is never touched.

**multi_capable — exclusivity vs packing.** Failure sims (`dns_fail`, `dhcp_fail`, `assoc_fail`, `auth_fail`, `ssidpw_fail`, `port_flap`) are `multi_capable=False` → **exclusive: one failure sim per client** (the engine won't stack a second failure sim onto a client already running one, whether the existing one came from the engine, a manual pin, or the bucket default). Traffic sims (`ping_test`, `download`, `www_traffic`, `iperf`) are `multi_capable=True` → **they PACK**: a traffic quota may stack onto a client the engine already owns under another quota, and onto a client running an exclusive failure sim. So a single client can run `dns_fail` + `ping_test` + `download`, but never `dns_fail` + `assoc_fail`.

**Site resolution — why it's PXMX-server-based (per-site pool vs tenant pool).** A quota's `site` decides which clients are eligible. The engine resolves a client's effective site in priority order: a per-client `wsite` **override** → the **hosting PXMX server's assigned site** (`pxmx_site_map`, Config → PXMX Sites) → the bucket-default `wsite` → a `sim_config` fallback. The PXMX-server step is the load-bearing one, and it exists because of how the RF plant is wired:

> The sim systems live in **RF chambers** with **dedicated Proxmox nodes per site**. A "site" is a physical chamber, and the pxmx server is its boundary. With **site-based SSID** enabled, the SSID appends the site — site `MIA` with a `PSK` SSID becomes `MIA-PSK` — so each site's clients associate to a distinct SSID. With site-based SSID **disabled**, every site uses the same SSID (e.g. just `PSK`).

That is why the sim↔site linkage is **PXMX-server-based, not bucket-based**: linking the pxmx servers to a site (`pxmx_site_map`) makes each site its **own pool** of runners — the quota "10 DNS-fail in MIA" fills from the clients on MIA's nodes only, matching the RF chamber boundary. **Without** that linkage, every client resolves to its bucket-default `wsite` and you effectively get **one entire-tenant pool** (a quota with a blank site draws from anywhere). The key difference is **scale**: per-site pools bound a quota's blast radius and runner count to one chamber; a tenant-wide pool lets one quota consume runners across every chamber. Use per-site pools when chambers must be independent (separate RF isolation, separate SSIDs, separate client counts); use a tenant-wide pool when the plant is one logical fleet and you want maximum runner availability.

**Re-home (opt-in).** A per-quota `rehome` flag (default off) lets a site-specific quota borrow free runners from OTHER sites when its own pool can't fill the count — the engine sets `wsite` to re-home the borrowed client and the ledger records its original site (`from_site`) so a later release reverts it. Off by default so it doesn't defeat the per-site-pool isolation above; turn it on only when filling the count matters more than chamber isolation.

**Per-site apportionment across site-serving spokes.** A site-scoped quota is split ONLY across the spokes that actually hold clients for that site (each spoke's `CS_TELEMETRY` `pool_by_site` block), not across every bound cs spoke. The site is alias-resolved (a transitive fixpoint, so a site label and its normalized form both count), and the split is **proportional to presence** — the count each spoke is asked to fill scales with how many of that site's clients live on it. Alert-tied quotas stay EVEN among the site-eligible spokes; presence/untethered quotas stay PROPORTIONAL. When no telemetry places the site on any spoke (cold cache / a just-connected spoke), it falls back to the legacy even/total-pool split so a freshly-joined spoke isn't starved. (`core/src/simulations/routes.py` `_site_weights` / `_payload_for`.)

**Adaptive "max without firing" alert.** When a quota is in adaptive-learning mode and has ramped its target up to `max` (the `at_max` phase) but the underlying monitored alert STILL isn't firing — and the engine actually filled to that max from the online pool — the hub fires an `adaptive_quota_maxed` alert ("Adaptive quota — at max, alert not firing"). It's the floor-learner telling you it's capped: the learner can't push the count higher, so if the alert still isn't appearing the sim quota alone won't surface it (the check definition, mapping, or upstream telemetry is the suspect). Edge-triggered against the spoke ledger so it only fires when the quota genuinely filled.

**Sharing is GLOBAL, not per-quota.** The per-quota stacking/sharing flag was removed — sharing (which sims may stack on the same client) is a **platform-wide** property, stored under the store's `__global__` key (`get_sim_shareable_global`) and pushed to every tenant's spoke. Per-quota rows carry only `multi_capable` / `rehome` / `learning` / `learn_knobs`, not a sharing flag. Configure the shareable/stackable map once in Setup → Simulations; it applies to all tenants and all three sources.

**Quota State view.** Config → Quota State shows the live ledger: which clients are currently assigned to each effective quota, the target count vs. assigned count, and `multi_capable`/`rehome` flags. (Manual-refresh under Config — form editors and the state view share the Config primary's no-auto-refresh.)

## Diagnostic tab (per product)

Each product tab (Central, Central On-Prem, Mist) has a **Diagnostic** subtab that compares the RAW vendor-API findings (alerts + insights) against the DERIVED dashboard status + firing, per monitored check and per site — so you can see exactly where the engine's view of a check diverges from what the vendor API actually returned (a stale poll, a missing site mapping, a check that's monitored but never fires). The render is one shared function, `_csRenderDiag(source)` (`WebUI/sim-views.js`), that routes per-source to its own browse call (`csCentralBrowse` / `csCentralOnPremBrowse` / `csMistBrowse`) and filters `monitored_checks` to that source only. A **Copy** button (`csCopyText(window._csDiagCopyText, …)`) puts the raw comparison in the clipboard for a support paste.

## How to use it

**Enable client simulation / auto-provisioning (the two toggles that both must be on).** Auto-provisioning has a *tenant* switch and a *per-agent* switch, and VMs only spawn when **both** are on:

1. Turn on the **tenant** switch: Simulations → **Setup → Proxmox** (or Config → Simulation), in the **"VM Auto-Provisioning"** card, set **"Auto-Provision VMs"** on (`usb_auto_provision`). While here also confirm the card's other knobs — VM template IDs, VMID range, CPU/mem thresholds, dongle VID:PIDs — since a missing template or empty dongle list also stops provisioning.
2. Turn on the **per-agent** switch for each Proxmox host: Setup → **Spokes & Agents** → the agent's row → **Edit** → check **"Enable Client Simulation mode on this host"** (`client_simulation.enabled`) and save. This is what actually puts the pxmx agent's provision loop into CS mode.
3. Watch **Simulations → VM Server**: each host row shows the `provision` diagnostic; when both flags are on and thresholds pass, the agent begins cloning sim VMs into the 90000+ VMID range.

**Overview Auto-Prov tile.** The VM Server → **Overview** page carries an **Auto-Provisioning** tile (top-aligned 2-col alongside the Fleet Reclone card, `csRenderVmServer` in `WebUI/sim-views.js`) listing every in-flight VM across the fleet with its status — prov-run / teardown / reclone — plus an inline **Enable** toggle (`csToggleAutoProvision`). It's live: `csAutoProvLivePanel` aggregates the fleet's in-flight VMs into `#cs-autoprov-live`, driven by `cs_progress` websocket frames via `csOverviewLiveRefresh` (re-renders within ~1s of a progress event and self-schedules a 2.5s refresh while work is in flight), so you can watch a clone/teardown sweep happen in real time without a manual refresh.

**Run a demo scenario (auto-expiring fault).** Simulations → **Clients** tab → the target client's **Demo** column → pick a scenario (`normal` = clear, or one of `dns_fail` / `dhcp_fail` / `assoc_fail` / `auth_fail` / `ssidpw_fail` / `port_flap`) → trigger. It shows in the **"Active Demo Scenarios"** card with minutes remaining; it auto-clears after **120 minutes** (or on client reboot), reverting to the client's persisted state. Clear early from the same card / column.

**Toggle a per-client fault (persisted override).** Simulations → **Clients** → the client row's **⚙ Control** button opens **"Live Overrides — {hostname}"** with the 11 toggles: `kill_switch`, `dns_fail`, `iperf`, `download`, `www_traffic`, `ping_test`, `ssidpw_fail`, `auth_fail`, `dhcp_fail`, `port_flap`, `assoc_fail`. Set what you want → **Apply** (persists to that client), **Clear Overrides** (removes them), or **Apply to ALL** (pushes the same set to every registered client). Unlike a demo, these persist until you clear them. The client picks them up on its next `/api/config` fetch.

**Use the kill switch (emergency stop).** Simulations → **Clients** → the banner at the top: **"⛔ Emergency Stop"** halts all sims (clients poll `/api/kill-switch` and stand down); **"▶ Resume Sims"** re-enables. This is global; the per-client `kill_switch` override above stops just one client.

## Troubleshooting / common questions

**"Auto-provisioning is enabled but nothing provisions."** This is almost always the **two-flag trap**: the tenant-level **"Auto-Provision VMs"** toggle (`usb_auto_provision`) is a *different* switch from each host's **"Enable Client Simulation mode on this host"** (`client_simulation.enabled`). The pxmx agent's loop only spawns when **both** are on. Check the host's `provision` diagnostic on **VM Server** — it reports `cs_enabled`, `loop_running`, `auto_provision_on`, a `reason` string for the current gate, and `halt`. Common gate reasons beyond the two flags: no VM template configured, an empty dongle VID:PID list, CPU/mem over the 1h-average thresholds, or `provision_halt` set. Remember the brain runs in the agent; cs only relays and displays the diagnostic.

**"Sim clients aren't getting an IP."** Their addresses come from the **cs-owned Kea** (`kea-dhcp4-sim`) on the **second NIC** at `169.253.1.1`, subnet `169.253.1.0/24`, pool `169.253.1.11`–`.254` — not from the `dhcp` module. Check the hub-level **Setup → Simulations** DHCP-server card (or the telemetry `dhcp` block) for `installed`/`running`/utilization. On the box: `systemctl is-active kea-dhcp4-sim`, confirm the second NIC is up at `169.253.1.1`, and that the sim VMs are actually on the isolated network. Because the scope serves no router option, sim clients are intentionally isolated and reach only `169.253.1.1:8080`.

**"I changed a config/provisioning setting and nothing happened."** Hub-pushed provisioning config lands via the **`CS_CONFIG_UPDATE`** handler; without it, `usb_vidpids` stays `[]`, the bridge pulls an empty list every 60s, and auto-provision never fires. Also note the hub-config store **REPLACES** on write, so the two Setup cards ("VM Auto-Provisioning" and the flat "Hub Config") must GET-merge-PUT — if a save wiped the other card's values, re-open both and re-save. For simulation-profile edits, remember they only apply to a client on its next `/api/config` fetch, and per-`[username]` overrides key off the hostname's first `-` segment.

**"The simulation spoke is offline / red."** cs runs mainly as the **`simulation`** role on the agent (sub-spoke `{agent}-simulation`), dialing the hub on 443. If it's red: confirm the agent (`lm-agent`) is up and approved, that `install_cs.sh --infra-only` host prep ran (cs Kea + second NIC), and check the spoke logs. A spoke that never provisioned its Kea/NIC still connects but the DHCP card shows "Not configured."

**"Why is the client API on 8080 and not 8000?"** The legacy `webui-spoke` used :8000, but the unified LM hub owns that box, so binding :8000 collided and crash-looped cs. The client API moved to **8080**; sim clients reach `169.253.1.1:8080`. The installer auto-migrates a stale `CS_API_PORT=8000` in `.env` to 8080.

## Related pages

[architecture-topology.md](architecture-topology.md), [pxmx.md](pxmx.md), [lm-hub.md](lm-hub.md), [environment-variables.md](environment-variables.md), [install-flags.md](install-flags.md), [mist.md](mist.md), [central-on-prem.md](central-on-prem.md).