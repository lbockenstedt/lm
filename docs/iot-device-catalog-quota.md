# IoT Device Catalog → Quota Engine (design / investigation)

Status: **investigation + design** (no implementation yet). Working doc to pick
up later. The catalog data file + loader exist on disk
(`cs/clients/t3/iot_catalog.json`, `cs/clients/t3/catalog.py`); everything else
here is design. Plan mirror: `.claude/plans/precious-napping-seahorse.md`.

## Goal

Feed the IoT device catalog into the sim-quota engine so an operator can
declare e.g. **"5 ClickShare devices on Site MIA"** and the engine keeps that
many emulated devices of that profile realized at that site. The catalog is
the device menu; the quota engine is the enforcement.

User-aligned decisions (this session):
- **Surface: Both** — T3 virtual WLAN interfaces for *wireless* IoT profiles
  (`surface=t3-vwlan`), cs VM clients for *wired/edge* profiles
  (`surface=vm-client`). Engine routes each catalog entry by `surface`
  (resolved in `catalog.py::device_surface`).
- **Expression: new `device` quota kind** — stored in
  `central_sites_config["sim_quotas"]` alongside alert-driven + presence;
  dedup `device::{device_id}::{site}`; rendered in Config → Sim Quotas with a
  Device dropdown sourced from the catalog.

---

## What exists today

### Quota engine (`cs/lm-spoke/src/sim_quota.py` + `lm/core/src/simulations/sim_quota.py` — byte-identical twins)
- Two quota kinds, both **detected by shape**: sim-quota (`sim_id` set) and
  presence (`sim_id` empty = "Clients Associated", N clients homed to a site,
  no sim).
- `quota_dedup_key`: sim → `alert_type:alert_id:site` (untethered sim →
  `sim:{sim_id}:{site}`); presence → `presence::site`.
- Engine (`cs/lm-spoke/src/sim_quota_engine.py`) pool = online registered cs
  clients by hostname; site resolved via `pxmx_site_map` → bucket `wsite`.
  Keep-substitute semantics: offline assigned client kept in ledger, substitute
  fills, over-N trim releases substitute, dead (>OFFLINE_TTL) released.
- `merge_effective_quotas` (lm twin, `sim_quota.py:258-329`): splits on `sim_id`
  truthiness into sim/presence buckets; sim merges per `(alert_type, alert_id)`;
  presence merges per-site (tenant owns a site → enabled wins, disabled
  suppresses global).
- Catalog endpoint: hub `GET /sim/api/{tenant}/sim-quota-catalog`
  (`routes.py:3436`) forwards `CS_GET_SIM_QUOTA_CATALOG` to cs spoke
  (`handlers_config.py:159`); 503-fallback calls `sim_quota_catalog_from_ini`
  (`sim_quota.py:636`) → `{sims, sites, suggested, meta}` (no `devices` yet).
- Store: global defaults `store.get/set_sim_quota_defaults` (`store.py:840`);
  per-tenant `sim_quotas` inside `central_sites_config`.
- UI row in **three** copies: `cs/lm-spoke/static/sim-views.js` (spoke),
  `lm/WebUI/sim-views.js` (hub Config→Sim Quotas), `lm/WebUI/main.js` setup
  editor (`_renderSimQuotaDefaultsEditor`). Presence already special-cases the
  row (`isPresence = !r.sim_id` → hides Type/Alert ID) — reusable template for
  a device kind.

### T3 / IoT surface
- `cs/clients/t3/` already has full opt60/opt55 fingerprint machinery:
  `wireless.sh` (per-vendor `dhcpcd -h <name> -i <opt60> -o <opt55> vwlanN` +
  per-vendor traffic), `gen_macs.sh` (reads `mac_config.json` → assigns
  `oui:07:<host_md5[:2]>:<iface#>` MACs + udev rules), `mac_config.json`
  (`[{vendor, oui, count}]`, total ≤25).
- A T3 mac-profile push path **does exist** — but in
  `cs/webui-local/app/routers/t3.py` (`t3_mac_update` command, payload
  `{mac_config}`), a **separate hub app**. Neither `lm/core` nor `cs/lm-spoke`
  has a handler for it. So the sim-quota stack has **no path to a T3 device**
  today.
- **Linux client has no fingerprint knob** (only DHCP option-12 host-name
  shaping at `simulation.sh:451`). DHCP-fingerprint work was research-only.

### Catalog (built this session)
`cs/clients/t3/iot_catalog.json` — 42 device profiles, each: id, vendor, model,
category, hostname, oui (or null), count, verified, source, dhcp
{vendor_class_id (opt60), param_request_list (opt55)}, traffic
{dns[], curl[], http[], wget[]}. 25 with OUI (exactly reproduces the existing
`mac_config.json`).
`cs/clients/t3/catalog.py` — `--validate` (green: 42 devices, 25 OUI),
`--emit-mac-config` (reproduces mac_config.json), `--emit-fingerprints`
(opt60/opt55/hostname/surface TSV), `--sim-quota-catalog` (device menu with
resolved `surface`: 37 `t3-vwlan`, 5 `vm-client`). Surface resolution:
explicit entry `surface` > `DEVICE_SURFACE_OVERRIDE` > `CATEGORY_SURFACE` >
`t3-vwlan`.

---

## Design: the `device` quota kind

Detected by shape (no explicit `kind` field), mirroring presence:
**`device_id` set AND `sim_id` empty** → device quota. This maximally reuses
the engine: a device quota on the vm-client surface behaves like an **exclusive
sim quota** whose per-client override is `device_profile=<id>` instead of
`<sim_id>=on`.

- `SIM_QUOTA_KEYS` += `"device_id"`.
- `normalize_quota`: coerce `device_id`; device shape → `multi_capable=False`
  (exclusive: one DHCP fingerprint per client interface), `alert_id=""`.
- `quota_dedup_key`: device → `device::{device_id}::{site}`.
- `validate_sim_quotas`: device branch — requires `device_id` + `site`,
  `sim_id` empty, `device_id in available_devices` (new arg); presence must not
  carry `device_id`; sim must not carry `device_id`; both set → error.
- Device quotas not knob-learnable (`learn_knobs` forced False).
- `merge_effective_quotas`: carve device rows into a third bucket; merge per
  `(device_id, site)` mirroring presence-per-site.
- Catalog response += `devices` key (from `catalog.sim_quota_catalog`).
- Vendor `iot_catalog.json` + `catalog.py` as a byte-identical twin into
  `lm/core/src/simulations/` (same pattern as `sim_quota.py`) so the hub
  fallback returns `devices` without a spoke round-trip.
- UI: `isDevice = !!r.device_id` branch in all three row renderers — hide
  Type/Alert/Sim, show Device `<select>` from catalog, keep Count/Site/Enabled.

---

## Client identity — "kbell cannot be a Tesla" (key design constraint)

### Current identity model (linux client)
Two distinct identities, both from the system hostname (e.g. `kbell-01`):

| Identity | Value | Used for | Set by |
|---|---|---|---|
| **management** | `hostname=$(hostname)` → `kbell-01` | `/api/status` `hostname` (`simulation.sh:457/492`), WS `?hostname=`, spoke/hub registry key, ledger | system hostname (unchanged) |
| **username** | `${HOSTNAME%%-*}` → `kbell` | per-user override section `[$username]`, **DHCP option 12** (host-name), **802.1X EAP identity** | `derive_username` (`common.sh:25`) |

Wire shaping today is **only DHCP option 12**: `simulation.sh:451` sed-replaces
`gethostname()` in `dhclient.conf` with `"$username"` so Central shows `kbell`
(comment: "Pure aesthetics so the usernames in Central look good"). No
`hostnamectl set-hostname`, no avahi/mDNS, no DNS registration — system hostname
and mDNS name stay `kbell-01`. 802.1X identity = `$username`
(`802-1x.identity "$username"`, lines 800/811).

So today: **wire identity = username = `kbell`**; **management identity =
hostname = `kbell-01`**.

### What a device profile must change (wire only)
The catalog already has a `hostname` per device (`Tesla`, `HPPrinter`,
`BarcoShare`). A `device_profile` override repoints the **wire identity** at
the device, leaving management identity intact:
- **DHCP option 12** (host-name) → catalog `hostname` (e.g. `Tesla`) not
  `$username`.
- **DHCP option 60** (vendor-class) → catalog `vendor_class_id`.
- **DHCP option 55** (param-request-list order) → catalog `param_request_list`.
- **802.1X identity** → catalog `hostname` (per-profile; many IoT devices
  don't do 802.1X).
- **traffic** → the profile's dns/curl/http/wget endpoints.
- **management identity stays** `kbell-01`: `/api/status` still reports the real
  hostname; registry/ledger/quota-state still track the VM; `[$username]`
  overrides still key on `kbell`. The spoke reads `device_profile` from the
  `[sX]` bucket (like `wsite`/sim flags) and bakes the device's
  opt60/opt55/hostname/traffic into the bucket via `/api/config` — the client
  stays dumb.

Profiler (ClearPass/Aruba) keys on MAC + opt60 + opt55 + option-12 → sees a
Tesla.

### Gotchas
1. **Option-12 shaping is once-per-boot.** `simulation.sh:450` guards on
   `.dhcp_hostname_done` and sed-replaces `gethostname()` once; afterward
   `gethostname()` is gone from dhclient.conf. A device profile that **changes**
   (quota reassigns ClickShare → Tesla) must re-write dhclient.conf + restart
   dhclient — the marker model breaks for dynamic swaps. **The device-profile
   path must be re-runnable** (clear marker, re-sed option 12/60/55, `dhclient
   -r`/renew) on each profile change, not once-per-boot.
2. **MAC is still the VM's real MAC** (deferred). Central sees a Tesla
   fingerprint on a non-Tesla OUI — a *partial* disguise. Completing it needs
   pxmx `qm set --netN mac=<OUI>:…` (Chunk 2 deferred item). Without it, "kbell
   looks like a Tesla" only at the DHCP-fingerprint layer, not the MAC layer.
3. **Hostname collisions across a fleet.** 5 ClickShare on MIA all send option
   12 = `BarcoShare` with distinct real MACs. Real IoT fleets share a model
   name, but many append a serial. Refinement: `device_hostname = <catalog
   hostname>-<host_seed>` (e.g. `BarcoShare-07`, mirroring the T3 MAC
   `:07:<seed>`) — keeps vendor identity, mimics per-device serials, avoids 5
   identical hostnames. Optional; catalog `hostname` is a model name, not
   unique-by-design.

Net: the wire-vs-management split already exists (option 12 = username today);
a device profile just repoints the wire layer at the catalog's
`hostname`/opt60/opt55/traffic while the registry keeps `kbell-01`. The real
work is making DHCP shaping re-runnable (#1) and deciding the hostname-suffix
convention (#3). MAC disguise (#2) is the deferred pxmx piece.

---

## Build chunks (in order)

### Chunk 1 — config foundation (no client/engine behavior)
- Schema: `device_id` in `SIM_QUOTA_KEYS` (both twins); normalize/dedup/validate;
  `merge_effective_quotas` device bucket; catalog `devices` exposure; vendor
  catalog twin into `lm/core/src/simulations/`.
- Routes: `set_central_sites` passes `available_devices`; defaults editor
  validates against catalog; `get_sim_quota_catalog` carries `devices`.
- UI: `isDevice` branch + Device dropdown in all three row renderers + Quota
  State renderer for device rows.
- Tests: cs + lm sim_quota device normalize/validate/dedup/catalog/merge.
- Low-risk; declaring a device quota only stores+validates+merges+renders it.

### Chunk 2 — vm-client engine + client knob (wired/edge surface)
- `sim_quota_engine.py`: device quotas reconcile like exclusive sims;
  `_quota_key` = `device::{device_id}::{site}`; `_assign` sets
  `device_profile=<id>` override (+ `wsite` re-home if `rehome`); `_release`
  clears it; `_pool_eligible` excludes clients already assigned to ANY device
  quota (one profile per client); ledger entry stores `device_id`; `_has_sim_on`
  applies to `device_profile`; substitute-on-offline/dead unchanged.
- Client (`cs/clients/linux/`): `simulation.sh` reads `device_profile` from the
  bucket via `get_value`; a new `device_profile.sh` (sourced from `lib/`)
  emits opt60/opt55 + option 12 = device hostname + traffic endpoints.
  **Re-runnable** (gotcha #1): clear `.dhcp_hostname_done`, re-sed dhclient.conf,
  `dhclient -r`/renew on profile change. `common.sh` `CS_OVERRIDE_KEYS` +=
  `device_profile` (+ `device_hostname`/`device_vendor_class`/`device_opt55`
  baked by `/api/config`). Bump `simulation.sh` `version=` header on edit.
- MAC emulation (vNIC → OUI) deferred (gotcha #2) — pxmx `qm set --netN`.

### Chunk 3 — t3-vwlan engine bridge (wireless surface; largest)
- Bridge lm/core sim-quota engine → existing `cs/webui-local` `t3_mac_update`
  push path. For t3-vwlan device quotas, engine computes a per-site device-mix
  (`mac_config` via `catalog.py --emit-mac-config` + fingerprint/traffic table
  via `--emit-fingerprints`) and pushes to the T3 Pis in that site. Cross-app
  gap (lm/core ↔ cs/webui-local): engine emits `t3_device_mix` the cs spoke
  consumes and re-publishes as `t3_mac_update`, OR calls the webui-local route
  directly — **design at Chunk 3 kickoff** (the open architecture question).
- T3 consumption: `wireless.sh`/`gen_macs.sh` read the pushed device-mix instead
  of the hardcoded per-vendor blocks (catalog + pushed JSON drive per-interface
  fingerprint+MAC+traffic; T3 primitives already exist).
- Reconcile verifies interface counts per site (extend the `/api/status`
  heartbeat payload with vwlan state).

---

## Verification (later)
- Static: `ast.parse` edited `.py`; `import sim_quota` smoke both twins;
  `python3 cs/clients/t3/catalog.py --validate` (already green).
- Unit (Chunk 1): sim_quota device tests; UI round-trip smoke.
- Lab (Chunk 2): declare `hue-bridge` x2 on MIA → engine assigns 2 MIA clients
  `device_profile=hue-bridge`; `curl /api/config?hostname=<h>` shows
  `[sX] device_profile=hue-bridge` + baked opt60/opt55/hostname/traffic;
  `dhclient` DISCOVER carries the vendor-class + device hostname (tcpdump /
  Aruba Central profiler confirms); substitute on offline; profile swap
  re-runs DHCP shaping.
- Lab (Chunk 3): declare `barco-clickshare` x5 on MIA → MIA T3 Pi gets a pushed
  mac_config + fingerprint table → `gen_macs` brings up 5 `vwlan` with ClickShare
  OUI MACs + `wireless.sh` runs 5 `dhcpcd -i/-o` + barco.com traffic; reconcile
  verifies 5 up.
- Deploy: WebUI Update button only (no CLI `/opt/lm` pulls on hub — watchdog-gated
  2am).

## Non-goals / open items
- MAC emulation on vm-client deferred to after Chunk 2 fingerprint+traffic.
- lm/core ↔ cs/webui-local bridge designed at Chunk 3 kickoff.
- Catalog `verified: false` expansion entries need OUIs confirmed against the
  IEEE registry before fleet MAC use; `--validate`/`--emit-mac-config` gate on
  OUI format but not registry validity. Operator curates counts ≤25 for MAC pool.
- Hostname-suffix convention (`BarcoShare-07`) undecided — see gotcha #3.
- Per-tenant scope (one sim_quotas list per tenant + global defaults); no
  per-host device override.

## Artifacts on disk now
- `cs/clients/t3/iot_catalog.json` — the catalog (42 devices).
- `cs/clients/t3/catalog.py` — loader/validator/emitter.
- `lm/docs/iot-device-catalog-quota.md` — this doc.
- `.claude/plans/precious-napping-seahorse.md` — plan mirror.