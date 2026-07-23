# Central On-Prem — a second Aruba Central instance (full twin + sim-quota)

Some operators run **two** Aruba Central planes: the public cloud Aruba Central
**and** an on-prem Aruba Central appliance. Before this feature the whole
Central surface was *one slot per tenant* — a single `central_config`, a single
`central_sites_config`, one `CentralHubPoller` pass, one `central_hub_status`,
one "Central" WebUI tab, one `"central"` sim-quota source. A second instance
would overwrite the first's config ("step on each other") and its alerts would
merge with cloud Central's in the sim-quota catalog.

**Central On-Prem** is a *third, fully-independent* Aruba Central instance that
sits alongside cloud Central and Mist. It reuses the **same Aruba Central API /
`ArubaClient`** unchanged (cloud vs on-prem differ only in config — `cluster_url`
+ creds — so `ArubaClient`'s module caches, keyed by an md5 of the config,
naturally keep the two separate). What's separate is everything *around* the
client: the config slot, the poller, the telemetry bucket, the sim-quota source,
and the WebUI tab. This mirrors exactly how Mist was added as a twin to Central
— a third sibling, not a refactor of Central into a list.

The result is **3 product tabs under Simulations: Central, Central On-Prem,
Mist**, and **3 sim-quota sources**: `Central:`, `Central On-Prem:`, `Mist:`.
A `Central On-Prem:<type>` quota fires on **on-prem** telemetry only — never
cloud Central's — so the two instances coexist without stepping on each other.

See also: [cs.md](cs.md) (the sim-quota engine + the shared spoke surface),
[mist.md](mist.md) (the Mist twin this was modelled on).

## The no-stepping guarantee (the invariant)

Cloud Central and Central On-Prem share the **same Aruba API** but live in
**separate slots at every layer**, so they can never overwrite or merge with
each other:

- **Store** — `central_config` / `central_sites_config` (cloud) vs
  `central_on_prem_config` / `central_on_prem_sites_config` (on-prem). Both hub
  (`core/src/simulations/store.py`) and cs spoke (`lm-spoke/src/local_store.py`).
- **Poller** — one parameterized `CentralHubPoller` class; the on-prem instance
  writes `central_on_prem_hub_status` (cloud writes `central_hub_status`). On
  the cs spoke one parameterized `CentralPoller` writes `central_on_prem_status`
  (cloud writes `central_status`).
- **Telemetry** — the cs spoke relays on-prem data under `data["central_on_prem"]`
  (cloud under `data["central"]`).
- **Sim-quota source** — `"central_on_prem"` routes to its OWN telemetry bucket
  (`data_key = source`), distinct from `"central"`.
- **Tracker shards** — on-prem uses separate filenames
  (`central_on_prem_client_count_baseline.json`,
  `central_on_prem_client_count_7day.json`,
  `central_on_prem_check_health_history.json`) so baselines/health history are
  isolated.
- **WebUI** — a separate `Central On-Prem` tab + `Central On-Prem API` Setup
  subtab, with their own table-state ids and DOM ids (see [WebUI](#webui)).

A single hub config-push that carries BOTH `central_config` and
`central_on_prem_config` lands each in its own slot — verified by
`test_config_update_central_on_prem_does_not_touch_cloud_central`.

## Config + processing mode

- **`central_on_prem_config`** — the on-prem Aruba Central creds: `cluster_url`
  (the on-prem cluster endpoint), `api_version` (`new_central` / `classic`),
  `client_id`, `client_secret`, `access_token`, `refresh_token`, plus the
  poll/processing knobs (`poll_interval_s`, `cc_thresholds`).
- **`central_on_prem_sites_config`** — the per-tenant site mappings,
  monitored checks, hardware checks, sim quotas (same shape as the cloud
  `central_sites_config`). Quota `alert_id`s use the `Central On-Prem:` prefix.
- **`processing_modes.central_on_prem_api`** — `"centralized"` (default, unset
  → centralized) or `"distributed"`. `central_on_prem_api_is_centralized(modes)`
  mirrors the cloud `central_api_is_centralized` check.

In **centralized** mode (default) the **hub** runs the on-prem poller + serves
browse/available/test from the on-prem config directly — the spoke is not
contacted. In **distributed** mode the hub forwards `CS_CENTRAL_ON_PREM_*`
commands to the cs spoke, which runs its own on-prem `CentralPoller` instance.

## Hub poller — one class, two instances

`core/src/simulations/central_hub_poller.py` is **parameterized** by an
instance slot rather than copy-pasted for on-prem. A module-level
`_CENTRAL_INSTANCES` dict has two entries — `"central"` (default) and
`"central_on_prem"` — each carrying: the catalog `source` stamp, the
`status_attr` on the hub (`central_hub_status` /
`central_on_prem_hub_status`), the store `config_getter`/`sites_getter`, and
the `mode_check`.

`CentralHubPoller.__init__(self, hub, instance="central")` stores
`self._inst = _CENTRAL_INSTANCES[instance]`; the ~5 places that previously
hardcoded `central` read from `self._inst` (the centralized-tenant selection,
the per-tenant config/sites reads, the `"source"` stamp, and the hub status
write). **Default `instance="central"` keeps existing behavior byte-identical**
— the on-prem instance is purely additive. Hub startup constructs a SECOND
`CentralHubPoller(hub, instance="central_on_prem")` and starts its own loop
(separate `_last_poll`/sleep, mirroring how the Mist poller runs alongside
Central). Each writes its own status slot.

## Sim-quota source routing

The `SimQuotaEngine` firing-eval (`core/src/simulations/routes.py`) routes each
quota to its **own** source's telemetry. The key generalization:

- `data_key = source` (the canonical lowercase key: `"central"`,
  `"central_on_prem"`, `"mist"`). Previously this was a `mist`-vs-`central`
  binary; for those two `data_key = source` is exactly equivalent, so no
  behavior change — only `central_on_prem` newly routes correctly.
- `service._hub_block_for_source(source, tenant_id)` dispatches `central` →
  `_hub_central`, `mist` → `_hub_mist`, `central_on_prem` →
  `_hub_central_on_prem` (default `_hub_central`).
- The spoke telemetry `src = (data or {}).get(data_key)` is already generic;
  the cs spoke relays `data["central_on_prem"]`.
- The per-source `alias_groups` dict gains a `"central_on_prem"` key (sourced
  from `get_central_on_prem_sites_config`), so alias resolution is per-source.
- `parse_alert_source` returns `"central_on_prem"` for `Central On-Prem:` ids,
  so a stored on-prem quota parses to the right source and routes correctly.

Source-prefix maps live in `core/src/simulations/sim_quota.py`:
`SOURCE_PREFIXES = {"central": "Central", "mist": "Mist",
"central_on_prem": "Central On-Prem"}`, and `_PREFIX_TO_SOURCE` is **derived**
(`{label.lower(): src for src, label in SOURCE_PREFIXES.items()}`) so the
display form `"Central On-Prem"` (with spaces/hyphens) maps to the source key
`"central_on_prem"` without a hand-maintained duplicate that would drift.

## Hub routes (mirror of the 9 Central routes)

`core/src/simulations/routes.py` mirrors the cloud Central routes adjacent to
them, reusing the **same Aruba helpers** (`browse_all_from_config`,
`test_central_from_config`, `get_central_available_from_config`) since the
on-prem API is identical to cloud Central's:

- `GET /sim/api/aggregate/central-on-prem` → `service.get_central_on_prem_data`
  (the per-spoke inventory; each spoke's on-prem telemetry is read from
  `data["central_on_prem"]` and returned under the **same `central_status` key**
  cloud Central uses, so the WebUI renderers work unchanged).
- `GET /sim/api/aggregate/central-on-prem-status` — merges
  `hub_central_on_prem_config` (token validity etc.).
- `GET /sim/api/aggregate/central-on-prem-browse` — centralized →
  `browse_all_from_config(cc_on_prem)`; distributed → forwards
  `CS_CENTRAL_ON_PREM_BROWSE`; records history tagged `source="central_on_prem"`.
- `POST /sim/api/aggregate/central-on-prem` → `save_central_on_prem`: **SSRF
  guard on `cluster_url`** (on-prem cluster_url is still an outbound hub target —
  `safe_external_url` + `host_resolves_external` apply), `poll_interval_s` floor
  60, `cc_thresholds` clamp; then `store.set_central_on_prem_config` +
  `_push_config({"central_on_prem_config": cfg})`.
- `GET/POST /sim/api/{tenant}/central-on-prem-sites-config` — merge +
  `validate_sim_quotas` + `set_central_on_prem_sites_config` +
  `_invalidate_sim_quota_catalog` + push
  `{"central_on_prem_sites_config": ..., "effective_sim_quotas": ...,
  "sim_shareable": ...}`.
- `GET /sim/api/{tenant}/central-on-prem/available` — centralized →
  `get_central_available_from_config(cc_on_prem)`; distributed →
  `CS_GET_CENTRAL_ON_PREM_AVAILABLE`.
- `POST /sim/api/{tenant}/test-central-on-prem` — centralized single "Hub
  (centralized)" row via `test_central_from_config`; distributed fans
  `CS_TEST_CENTRAL_ON_PREM`.

**`_record_alert_insight_history` source-tag fix.** The history recorder
previously hardcoded `source in ("central", "mist")` and reset anything else to
`"central"` — so an on-prem browse alert would have been tagged `Central:` in
the catalog picker. It now validates against `sim_quota.SOURCE_PREFIXES`, so
on-prem browse alerts correctly render as `Central On-Prem:`.

## CS spoke — on-prem commands + poller + push path

The cs spoke (`cs/lm-spoke/`) mirrors the cloud Central block but parameterizes
the **one** `CentralPoller` class by an instance slot (a module-level
`_INSTANCES` dict: `"central"` default, `"central_on_prem"`), selecting the
config getter, sites getter, the `status_attr` to write, and the tracker shard
filenames. Default `instance="central"` is byte-identical; the on-prem instance
writes `central_on_prem_status` and its own shard files.

- `central_poller.py` — `CentralPoller(spoke, instance=…)`; `_cfg()` /
  `_sites_cfg()` / `_set_status()` / `reload()` read from `self._inst`. The
  on-prem poller writes `central_on_prem_status` (cloud writes
  `central_status`) and uses `central_on_prem_client_count_baseline.json` /
  `central_on_prem_client_count_7day.json` /
  `central_on_prem_check_health_history.json`.
- `cs_spoke.py` — constructs both: `self.central_poller = CentralPoller(self)`
  (cloud) and `self.central_on_prem_poller = CentralPoller(self,
  instance="central_on_prem")`.
- `control_plane.py` — starts both pollers; relays
  `payload["central_on_prem"] = getattr(cs_mod, "central_on_prem_status", {})`
  alongside the cloud `payload["central"]` relay.
- `command_handlers/handlers_config.py` — the `CS_CENTRAL_ON_PREM_*` command
  block: `CS_GET/SET_CENTRAL_ON_PREM_CONFIG` (`_merge_central_on_prem_config`
  sentinel-merge twin — empty values KEEP existing creds, they're a sentinel
  not a wipe — + `central_on_prem_poller.reload()`),
  `CS_GET/SET_CENTRAL_ON_PREM_SITES_CONFIG` (validate_sim_quotas + reload),
  `CS_GET_CENTRAL_ON_PREM_AVAILABLE`, `CS_TEST_CENTRAL_ON_PREM`,
  `CS_CENTRAL_ON_PREM_BROWSE`, `CS_GET_CENTRAL_ON_PREM_HEALTH`. The
  `_apply_hub_config` path branches for `central_on_prem_config` +
  `central_on_prem_sites_config` (mirroring the cloud `central_config`
  branch), so hub-pushed on-prem config reaches the on-prem poller.

On-prem config is hub-pushed the same way as cloud Central — the cs spoke never
git-pushes it (the repo-sync strip invariant holds).

## WebUI

**sim-views-both-copies-edit-convention:** `lm/WebUI/sim-views.js` AND
`cs/lm-spoke/static/sim-views.js` carry byte-identical renderer code (the
per-copy `csFetch` shim handles the `/sim/api` vs `+?tenant_id=default`
difference). Edit both.

- **`lm/WebUI/main.js`** — the `cs` tab list gains `'Central On-Prem'` after
  `'Central'`; `VIEW_CHILDREN.cs` gains `'Central On-Prem': ['Sites',
  'Alerts', 'Insights', 'Clients', 'Hardware', 'Diagnostic']`; Setup gains
  `'Central On-Prem API'` after `'Central API'`.
- **`sim-views.js`** — a full on-prem renderer twin (`csCentralOnPremBrowse` +
  `csCentralOnPremTable` machinery + `csRenderCentralOnPrem` / `…Alerts` /
  `…Insights` / `…Clients` / `…Hardware` / `…Diagnostic` +
  `csMonitorCentralOnPremSiteModal` + `csToggleMonitorOnPremHardware` +
  `csCentralOnPremAvailable`), copied from the cloud Central block and
  repointed to `/aggregate/central-on-prem*` endpoints + `central-on-prem`
  table-state ids, mirroring exactly how the `csMist*` renderers were derived
  from `csCentral*`. The Setup twin (`csRenderSetupCentralOnPremApi` +
  `csSaveCentralOnPremConn`) posts `{mode, hub_central_on_prem_config}` to
  `/aggregate/central-on-prem`, with `cs-cop-csc-` DOM ids (the `cs-cop-`
  prefix avoids collisions with the cloud Central Setup form's `cs-csc-` ids).
- **`_csRenderDiag` generalization** — the shared Diagnostic helper now handles
  three sources: `prod = source === 'mist' ? 'Mist' : source ===
  'central_on_prem' ? 'Central On-Prem' : 'Central'`, the browse call dispatches
  `csCentralOnPremBrowse()` for on-prem, and the monitored-checks filter
  (`String(c.source || 'central').toLowerCase() === source`) already kept
  per-source isolation, so an on-prem Diagnostic tab shows only on-prem checks.
- **`cs/lm-spoke/static/dashboard.html`** — adds the `Central On-Prem` tab
  button (after `Central`) and the `Central On-Prem API Setup` tab button
  (after `Central API Setup`), plus the `TAB_RENDERERS` entries.

## Tests

- `core/tests/test_central_on_prem_source_routing.py` — the engine routes a
  `Central On-Prem:<type>` quota to on-prem telemetry only (cloud status=error
  doesn't fire it; on-prem status=ok does); all three sources survive a union
  with distinct counts; cloud/Mist routing unchanged with on-prem present.
- `core/tests/test_central_on_prem_routes.py` — not-configured → empty; save
  validates + pushes `central_on_prem_config`; the SSRF guard rejects internal
  `cluster_url`s (`127.0.0.1`, `10.0.0.5`, `localhost`) and coerces
  `poll_interval_s=10→60`; browse records history tagged
  `source=central_on_prem`; distributed forwards `CS_CENTRAL_ON_PREM_BROWSE`.
- `core/tests/test_central_on_prem_poller.py` — default instance unchanged;
  on-prem instance reads `get_central_on_prem_config`, writes
  `central_on_prem_hub_status`, stamps `source="central_on_prem"`.
- `cs/lm-spoke/tests/test_handlers_central_on_prem.py` — the
  `CS_CENTRAL_ON_PREM_*` commands read/write their OWN slots; the sentinel-merge
  keeps existing creds; `_apply_hub_config` reaches the on-prem poller; setting
  BOTH cloud + on-prem in one push keeps them in separate slots.

## Deployment

- **Hub-side** (store/poller/routes/WebUI-hub) — needs a **hub redeploy** (2am
  auto-update, or the footer "Update Now"). After that, **centralized** mode
  works end-to-end (the hub runs the on-prem poller + serves browse) without
  touching any spoke.
- **Spoke-side** (cs commands/poller/relay/WebUI-cs) — needs a
  **cs-spoke-update** before spokes accept `CS_CENTRAL_ON_PREM_*`. Until then,
  distributed mode forwards to an "Unknown command"; centralized mode (the
  default) is unaffected.

## Gotchas

- **`central_status` is the per-spoke data key, NOT `central_on_prem_status`.**
  The on-prem backend returns the SAME `central_status` key cloud Central does
  (same browse shape), so the WebUI renderers are reused unchanged — only JS
  function/table ids + endpoint paths + user-visible labels differ. Don't
  "fix" this by renaming the data key; it would force a full renderer fork.
- **The `/aggregate/central` prefix hazard.** `/aggregate/central` is a prefix
  of `/aggregate/central-status` / `-browse` / `-health`. A single
  `str.replace('/aggregate/central', '/aggregate/central-on-prem')` rewrites all
  of them correctly in one left-to-right pass (Python `str.replace` doesn't
  re-scan its replacements), so there's no `central-on-prem-on-prem` corruption.
- **Readability over efficiency.** The on-prem WebUI is a deliberate
  copy-paste of the cloud Central block (per-product copy-paste is the
  established pattern — Mist did it), NOT a parameterized factory. Keep the
  twin in sync with cloud Central when cloud Central's renderer changes.
- **Insights is `[]` for all three sources' browse** until the SLE-site-insights
  follow-on chunk ships (Mist's is the same TODO). An empty Insights tab is
  expected, not a bug.