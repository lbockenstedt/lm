# Mist — Juniper Mist API twin of Aruba Central (full twin + sim-quota)

**Mist** is a second monitoring product alongside Aruba Central, added as a
**full twin** — its own API client, its own per-tenant config, its own poller,
its own telemetry bucket, its own sim-quota source (`Mist:`), and its own
WebUI tab. It is the precedent Central On-Prem was modelled on (see
[central-on-prem.md](central-on-prem.md)): both follow the same "copy the
Central surface and repoint it" pattern rather than refactoring Central into a
list of products.

The result is a **Mist** tab under Simulations (Sites / Alerts / Insights /
Clients / Hardware / Diagnostic) plus a **Mist API** Setup subtab, and a
`Mist:<type>` sim-quota source whose quotas fire on **Mist** telemetry only.

See also: [cs.md](cs.md) (the shared sim-quota engine + spoke surface),
[central-on-prem.md](central-on-prem.md) (the third sibling that mirrors this
one).

## What Mist is, vs Central

- **`MistClient`** (`core/src/simulations/mist.py`) — Juniper Mist API client,
  one instance per tenant config. **Auth is a static API token** (no refresh,
  unlike Aruba's OAuth client-credentials flow): `Authorization: Token
  <api_token>`. Org-scoped (`org_id`). The host is one of the known Mist region
  hosts (`api.mist.com` Global 01, `api.eu.mist.com` EMEA, `api.gc1.mist.com`
  Global 02, `api.ac2.mist.com` Global 03, `api.ac5.mist.com` APAC), picked at
  Setup → Mist API. `validate_mist_host` does **not** DNS-check the host
  (unlike Aruba's `validate_cluster_url` SSRF resolve) — Mist's region hosts are
  a fixed, well-known set, and the hub route's SSRF validator runs before creds
  are ever accepted.
- **Module caches keyed by config hash** (md5 of the config), like `ArubaClient`,
  so the org-level sites/alarms/inventory calls are shared across all mapped
  sites in a poll cycle (one call per cycle, not N).
- **`MistPoller`** (`cs/lm-spoke/src/mist_poller.py`) is a near-twin of
  `CentralPoller`; `MistHubPoller` (`core/src/simulations/mist_hub_poller.py`)
  is the hub centralized-mode twin.

## Config + processing mode

- **`mist_config`** — `api_token`, `org_id`, `host`, plus the poll/processing
  knobs (`poll_interval_s`, `cc_thresholds`). Per-tenant, in the hub store
  (`core/src/simulations/store.py`) and the cs spoke local store
  (`lm-spoke/src/local_store.py`).
- **`mist_sites_config`** — site mappings, monitored checks, hardware checks,
  sim quotas (same shape as `central_sites_config`). Quota `alert_id`s use the
  `Mist:` prefix.
- **`processing_modes.mist_api`** — `"centralized"` (default, unset →
  centralized) or `"distributed"`. `mist_api_is_centralized(modes)` mirrors the
  cloud `central_api_is_centralized` check.

In **centralized** mode the **hub** runs `MistHubPoller` + serves
browse/available/test from the Mist config directly. In **distributed** mode
the hub forwards `CS_MIST_*` to the cs spoke, which runs `MistPoller`.

## The bare-type / prefix seam (important)

`poll_site_data`'s `alert_type_counts` keys are the **BARE** Mist alarm types
(e.g. `ap_offline`, `dns_failure`) — **no `Mist:` prefix**. The `Mist:` prefix
is applied **only in the sim-quota catalog layer** (`sim_quota.prefixed_alert_id`
+ `SOURCE_PREFIXES`). This keeps the poller's per-site counts directly
comparable to the raw Mist alarm `type` field, while the catalog picker shows
disambiguated `Mist:<type>` ids (a Mist `device_down` is not confused with a
Central one). Don't add the prefix in the poller.

## Mist API endpoints used

`MistClient` calls (all `GET` unless noted, `Authorization: Token <token>`):

- `GET /api/v1/orgs/:org_id` — **Test** (Setup → Mist API → Test). Only
  validates the token + org reachability; it does NOT fetch alarms, so a passing
  Test does NOT imply the Alerts tab will populate.
- `GET /api/v1/orgs/:org_id/sites` — list org sites (plural; falls back to the
  singular `/site` form on 404 for API-revision drift). Cached per cycle.
- `GET /api/v1/orgs/:org_id/alarms/search` — org alarms. **`duration` param
  required** (see [The alarms window](#the-alarms-window--7d-fix)). Bounded
  pagination (≤5 pages) so a looping `next` cursor can never stall the parallel
  browse gather.
- per-site `GET /api/v1/sites/:site_id/stats/clients` — client stats.
- org inventory (devices) → `devices_by_site` + `hw_devices` (device-down
  alarm types, `_DEVICE_DOWN_TYPES`, surface into the Hardware tab like Aruba's
  AP_DOWN/SWITCH_DOWN/GATEWAY_DOWN).

## The alarms window + 7d fix

The Mist `/alarms/search` endpoint **defaults to a 1-day window when
`duration` is omitted**, which hides any alarm older than 24h. Originally
`_fetch_alarms` never sent `duration`, so the Alerts tab read empty (the org's
alarms were older than 24h or all acked/cleared) while Sites populated and Test
passed (Test never fetches alarms). The fix:

- `_fetch_alarms(include_cleared=False, duration="1d")` gains a `duration`
  param. **The dashboard active-alarm poll (`poll_site_data`) keeps the 1d
  default** (current problems only) — `alarms, _ = await
  self._fetch_alarms()`. **`browse_all` + `available_checks` pass
  `_ALARMS_BROWSE_DURATION` ("7d")** to surface recent history.
- `_fetch_alarms` / `_list_alarms` return `(list, warning)`. A fetch FAILURE sets
  the `warning` (e.g. `"Mist alarms fetch failed: …"`) instead of being
  swallowed into a silent `[]`, so the Alerts tab (`_csMistWarn(data)` reads
  `data.warning`) can distinguish **"no alarms in the window"** (`([], None)`)
  from **"the call failed"** (`([], "…")`). `browse_all` propagates the warning
  into `result["warning"]`.
- Poll and browse use **different cache keys** (the key includes `duration`),
  so the 1d poll cache and the 7d browse cache don't collide. An empty/failed
  result is cached for only 60s (backdated) so a transient empty doesn't mask
  the next real fetch for the full 5 min.

This fix shipped to the **hub** (`core/src/simulations/mist.py`, commit
`8dc721a0`) and was then **ported to the cs spoke** (`cs/lm-spoke/src/mist.py`)
so **distributed** mode also gets the 7d window (the spoke's copy initially
missed the fix). Both legs now match. Pinned by `test_browse_passes_7d_duration_window`,
`test_poll_keeps_1d_default_duration`, `test_fetch_alarms_failure_sets_warning`.

## Fallback catalog (day-1 picker)

When the org has no live alarms yet, `available_checks` falls back to a
known-type catalog (`_KNOWN_MIST_ALARM_TYPES`) + `DEFAULT_MIST_HARDWARE_CHECKS`
/ `DEFAULT_MIST_MONITORED_CHECKS` so the Setup monitored-check picker isn't
empty on day 1 — mirrors Aruba's `KNOWN_CLASSIC_ALERT_TYPES` fallback. Live
alarm types (from the 7d browse window, `include_cleared=True`) take precedence
when present.

## Insights — not yet shipped

`browse_all` returns `"insights": []` with a `TODO: SLE site insights
(follow-on chunk)`. The Mist Insights tab is therefore **expected empty**
until that chunk ships — it is not a bug. (Central On-Prem's Insights is the
same TODO.)

## Hub routes (mirror of the Central routes)

`core/src/simulations/routes.py`:

- `GET /sim/api/aggregate/mist` → `service.get_mist_data`.
- `GET /sim/api/aggregate/mist-status` — merges `hub_mist_config` (token
  validity).
- `GET /sim/api/aggregate/mist-browse` — centralized → `browse_mist_from_config`;
  distributed → forwards `CS_MIST_BROWSE`; records history tagged
  `source="mist"` (the same `_record_alert_insight_history` path Central uses;
  validates against `sim_quota.SOURCE_PREFIXES`).
- `POST /sim/api/aggregate/mist` → `save_mist` (mirrors `save_central`).
- `GET/POST /sim/api/{tenant}/mist-sites-config` — validate + push.
- `GET /sim/api/{tenant}/mist/available` — centralized →
  `get_mist_available_from_config`; distributed → `CS_GET_MIST_AVAILABLE`.
- `POST /sim/api/{tenant}/test-mist` — centralized "Hub (centralized)" row via
  `test_mist_from_config`; distributed fans `CS_TEST_MIST`.

`browse_mist_from_config` / `get_mist_available_from_config` /
`test_mist_from_config` are the hub-side centralized-mode twins of the cs
spoke's `MistPoller.browse()` / `available_checks()` / `test_connection()`.

## Sim-quota source routing

Mist is the `"mist"` sim-quota source. The `SimQuotaEngine` routes a `Mist:<type>`
quota to `data["mist"]` telemetry (`data_key = source`) and to
`service._hub_mist(tenant_id)` (reading `hub.mist_hub_status`). The per-source
`alias_groups` dict has a `"mist"` key (sourced from `get_mist_sites_config`).
`parse_alert_source("Mist:dns_fail")` → `("mist", "dns_fail")`. See
[cs.md](cs.md) Sim Quotas for the engine contract; the Mist-specific note is the
bare-type/`Mist:` prefix seam above.

## CS spoke

`cs/lm-spoke/src/mist.py` (`MistClient` + `MistPoller` helpers) +
`mist_poller.py` (`MistPoller`). The `CS_MIST_*` command block
(`CS_GET/SET_MIST_CONFIG`, `CS_GET/SET_MIST_SITES_CONFIG`,
`CS_GET_MIST_AVAILABLE`, `CS_TEST_MIST`, `CS_MIST_BROWSE`, `CS_GET_MIST_HEALTH`)
mirrors the `CS_CENTRAL_*` block. The hub config-push path
(`_apply_hub_config`) branches for `mist_config` + `mist_sites_config`. Mist
config is hub-pushed (the spoke never git-pushes it — the repo-sync strip
invariant holds).

## WebUI

**sim-views-both-copies-edit-convention:** `lm/WebUI/sim-views.js` AND
`cs/lm-spoke/static/sim-views.js` carry byte-identical renderer code.

- The `cs` tab list has `'Mist'`; `VIEW_CHILDREN.cs['Mist']` = Sites/Alerts/
  Insights/Clients/Hardware/Diagnostic; Setup has `'Mist API'`.
- `csMistBrowse()` → `/aggregate/mist-browse` (60s client cache,
  `_csMistBrowseCache`); the Sites/Alerts/Clients/Hardware renderers read it.
  `_csMistWarn(data)` renders `data.warning` (the alarms-fetch-failure banner).
- `csRenderMist*` renderers are a full copy of the `csRenderCentral*` block,
  repointed to `/aggregate/mist*` + `mist` table-state ids.
- The Diagnostic subtab (`csRenderMistDiagnostic` → `_csRenderDiag('mist')`)
  compares RAW Mist alarms/insights vs the DERIVED dashboard status + firing,
  per monitored check + site, with a Copy button. `_csRenderDiag` routes the
  browse call to `csMistBrowse()` and filters monitored_checks to
  `source === 'mist'`.
- `cs/lm-spoke/static/dashboard.html` adds the `Mist` tab button + `Mist API
  Setup` tab button + `TAB_RENDERERS` entries.

## Tests

- `core/tests/test_mist_routes.py` — not-configured → empty; save validates +
  pushes; browse records `source=mist`; distributed forwards `CS_MIST_BROWSE`.
- `core/tests/test_mist_hub_poller.py` — centralized-mode poller reads
  `mist_config`, writes `mist_hub_status`, stamps `source="mist"`.
- `core/tests/test_mist_store.py` — the per-tenant `mist_config` /
  `mist_sites_config` slots + processing mode.
- `cs/lm-spoke/tests/test_mist_client.py` — token auth, sites/alarms/clients
  parsing, the `poll_site_data` shape contract (BARE `alert_type_counts` keys,
  no `Mist:` prefix; wired/wireless split; hw_devices from device-down alarms),
  the 7d browse window + 1d poll default + failure→warning contract.
- `cs/lm-spoke/tests/test_mist_poller.py`.

## Deployment

- **Hub-side** — needs a **hub redeploy** (2am auto-update or footer Update
  Now). Centralized mode then works end-to-end without a spoke update.
- **Spoke-side** — needs a **cs-spoke-update** for distributed mode (the
  `CS_MIST_*` commands + the 7d alarms-window fix on the spoke). Until then,
  distributed forwards to "Unknown command" and the spoke's browse still uses
  the 1d default.

## Gotchas

- **"Test passes but Alerts is empty."** Test only validates creds via `GET
  /orgs/:org_id` — it never fetches alarms. An empty Alerts tab with a passing
  Test means either no alarms in the window (genuine, `([], None)`) or the
  alarms call failed (`([], warning)` — the `_csMistWarn` banner shows why).
  The 7d browse window is what surfaces alarms older than 24h.
- **Insights is `[]`** until the SLE-site-insights follow-on chunk ships —
  expected empty, not a bug.
- **Don't prefix `alert_type_counts` with `Mist:`** in the poller — the prefix
  is catalog-layer only (the bare-type seam above).
- **`MistHubPoller` runs alongside `CentralHubPoller`** (and now the on-prem
  Central instance) — three independent poll loops, three status slots. A
  tenant with Mist config + no Central config is polled by the Mist poller
  only.