# CPPM Module Guide

The CPPM module provides integration with Aruba ClearPass Policy Manager for network access control and device visibility.

> **Note:** the CPPM spoke source is not present in this repository tree — this guide documents the integration contract for reference. The Hub-side routing and config surfaces for CPPM are present in `core/`.

## 1. Capabilities
- **Access Tracker**: Monitoring of authentication attempts and results.
- **Device Inventory**: Listing of endpoints and their posture.
- **Role Management**: Visibility into assigned user and device roles.
- **Policy Mapping**: Identifying which security policies are applying to specific endpoints.

## 2. Configuration
Configuration is managed via **Setup $\rightarrow$ CPPM Configuration**.

### Required Fields
- **Host**: The IP address of the ClearPass Publisher.
- **User**: API username.
- **Password**: API password.

## 3. Technical Implementation
The CPPM spoke interacts with the ClearPass REST API. It supports "API Probing" via the Hub's Diagnostics tool, allowing admins to test raw API paths against the CPPM server.

## 4. IPAM → ClearPass Endpoint Sync (`CPPM_SYNC_ENDPOINTS`)

A hub-orchestrated process periodically pulls endpoint records (IP / MAC /
tenant) from a configurable **IPAM source** (NetBox today; the design is modular
so another IPAM product can be swapped in later) and pushes them to the **CPPM
spoke**, which populates ClearPass Device Inventory with tenant-tagged
endpoints ahead of authentication (so a policy decision is possible even when
the endpoint has no IP at the 802.1X exchange). The hub owns the schedule, the
relay, and the per-tenant last-sync status; the **ClearPass write handler is
implemented in the CPPM spoke** (source not in this repo).

### IPAM sources (modular / swappable pull source)
The hub is source-agnostic: it talks to whichever IPAM product is selected via
the `source` config field, using a small registry — `Hub.IPAM_SOURCES` in
`core/src/main.py`. Today only NetBox is registered:

```python
IPAM_SOURCES = {
    "netbox": {"module_type": "ipam", "get_ips_command": "NETBOX_GET_IPS",
               "tenant_scope_field": "netbox_tenant_slug", "response_key": "ip_addresses",
               "label": "NetBox"},
}
```

Each entry tells the hub: which spoke module type to resolve, which command to
send for the tenant's IPs, which tenant-config key holds the per-tenant scope
value (NetBox → `netbox_tenant_slug`), and which key in the response carries the
IP list. **The response shape is the contract** — every IPAM spoke must answer
`<get_ips_command>` with `{"status": "SUCCESS", "<response_key>": [{address,
custom_fields.mac_address, dns_name}, ...]}` for `{"tenant": <scope>}`,
normalizing its own native fields into that shape, so the hub's endpoint
extraction stays source-agnostic.

The available sources (and each one's connected state) are exposed via
`GET /setup/endpoint-sync/sources`, which the WebUI source dropdown reads — a
newly registered source appears in the dropdown with no client change.

### Swapping in / adding another IPAM product later
Because the loop, the edit-trigger, the per-tenant scoping, and the WebUI
source dropdown all key off `IPAM_SOURCES`, swapping or adding a source is:
1. Add one entry to `Hub.IPAM_SOURCES` (`module_type`, `get_ips_command`,
   `tenant_scope_field`, `response_key`, `label`).
2. Stand up a spoke of that `module_type` that implements `<get_ips_command>`
   with the response shape above (request `{"tenant": <scope>}` →
   `{"status": "SUCCESS", "<response_key>": [...]}`).
3. (Per-tenant binding) populate the new `tenant_scope_field` on each tenant.
No hub logic, loop, or WebUI change required — select it in the UI dropdown or
set `source` in `global_config["netbox_cppm_sync"]`.

### Trigger model
- **Scheduled** — `run_endpoint_sync_loop` (`core/src/main.py`) runs on the
  configured schedule (see Configuration below) and syncs every tenant bound to
  the selected IPAM source.
- **On demand** — `POST /setup/endpoint-sync/run` (the "Sync now" button in
  Setup → Sync). Optional body `{"tenant_id": "<id>"}` syncs one
  tenant; absent → all tenants bound to the selected source.
- **On IPAM edit** — after any successful IPAM write through the LM module
  (e.g. add/update/delete a NetBox device or IP), the hub fires a background
  sync for the affected tenant (`trigger_endpoint_sync`) so a change made via
  the hub propagates immediately instead of waiting for the schedule. The
  trigger resolves the tenant by reverse-mapping the request body's `tenant`
  scope value via the selected source's scope field.

### Configuration (Setup → Sync → "IPAM → ClearPass Endpoint Sync")
Stored under `global_config["netbox_cppm_sync"]` (legacy key name; saved via
the generic `POST /setup/config` shallow-merge; read fresh each cycle by the
loop):

| Key | Type | Default | Meaning |
|-----|------|---------|---------|
| `enabled` | bool | `false` | Master switch for all automatic sync (scheduled **and** edit-triggered). |
| `source` | string | `"netbox"` | Which IPAM product to pull from (a key in `Hub.IPAM_SOURCES`). |
| `mode` | `"interval"` \| `"daily"` | `"interval"` | `interval` = every `interval_seconds`; `daily` = once a day at `daily_time`. |
| `interval_seconds` | int | `3600` | Used in `interval` mode (clamped ≥ 60 s). |
| `daily_time` | `"HH:MM"` | `"02:00"` | Local 24h time used in `daily` mode. |

Per-tenant binding: a tenant is synced when its `<source>.tenant_scope_field`
is set (NetBox → `netbox_tenant_slug`). A tenant can carry scope fields for
multiple products; switching `source` just changes which one is read.

Status (per-tenant last sync: `status` / `pushed` / `errors` / `message` /
`endpoints_total` / `last_sync_ts`) is persisted in `SimulationsStore`
(`simulations_store.json`, per-tenant `endpoint_sync` key) so it survives a hub
restart, and read by `GET /setup/endpoint-sync/status`.

### `CPPM_SYNC_ENDPOINTS` command contract

**Hub → CPPM spoke** (`request_response(spoke_nac, "CPPM_SYNC_ENDPOINTS", payload)`):

```json
{
  "tenant_id":   "<lm tenant id>",
  "tenant_slug": "<per-tenant IPAM scope value>",
  "tenant_name": "<tenant name>",
  "source":      "<IPAM source label, e.g. NetBox>",
  "replace":     true,
  "endpoints": [
    {"ip": "10.0.0.5", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "ws-01"}
  ]
}
```

- `endpoints[]` built from the selected IPAM source's IP list for the tenant:
  `ip` = `address` with the `/mask` stripped; `mac` =
  `custom_fields.mac_address`; `hostname` = `dns_name`. Records with neither
  `ip` nor `mac` are dropped.
- `tenant_slug` carries the per-tenant IPAM scope value (NetBox slug, or the
  scope id of whatever IPAM source is active) — named `tenant_slug` for
  backward compatibility. `tenant_*`
  come from hub tenant state, **not** from the IPAM IP record.
- `source` tells the CPPM spoke which product the batch originated from.
- **`replace: true` — the IPAM source is the source of truth.** The CPPM spoke
  must treat the batch as authoritative for `tenant_slug`: upsert the provided
  endpoints and remove/stale-mark any ClearPass endpoint tagged with this
  tenant that is no longer present in the IPAM source. (If `replace` were ever
  `false`, the spoke would upsert-only — but the hub always sends `true` today.)

**CPPM spoke → Hub** response:

```json
{"status": "SUCCESS", "pushed": <int>, "errors": <int>, "message": "<str>"}
```

`status: "ERROR"` records a per-tenant error in the sync status (the hub does
not raise). `pushed` defaults to `len(endpoints)` if the spoke omits it.

### Suggested ClearPass-side implementation (spoke repo)
Tag each upserted endpoint with the `tenant_slug` (a ClearPass endpoint custom
attribute, or an endpoint group named after the slug) so the Enforcement Policy
can match on it the same way the Context Server Action's `NetBox_Tenant_Slug`
attribute is matched (see `lm/clearpass/README.md`). On `replace: true`, delete
or disable endpoints previously tagged with this tenant that are absent from
the batch. Idempotent upsert keyed on MAC (fall back to IP when MAC is empty).
