# Unimplemented / stub LM hub routes — NOT dead

> **Status:** These routes are **stub / not-yet-implemented**, not dead code.
> They were flagged during the 2026-06-25 dead-code scan because they have **zero
> callers in the WebUI** today, but on review they are placeholders for module
> features that are wired on the spoke side but not yet driven from the UI (or
> are read/health probes expected to be used by external automation). **Do not
> remove without checking each one.** This file exists so we can revisit later.
>
> All paths are defined in `core/src/api.py`. Line numbers are as of commit
> `4a2b96b` (2026-06-25) and **will drift** — treat the path string as the
> stable identifier, the line number as a hint.

## Why they look dead

The dead-code scan (rg for each route path across `WebUI/`) found no WebUI
fetch callers. For the `setup/*-config` POST routes that's because the WebUI
`save*Config` functions that called them were removed in the same cleanup
(they were themselves dead — no UI bound them). The routes themselves remain
because they back module-config / health / sync surfaces that are either:
- implemented on the spoke and awaiting UI, or
- intended as machine-facing endpoints (health probes, sync triggers) for
  external automation / monitoring.

## Revisit checklist (apply to each before removing)

1. Is there a planned/built spoke-side handler for the command this route
   forwards (e.g. `hub.request_response(spoke, "GET_*", ...)`)?
2. Does any **external** caller (curl, cron, monitoring, installer, another
   service) hit this path? Grep the cs / pxmx repos and any ops scripts.
3. Is there a half-built WebUI view for this module that will call it?
4. If all three are "no", it's safe to remove — record the decision here.

---

## Setup module config (GET read + POST save pairs)

The POST side lost its WebUI callers when the dead `save*Config` JS functions
were removed. The GET side loads config for module setup pages. Likely
**awaiting UI rebind**, not dead.

| Path | GET | POST | Notes |
|---|---|---|---|
| `/setup/cppm-config` | 590 | 596 | ClearPass (CPPM/NAC) module config |
| `/setup/pxmx-config` | 627 | 636 | pxmx module config |
| `/setup/ldap-config` | 667 | 673 | LDAP IdP config |
| `/setup/dns-config` | 712 | 718 | DNS module config |
| `/setup/dhcp-config` | 732 | 738 | DHCP module config |
| `/setup/netbox-config` | 2540 | 2546 | Netbox (IPAM) module config |

## CPPM / NAC

| Path | Method | Line | Notes |
|---|---|---|---|
| `/cppm/refresh` | GET | 1168 | Refresh CPPM cache — likely external/monitoring |
| `/api/cppm/test-auth` | GET | 1183 | Test CPPM API credentials |
| `/api/cppm/probe` | GET | 1196 | Probe CPPM connectivity |
| `/cppm/health` | GET | 1209 | Health probe — machine-facing |
| `/api/cppm/roles` | GET | 1418 | List CPPM roles |
| `/api/cppm/logs` | GET | 1434 | Fetch CPPM logs |

## DNS

| Path | Method | Line | Notes |
|---|---|---|---|
| `/api/dns/status` | GET | 3795 | DNS spoke status |
| `/api/dns/sync` | POST | 3805 | Trigger DNS sync |

## DHCP

| Path | Method | Line | Notes |
|---|---|---|---|
| `/api/dhcp/status` | GET | 3909 | DHCP spoke status |
| `/api/dhcp/sync` | POST | 3919 | Trigger DHCP sync |

## Netbox (IPAM)

| Path | Method | Line | Notes |
|---|---|---|---|
| `/api/netbox/health` | GET | 2571 | Netbox health probe |
| `/api/netbox/sites` | GET | 2583 | List Netbox sites |

## LDAP

| Path | Method | Line | Notes |
|---|---|---|---|
| `/api/ldap/users/group` | POST | 2477 | Add user to group (DELETE ~2488) |

## Aggregate / provisioning

| Path | Method | Line | Notes |
|---|---|---|---|
| `/api/aggregate/opnsense` | GET | 1560 | Aggregate OPNsense (firewall) data |
| `/api/generic/provision` | POST | 3643 | Generic provisioning action |

## Setup admin / misc

| Path | Method | Line | Notes |
|---|---|---|---|
| `/setup/spoke-hosts` | GET | 312 | List spoke hosts |
| `/setup/update/spokes` | POST | 2923 | Trigger spoke updates |
| `/setup/modules` | GET | 2937 | List installable modules |
| `/setup/install-module` | POST | 2963 | Install a module |
| `/api/tenant/scoping` | GET | 3137 | Tenant scoping info |
| `/setup/generate-secret` | POST | 3177 | Generate a spoke secret |
| `/setup/logs/all` | GET | 2056 | All-module logs |
| `/admin/cache/status` | GET | 4081 | Admin cache status |

---

## What WAS removed (for contrast)

Genuinely dead and removed in `4a2b96b`:
- `/api/cppm/device-detail` — a **duplicate** of the live unified
  `/api/device-detail` (which the WebUI actually calls). Not a stub; a
  superseded variant. Zero repo-wide references.

The pre-native `/api/sim/start|stop|status|telemetry` block + the
`get_cs_spoke(hub)` helper were removed earlier in `058d305` — those were
superseded by the native `/sim/api/*` tree + `sim-views.js`, and the
corresponding spoke handlers (`CS_START/STOP_SIMULATION`,
`CS_GET_STATUS/TELEMETRY/CLIENTS`) were removed from
`cs/lm-spoke/src/cs_spoke.py` in cs commit `f0a2715`.