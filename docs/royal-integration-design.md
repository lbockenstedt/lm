---
summary: "Design and progress log for syncing LM-discovered network devices and credentials into RoyalApps Royal TS documents on a Windows Royal Server."
keywords: [royal, royalts, royal server, rtsz, export, nw_devices, credentials, design]
---

# DRAFT — Royal TS integration (design + progress log)

> Status: DESIGN — decisions below agreed 2026-11-02. No code yet.
> Goal: devices LM discovers (name, IP, DNS name) and their credentials appear in a
> RoyalApps **Royal TS** document (`.rtsz`) hosted on a Windows **Royal Server**
> (document unencrypted).

## 1. Decisions (locked)

| # | Decision | Why |
|---|---|---|
| 1 | **LM never writes `.rtsz`.** A PowerShell script on the Royal Windows server pulls from LM and writes the document with RoyalApps' `RoyalDocument.PowerShell` module. | `.rtsz` is a closed format; the module is the only supported writer. Keeps pwsh/.NET off the hub (dependency rule). LM spokes are Linux-only. |
| 2 | **Opt-in is a flag on the whole tenant:** `royal_sync.enabled`. | Not every tenant uses Royal. |
| 3 | **The script picks tenants by name** from its own JSON config, then asks LM whether each tenant has Royal sync enabled. | Different tenants use different Royal servers/documents. LM holds no Royal server/document config. |
| 4 | **Grouping is explicit, not inferred:** `site`, `location`, `role` on the device (local JSON override → NetBox → name-pattern *suggestion only*). | The mock sync (§5) found 0 of 34 devices with real grouping data. |
| 5 | **Identity = serial → MAC → hostname → IP**, tenant-scoped and lower-cased. | Matches the identity used across NetBox/LM, with the guards in §3. |
| 6 | **One Royal connection per physical device**, deduped with the hub's `nw_hardware_primaries` (`core/src/nw_discovery_sync.py:60`). | The scan stores one row per SVI IP (e.g. CRSW1 has 8 rows). |

## 2. Tenant flag and export API

Tenant record (free-form dict, `StateManager.update_tenant`, `core/src/state/manager.py:701`):

```json
"royal_sync": {"enabled": true, "include_passwords": false,
               "last_pull_at": 0, "last_pull_by": "", "last_pull_devices": 0}
```

- Set by a Global Admin, or by a tenant admin for their own tenant. The tenant list shows a "Royal sync" badge with the last pull time and device count, using the usual stale-ageing colours.
- An optional `royal_exclude: true` on an nw device record keeps it out of the export.

`GET /api/royal/export?tenant=<tenant name>` (read-only):

1. Resolve the name case-insensitively. An unknown name, or a tenant the caller can't access, returns **404**, so tenant names aren't leaked.
2. If `royal_sync.enabled` isn't set, return `200 {"tenant": ..., "royal_sync": false}`. The script skips the tenant and leaves the document untouched.
3. Otherwise return the deduped devices and credential objects, and write `last_pull_*`.
4. Passwords are included only when `include_passwords` is true (Global Admin only) and the vault secret is in `hub` mode. Otherwise credentials carry the username only.

**Auth:** one LM service user per Royal server (e.g. `svc-royal-<server>`), assigned only to the tenants that server syncs. It uses the existing API refresh tokens (`core/src/api_tokens.py`), so tenant isolation comes from existing access rules and no new token type is needed.

## 3. Device identity

The existing code doesn't use a single identity order:

- NetBox dedupe: `serial → mac → nw_device_id → ip → hostname` (`netbox/src/netbox_dedupe.py:4`).
- LM hub: serial, else short hostname + object_type. **MAC is excluded** because VSX peers share a system MAC (`core/src/nw_discovery_sync.py:60-71`).

Royal uses **serial → MAC → hostname → IP**, with two guards:

- **MAC counts only if no other device in the tenant has it**, so VSX pairs never merge.
- **Hostname comes before IP**, because the scan stores one row per SVI IP.

The export sends a stable `uid` plus every alias. The script matches an existing Royal object by ExternalID **or any alias** (stored in a custom property), then rewrites ExternalID to `lm:<tenant>:<uid>`. A device first seen by IP that later reports a serial is therefore updated in place, not re-created.

Serial, MAC and hostname come from poll data (`cache/nw_data.json` `info`), not from the stored device record.

## 4. Royal document layout

```
LM Discovered/
  <Tenant>/                 credential objects live here (one per vault credential)
    <Site>/<Location>/<Role>/
      <device name>         URI = FQDN if known, else mgmt IP
    _Unsorted/              devices with no site/location (never hidden)
```

- The description and custom properties hold: object_type, model, all IPs, `uid`, aliases, LM id.
- Connections reference credentials by ID (`CredentialMode` = by ID).
- The script only adds, updates or removes objects whose ExternalID starts with `lm:`. Hand-made Royal entries are never touched. A tenant whose sync is turned off is skipped, not deleted.
- Concurrency: the save rewrites the whole document. Run the script off-hours or use a dedicated LM-only document.

## 5. Mock sync on live LM-HUB data (2026-11-02, read-only, in memory)

Inputs: `system.json` (nw_devices, cred_vault metadata), `tenants.json`, `cache/nw_data.json`, and the warm cache (`nb_netbox_devices`, `nb_devices`, `nb_netbox_ips`, `netsvc_dhcp_list_res`).

**Ready**
- The 51 device rows dedupe to **34 physical devices**.
- UIDs: 32 serial, 1 MAC (MM-01), 1 IP (172.16.1.203).
- Tenant name lookup works (DEFAULT / DXP / LRB).
- All 5 vault credentials are in `hub` mode, so passwords *can* be exported, which is why the `include_passwords` guard matters.

**Gaps (of 34 devices)**

| Gap | Count | Detail |
|---|---|---|
| No location | 34 | `NETBOX_GET_DEVICES` returns no `location` (`netbox/src/netbox_dcim.py:202-214`), and rack is empty. |
| Placeholder site | 33 | NetBox site is "Discovered" (or the device is missing from NetBox). Only OLKS-MGMTSW = Olathe. |
| Placeholder role | 34 | Every NetBox role is "Discovered". |
| Not in NetBox | 6 | AZ13-LFSW-1-1, AZ16-LFSW-1-1, AZ3-SPSW-1-2, AZ4-LFSW-1-2, AZ5-LFSW-1-1, 172.16.1.203. |
| No DNS name | 16 | The whole DXP AZ fleet, RSVBE-INET-2, 172.16.1.203. |
| Short DNS name only | 15 of 18 | Only CRSW1/2 and MM-01 have FQDNs. A short name depends on the client's DNS suffix. |
| SNMP-only | 11 | SSPLM TORs. Their credential is the SNMP string, not a login. |
| Never polled | 1 | 172.16.1.203: no serial, MAC or hostname, and its name is an IP. |

NetBox data quality (side finding): 1121 device rows but only 743 unique, including case-variant duplicates (e.g. BO-BOMM-ACSW01 / BO-BOMm-ACSW01). 1084 rows have site "Discovered".

## 6. Next steps (in order)

1. **Grouping fields:** add `site`, `location`, `role` to nw device records, editable via API/UI, with NetBox fill-in when NetBox holds real values.
2. **NetBox:** add `location` to `NETBOX_GET_DEVICES`. Push the 6 missing devices. Replace the "Discovered" placeholders.
3. **`login_credential`** for SNMP-only devices, or exclude them from Royal.
4. **DNS:** prefer an FQDN for the URI. Resolve the missing names from DNS/DHCP, falling back to the IP.
5. **Tenant `royal_sync` flag** and badge.
6. **`GET /api/royal/export`** reusing `nw_hardware_primaries` and the §3 identity rules, with tests.
7. **PowerShell sync script** plus its JSON config (hub, token file, document, tenant names), using `RoyalDocument.PowerShell`.

## 7. References

- RoyalDocument.PowerShell: https://docs.royalapps.com/r2023/scripting/document/cmdlet-reference/index.html
- Credentials sample: https://docs.royalapps.com/r2023/scripting/document/samples/working-with-credentials.html
- Royal Server Document Store module: https://docs.royalapps.com/products/royalserver/scripting/module-reference/module-document-store.html
- Dynamic Folder JSON (alternative, not chosen): https://docs.royalapps.com/r2023/scripting/rjson/json-schema.html
