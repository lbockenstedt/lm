# ClearPass — NetBox "tenant for endpoint" Context Server Action

Importable ClearPass Context Server Actions (CSAs) that resolve **which NetBox
tenant an endpoint belongs to** and expose it as Authorization attributes
(`NetBox_Tenant_Slug` / `NetBox_Tenant_ID` / `NetBox_Tenant_Name`) for use as a
condition in an Enforcement Policy. This is the "ClearPass references the NetBox
API to get a Tenant ID for a policy decision" integration.

Two CSAs are included in `netbox-tenant-context-server-action.json`; **pick one**
and disable/delete the other after import (or keep both and assign only one to
your Authorization Source):

| CSA | NetBox endpoint | When to use |
|-----|-----------------|------------|
| **Tenant by Prefix (contains endpoint IP)** | `GET /api/ipam/prefixes/?contains=<ip>` | Preferred. Works when the prefix is assigned to a tenant even if the individual IP isn't registered. |
| **Tenant by IP (exact address)** | `GET /api/ipam/ip-addresses/?address=<ip>` | Only when individual IP-address objects exist in NetBox with a tenant. |

## 1. Replace the placeholders (do this BEFORE importing)

In the JSON, on every CSA:

- `https://NETBOX_HOST` → your NetBox base URL (e.g. `https://netbox.example.com`).
- `Token NETBOX_API_TOKEN` → a NetBox API token. Create a **read-only** token
  scoped to tenancy + IPAM (Administration → Tokens, or
  `/api/users/tokens/`). Treat the token as a secret — it lives in the CSA's
  request header. Do not commit a real token to this repo.

The endpoint IP is drawn from `%{Radius:IETF:Framed-IP-Address}` (the NAS /
switch must supply the endpoint's IP — e.g. via DHCP snooping / DHCP relay, or
on a re-auth/posture after the endpoint has an address). **Do not use
`%{Connection:Client-IP}`** — that is the *switch* IP, not the endpoint's.

## 2. Import

ClearPass admin UI:

> Configuration → Authentication → Context Server Actions → **Import** →
> choose `netbox-tenant-context-server-action.json`.

Or via REST API (ClearPass):

```
POST https://CPPM/api/context_server_action
Authorization: <cppm token>
Content-Type: application/json
<one CSA object from the array>
```

**Schema is version-dependent.** If the UI import rejects a field, export one
of your existing CSAs from the same ClearPass and diff the field names — then
adjust here and re-import. The fields that matter most (`name`, `host_type`,
`action_type`, `http_method`, `url`, `request_headers`, `attributes[].value`
JSON path) are stable across 6.9–6.11; the wrapper (`[...]` vs a bare object) and
minor keys (`content_type` / `response_type`, `use_proxy`) occasionally differ.

> JSON path note: the attribute `value` uses Jayway JSONPath (`$.results[0].tenant.slug`).
> If your ClearPass version rejects the leading `$.`, drop it
> (`results[0].tenant.slug`).

## 3. Create the Authorization Source (this is where caching + failure live)

> Configuration → Authentication → Authorization Sources → **Add**.

- **Type:** Generic HTTP (HTTP Authorization Source).
- **Context Server Action:** the imported CSA (prefix- or IP-based).
- **Cache lifetime:** set this (e.g. **300–900 s**). Without caching, every
  authentication triggers an HTTP call to NetBox. Caching is what makes this
  cheap at scale.
- **Primary/secondary:** set as a secondary source so a NetBox outage doesn't
  break auth entirely.
- **On failure / no attribute:** decide deliberately. When NetBox is
  unreachable, or the IP isn't in any tenant prefix, `NetBox_Tenant_Slug` is
  empty. Choose fail-closed (deny / default-reject role) or fail-open
  (default role) in the **Enforcement Policy**, not here.

## 4. Enforcement Policy — make the tenant a condition

> Configuration → Enforcement → Policies → your policy → Conditions.

Add a condition on the extracted attribute, e.g.:

```
Authorization:NetBox_Tenant_Slug  EQUALS  "contoso"   →  Enforcement Profile: Contoso_Employee_VLAN
Authorization:NetBox_Tenant_Slug  EQUALS  "guests"    →  Enforcement Profile: Guest_VLAN
Authorization:NetBox_Tenant_Slug  IS EMPTY            →  Enforcement Profile: Deny_or_Default
```

`NetBox_Tenant_Slug` here is the same slug the LM hub scopes everything else by
(`core/src/main.py` `NETBOX_GET_TENANTS`, `api.py` `netbox_tenant_slug`), so the
NAC decision and the rest of LM agree on tenant identity.

## 5. Caveats worth knowing

- **IP-at-auth-time:** at the initial 802.1X exchange the endpoint often has no
  IP (DHCP runs after the port is authorized). This CSA is most reliable on
  **re-auth**, **posture**, **MAC-auth with DHCP-snooped IP**, or when the NAS
  supplies `Framed-IP-Address`. For initial-auth role assignment with only a MAC,
  see the MAC note below.
- **Empty-IP guard:** if `Framed-IP-Address` is empty the URL becomes
  `?contains=` → NetBox returns the first prefix (wrong tenant). Either guard
  the condition (`Framed-IP-Address IS NOT EMPTY` before the tenant check) or
  handle empty in the Enforcement Policy.
- **Overlapping tenant prefixes:** `?contains=<ip>&limit=1` does NOT guarantee
  the most-specific prefix first. If tenant prefixes overlap, add an ordering
  that yields the longest match in your NetBox version, or ensure prefixes
  don't overlap across tenants.
- **NetBox `address` exact match:** the IP CSA's `address` filter is an exact
  match including the mask. If the framed IP is bare, the lookup misses;
  append `/32` (IPv4) / `/128` (IPv6), or use the prefix-contains CSA instead.
- **MAC-based resolution:** a single CSA can't do the two NetBox calls needed
  for MAC → tenant (`dcim/interfaces?mac_address=<mac>` → device → tenant).
  For MAC-only auth, either chain two CSAs, or maintain a tenant tag on the
  device/interface and query that, or rely on ClearPass endpoint profiling +
  the IP-based CSA on re-auth.

## 6. Test

ClearPass API Probing (the LM hub's CPPM module exposes this too, per
`docs/modules/cppm.md`) lets you send a raw request to NetBox from the hub
diagnostics — use it to confirm the URL + token + JSON path before wiring the
Enforcement Policy. A successful probe returns a `results[0].tenant.slug`
matching the LM hub's `netbox_tenant_slug` for that tenant.