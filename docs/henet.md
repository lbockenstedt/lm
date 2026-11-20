---
summary: "HE.NET spoke managing public-address-space A/AAAA records at Hurricane Electric's free DNS (dns.he.net)."
keywords: [account, dns, henet, henet_manager, henet_scrape, henet_web_record, install_henet, le, lm, module_type]
---

# henet — HE.NET public DNS (Hurricane Electric)

HE.NET spoke managing **public-address-space** A/AAAA records at Hurricane Electric's free DNS (`dns.he.net`). Vendored in-tree at `lm/henet/`. `module_type = "henet"`. See [architecture-topology.md](architecture-topology.md).

The public-address-space analogue of the [`dns`](dns.md) (Unbound) module: instead of writing records into a local Unbound conf and reloading, it manages records in Hurricane Electric's **web control panel** (`dns.he.net`) using the **account login**, driven hub-side by the `henet_scrape` client (HTML-form CRUD). HE.NET has **no** account-authenticated REST API — the only account-login interface is the web panel, so all record reads and writes go through it.

## Role & module_type

Pure HE web-panel client — no local server, no daemon to manage. Runs as the **`henet`** agent role (or a standalone `lm-henet` unit). `module_type = "henet"`. Record writes are performed **hub-side** (the hub has outbound access to `dns.he.net` and the account-login credential); the spoke is relayed the resulting record so it can track local management state.

## What it does

Manages public DNS records hosted at Hurricane Electric. Each record is created/updated in HE's **web control panel** (`dns.he.net/index.cgi`) via the account login (`henet_scrape.set_records`), and verified by re-reading the zone. The module tracks the set of records it manages in a small local JSON state file so the WebUI can list what's under management.

In the WebUI, HE.NET lives **under the DNS module** ("all things DNS") on the **External DNS** subtab, which groups internet-facing DNS providers (one tile each when more than one is connected): open **DNS → External DNS → HE.NET** to reach the records view. Each record belongs to one tenant or to the global set. A tenant-admin adds, edits and deletes their own tenant's records and assigns their tenant's credential. A Global Admin manages every tenant's records, and only a Global Admin can **Import existing**, **Sync all**, schedule the re-sync or move records to another tenant. Any other user with the DNS or HE.NET right sees their own tenant's records read-only. The exact gates are under **Hub API endpoints** below.

## Credential Vault (account login) — one secret, used for reads AND writes

**Updated 2026-08-19** — record management now uses the **account login** (email + password, `DNS → Hurricane Electric (account login)`) for *everything*: **Import existing**, **Add Record**, **Edit Record**, and **Sync all**. HE.NET has no account-authenticated REST API, so all CRUD is driven through the dns.he.net **web control panel** (HTML forms) using this one credential. There is **no per-record DDNS key field** anymore.

> Earlier revisions of this doc described a per-record **DDNS key** model (the `dyn.dns.he.net/nic/update` push endpoint). That path required a separate, per-hostname key and could not authenticate "Sync all" (every record has its own key, never persisted → `badauth`). It has been replaced by web-panel management, which the account login authenticates for the whole zone at once. The legacy dyndns push code still exists in `henet_manager` but is no longer wired to the UI.

**Assign the account-login credential once per tenant, or once for the global set** (DNS → External DNS → HE.NET → 🔐 Assign credential, for the tenant in view) — it powers Import and every record write. **Import existing** and **Sync all** appear only once the tenant in view (or the global set) has one, and saving a record without one asks you to assign it first. Add/Edit/Sync then work with just that credential; no extra per-record secret to supply.
- The hub resolves it in-place via `net_services._henet_resolve_account_login` (`cred_vault.automation_get`) and performs the web-panel write directly (`henet_scrape.set_records`), then relays `HENET_WEB_RECORD` to the spoke to persist local management state (no dyndns push).
- The credential **picker** lists automation-readable Credential Vault secrets (`/tenant/cred-vault/automation-secrets`, the same endpoint the LE module uses, so Global-Admin-slot (`__admin__`) keys appear): shared `dns` "Hurricane Electric" credentials carrying `he_username`/`he_password`.

## Entrypoints

`python3 -m src.control_plane` (`HENetControlPlane`); spoke `HENetSpoke(BaseSpoke)`; installer `install_henet.sh` (venv + systemd `lm-henet` unit). Runs primarily as the **`henet`** role hosted by the agent (`lm-agent`), loaded in-process via `agent/src/agent_spoke.py` (`_ROLE_MAP` → `HENetSpoke`, `repo_url=None` — bundled in-tree).

## Ports / backends

Record CRUD is performed **hub-side** against Hurricane Electric's web control panel `https://dns.he.net/index.cgi` (HTML-form POST, account-login authenticated; `henet_scrape`). The spoke's reachability probe (`henet_manager._endpoint_reachable`) hits the same host over HTTPS (stdlib `urllib`, 10s timeout) and treats any HTTP-level response — including 401 — as reachable. No port served. `requirements.txt` is just `websockets, python-dotenv`.

## Environment variables

`SPOKE_ID`, `SPOKE_SECRET`, `HUB_SECRET`, `HUB_WS`. No HE credential env var — the account login lives in the hub-resolved vault secret and is used hub-side.

## Install flags

`install_henet.sh` takes none of the server flags (no `--infra-only` — there is no local server to stand up). Standard path is loading the `henet` agent role.

## Key commands / handlers (`henet_spoke.handle_command`)

`GET_VERSION`, `HENET_STATUS` (HE reachability + managed-record count), `HENET_LIST` (records from local state), `HENET_WEB_RECORD` (persist a record the hub just wrote to the HE web panel into local management state — no dyndns push; `henet_manager.record_web_writes`), `HENET_DELETE` (remove from **local management only** — see gotcha below). Legacy `HENET_ADD`/`HENET_UPDATE`/`HENET_SYNC` (dyndns push) remain in the manager but are no longer invoked by the hub routes. Every manager call is offloaded via `asyncio.to_thread`.

## Hub API endpoints (`core/src/routes/net_services.py`)

`GET /api/henet/records`, `GET /api/henet/status`, `POST/PUT/DELETE /api/henet/record`, `POST /api/henet/record/tenant`, `POST /api/henet/sync`, `POST /api/henet/import`, `GET/POST /api/henet/sync-config`, and the credential-assignment routes `GET/POST/DELETE /api/henet/credential` (GET returns the assigned `{bucket, name}` reference — never a secret value; POST/DELETE assign/clear it). `henet_add_record`/`henet_update_record`/`henet_sync` write via `_henet_web_write` (hub-side account-login web-panel write, then relay `HENET_WEB_RECORD` to the spoke).

Who may call them (the `api.py` gates, then the handlers):

- **Every `/api/henet/` route** needs the `dns` right, the explicit `henet` right or admin, so anyone who can view DNS can also view HE.NET (`api.py` `/api/henet/` read gate; `access.py`). A non-admin's `GET /api/henet/records` holds only their own tenant's records, and their `GET /api/henet/credential` only their own tenant's slot. `GET /api/henet/status` (reachability and the managed-record count) and `GET /api/henet/sync-config` (the schedule and its last run) are fleet-wide.
- **Record and credential writes** (`/api/henet/record` and `/api/henet/credential`, `api.py` `_HENET_TENANT_WRITE_PREFIXES`) need a tenant-admin or Global Admin. A tenant-admin acts only on their own tenant: another tenant's record answers 404 (`_henet_assert_can_write`), a new record is given their tenant, and the credential they assign or clear is their own tenant's slot, from a vault bucket they can reach. Only a Global Admin can name another tenant (`tenant` in the body or query) or move a record to another tenant (`POST /api/henet/record/tenant`).
- **Bulk writes** are Global-Admin-only: `POST /api/henet/sync`, `POST /api/henet/import` and `POST /api/henet/sync-config` (`_ADMIN_INFRA_WRITE_PREFIXES` lists `/api/henet/sync`, which also covers `sync-config`, and `/api/henet/import`). They act on many records at once, with no single tenant owner.

## WebUI

HE.NET is reached via the **DNS** module's **External DNS** subtab (the DNS nav item covers Unbound *and* internet-facing providers). **DNS → External DNS** lists each connected external provider as a tile (or drills straight in when only one is connected); the HE.NET view shows a status line (HE reachable? + managed-record count + the assigned account credential, or "no credential assigned") and a records table (Name / Type / Value / TTL). The subtab shows for anyone with the DNS or HE.NET right. A Global Admin's view follows the top tenant selector (that tenant's records, or the global set on the default selection); everyone else sees only their own tenant's records. **🔐 Assign/Change credential**, **+ Add Record**, edit, delete and **🧹 Deconfigure** show for a tenant-admin or Global Admin and act on the tenant in view; **⇩ Import existing**, **↻ Sync all**, **⏱ Schedule…** and **➡ Move all…** show for a Global Admin only. The account-login credential is assigned once per tenant (or once for the global set) via **🔐 Assign/Change credential** (populated from the shared Hurricane Electric credentials via the automation-readable listing, so Global-Admin-slot keys appear). **Import existing** and **Sync all** appear only once a credential is assigned, saving a record without one asks you to assign it first, and they all reuse it without re-picking. Store the credential once under **Credential Vault → + Add secret → DNS → Hurricane Electric (account login)** (automation mode is forced) — the same one LE uses. The External DNS tab appears once a `henet` (or other external-DNS) spoke is connected.

**Scheduled re-sync status.** While **⏱ Schedule…** has the automatic re-sync turned on, a Global Admin's status line shows **⏱ auto-sync every …** (or **daily at HH:MM**). After a run that left a reason it also shows **last run:** and the reason, in red when the run recorded `error`, for example `2 of 5 scopes failed (1 HE.NET login or connection failure, 1 credential conflict); 3 records rejected by HE.NET`, `the HE.NET spoke did not return its record list`, `no managed records` or `HE.NET spoke not connected`. A run that had records to sync and no errors leaves no reason, so nothing follows the schedule. A *scope* is one tenant's records, or the global set; each is written with its tenant's own credential, or the global one when the tenant has none. A scope fails, and none of its records are written, when dns.he.net refuses the login, can't be reached or shows no zones, when several credential slots name the tenant, or when the vault read fails. A scope with no usable credential is skipped, not failed. The status is kept in memory, so it is empty after a hub restart until the next run.

The reason is deliberately **tenant-neutral**. `GET /api/henet/sync-config` returns the last run to every user with the DNS or HE.NET right, tenant users included, so the reason holds only counts and those failure kinds. It never names a tenant, record, HE username or vault secret, and never quotes an HE.NET, vault or spoke error. Those details are in the hub log, on the `henet scheduled sync: …` warning lines.

## Key files

`henet/src/control_plane.py`, `henet/src/henet_spoke.py`, `henet/src/henet_manager.py`, `henet/install_henet.sh`, `henet/requirements.txt`, `henet/VERSION`, `henet/tests/`.

## Notable behaviors & gotchas

- **Full record-type support.** The web panel handles A/AAAA and other record types (CNAME, TXT, MX, etc.). Writes are verified by re-reading the zone — only records HE actually accepted are persisted locally.
- **DELETE is local-only.** `HENET_DELETE` removes the record from local management — the zone entry remains at HE. Delete it in the dns.he.net UI if you want it gone (the response says so). (Web-panel delete exists but is intentionally not wired to limit scope/risk.)
- **The account credential is never returned to the browser** — it's resolved hub-side per-request from the Credential Vault and used only to talk to dns.he.net.
- **2FA must be disabled** on the HE account for web-panel automation to authenticate.
- Managed records live in `/etc/lm-henet/records.json` (written atomically via a temp file + `os.replace`); a corrupt/missing file starts from empty.

## How to use it

- **First-time setup:** store **one** Hurricane Electric credential in the Credential Vault — **+ Add secret → DNS → Hurricane Electric (account login)** (automation-readable is forced) — the same secret LE uses for certs. Then **assign it** to the tenant in view (or the global set): DNS → External DNS → HE.NET → **🔐 Assign credential** → pick the vault secret → save. **Import existing** and **Sync all** (Global Admin) appear once a credential is assigned.
- **Add a record:** DNS → External DNS → HE.NET → **+ Add Record** → name/type/value/ttl → submit. The hub writes it to the HE web panel with the assigned account login and verifies by re-reading the zone.
- **Edit a record:** edit action → change the value → save (updates the record in-place at HE via the web panel).
- **Remove from management:** delete action (leaves the HE zone entry intact — remove it at dns.he.net if desired).
- **Re-push everything:** **Sync all** → confirm → re-writes every managed record to HE using the assigned account login.
- **Change/clear the credential:** DNS → External DNS → HE.NET → **🔐 Assign/Change credential** → pick another secret and save, or **Clear** to unassign.

## Troubleshooting / common questions

- **"No HE.NET credential assigned."** Neither the tenant's own credential slot nor the global one is assigned (a tenant with no credential of its own uses the global one). Store one **DNS → Hurricane Electric (account login)** secret (automation mode) — shared with LE — and assign it via **🔐 Assign credential**.
- **Credential doesn't appear in the picker.** The picker lists automation-readable HE credentials (including the Global-Admin `__admin__` slot) via `/tenant/cred-vault/automation-secrets`: shared `dns` "Hurricane Electric" credentials. Ensure the secret was saved as a **"DNS → Hurricane Electric (account login)"** (automation mode is forced on save).
- **The page shows a red "HE.NET credential: …" message, or Sync returns 409, or the scheduled re-sync reports `error` (last run: … credential conflict), for one tenant.** That tenant has more than one credential slot whose ids differ only by case or surrounding spaces (saved before slots were matched in any case), so the hub can't tell which one is current, even when one is spelt exactly like the tenant. It uses none of them and writes none of that tenant's records, not even with the global login. `GET /api/henet/credential` answers 409 with the reason, which the page shows in red where the credential name would be; record saves, Import and Sync show the same reason. Open **🔐 Assign credential**: **Save** assigns the credential you pick and replaces every slot with one, **Clear** removes them all. The API equivalent is `POST /api/henet/credential` with `{"tenant": "<id>", "bucket": "<bucket>", "name": "<secret>"}` (a Global Admin sends `tenant`; a tenant-admin's own tenant is used).
- **"HE.NET spoke not connected."** The `henet` role isn't loaded on an agent. Load the `henet` agent role (or install `install_henet.sh`), and confirm the node's `lm-agent` unit is up.
- **"I deleted a record but it still resolves at HE."** Expected — delete is local-only. Remove the entry in the dns.he.net UI; the module only stopped managing it.
- **"Add/Edit/Sync failed" / login error.** The account-login credential is wrong, or 2FA is enabled on the HE account (disable it for automation). The hub verifies each write by re-reading the zone, so a record that doesn't appear afterward is reported as failed rather than silently persisted.
- **"last run: … HE.NET login or connection failure" (red).** The scheduled re-sync wrote none of those scopes' records: dns.he.net refused the login, couldn't be reached, or showed no zones for the account. Check the scope's credential and 2FA as above. The hub log line `henet scheduled sync: scope '<tenant>' not written: <message>` names the scope (`global` for the global set) and gives HE.NET's message.
- **"last run: the HE.NET spoke did not return its record list" (red).** The hub's `HENET_LIST` request to the spoke failed or timed out, so nothing was synced. The hub log line `henet scheduled sync: HENET_LIST failed: …` has the error.

## Related pages

[dns.md](dns.md) (private-DNS analogue), [le.md](le.md) (same Credential-Vault pattern), [architecture-topology.md](architecture-topology.md), [install-flags.md](install-flags.md).
