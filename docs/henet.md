# henet — HE.NET public DNS (Hurricane Electric)

HE.NET spoke managing **public-address-space** A/AAAA records at Hurricane Electric's free DNS (`dns.he.net`). Vendored in-tree at `lm/henet/`. `module_type = "henet"`. See [architecture-topology.md](architecture-topology.md).

The public-address-space analogue of the [`dns`](dns.md) (Unbound) module: instead of writing records into a local Unbound conf and reloading, it manages records in Hurricane Electric's **web control panel** (`dns.he.net`) using the **account login**, driven hub-side by the `henet_scrape` client (HTML-form CRUD). HE.NET has **no** account-authenticated REST API — the only account-login interface is the web panel, so all record reads and writes go through it.

## Role & module_type

Pure HE web-panel client — no local server, no daemon to manage. Runs as the **`henet`** agent role (or a standalone `lm-henet` unit). `module_type = "henet"`. Record writes are performed **hub-side** (the hub has outbound access to `dns.he.net` and the account-login credential); the spoke is relayed the resulting record so it can track local management state.

## What it does

Manages public DNS records hosted at Hurricane Electric. Each record is created/updated in HE's **web control panel** (`dns.he.net/index.cgi`) via the account login (`henet_scrape.set_records`), and verified by re-reading the zone. The module tracks the set of records it manages in a small local JSON state file so the WebUI can list what's under management.

In the WebUI, HE.NET lives **under the DNS module** ("all things DNS") on the **External DNS** subtab, which groups internet-facing DNS providers (one tile each when more than one is connected): open **DNS → External DNS → HE.NET** to reach the records view — an admin can add/edit/delete managed records and re-push them all with **Sync all**; a non-admin DNS viewer sees the records read-only.

## Credential Vault (account login) — one secret, used for reads AND writes

**Updated 2026-08-19** — record management now uses the **account login** (email + password, `DNS → Hurricane Electric (account login)`) for *everything*: **Import existing**, **Add Record**, **Edit Record**, and **Sync all**. HE.NET has no account-authenticated REST API, so all CRUD is driven through the dns.he.net **web control panel** (HTML forms) using this one credential. There is **no per-record DDNS key field** anymore.

> Earlier revisions of this doc described a per-record **DDNS key** model (the `dyn.dns.he.net/nic/update` push endpoint). That path required a separate, per-hostname key and could not authenticate "Sync all" (every record has its own key, never persisted → `badauth`). It has been replaced by web-panel management, which the account login authenticates for the whole zone at once. The legacy dyndns push code still exists in `henet_manager` but is no longer wired to the UI.

**Assign the account-login credential once** (module-level, DNS → External DNS → HE.NET → 🔐 Assign credential) — it gates the write UI's visibility and powers all reads and writes. Add/Edit/Sync then work with just that credential; no extra per-record secret to supply.
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

`GET /api/henet/records`, `GET /api/henet/status`, `POST/PUT/DELETE /api/henet/record`, `POST /api/henet/sync`, and the module-level credential-assignment routes `GET/POST/DELETE /api/henet/credential` (GET returns the assigned `{bucket, name}` reference — never a secret value — and is readable by any DNS viewer; POST/DELETE assign/clear it). `henet_add_record`/`henet_update_record`/`henet_sync` write via `_henet_web_write` (hub-side account-login web-panel write, then relay `HENET_WEB_RECORD` to the spoke). Writes are **Global-Admin-only** (`api.py` `_ADMIN_INFRA_WRITE_PREFIXES` includes `/api/henet/`), because HE.NET is public-address-space infra with no per-tenant object model. **Reads** are gated like the DNS module — the `dns` right OR the explicit `henet` right OR admin — so anyone who can view DNS can also view HE.NET records (`api.py` `/api/henet/` read gate; `access.py`).

## WebUI

HE.NET is reached via the **DNS** module's **External DNS** subtab (the DNS nav item covers Unbound *and* internet-facing providers). **DNS → External DNS** lists each connected external provider as a tile (or drills straight in when only one is connected); the HE.NET view shows a status line (HE reachable? + managed-record count + the assigned account credential, or "no credential assigned") and a records table (Name / Type / Value / TTL). External DNS manages **public address-space** records (infrastructure, not tenant data), so the whole subtab — view **and** management (**+ Add Record** / edit / delete / **Sync all**) — is **Global-Admin-only**; the server enforces the same on `/api/henet/*`, so a non-global-admin never sees the subtab or the records. A Global Admin first assigns the account-login credential once via **🔐 Assign/Change credential** (populated from the shared Hurricane Electric credentials via the automation-readable listing, so Global-Admin-slot keys appear); **+ Add Record** and **Sync all** only appear once a credential is assigned, and they reuse it without re-picking. Store the credential once under **Credential Vault → + Add secret → DNS → Hurricane Electric (account login)** (automation mode is forced) — the same one LE uses. The External DNS tab appears once a `henet` (or other external-DNS) spoke is connected.

## Key files

`henet/src/control_plane.py`, `henet/src/henet_spoke.py`, `henet/src/henet_manager.py`, `henet/install_henet.sh`, `henet/requirements.txt`, `henet/VERSION`, `henet/tests/`.

## Notable behaviors & gotchas

- **Full record-type support.** The web panel handles A/AAAA and other record types (CNAME, TXT, MX, etc.). Writes are verified by re-reading the zone — only records HE actually accepted are persisted locally.
- **DELETE is local-only.** `HENET_DELETE` removes the record from local management — the zone entry remains at HE. Delete it in the dns.he.net UI if you want it gone (the response says so). (Web-panel delete exists but is intentionally not wired to limit scope/risk.)
- **The account credential is never returned to the browser** — it's resolved hub-side per-request from the Credential Vault and used only to talk to dns.he.net.
- **2FA must be disabled** on the HE account for web-panel automation to authenticate.
- Managed records live in `/etc/lm-henet/records.json` (written atomically via a temp file + `os.replace`); a corrupt/missing file starts from empty.

## How to use it

- **First-time setup:** store **one** Hurricane Electric credential in the Credential Vault — **+ Add secret → DNS → Hurricane Electric (account login)** (automation-readable is forced) — the same secret LE uses for certs. Then **assign it once** to the module: DNS → External DNS → HE.NET → **🔐 Assign credential** → pick the vault secret → save. **+ Add Record** and **Sync all** appear once a credential is assigned.
- **Add a record:** DNS → External DNS → HE.NET → **+ Add Record** → name/type/value/ttl → submit. The hub writes it to the HE web panel with the assigned account login and verifies by re-reading the zone.
- **Edit a record:** edit action → change the value → save (updates the record in-place at HE via the web panel).
- **Remove from management:** delete action (leaves the HE zone entry intact — remove it at dns.he.net if desired).
- **Re-push everything:** **Sync all** → confirm → re-writes every managed record to HE using the assigned account login.
- **Change/clear the credential:** DNS → External DNS → HE.NET → **🔐 Assign/Change credential** → pick another secret and save, or **Clear** to unassign.

## Troubleshooting / common questions

- **"No HE.NET credential assigned."** No module-level credential is assigned. Store one **DNS → Hurricane Electric (account login)** secret (automation mode) — shared with LE — and assign it via **🔐 Assign credential**.
- **Credential doesn't appear in the picker.** The picker lists automation-readable HE credentials (including the Global-Admin `__admin__` slot) via `/tenant/cred-vault/automation-secrets`: shared `dns` "Hurricane Electric" credentials. Ensure the secret was saved as a **"DNS → Hurricane Electric (account login)"** (automation mode is forced on save).
- **"HE.NET spoke not connected."** The `henet` role isn't loaded on an agent. Load the `henet` agent role (or install `install_henet.sh`), and confirm the node's `lm-agent` unit is up.
- **"I deleted a record but it still resolves at HE."** Expected — delete is local-only. Remove the entry in the dns.he.net UI; the module only stopped managing it.
- **"Add/Edit/Sync failed" / login error.** The account-login credential is wrong, or 2FA is enabled on the HE account (disable it for automation). The hub verifies each write by re-reading the zone, so a record that doesn't appear afterward is reported as failed rather than silently persisted.

## Related pages

[dns.md](dns.md) (private-DNS analogue), [le.md](le.md) (same Credential-Vault pattern), [architecture-topology.md](architecture-topology.md), [install-flags.md](install-flags.md).
