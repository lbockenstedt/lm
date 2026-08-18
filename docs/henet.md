# henet — HE.NET public DNS (Hurricane Electric)

HE.NET spoke managing **public-address-space** A/AAAA records at Hurricane Electric's free DNS (`dns.he.net`). Vendored in-tree at `lm/henet/`. `module_type = "henet"`. See [architecture-topology.md](architecture-topology.md).

The public-address-space analogue of the [`dns`](dns.md) (Unbound) module: instead of writing records into a local Unbound conf and reloading, it pushes A/AAAA records to Hurricane Electric over HE's officially documented **dynamic-DNS update** protocol (`https://dyn.dns.he.net/nic/update`).

## Role & module_type

Pure HE-API client — no local server, no daemon to manage. Runs as the **`henet`** agent role (or a standalone `lm-henet` unit). `module_type = "henet"`.

## What it does

Manages public DNS A/AAAA records hosted at Hurricane Electric. Each record is pushed to HE's dyndns endpoint, which authenticates the update with a per-record **DDNS key** (the "Enable entry for dynamic DNS" key generated in the dns.he.net UI). The module tracks the set of records it manages in a small local JSON state file so the WebUI can list what's under management and show each record's last push result.

In the WebUI, HE.NET lives **under the DNS module** ("all things DNS") on the **External DNS** subtab, which groups internet-facing DNS providers (one tile each when more than one is connected): open **DNS → External DNS → HE.NET** to reach the records view — an admin can add/edit/delete managed records and re-push them all with **Sync all**; a non-admin DNS viewer sees the records read-only.

## Credential Vault (DDNS key) — exactly like the LE module

The HE DDNS key is a **secret** and — exactly like the LE module's DNS-01 credentials — is **NEVER stored on the spoke** and never sent to the browser. It lives in the hub-side **Credential Vault** ([le.md](le.md) uses the same mechanism):

- **One HE credential — stored once, used for both certs and DNS.** Do **not** create a separate "HE.NET DDNS key" secret. Store a single **DNS → Hurricane Electric (account login)** secret (email + password) in **automation-readable** (`hub`) mode; both the LE (certs) module and External DNS use it. The hub reformats whichever shape it finds into the single dyndns push password (`net_services._henet_extract_ddns_key`), trying `ddns_key`, then `he_password`/`password`, then `secret`, then `key`/`value`. (Older deployments may still hold a legacy `henet` DDNS-key secret — it keeps working and remains editable, but new setups use the shared Hurricane Electric DNS-01 secret so there is only **one** HE entry in the vault.)
- **Assign the credential once** (module-level), rather than picking it per record. A Global Admin assigns a `{bucket, name}` reference under **DNS → External DNS → HE.NET → 🔐 Assign credential**; the hub persists it in global config under `henet.vault_credential` and validates up-front that it resolves to an automation-readable secret carrying a usable HE key/password. See the credential routes below.
- On each write the hub falls back to the assigned credential (`net_services._henet_get_assigned_cred`) when the request carries no explicit `henet_vault_credential` reference — so add/sync never have to re-pick the key.
- The hub resolves it in-place via `cred_vault.automation_get(hub, bucket, name)` (`net_services._henet_resolve_vault_cred`) and injects `ddns_key` into the relayed `HENET_*` command — mirroring LE's `_le_resolve_vault_dns_cred`.
- The credential **picker** lists automation-readable Credential Vault secrets (`/tenant/cred-vault/automation-secrets`, the same endpoint the LE module uses, so Global-Admin-slot (`__admin__`) keys appear): both `henet` DDNS-key secrets **and** shared `dns` "Hurricane Electric" credentials (those carrying `he_username`/`he_password`/`ddns_key`). The older per-bucket, pass-phrase-gated listing skipped the admin slot.
- When Azure Key Vault is configured the secret lives there; otherwise it's stored encrypted-local (Fernet) in hub state. Either way the plaintext key only ever exists on the spoke for the duration of one push.

## Entrypoints

`python3 -m src.control_plane` (`HENetControlPlane`); spoke `HENetSpoke(BaseSpoke)`; installer `install_henet.sh` (venv + systemd `lm-henet` unit). Runs primarily as the **`henet`** role hosted by the agent (`lm-agent`), loaded in-process via `agent/src/agent_spoke.py` (`_ROLE_MAP` → `HENetSpoke`, `repo_url=None` — bundled in-tree).

## Ports / backends

Talks to Hurricane Electric's fixed dyndns endpoint `https://dyn.dns.he.net/nic/update` over HTTPS (stdlib `urllib`, 10s timeout). POST form `hostname`/`password`/`myip`; HE returns `good`/`nochg` on success, anything else is an error surfaced verbatim. No port served. `requirements.txt` is just `websockets, python-dotenv`.

## Environment variables

`SPOKE_ID`, `SPOKE_SECRET`, `HUB_SECRET`, `HUB_WS`. No HE credential env var — the key arrives per-command from the hub-resolved vault secret.

## Install flags

`install_henet.sh` takes none of the server flags (no `--infra-only` — there is no local server to stand up). Standard path is loading the `henet` agent role.

## Key commands / handlers (`henet_spoke.handle_command`)

`GET_VERSION`, `HENET_STATUS` (HE dyndns reachability + managed-record count), `HENET_LIST` (records from local state, each with `last_push_status`/`last_push_detail`/`last_pushed_at`), `HENET_ADD` / `HENET_UPDATE` (upsert + push the new IP to HE dyndns — update is just another push for the same hostname), `HENET_DELETE` (remove from **local management only** — see gotcha below), `HENET_SYNC` (replace the managed set and re-push every A/AAAA record). Every manager call is offloaded via `asyncio.to_thread`.

## Hub API endpoints (`core/src/routes/net_services.py`)

`GET /api/henet/records`, `GET /api/henet/status`, `POST/PUT/DELETE /api/henet/record`, `POST /api/henet/sync`, and the module-level credential-assignment routes `GET/POST/DELETE /api/henet/credential` (GET returns the assigned `{bucket, name}` reference — never a secret value — and is readable by any DNS viewer; POST/DELETE assign/clear it). Writes are **Global-Admin-only** (`api.py` `_ADMIN_INFRA_WRITE_PREFIXES` includes `/api/henet/`), because HE.NET is public-address-space infra with no per-tenant object model. **Reads** are gated like the DNS module — the `dns` right OR the explicit `henet` right OR admin — so anyone who can view DNS can also view HE.NET records (`api.py` `/api/henet/` read gate; `access.py`).

## WebUI

HE.NET is reached via the **DNS** module's **External DNS** subtab (the DNS nav item covers Unbound *and* internet-facing providers). **DNS → External DNS** lists each connected external provider as a tile (or drills straight in when only one is connected); the HE.NET view shows a status line (HE dyndns reachable? + managed-record count + the assigned DDNS credential, or "no DDNS credential assigned") and a records table (Name / Type / Value / TTL / Last Push). External DNS manages **public address-space** records (infrastructure, not tenant data), so the whole subtab — view **and** management (**+ Add Record** / edit / delete / **Sync all**) — is **Global-Admin-only**; the server enforces the same on `/api/henet/*`, so a non-global-admin never sees the subtab or the records. A Global Admin first assigns the DDNS credential once via **🔐 Assign/Change credential** (populated from the shared Hurricane Electric credentials via the automation-readable listing, so Global-Admin-slot keys appear); **+ Add Record** and **Sync all** only appear once a credential is assigned, and they reuse it without re-picking. Store the credential once under **Credential Vault → + Add secret → DNS → Hurricane Electric (account login)** (automation mode is forced) — the same one LE uses. The External DNS tab appears once a `henet` (or other external-DNS) spoke is connected.

## Key files

`henet/src/control_plane.py`, `henet/src/henet_spoke.py`, `henet/src/henet_manager.py`, `henet/install_henet.sh`, `henet/requirements.txt`, `henet/VERSION`, `henet/tests/`.

## Notable behaviors & gotchas

- **A/AAAA only.** HE's dyndns endpoint can only update A/AAAA IPs. Non-A/AAAA record types are rejected without pushing.
- **DELETE is local-only.** HE's dyndns API has **no delete verb**, so `HENET_DELETE` only removes the record from local management — the zone entry remains at HE. Delete it in the dns.he.net UI if you want it gone (the response says so).
- **The DDNS key is never persisted on the spoke** and never returned to the browser — it's resolved per-command from the Credential Vault.
- Invalid IPs, unknown record types, and a missing DDNS key are rejected **without** contacting HE.
- Managed records live in `/etc/lm-henet/records.json` (written atomically via a temp file + `os.replace`); a corrupt/missing file starts from empty.

## How to use it

- **First-time setup:** store **one** Hurricane Electric credential in the Credential Vault — **+ Add secret → DNS → Hurricane Electric (account login)** (automation-readable is forced) — the same secret LE uses for certs. Then **assign it once** to the module: DNS → External DNS → HE.NET → **🔐 Assign credential** → pick the vault secret → save. **+ Add Record** and **Sync all** appear once a credential is assigned.
- **Add a record:** DNS → External DNS → HE.NET → **+ Add Record** → name/type(A|AAAA)/value(IP)/ttl → submit. The hub resolves the assigned key and pushes to HE; the record's Last Push badge shows the result.
- **Edit a record:** edit action → change the IP → save (re-pushes the same hostname).
- **Remove from management:** delete action (leaves the HE zone entry intact — remove it at dns.he.net if desired).
- **Re-push everything:** **Sync all** → confirm → syncs every managed A/AAAA record to HE using the assigned credential.
- **Change/clear the credential:** DNS → External DNS → HE.NET → **🔐 Assign/Change credential** → pick another secret and save, or **Clear** to unassign.

## Troubleshooting / common questions

- **"No HE.NET DDNS credential assigned."** No module-level credential is assigned. Store one **DNS → Hurricane Electric (account login)** secret (automation mode) — shared with LE — and assign it via **🔐 Assign credential**.
- **Credential doesn't appear in the picker.** The picker lists automation-readable HE credentials (including the Global-Admin `__admin__` slot) via `/tenant/cred-vault/automation-secrets`: shared `dns` "Hurricane Electric" credentials (and any legacy `henet` DDNS-key secrets). Ensure the secret was saved as a **"DNS → Hurricane Electric (account login)"** (automation mode is forced on save).
- **"HE.NET spoke not connected."** The `henet` role isn't loaded on an agent. Load the `henet` agent role (or install `install_henet.sh`), and confirm the node's `lm-agent` unit is up.
- **"I deleted a record but it still resolves at HE."** Expected — dyndns can't delete. Remove the entry in the dns.he.net UI; the module only stopped managing it.
- **"Push returned an error token."** HE's raw response (e.g. `badauth`, `nohost`) is surfaced verbatim in the Last Push tooltip — check the DDNS key and that the hostname has dynamic-DNS enabled at HE.

## Related pages

[dns.md](dns.md) (private-DNS analogue), [le.md](le.md) (same Credential-Vault pattern), [architecture-topology.md](architecture-topology.md), [install-flags.md](install-flags.md).
