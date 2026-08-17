# henet — HE.NET public DNS (Hurricane Electric)

HE.NET spoke managing **public-address-space** A/AAAA records at Hurricane Electric's free DNS (`dns.he.net`). Vendored in-tree at `lm/henet/`. `module_type = "henet"`. See [architecture-topology.md](architecture-topology.md).

The public-address-space analogue of the [`dns`](dns.md) (Unbound) module: instead of writing records into a local Unbound conf and reloading, it pushes A/AAAA records to Hurricane Electric over HE's officially documented **dynamic-DNS update** protocol (`https://dyn.dns.he.net/nic/update`).

## Role & module_type

Pure HE-API client — no local server, no daemon to manage. Runs as the **`henet`** agent role (or a standalone `lm-henet` unit). `module_type = "henet"`.

## What it does

Manages public DNS A/AAAA records hosted at Hurricane Electric. Each record is pushed to HE's dyndns endpoint, which authenticates the update with a per-record **DDNS key** (the "Enable entry for dynamic DNS" key generated in the dns.he.net UI). The module tracks the set of records it manages in a small local JSON state file so the WebUI can list what's under management and show each record's last push result.

In the WebUI, HE.NET lives **under the DNS module** ("all things DNS"): open **DNS → HE.NET** tab to reach the records view — an admin can add/edit/delete managed records and re-push them all with **Sync all**; a non-admin DNS viewer sees the records read-only.

## Credential Vault (DDNS key) — exactly like the LE module

The HE DDNS key is a **secret** and — exactly like the LE module's DNS-01 credentials — is **NEVER stored on the spoke** and never sent to the browser. It lives in the hub-side **Credential Vault** ([le.md](le.md) uses the same mechanism):

- Store the key as a Credential Vault secret of type **`henet`** (`{ ddns_key: ... }`), in **automation-readable** (`hub`) mode so the hub can resolve it unattended.
- On each write, the WebUI sends a `henet_vault_credential` `{bucket, name}` reference (not the key itself).
- The hub resolves it in-place via `cred_vault.automation_get(hub, bucket, name)` (`net_services._henet_resolve_vault_cred`) and injects `ddns_key` into the relayed `HENET_*` command — mirroring LE's `_le_resolve_vault_dns_cred`.
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

`GET /api/henet/records`, `GET /api/henet/status`, `POST/PUT/DELETE /api/henet/record`, `POST /api/henet/sync`. Writes are **Global-Admin-only** (`api.py` `_ADMIN_INFRA_WRITE_PREFIXES` includes `/api/henet/`), because HE.NET is public-address-space infra with no per-tenant object model. **Reads** are gated like the DNS module — the `dns` right OR the explicit `henet` right OR admin — so anyone who can view DNS can also view HE.NET records (`api.py` `/api/henet/` read gate; `access.py`).

## WebUI

HE.NET is a subtab of the **DNS** module (the DNS nav item covers Unbound *and* HE.NET). **DNS → HE.NET** shows a status line (HE dyndns reachable? + managed-record count) and a records table (Name / Type / Value / TTL / Last Push). Management — **+ Add Record** / edit / delete / **Sync all** — is admin-only; a non-admin DNS viewer sees the table read-only. The Add/Edit modal includes a **HE DDNS credential** picker populated from Credential Vault secrets of type `henet`. Add a key under **Credential Vault → + Add secret → HE.NET DDNS key** (automation mode is forced). The HE.NET tab appears once a `henet` spoke is connected.

## Key files

`henet/src/control_plane.py`, `henet/src/henet_spoke.py`, `henet/src/henet_manager.py`, `henet/install_henet.sh`, `henet/requirements.txt`, `henet/VERSION`, `henet/tests/`.

## Notable behaviors & gotchas

- **A/AAAA only.** HE's dyndns endpoint can only update A/AAAA IPs. Non-A/AAAA record types are rejected without pushing.
- **DELETE is local-only.** HE's dyndns API has **no delete verb**, so `HENET_DELETE` only removes the record from local management — the zone entry remains at HE. Delete it in the dns.he.net UI if you want it gone (the response says so).
- **The DDNS key is never persisted on the spoke** and never returned to the browser — it's resolved per-command from the Credential Vault.
- Invalid IPs, unknown record types, and a missing DDNS key are rejected **without** contacting HE.
- Managed records live in `/etc/lm-henet/records.json` (written atomically via a temp file + `os.replace`); a corrupt/missing file starts from empty.

## How to use it

- **Add a record:** HE.NET module → **+ Add Record** → name/type(A|AAAA)/value(IP)/ttl → pick an HE DDNS credential → submit. The hub resolves the key and pushes to HE; the record's Last Push badge shows the result.
- **Edit a record:** edit action → change the IP → save (re-pushes the same hostname).
- **Remove from management:** delete action (leaves the HE zone entry intact — remove it at dns.he.net if desired).
- **Re-push everything:** **Sync all** → pick a credential → syncs every managed A/AAAA record to HE.
- **First-time setup:** store the HE DDNS key in the Credential Vault (secret type "HE.NET DDNS key", automation-readable) before adding records.

## Troubleshooting / common questions

- **"Add failed: no DDNS key supplied."** No `henet` credential was selected/resolvable. Store the HE DDNS key as a Credential Vault secret of type `henet` (automation mode) and select it in the Add/Sync modal.
- **"HE.NET spoke not connected."** The `henet` role isn't loaded on an agent. Load the `henet` agent role (or install `install_henet.sh`), and confirm the node's `lm-agent` unit is up.
- **"I deleted a record but it still resolves at HE."** Expected — dyndns can't delete. Remove the entry in the dns.he.net UI; the module only stopped managing it.
- **"Push returned an error token."** HE's raw response (e.g. `badauth`, `nohost`) is surfaced verbatim in the Last Push tooltip — check the DDNS key and that the hostname has dynamic-DNS enabled at HE.

## Related pages

[dns.md](dns.md) (private-DNS analogue), [le.md](le.md) (same Credential-Vault pattern), [architecture-topology.md](architecture-topology.md), [install-flags.md](install-flags.md).
