# Credential Vault

Hub-side encrypted store for the secrets modules need — DNS-01 credentials for
Let's Encrypt, the Hurricane Electric DDNS key, serial-console logins, and
generic API keys/tokens. Secrets are **encrypted at rest** (Azure Key Vault when
configured, otherwise a Fernet-encrypted blob in hub state) and, critically, are
**never sent to the browser**: a module stores only a `{bucket, name}` reference
and the hub resolves the plaintext unattended at use-time. Canonical code:
`core/src/cred_vault.py` (engine) and `core/src/routes/cred_vault.py` (routes).

## Concepts

### Buckets — one per tenant + the Global-Admin slot
Each **bucket** holds one tenant's secrets. A tenant-admin can reach only their
own tenant buckets; a **Global Admin** can reach every tenant bucket **plus** the
special `__admin__` slot ("Global Admin slot") for cross-tenant / infrastructure
credentials (e.g. the HE.NET DDNS key, the shared console login). `__admin__` is
excluded from tenant-admin reach. (`cred_vault.py:1-15, 62-68`;
`routes/cred_vault.py:68-83`.)

Two independent gates protect a secret:
- **Reach** (role) — which buckets you can see at all.
- **Pass-phrase / PSK** (knowledge) — whether you can *decrypt* an interactive
  secret. (`cred_vault.py:17-23`.)

### Secret modes — `psk` vs `hub` (automation-readable)
Every secret is stored in one of two modes (`cred_vault.py:24-35`):

| Mode | Encryption | Who can read it |
| :--- | :--- | :--- |
| `psk` (default, strongest) | key derived from the bucket **pass-phrase** via scrypt | interactive reveal only, with the PSK — **no** unattended access |
| `hub` (automation-readable) | the hub's **Fernet** key | the hub resolves it unattended via `automation_get`; interactive reveal still needs the PSK |

Modules that must resolve a secret without a human present (LE issuance, HE.NET
pushes, console auto-login) require **`hub`** mode — the add-secret form forces
and locks it for those types.

### Storage backend — Azure Key Vault or local Fernet
The hub picks the backend per `_vault_available(hub)` (true when a Key Vault
`vault_url` is configured, `cred_vault.py:140-147`):
- **Azure Key Vault** when configured — ciphertext lives in Key Vault
  (`_store_put/_get/_del` via the `key_vault` REST broker).
- **Local fallback** otherwise — ciphertext lives in hub-state `blobs`.

Either way the value is Fernet-encrypted before it leaves the hub
(`cred_vault.py:157-184`). Key Vault config env: `LM_KEYVAULT_URL`,
`LM_KEYVAULT_CLIENT_ID` (`core/src/security/credential_store.py:94-96, 165-183`).

## Secret types & value shapes

The add-secret form (`WebUI/main.js:4486-4625`) supports:

| Type | Value shape | Used by |
| :--- | :--- | :--- |
| `login` | `{username, password}` | generic |
| `apikey` | `{apikey}` | generic |
| `token` | `{token}` | generic |
| `dns` (DNS-01) | `he-login`: `{provider, he_username, he_password}`; others: `{provider, dns_creds}` (INI) | LE (and shared with HE.NET) |
| `henet` | `{ddns_key}` | HE.NET (and shared with LE) |
| `console` | `{credentials: [{username, password}]}` | Console |
| `generic` | `{[key]: value}` | anything |

`dns` providers: `he-login`, `cloudflare`, `rfc2136`, `route53`
(`WebUI/main.js:20939-20953`). A secret's non-secret `fields` metadata (the list
of value keys) is what pickers use to recognize, e.g., a Hurricane Electric
credential.

## HTTP API (`/tenant/cred-vault/*`)

All routes are tenant-admin / Global-Admin only at the middleware layer
(`routes/cred_vault.py:1-17`). Pass-phrase-guarded routes are wrapped by
`_guard` (maps domain errors → HTTP 400/503/502).

| Method + path | Purpose | PSK? |
| :--- | :--- | :--- |
| `GET /tenant/cred-vault/buckets` | list reachable buckets + PSK status + counts (GA sees all + `__admin__`) | no |
| `GET /tenant/cred-vault/secrets?bucket=` | list secrets in one bucket (names + metadata, no values) | no |
| `GET /tenant/cred-vault/automation-secrets[?type=]` | list only `hub`-mode secrets across reachable buckets — the **picker source** for module references | no |
| `POST /tenant/cred-vault/psk` | set/rotate a bucket pass-phrase (rekeys `psk`-mode secrets) | — |
| `POST /tenant/cred-vault/secret` | create/update a secret (`value` object, `mode`, `type`, `description`) | ✔ |
| `POST /tenant/cred-vault/reveal` | reveal plaintext (response is `no-store`) | ✔ |
| `POST /tenant/cred-vault/delete` | delete a secret | ✔ |

The `automation-secrets` endpoint is the key to the "store once, resolve
unattended" pattern: it returns hub-mode secrets across **every** reachable
bucket **including** the `__admin__` slot, with no pass-phrase — so a module
picker sees automation keys a per-bucket PSK-gated listing would hide.

## How modules consume vault secrets

The pattern: the module stores just a `{bucket, name}` reference; a server-side
resolver calls `cred_vault.automation_get(hub, bucket, name)` at use-time and
injects the plaintext into the outbound command. The browser never sees the
value.

- **Let's Encrypt (le)** — DNS-01 credentials are added in the vault (not the old
  LE form). Resolve: `_le_resolve_vault_dns_cred()`
  (`core/src/routes/net_services.py:487-541`); the tenant's chosen ref persists in
  `global_config["le_vault_dns_creds"]` (`net_services.py:543-555`) and re-syncs to
  the spoke on reconnect (`core/src/le_cache.py:103-161`). See [le.md](le.md).
- **HE.NET (henet)** — `_henet_resolve_vault_cred()`
  (`net_services.py:277-329`) resolves the assigned or explicit ref and injects
  `ddns_key`; the module-level assignment persists in
  `global_config["henet"]["vault_credential"]` via `GET/POST/DELETE
  /api/henet/credential`. **One Hurricane Electric credential serves both LE and
  HE.NET** — the picker accepts `henet` DDNS-key secrets *and* shared `dns`
  Hurricane-Electric secrets, and the hub reformats either shape into the dyndns
  push password (`_henet_extract_ddns_key`). See [henet.md](henet.md).
- **Console** — `_console_load_credentials_resolved()`
  (`core/src/routes/console.py:451-465`) prefers the `__admin__` slot secret
  `console-auto-credentials` (`type=console`, `mode=hub`); `POST
  /api/console/credentials/to-vault` migrates existing creds into the vault
  (`console.py:1107-1136`). See [console.md](console.md).

## WebUI

The **Credential Vault** appears in the left nav for tenant-admins / admins
(`_credVaultNavHtml()`, `WebUI/main.js:3033`). The screen (`loadCredVault()`,
`WebUI/main.js:4329+`) lists buckets and their secrets; **+ Add secret**
(`_cvAddSecretModal` → `_cvRenderAddFields` / `_cvDnsRenderFields` →
`_cvDoAddSecret`) picks a type and (for automation types) forces `hub` mode;
**Reveal** (`_cvRevealModal`) prompts for the bucket pass-phrase.

## Gotchas

- **`psk`-mode secrets can't be resolved unattended** — a module that needs a
  credential (LE/HE.NET/console) must have it stored in **`hub`** mode. The
  add-secret form forces this for those types.
- **The picker only shows `hub`-mode secrets** (`automation-secrets`). A secret
  saved in `psk` mode won't appear as an assignable module credential.
- **Infra credentials belong in `__admin__`** — only a Global Admin can reach
  that slot; it's where cross-tenant keys (HE.NET DDNS, shared console login)
  live so they aren't tied to one tenant bucket.
- **Rotating a bucket PSK rekeys only `psk`-mode secrets** — `hub`-mode secrets
  are encrypted with the hub key, not the PSK (`cred_vault.py:223-255`).
