---
summary: "Hub-side encrypted store for the secrets modules need — DNS-01 credentials for Let's Encrypt, the Hurricane Electric DDNS key, serial-console logins, and generic API…"
keywords: [api_token, apikey, automation_get, cred_vault, credential, credentials, ddns_key, lm, net_services, password, passwords, secrets, token, vault]
---

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
credentials (e.g. the shared Hurricane Electric credential, the shared console login). `__admin__` is
excluded from tenant-admin reach. (`cred_vault.py:1-15, 62-68`;
`routes/cred_vault.py:68-83`.)

A bucket is listed for **every** tenant — including `default` (the DEFAULT
tenant), which is a real tenant that owns real spokes. It used to be hidden as a
"system" bucket, which meant a Global Admin could not store a credential for the
DEFAULT tenant at all, so no scan-credential set could be built for it and an
`nw` agent bound to `default` had nothing to scan with.

A bucket that matches **no** tenant and is not `__admin__` is reported as
**orphaned** (`is_orphan`) and labelled as such in the UI. Orphans only exist
because they hold secrets (e.g. a bucket created by typing a free-text name like
`admin`); nothing tenant-scoped can ever reference one, and a tenant-admin can
never reach it. Do not confuse an orphan named `admin` with the real Global
Admin slot, which is `__admin__`.

An orphan can be cleared up: a Global Admin gets a banner offering **Move a
secret out…** (rescue the credential into a bucket something can actually
reference) and **Delete this bucket**. See *Rescuing and removing an orphaned
bucket* below.

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
| `dns` (DNS) | `he-login`: `{provider, he_username, he_password}`; others: `{provider, dns_creds}` (INI) | LE DNS-01 issuance (and shared with HE.NET) |
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
| `POST /tenant/cred-vault/reset-psk` | **Global Admin only** — last-resort reset of a lost/corrupted pass-phrase, no old pass-phrase required | — |
| `POST /tenant/cred-vault/secret` | create/update a secret (`value` object, `mode`, `type`, `description`) | ✔ |
| `POST /tenant/cred-vault/reveal` | reveal plaintext (response is `no-store`) | ✔ |
| `POST /tenant/cred-vault/delete` | delete a secret | ✔ |
| `POST /tenant/cred-vault/move-secret` | **Global Admin only** — move one secret to another bucket (metadata re-point, no copy) | only for `psk`-mode |
| `POST /tenant/cred-vault/delete-bucket` | **Global Admin only** — delete a bucket outright; refuses `__admin__` and live-tenant buckets | — |

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
- **Module connections (NAC / network devices / IPAM)** — a saved connection
  instance may carry a `vault_credential` `{bucket, name}` reference instead of an
  inline secret. `core/src/instance_vault.py` (`SECRET_FIELDS`) maps each
  product's secret fields to the vault-secret aliases: **ClearPass**
  (`nac_instances`) → `client_secret` / `user` / `password`; **network devices**
  (`nw_devices`) → `password` / `enable_secret` / `api_token` / `snmp_community`;
  **NetBox/IPAM** (`ipam_instances`) → `api_token`. On save the inline secret is
  stripped and the ref validated; at push time `instance_vault.overlay()` fills
  the field(s) the resolved secret carries before the config reaches the spoke.
  See [cppm.md](cppm.md) and [netbox.md](netbox.md).

## WebUI

The **Credential Vault** appears in the left nav for tenant-admins / admins
(`_credVaultNavHtml()`, `WebUI/main.js:3033`). The screen (`loadCredVault()`,
`WebUI/main.js:4329+`) lists buckets and their secrets; **+ Add secret**
(`_cvAddSecretModal` → `_cvRenderAddFields` / `_cvDnsRenderFields` →
`_cvDoAddSecret`) picks a type and (for automation types) forces `hub` mode;
**Reveal** (`_cvRevealModal`) prompts for the bucket pass-phrase.

For an orphaned bucket a Global Admin also sees an amber banner with
`_cvMoveSecretModal()` and `_cvDeleteBucketModal()`. The move modal hides the
pass-phrase fields entirely when the selected secret is `hub`-mode, since none
is needed; the delete modal names every secret that would be destroyed and
requires a tick-box before it will do so.

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
- **A lost pass-phrase is recoverable, as a last resort.** `POST /psk` can only
  *rotate*, because it verifies the old pass-phrase first; a forgotten one used
  to brick the bucket through the UI forever. A **Global Admin** can now
  `POST /tenant/cred-vault/reset-psk` (surfaced as "Lost the current
  pass-phrase? Reset it" in the set/change modal). The blast radius is exactly
  the `psk`-mode secrets:
  - `hub`-mode secrets are keyed on the hub Fernet key, **not** the
    pass-phrase, so they survive a reset untouched and keep serving automation.
    A bucket holding only `hub`-mode secrets resets with **zero** data loss.
  - `psk`-mode secrets are already undecryptable once the pass-phrase is lost,
    so they can only be discarded — which the endpoint refuses unless
    `confirm_destroy` is sent. Those credentials must then be re-entered.

  The reset is audit-logged with the acting account. A non-Global-Admin gets a
  404, not a 403, so the door isn't advertised.
- **Moving a secret does not copy it.** The at-rest blob name is a random id,
  not derived from the bucket, so `move-secret` re-points metadata rather than
  writing a second copy and deleting the first — the credential never exists in
  two buckets at once and is never briefly missing. `hub`-mode secrets are keyed
  on the hub Fernet key, so no pass-phrase is needed for either side;
  `psk`-mode secrets are keyed on the **source** bucket, so both `psk` and
  `to_psk` must be supplied and the value is re-encrypted under the
  destination's key. A move refuses to overwrite a same-named secret in the
  destination.
- **A bucket could be created but never removed.** `list_buckets` derives from
  the pass-phrase records UNION the secret records, so a bucket created by
  typing a free-text name lingered in every Global Admin's picker forever —
  inviting credentials to be stored somewhere no tenant-scoped code can
  reference. `delete-bucket` removes it, and:
  - always refuses `__admin__`, which is load-bearing infrastructure
    (IPAM/NetBox and the HE.NET + Let's Encrypt DNS credentials resolve
    through it);
  - refuses any bucket that belongs to a **live tenant** — those follow the
    tenant lifecycle; delete the tenant instead;
  - refuses to destroy leftover secrets unless `confirm_destroy` is sent, and
    deletes their backing blobs when it does, so nothing is left alive in Key
    Vault after the operator is told it was destroyed.

### Rescuing and removing an orphaned bucket

If the pass-phrase is also lost, none of this is blocked as long as the secrets
are `hub`-mode:

1. **Reset the pass-phrase** (`reset-psk`) — loses nothing if every secret is
   `hub`-mode.
2. **Move each secret out** (`move-secret`) into a bucket that matches a real
   tenant, or into `shared` if it is genuinely cross-tenant.
3. **Delete the bucket** (`delete-bucket`).
4. If the credential was meant for scanning, build an `nw` scan-credential set
   referencing it so the tenant's agent can finally use it.
