# Install Flags Reference

Consolidated reference for every installer and its flags across the LM system. Canonical copy in `lm/docs/`. See [architecture-topology.md](architecture-topology.md) and [environment-variables.md](environment-variables.md).

## Common spoke flags (most spoke installers)

| Flag | Meaning |
|---|---|
| `--hub <url>` | Hub WebSocket URL (often optional/`auto` → discover) |
| `--id <id>` / `--name <id>` | Spoke ID (default `<hostname>-spoke` or `<hostname>-spoke-1`) |
| `--secret <s>` | Spoke first secret (omit → pending-negotiation, await admin approval) |
| `--hub-secret <s>` | Hub root secret for mutual auth |
| `--tls-verify` | Enable hub TLS cert verification (sets `LM_HUB_TLS_VERIFY=1` + `LM_HUB_CA_CERT`) |
| `--tls-ca-cert <path>` | CA cert path (required by standalone installers when `--tls-verify`) |
| `--all-prereqs` | No-op (hub-compat placeholder) |

## lm (hub)

### `install_all.sh` — hub + co-located spokes
`--reinstall` (reinstall over existing), `--reset-secrets` (wipe spoke/hub secrets), `--reset-users` (wipe user accounts), `--exclude <csv>` (skip spoke modules), `--tls-verify` (optional `--tls-ca-cert <path>`; defaults CA to the hub's own `$TLS_CERT`). Per-module loop honors `--exclude` and passes `--hub $HUB_WS --id $SPOKE_ID [--spoke-only]`.

### `install_menu.sh` — interactive bootstrap
Top menu: `1) Hub` (spoke checklist → `install_all.sh --exclude <unselected>`) or `2) Generic agent` (→ `generic_agent/install_github.sh`). Hub path prompts co-located spokes; Generic path prompts `--spoke-url` (default `auto`), `--id`, first secret, hub root secret, "Verify hub TLS certificate? (requires the hub CA cert) [y/N]", clone-only. Env `LM_BRANCH` (default `main`). Re-exes as root via sudo; re-exec from a temp file with stdin on `/dev/tty` for the one-liner.

### `generic_agent/install_github.sh`
`--spoke-url` (optional/`auto` → auto-discover), `--id`, `--secret`, `--hub-secret`, `--tls-verify` (+ `--tls-ca-cert`; defaults `/opt/lm/certs/hub.crt` if present, else requires it), `--clone` (install but don't start). Builds ExecStart arg list conditionally (omits blank `--secret`/`--id`).

### `agent/install_agent.sh`
`--hub` (required), `--id`, `--secret`, `--role` (one of `dns|dhcp|network|netbox|opnsense|ldap|simulation|cppm|proxmox|le`). Boot-time `--role` does NOT run `_install_role` (only system packages pre-installed).

### Other lm installers
`install.sh`, `install_hub.sh`, `install_ui.sh`, `install_hub_ui.sh`, `install_pxmx.sh` (pxmx agent/spoke; **standalone DEFAULT** — spoke serves `wss://:443`, agent dials `wss://<spoke>:443/ws/agent` directly, `agent → spoke → hub`; `--loopback` opt-in for co-located all-in-one — binds loopback `8443`, hub `/ws/agent` byte-proxies to it, `agent → hub → spoke`, passed only by `install_all.sh`; legacy `8766` no-TLS fallback), `install_cs.sh`, `install_opnsense.sh`, `install_production.sh`, `prep_for_image.sh`, `start.sh`, `start_all.sh`, `sync_secrets.sh`, `verify_auth.sh`.

## pxmx

### `install_pxmx.sh`
`--hub`, `--id`/`--name`, `--secret`, `--hub-secret`, `--tls-verify` (+ `--tls-ca-cert`; **required** on standalone), `--loopback` (opt-in co-located/all-in-one mode — **passed only by `install_all.sh`**; default is standalone `agent → spoke → hub`), `--all-prereqs` (no-op). IDs default `<hostname>-spoke`. See [pxmx.md "Agent listener modes"](pxmx.md).

### `agent/install_agent.sh`
`--spoke-ip` (preferred; auto-determines the WS URL), `--spoke-url` (advanced full-URL pin), `--id`, `--secret`. **Standalone spoke: `--spoke-ip <spoke>` is REQUIRED (just the IP; the agent auto-determines the rest)** (a standalone spoke does not broadcast `_lm-hub` mDNS, so the agent cannot auto-discover it). Auto-discovery (`--spoke-ip`/`--spoke-url` absent) applies only on the loopback/all-in-one path, where the agent discovers the **hub** and dials `wss://<hub>:443/ws/agent`.

## cs

### `lm-spoke/install_cs.sh`
`--hub`, `--id`/`--name`, `--secret`, `--hub-secret`, `--dhcp-iface`, `--no-dhcp`, `--tls-verify` (+ `--tls-ca-cert`, **required**), `--admin-token` (deprecated no-op), `--all-prereqs` (no-op). Stale `CS_API_PORT=8000` auto-migrated to 8080. `control_plane.py` CLI also accepts `--port`, `--host`, `--standalone`, `--onboarding-psk`, `--tenant-id-hint`.

### `installers/install-lxc.sh` (webui-spoke legacy)
`--branch`, `--port`, `--admin-password`, `--hub-url`, `--hub-tenant`, `--hub-psk`, `--reinstall`, `--force`.

## le

### `install_le.sh`
`--hub`, `--id`/`--name`, `--secret`, `--hub-secret`, `--all-prereqs` (no-op). Default `SPOKE_ID=le-<hostname>`, `HUB_URL=wss://localhost:443/ws/spoke`. **No** `--tls-verify`/`--tls-ca-cert` (not wired).

## netbox

### `install.sh`
`--hub`, `--id`/`--name`, `--secret`, `--hub-secret`, `--netbox-url`, `--netbox-token`, `--db-pass`, `--superuser`, `--superpass`, `--supermail`, `--netbox-version`, `--spoke-only` (skip full app), `--all-prereqs` (no-op), `--admin-token` (deprecated). Installs NetBox v4.2+, provisions custom fields, injects `CUSTOM_VALIDATORS`, registers the API token with the hub.

## opnsense

### `install_opnsense.sh`
`--hub`, `--id`/`--name`, `--secret`, `--hub-secret`, `--all-prereqs` (no-op). Keeps default PSK `lm-secret` for zero-touch.

## nw

### `install_nw.sh`
`--hub`, `--id`/`--name`, `--secret`, `--hub-secret`, `--all-prereqs` (no-op). Equals-attached `--id=…` form (values starting with `-` don't trip argparse). Clears `SPOKE_SECRET` to `""` when unset (zero-touch pending).

## ldap

### `install_ldap.sh`
`--hub`, `--id`/`--name`, `--secret`, `--hub-secret`, `--all-prereqs` (no-op). Only passes `--secret`/`--hub-secret` when non-empty (avoid argparse abort).

## cppm

### `install.sh`
`--hub`, `--id`/`--name`, `--secret`, `--hub-secret`, `--all-prereqs` (no-op). Keeps default PSK `lm-secret` for zero-touch.

## dhcp / dns

**No install scripts** in these repos (minimal/stub-style). Deployed via the agent-spoke role loader or a manual unit.

## bugfixer

### `install.sh`
None (curl|bash; stdin to `/dev/null`).

### `install_github.sh` (legacy)
`--spoke-url`, `--id`, `--secret`, `--hub-secret`, `--clone-only`.

## Notes

- **`--tls-verify` is the only TLS opt-in.** No flag = verify off (encrypt, no auth). See [architecture-topology.md](architecture-topology.md) § TLS trust model.
- **Standalone vs co-located:** `install_all.sh` (co-located) defaults the CA to the hub's own cert; standalone installers (pxmx, cs) **require** `--tls-ca-cert`.
- **No-secret = pending:** omitting `--secret` is a valid first-install state — the spoke connects unauthenticated and shows up pending in the WebUI until approved (or matches a hub PSK).