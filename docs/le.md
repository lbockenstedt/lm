# le — Certificate Management

Certificate producer spoke. Repo: `le`. `module_type = "certificates"`. See [architecture-topology.md](architecture-topology.md).

## Role & module_type

A **producer** spoke that runs certbot ACME to issue/renew/revoke/list TLS certificates for the domains the hub manages. The hub **brokers** distribution: this spoke is the source of cert material (`LE_GET_CERT` pulls fullchain+key); target spokes apply it to their devices; `LE_MARK_DISTRIBUTED` is the hub's per-target ack recorded in the ledger. The lm-core `cert_distribution.py` runs the hub-side loop; this repo is the le spoke itself (ACME wrapper + ledger + control plane).

## What it does

le is where you request, renew, and revoke real Let's Encrypt (ACME) TLS certificates for the lab, from the WebUI's **Certificate Management** view instead of running `certbot` by hand.

le itself only *produces* certificates — it doesn't configure other services. Once a certificate exists, the hub distributes the cert material to whichever other modules you've pointed at it (for example, an OPNsense firewall or the LDAP directory server), so those modules can install it on their own devices.

## Entrypoints

`python3 -m src.control_plane` (`LEControlPlane`), systemd `lm-le.service`, `User=root` (root because certbot binds :80 for HTTP-01 and writes `/etc/letsencrypt`). Installer `install_le.sh` (clones lm core to `/opt/lm/core`, le to `/opt/lm/le`, apt `certbot python3-certbot-dns-cloudflare python3-certbot-dns-route53`, `/etc/lm-le` DNS-creds dir, `lm-le.service`).

> **Primarily a role now.** le runs mainly as the **`le`** role hosted by the generic agent (`agent-<hostname>`, unit `lm-agent`): the agent opens a sub-spoke `{agent}-le` (module_type `certificates`, parent-auto-approved) and self-installs it via `agent/src/agent_spoke.py::_install_role` (clones `lbockenstedt/le.git` + deps). The dedicated `lm-le.service` / `install_le.sh` `le-<hostname>` path is the **legacy/standalone** alternative. Config (`renew_interval`, ACME/DNS settings) comes from the hub push (WebUI), not a per-module `.env`.

## Ports

No listener. Spoke dials hub on **443** (`/ws/spoke`, wss). certbot transiently binds **:80** for HTTP-01 `--standalone` (or `--webroot -w <path>`).

## Environment variables

- `.env`: `HUB_URL`, `SPOKE_ID`, `SPOKE_SECRET`, `HUB_SECRET`.
- `acme.py`: `LM_LE_LIVE_DIR` (`/etc/letsencrypt/live`), `LM_LE_CONFIG_DIR` (`/etc/letsencrypt`), `LM_LE_DNS_CREDS_DIR` (`/etc/lm-le`), `LM_LE_CERTBOT_BIN` (`certbot`).
- `le_spoke.py`: `LM_LE_LEDGER` (`/var/lib/lm/<spoke_id>/certs.json`), `renew_interval` via `UPDATE_CONFIG` (default 86400s).

## Install flags

`install_le.sh`: `--hub`, `--id`/`--name`, `--secret`, `--hub-secret`, `--all-prereqs` (no-op). Default `SPOKE_ID=le-<hostname>`, `HUB_URL=auto` (mDNS/DNS auto-discovery — same as every other LM spoke; the old `wss://localhost:443/ws/spoke` default is gone). Pass `--hub <url>` to pin. **No** `--tls-verify`/`--tls-ca-cert` (not wired in this installer).

## Key commands / handlers (`LESpoke.handle_command`, `src/le_spoke.py`)

`LE_GET_STATUS` (version, `certbot_present`, certs managed), `LE_LIST_CERTS`, `LE_GET_CERT` (returns `fullchain`/`privkey`/`chain`/`material_hash`/`not_after`; `privkey` masked in logs but returned for distribution), `LE_ISSUE_CERT` (`domain`, `email`, `challenge` http|dns|tls-alpn, `webroot`, `dns_provider`, `dns_creds`/`dns_creds_ini`, `staging`, `key_type`, `targets[]`), `LE_RENEW_CERT` (one domain or all), `LE_REVOKE_CERT` (`domain`, `delete`), `LE_ADD_TARGET` (`domain`, `target.module_type`, `target.identifier`)/`LE_REMOVE_TARGET` (`domain`, `idx` — positional target index into the ledger's `targets[]` list), `LE_MARK_DISTRIBUTED` (`domain`, `module_type`, `identifier`, `hash`, `status`, `message`), `LE_CERT_RENEWED` (agent-initiated notify on background renewal), `UPDATE_CONFIG` (honors `renew_interval`), `GET_VERSION`, `SET_LOG_LEVEL`.

Background `_renew_loop`: daily reconcile of ledger vs `/etc/letsencrypt/live`, renews any cert within the 30-day window, refreshes `material_hash`/`not_after` so the hub re-pushes.

## HTTP-01 / DNS-01 / TLS-ALPN-01 (`src/acme.py`)

- `_normalize_challenge`: `http`/`http-01`/`http01` → `http`; `dns`/`dns-01`/`dns01` → `dns`; `tls-alpn`/`tls-alpn-01`/`tlsalpn01`/`tls_alpn`/`tls_alpn_01` → `tls-alpn`; else `ValueError`.
- HTTP-01: `certbot certonly --standalone` (default) or `--webroot -w <webroot>`.
- DNS-01: `--dns-<provider> --dns-<provider>-credentials <ini>`; creds INI written atomically 0600 to `/etc/lm-le/dns-<provider>.ini` (`write_dns_creds`, never logged). Preinstalled apt plugins: cloudflare + route53; others installable on demand.
- TLS-ALPN-01: `--preferred-challenges tls-alpn-01`. certbot ships no authenticator for this challenge by default — it requires a TLS-ALPN-01 plugin installed on the host (le does not auto-install one).
- Certs stored in certbot's native `/etc/letsencrypt/live/<name>/` layout so `certbot renew`/standard tooling still work; the LM ledger is the parallel index.

## Key files

`src/control_plane.py` (`LEControlPlane`, `run_hub_mode`), `src/le_spoke.py` (`LESpoke` + renewal loop), `src/acme.py` (certbot wrapper: `issue`/`renew`/`revoke`/`list_certs`/`read_material`/`expiring`), `src/ledger.py` (`Ledger` atomic JSON — `upsert_cert`/`add_target`/`remove_target`/`target_key`), `install_le.sh`, `tests/test_acme.py`, `tests/test_le_spoke.py`, `tests/test_ledger.py`, `requirements.txt`, `VERSION`.

## Notable behaviors & gotchas

- **README says "structured stubs" but current code wires real certbot** — the README is stale on that point.
- **Simplest spoke** — no listener port, no `--tls-verify` installer flag, no FastAPI dep. ACME producer + ledger.
- **Hub-side cert distribution** (`lm core cert_distribution.py`) is out of scope for the le repo; this spoke just produces + ledger-tracks cert material.

## How it works

- **Hub connection.** Like every LM spoke, le dials the hub over a WebSocket. In the current unified model this is the sub-spoke `{agent}-le` opened by the generic agent (parent-auto-approved); the legacy path is the standalone `le-<hostname>` dialing the hub directly.
- **Config delivery.** le has very little to configure — mainly `renew_interval` (default 86400s / daily) — and it arrives via the hub's `UPDATE_CONFIG` push, not a per-module `.env`. Pushing a new `renew_interval` restarts the background renewal loop immediately with the new timer.
- **Command flow.** Every WebUI action (issue, renew, revoke, list, add/remove a distribution target) becomes one `LESpoke.handle_command` call. Issuing or renewing shells out to `certbot` as an async subprocess (never blocking the event loop); revoking removes the cert from the ledger as well as from certbot.
- **The ledger.** A per-spoke JSON file (`/var/lib/lm/<spoke_id>/certs.json`, atomic tmp-file + `os.replace` writes) tracks, per domain: `material_hash`, `not_after`, `last_renewed_at`/`last_error`, and a `targets[]` list — the modules this cert should be pushed to, each with its own `last_pushed_hash`/`last_pushed_at`/`last_status`. Certificates themselves stay in certbot's native `/etc/letsencrypt/live/<name>/` layout, so plain `certbot renew` and other standard tooling keep working; the ledger is a parallel index the hub reads through the spoke.
- **Background renewal loop.** A daily (or `renew_interval`-configured) asyncio task reconciles the ledger against `/etc/letsencrypt/live` — picking up certs renewed out-of-band by bare `certbot renew` too — and renews anything whose `not_after` is within 30 days. A successful renewal updates the ledger's hash/expiry **and** immediately notifies the hub with `LE_CERT_RENEWED`, so distribution doesn't have to wait for the hourly hub-side sweep.
- **Hub-side distribution** (`lm/core/src/cert_distribution.py` + `hub_cert_distribution.py`, not part of this repo): the hub runs an hourly loop (60s startup delay, then every 3600s), and also fires distribution immediately on `/api/le/issue`, `/api/le/renew`, and on the `LE_CERT_RENEWED` event above. For each managed cert with targets, the hub pulls `fullchain`/`privkey`/`chain` from le via `LE_GET_CERT`, then sends a single generic `INSTALL_CERT` command (not a module-specific command name) to each target spoke, resolved by `module_type`. Supported target module types (`CERT_CAPABLE_MODULES`) today are **firewall** (OPNsense), **hypervisor** (pxmx — relays down to the per-node agent's `pvenode cert set`), **simulation** (cs/lm-spoke — relays to its pxmx agents **and** applies the cert to its own 8080 dashboard), **directory** (ldap → `slapd` TLS), **hub** (the hub self-installs on its own TLS endpoint), **statuspage**, **ipam** (NetBox), **nac** (ClearPass), and **nw** (AOS-CX switches). `dns`/`dhcp` are **not** cert-capable. See each module's own docs for what `INSTALL_CERT` does on that side. **Split-topology note:** where pxmx agents dial a **cs** spoke instead of a pxmx spoke, both a `hypervisor` target and a `simulation` target resolve to those same cs-owned agents — see the targets warning below. After a push, the hub calls `LE_MARK_DISTRIBUTED` on le so the ledger's `last_pushed_hash` is updated and an unchanged cert isn't redundantly re-pushed on the next sweep.
- **Distribution targets live on le, not on the hub.** `LE_ADD_TARGET`/`LE_REMOVE_TARGET` add or remove entries in *this spoke's* ledger (usually seeded via `targets` on the original `LE_ISSUE_CERT` call). The hub doesn't keep its own separate target list — it always asks le which targets a domain has.
- **Challenge types** (`src/acme.py`): HTTP-01 uses `certbot certonly --standalone` (needs port 80 free momentarily) or `--webroot` if a webroot path is supplied; DNS-01 uses a `--dns-<provider>` plugin with a credentials INI file written atomically at `0600` under `/etc/lm-le/`; DNS-01 plugins beyond the preinstalled cloudflare/route53 are `apt-get install`ed on demand the first time they're needed. TLS-ALPN-01 emits `--preferred-challenges tls-alpn-01` and requires a TLS-ALPN-01 authenticator plugin on the host (not shipped with certbot by default). A `staging` flag issues from Let's Encrypt's staging environment (untrusted by browsers, but exempt from production rate limits) for testing the whole flow safely.

## How to use it

1. **Issue a certificate.** In the Certificate Management view, provide the domain, a contact email, and a challenge type (`http`, `dns`, or `tls-alpn`). For `http`, make sure port 80 on this host is reachable from the internet and DNS for the domain already points here. For `dns`, pick a DNS provider and supply its API credentials — le writes them to a locked-down file and never logs them. For `tls-alpn`, a TLS-ALPN-01 authenticator plugin must be installed on the host. You can optionally seed one or more distribution targets (module type + identifier) at issue time.
2. **Enable/disable a distribution target — right on the Certificates list.** Each cert row has a **Distribute** strip listing every connected cert-capable spoke/agent as a chip: click a grey **`+`** chip to **enable** distribution to that node, or click a green **`✓`** chip to **disable** it (it turns red on hover to signal the click stops distribution). The status badges above the strip show each enabled target's last push result (✓/✗) and click-to-deploy that cert to just that target. (The Manage modal offers the same add/remove plus removing targets whose spoke is currently offline.)
3. **Renew a certificate.** Renew a single domain, or trigger renewal for everything le manages. le also renews automatically as certs approach their 30-day expiry window — manual renew is mainly for testing or forcing a push after a target-list change.
4. **Revoke a certificate.** Revoking calls certbot's revoke (optionally deleting the local material) and removes the domain from le's ledger — any target spokes keep serving the old cert until it expires or is replaced, since revoke doesn't push anything to targets.
5. **Check status / list certs.** The status view shows whether `certbot` is present and how many certs are managed; the list view shows each cert's expiry, hash, and target push state.

## Distribution targets — warnings & gotchas

These apply to the **agent-hosting** target types (`hypervisor`, `simulation`), where one target can mean a whole spoke's worth of Proxmox nodes. The Certificates view enforces the first point with a hover tooltip on the target chips, an inline ⚠ note on the cert row, and a confirm dialog when you add an overlapping target.

- **Pick ONE granularity per module — a group OR individual nodes, not both.** Each agent-hosting spoke offers two kinds of target: a **group** ("`simulation` — all nodes", identifier empty → broadcasts to every pxmx agent on that spoke) and **per-node** ("`simulation/<agent-id>`", identifier = the agent). If a spoke has one agent, the group target and that node's per-node target are the **same deploy**. Selecting both makes the hub push the same cert to the same node twice per sweep, so `pvenode cert set --restart` runs concurrently and the pveproxy restarts contend. Choose per-node targets for clean 1:1 status, or the group target if you want new agents auto-covered — never both.
- **`hypervisor` and `simulation` overlap in the split topology.** When pxmx agents dial a **cs** spoke (the common lab layout), a `hypervisor — all nodes` target and a `simulation — all nodes` target both land on the *same* cs-owned agents. Add only one; a `hypervisor` target here is redundant with the `simulation` one (and may also show failed if no pxmx spoke resolves it).
- **A target can briefly show "failed" while the cert is actually installing.** `pvenode` writes `/etc/pve/local/pveproxy-ssl.{pem,key}` **before** restarting pveproxy, and a loaded restart can outlive the wait or exit non-zero. The pxmx agent treats the on-disk cert fingerprint as authoritative — it reports **SUCCESS** once the cert is verified on disk (even on a slow/non-zero pveproxy restart), so a genuinely-deployed cert settles to green. Only a cert that isn't on disk stays red. Hypervisor/simulation `INSTALL_CERT` timeouts are 640s (> the spoke's 620s relay > the agent's 600s pvenode wait) precisely so the hub never times out first and masks an in-progress deploy.
- **Redundant targets used to loop.** Before the verify-on-disk fix, a target that deployed but reported ERROR never recorded SUCCESS in the ledger, so "failed targets retry each sweep" re-pushed forever — each retry re-ran pvenode and, for a `simulation` target, rebound the cs spoke's `/ws/agent` listener (dropping + reconnecting every agent). That was the "simulation keeps restarting" symptom. Trimming redundant targets removes the restart contention that provoked it.

## Troubleshooting / common questions

- **"Issuing over HTTP-01 fails."** Port 80 on this host must be free (certbot's `--standalone` binds it transiently) and the domain's DNS must already resolve to this host — Let's Encrypt validates by connecting back over HTTP.
- **"Issuing over DNS-01 fails."** Check the DNS provider name and API credentials; a wrong/expired token is the most common cause. If the provider isn't cloudflare or route53, le apt-installs the certbot plugin on first use — a failure there (e.g. no internet access to apt) surfaces as a clear plugin-install error rather than a certbot traceback.
- **"How do I test without risking Let's Encrypt's real rate limits?"** Set the `staging` flag on issue — certificates come from Let's Encrypt's staging CA (not trusted by browsers) but let you validate the whole issue/renew/distribute flow.
- **"The certificate didn't reach my firewall/directory server."** Check that a distribution target was actually added for that domain and module, that the target spoke is online, and that its own docs' `INSTALL_CERT` handling succeeded (each target spoke logs its own install result, echoed back to le via `LE_MARK_DISTRIBUTED`). Distribution also fires immediately after issue/renew, so a stuck cert usually means the target list or target spoke, not the timing.
- **"The cert reached my Proxmox node but the target shows failed."** `pvenode` writes the cert before restarting pveproxy, so a slow/among-warning restart can exit non-zero even though the cert is deployed. The agent verifies by fingerprint and reports SUCCESS when the cert is on disk, so this should self-correct once the agent is on the current build. If it persists, check you don't have **overlapping targets** (a group *and* a per-node target, or both `hypervisor` and `simulation`, for the same nodes) — the concurrent restarts are the usual cause. See "Distribution targets — warnings" above.
- **"A `simulation` target keeps restarting / looping."** Almost always overlapping targets keeping the ledger from settling on SUCCESS (see warnings above). Trim to one target per node; the loop stops once the deploy records SUCCESS + hash.
- **"The le spoke shows offline/red."** The `le` role isn't installed on the agent, `lm-agent` (or the legacy `lm-le` unit) isn't running, or the sub-spoke hasn't been approved.
- **"Why does this run as root?"** certbot needs to bind privileged port 80 for HTTP-01 challenges and write into `/etc/letsencrypt`; the installer runs the unit as root for that reason.

## Related pages

[architecture-topology.md](architecture-topology.md), [lm-hub.md](lm-hub.md), [opnsense.md](opnsense.md) (OPNsense `OPNSENSE_INSTALL_CERT` is a cert-distribution target), [install-flags.md](install-flags.md).