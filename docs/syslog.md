---
summary: "Syslog: per-tenant rsyslog collectors on LM agents with a 24 h local store, an optional long-term archive (LM-installed Graylog or any external syslog server), drop rules applied to both, and hub routes to search, tail, tune and troubleshoot it all from the WebUI."
keywords: [syslog, logging, rsyslog, graylog, archive, collector, drop rules, syslog-collector, syslog-graylog, SYSLOG_QUERY, SYSLOG_DIAG, logging module]
---

# Syslog

Network devices, servers and appliances send their syslog to a **collector**
that LM installs on one of the tenant's agents. The collector keeps the last
24 hours on local disk and, when the tenant has one, forwards a copy to a
long-term **archive**. The Syslog page in the WebUI searches, tails and tunes
everything through the hub; nobody needs shell access to a collector.

The hub never carries the log traffic itself. Devices talk to collectors, and
collectors talk to the archive directly over TLS. The hub only sends commands
and merges the answers.

## Parts

| Part | What it is | Where |
|------|------------|-------|
| `syslog-collector` | Deploy role. Installs rsyslog listening on UDP/TCP 514 and TLS 6514, with an hourly local store under `/var/lib/lm/syslog`. | Any agent of the tenant (several allowed). |
| `syslog` | Spoke role (module_type `logging`, repo `lbockenstedt/syslog`). Manages the collector: drop rules, retention, archive forwarding, queries. | Loaded by the hub on the same agent right after `syslog-collector` deploys. |
| `syslog-graylog` | Deploy role. Installs Graylog + OpenSearch + MongoDB as the tenant's archive. Syslog input TCP+TLS 1514, API/UI 9000. | One per tenant. |

Install both deploy roles from **Setup → Agents → Load Role**. The roles are
in the catalog next to `zabbix-server` and `zbxproxy`.

## How devices send logs

Point the device at any of the tenant's collector IPs (shown on **Syslog →
Settings**):

- UDP 514 or TCP 514 (plain syslog), or
- TCP 6514 (syslog over TLS; the collector's cert is signed by the hub CA).

Each message is stored with the original hostname and the sender's source IP.

## Local store (24 h)

Each collector keeps `retention_hours` (default 24, 1–168) of messages, capped
at `max_mb` (default 2048 MB). Older hours are compressed and then deleted;
if the size cap is hit, the oldest hours go first. Searches within this window
are answered by the collectors themselves.

## Archive

A tenant has **at most one archive**. Collectors forward standard RFC 5424
syslog over TLS (always; a plain-text archive is refused), keeping the original hostname and adding
`[lm@32473 src_ip="…" lm_tenant="…"]`. Any syslog server can receive that, so
the archive backend can be swapped.

- **LM-installed (Graylog).** Load `syslog-graylog` on an agent of the tenant.
  Before install the hub generates the Graylog admin and read-only
  (`lm-reader`) passwords and a hub-CA certificate named
  `syslog-graylog-<tenant>`. The passwords are stored encrypted on the hub
  (cloud vault when enabled, otherwise the encrypted hub state) and never
  shown or logged. The agent hands them to the installer as 0600 files that
  the installer reads and deletes, never on a command line. When the role loads, the hub asks the agent for its IP,
  saves the archive record and pushes it to every collector of the tenant
  (`SYSLOG_CONFIG {"archive": …}`). Hub-CA certificates carry only their name
  as a DNS SAN, so collectors connect to the IP and verify the certificate
  against `tls_name` (`syslog-graylog-<tenant>`). Unloading or uninstalling the
  role removes the record and tells the collectors to stop forwarding. The
  archive data (`/var/lib/opensearch`, MongoDB) is left on disk.
- **External server.** **Syslog → Settings → Archive → External** (tenant
  admin): backend `graylog` or `syslog` (forward only), host, TLS port
  (always encrypted: `tls: false` is refused), optional CA PEM and `tls_name`, the name in the archive's certificate
  (required when the host is an IP address; blank = verify against the host
  name). The collector always checks that name, never only the CA chain.
  For Graylog, also an `https` API URL, user and password (or a Credential
  Vault reference) so searches older than the local window can be answered.
  Only the tenant's collectors call the API URL (the hub never does), so a
  lab-internal address is fine; link-local addresses are refused.
- **None.** Collectors keep only their local window.

You cannot replace or delete an LM-installed archive from the Archive section
(HTTP 409); unload the `syslog-graylog` role first. Loading a second archive
role for a tenant that already has an archive is refused (HTTP 400).

A search that starts before the collectors' local data is split at one
cut-off for all of them: the newest "oldest local message" across the
tenant's collectors (from the overview cache). Each collector returns its
local messages from the cut-off on, and one collector also searches the
archive (filtered to the tenant) for the time before it, so results neither
overlap nor leave a gap and a slow archive never hides recent messages.

### Graylog UI

Tenants never see Graylog's own UI; all searching happens in LM. **Global
Admins** see the Graylog UI link (`ui_url`) in the overview for
troubleshooting and upgrades.

## Drop rules

Per-tenant rules that discard noise **before** it is stored locally and
before it is forwarded, so they apply to the local store and to the archive.

`{"field": "host"|"program"|"msg"|"severity", "op": "equals"|"contains"|"regex"|"gte", "value": …, "enabled": true, "note": "…"}`

- At most 50 rules. Regexes must compile (checked on the hub and on the spoke).
- `severity` uses syslog numbers 0 (emerg) to 7 (debug). `gte` is only valid
  for severity: `gte 7` drops debug, `gte 6` drops info and debug.
- **Drop preview** shows how many of the last hour's messages each rule would
  drop before you save.

## Hub routes

All routes are tenant-scoped: a user sees only their own tenant (`?tenant=`
selects one of the user's tenants; Global Admins must pick a tenant). Another
tenant's collectors are never asked.

| Route | Who | What |
|-------|-----|------|
| `GET /api/syslog/overview` | tenant member | Collectors (status), merged sources of the last hour, archive (no secrets; `ui_url` for Global Admins only; `host_status` = the archive agent's deploy-role state). Served from the hub cache, refreshed every 60 s. |
| `POST /api/syslog/query` | tenant member | `SYSLOG_QUERY` fields (`start`, `end`, `host`, `program`, `severity_max`, `text`, `limit` ≤ 5000, `after_ts` for live tail) + optional `collector` name. Fans out (bounded), merges newest first. Returns `messages` (each with `collector`), `sources` counts, `errors` per collector, `truncated`. |
| `GET /api/syslog/settings` | tenant member | Drop rules, retention, size cap and the rule limits. |
| `PUT /api/syslog/settings` | tenant admin | Validates, saves, pushes `SYSLOG_CONFIG` and returns the result per collector. |
| `POST /api/syslog/drop-preview` | tenant member | Sums `SYSLOG_DROP_PREVIEW` over the tenant's collectors. |
| `PUT /api/syslog/archive` | tenant admin | Connect or update an external archive (409 if LM-installed). |
| `DELETE /api/syslog/archive` | tenant admin | Disconnect the external archive (409 if LM-installed). |
| `GET /api/syslog/diagnostics?collector=<name>` | tenant admin, Global Admin | Relays `SYSLOG_DIAG` (60 s timeout). |

## Settings delivery

Settings and the archive live in the hub's encrypted state
(`system_state["syslog"][<tenant>]`). They reach collectors three ways:

1. after a save (`SYSLOG_CONFIG`),
2. in the `LOAD_ROLE syslog` config right after a collector deploys, and
3. on every reconnect (`UPDATE_CONFIG {"tenant", "archive", "drop_rules", "retention_hours", "max_mb"}`), so a restarted collector gets its settings back.

The archive password is resolved only while a push is built and is never
logged or cached.

## Troubleshooting

Everything is reachable from the hub:

- **Syslog → Diagnostics** (`SYSLOG_DIAG`): rsyslog state, `rsyslogd -N1`
  check, the last journal lines, listeners on 514/6514, the rendered
  `/etc/lm-syslog/drop.rsyslog` and `/etc/lm-syslog/archive.rsyslog`, store
  usage, forward-queue size, an archive probe (TCP, TLS, API), the installer
  log and recent errors. No secrets are included.
- **Logs view**: the spoke logs every command, config write, rsyslog restart
  and retention action under logger names starting with `Syslog`. The hub
  logs every role hook (archive saved/removed), every push and every query
  error with the collector name (`syslog: …`).
- **Installer logs**: `/var/log/lm/syslog-collector-install.log` and
  `/var/log/lm/syslog-graylog-install.log`, ending with `OK` or
  `FAILED: <step>`; they appear in the Diagnostics tab.
- The Graylog host has no spoke. Its health comes from the collectors'
  archive probe and from the agent's deploy-role state in the overview.

## Code

- Hub: `core/src/syslog_archive.py` (settings, archive record, role hooks,
  pushes), `core/src/syslog_cache.py` (overview cache), `core/src/routes/syslog.py`,
  hooks in `core/src/routes/agents.py`, the `logging` branch of
  `push_config_to_spoke` in `core/src/main.py`, `hub_secret_store.py`
  (generated passwords).
- Agent: `syslog-collector` / `syslog-graylog` in `agent/src/agent_spoke.py`
  (`_DEPLOY_ROLES`, units, purge, `_syslog_install_args`).
- Spoke: the `syslog` repo (`SyslogSpoke`).
