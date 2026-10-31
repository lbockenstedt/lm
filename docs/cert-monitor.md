---
summary: "Cert Expiry Monitor: Global-Admin-only, opt-in daily TLS certificate expiry check of public Aruba Central / HPE GreenLake and Juniper Mist cloud endpoints, stored as JSON on the hub, with email alert rules (breach, scheduled reminders with an escalation ladder, recovery)."
keywords: [cert-monitor, certmon, certificate, expiry, tls, aruba-central, greenlake, mist, alerts, notifications]
---

# Cert Expiry Monitor

Tracks when the TLS certificates on the public **Aruba Central / HPE GreenLake**
and **Juniper Mist** cloud endpoints expire, plus any custom hosts you add.

## Enabling

- **System → General → Cert Expiry Monitor → Enable** (Global Admin only).
- Once enabled, a **Cert Monitor** item appears in the left menu. It is shown only
  to Global Admins and only while the feature is enabled. Disabling it hides the
  menu item and stops the daily check.
- Enabling it starts the first check right away if none has run in the last 24h.

## What it checks

- About 160 built-in hosts (`cert_monitor.BUILTIN_HOSTS`):
  - **Mist:** `manage`, `api`, `api-ws`, `portal`, `ep-terminator`,
    `jma-terminator` and `ztp` for every cloud (Global 01–08, EMEA 01–03,
    APAC 01), plus `ep-terminator.mistsys.net`, `jma-terminator.mistsys.net`,
    `redirect.mist.com` and `www.mist.com`.
  - **Aruba Central:**
    - Classic Central: the UI portal, the API gateway and the device-connectivity
      hosts for each cluster (US-1/2, US-East-1, US-West-4/5, EU-1/2/3, Canada-1,
      APAC-1/East-1/South-1, UAE-North-1, China-1).
    - New Central API gateways (`<region>.api.central.arubanetworks.com`).
    - GreenLake: `common.cloud.hpe.com`, `sso.common.cloud.hpe.com`,
      `global.api.greenlake.hpe.com`, `auth.hpe.com`.
    - `activate.arubanetworks.com` and `device.arubanetworks.com`.
- **Custom hosts:** add them in the Cert Monitor view, one per line, as `host`,
  `host:port` or a pasted URL.

Each host gets a TLS handshake with SNI on its port. The leaf certificate is
recorded **even when chain verification fails**. Mist terminators and Aruba
device endpoints present private device-CA certificates; they are shown as
"private CA / untrusted" and their expiry is still tracked.

For each host it captures:
- subject CN and SANs
- issuer organisation (the **provider**) and issuer CN
- cert type (DV / OV / EV and wildcard, from the CA/B policy OIDs)
- key type and size, and the signature algorithm
- serial number and the validity dates
- days left

## Colours / ordering

| Status | Rule |
| :-- | :-- |
| 🔴 red | under 30 days left (or already expired), sorted to the top |
| 🟡 yellow | under 90 days left |
| 🟢 green | 90 days or more |
| grey | DNS failure, timeout or handshake error |

Rows are sorted red → yellow → error → green, then by days left. Days left are
recalculated from `not_after` every time the view loads, so the colours stay
correct between the daily checks.

## Ignoring a cert

Each row has an **Ignore** button (**Un-ignore** once ignored). Use it for an
endpoint whose status you have accepted, for example a known-expired or
private-CA host you can't fix.

An ignored cert:
- stays in the list, muted, with its real status still shown and tagged
  "(ignored)" (hover it for who ignored it and when);
- is sorted after the active rows;
- is left out of the red / yellow / green / error totals (the header shows the
  ignored count separately);
- never breaches an alert rule. If it was already breached, it drops out of the
  rule's state silently (no "recovered" email). Un-ignoring a cert that is still
  bad makes it breach again on the next evaluation.

Ignores are keyed by **`host:port`**, the same identity the monitor and the
alert state use, so an ignore survives cert renewals and hub restarts. They are
stored in `global_config.cert_monitor_ignored` as
`{"host:port": {"by": <username>, "at": <ISO timestamp>}}`.

## Schedule & storage

- A scheduler started with the hub checks every 15 minutes whether a run is due.
  A run happens **once per 24h**, and only while the feature is enabled.
  While any non-ignored cert expires within 24 hours (or has already expired) the
  run happens **every hour** instead, so a renewal is picked up — and its reminder
  emails stop — within the hour. Ignore a dead cert to drop back to daily.
  **Check now** forces an immediate run.
- Results are written atomically to `$LM_STATE_DIR/cert_monitor.json`
  (default `/var/lib/lm/state/cert_monitor.json`). The file holds `last_run`,
  `duration_s`, `counts` and a sorted `results` array.
- Config is stored in `global_config.cert_monitor`:
  `{enabled, custom_hosts, disabled_builtin}`.

## Built-in host list auto-update

Before the daily check, the built-in Mist / Central list is refreshed (at most once
per 24h) from the vendors' published endpoint pages:

| Source | Page | Replaces built-in |
|---|---|---|
| `mist` | Juniper Mist "Firewall ports to open" | all Juniper Mist hosts (ports taken from "host (TCP n)"; `oc-term` TCP 2200 skipped — SSH, not TLS) |
| `central-apigw` | Aruba developer "API OAuth access token" | Aruba Central API gateways |
| `new-central` | Aruba developer "Getting started with REST APIs" | New Central API gateways |

- New endpoints are added and retired ones dropped. Hosts not covered by a source
  (Central portals / device endpoints, GreenLake) stay on the static list.
- A page that can't be fetched, or that yields fewer than half the hosts it had
  (page moved / redesigned), is **not** used: the previous list is kept and the error
  is shown on the Cert Monitor page under **Built-in host list**.
- State lives in `$LM_STATE_DIR/cert_monitor_sources.json`
  (`{source: {hosts, updated_at, checked_at, error, added, removed, changed_at}}`).
  Delete the file to fall back to the static list. `GET /api/certmon/overview`
  returns it as `host_sources`.
- Disabled built-ins (by host) and ignored certs (by `host:port`) survive a refresh.

## Alert rules

Cert alert rules live in the single **Alert Rules** tile of the **Reports**
view, alongside the realtime alert rules. Click **+ Add alert** and choose a
source from the **Cert Expiry Monitor** group. These sources (and the cert rules
in the list) appear only to a Global Admin while the monitor is enabled. Cert
rules are hub-wide, not per-tenant. Each rule has:

- a trigger (see the table below)
- an optional list of services to watch (no services ticked = all)
- recipients
- a format: **human** (a formatted email with a host table) or **raw** (a JSON
  body for automation)
- an on/off switch
- **Repeat every N hours while still bad** (`repeat_hours`, 0 = no reminders)
- for `expiring` rules, an **escalation** ladder (`reminders`) of
  `{days, every_hours}` steps: once fewer than `days` days are left
  (0 = expired), remind every `every_hours` hours (0 = one email on entering the
  step). The most urgent matching step wins; above every step the rule's repeat
  applies. New rules start with the example "fewer than 7 days: every 24 h;
  expired: every 6 h".

| Trigger | A host breaches when |
| :-- | :-- |
| `expiring` | days left < the rule's `threshold_days` (default 30; expired certs always match) |
| `error` | the check failed (DNS failure, timeout or handshake error) |
| `untrusted` | the cert did not validate against the system trust store (expected for private device-CA endpoints) |

How emails go out:
- One email goes out when hosts newly breach a rule, and one when they recover.
- A host that stays bad gets a reminder when its repeat interval has passed
  since its last email, or right away when it moves into a more urgent
  escalation step. With no repeat and no steps it stays silent.
- Each email is a digest: it lists every host that breached, is due a reminder
  ("still bad") or recovered in that evaluation, so a shared wildcard cert on
  many endpoints sends one email, not dozens.
- If a host can't be reached, an `expiring` rule keeps its last verdict instead
  of reporting it as recovered.

Rules are evaluated after every check and on every 15-minute scheduler tick,
using days left recalculated from `not_after`. That way a threshold crossed
between daily checks still fires. Evaluation only runs while the feature is
enabled.

The breach state and the time of each host's last email are saved in
`$LM_STATE_DIR/cert_monitor_alert_state.json`, so a hub restart does not repeat
alerts that were already sent or reset the reminder clock. A rule's state only moves forward after its
email is delivered, so a failed send is retried on the next tick. Changing a
rule's trigger resets that rule's state. Deleting a rule drops its state.

Emails go through the hub provider in **Setup → Notifications**. **Test** sends
the rule's current matches in the rule's format without changing any state.

Rules are stored in `global_config.cert_monitor_alerts.rules`. The code is in
`core/src/cert_monitor_alerts.py`.

## API (Global Admin only — 403 otherwise)

| Method | Path | Purpose |
| :-- | :-- | :-- |
| GET | `/api/certmon/status` | `{enabled, running}` (drives the left-nav item) |
| GET | `/api/certmon/overview` | config, built-in host list, counts (ignored certs excluded, plus an `ignored` total), sorted results (each with `ignored`, `ignored_by`, `ignored_at`), the `ignored` map |
| PUT | `/api/certmon/config` | `{enabled?, custom_hosts?, disabled_builtin?}` |
| POST | `/api/certmon/run` | start a check now (409 when disabled) |
| POST | `/api/certmon/ignore` | `{host, port?, ignored}` — ignore (`true`, default) or un-ignore (`false`) one cert; `host` may be `host:port`. 400 for a bad host, 404 when ignoring a host that isn't monitored |
| GET | `/api/certmon/alerts/rules` | rules plus the trigger and service lists |
| POST | `/api/certmon/alerts/rules` | create `{name, trigger, threshold_days, services, recipients, format, enabled, repeat_hours, reminders}` |
| PUT | `/api/certmon/alerts/rules/{id}` | update a rule |
| DELETE | `/api/certmon/alerts/rules/{id}` | delete a rule |
| POST | `/api/certmon/alerts/rules/{id}/test` | send a test email with the current matches |

Code: `core/src/cert_monitor.py` (probe, classify, store),
`core/src/cert_monitor_alerts.py` (alert rules) and
`core/src/routes/cert_monitor.py` (routes and scheduler).
