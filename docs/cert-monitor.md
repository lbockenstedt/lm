---
summary: "Cert Expiry Monitor: Global-Admin-only, opt-in daily TLS certificate expiry check of public Aruba Central / HPE GreenLake and Juniper Mist cloud endpoints, stored as JSON on the hub."
keywords: [cert-monitor, certmon, certificate, expiry, tls, aruba-central, greenlake, mist]
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

## Schedule & storage

- A scheduler started with the hub checks every 15 minutes whether a run is due.
  A run happens at most **once per 24h**, and only while the feature is enabled.
  **Check now** forces an immediate run.
- Results are written atomically to `$LM_STATE_DIR/cert_monitor.json`
  (default `/var/lib/lm/state/cert_monitor.json`). The file holds `last_run`,
  `duration_s`, `counts` and a sorted `results` array.
- Config is stored in `global_config.cert_monitor`:
  `{enabled, custom_hosts, disabled_builtin}`.

## API (Global Admin only — 403 otherwise)

| Method | Path | Purpose |
| :-- | :-- | :-- |
| GET | `/api/certmon/status` | `{enabled, running}` (drives the left-nav item) |
| GET | `/api/certmon/overview` | config, built-in host list, counts, sorted results |
| PUT | `/api/certmon/config` | `{enabled?, custom_hosts?, disabled_builtin?}` |
| POST | `/api/certmon/run` | start a check now (409 when disabled) |

Code: `core/src/cert_monitor.py` (probe, classify, store) and
`core/src/routes/cert_monitor.py` (routes and scheduler).
