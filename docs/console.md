# Console — serial console access (`console`)

An **in-repo** agent role (`lm/console/`, `_ROLE_MAP` `repo_url=None`, staged from the
`/opt/lm` clone like dns/dhcp) that turns any agent host with serial adapters into a
network-reachable serial console server — ConsolePi-inspired, natively integrated. See
`docs/console-role-design.md` for the full design + locked decisions.

## What it does
- Enumerates serial ports (USB adapters via pyserial + on-board UARTs `ttyAMA*`/`ttyS*`),
  each with a stable **software** `port_id` (USB serial#/`ID_PATH`; UART by device path — no udev).
- **Baud auto-detect** — sweeps candidate rates, scores by printable-ASCII + prompt hints.
- **Interactive terminal** in the hub WebUI (xterm.js) over the hub↔spoke WS, reusing the
  VNC-relay pattern. **One writer per port**, extra viewers are read-only observers.
- **Auto-identify (fingerprint)** — fully automatic on a newly-seen port (read-only): banner
  scrape → vendor-profile match (Cisco IOS/NX-OS, Aruba AOS-CX, HP ProCurve, generic Linux) →
  credential login (global encrypted list, tried once each) → run the profile's read-only
  identity commands → parse serial/MAC/mgmt-IP/model/hostname → **NetBox match + create**.
- **Two-level tenant binding** — the whole console agent (spoke Tenant action) or an individual
  port (`CONSOLE_SET_TENANT` override). Effective tenant = per-port override, else the agent's.
- Gated by the **`console`** permission right (User Management column + `/api/console/*` gate).

## Command envelope (spoke)
`CONSOLE_LIST_PORTS` · `CONSOLE_GET_SETTINGS` · `CONSOLE_SET_SETTINGS` · `CONSOLE_SET_ALIAS` ·
`CONSOLE_SET_TENANT` · `CONSOLE_DETECT_BAUD` · `CONSOLE_OPEN` · `CONSOLE_DATA` (down, fire-and-forget) ·
`CONSOLE_DATA_UP`/`CONSOLE_READY`/`CONSOLE_ERROR`/`CONSOLE_CLOSED` (up) · `CONSOLE_SEND_BREAK` ·
`CONSOLE_RESIZE` · `CONSOLE_CLOSE` · `CONSOLE_SET_CREDENTIALS` (hub→spoke, signed) ·
`CONSOLE_AUTOPROBE` + `CONSOLE_PROBE_RESULT` (up) · `CONSOLE_GET_CONFIG` · `CONSOLE_PUSH_CONFIG`.

## Hub surface
- Registry: `console_sessions` (+ register/get/unregister; a `connected` flag exempts live
  sessions from the 60s pre-connect TTL). Inbound dispatch routes `CONSOLE_DATA_UP`/control
  frames to the session queue; `CONSOLE_PROBE_RESULT` → `_handle_console_probe` (NetBox upsert).
- REST (`core/src/api.py`, `console` right or admin): `GET /api/console/ports` (tenant-scoped,
  effective/override/agent tenant per port), `POST /api/console/{open,settings,detect-baud,identify}`,
  `POST /api/console/tenant` (admin, per-port), `GET|POST /api/console/credentials` (admin;
  Fernet-encrypted; passwords never returned). Browser relay: `@app.websocket /ws/console-serial/{session_id}`
  (ws_token-gated; ready→continue / error→1011 / disconnect→1000; `CONSOLE_CLOSE` on exit).

## Files
- `console/src/serial_manager.py` — enumeration, stable id, `PortStore`, baud detect, `PortChannel`/`SessionManager`.
- `console/src/console_spoke.py` — `ConsoleSpoke(BaseSpoke)` command dispatch + auto-probe loop.
- `console/src/fingerprint.py` — vendor profiles + `detect_vendor`/`parse_identity`/`run_identify`.
- WebUI Console view + xterm terminal + credential library (`WebUI/main.js`).

## Security / safety
- Auto-identify sends **only** a matched profile's read-only commands; credential list tried once
  per device then 1h cooldown (no lockout hammering); skips ports a human holds (writer lock).
- Credentials Fernet-encrypted in hub state, pushed signed; never logged/displayed.
- Serial byte relay gated by a one-shot `ws_token`; tenant isolation enforced on list + open.
- The agent runs as root (serial access); config-**write** (Phase G) is a deliberate, separate,
  higher-privileged path — NOT bound by the read-only auto-probe.

## Gotchas / notes
- xterm.js is dynamic-imported from CDN (like noVNC); vendoring under `WebUI/assets/` is a follow-up.
- NetBox auto-create currently maps ip/mac/hostname (the `sync_devices` shape); serial→`device.serial`
  and full match-by-serial need a NetBox-side field mapping — flagged for real-device verification.
- Disable auto-identify per agent with role config `auto_identify=false`.

## Config read / push (write access)
A deliberate, admin/`console_write`-gated write path, separate from the read-only auto-probe:
- `CONSOLE_GET_CONFIG` reads/backs up the running-config (`POST /api/console/config/get`).
- `CONSOLE_PUSH_CONFIG` (`POST /api/console/config/push`) is **transactional, no post-request approval**:
  login → backup → enter config mode → send lines (per-line error watch) → exit → **post-verify** the
  pushed lines are in running-config → on PASS save (unless `save=false`); on FAIL **never save** and roll
  back (default `no <command>` negation, or `reboot` to revert the unsaved running-config).
- Gated by the **`console_write`** right (User-Management CW column; `/api/console/config/*` middleware).
  Requires the device to have been Identified (the vendor profile carries the config verbs); respects the
  one-writer lock. Config sources: paste/upload (v1); template/NetBox/API share the same push path (follow-up).
- **Defaults chosen** (changeable): verify = pushed-lines-present recheck; rollback = negate (reboot optional);
  backup = display/download (versioned lm archive is a follow-up). Reboot-rollback + on-device verify are
  heuristic — verify on real hardware before relying on them.
