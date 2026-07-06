# Console — serial console access (`console`)

An **in-repo** agent role (`lm/console/`, `_ROLE_MAP` `repo_url=None`, staged from the
`/opt/lm` clone like dns/dhcp) that turns any agent host with serial adapters into a
network-reachable serial console server — ConsolePi-inspired, natively integrated. See
`docs/console-role-design.md` for the full design + locked decisions.

## What it does
Console turns any agent host with serial adapters or on-board UARTs plugged into it
into a network-reachable serial console server, so admins never need physical/USB
access to a switch, router, or appliance's console port. Load the `console` role on an
agent from **Setup → Agents**, then open an interactive terminal to any of that host's
serial ports from the hub WebUI's **Console** view (an xterm.js terminal in the browser)
— no SSH/telnet client, VPN, or physical presence at the rack required.

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

## How it works

- **Port discovery.** `enumerate_ports()` (`console/src/serial_manager.py`) lists USB
  serial adapters via pyserial's `list_ports.comports()` plus real on-board UARTs
  (`/dev/ttyAMA*`, `/dev/ttyS*`, `/dev/ttyO*` — filtered to ones with an actual
  `/sys/class/tty/<dev>/device`, so phantom `ttyS*` stubs don't clutter the list). Each
  port gets a stable software `port_id` derived from its USB serial number / `by-id`
  symlink (or vid:pid+location, or the raw device path for a UART) — this id survives
  unplug/replug and reboot without needing udev rules. Per-port settings (baud, bytesize,
  parity, stopbits, flow, alias, tenant override, last probe result) persist to
  `/var/lib/lm/console/ports.json` (falling back to a repo-local state dir if that path
  isn't writable).
- **Baud auto-detect.** `CONSOLE_DETECT_BAUD` (or the automatic identify pipeline) opens
  the port at each candidate rate in turn (`9600, 115200, 38400, 19200, 57600, 4800,
  2400, 230400`), sends a CR/LF, and scores the reply by printable-ASCII ratio plus a
  bonus if it matches a known login/prompt/banner regex (`login:`, `Username:`,
  `Cisco`, `Aruba`, a shell prompt, etc.). The best-scoring rate is locked in and saved
  to the port's settings; a confidently-good match (score ≥ 1.3) stops the sweep early.
- **One-writer session relay.** Opening a terminal (`CONSOLE_OPEN`) attaches a browser
  session to a `PortChannel` — one real OS serial handle per physical port, shared by
  every attached session. A background reader thread reads the handle once and fans the
  bytes out to all attached sessions, so several admins can watch the same console
  simultaneously; only the first session that asked for read-write (`mode=rw`) holds the
  writer lock and can actually send keystrokes (`CONSOLE_DATA`, fire-and-forget), everyone
  else is a read-only observer. This rides the same hub↔spoke WebSocket relay pattern
  used for VM VNC consoles: the browser opens `/ws/console-serial/{session_id}` (gated by
  a one-shot `ws_token`), and device output is pushed up unsolicited as `CONSOLE_DATA_UP`.
- **Auto-identify (fingerprint).** On every newly-seen port, a background loop
  (`_autoprobe_loop` in `console/src/console_spoke.py`, every ~2 minutes, unless
  `auto_identify=false`) automatically — and read-only — wakes the line, captures the
  banner, matches it against a built-in vendor profile (Cisco IOS, Aruba AOS-CX, HP
  ProCurve, generic Linux — `console/src/fingerprint.py::PROFILES`), tries the
  hub-managed encrypted credential list once each at a login prompt (never re-hammering),
  and if it gets in, runs that profile's read-only identity commands (`show version`,
  `show system`, etc.) and regex-parses serial number, MAC, management IP, model, and
  hostname. The result is pushed to the hub as `CONSOLE_PROBE_RESULT`, which upserts a
  NetBox device (match by serial/MAC/hostname, or create). A port is skipped by
  auto-probe while a human holds the writer lock, and a failed probe backs off for an
  hour before retrying — no credential lockout hammering.
- **Two-level tenant binding.** The whole console agent can be bound to a tenant like any
  spoke; additionally, an individual port can carry its own tenant override
  (`CONSOLE_SET_TENANT`) so one console host can serve ports to different tenants. The
  effective tenant for a port is the per-port override if set, else the agent's tenant;
  `/api/console/ports` reports all three (effective/override/agent) and hides ports a
  non-admin can't access.
- **Permissions.** Everything under `/api/console/*` (list/open/settings/detect-baud/
  identify) is gated by the `console` right; the separate config read/push endpoints
  additionally require `console_write` — a higher tier, since those can change a live
  device's configuration.

## How to use it

1. **Open a console session.** Load the `console` role on an agent (Setup → Agents →
   Load Role → `console`), then go to the **Console** view in the WebUI, pick the agent,
   and click a port to open a terminal. If you're the first to open it you get read-write;
   if someone else already has it open, you get a read-only view of their session.
2. **Set baud / auto-detect.** From the port's settings panel, either pick a known baud
   rate manually or click **Detect Baud** to let the agent sweep candidate rates and lock
   the best match — useful the first time you plug in an unfamiliar device. Detected/
   manually-set baud persists across sessions and reboots.
3. **Alias a port.** Give a port a friendly name (`CONSOLE_SET_ALIAS`) so it's recognizable
   in the port list instead of a raw device path or USB id — handy on a host with many
   adapters plugged in.
4. **Identify a device.** If auto-identify hasn't already run (or is disabled), trigger a
   manual identify (`CONSOLE_AUTOPROBE`) from the UI — this requires the port not be in
   use. A successful identify populates vendor/model/serial/MAC/IP and unlocks the config
   read/push actions (which need a known vendor profile).
5. **Bind a port or the whole agent to a tenant.** Use the agent's Tenant action to bind
   every port on that host, or set a per-port override for ports that belong to a
   different tenant than the host itself.
6. **Push config (write access).** Requires `console_write` and a device that's already
   been Identified. Paste or upload the config, submit — the push is transactional: it
   backs up the current config, applies your lines, verifies they landed, and either saves
   (on pass) or rolls back automatically (on fail). There is no separate "approve" step
   once you submit a push.

## Troubleshooting / common questions

- **A port isn't listed.** Confirm the `console` role is actually loaded on that agent
  (Setup → Agents) and that the adapter shows up to the OS (`ls /dev/ttyUSB*
  /dev/ttyACM*` on the host). On-board UARTs only appear if the kernel exposes a real
  `/sys/class/tty/<dev>/device` for them — a `ttyS*` node with no backing hardware is
  filtered out on purpose, not a bug.
- **Output is garbled or the terminal shows line noise.** Wrong baud rate. Run **Detect
  Baud** rather than guessing — it sweeps the common console rates and scores the reply
  for printable text and known prompt patterns.
- **The session opened but I can't type ("read-only").** Someone else already holds the
  writer lock on that port (one-writer-per-port by design). Ask them to close their
  session, or open your own to a different port if this is meant to be independent
  access. There's no "steal the lock" action — this is intentional to avoid two admins
  fighting over the same keystrokes.
- **The Console nav item / Open button is missing.** The `console` permission right
  isn't granted to your user — check the Console column in User Management. `console`
  gates viewing/opening sessions; `console_write` (a separate, higher tier) gates config
  push and is usually granted to fewer users.
- **A device is never auto-identified.** Either `auto_identify=false` is set in that
  agent's role config (check with the admin who loaded the role), the device's banner
  doesn't match any built-in vendor profile (only Cisco IOS/NX-OS, Aruba AOS-CX, HP
  ProCurve, and generic Linux are recognized today), or none of the configured
  credentials logged in (the probe stops after trying each once — it deliberately does
  not retry/hammer). A manual Identify surfaces the raw banner even if the profile match
  or login failed, which helps diagnose which step is failing.
- **Agent shows offline.** That's the underlying generic-agent host, not the console role
  specifically — see [generic-agent.md](generic-agent.md) troubleshooting for the base
  agent connection.
