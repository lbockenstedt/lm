---
summary: "An in-repo agent role (lm/console/, ROLEMAP repourl=None, staged from the /opt/lm clone like dns/dhcp) that turns any agent host with serial adapters into a…"
keywords: [access, auto_identify, console, console_data_up, console_probe_result, console_set_tenant, console_write, consoleserver, download, lm, serial, terminal, tty, usb]
---

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
  scrape → vendor-profile match (Cisco IOS/NX-OS, Aruba AOS-CX, ArubaOS gateway/controller, HP ProCurve, Juniper, generic Linux) →
  credential login (global encrypted list, tried once each) → run the profile's read-only
  identity commands → parse serial/MAC/mgmt-IP/model/hostname → **NetBox match + create**.
- **VSF stack detection (HPE/Aruba)** — a stack is one logical switch spread over several
  chassis, each with its own serial line. The identify run adds `show vsf` + `show version`
  on the Aruba profiles and labels every port with its role (**conductor** / **standby** /
  **member**), the stack topology, member count and running image version. The hub then
  cross-references the member MACs to point a standby/member at the **conductor's** console
  port — even when the chassis hang off different console agents. See *VSF stacks* below.
- **Two-level tenant binding** — the whole console agent (spoke Tenant action) or an individual
  port (`CONSOLE_SET_TENANT` override). Effective tenant = per-port override, else the agent's.
- **Tenant picker scoping** — `?tenant=<id>` from the picker. `default` is the built-in
  **ADMIN** tenant, *not* an "All tenants" view: under it the list shows UNASSIGNED ports,
  ports explicitly bound to `default`, and shared infra (unmasked — the ADMIN tenant owns no
  NetBox prefixes, so masking there would fail closed), but **never another tenant's
  dedicated ports**. Selecting a real tenant shows that tenant's dedicated ports plus shared
  infra subnet-masked to it. Only a call with no `?tenant=` at all (programmatic, never the
  WebUI) is unscoped. Same rule `routes/nw.py` names *"ADMIN(default) must not accumulate
  across tenants"*; the shared predicates are `access.tenant_scope_ids` /
  `access.in_tenant_scope`.
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
- `console/src/fingerprint.py` — vendor profiles + `detect_vendor`/`parse_identity`/`run_identify`/`detect_stack`.
- `console/src/vsf_stack.py` — pure parsers for HPE/Aruba VSF `show vsf` / `show version`.
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

## Probe timing (patience)

Identify is **not** latency-sensitive: it runs on a background probe loop, holds the serial
handle exclusively for one port at a time, and `CONSOLE_AUTOPROBE` emits keepalive progress
frames so it isn't cut off at the hub's base timeout. The expensive failure is the opposite
one — being *impatient*. A loaded chassis that pauses a few seconds mid-reply gets written off
as unresponsive and the device is reported **unknown**, which costs an operator a manual login.

Every read window is therefore sized for a slow, busy switch on a noisy line. The one that
matters most is the **idle gap** (`_IDLE_SECS`): `_read_until` stops when the stream goes
quiet, and the serial handle is opened with a 0.3 s read timeout, so at the old 0.4 s a
*single* missed poll ended the read mid-reply. It is now several polls wide.

If a site has gear that is slower still, scale the whole schedule from one place with role
config **`console_probe_patience`** (a multiplier, default `1.0`, clamped to 0.01–10):

```
console_probe_patience = 2.0     # twice as patient with everything
```

It multiplies every read/settle window in `fingerprint.py` — banner, login nudges, credential
re-prompt, enable flow, per-command output and config reads — so their relative behaviour
(and the code paths they drive) stay identical. The console test suite sets it to `0.05` for
exactly this reason.

## Enable / privilege escalation

A prompt ending in **`>`** is *unprivileged* (user EXEC) on Cisco IOS, HPE/Aruba AOS-S and
most network CLIs. Almost all of the identity `show` commands are rejected there, so a device
we logged into perfectly well would still come back as **unknown**. After login — and before
any `show` runs — the probe therefore sends `enable` and answers whatever the device asks for
(the just-used credential's password first, then a bare Enter, since many devices have no
separate enable secret) until the prompt ends in `#`.

Rules worth knowing:
- **`$` and `%` prompts never receive `enable`.** Those are UNIX shells, where the word is
  meaningless and on some appliances is a real, state-changing command.
- At most two secrets are tried. A refusal is classified from the error text: *no `enable`
  command at all* (`>` **is** the top level — retrying is pointless) versus *rejected secret*.
- Many switches need **no secret at all** — HPE/Aruba AOS-S goes straight from `>` to `#` and
  answers with a multi-line *"Your previous successful login (as manager) was on …"* notice.
  That notice contains the word "login" and must not be answered as a login prompt. Devices
  also pause mid-reply, so the probe will re-read a couple of times before calling a line
  unresponsive rather than trusting the first idle gap.
- `enable`/`disable` are in `is_readonly_command`'s mutation list, so they are written straight
  to the line by the login code and can never be requested through the profile/LLM command path.
- If we escalated an **operator's already-open session** — one we did not authenticate and so
  will not log out of — the privilege level is put back with `disable` afterwards, so a
  read-only identify never leaves a shared console line sitting in enable mode.

The result shows up in the port's login telemetry as `diag.privilege` (`enable` / `user`),
`diag.enable` (`attempted`, `escalated`, `secrets_tried`, `reason`) and, when escalation
failed, a human-readable `diag.enable_reason`.

New prompt spellings are operator-editable in `console/src/prompt_patterns.json` under the
`unpriv_prompt`, `priv_prompt`, `enable_unsupported` and `enable_denied` families — no code
change needed.

## VSF stacks (HPE/Aruba)

A VSF stack presents **one** logical switch across several physical chassis, but the console
module sees each chassis as its own serial port. The member that matters is the **conductor**
(older AOS-S firmware calls it the **commander**) — it is the only one that accepts
configuration. Every other member rejects almost everything.

**The problem this solves.** A stack's standby member has no hostname of its own, prints no
vendor banner, and answers `show system` with `Invalid input`. Its CLI prompt is literally the
bare word `standby`:

```
6300 login: admin
Password:
standby# show system
Invalid input: sys
```

Left alone, that port stays an unidentified box forever, and there is nothing on screen telling
an operator which of their cables actually reaches the conductor.

**How detection works.**

1. `console/src/vsf_stack.py` `at_standby_console()` spots the `standby#` prompt (also
   `<host>-standby login:` and the standby banner). Only the tail of the capture is examined,
   so a `show vsf` table scrolled past earlier — which legitimately contains the word
   "Standby" — can't trigger it.
2. A port sitting at that prompt adopts the **aruba-cx** profile even though `detect_vendor`
   found no banner, which is what allows `show vsf` to run at all. (The read-only safety
   contract is unchanged: still only a matched profile's `show` commands are ever sent.)
3. `parse_show_vsf()` reads the member table. It handles the AOS-CX wrapped header, the
   **reduced** table a standby prints (no header block, but an authoritative `This Mbr ID`),
   the newer firmware's separate `Role` column and `Not Present` slots, and the AOS-S layout
   with `xxxxxx-xxxxxx` MACs and a `*` marking the local member.
4. `parse_show_version()` records the running image — only the line labelled exactly
   `Version`, never `Service OS Version` or `BIOS Version`. A mismatched image is the usual
   reason a chassis refuses to join a stack.
5. The spoke stores the result under `probe.stack` (absent entirely for a standalone switch,
   which still reports itself as "Conductor" of a 1-member VSF).
6. The hub's `_correlate_stacks()` joins `stack.conductor_mac` against every visible port's
   learned MAC and fills in `conductor_port_id` / `conductor_spoke_id` / `conductor_hostname`,
   plus a `stack_id` for grouping. This runs on the hub because a stack's chassis are often
   cabled to **different** console agents, and only the hub sees them all.

**`probe.stack` shape**

| field | meaning |
| --- | --- |
| `is_stack` | true only for a real stack (2+ present members, or a Ring/Chain/Mesh topology) |
| `role` | `conductor` \| `standby` \| `member` — of the chassis this cable reaches |
| `member_id` | its member number in the stack |
| `topology` | `Ring` / `Chain` / `Standalone` |
| `stack_mac`, `local_mac` | the stack's MAC and this chassis' own member MAC |
| `conductor_mac` | the cross-reference key used to find the conductor's port |
| `sw_version` | running image, e.g. `FL.10.13.1000` |
| `members[]` | `member_id`, `mac`, `model`, `role`, `present` |
| `is_conductor`, `stack_id`, `conductor_port_id`, `conductor_spoke_id`, `conductor_hostname` | added hub-side by `_correlate_stacks` |

**In the UI.** The port row gets a role badge (⬢ conductor / ⬢ standby / ⬢ member with the
member number) plus a detail line showing member count, topology, image version and a link to
the conductor's own console port. If no visible port has identified the conductor yet, it says
so rather than pointing nowhere — a conductor outside the caller's tenant scope is never
revealed.

**Notes.**
- A standby's own member MAC becomes the port's identity MAC. It has no hostname and no
  `show system`, so that is the only stable key for reattaching the port when `/dev/ttyUSBn`
  renumbers.
- `show vsf` is on the **aruba-cx** and **hp-procurve** profiles only; a Cisco/Juniper port is
  never asked about VSF. A non-stacking ProCurve just answers `Invalid input: vsf`, which parses
  to "not a stack".

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

## Direct Port Access (DPA) — enabling it
DPA exposes each serial port over a per-port **telnet** listener (auto-assigned from
`console_dpa_base`=2200) so you can attach a terminal straight to the line (à la ser2net).
The endpoint then shows as a `🔌 telnet <bind>:<port>` badge in the **Console** port list
and in the `CONSOLE_LIST_PORTS` `dpa` field.

**It is OFF by default** — telnet is unauthenticated/unencrypted, so the localhost bind
(or an explicit source-IP allow-list when widened) is the guard. If you don't see a DPA
badge on the Console page, DPA simply isn't enabled yet.

Enable it when loading the console role: **Setup → Spokes & Agents → Load Role**, tick
**console**, then **Enable Direct Port Access**. Keep the bind at `127.0.0.1` (reach it by
SSH-tunnelling to the console host) unless you deliberately widen it, in which case set a
comma-separated **source-IP allow-list**. This maps to the role config keys
`console_dpa_enabled` / `console_dpa_bind` / `console_dpa_allow` (`console/src/console_spoke.py::_ensure_dpa_task`).

- **The console role must not already be loaded** to pass this config — the Load Role modal
  only lists roles that aren't loaded. To turn DPA on/off for an already-loaded console role,
  **Unload** it first, then Load it again with the box ticked (or not).
- **Applies at load only.** Like all interactive role config (netbox/ldap admin creds too),
  it is not re-applied when the agent reboots or the hub re-adopts the role config-less, so
  DPA reverts to off after an agent restart. *Follow-ups:* persist the role config for
  re-push on reconnect, and a live on/off toggle on the Console page (`CONSOLE_SET_DPA`).

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
  isn't writable). Set **`LM_CONSOLE_STATE_DIR`** to override that directory.
- **Restart-durable local state.** Everything the console page shows for a port is kept on
  disk in the state dir, so restarting the service (or the whole host) never blanks the
  page:

  | File | Holds |
  | :--- | :--- |
  | `ports.json` | settings, alias, tenant override, and the identify **profile** (vendor, family, identity fields, banner) |
  | `telemetry.json` | per-port `last_activity` + cumulative `capture_bytes` |
  | `health.json` | serial-health / diagnostics history — open failures, disconnects, recoveries, identify-attempt stats, hostname history, boot state |
  | `capture/<port>.log` | the durable circular recording (5 MiB per device by default) |

  All four are loaded back into memory on startup and written atomically (tmp + rename).
  The telemetry and health writes are debounced (10 s / 15 s) because the serial reader
  thread touches them constantly; the first write of a process and rare state transitions
  (a new port, a disconnect, a recovery) are flushed immediately. Hub-side, the last
  `CONSOLE_LIST_PORTS` result per spoke is additionally kept in the hub's warm cache
  (`warm_cache.json`), so a hub restart — or a console host that is down — still renders
  the fleet, marked `stale`.
- **Baud auto-detect.** `CONSOLE_DETECT_BAUD` (or the automatic identify pipeline) opens
  the port at each candidate rate in turn (`115200, 9600, 38400, 19200, 57600, 4800,
  2400, 230400`), sends a CR/LF, and scores the reply by printable-ASCII ratio plus a
  bonus if it matches a known login/prompt/banner regex (`login:`, `Username:`,
  `Cisco`, `Aruba`, a shell prompt, etc.). **115200 and 9600 lead the sweep** — between
  them they cover almost all console gear — and the moment either answers with a
  confident (mostly-printable) reply the sweep locks it and stops, without drifting onto
  an exotic rate that happened to score marginally higher. Only if both stay silent/garbled
  does it fall through to the less-common rates. The chosen rate is saved to the port's
  settings; a confidently-good match (score ≥ 1.3) also stops the sweep early.
- **115200 is the standing default.** A port nobody has configured opens at **115200**,
  and a sweep that never gets a readable reply reports 115200 rather than whichever rate
  happened to rattle loudest — so a port can never quietly settle on 9600. Only a
  *confident* sweep is allowed to change a port's stored rate; an inconclusive one is
  reported but never persisted. On an exact score tie a priority rate (115200, then 9600)
  always beats an exotic one.
- **Operator pin.** Setting the baud by hand (`CONSOLE_SET_SETTINGS`) **pins** it: neither
  auto-detect nor the boot-time re-lock will overwrite an operator's choice, so a manually
  set 115200 stays put. Setting it by hand again simply re-pins the new value. Conversely,
  an *automatic* lock is never permanent: if a port that auto-locked onto a rate later
  reads as garbage, the boot watcher re-sweeps it (rate-limited), starting again at 115200.
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
  (`_autoprobe_loop` in `console/src/console_spoke.py`, polling every ~30s — a newly
  connected console cable is auto-profiled almost immediately — unless
  `auto_identify=false`) automatically — and read-only — wakes the line, captures the
  banner, matches it against a built-in vendor profile (Cisco IOS, Aruba AOS-CX,
  ArubaOS gateway/controller — recognised by its `(hostname) #` prompt — HP
  ProCurve, Juniper, generic Linux — `console/src/fingerprint.py::PROFILES`), tries the
  hub-managed encrypted credential list **followed by a short set of well-known
  factory-default credentials** (`FACTORY_DEFAULT_CREDENTIALS`, gated by role config
  `console_factory_default_creds`, default on) once each at a login prompt — never
  re-hammering, but each credential is guaranteed to actually be presented even if the
  device is slow to redraw or rate-limits after a failed attempt. On a **net-new device
  that forces a password set/change** after a first login (`Enter new password:`,
  `You must change your password`), the probe **declines by sending bare Enters to skip
  it** — identify is read-only and never sets a password — so the device still drops to a
  shell and can be profiled.
  If it gets in, it runs that profile's read-only identity commands (`show version`,
  `show inventory`, `show system`, etc.) and regex-parses serial number, MAC, management
  IP, model, and hostname — the model + serial are bubbled up in the UI (port identity
  line + device card) so the box can be found in NetBox and physically in the rack.
  **When the identify used one of our credentials to log in, it then cleanly
  logs out** (sends `exit`/`logout` and confirms a login prompt returns — `diag.logged_out`),
  so profiling never leaves a privileged shell open on the shared line; an already-open
  console we only read from is left untouched. The result is pushed to the hub as
  `CONSOLE_PROBE_RESULT`, which upserts a NetBox device (match by serial/MAC/hostname, or
  create). A port is skipped by auto-probe while a human holds the writer lock, and a
  failed probe backs off (escalating) before retrying — no credential lockout hammering.
  The retry policy is operator-tunable via role config: `console_identify_retry_secs`
  (floor backoff, default 300), `console_identify_retry_max_secs` (cap, default 3600),
  `console_identify_reverify_secs` (re-verify interval after success, default 1800),
  `console_identify_max_attempts` (give up after N consecutive failures, `0`=never, the
  default), and `console_autoprobe_interval` (poll/first-seen cadence, default 30s).
  Unplugging a cable clears that port's retry state so re-plugging starts fresh.
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
   manually-set baud persists across sessions and reboots, and a rate you set by hand is
   **pinned** so auto-detection can never roll it back. Unconfigured ports default to 115200.
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
  doesn't match any built-in vendor profile (only Cisco IOS/NX-OS, Aruba AOS-CX,
  ArubaOS gateway/controller, HP ProCurve, Juniper, and generic Linux are recognized
  today), or none of the configured
  credentials logged in (the probe stops after trying each once — it deliberately does
  not retry/hammer). A manual Identify surfaces the raw banner even if the profile match
  or login failed, which helps diagnose which step is failing.
- **It says it can't log in, but no login is ever attempted on the line.** Check the
  port's diagnostics `reason`. Two causes look identical from the UI:
  - *"output seen but no recognizable login/password prompt"* — the device printed
    something after its prompt so the prompt was no longer the last thing on the wire.
    Gear that logs to its own console does this constantly (Juniper SRX/EX ship with
    console logging on). The probe now strips trailing syslog/kernel/facility lines
    before matching, so this should resolve itself; if a device uses a prompt string
    we don't know, add it to `console/src/prompt_patterns.json` — no code change needed.
  - *"login prompt seen but no stored credentials to try"* — the hub pushed an empty
    credential list. A Credential Vault secret only reaches a console agent when it is
    (a) typed `console` **or** `login`, (b) stored **automation-readable** (hub mode —
    a pass-phrase-only secret is deliberately skipped, since the hub can't decrypt it
    unattended), and (c) in the agent's **own tenant bucket or the `__admin__` slot**.
    A login saved into a different tenant's bucket is never pushed to that agent. The
    Console diagnostics banner reports the saved/seeded counts (counts only, never
    values) so you can tell "not saved" from "saved but not seeded".
- **A Juniper device is reported as a Linux server.** A login-locked SRX/EX prints only
  `<hostname> (ttyu0)` — no vendor string — so it used to fall through to the generic
  `login:` match. It is now recognized pre-login; the full model/serial still require a
  successful login, so fix the credential first.
- **Agent shows offline.** That's the underlying generic-agent host, not the console role
  specifically — see [generic-agent.md](generic-agent.md) troubleshooting for the base
  agent connection.
