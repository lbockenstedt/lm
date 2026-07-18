# DRAFT — "Console" Serial Console Role for lm (design)

> Status: DESIGN — decisions LOCKED 2026-07-05 (see §6). Uncommitted draft.
> Modeled on ConsolePi (github.com/Pack3tL0ss/ConsolePi), natively integrated into lm.
> Tracked as the Console epic on the todo list.

## 1. Executive summary
The **Console** role turns any lm agent host with serial adapters (`/dev/ttyUSB*`, `/dev/ttyACM*`,
on-board UARTs `/dev/ttyAMA*`) into a network-reachable serial console server — an lm-native
reimagining of ConsolePi. An admin assigns the `console` role to an Agent via the existing
"Load Role" flow; the agent enumerates + registers its serial ports; the admin opens an interactive
**xterm.js** terminal in the hub WebUI to a selected port, with the raw serial byte stream proxied
over the existing hub↔spoke WebSocket transport — mirroring how lm relays VM VNC consoles today.
Per-port baud/parity/flow, one-writer session locking, tenant gating, and mandatory log relay included.

**Simplification vs VNC:** the console sub-spoke runs *directly on the machine that owns the serial
ports*, so it opens the pyserial port locally and pushes bytes straight up its own hub WebSocket via
`send_to_hub(...)` — no `AGENT_RELAY_UP` wrapper, one fewer hop than the pxmx VNC relay. We reuse the
VNC *relay pattern* (session registry, queue-consumer discipline, request/response for setup).

## 2. ConsolePi capabilities & which we adopt
| Capability | ConsolePi | lm plan | v1? |
|---|---|---|---|
| Serial adapter auto-detect | scans ttyUSB/ttyACM/ttyAMA | pyserial `list_ports` + `/dev/serial/by-id` scan on the console sub-spoke | Yes |
| Stable port naming | udev rules by serial#/vendor | software-derived stable `port_id` from USB serial#/`ID_PATH` + editable alias in role config; udev-writing later | Stable ID Yes; udev Defer |
| Per-port baud/flow/parity | ser2net cfg, 9600 8N1 | per-port settings in role config, applied on open; editable in WebUI | Yes |
| Telnet (ser2net) | 7000/8000/9000 | NOT adopted — access only via hub WebUI relay (no unauth bypass) | No |
| SSH menu | consolepi-menu TUI | replaced by hub WebUI terminal | No |
| Web interface | Flask :5000, no auth | native lm WebUI + `/api/console/*`, gated by session auth + `console` right | Yes |
| Remote/clustered | mDNS + gdrive CSV | hub already aggregates every console sub-spoke; native | Yes |
| Power control | GPIO/Tasmota/DLI outlets | optional per-port `CONSOLE_POWER_*` later | Defer |
| Bluetooth / cloud sync / ZTP / hotspot / VPN | various | out of scope (lm has dns/dhcp/opnsense) | No |
| Session record/replay | n/a | optional opt-in byte capture | Defer |

## 3. Architecture (highlights)
- **Where it lives:** `ConsoleSpoke(BaseSpoke)` loaded via the role machinery (`agent/src/agent_spoke.py:35`
  `_ROLE_MAP`, `:291` LOAD_ROLE, `:127` loader), `RoleConnection` under `{agent}-console`,
  `module_type "console"` (`agent/src/control_plane.py:57`), parent-auto-approved.
- **Serial layer:** port inventory (stable `port_id`, dev_path, alias, vendor/product/serial, baud…),
  open-session map (`session_id → serial handle + reader task + writer lock + viewers`), one writer per
  port, extra openers read-only. Adds `pyserial` (optionally `pyserial-asyncio`).
- **Relay (reuse VNC pattern):** browser POST `/api/console/open` mints `session_id`+`ws_token`,
  `register_console_session(...)` (peer to `register_vnc_session` `core/src/main.py:786`), then
  **`request_response(console_spoke,"CONSOLE_OPEN",…)`** (NOT fire-and-forget). Browser connects
  `/ws/console-serial/{session_id}?token=` (peer to `pxmx_console_ws` `api.py:3705`). Keystrokes down via
  fire-and-forget `send_to_spoke_command("CONSOLE_DATA")`; device output up via
  `send_to_hub("CONSOLE_DATA_UP",…)` (`messaging/control_plane.py:542`) → new inbound dispatch branch in
  the hub loop (`main.py:~2243`) → session queue → `spoke_to_browser` → xterm.
- **GOTCHAS to avoid (from memory):** (1) queue consumer must `ready→continue`, `disconnect→close(1000)`,
  `error→close(1011)` — never bare-return (the VNC `api.py:3767` fix); (2) setup must be request/response
  (fire-and-forget drops the spoke's COMMAND_RESULT — `main.py:763`); fire-and-forget only for the
  high-rate keystroke stream; (3) no secondary credential like VNC's RFB ticket — `ws_token` alone gates.

### Command envelope
`CONSOLE_LIST_PORTS`, `CONSOLE_GET_SETTINGS`, `CONSOLE_SET_SETTINGS`, `CONSOLE_SET_ALIAS` (req/resp);
`CONSOLE_OPEN {session_id,port_id,mode:rw|ro}` (req/resp), `CONSOLE_DATA {session_id,data:b64}` (down,
fire-and-forget), `CONSOLE_DATA_UP` (up), `CONSOLE_READY|CONSOLE_ERROR|CONSOLE_CLOSED` (control up),
`CONSOLE_RESIZE`, `CONSOLE_SEND_BREAK` (BREAK for ROMMON etc.), `CONSOLE_CLOSE`.

### WebUI / permissions / logging
- xterm.js vendored under `WebUI/assets/` (offline-safe, matches html2canvas); new Console nav view listing
  console sub-spokes + ports with per-port Open button (mirror `pxmxOpenConsole`/`pxmxShowVncModal`
  `main.js:7691/7730`); per-port settings panel.
- `has_console_access` in `core/src/access.py:233`; `/api/console/*` middleware gate (mirror `/api/nw/*`
  `api.py:658`); `MODULE_RIGHT 'Console':'console'` (`main.js:607`); Console column in User Mgmt; tenant
  binding stamped on the session end-to-end.
- Logging contract: named `ConsoleSpoke` logger + shared `configure_logging()` → `/var/log/lm/console.log`;
  inherits SPOKE_LOG + uncaught-exception relay from `BaseControlPlane`; per-byte lines at DEBUG.

## 4. In-repo (DECIDED)
**Console ships IN-REPO** (user decision #8), i.e. inside the lm repo at `lm/console/src/console_spoke.py`
with `_ROLE_MAP` `repo_url=None` (like dns/dhcp) — staged from the existing `/opt/lm` clone on LOAD_ROLE,
no sibling repo, no extra `git clone`. `pyserial` still needs adding to a `requirements.txt` the agent
installs, and `install_agent.sh stage_role()` must grant the `dialout` group for `/dev/tty*`.

Register the 11th role by touching: `_ROLE_MAP` (`agent_spoke.py:35`); `stage_role()` + Valid list
(`install_agent.sh:188,203`); WebUI `AGENT_ROLES` (`main.js:436`), `MODULE_TYPE_PRODUCT` (`:471`),
`MODULE_RIGHT` (`:607`), `PRODUCT_MAP` (`:450`); hub `console_sessions` registry + dispatch branch +
`_MODULE_TYPE_PREFIX` (`main.js`/`main.py:223`) + `_evict_spoke` cleanup (`:808`); `api.py` routes + WS +
gate; `access.py:233`; new sibling repo; canonical `lm/docs/console.md` + `docs/README.md` index.

## 5. Security
Serial = root-on-device power. Auth every leg (session + `console` right + one-shot `ws_token`, 4401 on
mismatch); tenant isolation stamped/checked end-to-end; **one writer per port**, others read-only; audit
INFO log of every OPEN/CLOSE (user/tenant/port/mode) relayed to hub; optional opt-in session recording
(secrets in scrollback — privacy-sensitive); run in `dialout` group not root; no telnet/ser2net bypass;
BREAK + power actions admin-only.

## 6. Decisions (LOCKED 2026-07-05) — supersede §2 deferrals
1. **Stable naming:** software-derived `port_id` (USB serial#/`ID_PATH`; UART by device path/sysfs). No udev.
2. **Power control:** OUT — a PDU integration comes later.
3. **Session recording:** OUT.
4. **Concurrency:** one-writer lock (single writer per port; extra openers read-only).
5. **Baud:** AUTO-DETECT (see §6b).
6. **Devices:** mixed — both USB adapters and on-board UARTs (`ttyAMA*`/`ttyS*`).
7. **Terminal:** xterm.js (vendored under `WebUI/assets/`).
8. **Placement:** IN-REPO (`lm/console/`, `repo_url=None`) — see §4.
9. **Auto-identify:** FULLY AUTOMATIC on detection (§6b), GLOBAL encrypted credential list, banner→vendor-profile
   auto-detect, and NetBox **match + auto-create** in v1.

## 6b. Auto-identify / fingerprint subsystem (the added requirement)
On a newly-seen stable `port_id`, the console spoke runs an automatic, **read-only** identify pipeline and
reports results to the hub (surfaced in the Console UI + pushed to NetBox):

1. **Baud auto-detect** — cycle candidates `[9600,115200,38400,19200,57600,4800,115200,230400]` at 8N1, send
   CR/LF, score each by printable-ASCII ratio + known prompt/banner regexes; lock the best, store on the port
   record, allow manual override. (Primitive lives in the serial layer / Phase A.)
2. **Banner scrape** — after baud lock, press Enter and capture the initial output (bounded time + KB) as
   `banner`; surface it in the UI so the admin gets "the initial screen" to recognize the device.
3. **Vendor-profile detection** — match banner/prompt against built-in profiles: Cisco IOS/NX-OS, Aruba/HPE
   AOS-CX + ProCurve, generic Linux (extensible). Each profile = {prompt regex, login-prompt regex, pager
   handling, ordered READ-ONLY identity commands, parse regexes for serial/MAC/mgmt-IP/model/hostname}.
4. **Credential login** — GLOBAL ordered credential list, WebUI-managed, **Fernet-encrypted** in hub state,
   delivered to the spoke over the signed control channel; tried in order at the login prompt. Passwords
   never logged.
5. **Harvest** — run the profile's read-only commands, parse identity fields (serial, MAC, mgmt IP, model,
   hostname). Consider reusing the **nw** module's CLI command/parse assets rather than reinventing.
6. **NetBox match + auto-create** — route the harvested identity through the **netbox** module's existing
   device dedup (match serial → MAC → hostname; create if none), tagging `discovered_from="console"` + the
   console port + banner; respect source-of-truth settings. Reuses the nw→NetBox sync path.

**Guardrails for FULLY-AUTOMATIC (asserted, not optional):**
- Global "Auto-identify new devices" toggle (default ON) + per-port opt-out + a kill switch.
- Probe only when the port has **no human writer** (respects the one-writer lock); it takes the lock, then
  releases + logs out when done.
- **Read-only enforcement:** only commands from the profile's allow-list are sent; a denylist rejects any
  config/write verb.
- **Lockout safety:** try the credential list at most once per device, then cool down (no re-hammering);
  cap attempts; back off. Full audit log (INFO, relayed) of every probe + which credential index succeeded.

New envelope commands: `CONSOLE_AUTOPROBE {port_id, opts}`, `CONSOLE_PROBE_RESULT {banner,baud,vendor,identity}`
(up), `CONSOLE_SET_CREDENTIALS` (hub→spoke, signed), `CONSOLE_SET_PROFILES` (hub→spoke). NetBox push via the
existing `NETBOX_SYNC_DEVICES` (or a thin `CONSOLE_SYNC_DEVICE` wrapper).

## 6c. Config read / push — WRITE access (added requirement 2026-07-05)
The console agent also needs to **write** to devices — read/back up a running config, and push a supplied
config. This is a DELIBERATE, admin-triggered write path, **separate** from the read-only auto-probe:
- **Read/backup** — `CONSOLE_GET_CONFIG {port_id}` runs the vendor profile's read-only "show running-config" /
  "display current-configuration" (pager-aware), returns the captured text. Surfaced in the UI + optionally
  stored/attached (destination TBD, see questions).
- **Push (transactional, NO post-request approval)** — `CONSOLE_PUSH_CONFIG {port_id, config, source}` runs
  without any separate admin confirm once requested (whether pasted, NetBox-rendered, or from a template):
  1. **Pre-verify + backup:** confirm the device is reachable + at a usable prompt; capture the current
     running-config as a baseline/backup.
  2. Acquire the one-writer lock, log in, enter config mode, send the config line-by-line (profile enter/exit
     verbs), watching for per-line errors.
  3. **Post-verify:** confirm the device reached the intended state (method TBD — see questions).
  4. **On PASS → save to startup** (`write memory`/`commit`). **On FAIL → do NOT save**, and roll back by
     either rebooting (running-config is unsaved → reboot cleanly reverts to startup) or negating the applied
     lines (`no <command>`). Rollback method TBD (see questions).
  5. Log out; audit-log the whole transaction (user, tenant, port, source, verify result, save y/n, rollback).
  Config **sources** (all four requested): paste/upload (v1) · lm template library · NetBox-rendered · hub API —
  all share this one `CONSOLE_PUSH_CONFIG` path; v1 wires paste/upload and stubs the rest.
- **Vendor profiles gain a config section:** `{enter_config, exit_config, save, error_regex, show_running}`.
- **Guardrails (distinct from auto-probe):** requires the one-writer lock (fails if a human holds it) and a
  higher permission tier than read/observe (config-push should NOT be available to view-only console users);
  every push is audit-logged (user, tenant, port, bytes, save y/n, result) and relayed to the hub; consider a
  confirm step + dry-run default. This path is intentionally NOT bound by the auto-probe read-only allow-list.

Envelope: `CONSOLE_GET_CONFIG` (req/resp, up), `CONSOLE_PUSH_CONFIG {config,save,dry_run}` (req/resp).

### Parked for Phase G (config read/push) — confirm when that phase is built (does NOT block Phases A–F)
- **Verification method:** how is post-push "passed" determined — re-read running-config for the intended
  lines? a reachability/health check (mgmt IP / interface up)? a per-push expected-output regex? a combo?
- **Rollback default:** reboot (clean revert to unsaved startup) vs `no <command>` negation — default + is it
  per-push selectable? Is a reboot acceptable as the safe fallback?
- **Permission tier:** a separate `console-write` right above `console` (view/interact)?
- **Backup destination:** pre-push baseline + on-demand backups — display-only / versioned lm archive /
  attached to the NetBox device record?
(Config source RESOLVED: all four requested; v1 builds paste/upload, stubs template/NetBox/API on the same path.
Apply flow RESOLVED: transactional, no post-request approval, verify before+after, save-on-pass, rollback-on-fail.)

## 6d. Tenant binding + Console permission (added 2026-07-05)
- **Two-level tenant binding.** The WHOLE console agent binds to a tenant via the
  standard spoke Tenant action (a console sub-spoke also inherits the parent agent's
  tenant on parent-auto-approve). Additionally an INDIVIDUAL port can be bound
  (per-port override, `CONSOLE_SET_TENANT`) so one console host serves ports to
  different tenants. Effective tenant = per-port override, else the agent's tenant
  (`hub.state.get_spoke_tenant`). `/api/console/ports` tags each port with
  effective/override/agent tenant and hides ports a non-admin can't access;
  `/api/console/open` enforces it; per-port assignment (`POST /api/console/tenant`)
  is admin-only like whole-agent assignment. The Phase F auto-created NetBox device
  uses the port's effective tenant.
- **Console is a User-Management right.** `console` is a permission right
  (`access.has_console_access` + `/api/console/*` middleware gate) surfaced as a
  Console column/checkbox in User Management + `MODULE_RIGHT 'Console':'console'` so
  nav-hiding and API access agree (Phase D). Config-push (Phase G) adds a higher
  `console-write` tier.

## 7. Implementation task breakdown → todo list (Console epic #1 + Phase tasks)
A serial layer + in-repo scaffold + baud-detect primitive → B hub relay → C REST+WS → D WebUI terminal +
credential/settings UI + banner/vendor display → E in-repo role + permissions → **F auto-identify/fingerprint
engine (banner, vendor profiles, encrypted creds, read-only harvest, NetBox match+create)** → G docs + tests.
