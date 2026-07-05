# Logging & Observability Contract (every module & agent)

**Status: MANDATORY.** Applies to every spoke, agent, and module in the platform
— existing and new. Audience: developers building or modifying any module.

## Why this is a hard requirement

- The operator **cannot always reach a box's CLI** (a module may run in an LXC
  container, on a headless Proxmox host, or a remote site). Diagnostics must be
  visible from the hub WebUI alone.
- The **BugFixer** module reads relayed logs/errors to triage, auto-fix issues,
  and open GitHub issues. A log that never reaches the hub is invisible to it.

So: **once a module/agent is connected to the hub, the hub must have all of its
logs.** Relay is additive — the local file log stays; the hub copy is on top.

## The hub's two logs (where your relayed lines land)

The hub exposes **two** views, both built from the same sources — the hub's own
deque, the per-module/agent relayed deques (`agent_logs[...]`, fed by `AGENT_LOG`
/ `SPOKE_LOG`), and any `/var/log/lm/*.log` files **on the hub box**:

1. **Error Log** — `LabManagerHub.collect_error_logs()` → the WebUI **Error Log
   tab** and the **BugFixer**. Aggregates errors across **all** modules, keeping
   only lines matching `\b(error|exception|traceback|critical)\b`
   (case-insensitive), each prefixed `[module]`.
2. **Per-module log** — `collect_all_logs()` → the module's own log view (all
   levels, grouped by module).

Two consequences every module must respect:

- **Remote modules depend entirely on the relay.** The `/var/log/lm/*.log` disk
  source only covers modules **co-located on the hub box**. An agent/spoke on a
  separate host (e.g. a Proxmox node, a remote-site LXC) writes to *its own*
  `/var/log/lm` — invisible to the hub filesystem. Its **only** path into either
  hub log is the WebSocket relay. This is why the relay is mandatory, not optional.
- **Error lines must carry the level word** so the Error-Log/BugFixer regex
  matches them. The standard formatter `%(asctime)s - %(name)s - %(levelname)s -
  %(message)s` guarantees this (an ERROR record contains "ERROR"; an
  `exc_info=` traceback contains "Traceback"/"Exception"). Use it for the relay
  handler; don't strip the level.

## The six requirements

1. **Relay own logs to the hub once connected.**
   - Spokes: relay via the control-plane `SPOKE_LOG` / log-relay path.
   - Agents: attach a `WebSocketLogHandler` that sends `AGENT_LOG` frames (the
     spoke forwards them up via `AGENT_RELAY_UP`; the hub surfaces them in
     **Setup → Agent/Spoke Logs** and feeds the BugFixer).
   - Relay level **INFO and above** (WARNING/ERROR always included).

2. **Install the relay ONCE for the process lifetime** — at construction/startup,
   not inside the per-connection handler. Adding on connect and removing on
   disconnect silently drops every record logged before auth and during any
   reconnect gap.

3. **Buffer while disconnected, flush on (re)connect.** Records emitted while the
   socket is down (startup, between reconnects) go to a **bounded ring buffer**
   (e.g. `collections.deque(maxlen=1000)`); drain it the moment auth completes so
   the hub receives what it missed. Bounded so a long outage can't exhaust memory.

4. **Relay uncaught exceptions, not just logged records.** Install:
   - `sys.excepthook` — routes sync crashes through the module logger before the
     interpreter's default handler runs.
   - `loop.set_exception_handler(...)` — routes unhandled asyncio-task exceptions
     through the module logger, then defers to `default_exception_handler`.
   Without these, a traceback lands only in the local file (via systemd stderr
   capture) and never reaches the hub or the BugFixer.

5. **Log through the module's own named logger** (`getLogger("PxmxAgent")`,
   `getLogger("Hub")`, etc.) so the relay's prefix filter forwards it. Don't rely
   solely on a `FileHandler`; a record that only hits the file is invisible to the
   hub. (Note: on the canonical `/var/log/lm/<x>.log` path the stderr
   StreamHandler is intentionally dropped to avoid double-writes — that makes the
   named-logger relay the *only* path to the hub, so it must be wired.)

6. **Keep the local file log.** Relay never replaces the file — the file is the
   fallback when the hub link itself is down.

## Reference implementation

`pxmx/agent/src/agent.py`:
- `WebSocketLogHandler` — INFO+, prefix-filtered, buffer-on-disconnect +
  `flush_buffered()` on connect; installed once in `__init__`, never removed.
- `_install_uncaught_exception_relay()` — `sys.excepthook`.
- `_asyncio_exception_relay()` — wired via `set_exception_handler` at the top of
  `run()` once the loop exists.

## Checklist when building or touching a module

- [ ] Relay handler installed once (not per-connection).
- [ ] INFO+ from the module's own logger reaches the hub.
- [ ] Buffered while disconnected; flushed after auth.
- [ ] `sys.excepthook` + asyncio exception handler route tracebacks to the hub.
- [ ] Local file log retained.
- [ ] Verified in **Setup → Agent/Spoke Logs** (not just the box CLI).
