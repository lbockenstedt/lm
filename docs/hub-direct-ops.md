---
summary: "Hub-direct operations and the virtual hub-self spoke: how the hub, the one box that is not a spoke, manages itself via the WRITE_FILE/RUN_COMMAND primitives."
keywords: [direct, hub, hub_self, lm, lm_hub_self_agent, ops, recovery, run_command, self, write_file]
---

# Hub-direct operations & the virtual hub-self spoke

**Agent rework #5 / Phase 4.** See `core/src/hub_self.py` for the implementation
and `~/.claude/plans/precious-napping-seahorse.md` for the phased plan.

## Why a hub-self spoke at all

The tiered model is *always-a-spoke*: a spoke owns logic + cert custody and
deploys to its box via the generic `WRITE_FILE` + `RUN_COMMAND` primitives, with
a dumb agent as the thin executor. The hub is the one box that is NOT a spoke —
so its own cert install (`_install_cert_on_hub`) was the lone outlier doing
inline `open()`/`os.replace()` + `subprocess.Popen` while every spoke-side cert
deploy went through the agent primitives.

The hub-self spoke closes that gap with **uniformity, not architecture**: a
loopback `AgentHostingControlPlane` runs *inside the hub process* and serves
`/ws/agent` to an in-process dumb agent, so `_install_cert_on_hub` issues the
SAME `WRITE_FILE` + `RUN_COMMAND` a spoke deploy does. The win is marginal
(one code path for cert installs everywhere); 13 of 15 hub-direct ops stay
hub-local because routing them through a loopback agent would add a new failure
mode *on the hub* for no benefit.

## What it is

- `core/src/hub_self.py::HubSelfControlPlane(AgentHostingControlPlane)` —
  `MODULE_TYPE="hub-self"`, loopback-only (always `127.0.0.1`, never `0.0.0.0`;
  TLS terminates on the hub's unified `:443` surface).
- A task started in `core/src/main.py::LabManagerHub.run()` (NOT a separate
  systemd unit; NOT a spoke in the hub registry — invisible to the WebUI Spokes
  list). Gated by `LM_HUB_SELF_AGENT` (default `1`; set `=0` to disable).
- Default loopback port `8768` (hub=8765, pxmx=8766, cs=8767); override with
  `LM_HUB_SELF_AGENT_PORT`.
- The in-process agent (`_run_in_process_agent`) is a **minimal executor**, NOT
  the device-mode `SpokeClient`: `SpokeClient.run()` arms the code-drift
  watchdog whose `os._exit(3)` would kill the hub if the agent repo ever
  drifted. The hub-self agent reuses only the two primitives that matter
  (`command_runner.run_local_command` + an atomic `WRITE_FILE`) and undoes
  `BaseControlPlane.__init__`'s root-logger/excepthook side effects — it is an
  in-process guest, not a standalone process.
- The shared `agent_secret` is minted in-process (`secrets.token_hex(32)`,
  best-effort persisted to `/etc/lm-hub-self-agent/config.json` 0600) — the
  server and its agent are the same process, so no installer provisioning is
  needed; the value is re-shared on every hub start.

## What moved through the hub-self agent

Only `_install_cert_on_hub` (in `core/src/hub_cert_distribution.py`):

| Op | Via | Fallback |
|---|---|---|
| Write `LM_TLS_CERT` (fullchain, 0644) | `WRITE_FILE` → `_hub_self_write` | direct `_atomic_write` |
| Write `LM_TLS_KEY` (privkey, 0600) | `WRITE_FILE` → `_hub_self_write` | direct `_atomic_write` |
| Write `mtls-ca.pem` (CA bundle, 0644) | `WRITE_FILE` → `_hub_self_write` | direct `_atomic_write` |
| Schedule `lm-self-restart` | `RUN_COMMAND` (`sudo -n …`, awaited) → `_hub_self_restart` | direct `asyncio.create_subprocess_exec` (awaited) |

**Direct fallback** fires whenever the hub-self agent isn't connected (feature
off, not booted yet, listener died), OR the agent reached it but the command
itself genuinely failed (see below). The fallback is byte-identical to what the
agent would have run, so behavior is unchanged from pre-Phase-4 when the agent
is absent — this is why existing cert-rotation tests pass without a hub-self
agent.

The restart command is **awaited to completion**, not backgrounded. That's
safe despite restarting the very process running it: `lm-self-restart` (see
`install_all.sh`) itself only runs `systemd-run --no-block … systemctl
restart lm`, which returns almost instantly having merely SCHEDULED a
transient unit — the actual kill/restart happens ~3s later from that
separate unit, outside lm's cgroup. Awaiting `lm-self-restart`'s own exit
status doesn't risk dropping the response mid-restart; it's exactly what
lets `_hub_self_restart` tell whether `sudo` actually succeeded, and RAISE
instead of optimistically claiming success when it didn't (e.g. `sudo`
denied or misconfigured — this used to be silently swallowed, since the old
code only checked that the command *launched*, not that it *exited 0*; the
real result was nested at `resp["result"]["rc"]`/`["stderr"]`, never read).

`_register_hub_mtls_ca` (runtime CA registry + `global_config` persist) stays
**inline** — it's hub-state mutation, not a file-on-disk-via-agent op. Cert
validation (throwaway `ssl.SSLContext.load_cert_chain`) also stays inline — a
bad cert must never reach the live paths regardless of which write path runs.

## What did NOT move (intentionally hub-local)

These 13 ops are legitimately hub-local — routing them through a loopback agent
would add a failure mode on the hub for zero architectural win. They stay as-is:

- `git pull /opt/lm` (hub core self-update — gated by `lm-watchdog`)
- `repo_sync` (per-tenant GitHub branch pull loop)
- `self_backup` (Fernet-encrypted hub state backup)
- `write_active_users_file` (LDAP/Entra user cache)
- `lm-update-restart` (the hub's own update+restart helper)
- `systemctl restart lm-dns` / `lm-dhcp` (hub-hosted DNS/DHCP services)
- `lm-spoke-recover` (hub-driven spoke recovery)
- remote-console hub target (Setup → Remote Console; admin-only, audited)
- the `ca_only` mTLS-CA fan-out's runtime registration (above)

## Disabling

`LM_HUB_SELF_AGENT=0` → `main.py` never instantiates `HubSelfControlPlane`;
`_install_cert_on_hub` sees no `_hub_self` and takes the direct inline path
exactly as it did before Phase 4. Safe to set on a hub where the loopback
listener must not bind.

## Verification

- Unit: `core/tests/test_hub_self.py` pins the `_hub_self_write` /
  `_hub_self_restart` routing + fallback contract (agent path, agent-error
  fallback, no-agent direct path, direct-write failure, awaited restart,
  direct-exec fallback, exec-failure raises). `core/tests/
  test_hub_self_restart_honesty.py` pins the deeper exit-code-checking
  contract — a transport-level "SUCCESS" with a genuinely failed inner
  command (e.g. `sudo` denied) must NOT be reported as success.
- End-to-end (lab, Python 3.10+): rotate the hub's cert via the le flow and
  confirm the cert/key land via `WRITE_FILE` and `lm-self-restart` fires via
  `RUN_COMMAND`, then the hub reloads the new cert. With `LM_HUB_SELF_AGENT=0`,
  confirm the same rotation succeeds via the direct fallback.