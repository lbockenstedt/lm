---
summary: "Fleet-wide code-complexity scan and refactor backlog for the 'human readable, as simple as possible' rule."
keywords: [complexity, cyclomatic, readability, refactor, simplicity, backlog, complexity_scan]
---

# Code Simplicity Backlog — 2026-10

**Rule:** code must be human readable and as simple as possible. Prefer plain,
direct code over clever or deeply abstracted code. Keep functions small, flat
and single-purpose.

This doc ranks the functions across all fleet repos that break that rule the
most, and lists the refactor patterns that fix them. It is a backlog, not a
mandate to rewrite everything: refactor a hot spot **when you are already
changing it**, and always behind the existing tests.

## How it was measured

```bash
cd /Users/lbockenstedt/vscode
python3 lm/scripts/complexity_scan.py [ROOT] [--json /tmp/cx.json]
```

For each non-test Python function the scanner reports:

- **cc**: McCabe cyclomatic complexity (1 + each `if`/loop/`except`/`with`/boolean operator). Nested functions are scored separately.
- **len**: length in lines.
- **depth**: maximum nesting depth. An `elif` does not count as an extra level.
- **params**: number of parameters.

Rough guide: cc ≤ 10 is easy to follow, cc > 25 is hard, and cc > 50 can no
longer be reviewed with confidence.

## Per-repo totals

| repo | functions | cc>25 | cc>50 | len>200 | depth≥6 |
|---|---:|---:|---:|---:|---:|
| lm | 5024 | 188 | 44 | 68 | 24 |
| cs | 1934 | 78 | 35 | 22 | 22 |
| ab | 1099 | 59 | 17 | 17 | 24 |
| pxmx | 622 | 26 | 7 | 9 | 8 |
| netbox | 197 | 19 | 9 | 8 | 6 |
| dhcp¹ | 201 | 10 | 3 | 1 | 2 |
| cppm | 80 | 6 | 2 | 1 | 0 |
| dns¹ | 127 | 5 | 0 | 0 | 0 |
| nw | 269 | 4 | 1 | 0 | 1 |
| opnsense | 61 | 3 | 1 | 1 | 0 |
| le | 102 | 2 | 1 | 0 | 0 |
| kvm / ldap / truenas | 34 / 89 / 75 | 1 each | 0 | 0 | 0 |
| qa | 73 | 0 | 0 | 0 | 0 |

¹ The sibling `dns` and `dhcp` repos are retired; the live code is `lm/dns` and `lm/dhcp`, which are counted under lm.

## Worst offenders and the fix for each

### Pattern 1 — giant command dispatchers → dispatch table

One `if cmd == "A": … elif cmd == "B": …` chain holds the code for dozens of
commands. Fix: keep one small handler function per command and route with a
dict `{"A": _handle_a, …}`. Each handler can then be read and tested on its own.

| cc | len | location |
|---:|---:|---|
| 304 | 919 | `cs/lm-spoke/src/command_handlers/handlers_config.py:63` `_dispatch_config` — ✅ done (cs 5f16e14: dispatch tables for all 5 mixins) |
| 241 | 1375 | `lm/core/src/main.py:5299` `handle_connection` (WS message-type chain) |
| 137 | 463 | `pxmx/src/proxmox_spoke.py:103` `handle_command` |
| 119 | 292 | `cs/lm-spoke/src/command_handlers/handlers_agents.py:47` `_dispatch_agents` |
| 99 | 314 | `lm/console/src/console_spoke.py:293` `handle_command` |
| 86 | 438 | `lm/agent/src/agent_spoke.py:1677` `handle_command` |
| 86 | 263 | `lm/dhcp/src/dhcp_spoke.py:853` `handle_command` |
| 84 | 289 | `cs/lm-spoke/src/command_handlers/handlers_ingest.py:25` `_dispatch_ingest` |

### Pattern 2 — long sync/poll loops → named steps

One loop body fetches, diffs, writes, logs and retries everything inline.
Fix: split the body into named steps, for example
`fetch_x()`, `diff_x()`, `apply_x()` and `report()`. Use early `continue`
instead of nesting to bring the depth down.

| cc | len | depth | location |
|---:|---:|---:|---|
| 225 | 727 | 9 | `netbox/src/netbox_sync.py:543` `sync_devices` |
| 188 | 791 | 7 | `pxmx/agent/src/agent.py:2068` `_connect_once` |
| 160 | 414 | 10 | `cs/webui-local/app/tasks.py:543` `aruba_poller` |
| 159 | 1048 | 5 | `pxmx/agent/src/usb_provision.py:2597` `run_provision_loop` |
| 156 | 908 | 9 | `ab/fix_engine.py:4645` `process_single_issue` |
| 129 | 505 | 5 | `cs/lm-spoke/src/sim_quota_engine.py:1727` `reconcile` |
| 108 | 455 | 6 | `cs/webui-spoke/server.py:4215` `relay_sync_once` |
| 108 | 353 | 6 | `netbox/src/netbox_sync.py:1271` `sync_nw_device` |
| 93 | 434 | 7 | `ab/pr_review.py:1996` `fix_one_pr` |
| 91 | 550 | 6 | `lm/core/src/update_pipeline.py:1437` `perform_update` |
| 86 | 203 | 7 | `lm/core/src/simulations/routes.py:1637` `_run_adaptive_controller` |
| 84 | 314 | 4 | `lm/core/src/simulations/central_hub_poller.py:959` `_poll_tenant` |
| 83 | 374 | 8 | `netbox/src/netbox_sync.py:1652` `sync_access_tracker` |
| 82 | 291 | 10 | `cs/webui-spoke/services/aruba_poller.py:482` `_poll_central_once` |
| 82 | 359 | 6 | `netbox/src/netbox_vmsync.py:511` `sync_vms` |

### Pattern 3 — field-by-field settings/state appliers → declarative table

The same "if key in payload: validate, coerce, assign" block is repeated for
every field. Fix: describe each field once (name, type, default, validator) in
a list and apply them all in one loop.

| cc | len | location |
|---:|---:|---|
| 221 | 637 | `cs/webui-spoke/services/proxmox_agent.py:2564` `_apply_proxmox_telemetry_state` |
| 160 | 593 | `ab/routes.py:2704` `save_settings` |
| 130 | 377 | `cs/webui-spoke/routers/settings.py:67` `api_settings_update` |
| 107 | 406 | `cs/lm-spoke/src/command_handlers/handlers_config.py:1110` `_apply_hub_config` — ✅ done (cs 5f16e14: cc 107 → 13) |
| 97 | 242 | `cs/webui-spoke/server.py:3971` `_apply_hub_config` |
| 90 | 302 | `cs/webui-spoke/server.py:3667` `_apply_relay_command_batch` |

### Pattern 4 — middleware/route functions doing many jobs → small guards

| cc | len | location | fix |
|---:|---:|---|---|
| 155 | 584 | `lm/core/src/api.py:1487` `access_control_middleware` | One function per rule (public path, admin path, tenant scope, token routes), run in order, first match wins. |
| 105 | 182 | `lm/core/src/routes/cppm.py:337` `get_device_detail` | Split into one fetch helper per data source plus one assembler. |
| 102 | 221 | `cs/webui-spoke/server.py:1168` `_fetch_nc_browse_for_spoke` | Same as above. |
| 83 | 245 | `lm/core/src/routes/nw.py:1925` `_execute_nw_scan` | Same as above. |

### Pattern 5 — duplicated pollers (also a consolidation item)

`poll_site_data` has cc 86–91 in each of `cs/webui-local/app/aruba.py:338`,
`cs/lm-spoke/src/aruba.py:407` and `lm/core/src/simulations/aruba.py:515`.
Simplify one copy, then fold the others into it. See Tier 3 in
[code-consolidation-backlog.md](code-consolidation-backlog.md).

## Suggested order

1. Simplify the Pattern 1 dispatchers first. The change is mechanical, the risk is low, and the payoff is large: `_dispatch_config` and `handle_connection` alone account for more than 2,000 lines.
2. Pattern 3 appliers, because they are also mechanical and well covered by tests.
3. Patterns 2 and 4, one function per PR, only with good test coverage.
4. Re-run `complexity_scan.py` after each step and update the tables above.

## Guarding against regressions

- Do not add a hard CI gate yet. Too many existing functions would fail it.
- Once the top offenders are done, a ratchet that fails CI only when a function's cc *increases* past 25 would keep new code simple.
- The rule also needs to reach the code-writing agents (AB's coder and reviewer prompts, `lm/.claude/skills`, and each repo's `AGENTS.md` rules). Without that, new code will keep adding complexity.
