# LM Hub — Code Diagnosability & Documentation Review (Post-Fix Re-Review)

> **⚠ SUPERSEDED — retained as a historical audit record only.**
> **The commit SHAs referenced below (`82c1129`, `7bc70c6`, `058d305`, etc.)
> predate the 2026-06-28 repo history reset and no longer resolve in `git log`;
> they are kept as historical anchors only.** The doc paths cited inside
> (`docs/operations.md`, `docs/log_format.md`, `docs/installation.md`,
> `docs/modules/*`) also reflect the pre-consolidation docs tree and have since
> been merged into the flat `docs/*.md` set.
>
> All 28 findings below were addressed across three subsequent passes:
> 1. The 4-tier parallel pass (commit `82c1129`, 21 files, +1599/−961) — rolled out
>    `_refresh_module_all_tenants` to all 13 sites, added DEBUG relay-trace to ~15 routes,
>    added `logger.exception` before ~95 bare-500 raises, standardized the error-response
>    contract (NetBox 200+ERROR→503; `success`→`ok`; `partial_success` kept with `pushed:bool`),
>    factored `_netbox_list_get`/`_hub_msg`/`_cached_or_live`-style helpers, consolidated
>    the recovery state machine into `update_recovery.py` (single source + CLI), deleted dead
>    `security/codec.py`, fixed the `key_manager` fd leak, added `security/*.py` module
>    docstrings, split `loadSpokesAndAgents`/`loadCPPMData`, added `CRUD_ROUTES`/`SIM_ROUTES`,
>    and corrected `operations.md` helper descriptions + sudoers fragment.
> 2. The doc-vs-code re-verification pass — fixed 7 drift items (route map, relay-trace
>    comment, `_netbox_list_get` cross-ref, rotate-key token, error-convention docstring,
>    operations.md sudoers/snapshot_code).
> 3. The follow-up pass (this file's residuals) — added `logger.exception`/`logger.error`
>    to the last 4 bare-500 sites (probe_api, bug-report store, 2 update-trigger failure
>    branches); asserted fixed `/var/log/lm/lm-netbox*.log`/`lm-ldap.log`/`lm-cppm.log`
>    paths in `log_format.md` + `operations.md` + `netbox.md` (verified against sibling
>    installers); confirmed DNS/DHCP already return 503 backend + handle it via `_spokeFetch`
>    on the frontend (no residual 200+ERROR).
>
> The body below describes the tree as it was **before** those passes and should not be
> read as a current issue list. Read it for the rationale/structure of the fixes, not for
> outstanding work. The current tree state is captured in the module docstrings, the
> `api-error-contract-standardized` + `webui-update-recovery-gap` memory notes, and the
> updated `docs/*`.

---

**Status:** Read-only review. **No code changes.** Generated for review.
**Scope:** `/Users/lbockenstedt/vscode/lm` (and sibling repos under `vscode/` for cross-refs).
**Basis:** Re-audit performed after commit `7bc70c6` ("Code diagnosability + documentation pass").
**Compared against:** the pre-fix review (this file's prior contents). This document
**supersedes** that one and reflects the current tree state.

---

## Executive summary

The `7bc70c6` pass materially improved diagnosability and navigability across all four
areas, and fixed two real bugs (the `broadcaster.broadcast` arity mismatch that silently
killed all CS telemetry fan-out, and the `netbox_delete_device`/`netbox_release_ip`
`NameError` that 500'd on successful delete/release). Structured greppable log markers,
the per-frame inbound DEBUG trace, per-socket broadcast isolation, signer log redaction,
and the quieted tenant-miss log are all genuine wins. The module-type/prefix-map
consolidation and the three dispatch-branch extractions are clean and well-commented.

However, the pass largely **documented** the remaining diagnosability debts rather than
**paying** them. The pattern across all four areas is the same: a helper or convention was
introduced and then adopted at only 1–2 sites instead of across the full duplicated
surface. Specifically:

- `_refresh_module_all_tenants` — written, docstring'd, adopted at **2 of 15** sites.
- DEBUG relay-trace one-liner — added to **2 of ~17** relay routes (the comment asks for
  replication but it wasn't done).
- Error-response contract (200+ERROR vs 503 vs 502; `success`/`ok`/`partial_success`)
  — described in prose, **unchanged in code**.
- The cache→spoke→offline GET pattern and the `Message(...)` construction blocks —
  **entirely unfactored** (8 + 11 duplication sites respectively).
- Recovery state machine — **cross-referenced across 3 locations but not consolidated**.
- `security/*.py` module docstrings — **not added** (the docstring pass was scoped to
  `messaging/*.py` only).
- `operations.md` — two of its three root-helper descriptions are now **factually wrong**
  relative to what the helpers actually emit (new doc/script drift introduced).

No correctness regressions were found in the audited surface. The remaining work is
bounded and largely mechanical. Recommendations are prioritized into 4 tiers below.

---

## Area status table (current state)

| Area | Documentation | Diagnosability | Logic clarity | Net |
|---|---|---|---|---|
| Hub core (`main.py`, `messaging/*`, `state/*`, `security/*`, `update_*`) | Strong (except `security/*.py` module docstrings) | Strong (markers, trace, isolation, redaction) | Good (3/4 dispatch branches extracted; `handle_connection` still 377 ln) | Improved, small residuals |
| HTTP API (`api.py`, `simulations/routes.py`) | Module docstring Strong; per-route Weak (41/185) | Mixed (relay trace 2/~17; ~40 silent 500-raisers) | Helpers added but under-adopted; duplication unfactored | Documented-not-paid |
| WebUI (`main.js`, `sim-views.js`, `update_handler.js`) | Strong file headers + ROUTES table (partial) | Strong (all sim-views catches now logged) | Refactors real and shrunk targets; per-module loaders still large | Improved, ROUTES gap |
| Install + docs (`install_all.sh`, `docs/*`) | Strong phase docs + recovery cross-refs | Mostly good; 2 silent restarts; success path omits log paths | Recovery dedup not done; `operations.md` inaccurate | Improved, doc drift |

---

## Tier 1 — Real defects / factual errors (fix first)

These are correctness or factual issues, not stylistic preferences.

1. **`operations.md` §1 misdescribes two of three root helpers** (`docs/operations.md:22`,
   `:24`, runbook (a) `:74-83`).
   - `lm-self-restart` row claims it "polls `http://localhost:8000/status` and exits 0 on
     200." The actual helper (`install_all.sh:312-322`) is `sleep 3; exec systemctl
     restart lm` — **no** health polling. Description copied from `lm-update-restart`.
   - `lm-spoke-recover` row claims `--inspect` prints `ExecStart`/`User`/`WorkingDirectory`,
     checks venv existence, tails journald, and that recover **rewrites the unit file**.
     None of this is true: the actual helper (`install_all.sh:483-528`) calls
     `systemctl show` for six properties (`ActiveState,SubState,Result,ExecMainStatus,
     ExecMainCode,NRestarts`) and recover only does `reset-failed + restart` (no rewrite).
     Runbook (a) instructs the operator to review fields the helper does not emit.
   - **Fix:** either correct the docs to match the helper, or extend the helper to emit
     what the docs already promise (better diagnosability outcome). Pick one.

2. **`run_mps_loop` has no try/except** (`main.py:1381-1398`) — the only background loop
   without one. Every other loop (`run_tenant_sync_loop`, `run_pxmx_diag_loop`,
   `run_key_rotation_loop`, `run_autoupdate_loop`, `run_opnsense_polling_loop`,
   `run_hub_heartbeat_loop`) wraps its body. An exception here kills the metrics task
   silently. Add the guard for consistency.

3. **Silent `except: pass` in `_get_bug_report`** (`main.py:1828-1829`, `:1840-1841`) —
   artifact/screenshot read failures are swallowed with no log; bugfixer gets a
   silently-partial report with no indication why fields are missing. Replace with
   `logger.debug`.

4. **`key_manager.py:136` unclosed file handle** — `json.load(open(self.storage_path, "r"))`
   with no `with` on the plain-text fallback path. Leaks an fd per load. Use `with open(...)`.

5. **`security/codec.py` is dead code** — `MessageCodec` is defined but imported/used
   **nowhere** in the tree, and it duplicates `signer.py`'s canonicalization. Delete it,
   or wire `signer.py` to delegate to it so there's one canonicalization path. Leaving a
   dead, duplicative module is a maintenance trap.

6. **Two silent spoke-restart swallows in `install_all.sh`**:
   - `:982` — `systemctl restart "lm-$mod" 2>/dev/null || true`: a failed post-install
     spoke restart is invisible; the loop still logs "✅ $mod installed" (`:972`). A down
     spoke looks identical to a healthy one in the install log.
   - `:1053-1054` — `systemctl restart "$svc" || true` followed unconditionally by
     `log_c "  ✅ $svc restarted"`: prints success regardless of restart outcome.
   - Gate the "✅" log on the real exit code; surface failures via `log_e`.

7. **`docs/log_format.md` log table partially wrong** (`:52-58`):
   - `opnsense` listed as `/var/log/lm/lm-opnsense.log` — **wrong**; the unit
     (`install_opnsense.sh:78-92`) has no file redirect → journald only.
   - `dns` and `dhcp` **missing** from the table, yet both ship in-repo and *do* write
     file logs (`/var/log/lm/lm-dns.log`, `/var/log/lm/lm-dhcp.log`).
   - `netbox`/`ldap`/`cppm` paths unverifiable from this repo (sibling installers).
   - Also `docs/modules/client-sim.md:49` overclaims cs "differs from every other spoke"
     on journald-only — opnsense is also journald-only.

8. **`docs/installation.md` module table (`:134-144`)** — LDAP missing (but
   `install_all.sh:630,914,921` clones + installs it). NetBox row points at the
   `provisioning_repos/netbox/install.sh` stub rather than the cloned
   `/opt/lm/netbox/install.sh` `install_all.sh` actually runs. Same path mismatch in
   `docs/modules/netbox.md:6-7,68`. `user_manual.md:11` pipes `install_all.sh` to `bash`
   without `sudo` (script requires root → exit 1).

---

## Tier 2 — "documented-not-paid" debts (finish the adoption)

These were *started* in the prior pass and then left half-done. Completing them is
mostly mechanical.

9. **Roll out `_refresh_module_all_tenants` to the remaining 13 sites** (`api.py`).
   The helper exists at `api.py:251-265` with a docstring advertising it as the
   replacement, but only the two NameError-fix sites use it (`netbox_delete_device`
   `:3386`, `netbox_release_ip` `:3623`). 13 sites still inline the
   `_invalidate_module_all_tenants(key)` + `for tid in list(_tenant_cache):
   asyncio.create_task(_fetch_module(...))` two-liner
   (`:3206/3207, 3223/3224, 3238/3239, 3282/3283, 3402/3403, 3447/3449, 3466/3467,
   3481-3485, 3559-3563, 3607/3608, 3639/3640`). Removes ~26 lines of copy-paste + drift risk.

10. **Add the DEBUG relay-trace one-liner to every relay route** (`api.py`). The exact
    form is specified at `api.py:1644-1646` with a comment "Replicate this one-liner on
    other relay routes" — but only `get_cppm_devices` (`:1647`) and `netbox_get_devices`
    (`:3248`) have it. ~15 other relay routes (cppm_sessions/logs/roles, netbox_racks/
    prefixes/ips, pxmx_vms, all DNS, all DHCP, all LDAP, firewall live-fetch) have no
    happy-path log → a slow/failed spoke round-trip is invisible on the happy path.

11. **Add error-path logging to the ~40 silent 500-raisers** (`api.py`). NetBox CRUD, all
    DNS, all DHCP, all LDAP list/create, several pxmx routes do
    `except Exception as e: raise HTTPException(500, str(e))` with no `logger` call. Because
    `HTTPException` is caught by FastAPI's handler (not the outer
    `error_logging_middleware` at `:513`, which only sees non-HTTP exceptions), these
    failures produce **no hub log entry** — only a 500 to the client. A single
    `logger.exception(...)` before each raise makes them visible.

12. **Standardize the error-response contract** (`api.py`). The docstring at `:61-67`
    documents the debt but the code is unchanged: 7 NetBox 200+ERROR sites
    (`:3151, 3163, 3186, 3262, 3298, 3426, 3586`) that HTTP-level monitors can't see; 47
    `503` sites (uniform within their clusters — good); success tokens vary
    (`"success"` ~40 sites, `"ok"` 11, `"partial_success"` 8). Pick one success token;
    migrate the 7 NetBox 200+ERROR sites to 503. Highest payoff for external callers.

13. **Add module docstrings to `security/{signer,key_manager,encryption,codec}.py`** to
    match the `messaging/*` standard. The class docstrings are good but the module-level
    "what this file owns + audience" framing is missing.

14. **Log the remaining silent swallows in `main.js`** (`:4143, 4164, 4198`; consider
    `:5417, :7637, :7670`). The two pxmx-agent swallows at `:4164`/`:4198` are internally
    inconsistent — the identical best-effort pattern *is* logged at `:1611` and `:3213`.
    Make them consistent. (Note: the bug-buffer IIFE catch at `:198` is intentionally
    silent — logging there would recurse.)

15. **Add a closing-summary log-path line on success** (`install_all.sh:1068-1074`). The
    failure trap (`:104`) names `/var/log/lm/install.log` + `/var/log/lm/hub.log`; the
    success summary does not. An operator whose install succeeds but the hub later
    misbehaves isn't pointed at the logs.

---

## Tier 3 — Factoring / dedup (clarity, larger effort)

16. **Factor the cache→spoke→offline GET pattern** (`api.py`). The repeated shape —
    (a) non-admin cache hit returns filtered cache, (b) spoke lookup, (c) spoke down →
    offline cache fallback or 503/200+ERROR, (d) live `request_response` + filter — appears
    in 8 handlers: `get_firewall_data` (`:1135`), `get_cppm_devices` (`:1640`),
    `get_cppm_sessions` (`:1940`), `get_pxmx_vms` (`:2323`), `netbox_get_racks` (`:3170`),
    `netbox_get_devices` (`:3245`), `netbox_get_prefixes` (`:3410`), `netbox_get_ips`
    (`:3570`). A `_cached_or_live(request, cache_key, spoke_type, cmd, ...)` helper
    collapses them and centralizes the offline-fallback policy.

17. **Add a `Message` factory `_hub_msg(spoke_id, type, data)`** (`api.py`). ~11 verbose
    `Message(header=MessageHeader(message_id=..., timestamp=..., sender_id="hub",
    destination_id=...), payload=MessagePayload(type=..., data=...))` constructions
    remain (`:701, 790, 805, 844, 981, 1026, 1349, 1398, 3135, 3785, 3799`). Collapses to
    one-liners.

18. **Factor the SPOKE_UPDATE fan-out** (`update_pipeline.py`). `perform_update`
    (`:356-397`), `update_spokes_only` (`:453-500`), `update_agents_only` (`:535-558`) all
    repeat "resolve module_key → repo_url → build SPOKE_UPDATE Message → mailbox.push →
    log" (`update_spokes_only` even re-derives `{**_UPDATE_SOURCE_PREFIX_MAP, 'qa':'qa'}`
    inline). A shared `_dispatch_spoke_update(spoke_id, sources, branch, prefix_map)`
    removes ~80 lines.

19. **Extract `_handle_agent_relay_up`** from `handle_connection` (`main.py:1117-1161`,
    ~45 lines with nested AGENT_LOG/HEARTBEAT/AGENT_TELEMETRY/CS_* sub-branches). The
    prior pass extracted CS_TELEMETRY/SPOKE_LOG/HUB_REQUEST but left AGENT_RELAY_UP
    inline (its unmatched sub-types don't `continue`, so extraction changes semantics —
    flagged as risk-managed, but completing the set would bring `handle_connection` down
    toward a pure dispatch shell). Re-read the fall-through semantics first.

20. **Consolidate the recovery state machine.** Three full independent implementations
    remain (`install_all.sh:77-240`, the `lm-update-restart` heredoc `:337-467`, and
    `core/src/update_recovery.py:67-211`), each with its own constants + JSON logic, linked
    only by `KEEP IN SYNC WITH` comments. Lowest-risk consolidation: make the two bash
    blocks thin wrappers shelling out to a single Python entrypoint
    (`python3 -m update_recovery snapshot|rollback|markbad|writefailed`), retiring the
    cross-ref comments rather than relying on them.

21. **Split `loadSpokesAndAgents`** (`main.js:3174`, 231 ln) into `_renderSpokesTable` /
    `_renderAgentsTable` around the existing fetch+split preamble — mirrors the
    `_renderSetupSection`/`SETUP_TILES` split that already worked. Also split
    `loadCPPMData` (`:6367`, 126 ln) into `_renderCppmSessions`/`_renderCppmDevices` (the
    two branches are already structurally separate and each owns its `_cppm403Hint` card).

---

## Tier 4 — Documentation completeness / minor

22. **Per-route docstrings: 144 of 185 undocumented** (`api.py`, 22% documented today).
    Prioritize by user-impact: `auth/login` (`:4142`), `auth/me` (`:4195`), `auth/logout`
    (`:4222`), then the NetBox CRUD cluster, then DNS/DHCP. Even one-liner docstrings help;
    the `_instance_crud` factory (`:1411`) has a strong one but its 20 emitted routes
    inherit nothing.

23. **Section banners for the remaining ~8 clusters** (`api.py`): Setup/spokes
    (`:530`), product-config pairs (`:822`), diagnostics+bug-report (`:2698`), LDAP
    (`:2942`, convert `---` to `──`), tenants/users (`:3815`), auth routes (`:4142`),
    update/modules (`:3647`), cache management (`:4758`, convert `---` to `──`). Cheap.

24. **Expand `ROUTES` to cover CRUD handlers** (`main.js`). The table has ~77 entries but
    omits the entire CRUD underbelly: every `delete*`, `save*`, `edit*`, `toggle*`,
    `approve*`/`unapprove*`, `revoke*`, `reset*`, `assign*`, `remove*` handler (~70
    fetch-issuing handlers). The "click→handler→fetch→API" goal is met only for `load*`
    paths. If full coverage is noisy, add a `CRUD_ROUTES` companion + a header note. **This
    is the single biggest WebUI diagnosability gap.**

25. **Add a `SIM_ROUTES` table in `sim-views.js`** (or extend `ROUTES`). 56 `csFetch(...)`
    calls; only 3 sim entries appear in `main.js` ROUTES (`:168-170`). Simulations is the
    only sub-module whose endpoint surface is entirely undocumented in table form.

26. **Re-sync the section-index line numbers** in `main.js:19-52` (they use "~" and drift
    — e.g. updateStatus advertised ~1174, actual 1380). Either re-sync or drop the numbers
    and keep section names only. Thickens `csFetch` JSDoc (`sim-views.js:54`) to match
    `setupFetch`'s block form while you're there.

27. **Normalize service-user + logging across in-repo spoke installers.**
    `install_opnsense.sh:84`, `dns/install_dns.sh:69`, `dhcp/install_dhcp.sh:84` still
    write `User=root` units while `install_pxmx.sh` writes `svc_lm`. Pick one (preferably
    `svc_lm` + the sudoers helper) for consistency. Optionally bring `start_all.sh` (the
    dev/fallback launch path, `install_all.sh:1024`) up to the same `set -euo pipefail` +
    `log`/`log_e` standard.

28. **Minor core items:** add a one-line comment to `run_retry_loop`'s `ConnectionMap`
    (`main.py:2203`) explaining `.get(spoke_id)` intentionally routes through
    `hub.send_to_spoke` (not a real map); `main.py:1082` redundant `payload` reassignment;
    `main.py:413-416` duplicated "Legacy fallback" comment; `loadFirewalls` vs
    `loadFirewallsList` (`main.js:764` vs ROUTES `:81`) both map to `GET /setup/firewalls` —
    confirm the alias is still load-bearing or fold it.

---

## Verification baseline (from the prior pass, still valid)

- `py_compile` clean on all touched Python files.
- `bash -n` clean on all touched shell scripts.
- JS brace/paren exactly balanced (main.js, sim-views.js, update_handler.js).
- Two real bugs confirmed fixed: `broadcaster.broadcast` arity + per-socket isolation
  (`broadcaster.py:25-69`); `netbox_delete_device`/`netbox_release_ip` `request: Request`
  params (`api.py:3379, 3616`).
- One process smell noted: the 7bc70c6 pass introduced a recursive `_unwrap_spoke`
  (`return _unwrap_spoke(result)`) that was caught only by a later re-export refactor to
  `access.unwrap_spoke` (`api.py:108, 276-279`). All ~26 call sites now resolve correctly,
  but the incident argues for a runtime smoke-test of dedup helpers before commit.

---

## Net assessment

The codebase is now materially more readable and diagnosable than before the fix pass.
The remaining work is bounded, prioritized above, and falls into three buckets:

1. **Real defects** (Tier 1) — the `operations.md` inaccuracies, `run_mps_loop` guard,
   silent swallows, dead `codec.py`, silent install-restarts. These should be fixed.
2. **Finish-the-adoption** (Tier 2) — helpers/conventions introduced but under-adopted.
   Mechanical; high value relative to effort.
3. **Factoring** (Tier 3) — larger refactors that the prior pass deliberately scoped out
   (the file can't be runtime-tested in this environment). Documented with cross-refs
   today; can be executed when a test harness is available.

No recommendation here requires an architectural change; all are local and reversible.