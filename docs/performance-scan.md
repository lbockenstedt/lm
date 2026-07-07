# Performance & Caching Scan — 2026-07-06

A deep, whole-codebase performance + caching audit. Six parallel scans ran over
the hub (`lm/core`), WebUI (`lm/WebUI`), and every sibling spoke repo
(`netbox`, `opnsense`, `nw`, `cppm`, `le`, `pxmx`, `cs`, `dns`, `dhcp`, `ldap`).

Findings are ranked **H → M → L** by impact, de-duplicated across scans, and
grouped by theme. Each item carries `file:line`, the failure mode, the fix, and
an effort estimate (S = one-line to small, M = half-day, L = multi-day).

> Read-only audit. No files were modified by the scan. Apply fixes in the
> order listed — the top of each theme is the highest leverage.

---

## Theme A — Event-loop I/O starvation (sync disk/subprocess on async loops)

This is the **same bug class that took down cs-svr-02-spoke** (sync disk writes on
the shared asyncio loop stalled the hub WS link → 5s Request Timeout). The cs fix
(`6ca8123`/`fed8c5d`, already in cs HEAD) used `asyncio.to_thread` /
`command_queue._asave`. The same pattern is repeated across the hub and most
spokes. **Every H below is a `to_thread` swap — mostly one-line.**

| # | file:line | what blocks the loop | fix | effort |
|---|---|---|---|---|
| A1 | `lm/core/src/messaging/mailbox.py` `_save` (called from `acknowledge`/`push`/`retry_loop`/`flush_mailbox`) | hub-side twin of the cs `command_queue` fix; every COMMAND_RESULT + command-dispatch fan-in writes JSON synchronously | `_asave` + six `await` swaps | M |
| A2 | `netbox/src/netbox_spoke.py:442` `get_status` → `engine.get_system_health` | NetBox spoke's only non-offloaded engine call; slow/unreachable NetBox parks the spoke loop → Request Timeout (identical shape to the cs bug) | `return await self._run_sync(self.engine.get_system_health)` | S |
| A3 | `dns/src/dns_spoke.py:38` `handle_command` → sync `unbound_manager.*` | every DNS command + heartbeat runs `unbound-control` subprocess (5-10s) + conf parse inline | wrap each `self.mgr.*` in `await asyncio.to_thread(...)` (mirror `ldap_spoke.py`) | S |
| A4 | `dhcp/src/dhcp_spoke.py:35` `handle_command` → sync `kea_manager.*` | every DHCP command + heartbeat; `DHCP_SYNC` chains 3 Kea RPCs (up to 30s) | `await asyncio.to_thread(...)` or convert `_rpc` to `httpx.AsyncClient` | S/M |
| A5 | `pxmx/agent/src/agent.py:707` `psutil.cpu_percent(interval=1)` | deterministic 1s stall every 60s telemetry tick + on-demand GET_SYSTEM_STATS | drop `interval=1` (seed once at startup, use `interval=None`) | S |
| A6 | `pxmx/agent/src/watchdogs.py:310` `_hw_check` inline `subprocess.run(["journalctl"],timeout=15)` | 15s stall on the 60s watchdog loop; an async `_journalctl()` helper already exists | use the existing `await _journalctl(...)` | S |
| A7 | `pxmx/src/control_plane.py:177` `_on_agent_telemetry` → `_save_disk_cache()` | sync JSON write every telemetry frame from every pxmx agent | `await asyncio.to_thread(self._save_disk_cache)` | S |
| A8 | `cs/webui-spoke/server.py:3014` `_broadcast_relay_state` → `_save_relay_state()` | fires on every telemetry_ack (~10s) + relay cycle (~14 call sites) | single `await asyncio.to_thread(_save_relay_state)` covers all callers | S |
| A9 | `cs/webui-spoke/server.py:5492` `_poll_agent_inbox` → `_save_commands()` | per agent poll (~10-60s); an async wrapper `_async_save_commands` already exists | swap to `await _async_save_commands()` | S |
| A10 | `cs/webui-spoke/server.py:4024,4033` + `:3547,3624,3647,4195` `_apply_hub_config`/`_save_settings` | every hub config push + 4 command-handler sites | `await asyncio.to_thread(...)` at each site | S |
| A11 | `cs/lm-spoke/src/simulation_engine.py:226-235` `_beacon` | every sim iteration (~5s): two `subprocess.run` host helpers (nmcli/ip route/ping, up to ~6s) + JSON write inline | `to_thread` the helpers + write | S |
| A12 | `lm/core/src/update_recovery.py:142` `snapshot_code` (`shutil.copytree` of core/src + WebUI + dns + dhcp) called from `async def perform_update` | hourly `run_repo_sync_all` path; recursive sync I/O stalls the hub loop for seconds → all heartbeats/API/`request_response` time out | wrap `snapshot_code`+`write_pending` in `asyncio.to_thread` inside `perform_update` | S |
| A13 | `lm/core/src/main.py:2433,2479` `collect_all_logs`/`collect_error_logs` | `os.listdir` + per-file `open` + `deque` then inline `json.dumps` binary search; in-code comment notes this "stalled the event loop on every BugFixer poll" | `await asyncio.to_thread(collect_all_logs, ...)` from `handle_hub_request` + `/setup/logs*` handlers | S |
| A14 | `lm/core/src/main.py:3137-3138` `poll_opnsense_rules` inline `json.dump` to cache file | hourly per-firewall loop; ruleset can be large | `asyncio.to_thread` the cache write (mirror `NwCacheMixin._nw_cache_persist`) | S |
| A15 | `lm/core/src/simulations/store.py:95-102` `SimulationsStore._save` | ~20 async `set_*` setters incl. periodic sync-status writers (hourly staleness/vm/endpoint/fw/nw/realtime loops) | wrap `_save` in `asyncio.to_thread` | S |
| A16 | `lm/core/src/hub_bug_store.py:30-85,90-121` `_store_bug_report`/`_get_bug_report` | POST `/api/bug-report` + GET_BUG_REPORT (bugfixer): makedirs + 3 writes + base64 decode + screenshot | `asyncio.to_thread` both | S |
| A17 | `lm/core/src/state/manager.py` + `key_manager` saves on 60s/5-min/rotation loops | hub StateManager/KeyManager save_state inline on hot rotation loops | `to_thread` the saves | S-M |
| A18 | `cs/webui-spoke/services/proxmox_agent.py:1691-1795` `_hub_self_register`/`_hub_check_approval` saves | every relay poll (~10s) during pending registration | `to_thread` each save | S |

**Medium-frequency stalls** (same loops, smaller/throttled — `to_thread`):
pxmx `usb_provision.run_provision_loop` 6-10 JSON I/O per tick; pxmx watchdogs
JSON I/O; pxmx agent `UPDATE_CONFIG`→`_save_persisted_config`; pxmx
`_cs_telemetry_body` `/sys` enumeration; cs `handle_command` config-file
writes; cs `sim_client_count_sampler` saves; cs `sim_port_flap`/`_setup_sim_phy`
inline `subprocess.run(["ip"],timeout=3)`; cs `_enqueue_command_locked`→
`_save_commands` under lock; hub `_install_cert_on_hub` atomic writes; hub
`_is_git_repo`/repo_sync `subprocess.run` git; le `_persist()`/`read_material`
(`Ledger.save_async` exists but is unused — switch callers to it).

**Already clean (reference patterns to mirror):** `ldap_spoke.py` (every
python-ldap call wrapped in `to_thread`), `nw` (asyncssh/httpx/pysnmp, native
async), `netbox` engine calls (`_run_sync` — exception is A2), `cppm`
`refresh_cache` (`run_in_executor`), `opnsense_engine._request`
(`create_subprocess_exec`), `le acme._run`, `NwCacheMixin._nw_cache_persist`,
hub SPOKE_UPDATE handler (`to_thread`).

---

## Theme B — N+1 pynetbox `.get(id)` + `.save()` per row (biggest DB cost)

The dominant cost in every NetBox sync. The bulk `_api_get_all` already returns
every row dict (including `id`, `custom_fields`, `status`), but the upsert loop
re-fetches a pynetbox ORM object per row just to call `.save()`.

| # | file:line | pattern | N | fix | effort |
|---|---|---|---|---|---|
| B1 | `netbox/src/netbox_staleness.py:94-144` (+ VM loop `:153-205`) | `nb.dcim.devices.get(row["id"])` fires BEFORE the `age >= cutoff_stale` check; vast majority of rows are fresh | full discovery-owned fleet | hoist the staleness check ABOVE the `.get()`; PATCH-by-id only on rows that mutate | S |
| B2 | `netbox/src/netbox_vmsync.py:516-695` | per-VM `virtualization.virtual_machines.get(id)` + `.save()` + per-iface create + per-IP create | all VMs in cluster | direct REST PATCH by id (bulk row already has `id`); bulk `virtual_machines.update([...])` | M |
| B3 | `netbox/src/netbox_sync.py:308-636` `sync_devices` | per-device `devices.get(id)` + `.save()`/`.delete()` + `interfaces.create` + `_reuse_or_create_ip` | all discovered devices | direct REST PATCH/DELETE by id via `_api_get` helper | M |
| B4 | `netbox/src/netbox_sync.py:1183-1313` `sync_access_tracker` | refresh path (common case): `devices.get(id)` + `devobj.save()` per matched session every cycle | NAC sessions per cycle | hoist CF merge to the bulk row, PATCH by id | M |
| B5 | `netbox/src/netbox_sync.py:294-475` `_reuse_or_create_ip` | fresh `ip_addresses.get(address=addr)` per IP regardless of reuse/create | ~1000 GETs/1000-device sync | batch-resolve once via `ip_addresses.filter(address__in=[...])`, build `{addr: ipobj}` index | M-L |

**NetBox picklist re-resolution (a single TTL cache decorator covers all of these, S effort):**
`_resolve_tenant_ci` (`:963` — 2 RTTs per sync command), `get_device_form_options`
(`netbox_dcim.py:128` — 4 serial GETs per Claim modal), `get_tenants`/`get_sites`/
`get_system_health`/`get_dhcp_prefixes` (fresh every command — `get_system_health`
is the hot status-poll one), `_ensure_device_role`/`_ensure_device_type`/
`_resolve_site` (`:66-124` — 3-7 extra GETs per sync for constant slugs),
`claim_device`/`allocate_prefix`/`claim_prefix` slug GETs. **One process-lifetime +
TTL (60-300s) cache on `/tenancy/tenants/`, `/dcim/sites/`, `/dcim/device-roles/`,
`/dcim/device-types/`, `/dcim/manufacturers/`, `/ipam/prefixes/` with invalidation
on `reconnect()` resolves 5 findings at S effort.**

**NetBox misc:**
- `netbox_staleness.py:89,148,213` — 3 full cluster-wide paginated lists (devices/VMs/IPs, ~200 pages each) every sweep. Short-TTL (60s) on the three lists for overlap; `last_seen__isnull=False` filter so only mutating rows come back.
- `netbox_spoke.py:55-102` `_kea_sync_loop` — fresh `httpx.AsyncClient(timeout=5.0)` per scope per 5-min cycle (N scopes = N fresh TCP+TLS). Reuse one client across scopes. S.
- `netbox_dcim.py:162` `find_available_prefixes` — full paginated scan of all prefixes inside the RFC1918 block each call. TTL (60-120s) keyed by `(container, prefix_length)`, invalidate on claim/allocate/release/delete. M.

**Per-record journal (M effort, fire-and-forget queue):** `netbox/src/netbox_changelog.py:36`
`extras.journal_entries.create()` POST on every upsert from `sync_vms`/
`sync_devices`/`sync_access_tracker`/`staleness_sweep` — synchronous HTTP POST per
record on the hot path. No bulk journal endpoint exists; route via a bounded
background queue or skip-on-update.

---

## Theme C — Missing timeouts / hangs (robustness)

The hub `request_response` default timeout is **5.0s hardcoded** (`main.py:646`).
For any real fetch (paginated lists, ACME, multi-step NetBox ops, git clone, curl
budgets ≥15s) the 5s default silently produces an empty/wrong answer. Three
sub-classes:

### C1 — 5s-too-tight, silently wrong/empty (H — one-line `timeout=` each)

| # | file:line | op | fix |
|---|---|---|---|
| C1a | `lm/core/src/api.py:444` | `_FW_CMD_MAP` cache warmer — `_FW_FETCH_TIMEOUTS["nat"]=60`/`_FW_FETCH_TIMEOUT_DEFAULT=30` exist at `:327-335` but `_fetch_module` doesn't use them → NAT always times out → cache stays empty | use `_FW_FETCH_TIMEOUTS.get(module_key, _FW_FETCH_TIMEOUT_DEFAULT)` |
| C1b | `lm/core/src/routes/netbox.py:83` | `_netbox_list_get` shared helper for `NETBOX_GET_RACKS/DEVICES/PREFIXES/IPS` — no timeout; **same bug documented at `api.py:471-475`** (uses 30s) — duplicate site | `timeout=30.0` |
| C1c | `lm/core/src/routes/agents.py:35` + `tenants_users.py:111` | `LOAD_ROLE` (network git clone of role repo); sibling `load_agent_role` at `:138` documents "routinely exceeds 5s" and uses 120s — these two sites were missed | `timeout=120.0` |
| C1d | `lm/core/src/main.py:3106` | `OPNSENSE_GET_ALL_RULES` background warmer; spoke curl budget is 15s → 5s guarantees timeout on cold/WAN → cache empty | `timeout=30.0` |
| C1e | `lm/core/src/access.py:496` | `OPNSENSE_GET_ALIASES` in `_fw_alias_map_for`; failure returns `None` and is NOT cached → retries every render | `timeout=30.0` |
| C1f | `lm/core/src/routes/nw.py:144` | `NW_RUN_CONFIG` (multi-line SSH config apply); timeout returns ERROR envelope unwrapped as clean error | `timeout=45.0` |
| C1g | `lm/core/src/api.py:454,460,482` | `CPPM_GET_ACCESS_TRACKER` / `LIST_ENDPOINTS` / `PXMX_LIST_VMS` cache warmers (paginated/large/grab-all) | `timeout=30.0` |

### C2 — M-tier 5s-too-tight (real fetches, exception-tolerant — blanket 30s sweep)

The same one-line `timeout=N` pattern across ~30 sites. Right value per family:
**30s** for NetBox/CPPM/NW/OPNsense/PXMX reads (`dns_dhcp_sync.py:168,186`
DNS_SYNC/DHCP_SYNC push; `routes/nw.py:67,117`; `routes/pxmx.py:176,490,593`;
`routes/setup.py:65`; `routes/netbox.py:203,293`; `routes/cppm.py:53,139,161,180,334,401,433,455`;
`routes/tenants_users.py:187`; `routes/setup_admin.py:288`; `routes/agents.py:92`;
`routes/pxmx_vm.py:304`; `routes/help_assistant.py:91`; `dashboard.py:185`),
**60s** for LE cert ops (`routes/net_services.py:139` LE_REQUEST_CERT/RENEW ACME),
**120s** for LOAD_ROLE (C1c), **30s** for all 14 LDAP UI handlers (`routes/ldap.py:*`
— directory ops over WAN to campus AD can exceed 5s).

### C3 — Hub-side hang (no deadline → blocks loop / parks handler forever)

| # | file:line | pattern | fix |
|---|---|---|---|
| C3a | `lm/core/src/routes/ws_transport.py:50` | `websockets.connect(upstream_uri)` hub proxy dial to pxmx loopback — no `open_timeout`; a hang blocks the hub loop | `open_timeout=5` |
| C3b | `lm/core/src/main.py:1894` | `auth_json = await websocket.recv()` hub spoke-handshake first frame — no `wait_for`; a spoke that opens TCP then sends nothing hangs the handler | `wait_for(websocket.recv(), timeout=15)` |
| C3c | `lm/core/src/messaging/agent_hosting.py:291` | hub agent-handshake first `recv` (acks at `:314/:334` ARE wrapped — the initial recv is NOT) | `wait_for(..., timeout=15)` |
| C3d | `lm/core/src/main.py:2148` + `agent_hosting.py:355` | hub main spoke/agent message loops — no per-read deadline; silent peer parks the handler forever | per-read `wait_for(..., timeout=N)` |
| C3e | `lm/core/src/messaging/control_plane.py:769` | `async with websockets.connect(self.hub_url,...)` spoke→hub connect — no `open_timeout`; every spoke uses this | `open_timeout=10` |
| C3f | `lm/core/src/messaging/control_plane.py:149,1127,1132,1111,145,375` | `_run_git`/`git fetch`/`git rebase --abort`/`git reset --hard`/`git config`/`pip install` — no `timeout=` in the SPOKE_UPDATE path | `timeout=` per call (60-300) |
| C3g | `lm/core/src/update_pipeline.py:200,224,432` + `repo_sync.py:80,102` | hub-side `await proc.communicate()` (git rev-parse/ls-remote/pull) — no `wait_for` | `wait_for(proc.communicate(), timeout=N)` |
| C3h | `lm/core/src/messaging/control_plane.py:1279,1283` | inline `subprocess.run(["sudo","hostnamectl"/"sed"...])` in async `SPOKE_SET_HOSTNAME` — blocks loop, no timeout | `timeout=10-15` + `to_thread` |
| C3i | `netbox/src/netbox_spoke.py:137` | `subprocess.run(["git","pull",...])` in async `SPOKE_UPDATE` — no timeout, no `to_thread` | `timeout=120` + `to_thread` |

**Spoke/agent-side hangs (M-tier):** per-spoke/agent `websockets.connect` with no
`open_timeout` (pxmx `agent.py:1760`, `pve_cmds.py:785`; cs `server.py:4555,5189`,
`proxmox_agent.py:1976`; `cs/proxmox/proxmox-agent.sh:4556`); spoke/agent
`async for websocket` with no per-read deadline (`control_plane.py:930`,
`spoke_gateway.py:59,37`, `agent.py:1793,1840`); `await proc.communicate()` with
no `wait_for` (`agent_spoke.py:379,506`, `opnsense_engine.py:79`).

### C4 — Stampede-to-one-spoke / unbounded fan-out

| # | file:line | pattern | fix |
|---|---|---|---|
| C4a | `lm/core/src/nw_discovery_sync.py:236` | `gather(*fetches)` over spokes × devices with no Semaphore; a single spoke backing M devices fires M concurrent `request_response` to the SAME spoke WS (2M if mac_command). Push phase at `:571` IS bounded — fetch is not. | wrap `_fetch` in `async with sem` (reuse `_nw_discovery_concurrency()`) |
| C4b | `lm/core/src/api.py:541` | `_refresh_module_all_tenants`'s `while True` `gather(*tasks)` NOT gated by `_cache_semaphore` (only `_preload_all_parallel:499` acquires it); every cache invalidation fans N tenant calls | `async with _cache_semaphore` or route via `_preload_all_parallel` |
| C4c | `lm/core/src/fw_discovery_sync.py:245` | fetch-phase `gather` over firewall spokes × 2 unbounded (push at `:416` IS bounded) | reuse `_fw_discovery_concurrency()` |
| C4d | `lm/core/src/routes/pxmx.py:75,232,248` | `GET_AGENTS`/OPN/`GET_VM_INFO` fan-out to every agent/opn/pxmx spoke — no cap | `Semaphore(8)` around `_one` |
| C4e | `lm/core/src/messaging/agent_hosting.py:559` | broadcast `gather(*tasks)` over every connected agent — no cap | `Semaphore(16)` |
| C4f | `lm/core/src/dns_dhcp_sync.py:167,184` | sequential DNS then DHCP sync, each fetching the full NetBox IP list independently (2 paginations/cycle) | fetch once, `gather` the two spoke pushes |

### C5 — Unbounded list / pagination (memory-blowup / DoS)

| # | file:line | pattern | fix | effort |
|---|---|---|---|---|
| C5a | `lm/core/src/routes/netbox.py:44-92` + `netbox/src/netbox_engine.py:86-114` | `_netbox_list_get` paginates up to `max_pages=200 × limit=500 = 100k rows`, materializes whole flat list; hub routes accept only `site/tenant/prefix/device` — no `limit/offset/page`, no server cap | add `limit/offset` route params + server cap <100k or stream | M |
| C5b | `lm/core/src/routes/ldap.py:16-111` + `ldap/src/ldap_manager.py:65,89,124` | `LIST_OUS/USERS/GROUPS` relayed whole; spoke `search_s` with no `size_limit`/`time_limit`/RFC 2696 paged search — 100k-user dir returns 100k entries | `limit/offset` + RFC 2696 paged search + `size_limit` | M |
| C5c | `lm/core/src/routes/pxmx.py:593` + `proxmox_spoke.py:340-448` | `PXMX_LIST_VMS` aggregates `vms` across every agent + disk cache, concatenated whole; no count cap | `limit/offset` to `/api/pxmx/vms`, cap agent fan-out | M |
| C5d | `lm/core/src/routes/ws_transport.py:10-24` + `main.py:1894,2148` | WS server has no `max_size`; `recv()`+`json.loads()` unbounded — the "16 MiB max_size" comment at `main.py:2465/3556` is stale (not applied on the Starlette/uvicorn path) | set explicit `max_size` on uvicorn WS config, reject >16 MiB with 1009 | S |
| C5e | `opnsense/src/opnsense_engine.py:487-507,255-294` | `get_all_aliases` + `get_dns_records` return whole (rules/NAT/DHCP leases cap to 200) | cap `processed`/`processed_dns` to 200 | S |

### C6 — Polling/retry discipline (L)

- `lm/core/src/main.py:3240-3245` `run_opnsense_polling_loop` — `interval_hours = config.get("opnsense_poll_interval", 1)` with no `max(1, ...)`; a 0 config → `sleep(0)` busy-loop. All sync mixins clamp `>=60`; this one doesn't. **S.**
- `lm/core/src/le_spoke.py:113-122` `_renew_loop` fixed 60s, no jitter — every le spoke hits the same 60s beat on hard-down. Add `60 + random.uniform(0,30)`. **S.**
- `lm/core/src/messaging/mailbox.py:43` `retry_intervals=[5,15,60,300,900]` deterministic — ±20% jitter. **S.**

---

## Theme D — Caching opportunities (where caching API responses helps)

### D1 — Hub cache gaps (drifted agent's findings, high-quality)

| # | file:line | what's not cached | fix | effort |
|---|---|---|---|---|
| D1a | `lm/core/src/routes/dashboard.py:39-46` `_compute_tenant_counts` | 5 live `request_response` calls (NETBOX/CPPM/PXMX/NW/OPNsense) per dashboard load, not cached | 60s memoization (the per-tenant gather at `:108-123` already has it; counts don't) | S |
| D1b | `lm/core/src/routes/netbox.py` claim-device (`:300-303`) + options + sites list | live every call (claim-device already refreshed via `_refresh_module_all_tenants` after mutation, but options/sites are live) | TTL cache on sites/options | S |
| D1c | `lm/core/src/routes/pxmx.py` aggregate opnsense + proxmox | live per Hypervisors-tab load | TTL cache | S |
| D1d | `lm/core/src/routes/cppm.py` unknown-devices | live | TTL cache | S |
| D1e | `lm/core/src/routes/firewall.py` admin firewall reads | live-always (non-admin uses tenant cache; admin bypasses it) | short-TTL for admin reads | S |
| D1f | `lm/core/src/routes/dashboard.py:143` `/api/search` | no memo; same `q` re-fans 5 spokes | short-TTL (5-15s) keyed by normalized `q` | S |

### D2 — Spoke cache opportunities (per-spoke agent)

**netbox** — the picklist TTL cache (Theme B note) covers `_resolve_tenant_ci`,
`get_device_form_options`, `get_tenants/get_sites/get_system_health/get_dhcp_prefixes`,
`_ensure_device_role/_ensure_device_type/_resolve_site`, claim/allocate slug GETs.
One decorator, S effort, resolves 5 findings. **Highest-leverage spoke cache win.**

**opnsense** — (1) `opnsense_engine.py:37-96` `_request` spawns a fresh `curl`
subprocess (new TCP+TLS+Basic auth) per call — replace with a persistent
`httpx.AsyncClient` keep-alive (M, the big one). (2) `_alias_category_map:422`
fetched per `get_all_aliases` + every alias write — TTL 5-10 min (S). (3)
`get_rules_for_ip:776` re-fetches whole ruleset per IP query even though
`OPNSENSE_GET_ALL_RULES` is cached — read cache first (S). (4) `get_nat_policies`
probes 3 endpoints sequentially — `asyncio.gather` (S). (5) `get_status:377`
ignores the cached `GET_SYSTEM_HEALTH` entry — return cached w/ live fallback (S).
(6) `refresh_cache:88` stores `OPNSENSE_GET_DHCP_LEASES` every refresh but
`handle_command` cache_map excludes it — wasted curl; drop from refresh_map (S).

**nw** — stateless by design (spoke-side cache is hub-side `NwCacheMixin`).
(1) `nw_engine.py:221-284` every datum method opens a fresh `CliSession`
(`asyncssh.connect`+login+paging+enable) or `RestSession` (`httpx.AsyncClient`)
— `NW_POLL` = 5 independent SSH connections per poll. Per-device connection
pool across a poll's sub-calls (M, the big one). (2) `snmp_io.py:362` +
`nw_engine.py:187` — `IF_PREFIX` walked up to 3× per poll (interfaces/arp/mac_table);
build iftable once per poll and pass via existing `ifaces=` param (S). (3)
`nw_engine.py:402` `list_devices` no spoke cache, re-runs every command —
short-TTL (30-60s) fleet reachability or rely on hub cache (S).

**cppm** — (1) `spoke.py:30,141-148` `self._cache` populated only on explicit
`CPPM_REFRESH_CACHE` (no scheduled caller), never expires, miss goes fully live
— add TTL (30-60s) or schedule refresh on a timer (S/M). (2)
`queries.py:282` `get_nac_status` = 4 sequential HTTP RTTs — concurrent fetch (S).
(3) `queries.py:1034` `search` = 2 exact GETs + bounded paged scan, serial, no
cache — short-TTL (5-15s) keyed by normalized `q` (S). (4) `queries.py:762,672`
`sync_endpoints` pages `/api/endpoint` 2-3× per batch (mac map + ip map + tagged
delete pass) — unify into one paged pass, three outputs (M). (5) `spoke.py:90-124`
`TEST_AUTH` builds fresh `requests.Session` each call — reuse `self.client.session` (S).

**le** — (1) `acme.py:360` `read_material(domain)` reads + x509-parses `not_after`
on every `LE_GET_CERT`/`_issue`/`_renew`/reconcile tick — mtime-memoize on
`fullchain.pem`, invalidate on ISSUE/RENEW/REVOKE (S). (2) `acme.py:41` `shutil.which(CERTBOT_BIN)`
+ `:64` `dpkg -s` per DNS-01 issue — `@functools.lru_cache` / TTL 60s (S).

**pxmx** — (1) `agent.py:2266` `_telemetry_loop` (60s hot path) re-runs
`get_vm_list` + `get_node_stats` + per-VM `_annotate_vm_interfaces` (pvesh per VM)
every tick, none TTL-cached — short TTL (5-10s) on `/cluster/resources` (fetched
**twice** per tick by `get_vm_list` + `get_node_stats`), 30-60s on per-VM interface
annotation keyed by `(node,vmid,status)` (M). (2) `agent.py:713` `get_node_stats`
re-fetches `/cluster/resources` already fetched in the same tick — fetch once,
share (S).

**cs** — (1) `cs/lm-spoke/control_plane.py:199` `_cs_telemetry_relay_loop` (10s hot path)
rebuilds `usb_vmid_index`/`vm_tier_index`/per-client `client_has_usb` every tick
by iterating every host's `vms`+`usb_state` (O(hosts×vms×clients)) — cache on
`proxmox_states` mutation or 5-10s TTL; 30s TTL on `collect_dhcp_status` subprocess (M).
(2) `cs/webui-spoke/routers/simulations.py:182` `api_sim_clients` re-reads
`simulation.conf` + `client-setup.conf` from disk every call, NO mtime cache (unlike
`api_simulations` which has `_sim_conf_cache`) — extend mtime cache (S). (3)
`history.py:21` `_load_history` reads + JSON-parses entire `central_history.jsonl`
every call — in-memory list refreshed on append (S). (4) `routers/config.py:42,73,97`
`api_config*` re-read conf from disk every call — mtime-memoize (S). (5)
`routers/proxmox.py:502` `api_create_console_session` opens fresh
`httpx.AsyncClient(verify=False)` per console-open — module-level shared client (S).

**dns** — (1) **DnsDhcpSyncMixin** (`dns_dhcp_sync.py:196-217`) re-fetches full
NetBox IP + prefix lists, rebuilds payloads, and unconditionally pushes
`DNS_SYNC` (`unbound-control reload`, 10s) + `DHCP_SYNC` (3 Kea RPCs) every 300s
regardless of whether NetBox changed — keep a payload hash, skip the spoke push
when identical. **Biggest periodic-loop win; covers DNS+DHCP.** M effort. (2)
`unbound_manager.py:56-80` `list_records` reads + regex-parses conf from scratch
on every call (DNS_LIST + status/add/update/delete) — `os.stat(conf_path).st_mtime`-
keyed memoize, invalidate in `sync()` (which writes the file). Single fix covers
list_records across status/add/update/delete. S.

**dhcp** — (1) DnsDhcpSyncMixin skip-if-unchanged (same as DNS #1). (2)
`kea_manager.py:21-35` `_rpc` does a fresh `requests.post` per call, no shared
`requests.Session` — one `requests.Session` in `__init__`, free keepalive. S.
(3) `kea_manager.py:47` `get_config` (full Dhcp4 config) before every CRUD op,
twice for `update_reservation` — in-memory snapshot invalidated after `_set_config`.
S-M. (4) `kea_manager.py:39` `list_subnets` extra RPC per status/stats/list_leases
— short-TTL (5-10s) or invalidate in `sync()`/`_set_config()`. S.

**ldap** — `ldap_manager.py:21-39` every LDAP command opens a new TCP connection
+ `simple_bind_s` with admin creds; the `_get_connection` write/search path never
`unbind_s` (explicit FD-leak docstring) — introduce a pooled/reusable bound
connection (`ReentrantLDAPObject` or single long-lived conn under `threading.Lock`,
all commands already run via `asyncio.to_thread`); tear down on `UPDATE_CONFIG`.
**Correctness + perf.** M effort.

---

## Theme E — WebUI JS re-render storms

| # | file:line | issue | fix | effort |
|---|---|---|---|---|
| E1 | `lm/WebUI/main.js` logs panel | giant `innerHTML` render of full log list, no pagination/virtualization | paginate/virtualize, cap DOM nodes | M |
| E2 | `lm/WebUI/main.js` CS filter inputs (`csClientFilter`/`csSimChecksFilter`) | no debounce → filters re-render the whole list per keystroke | `debounce(fn, 200ms)` | S |
| E3 | `lm/WebUI/main.js` mutation handlers | full-list re-fetch + full re-render after every add/delete (the cache-refresh-on-mutation work in commit `dd59ac8` triggers the refresh, but the render path re-renders the entire list rather than patching the one row) | patch the single row from the refreshed cache | M |
| E4 | `lm/WebUI/main.js` unbounded list renders | no pagination on long lists (devices/VMs/sessions) | paginate server-side (pairs with C5) | M |
| E5 | `lm/WebUI/main.js` `loadSpokesAndAgents` | 3 sequential awaits | `Promise.all` | S |
| E6 | `lm/WebUI/main.js` `_renderDashboardLists` | extra fetch on 10s poll | reuse the polled data already in hand | S |
| E7 | `lm/WebUI/main.js` `updateStatus` | rebuilds nav every 10s | diff/patch, don't full rebuild | S |
| E8 | `lm/WebUI/main.js` `csVmBulk` | N sequential awaits | bounded `Promise.all` chunks | S |
| E9 | `lm/WebUI/main.js` CS telemetry WS handler | full re-render on every telemetry frame | patch changed rows only | M |
| E10 | `lm/WebUI/main.js` `_ddSyncStatusLine` | extra fetch | reuse polled data | S |
| E11 | `lm/WebUI/main.js` per-row `addEventListener` | per-render listener attachment leaks | event delegation | S |
| E12 | `lm/WebUI/main.js` localStorage parse per render | parse every render | parse once, cache | S |
| E13 | `lm/WebUI/main.js` `cacheStatusPoller` 1500ms | aggressive poll | raise to align with cache TTL | S |

---

## Highest-leverage fixes (apply in this order)

**Quick wins (each S, mostly one-line):**
1. **A2** — netbox `get_status` `_run_sync` (latent spoke-stall, same class as the cs-svr-02 outage).
2. **A5** — pxmx `psutil.cpu_percent(interval=1)` → drop `interval=1`.
3. **A6** — pxmx `_hw_check` → use existing `await _journalctl`.
4. **A8/A9** — cs `_save_relay_state` + `_save_commands` → `to_thread` (single fix each, many callers).
5. **C1a/C1b** — `_fetch_module` use `_FW_FETCH_TIMEOUTS`; `routes/netbox.py:83` `timeout=30.0`.
6. **C1c** — `LOAD_ROLE` `timeout=120.0` (2 sites; sibling already documents it).
7. **C3a/C3b/C3c** — hub WS `open_timeout=5` + handshake `wait_for(recv, timeout=15)`.
8. **C4a** — `nw_discovery_sync.py:236` Semaphore (only true stampede-to-one-spoke).
9. **B1** — netbox staleness: hoist the check above the `.get()` (pure reorder, biggest DB payoff).
10. **A11** — cs `_beacon` `to_thread` the host helpers (removes ~6s stall per sim iteration).

**Single-decorator wins (S, cover many sites):**
- NetBox picklist TTL cache (D2 netbox) → 5 findings.
- `list_records` mtime-memoize (D2 dns) → covers status/add/update/delete.

**Medium-effort high-impact (M):**
- **A1** — hub `mailbox._asave` (hub-side twin of the cs fix).
- **B2/B3/B4/B5** — eliminate per-row pynetbox `.get(id)`+`.save()` (biggest DB cost).
- **D2 opnsense** — persistent `httpx.AsyncClient` (kills curl-per-call).
- **D2 nw** — per-poll SSH connection pool (kills 5× handshake per poll).
- **D2 ldap** — connection pool + fix unbind leak (correctness + perf).
- **D2 dns/dhcp** — DnsDhcpSyncMixin skip-if-unchanged (biggest periodic-loop win).
- **D2 pxmx** — telemetry-loop `/cluster/resources` TTL cache (fetched 2× per tick).
- **C5a/C5b/C5c** — `limit/offset` + server cap on NetBox/LDAP/PXMX list endpoints.

---

## Verified clean (reference — no action)

Reconnect backoff (5→300s), SPOKE_UPDATE per-repo tip gate, sync-mixin `>=60s`
cadence clamp (all mixins), `requests.post` in kea (timeout=10), already-wrapped
`proc.communicate()` (main.py:2868/2985, setup_misc, agent_spoke, ldap_spoke,
le/acme), already-wrapped `recv()` (main.py:1984, control_plane:802,
agent_hosting:314/334, agent:1779), already-bounded gathers (fw_discovery:416,
access:382 Sem8, nw_discovery:581, endpoint_sync:333, realtime_nac:320,
api:512 `_cache_semaphore`, dashboard:123 Sem5, pxmx agent:952 Sem16),
already-capped spoke responses (CPPM LIST_ENDPOINTS/ACCESS_TRACKER limit=200,
OPNsense rules/NAT/DHCP cap 200, help_assistant merged[:50]), explicit timeouts
on `routes/firewall.py`, `routes/pxmx_vm.py`, `routes/console.py`,
`simulations/routes.py`, and almost all background-sync-loop `request_response`
(staleness 180s, fw_discovery 30/120s, nw_discovery 30-120s, endpoint 30/180s,
realtime_nac 30/120s, vm_sync 30/180s, dns_dhcp fetch 30s).