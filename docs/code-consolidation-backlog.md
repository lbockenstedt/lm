---
summary: "Backlog of cross-repo duplicate code still to consolidate (Tiers 2-4 of the duplicate-function sweep), plus deliberately-vendored copies and how to re-run the scanner."
keywords: [duplication, consolidation, vendored, refactor, backlog, dupscan]
---

# Code consolidation backlog

## How the sweep works

`scripts/dupscan.py` parses every Python file in the sibling repos and hashes the body of each function that is 6 lines or longer. Tests are skipped. It reports two kinds of groups:

- **exact**: identical bodies.
- **structural**: identical once variable names and strings are normalised.

Re-run it with:

```bash
python3 lm/scripts/dupscan.py   # from the parent dir holding all repos
```

It prints a summary and writes `/tmp/dupscan.json`.

### Baseline (2026-10-24)

| Run | Exact groups | Redundant lines (exact) | Structural groups |
| :-- | --: | --: | --: |
| Before Tier 1 | 413 | ~11.3k | 61 |
| After the pxmx Tier 1 cleanup | 384 | ~9.9k | — |

Retiring the dns/dhcp siblings removes the largest remaining block, about 5k lines.

## Tier 1: done

- **pxmx:**
  - `pxmx/src/drive_health.py` was deleted. It was unused at runtime; the spoke fetches drive health from each host agent.
  - `pxmx/src/discovery.py` was deleted. `install_pxmx.sh` now runs `agent/src/discovery.py`.
- **dns/dhcp sibling repos:**
  - Their remaining fixes were ported into `lm/dns` and `lm/dhcp`, including the DHCPv6 HA worker-op allowlist.
  - The siblings are now marked retired.
  - AppBuilder's `log_scan` routes dns/dhcp issues to `lm`.
  - `pr_review.check_parity` flags code changes made in the retired repos instead of asking for twin PRs.
- **Vendoring headers corrected:**
  - `resource_pressure.py`: the canonical copy is `cs/lm-spoke/src`, vendored into `pxmx/agent/src`.
  - `probe_signatures.py`: the canonical copy is `lm/core/src/security`, vendored into `ab`.

### Still open from Tier 1

- **Archive the GitHub repos** `lbockenstedt/dns` and `lbockenstedt/dhcp`. This needs an owner decision.
- **Kea→Unbound real-time DNS hook:** decide whether to port it. It lives in the sibling dhcp repo, commits d844d7e, 58ead78, 4fb3c03 and b0be963. It was not ported because lm uses the lease→DNS sync in core `dns_dhcp_sync.py`.

## Deliberately vendored: these need packaging, not deletion

Each copy below lives in a separately deployed tree that has no shared import path. Consolidating any of them needs a shared package; see Tier 2.

| File | Copies | Guard |
| :-- | :-- | :-- |
| `check_eval.py` | cs `lm-spoke/src` (canonical), `webui-local/app`, `webui-spoke`, `lm/core/src/simulations` | SHA-pin test in each tree |
| `hub_discovery.py` | `lm/core/src/messaging` (canonical), `pxmx/agent/src/discovery.py` | manual. **Drifted:** the pxmx copy has the extra `resolve_agent_url` / `_AGENT_LISTENER_CANDIDATES` code. Back-port it to the canonical copy, then add a SHA-pin test. |
| `collab_pcap.py` | `cs/clients/linux`, `lm/collab_sink` | header note only |
| `resource_pressure.py` | `cs/lm-spoke/src`, `pxmx/agent/src` | header note only |
| `probe_signatures.py` | `lm/core/src/security`, `ab` | header note only |
| `aruba.py` (not byte-identical) | cs `lm-spoke/src`, `webui-local/app`, `webui-spoke/routers`, `lm/core/src/simulations` | none. About 900 shared lines; reconcile the copies, then vendor them. |
| `acme.py` (not byte-identical) | cs `webui-local/app`, `webui-spoke` | none |

**Quick win:** add the `check_eval`-style SHA-pin test to every copy that has only a header note.

## Tier 2: shared "agent runtime" package (lm core ↔ pxmx agent ↔ ab)

These copies are near-identical and could become one `lm-common` package. Pick a packaging model first: vendor the package by CI sync (the way ab already syncs `bump_version.py`), or pip-install it from the lm repo.

| Area | Locations | ~Lines |
| :-- | :-- | --: |
| Hub discovery / mDNS (`discover_hub_url`, `_mdns_discover`, `_dns_candidates`, `_resolve_host`, `_own_ipv4s`, `_resolv_search_domains`) | `lm/core/src/messaging/hub_discovery.py`, `pxmx/agent/src/discovery.py` | 500 |
| Update recovery | `lm/core/src/update_recovery.py`, `pxmx/agent/src/update_recovery.py` | 370 |
| `dep_guard` | `lm/core/src/dep_guard.py`, `pxmx/agent/src/dep_guard.py` | 90 |
| `os_update` | `lm/core/src/os_update.py`, `pxmx/agent/src/os_update.py` | 50 |
| Exception relay hooks (`_hook`, `_hub_excepthook`, `_install_uncaught_exception_relay`, `_asyncio_exception_relay`, `set_log_level`) | ab, lm, pxmx (5 places) | 60 |
| `encode_frame`, `run_local_command`, `_check_allowlisted`, `is_hub_local`, `_ws_keepalive_env` | ab, lm agent/core, pxmx agent | 120 |
| `ab/hub_agent.py` ↔ `lm/agent/src/spoke_client.py` connection helpers | ab, lm | 80 |
| `ab/oidc.py` ↔ `lm/core/src/security/oidc.py` | ab, lm | 55 |
| Command runner | `lm/agent/src/command_runner.py`, `lm/core/src/command_runner.py` (+1) | 80 |
| Spoke boilerplate: `get_version`, `__init__`, and in dhcp/dns/lm `transaction`, `_build_transport`, `_agent_listener_enabled`, `_standdown_removed` | dhcp, dns, kvm, ldap, lm, opnsense, pxmx, nw, truenas | 150 |

## Tier 3: simulation pollers (cs ↔ lm hub)

The cs spoke and the hub each run a copy of the Central/Mist telemetry logic. Introduce a shared poller base class (Central and Mist differ only by API adapter), and vendor it the way `check_eval.py` is vendored.

| Area | Locations | ~Lines |
| :-- | :-- | --: |
| `mist.py` | `cs/lm-spoke/src`, `lm/core/src/simulations` | 450 |
| Central vs Mist hub pollers (20 identical fns) | `lm/core/src/simulations/central_hub_poller.py` ↔ `mist_hub_poller.py` | 270 |
| Spoke pollers | `cs/lm-spoke/src/central_poller.py` ↔ `mist_tracker.py` (+2) | 380 |
| `sim_quota.py` | `cs/lm-spoke/src`, `lm/core/src/simulations` | 200 |
| `_cc_*` / `_mist_cc_*` thresholds, `poll_alerts_and_insights`, `_new_central_*`, `_reason_*`, `_ensure_token`, `list_sites` | cs, lm | 450 |
| `local_store` ↔ `simulations/helpers` | cs, lm | 35 |

## Tier 4: CI boilerplate. Leave as is.

`bump_version.py` (17 repos) and `test_promote_version_docs.py` (16 repos) are byte-identical and already synced from ab. They are intentional.

## Smaller within-repo duplicates (opportunistic)

- `lm/core/src/routes/oci_nsg.py` ↔ `oci_vault.py`: shared OCI client setup.
- `lm/core/src/routes/help_assistant.py` ↔ `request_assistant.py`.
- `lm` `_fw_attribute` / `_nw_attribute` / `_rt_attribute`, and `_nw_devices_for_spoke` / `_truenas_appliances_for_spoke`.
- `cs/lm-spoke/src/sim_primitives.py` ↔ `simulation_engine.py`.
- `ab/main.py` ↔ `ab/watchdog.py`.
- `cs/webui-local/frontend/shared/shared_utils.py` ↔ `cs/webui-local/shared/shared_utils.py`.
