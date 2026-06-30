# Hub backend tests

Pytest scaffold covering the four critical paths that most warrant regression
protection (the security/enforcement boundaries + update detection). Run from
`core/`:

```
core/venv/bin/pip install -r core/requirements-dev.txt   # first time
core/venv/bin/python -m pytest                            # run all
core/venv/bin/python -m pytest tests/test_update_gate.py  # one file
```

`conftest.py` puts `core/src` on `sys.path` (the way the hub runs) so tests
import modules as top-level (`import access`, `import api`, …). `_fakes.py`
holds minimal `FakeHub` / `FakeState` stand-ins.

## What's covered

| Path | File | What's locked in |
|---|---|---|
| 1. Tenant subnet filter | `test_subnet_filter.py` | `filter_config` / `filter_enabled` resolution (defaults, overrides, coercion) — the server-side isolation gate |
| 2. Hub self-update gate | `test_update_gate.py` | `_update_available` commit-SHA decision (git vs non-git, unknown-remote safe fallback, force, VERSION fallback) |
| 3. Spoke relay contract | `test_relay_contract.py` | `_spoke_payload_or_raise` — spoke ERROR → HTTP 502, SUCCESS passthrough |
| 4. Endpoint sync source registry | `test_endpoint_sync.py` | `IPAM_SOURCES` registry shape + `_endpoint_sync_source` fallback (modular source swap) |
| 5. Prefix matching | `test_tenant_filter.py` | `extract_addrs` / `filter_items_by_prefixes` / `filter_firewall_rules` / `firewall_rule_in_prefixes` / `build_alias_map` — empty→show-all, in/out-of-prefix, alias/wildcard show, nested-alias resolution |
| 6. Endpoint sync flow | `test_endpoint_sync_flow.py` | `sync_tenant_endpoints` with canned `request_response` — extract→push replace=True, spoke-offline/tenant-unbound/IPAM-error/CPPM-error branches |
| 7. State persistence | `test_state_persistence.py` | dirty-flag mechanics — in-memory mutator marks dirty, `_flush_if_dirty` writes-once + clears, no-op when clean, failed write restores dirty, `save_state()` clears, racing mutation not lost |

## What's NOT yet covered (TODOs in the files)

- Live `get_local_commit` / `get_remote_commit` (git rev-parse / ls-remote) — host integration test (needs a real git checkout at a known path).
- Relay routes end-to-end via `fastapi.testclient.TestClient` against `create_app(hub)` with a faked `_session_user` + `request_response` — would assert 502/200 at the HTTP layer, not just the `_spoke_payload_or_raise` helper. The pure-helper contract is already locked in; the HTTP-layer test needs an auth-cookie harness.

The pure decision functions were extracted from `perform_update`, the
`_relay_spoke` closure, and `persistence_loop` (`_flush_if_dirty`) specifically
so these paths are testable without I/O; the integration TODOs above layer on
top of that.