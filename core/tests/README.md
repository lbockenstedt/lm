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
| 1. Tenant subnet filter | `test_subnet_filter.py` | `subnet_filter_config` / `subnet_filter_enabled` resolution (defaults, overrides, coercion) — the server-side isolation gate |
| 2. Hub self-update gate | `test_update_gate.py` | `_update_available` commit-SHA decision (git vs non-git, unknown-remote safe fallback, force, VERSION fallback) |
| 3. Spoke relay contract | `test_relay_contract.py` | `_spoke_payload_or_raise` — spoke ERROR → HTTP 502, SUCCESS passthrough |
| 4. Endpoint sync | `test_endpoint_sync.py` | `IPAM_SOURCES` registry shape + `_endpoint_sync_source` fallback (modular source swap) |

## What's NOT yet covered (TODOs in the files)

- Prefix-matching itself (`simulations/tenant_filter.py`) — needs a prefix-set fixture.
- Live `get_local_commit` / `get_remote_commit` (git rev-parse / ls-remote) — host integration test.
- Relay routes end-to-end via `fastapi.testclient.TestClient` against `create_app(hub)` with a `FakeHub.request_response` — would assert 502/200 at the HTTP layer, not just the helper.
- `sync_tenant_endpoints` full IPAM→CPPM loop with canned spoke payloads.

The pure decision functions were extracted from `perform_update` and the
`_relay_spoke` closure specifically so these paths are testable without I/O;
the integration TODOs above layer on top of that.