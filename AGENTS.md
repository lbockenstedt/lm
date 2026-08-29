# AGENTS.md — `lm` (the hub)

**This is the hub and the project master registry.** Control plane, REST API, WebUI, and the
canonical documentation set for all 16 Lab Manager repos.

- **Repo:** `github.com/lbockenstedt/lm`
- **Canonical docs:** [`docs/`](docs/) — one page per module. **This directory is the source of truth for the entire fleet.**
- **Fleet map:** [`../AGENTS.md`](../AGENTS.md) *(only present in a side-by-side checkout)*

## What LM is

A modular, containerized, **multitenant** "private cloud orchestrator" for lab resources.
Users declare intent; LM implements it across the hardware pool. See
[`PROJECT_DESCRIPTION.md`](PROJECT_DESCRIPTION.md).

One hub, many spokes. Each spoke is its **own repo** wrapping one external system (Proxmox,
OPNsense, NetBox, ClearPass, LDAP, Kea, Unbound, switches, TrueNAS, certbot) and dialling
`/ws/spoke` on port 443. Some spokes bridge further out to agents on remote hosts.

## Components — each subdir is a separately-deployed app

| Path | Role |
| :--- | :--- |
| `core/src/` | **Hub proper.** `main.py::LabManagerHub`, `api.py` (FastAPI), `routes/`, `messaging/`, `gateway/`, `security/`. |
| `WebUI/` | Browser front end. Vanilla JS/HTML, **no build step**. |
| `agent/src/` | **Generic agent** — `agent_spoke.py::GenericAgent`. One agent per node, hosting module *roles* as sub-spokes. How `dns`/`dhcp` normally deploy. |
| `docs/` | Canonical fleet documentation. |
| `console/`, `proxy/`, `statuspage/`, `henet/`, `collab_sink/` | Supporting hub-side services. |
| `dns/`, `dhcp/`, `qa/`, `client_sim/`, `clearpass/` | Hub-side installers / thin wrappers; the real source lives in the sibling repo. |
| `scripts/` | Operator tooling — `lmctl`, `set-version.sh`, watchdog, load tests. |
| `provisioning_repos/` | Recipes for lab services LM can stand up (kea, ldap, netbox, pihole, graylog, iperf, consolepi). |

## Key reading

| Question | File |
| :--- | :--- |
| How does the mesh fit together? | `docs/architecture-topology.md` |
| What must a module implement? | `MODULE_REQUIREMENTS.md` |
| Where does logic belong? | `docs/architecture-spoke-heavy-lifting.md` |
| Install anything | `README.md` (every module, one table) · `docs/install-flags.md` |
| Env vars | `docs/environment-variables.md` |
| Agents & roles | `docs/generic-agent.md` · `docs/agents-and-skills.md` |
| WebUI | `docs/webui.md` · `docs/webui-style.md` |
| New module | `docs/template-repo.md` |
| Logging contract | `docs/logging-observability-contract.md` |

## Hub-specific gotchas

- **`hub_discovery.py` is vendored three times** — `core/src/messaging/hub_discovery.py` (canonical), `pxmx/src/discovery.py`, `pxmx/agent/src/discovery.py`. **They must change together.**
- **The hub is a relay, not a brain.** Resist adding module logic here. The canonical example: Client-Sim auto-provisioning lives in the *pxmx agent*, not the hub, not the cs spoke.
- **Changing a message type is a fleet-wide contract change.** Spokes deploy independently — stay backward-compatible.
- `docs/` pages are copied verbatim into each module repo's own `docs/`. Update here first.
- `state_cache.json` is a committed runtime artifact, not source.
- See `UNIMPLEMENTED_ROUTES.md` and `CODE_DIAGNOSABILITY_REVIEW.md` for known gaps.

## Fleet conventions (identical in every LM repo)

- **Python 3.11**, FastAPI + `websockets` + `asyncio`. WebUI is dependency-free vanilla JS — **no npm build step exists anywhere in this project**.
- **`VERSION` is `MAJOR.NN` and branch-owned.** A bot bumps the last segment. **Never bump it by hand.** Promotion carries code only.
- **Branching: `dev -> qa -> main`.** `qa` and `main` need a PR; `ci.yml` is the required check. Direct pushes to `dev` are allowed.
- **CI runs one pytest process per component.** Components share top-level module names (`control_plane.py` exists in most repos) and collide in a single process.
- **Installers are idempotent** — re-running updates code and preserves credentials. Common flags: `--hub` (bare hostname is normalised to `wss://...:443`), `--id`/`--name`, `--secret`, `--hub-secret`, `--all-prereqs`.
- **Transport:** WebSocket on 443, mailbox pattern, **push-ack-retry — no fire-and-forget**. Heartbeat 30s; yellow at >=120s, red at >=300s. Hub queues 24h for offline spokes.
- **TLS:** encrypted but **verify-OFF by default** (self-signed hub cert). Verification is opt-in at install time via `--tls-verify` / `--tls-ca-cert` — never by hand-editing `.env`.
- **Heavy lifting belongs in the spoke, not the hub.** The hub is transport, state, policy and UI. See `lm/docs/architecture-spoke-heavy-lifting.md`.
- **API-first:** every operation exposes an API; the WebUI only ever calls that API.
- **Atomic transactions:** a mid-chain failure rolls back every preceding step and reports a before/after diff. No zombie resources.
- **Multitenancy is not optional:** isolation rides on Proxmox labels + NetBox tenant IDs. New resources carry tenant context.

## Rules

1. **One repo per change.** Cross-repo work is separate PRs, and the wire contract must stay backward-compatible because the two sides deploy independently.
2. **Read the canonical doc first** (linked above) — it is usually more current than this repo's README.
3. **Never hand-edit `VERSION`.**
4. **Check you are editing the live path,** not a preserved legacy one.
5. Match surrounding style. Comment only what needs clarifying.
