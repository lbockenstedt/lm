# bugfixer — Autonomous GitHub Issue Fixer

Autonomous bot, and an optional hub **agent** (not a spoke). Repo: `bugfixer`. See [architecture-topology.md](architecture-topology.md).

## Role & module_type

A standalone autonomous bot that polls GitHub repos for issues labeled `automated-fix`, generates code fixes via local/cloud LLMs, verifies (internal tests or external QA), iterates up to 3×, pushes to a branch (PR) or directly to main (trusted repos), and notifies an external infra API. It is **not a spoke** — it is a standalone FastAPI app (dashboard :8000) that **optionally connects to the LM hub as a WebSocket agent** (`module_type = "agent"`) via `hub_agent.py`, so the hub can broadcast `SET_LOG_LEVEL` to it and it can call the hub (signed `HUB_REQUEST`) for aggregated logs and to trigger spoke self-updates.

## What it does

BugFixer is two things wearing one hat: (1) an autonomous bot that watches your GitHub
repos for issues labeled `automated-fix`, generates a code fix with an LLM, verifies it,
and opens a PR (or pushes directly on a trusted repo); and (2) the LLM engine behind the
in-app **"Ask AI"** help button in the Lab Manager WebUI — when a user asks a question
there, the hub relays it to BugFixer's LLM layer and streams back an answer grounded in
the docs. It has its own dashboard at `http://<bugfixer-host>:8000` (issue queue, config,
logs, LLM provider setup) and, separately, an optional connection to the LM hub as an
**agent** (not a spoke) so the hub can reach it for logs, debug toggling, and the Ask AI
relay.

## Entrypoints

- **Main:** `python3 main.py` (FastAPI app, poller, LLM orchestration, git workflow), systemd `bugfixer.service`, `User=root`, `Restart=always`. Installer `install.sh` (clones to `/opt/bugfixer`, apt + Node.js 20 + `@anthropic-ai/claude-code` CLI, `bugfixer.service` + `bugfixer-watchdog.service`, config to `/etc/bugfixer/config.json`). Alternates: `setup.sh` (local), `install_github.sh` (legacy spoke-style installer), `update.sh` (hourly self-update).
- **Watchdog:** `python3 watchdog.py`, systemd `bugfixer-watchdog.service` — polls `http://localhost:8000/api/health` every 5s and rolls back a failed auto-update.

## Ports

FastAPI dashboard on **8000** (HTTP). No WS listener — it is a WS **client** to the hub (when `HUB_WS_URL` configured); `hub_agent.py` connects with `max_size=16 MiB` to accept large `GET_LOGS` responses.

## Environment variables

- `.env`: `GITHUB_TOKEN`, `LOCAL_OLLAMA_MODEL`, `CLOUD_OLLAMA_MODEL`, `LOCAL_OLLAMA_URL`, `CLOUD_OLLAMA_URL`, `POLL_INTERVAL_SECONDS`, `UPDATE_API_URL`, `LOG_FILE_PATH` (`/var/log/bugfixer.log`).
- `config.json`: `monitored_repos`, `trusted_repos`, `default_branch`, `self_diagnosis_repo`, `enabled_models`, `direct_push_enabled`, `dev_branch`, `repo_tests`, `GITHUB_TOKEN`, `monitored_labels` (default `["automated-fix"]`), `HUB_WS_URL`, `HUB_AGENT_ID` (default `bugfixer`), `HUB_AGENT_SECRET`, `HUB_SECRET`, `refresh_status_seconds`, `refresh_logs_seconds`, `bug_report_enabled`, `bug_report_repo`, `TRIAGE_STRICTNESS`, `heartbeat_exclude`. LLM provider slots: `LLM_PROVIDER_N`, `LLM_API_KEY_N`, `LLM_MODEL_N`, `LLM_BASE_URL_N`, `LLM_RPM_N` (1-based; vault-based `llm_credentials`/`llm_entries`/`llm_slots` supported). Providers: openai, anthropic, google, groq, ollama (local+cloud), lmstudio, claude_cli.

## Install flags

`install.sh`: none (curl|bash; stdin to `/dev/null`). `install_github.sh`: `--spoke-url`, `--id`, `--secret`, `--hub-secret`, `--clone-only` (legacy).

## Key commands / handlers

- **Inbound from hub** (`hub_agent.py::_handle_message`): `APPROVAL_REQUIRED`, `APPROVED`, `SPOKE_UPDATE_SESSION_KEY` (provisions session secret), `SPOKE_SET_HUB_SECRET`, `HUB_RESPONSE` (correlated reply to a `HUB_REQUEST`), `DENIED`, `get_version`/`GET_VERSION` (signed `COMMAND_RESULT` with `data.version`), `SET_LOG_LEVEL`/`SPOKE_SET_LOG_LEVEL` (WebUI "Enable Debug" broadcast).
- **Outbound to hub** (`client.request_sync`): `GET_LOGS` (aggregated spoke logs, 20s timeout), `TRIGGER_ALL_UPDATES` (kick all spoke self-updates, 60s timeout). These replace the old static-token HTTP calls (`LM_ADMIN_TOKEN`/`X-Admin-Token`) the hub never honored.
- **FastAPI routes (own dashboard):** `/api/health`, settings, status/logs endpoints, `hub_agent_status`/`hub_agent_reregister`, scan/poll/fix/verify/iterate/deploy/sync workflow. The hub agent singleton starts at app startup via `_start_hub_agent()` → `hub_agent.start_agent_from_config(...)`.

## Key files

`main.py` (FastAPI app — poller, LLM orchestration, git workflow, triage), `hub_agent.py` (self-contained `HubAgentClient` + `MessageSigner` reimplementing lm-core's HMAC-SHA256 scheme; daemon-thread asyncio loop), `dedup.py` (pure stdlib duplicate-issue detection, `test_dedup.py`), `watchdog.py` (health-gate + auto-update rollback), `install.sh`/`setup.sh`/`update.sh`/`install_github.sh`, `templates/index.html`, `config.json.example`, `.env.example`, `requirements.txt`, `Dockerfile`, `VERSION`, `.github/workflows/version-bump.yml`.

## Notable behaviors & gotchas

- **Hub agent, not spoke** — registered in `active_connections` as `module_type="agent"`; does not register a spoke module or handle `CS_*`/`PXMX_*`/`LE_*` commands.
- **Reimplements lm-core signing** — `hub_agent.py::MessageSigner` mirrors `lm/core/src/security/signer.py` (HMAC-SHA256 canonical JSON) so it can talk to the hub without depending on lm-core.
- **Watchdog rollback** — polls `/api/health` every 5s; rolls back via `update_state.json`/`update_pending` in `/etc/bugfixer/` only on a failed auto-update.
- **`SET_LOG_LEVEL`** — bugfixer is in the hub's broadcast set, so the WebUI "Enable Debug" flips its log level too.

## How it works

- **Issue-fixing loop** (`poller_worker` → `run_scan_cycle` → `scan_repo_issues` in
  `main.py`, fix logic in `fix_engine.py`). On each poll cycle (default every
  `POLL_INTERVAL_SECONDS`, tighter during configured work hours) BugFixer lists open
  issues in every repo under `monitored_repos` that carry one of `monitored_labels`
  (default `["automated-fix"]`; `"ANY"` matches all open issues, `"NONE"` disables
  scanning), skipping issues already resolved/failed or marked `bugfixer-dismissed`.
  For each candidate issue, `fix_engine.process_single_issue` clones the repo, runs
  `analyze_issue`/`identify_files_to_fix`, asks the configured LLM to generate a fix
  (`apply_ai_fix`), verifies it (internal test run or an external QA service call via
  `_qa_service_verify`), and iterates up to a few rounds if verification fails. A
  built-in "skeptical reviewer" pass (`review_fix`) has to approve before deployment.
  Duplicate-issue detection (`dedup.py`) prevents the same underlying bug from spawning
  repeated fix issues.
- **Deployment decision.** A fix only gets pushed directly to the default branch when
  the repo is in `trusted_repos`, `direct_push_enabled` is on, BugFixer owns the repo
  (or it's the self-diagnosis repo), and the reviewer approved. Otherwise BugFixer opens
  a pull request instead and leaves it for a human to merge.
- **"Ask AI" / help assistant.** The hub owns the docs corpus and the tool-calling loop
  (`lm/core/src/routes/help_assistant.py`): it picks a few relevant `lm/docs/*.md` files
  by keyword match, builds a system prompt, and relays each model turn to BugFixer over
  the hub connection as an `HELP_ASK` command (`hub_agent.py::_handle_message`).
  BugFixer runs exactly one `call_llm` turn using whatever LLM provider is configured
  and returns `{content, tool_calls}`; the hub executes any tool calls (e.g.
  `get_spokes_status`, `search_devices`) itself and loops (up to 5 rounds) until the
  model gives a final answer with no more tool calls. `GET /api/help/available` reports
  `true` only when a BugFixer agent connection is present in the hub's
  `active_connections` — that's what shows or hides the "Ask AI" button in the WebUI.
- **Connecting to the hub.** BugFixer is a hub **agent**, never a spoke: it authenticates
  the same zero-touch/admin-approval + HMAC session-key flow every spoke uses, but
  registers as `module_type="agent"` and does not handle any `CS_*`/`PXMX_*`/`LE_*`
  commands. `hub_agent.py` reimplements the hub's HMAC-SHA256 canonical-JSON signing
  scheme itself (`MessageSigner`) so BugFixer never has to import the `lm` core package —
  it can run standalone, on a host with no lm source tree at all. Once connected it also
  relays its own INFO+ logs and uncaught exceptions to the hub (so the tool that triages
  everyone else's crashes is not itself a blind spot), answers `GET_VERSION`, and honors
  `SET_LOG_LEVEL` broadcasts (the WebUI "Enable Debug" button flips BugFixer's log level
  too).
- **Watchdog + rollback.** `bugfixer-watchdog.service` (`watchdog.py`) polls
  `/api/health` every 5 seconds. When an auto-update is pending (`update_pending` file
  in `/etc/bugfixer/`), it makes sure the running process is actually on the new commit
  (forcing a restart if not), then health-checks it for up to 60 seconds. A passing
  check promotes that commit to `last_known_good_commit`; a failing check `git reset
  --hard`s `/opt/bugfixer` back to the last known-good commit and restarts the service —
  so a broken self-update can't strand BugFixer down.

## How to use it

1. **Point BugFixer at repos and labels.** Edit `/etc/bugfixer/config.json` (or the
   dashboard's Settings page): set `monitored_repos` to the GitHub `owner/repo` strings
   you want watched, `monitored_labels` to the label(s) that mark an issue as
   fix-eligible (default `["automated-fix"]`), and `GITHUB_TOKEN` with access to those
   repos. Add a repo to `trusted_repos` and enable `direct_push_enabled` only once
   you're comfortable letting it push straight to the default branch on that repo.
2. **Configure at least one LLM provider.** From the dashboard's LLM setup page, add
   provider credentials (OpenAI, Anthropic, Google, Groq, Ollama local/cloud, LM
   Studio, or the `claude_cli` slot which needs no API key). BugFixer won't attempt a
   fix if no provider is reachable — it logs a cooldown/skip message and retries on the
   next poll cycle instead of failing loudly.
3. **Connect it to the hub** (enables both the hub-relayed log/update tooling and the
   "Ask AI" assistant): set `HUB_WS_URL` (e.g. `wss://HUB_IP:443/ws/spoke`),
   `HUB_AGENT_ID` (defaults to `bugfixer`), and optionally a pre-shared `HUB_AGENT_SECRET`
   / `HUB_SECRET` in `config.json`, then restart the `bugfixer` service. With no secret it
   connects zero-touch and waits for approval in the hub's **Setup → Spoke Approvals**
   (BugFixer shows up there like any other agent, even though it isn't a spoke).
4. **Verify "Ask AI" is live.** Once BugFixer is connected and approved, the WebUI's
   help button should appear; `GET /api/help/available` on the hub should return
   `{"available": true}`.

## Troubleshooting / common questions

- **The "Ask AI" button is missing in the WebUI.** This means the hub's
  `/api/help/available` check found no connected BugFixer agent. Check that the
  `bugfixer` service is running, that `HUB_WS_URL` is set and reachable, and that the
  agent has been approved in **Setup → Spoke Approvals** (a pending/unapproved
  connection doesn't count as available).
- **Issues aren't getting fixed even though they're labeled correctly.** Check, in
  order: is the repo actually listed in `monitored_repos`? Does `GITHUB_TOKEN` have
  access to it (a 404 in the logs for that repo means no access, or the repo name is
  wrong)? Does the issue carry a label in `monitored_labels` (or is `monitored_labels`
  accidentally set to `["NONE"]`, which disables scanning entirely)? Is at least one LLM
  provider configured and out of cooldown (an "all providers in cooldown" log line means
  it will retry automatically on a later cycle, not that it gave up)? Does the issue
  already carry `bugfixer-dismissed` (that label permanently skips it until removed)?
- **BugFixer is offline / the hub can't reach it.** BugFixer connects to the hub *as a
  client* — it's not a listener the hub dials into — so "offline" almost always means
  the `bugfixer` systemd service isn't running, or `HUB_WS_URL` is wrong/unreachable
  from the BugFixer host. Its own dashboard on port 8000 is independent of the hub
  connection, so the dashboard can be up while the hub connection is down; check
  `hub_agent_status` on the BugFixer dashboard to see the connection state directly.
- **A self-update seems to have broken BugFixer.** The watchdog (`bugfixer-watchdog`
  service) should catch this automatically within about a minute and roll back to the
  last known-good commit — check `/var/log/bugfixer_watchdog.log` for a rollback entry.
  If the watchdog service itself isn't running, that automatic recovery won't happen.

## Related pages

[architecture-topology.md](architecture-topology.md), [lm-hub.md](lm-hub.md), [generic-agent.md](generic-agent.md), [install-flags.md](install-flags.md).