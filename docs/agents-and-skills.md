---
summary: "Fleet rules, custom agents and skills: where they live (lm only), how they reach every repo, and how Copilot, other tools and AppBuilder use them."
keywords: [agents, skills, rules, fleet-rules, copilot, appbuilder, sync, AGENTS.md]
---

# Rules, agents and skills

Three kinds of shared guidance keep every contributor (people, Copilot,
Claude and AppBuilder) working the same way:

| Kind | What it is | Lives in (edit here only) |
| :--- | :--- | :--- |
| **Fleet rules** | The rules every change must follow, with an enforcement map. | `lm/.github/fleet-rules.md` |
| **Agents** | A specialist persona and checklist for one kind of work, e.g. "spoke integration" or "tenant scope audit". | `lm/.github/agents/<name>.agent.md` |
| **Skills** | A step-by-step recipe for one repeatable change, e.g. "add a vault secret field". | `lm/.claude/skills/<name>/SKILL.md` (+ optional `reference.md`) |

An agent says *how to think* about an area and which skills to follow. A
skill says *exactly which files to touch, in what order*, and how to test.

## How they reach every repo

`.github/twins.json` (section `fleet`) lists the fleet repos and the files lm
owns. On every lm `dev` push that changes them, `sync-fleet-files.yml` runs
`.github/scripts/sync_fleet_files.py`, which:

- copies `.github/fleet-rules.md`, `.github/agents/`, `.claude/skills/` and
  the AI spend gate (`.github/hooks/`, `.github/ai-budget.json`) and the
  model policy (`.github/model-policy.json`) into each
  repo, removing files lm no longer has (except a repo's own `<repo>-*`
  agents and skills);
- writes the rules into each repo's `AGENTS.md`, between the
  `fleet-rules:begin` and `fleet-rules:end` markers, so any tool that
  auto-loads `AGENTS.md` sees them. The rest of `AGENTS.md` holds that repo's
  own facts and is never touched.

The `fleet-rules` CI check (`check_twins.py`) warns when a copy was edited
in place instead of in lm. Run the sync locally with:

    python lm/.github/scripts/sync_fleet_files.py --src lm --dest-root . [--check]

## Who uses them

- **GitHub Copilot (CLI, VS Code, coding agent)** loads `AGENTS.md` (and so
  the rules) automatically. Pick an agent with `/agent`, or let Copilot pick
  one by its description. Skills are used automatically when they match.
- **Claude Code, Codex, Cursor and others** read `AGENTS.md`. Point Claude at
  it with a personal `CLAUDE.md` containing `@AGENTS.md`; the fleet ships no
  `CLAUDE.md`, so nothing is loaded twice.
- **AppBuilder** reads `.github/fleet-rules.md` into every fix, build and
  review prompt (`fleet_checks.rules_text()`), and loads lm's skills and
  agents (`skills_loader`).
  - Skills are offered by name and description; a feature build injects the
    chosen skill in full.
  - An agent whose `metadata.ab-match` regex matches the issue or PR text has
    its full checklist injected (`agents_context()`); at most two agents, best
    match first.

## The agents

| Agent | Use for |
| :--- | :--- |
| `fleet-rules-reviewer` | Read-only review of any diff or PR against the rules; runs the CI checks locally. |
| `tenant-scope-auditor` | Routes, views and fan-outs that return per-tenant data; cross-tenant leaks; tenant 403s. |
| `credential-vault-wiring` | Any new password, key or token, or moving an inline secret into the vault. |
| `spoke-integration-engineer` | New or extended vendor/appliance spokes and hub↔spoke commands. |
| `netbox-sync-engineer` | NetBox sync, dedupe, auto-rack, VRF/IP placement, custom fields, feeders. |
| `client-sim-engineer` | Client-sim across cs, lm and pxmx (sims, sim-quota, dongles, scripts). |
| `webui-view-builder` | New or reworked WebUI pages, tabs and tiles. |
| `fleet-pipeline-engineer` | Promote/backmerge/CI/fleet workflows and promotion triage. |
| `ab-maintainer` | AppBuilder internals: LLM providers, review, fix engine, fleet_checks. |
| `sim-builder` | Adding one new client simulation end to end (follows `add-simulation`). |
| `feature-builder` | One small bolt-on feature using an existing skill (interactive counterpart of AB's feature build). |

Each agent was chosen from a scan of four months of commits across the fleet:
the areas with the most work and the most same-file fix-ups. Every agent file
cites the commits that motivated its checklist.

## The skills

| Skill | Recipe for |
| :--- | :--- |
| `review` | AB's two review panels run locally on a change before every push (any tool). |
| `dual-copy-guard` | Keeping twin files (hub↔spoke, linux↔windows, pipelines) in step. |
| `add-simulation` | A new client traffic simulation. |
| `add-webui-control` | A single WebUI button, toggle or small form. |
| `add-webui-view` | A new WebUI page or tab. |
| `add-vault-secret-field` | A secret field wired through the Credential Vault. |
| `add-hub-spoke-command` | A new `<MOD>_<VERB>` command: hub route, relay, spoke handler. |
| `add-spoke-module` | A new spoke type and all its hub wiring. |
| `add-hub-pushed-setting` | A setting edited on the hub and pushed to spokes. |
| `add-netbox-custom-field` | A NetBox custom field with its full read/write path. |
| `change-fleet-pipeline` | A workflow change made once in lm and rolled out. |
| `ab-add-llm-provider` | An LLM provider or model in AppBuilder. |
| `ab-add-fleet-rule` | Turning a recurring rework class into a `fleet_checks` rule. |

## The daily AI spend gate

Fleet rule 1.10 (`.github/fleet-rules.md`). The gate stops runaway sessions;
it is not a budget, and a person can reopen it and keep going. Three
fleet-owned files carry it, synced to every repo like the rules:

- `.github/ai-budget.json`: the numbers;
- `.github/hooks/fleet-hooks.json`: the Copilot CLI hooks;
- `.github/hooks/ai_budget.py`: the script the hooks run (plain Python 3.9+,
  no dependencies).

The numbers in `.github/ai-budget.json`:

- `gate_usd` (100): cloud AI spend in one local calendar day that closes the
  gate;
- `step_usd` (100): how much more `continue` allows by default;
- `reserve_usd` (25): within this much of the gate, new cloud sub-agents are
  refused;
- `prices_usd_per_mtok`: USD per 1M tokens for each model, used by AB.

Spend comes from Copilot CLI's own usage log on the machine,
`$COPILOT_HOME/session-store.db` (default `~/.copilot`). It covers every CLI
session and sub-agent on that machine; local models (Ollama, llama.cpp) cost
$0 in it.

What the hooks do:

- At session and sub-agent start, the agent is told today's spend and to
  prefer local models.
- Past the gate, every tool call of a session that used a cloud model today
  (its own calls or a sub-agent's) is refused, except `task_complete`,
  `ask_user`, `stop_bash` and a shell call that only runs
  `python3 .../ai_budget.py status`. The refusal tells the agent to stop and
  tell the user. A session whose model calls today were all free (local
  models) keeps working, but cannot start cloud sub-agents. A session with
  no model calls logged after a 2-second wait, or with no session id in the
  hook, counts as cloud.
- Within `reserve_usd` of the gate, a `task` sub-agent on a cloud model is
  refused (any model not named `ollama/*` or `llamacpp/*`; with no model
  given, any agent type not named `local-*`), and so is a workflow run.
- An agent's attempt to run `ai_budget.py continue`, or to change the state
  file, is always refused.

Commands for a person, from a terminal in the repo:

- `python3 .github/hooks/ai_budget.py status`: today's spend and the gate.
- `python3 .github/hooks/ai_budget.py continue [USD]`: reopens the gate for
  USD more today (default `step_usd`). It is stored in
  `$COPILOT_HOME/ai-budget-state.json` and ends at local midnight.
- `python3 .github/hooks/ai_budget.py prices`: the per-model prices seen in
  the last 30 days, in the format of `prices_usd_per_mtok`, to refresh the
  table.

Where it applies:

- Copilot CLI sessions started in a fleet repo the CLI trusts
  (`trustedFolders` in `~/.copilot/config.json`); the CLI skips repo hooks
  in an untrusted folder. A session loads its hooks when it starts. In a
  folder that is not a git repo, the CLI reads that folder's own
  `.github/hooks`.
- Copilot's cloud agent has no usage log there, so the gate stays open.
  Other tools (Claude Code, Cursor) do not run these hooks, but rule 1.10
  still applies to them.
- It fails open: with no usage log, or on any error, the hook prints nothing
  and exits 0, because Copilot refuses the tool call when a `preToolUse`
  hook fails. It is a gate for agents that follow the rules, not a security
  boundary.
- AB reads the same `.github/ai-budget.json`, counts its own Copilot spend
  per day, and stops calling Copilot at the gate until a person presses
  Continue in AB (see `ab/docs/ab.md`). Each machine running Copilot CLI,
  and AB, has its own gate.

## The model policy

`.github/model-policy.json` says which Copilot model and effort each role
uses, so CLI sessions and AB climb the same ladder. It is fleet-owned (edit
only in lm) and synced to every repo with the rules.

- **`effort`**: `medium` for every role. Measured Nov 2026: about 80% of this
  Mac's Opus spend was at max effort, and low effort is not a usable rung
  (Opus at low approved a bad change in review and passed 1 of 3 real fixes;
  Sonnet at low passed none).
- **`coordinator`**: the interactive session's model. It plans, scopes,
  reviews every diff, runs the tests and commits; it does not code.
- **`coding.ladder`**: cheapest first: Haiku 5.5 (`cloud-coder`), Sonnet 5.5
  (`cloud-coder-plus`), then Opus 5.5. Climb one rung only when the tests
  still fail. On three real fleet fixes with a precise spec, Haiku passed 2
  (about $0.02 each), Opus and GPT-5.6-sol 1 each (about $0.40), and Sonnet
  came closest on the hardest (37 of 39 tests).
- **`review`**: adopted for local sessions (the `review` skill). Each panel
  gets one reviewer: `mai-code-2-flash` first, then the frontier model of a
  different vendor from the author (`gpt-5.6-sol` for Anthropic-written code)
  only when the cheap verdict is disputed with file evidence, below 0.80
  confidence, or failed. The frontier verdict stands.

Who reads it:

- **CLI**: `scripts/copilot-setup/install.sh` stamps the coordinator model
  and effort into `~/.copilot/settings.json` and each rung's model into the
  `cloud-coder*` agents, and installs the coordinator rules
  (`scripts/copilot-setup/README.md`). Re-run it after the policy changes.
- **AB**: fixes walk `coding.ladder` (Settings → Fix model ladder,
  `FIX_MODEL_LADDER`, on by default; see `ab/docs/ab.md`, "Fix model
  ladder"). AB's review panels still seat several reviewers through
  `fix_engine.panel_verdict`; moving them to the `review` ladder is a
  separate AB change.

The same installer sets up the daily AI spend gate below as a personal hook,
so it covers every session on the machine, not only those started in a
fleet repo.

## Adding or changing one

1. Edit in lm only.
   - An agent is `.github/agents/<name>.agent.md` with YAML frontmatter:
     `name`, `description` (say *when* to use it; tools route on it), and
     optionally `tools` and `metadata: {ab-match: "<regex>"}` for AB.
   - A skill is `.claude/skills/<name>/SKILL.md` with `name` and
     `description`.
2. Keep it self-contained. Name real files and functions, cite the commits
   behind each "common miss", and never rely on personal memory or "as we
   discussed". A teammate's tool and AB must run it identically.
3. Don't restate the fleet rules; refer to their section in
   `.github/fleet-rules.md`.
4. A rule belongs in `fleet-rules.md`, a checklist in an agent, and a recipe
   in a skill. Never put the same text in two places.
5. Repo-only agents or skills can live in that repo, named `<repo>-…`; the
   sync leaves them alone.
