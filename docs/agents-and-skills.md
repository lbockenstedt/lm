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

- copies `.github/fleet-rules.md`, `.github/agents/` and `.claude/skills/` into
  each repo, removing files lm no longer has (except a repo's own
  `<repo>-*` agents and skills);
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
