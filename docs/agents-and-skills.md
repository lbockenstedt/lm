---
summary: "'Agents' here are Claude skills — repo-committed, self-contained procedures that encode tribal knowledge so both an interactive Claude session and AppBuilder execute the…"
keywords: [agents, dns_fail, dual, guard, live, lm, sim, simulation, skill, skills]
---

# Agents & Skills

"Agents" here are **Claude skills** — repo-committed, self-contained procedures that
encode tribal knowledge so both an interactive Claude session *and* AppBuilder execute
the same recipe with the same boundaries. Each skill is a folder with a `SKILL.md`
(name + description + instructions) and optional supporting files (e.g. a
`reference.md` with the full checklist).

## Where they live
`lm/.claude/skills/` — the LM (hub) repo is the single source of truth. (They were
originally committed at the workspace root, which is the `nw` checkout; moved here so
they have a sensible home instead of living in a network-devices module repo.)

```
lm/.claude/skills/
├── dual-copy-guard/     SKILL.md + reference.md
└── add-simulation/      SKILL.md + reference.md
```

## The skills

### `dual-copy-guard`
Knows every **mirror / twin pair** in the codebase and checks/enforces them so an
edit to one copy never silently misses the other. Pairs include: the two
`sim-views.js` copies (lm/WebUI ↔ cs/lm-spoke/static), canonical `common.sh`
(clients/lib) → generated (clients/linux), `common.sh` ↔ `common.ps1` parity,
`sim_quota.py` hub/spoke twin, linux ↔ windows client scripts, dns/dhcp dual copies,
and `dns_fail.txt` ×3. Two modes: **guard** (after an edit, check its twin) and
**audit** (sweep all pairs for drift).

### `add-simulation`
The end-to-end recipe for adding a new client traffic simulation: both linux `.sh`
and windows `.ps1` scripts, the shared config, both orchestrators, **both**
`sim-views.js` UI copies, the quota engine + its hub twin, and the alert docs — with
the boundaries baked in. Top boundary: **a sim is a NEW FILE, never a function in
the orchestrator** — `cs/clients/linux/<sim>.sh` (+ `.ps1` twin), dispatched by
`simulation.sh`/`.ps1` ONLY as a flag-gated `run_simulation "<sim>.sh" <pause>`
call. Plus: shared DNS ceiling, never self-kill, edit canonical not generated, T3
out of scope.

## Subagents
Beyond the skills above, a Claude Code **subagent** (`.claude/agents/<name>.md`,
spawnable via the Agent tool) can wrap a skill to drive a whole task hands-off.
These are a *convenience for interactive Claude* — AppBuilder loads **skills**
(`.claude/skills`), not subagents, so a subagent's value is the skill it follows.

### `sim-builder`
Adds one new simulation end-to-end by loading + following the `add-simulation`
skill: gathers the spec (name/flag/kind/targets), builds the ~15 touch-points
across cs + lm holding every boundary (new-file-not-orchestrator-function first),
then verifies with `dual-copy-guard`. Invoke it for "add a sim" / "create a
simulation" / "new traffic-or-alert generator" instead of hand-walking the recipe.

## Who uses them
1. **Interactive Claude** — invoked as `/dual-copy-guard` / `/add-simulation`, or
   auto-matched by task. (Auto-listing as slash-commands happens from the workspace
   root; when working from the LM repo they're read directly.)
2. **AppBuilder** — fetches these from `lbockenstedt/lm` `.claude/skills/` (a monitored
   repo) and loads them to inform its fix / build / PR-review work, so a AppBuilder
   change follows the same recipe + boundaries a human invoking the skill would. This
   is the single-source-of-truth link: author the rules once, both consumers use them.

## Adding a skill
Create `lm/.claude/skills/<name>/SKILL.md` with YAML frontmatter (`name`,
`description`) + instructions; add a `reference.md` for a long checklist and have
`SKILL.md` point to it. Keep it **self-contained** — no reliance on personal memory
or "as we discussed" — so a teammate's Claude (and AppBuilder) run it identically.
