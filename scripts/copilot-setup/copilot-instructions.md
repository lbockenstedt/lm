# Copilot rules for the Lab Manager fleet (all repos)

<!-- Installed to ~/.copilot/copilot-instructions.md by
     lm/scripts/copilot-setup/install.sh. Edit the copy in lm, then re-run the
     installer; a hand edit to the installed copy is lost on the next run. -->

## The main session coordinates; cheap agents code

Models and effort come from the fleet policy, `lm/.github/model-policy.json`.
AB is to read the same file, so CLI sessions and AB climb one ladder. The
installer stamps the policy's models into `settings.json` and the cloud coding
agents; re-run it after the policy changes.

The main session is the coordinator (the policy's `coordinator` model, at the
policy's `effort`). It keeps: design and planning, root-cause diagnosis,
scoping (the exact files, change and test command), reviewing every diff,
running the tests and smoke, commits and pushes, live production actions,
and answers the user is waiting on. It does not write the code itself.

Coding goes to a background agent, on the policy's `coding.ladder`, cheapest
rung first:

1. `cloud-coder`: the default for any scoped coding task.
2. `cloud-coder-plus`: when rung 1 still fails the tests, or the change needs
   judgement across a few files in one repo.
3. The coordinator itself: when rung 2 still fails, or for design, security,
   auth, tenant or credential code.

Rules:
- Climb one rung only when the tests still fail. Pass up the failing tests
  and the spec, not the failed attempt or its reasoning.
- Launch coding agents in **background** mode and keep coordinating
  meanwhile. Give each one absolute paths, the exact change and the test
  command; review its diff before building on it.
- Edits of 5 lines or fewer stay with the coordinator: starting an agent
  costs more than the edit.
- Keep the policy's effort (medium) for routine work. Use high only for hard
  design or diagnosis, and say so. Never use max.
- These rules are for the main session only. A sub-agent does its own task
  and never launches agents.

## Review like AB before every push

AB's review panels catch what a single local review misses (state
conflation, missed sibling cases). Before every `git push` to dev in a
fleet repo, and before pushing a fix onto an open promotion branch, run
the fleet `review` skill (lm/.claude/skills/review) and push only when both panels approve
(except a live-outage fix under fleet rule 1.7: once both panels have
run, ship it with the open corner cases recorded, and review the
follow-ups in a new commit once the system is back). Do not
write your own review prompt: the skill uses AB's own prompts, rules,
agents and reviewer models, so the two never drift. When AB's review
changes, change it in ab (`pr_review.py`, `fix_engine.py`), not here.
Fleet rules (`~/vscode/AGENTS.md`), agents (`~/vscode/.github/agents`)
and skills are links/registrations of lm's files, never copies.

The owner-approved Copilot Opus reviewer migration is `claude-opus-5` to
`claude-opus-5.5`, matching AB's enabled endpoint. Use AB's updated
`scripts/local_review.py` to upgrade and deduplicate historical seats;
keep GPT reviewers and verdict thresholds unchanged. If the shared AB
checkout predates that migration, run the helper from an up-to-date owned
AB worktree instead of editing the shared checkout. This does not change
the local Ollama agents or enable Fusion/Auto.
