# CI checks across the fleet

What GitHub Actions enforces, so the same rules hold for AppBuilder, a Copilot
session, or a hand-made push.

| Workflow | Where | When | Blocks? |
|---|---|---|---|
| `ci.yml` | every repo | push to dev, every PR | yes: the required check on qa/main PRs |
| `fleet-rules.yml` → lm `fleet-rules-reusable.yml` | every repo | push/PR to dev | errors only |
| `spoke-dispatch.yml` | lm | lm `core/**` push to dev | no (report only) |
| `promote.yml`, `backmerge.yml`, `branch-flow.yml` | every repo | see the files | promotion pipeline |

## Fleet rules (`fleet-rules-reusable.yml`)

Runs on pushes and PRs to `dev` only. Promotion PRs carry commits that already
passed here.

- **Fleet code rules**: `ab/fleet_checks.py --base <sha>`, the same
  deterministic rules AB gates its own changes with. Covers secrets and the
  vault, the WebUI ratchet, UUIDs in UI text, docstrings and step comments,
  docs updated for new routes/fields, and more. Rule text is in
  `lm/.github/fleet-rules.md`. Error-level findings fail the run; warnings show as
  annotations.
- **Ruff, new errors only**: `.github/scripts/ruff_new.py` lints each changed
  `.py` file at the base and at HEAD (E9, F63, F7, F82) and fails only on
  findings the change adds. Inherited findings are warnings, so touching an
  old file never fails you for someone else's bug.
- **Twin files**: `.github/scripts/check_twins.py` with `.github/twins.json`.
  See `.claude/skills/dual-copy-guard/reference.md`.
- **pip-audit**: only when a `requirements*.txt` changed; advisory.

Run the rules locally before pushing:

```bash
python ../ab/fleet_checks.py --base origin/dev --repo lbockenstedt/<repo>
python ../lm/.github/scripts/ruff_new.py --base origin/dev
```

## lm JavaScript syntax

lm `ci.yml` runs `node --check` on every WebUI script (except vendored
`WebUI/assets`) before the browser smoke test. A stray brace blanks the whole
page, and this step names the file and line.

## Spoke compatibility (`spoke-dispatch.yml`)

Spokes import `BaseSpoke` from lm/core, but their CI used to run only on their
own pushes. On each lm `core/**` push to dev, lm sends `repository_dispatch`
`lm-changed` to every spoke whose CI checks out lm as `_lm`. That spoke's CI
then tests its `dev` against that exact lm commit. Look for runs with event
`repository_dispatch` in each spoke's Actions tab. Needs `WORKFLOW_TOKEN` in lm
with repo scope on the spokes.

## Promoting several repos

`.github/scripts/promote_fleet.sh [--to qa|main] <repo>...` dispatches
`promote.yml` and waits for the promotion PR and its checks. It merges each
unit with a merge commit until none remain. It never opens a PR or pushes a
branch itself: if no PR appears, it reports this and stops.

It waits until GitHub reports the PR as mergeable, not just until the listed
checks pass. A promotion PR whose head was pushed with `GITHUB_TOKEN` starts
no CI, so the required `test` check never appears. When the PR is still
blocked after two minutes, the script closes and reopens it as you, which
starts CI.

## Rules, agents and skills sync (`sync-fleet-files.yml`)

On an lm `dev` push that changes `.github/fleet-rules.md`, `.github/agents/`,
`.claude/skills/` or the `fleet` section of `twins.json`, this workflow runs
`.github/scripts/sync_fleet_files.py`. The script copies those files to every
fleet repo's `dev` and writes the rules into each repo's `AGENTS.md`, between
the `fleet-rules` markers. It pushes with `WORKFLOW_TOKEN`. The `fleet-rules`
check warns when a repo's copy differs from lm's. See
[agents-and-skills.md](agents-and-skills.md).

`dhcp` and `dns` are archived (read-only); every fleet list leaves them out.
