# CI checks across the fleet

What GitHub Actions enforces, so the same rules hold for AppBuilder, a Copilot
session, or a hand-made push.

| Workflow | Where | When | Blocks? |
|---|---|---|---|
| `ci.yml`: `checks` job → lm `fleet-rules-reusable.yml` | every repo | push/PR to dev | errors only |
| `ci.yml`: `test` job (nw: `lint-python`, `lint-shell`, `test-unit`) | every repo | push to dev, every PR | yes: the required check on qa/main PRs |
| `spoke-dispatch.yml` | lm | lm `core/**` push to dev | no (report only) |
| `promote.yml`, `backmerge.yml` → lm `promote-reusable.yml`, `backmerge-reusable.yml` | every repo | see the files | promotion pipeline |
| `branch-flow.yml` | every repo | PRs into qa/main | yes: `check-direction` |

## Order of operations in `ci.yml`

Cheap checks run first so a bad change is rejected in seconds, not minutes:

1. **`checks`** (about 20 s): the fleet rules below. Dev pushes and PRs into
   dev only; promotion PRs into qa/main carry commits that already passed.
2. **`test`** waits for `checks`. If `checks` failed, `test` fails in its first
   step without installing anything. It still *runs* rather than being
   skipped, because a skipped required check counts as passing on qa/main.
   On qa/main PRs `checks` is skipped and `test` runs on its own.
3. **`pytest -x`**: inside `test`, the suite stops at the first failing test,
   so a broken change fails in about the time it takes to reach that test
   instead of after the whole suite (lm's full run is about 6 minutes). The
   cost is that later failures are hidden until the first one is fixed; run
   `smoke.sh --all` locally to see them all. lm's per-component loop
   still runs every component and lists each one that failed.

Every `ci.yml` also cancels an older run when a newer push lands on the same
branch or PR, and caches pip downloads where the repo has requirements files.
lm caches the Playwright Chromium download and runs the promotion tests
(`.github/tests`, `.github/scripts/promotion_selftest.sh`) before the browser
install.

## Fleet rules (`fleet-rules-reusable.yml`)

Called by the `checks` job of every repo's `ci.yml`. lm calls its local copy,
so a change is exercised on lm dev before the other repos pick it up from main.

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

## Local smoke test (`.github/scripts/smoke.sh`)

The same checks and tests GitHub runs, run locally before every push. CI is
the backstop. Run from any repo's root, with ab and lm cloned next to it:

```bash
../lm/.github/scripts/smoke.sh                 # stop at the first failure
../lm/.github/scripts/smoke.sh --all           # list every failing test
../lm/.github/scripts/smoke.sh --install-hook  # run on every git push
```

Order, cheapest first, as in `ci.yml`:

0. Python environment: one venv per repo in `../.smoke-venvs/<repo>` (outside
   every repo), installed the way CI installs it: the pip packages named in the
   repo's `ci.yml` plus every `requirements*.txt`, and ruff. It is rebuilt only
   when those change. It uses python3.11 if installed (CI's version), else
   the newest python3. Without this, tests whose imports are missing are
   skipped locally while they run in CI.
1. Fleet rules: `../ab/fleet_checks.py --base origin/dev`.
2. Ruff, new errors only.
3. Twin files (`check_twins.py`; reads the other repos' copies from GitHub).
4. Tests: the steps read from the repo's own `ci.yml`, so the local and CI
   commands can't drift. These are the compile check (nw) and the WebUI
   `node --check` (lm) where `ci.yml` has them, then its `pytest -x ...`
   command. Spokes get the sibling `../lm` on `PYTHONPATH`, as CI does with
   `_lm`. lm runs `.github/tests`, `promotion_selftest.sh` and then one process
   per component. tsa runs `npm run typecheck` and `npm test`, installing
   packages and generating the Prisma client first if needed.

Set `PYTHON=` to use your own interpreter or virtualenv instead (nothing is
installed into it; `--timeout` is dropped if it lacks `pytest-timeout`). Skip
the hook once with `git push --no-verify`. CI-only, not run locally: lm's
browser smoke test (skips when `CI` is unset) and nw's advisory
ruff/bandit/pip-audit/ShellCheck reports, which never fail a build.

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

## Promotion and back-merge (`*-reusable.yml`)

Each repo's `promote.yml` and `backmerge.yml` is a thin caller generated from
`.github/workflow-templates-fleet/`: it owns only the triggers and token
permissions, and passes `WORKFLOW_TOKEN` by name. The logic lives once, in
lm's `promote-reusable.yml` and `backmerge-reusable.yml`; lm calls its local
copies. ab adds the `target` input (dev → main override) and the weekday
schedule; kvm promotes on dispatch only. To change promotion, edit the
reusable in lm.

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
