#!/usr/bin/env bash
# Local smoke test: run what CI runs, in the same order, before you push.
#
#   cd <repo> && ../lm/.github/scripts/smoke.sh [--all] [--base <ref>]
#   ../lm/.github/scripts/smoke.sh --install-hook   # run it on every git push
#
# Cheapest first, stopping at the first failure (lm docs/ci-checks.md):
#   0. python env    a venv per repo in ../.smoke-venvs, installed like CI
#                    (ci.yml pip packages + every requirements*.txt)
#   1. fleet rules   ../ab/fleet_checks.py against the base
#   2. ruff          new errors only (lm .github/scripts/ruff_new.py)
#   3. twin files    lm .github/scripts/check_twins.py
#   4. tests         the steps from this repo's own ci.yml, so local and CI
#                    never drift: compile / JS syntax checks where ci.yml has
#                    them, then its pytest command. Stops at the first failing
#                    test (-x); --all drops -x to list every failure.
# Needs the ab and lm checkouts as siblings of this repo.
#
# AppBuilder runs this same script in its sandbox before it pushes a fix
# (ab fix_engine.verify_fix), where there are no sibling checkouts and no
# credentials, using:
#   --no-fleet-rules   AB runs fleet_checks.gate on the change in-process
#   --no-fetch         the sandbox has no git credentials
#   --setup-only       build the venv only (AB's install phase), then exit
#   SMOKE_HELPERS=dir  lm's .github (scripts/, twins.json); default ../lm/.github
#   SMOKE_VENV=dir     the venv to build and use; default ../.smoke-venvs/<repo>
set -uo pipefail

base="origin/dev"
all=0
fleet_rules=1
fetch=1
setup_only=0
while [ $# -gt 0 ]; do
  case "$1" in
    --all) all=1 ;;
    --base) base="$2"; shift ;;
    --no-fleet-rules) fleet_rules=0 ;;
    --no-fetch) fetch=0 ;;
    --setup-only) setup_only=1 ;;
    --install-hook)
      hook="$(git rev-parse --git-path hooks)/pre-push"
      # shellcheck disable=SC2016 # the hook expands it at push time
      printf '#!/usr/bin/env bash\n# Installed by lm/.github/scripts/smoke.sh --install-hook. Skip once: git push --no-verify\nexec "$(git rev-parse --show-toplevel)/../lm/.github/scripts/smoke.sh"\n' > "$hook"
      chmod +x "$hook"
      echo "pre-push hook installed: $hook"
      exit 0 ;;
    -h|--help) sed -n '2,28p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

root="$(git rev-parse --show-toplevel)" || exit 2
cd "$root" || exit 2
# A pre-push hook in a git worktree exports an absolute GIT_DIR. Every step
# below inherits it, so the promotion self-test's scratch `git init`, commit,
# `branch -M main` and `push origin` ran against the real repo instead. From
# here git finds the repo from the working directory, as it would in CI.
# shellcheck disable=SC2046 # one variable name per word
unset $(git rev-parse --local-env-vars)
# The repo name comes from the origin remote, so a git worktree in a directory
# with another name (e.g. wt-feature) still runs that repo's steps; fall back
# to the directory name when there is no origin.
origin="$(git remote get-url origin 2>/dev/null)"
name="$(basename "${origin:-$root}" .git)"
fleet="$(dirname "$root")"
helpers="${SMOKE_HELPERS:-$fleet/lm/.github}"
ci=".github/workflows/ci.yml"

step() { printf '\n== %s\n' "$1"; }
fail() { printf '\nSMOKE FAILED at: %s\n' "$1"; exit 1; }

needs="$helpers/scripts/ruff_new.py"
[ $fleet_rules = 0 ] || needs="$fleet/ab/fleet_checks.py $needs"
for need in $needs; do
  [ -f "$need" ] || { echo "missing $need (clone ab and lm next to $name)"; exit 2; }
done

# 0. Python environment, installed the way CI installs it: one venv per repo
# (CI starts each repo clean too) with the pip packages named in ci.yml plus
# every requirements*.txt. Re-installed only when those inputs change.
# PYTHON=/path/to/python skips this and uses that interpreter as-is.
if [ -n "${PYTHON:-}" ]; then
  py="$PYTHON"
elif [ -f requirements.txt ] || [ -n "$(find . -name 'requirements*.txt' -not -path '*/node_modules/*' -print -quit)" ] || grep -q 'pip install' "$ci" 2>/dev/null; then
  base_py=""
  for cand in python3.11 python3.12 python3.13 python3; do
    command -v "$cand" >/dev/null && { base_py="$cand"; break; }
  done
  [ -n "$base_py" ] || { echo "no python3 found"; exit 2; }
  venv="${SMOKE_VENV:-$fleet/.smoke-venvs/$name}"
  py="$venv/bin/python"
  reqs="$(find . -name 'requirements*.txt' -not -path './_lm/*' -not -path './.ab-*' -not -path '*/venv/*' \
            -not -path '*/.venv/*' -not -path '*/node_modules/*' | sort)"
  # Test-job packages from ci.yml. Not playwright (the browser test is CI-only)
  # nor nw's advisory bandit/pip-audit; ruff is added for step 2.
  pkgs="$(grep -o 'pip install [a-z][^|&;#]*' "$ci" 2>/dev/null | sed 's/^pip install //' \
            | tr ' ' '\n' | grep -vE '^(-|playwright|bandit|pip-audit|$)' | sort -u | tr '\n' ' ')"
  pkgs="$pkgs ruff"
  # shellcheck disable=SC2086
  want="$( { "$base_py" --version; echo "$pkgs"; [ -z "$reqs" ] || cat $reqs; } 2>&1 | cksum | cut -d' ' -f1)"
  if [ "$(cat "$venv/.smoke-stamp" 2>/dev/null)" != "$want" ]; then
    step "python env ($venv, $("$base_py" --version 2>&1); CI uses 3.11)"
    [ -x "$py" ] || "$base_py" -m venv "$venv" || fail "venv"
    "$py" -m pip install -q --upgrade pip >/dev/null
    # shellcheck disable=SC2086
    "$py" -m pip install -q $pkgs || fail "pip install $pkgs"
    # Non-fatal per file, as in CI: a missing import still fails the tests.
    for r in $reqs; do
      echo "installing $r"
      "$py" -m pip install -q -r "$r" || echo "warning: pip install -r $r failed"
    done
    echo "$want" > "$venv/.smoke-stamp"
  fi
  export PATH="$venv/bin:$PATH"
else
  py="python3"
fi
[ $setup_only = 0 ] || { echo "setup done"; exit 0; }
if [ $fetch = 1 ]; then
  git fetch -q origin 2>/dev/null || echo "warning: git fetch failed; comparing against the local $base"
fi

# 1. Fleet rules: error-level findings fail, exactly as in the checks job.
if [ $fleet_rules = 1 ]; then
  step "fleet rules (vs $base)"
  "$py" "$fleet/ab/fleet_checks.py" --base "$base" --repo "lbockenstedt/$name" || fail "fleet rules"
fi

# 2. Ruff, new errors only.
step "ruff (new errors only)"
if "$py" -m ruff --version >/dev/null 2>&1 || command -v ruff >/dev/null; then
  "$py" "$helpers/scripts/ruff_new.py" --base "$base" || fail "ruff"
else
  echo "skipped: ruff not installed (pip install ruff)"
fi

# 3. Twin files must match their copies in the other repos.
step "twin files"
"$py" "$helpers/scripts/check_twins.py" --repo "$name" --branch dev \
  --twins "$helpers/twins.json" --root . || fail "twin files"

# 4. Tests, using this repo's CI command.
if [ -f package.json ] && ! grep -q 'pytest -x' "$ci" 2>/dev/null; then
  step "typecheck + tests (npm)"
  # Same setup as CI: install deps and generate the Prisma client if missing.
  [ -d node_modules ] || npm install --no-audit --no-fund --no-package-lock || fail "npm install"
  if [ -f prisma/schema.prisma ] && [ ! -d node_modules/.prisma/client ]; then
    npx prisma generate >/dev/null || fail "prisma generate"
  fi
  npm run -s typecheck || fail "typecheck"
  if [ $all = 1 ]; then npm test || fail "tests"; else npm test -- --bail 1 || fail "tests"; fi
  printf '\nSMOKE PASSED\n'; exit 0
fi

# Spokes import lm's BaseSpoke; CI checks lm out to _lm, locally it is the sibling.
if [ "$name" != lm ] && [ -d "$fleet/lm/core/src" ]; then
  export PYTHONPATH="$fleet/lm:$fleet/lm/core/src${PYTHONPATH:+:$PYTHONPATH}"
fi

pytest_args() {
  # The `pytest -x ...` line from ci.yml, minus anything after `||`.
  grep -o 'pytest -x[^|]*' "$ci" | grep -v '\.github/tests' | head -1 | sed 's/^pytest //; s/[[:space:]]*$//'
}
args="$(pytest_args)"
[ -n "$args" ] || { echo "no 'pytest -x' line in $ci"; exit 2; }
[ $all = 1 ] && args="${args/-x /}"
# --timeout needs pytest-timeout; drop it rather than fail when it is missing.
if [[ "$args" == *--timeout* ]] && ! "$py" -c 'import pytest_timeout' 2>/dev/null; then
  echo "note: pytest-timeout not installed; running without --timeout"
  args="$(sed -E 's/--timeout(-method)?=[^ ]+//g' <<<"$args")"
fi

# The cheap pre-test steps some ci.yml files have.
if grep -q 'py_compile' "$ci"; then
  step "compile check"
  for d in src scripts; do
    [ ! -d "$d" ] || find "$d" -name '*.py' -exec "$py" -m py_compile {} + || fail "compile check"
  done
fi
if grep -q 'node --check' "$ci" && [ -d WebUI ] && ! command -v node >/dev/null; then
  echo "note: node not installed; WebUI JavaScript syntax check skipped"
elif grep -q 'node --check' "$ci" && [ -d WebUI ]; then
  step "WebUI JavaScript syntax check"
  find WebUI -name '*.js' -not -path 'WebUI/assets/*' -not -path '*/node_modules/*' \
       -not -name '*.min.js' -print0 | xargs -0 -n1 node --check || fail "WebUI JS syntax"
fi

if [ "$name" = lm ]; then
  # lm: workflow tests first, then one process per component (see ci.yml).
  step "tests: .github/tests"
  "$py" -m pytest -x -q .github/tests || fail "tests (.github/tests)"
  if [ -f .github/scripts/promotion_selftest.sh ]; then
    bash .github/scripts/promotion_selftest.sh || fail "promotion selftest"
  fi
  comps="$(grep -o 'for c in [a-z ]*; do' "$ci" | head -1 | sed 's/for c in //; s/; do//')"
  # shellcheck disable=SC2001
  largs="$(sed 's|"\$c/tests"||' <<<"$args")"
  failed=""
  for c in $comps; do
    step "tests: $c"
    # shellcheck disable=SC2086 # args are word-split on purpose
    if ! "$py" -m pytest $largs "$c/tests"; then
      [ $all = 1 ] || fail "tests ($c)"
      failed="$failed $c"
    fi
  done
  [ -z "$failed" ] || fail "tests:$failed"
else
  step "tests: pytest $args"
  # shellcheck disable=SC2086
  "$py" -m pytest $args || fail "tests"
fi

printf '\nSMOKE PASSED\n'
