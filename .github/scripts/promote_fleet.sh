#!/usr/bin/env bash
# Promote fleet repos through dev -> qa (-> main) using ONLY promote.yml.
#
# Usage: promote_fleet.sh [--to qa|main] <repo> [<repo> ...]
#
# For each hop it dispatches promote.yml, waits for the promote/<src>-to-<tgt>
# PR the workflow opens, waits for its checks, and merges it with a merge
# commit. Promotion is split one original PR per unit, so after each merge it
# waits for the next unit's PR and repeats until none appears.
#
# It never creates a PR or pushes a branch itself. An earlier ad-hoc helper
# did, when the promote PR was slow to appear, and opened direct dev->qa PRs
# that bypassed the VERSION pinning and intent carry-over. If no PR appears,
# that is reported and the repo is left alone for a human to look at.
set -u
OWNER=lbockenstedt
TO=main
WAIT_PR=240      # seconds to wait for promote.yml to open (or refresh) a PR
POLL=10

if [ "${1:-}" = "--to" ]; then TO=$2; shift 2; fi
case "$TO" in qa|main) ;; *) echo "--to must be qa or main" >&2; exit 2;; esac
[ $# -gt 0 ] || { sed -n '2,4p' "$0" >&2; exit 2; }

# Number of the open promotion PR for a hop, or empty.
open_pr() {
  gh pr list -R "$OWNER/$1" --head "promote/$2-to-$3" --base "$3" --state open \
     --json number -q '.[0].number' 2>/dev/null
}

# Merge every unit of one hop. Returns 1 if a PR could not be merged.
promote_hop() {
  local repo=$1 src=$2 tgt=$3 n waited merged=""
  echo "[$repo] $src -> $tgt: dispatching promote.yml"
  gh workflow run promote.yml -R "$OWNER/$repo" -f source="$src" >/dev/null || return 1
  while :; do
    # Wait for a PR we have not merged yet.
    n=""; waited=0
    while [ $waited -lt $WAIT_PR ]; do
      n=$(open_pr "$repo" "$src" "$tgt")
      [ -n "$n" ] && ! [[ " $merged " == *" $n "* ]] && break
      n=""; sleep $POLL; waited=$((waited + POLL))
    done
    if [ -z "$n" ]; then
      # No (further) PR: either nothing is left, or the workflow failed.
      local last
      last=$(gh run list -R "$OWNER/$repo" --workflow promote.yml -L 1 \
               --json conclusion,url -q '.[0] | "\(.conclusion) \(.url)"' 2>/dev/null)
      if [ -z "$merged" ]; then
        echo "[$repo] $src -> $tgt: no promotion PR appeared (last run: ${last:-unknown})"
      else
        echo "[$repo] $src -> $tgt: done (merged:$merged)"
      fi
      [ "${last%% *}" = "failure" ] && return 1
      return 0
    fi
    # Checks must finish green. The promote run may force-push the branch while
    # we watch, cancelling the run being watched, so judge by a fresh look:
    # gh exits 0 = all passed, 8 = still pending (watch again), else failed.
    local rc=8 tries=0
    while [ $rc -eq 8 ] && [ $tries -lt 6 ]; do
      sleep 15
      gh pr checks "$n" -R "$OWNER/$repo" --watch -i 20 >/dev/null 2>&1
      gh pr checks "$n" -R "$OWNER/$repo" >/dev/null 2>&1; rc=$?
      tries=$((tries + 1))
    done
    if [ $rc -ne 0 ]; then
      echo "[$repo] PR #$n checks failed -- not merging: https://github.com/$OWNER/$repo/pull/$n"
      return 1
    fi
    # Green listed checks are not enough: a required check that has not
    # registered yet leaves the PR BLOCKED. Wait for GitHub to call it CLEAN.
    local state="" w=0
    while [ $w -lt 1200 ]; do
      state=$(gh pr view "$n" -R "$OWNER/$repo" --json mergeStateStatus -q .mergeStateStatus 2>/dev/null)
      case "$state" in CLEAN|HAS_HOOKS|UNSTABLE) break ;; DIRTY) break ;; esac
      sleep 20; w=$((w + 20))
      # A head pushed with GITHUB_TOKEN starts no CI, so the required check
      # never appears. Close + reopen (as this user) once to start it.
      if [ $w -eq 120 ] && [ "$state" = BLOCKED ]; then
        echo "[$repo] PR #$n still BLOCKED -- reopening to start missing checks"
        gh pr close "$n" -R "$OWNER/$repo" >/dev/null 2>&1
        gh pr reopen "$n" -R "$OWNER/$repo" >/dev/null 2>&1
        sleep 20
      fi
      # A late check may have started: watch it through before looking again.
      gh pr checks "$n" -R "$OWNER/$repo" --watch -i 20 >/dev/null 2>&1
    done
    case "$state" in CLEAN|HAS_HOOKS|UNSTABLE) ;; *)
      echo "[$repo] PR #$n is $state -- not merging: https://github.com/$OWNER/$repo/pull/$n"
      return 1 ;;
    esac
    gh pr merge "$n" -R "$OWNER/$repo" --merge >/dev/null || {
      echo "[$repo] PR #$n merge refused: https://github.com/$OWNER/$repo/pull/$n"; return 1; }
    echo "[$repo] merged #$n into $tgt"
    merged="$merged $n"
    # The qa push queues the next dev->qa unit itself; main has no such
    # trigger, so ask again (a no-op when nothing is left).
    [ "$tgt" = main ] && gh workflow run promote.yml -R "$OWNER/$repo" -f source=qa >/dev/null
  done
}

rc=0
for repo in "$@"; do
  promote_hop "$repo" dev qa || { rc=1; continue; }
  if [ "$TO" = main ]; then
    sleep 20  # let qa's own push-triggered run settle before asking for main
    promote_hop "$repo" qa main || rc=1
  fi
done
exit $rc
