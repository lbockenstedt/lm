#!/usr/bin/env bash
# ======================================================================
# set-version.sh — set every tracked VERSION file in THIS repo to a given
# MAJOR.MM version and commit "release v<ver> [skip ci]".
#
# Use for the coordinated MAJOR milestone: the auto-bump workflow never
# advances the major (it only bumps the minor and holds at .98), so cutting
# e.g. V2.00 is a deliberate fleet-wide action — run this in EACH repo with
# the same value:
#     bash scripts/set-version.sh 2.00
#
# Also handy for the one-time cutover from the legacy .NN scheme to 1.00.
# The [skip ci] message stops the bump workflow from immediately advancing
# the minor off .00. Does NOT push — review, then `git push`.
# ======================================================================
set -euo pipefail

ver="${1:-}"
if ! [[ "$ver" =~ ^[0-9]+\.[0-9]{2}$ ]]; then
    echo "usage: set-version.sh <MAJOR.MM>   e.g. 2.00   (2-digit zero-padded minor)" >&2
    exit 2
fi

cd "$(git rev-parse --show-toplevel)"

files=()
while IFS= read -r f; do [ -n "$f" ] && files+=("$f"); done < <(git ls-files | grep -E '(^|/)VERSION$')
if [ "${#files[@]}" -eq 0 ]; then
    echo "No tracked VERSION files in this repo." >&2
    exit 1
fi

for f in "${files[@]}"; do
    printf '%s\n' "$ver" > "$f"
    echo "  $f -> $ver"
done

git add -- "${files[@]}"
if git diff --cached --quiet; then
    echo "VERSION file(s) already at $ver — nothing to commit."
    exit 0
fi
git commit -m "release v$ver [skip ci]"
echo
echo "Committed release v$ver. Review, then: git push"
