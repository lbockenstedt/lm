#!/usr/bin/env python3
"""Fail CI only on ruff errors a change introduces, not on ones it inherited.

The fleet carries latent errors (undefined names, syntax in scratch files) in
files nobody has touched in months. Blocking on every error in a changed file
would fail the first person to fix a typo there, so for each changed .py file
we lint both the base version and the new one and block only on findings that
are new. Inherited findings are reported as warnings so they stay visible.

Usage: ruff_new.py --base <sha> [--select E9,F63,F7,F82] [--path .]
"""
import argparse
import collections
import json
import os
import subprocess
import sys
import tempfile

# Directories other workflow steps check out next to the repo; never ours to lint.
SKIP_PREFIXES = ("_ab/", "_lm/", "_lmci/")


def git(path, *args):
    """Run git in ``path`` and return stdout (empty string on failure)."""
    r = subprocess.run(["git", "-C", path, *args], capture_output=True, text=True)
    return r.stdout if r.returncode == 0 else ""


def ruff(file_path, select):
    """Lint one file; return a list of ruff's JSON findings."""
    r = subprocess.run([sys.executable, "-m", "ruff", "check", "--no-cache", "--isolated",
                        "--select", select, "--output-format", "json", file_path],
                       capture_output=True, text=True)
    try:
        return json.loads(r.stdout or "[]")
    except ValueError:
        return []


def key(f):
    """Identity of a finding that survives unrelated edits moving its line."""
    return (f.get("code") or "syntax", f.get("message", ""))


def main(argv=None):
    """Lint changed files at base and head; exit 1 if head adds any finding."""
    ap = argparse.ArgumentParser(description=main.__doc__)
    ap.add_argument("--base", required=True)
    ap.add_argument("--select", default="E9,F63,F7,F82")
    ap.add_argument("--path", default=".")
    args = ap.parse_args(argv)

    # New branch or unknown base: nothing to compare against.
    if not args.base.strip("0") or not git(args.path, "cat-file", "-t", args.base).strip():
        print("ruff: no usable base (%s); skipped" % args.base)
        return 0
    changed = [p for p in git(args.path, "diff", "--name-only", "--diff-filter=AMR",
                              args.base + "...HEAD", "--", "*.py").splitlines()
               if p and not p.startswith(SKIP_PREFIXES)]

    new_count = old_count = 0
    with tempfile.TemporaryDirectory() as tmp:
        for rel in changed:
            head = ruff(os.path.join(args.path, rel), args.select)
            if not head:
                continue
            # Same file at the base (absent for added files -> everything is new).
            before = collections.Counter()
            src = git(args.path, "show", "%s:%s" % (args.base, rel))
            if src:
                base_file = os.path.join(tmp, os.path.basename(rel))
                with open(base_file, "w", encoding="utf-8") as fh:
                    fh.write(src)
                before.update(key(f) for f in ruff(base_file, args.select))
            # Consume base findings one-for-one; whatever is left is new.
            for f in head:
                k = key(f)
                row = (f.get("location") or {}).get("row", 1)
                if before[k] > 0:
                    before[k] -= 1
                    old_count += 1
                    level = "warning"
                else:
                    new_count += 1
                    level = "error"
                print("::%s file=%s,line=%s,title=ruff %s::%s%s" % (
                    level, rel, row, k[0], f.get("message", ""),
                    "" if level == "error" else " (pre-existing)"))
    print("ruff: %d new error(s), %d pre-existing in %d changed file(s)"
          % (new_count, old_count, len(changed)))
    return 1 if new_count else 0


if __name__ == "__main__":
    raise SystemExit(main())
