#!/usr/bin/env python3
"""Copy the fleet-owned files from lm into every fleet repo (twins.json "fleet").

lm holds the single copy people edit: the fleet rules, the fleet agents and
the skills. Tools only read them from the repo they are working in, so each
repo carries a copy, and this script keeps those copies identical.

- files:    copied as-is.
- dirs:     mirrored recursively; anything the repo has but lm does not is
            deleted, unless its top-level name is "<repo>-..." (a repo's own
            agent or skill stays).
- agents_md: {"source": <file>, "target": "AGENTS.md"} -- the source file is
            placed between the fleet-rules markers in the target, so every tool
            that auto-loads AGENTS.md (Copilot, Codex, Cursor, Claude via
            @AGENTS.md) sees the rules. Also applied to lm itself. The rest of
            AGENTS.md (repo-specific facts) is left alone.

Used by .github/workflows/sync-fleet-files.yml on the runner, and locally:

    python lm/.github/scripts/sync_fleet_files.py --src lm --dest-root .            # write
    python lm/.github/scripts/sync_fleet_files.py --src lm --dest-root . --check    # report only

Plain Python, no dependencies. Prints one "changed <repo>" line per repo it
changed (or would change, with --check) and exits 1 on --check drift.
"""
import argparse
import filecmp
import json
import os
import re
import shutil
import sys

BEGIN = "<!-- fleet-rules:begin (synced from lm/.github/fleet-rules.md -- edit there) -->"
END = "<!-- fleet-rules:end -->"


def _files_under(root):
    """Paths (relative to root) of every file below root, sorted; [] if absent."""
    out = []
    for base, _dirs, names in os.walk(root):
        out += [os.path.relpath(os.path.join(base, n), root) for n in names]
    return sorted(out)


def plan(src, dest, repo, files, dirs):
    """(copies, deletes) needed to bring one repo checkout in line with lm."""
    copies, deletes = [], []
    # Single files: copy when missing or different.
    for rel in files:
        s, d = os.path.join(src, rel), os.path.join(dest, rel)
        if os.path.isfile(s) and not (os.path.isfile(d) and filecmp.cmp(s, d, shallow=False)):
            copies.append(rel)
    # Directories: mirror lm's tree, keep the repo's own "<repo>-*" entries.
    for rel in dirs:
        wanted = _files_under(os.path.join(src, rel))
        for sub in wanted:
            s, d = os.path.join(src, rel, sub), os.path.join(dest, rel, sub)
            if not (os.path.isfile(d) and filecmp.cmp(s, d, shallow=False)):
                copies.append(os.path.join(rel, sub))
        for sub in _files_under(os.path.join(dest, rel)):
            if sub not in wanted and not sub.split(os.sep)[0].startswith(repo + "-"):
                deletes.append(os.path.join(rel, sub))
    return copies, deletes


def with_block(text, block):
    """``text`` (an AGENTS.md) with ``block`` between the fleet-rules markers.

    An existing marked block is replaced in place. Otherwise the block is
    appended, so the repo's own facts stay at the top where readers start."""
    marked = "%s\n\n%s\n\n%s\n" % (BEGIN, block.strip(), END)
    if BEGIN in text and END in text:
        head, rest = text.split(BEGIN, 1)
        tail = rest.split(END, 1)[1].lstrip("\n")
        return head + marked + ("\n" + tail if tail else "")
    return (text.rstrip("\n") + "\n\n" if text.strip() else "") + marked


def rules_block(src, spec):
    """The rules text to place in AGENTS.md: the source file minus its
    editor-facing HTML comment header."""
    with open(os.path.join(src, spec["source"]), encoding="utf-8") as fh:
        return re.sub(r"<!--.*?-->\s*", "", fh.read(), count=1, flags=re.S).strip()


def agents_md_change(src, dest, spec):
    """New AGENTS.md text for this checkout, or None when already current."""
    if not spec:
        return None
    path = os.path.join(dest, spec.get("target", "AGENTS.md"))
    old = ""
    if os.path.isfile(path):
        with open(path, encoding="utf-8") as fh:
            old = fh.read()
    new = with_block(old, rules_block(src, spec))
    return None if new == old else new


def main(argv=None):
    """Sync (or with --check, report) every fleet repo under --dest-root."""
    ap = argparse.ArgumentParser(description=main.__doc__)
    ap.add_argument("--src", required=True, help="lm checkout")
    ap.add_argument("--dest-root", required=True, help="directory holding the repo checkouts")
    ap.add_argument("--repos", nargs="*", help="default: every repo in twins.json fleet.repos")
    ap.add_argument("--check", action="store_true", help="report drift, change nothing")
    args = ap.parse_args(argv)
    with open(os.path.join(args.src, ".github", "twins.json"), encoding="utf-8") as fh:
        fleet = json.load(fh)["fleet"]

    drift = False
    spec = fleet.get("agents_md")
    repos = args.repos or [fleet["source"]] + fleet["repos"]
    for repo in repos:
        dest = os.path.join(args.dest_root, repo)
        if not os.path.isdir(dest):
            print("skip %s: no checkout at %s" % (repo, dest))
            continue
        # lm is the source: only its AGENTS.md block can be out of date.
        if os.path.realpath(dest) == os.path.realpath(args.src):
            copies, deletes = [], []
        else:
            copies, deletes = plan(args.src, dest, repo, fleet.get("files", []), fleet.get("dirs", []))
        agents_md = agents_md_change(args.src, dest, spec)
        if not copies and not deletes and agents_md is None:
            continue
        drift = True
        what = ["+" + c for c in copies] + ["-" + d for d in deletes]
        what += ["~" + spec.get("target", "AGENTS.md")] if agents_md is not None else []
        print("changed %s: %s" % (repo, ", ".join(what)))
        if args.check:
            continue
        # Apply: copy, delete, then rewrite the AGENTS.md block.
        for rel in copies:
            os.makedirs(os.path.dirname(os.path.join(dest, rel)), exist_ok=True)
            shutil.copyfile(os.path.join(args.src, rel), os.path.join(dest, rel))
        for rel in deletes:
            os.remove(os.path.join(dest, rel))
        if agents_md is not None:
            with open(os.path.join(dest, spec.get("target", "AGENTS.md")), "w", encoding="utf-8") as fh:
                fh.write(agents_md)
    return 1 if (args.check and drift) else 0


if __name__ == "__main__":
    sys.exit(main())
