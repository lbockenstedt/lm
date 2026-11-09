#!/usr/bin/env python3
"""Check that twin files stay in step (twins.json).

Run from a repo's CI. Every pair that includes this repo is compared:
- a pair inside this repo that differs is an error (fails the job);
- a pair across repos that differs is a warning, because the other repo's
  matching change may still be on its way.
The other repo's copy is read from GitHub (all fleet repos are public) on the
same branch. Plain Python, no dependencies.

Usage: check_twins.py --repo cs --branch dev [--twins path] [--root .]
"""
import argparse
import ast
import json
import os
import re
import sys
import urllib.request

OWNER = "lbockenstedt"


def read_side(spec, repo, root, branch):
    """Text of one 'repo:path' side: from disk for this repo, else from GitHub."""
    other, path = spec.split(":", 1)
    if other == repo:
        try:
            with open(os.path.join(root, path), encoding="utf-8", errors="replace") as fh:
                return fh.read()
        except OSError:
            return None
    url = "https://raw.githubusercontent.com/%s/%s/%s/%s" % (OWNER, other, branch, path)
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001 - a missing remote copy is reported as unreadable
        return None


def extract_keys(text, symbol, path):
    """The list a file defines under ``symbol`` (Python, JS, bash or PowerShell)."""
    if path.endswith(".py"):
        for node in ast.walk(ast.parse(text)):
            targets = node.targets if isinstance(node, ast.Assign) else (
                [node.target] if isinstance(node, ast.AnnAssign) else [])
            if any(getattr(t, "id", None) == symbol for t in targets):
                return list(ast.literal_eval(node.value))
        return None
    # Bash: NAME=( a b c )   PowerShell: $script:NAME = @( 'a', 'b' )   JS: NAME = [ 'a', 'b' ]
    m = re.search(r"%s\s*=\s*(?:@\(|\(|\[)([^)\]]*)[)\]]" % re.escape(symbol), text)
    if not m:
        return None
    body = re.sub(r"#[^\n]*|//[^\n]*", "", m.group(1))
    return re.findall(r"""['"]?([\w.-]+)['"]?""", body)


def check(twins, repo, root, branch):
    """Return (errors, warnings) as lists of messages."""
    errors, warnings = [], []
    for pair in twins["pairs"]:
        # Only pairs with a copy in this repo; same-repo-only pairs can block.
        files = pair["files"]
        if not any(f.split(":", 1)[0] == repo for f in files):
            continue
        local = all(f.split(":", 1)[0] == repo for f in files)
        # Every copy's text: from disk here, from GitHub for other repos.
        texts = [read_side(f, repo, root, branch) for f in files]
        if any(t is None for t in texts):
            warnings.append("%s: could not read %s" % (pair["name"], ", ".join(
                f for f, t in zip(files, texts) if t is None)))
            continue
        # Compare whole files, or just the named key list in each.
        if pair["kind"] == "keys":
            values = [extract_keys(t, pair["symbol"], f.split(":", 1)[1]) for f, t in zip(files, texts)]
        else:
            values = texts
        missing = any(v is None for v in values)
        if not missing and all(v == values[0] for v in values[1:]):
            continue
        msg = "%s differs between %s%s" % (pair["name"], " and ".join(files),
                                           " (symbol not found)" if missing else "")
        (errors if local else warnings).append(msg)
    return errors, warnings


def main(argv=None):
    """CLI: print GitHub annotations; exit 1 when a same-repo pair differs."""
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--repo", required=True, help="short name of this repo, e.g. cs")
    ap.add_argument("--branch", default="dev", help="branch to read the other repos' copies from")
    ap.add_argument("--twins", default=os.path.join(os.path.dirname(__file__), "..", "twins.json"))
    ap.add_argument("--root", default=".")
    args = ap.parse_args(argv)
    # Load the pair list, check, then report as GitHub annotations.
    with open(args.twins, encoding="utf-8") as fh:
        twins = json.load(fh)
    errors, warnings = check(twins, args.repo, args.root, args.branch)
    for w in warnings:
        print("::warning title=Twin files out of step::%s" % w)
    for e in errors:
        print("::error title=Twin files out of step::%s" % e)
    print("twins: %d error(s), %d warning(s)" % (len(errors), len(warnings)))
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
