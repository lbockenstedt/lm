"""Cross-repo code-complexity scanner (see docs/code-simplicity-backlog.md).

Usage: python3 scripts/complexity_scan.py [ROOT] [--json OUT]
Reports per function: cyclomatic complexity (McCabe), length, max nesting depth,
and parameter count; prints the worst offenders and per-repo totals.
"""
# argparse: CLI flags; ast: parse Python source into syntax trees; json: --json output;
# os: walk the repos; collections: Counter/defaultdict for per-repo totals.
import argparse, ast, json, os, collections

# Directory names never scanned: virtualenvs, dependencies, caches, git data, build output.
SKIP = {"venv", ".venv", "node_modules", "__pycache__", ".git", "build", "dist"}
# AST node types that each add one independent path through a function (McCabe rule).
BRANCHES = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.ExceptHandler, ast.With,
            ast.AsyncWith, ast.IfExp, ast.comprehension, ast.Assert)
# AST node types that open a new indented block, used to measure nesting depth.
NESTERS = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.Try, ast.With, ast.AsyncWith)


def _own_nodes(fn):
    """Walk fn's body without descending into nested functions/classes (they are scored separately)."""
    # Depth-first walk using an explicit stack of nodes still to visit.
    stack = list(ast.iter_child_nodes(fn))
    while stack:
        n = stack.pop()
        # Nested defs/classes/lambdas are skipped so their complexity is not double-counted.
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        # Hand this node to the caller, then queue its children for visiting.
        yield n
        stack.extend(ast.iter_child_nodes(n))


def cyclomatic(fn):
    """Return the McCabe cyclomatic complexity of fn (1 + number of decision points)."""
    # Every function starts with one path.
    cc = 1
    # Count decision points in this function's own code only.
    for n in _own_nodes(fn):
        # if/for/while/except/with/ternary/comprehension/assert each add one branch.
        if isinstance(n, BRANCHES):
            cc += 1
        # "a and b and c" has 2 short-circuit decisions: one less than its operand count.
        elif isinstance(n, ast.BoolOp):
            cc += len(n.values) - 1
        # Each "case" in a match statement adds a branch (only on Python 3.10+ which has
        # match_case).
        elif isinstance(n, ast.match_case if hasattr(ast, "match_case") else ()):
            cc += 1
    return cc


def depth(node, d=0):
    """Return the deepest block-nesting level below node, starting the count at d."""
    # Deepest level seen so far; at minimum the current level.
    best = d
    # Check every direct child of this node.
    for c in ast.iter_child_nodes(node):
        # Nested defs/classes/lambdas are scored on their own, so they do not add depth here.
        if isinstance(c, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        # An "elif" is stored as an If inside the parent If's else-list; treat it as the
        # same level rather than one deeper, matching how it looks in the source.
        is_elif = (isinstance(node, ast.If) and isinstance(c, ast.If)
                   and len(node.orelse) == 1 and node.orelse[0] is c)
        # Only block-opening statements (that are not elifs) increase the depth.
        nests = isinstance(c, NESTERS) and not is_elif
        # Recurse into the child and keep the largest depth found.
        best = max(best, depth(c, d + 1 if nests else d))
    return best


def scan(root):
    """Scan every git repo directly under root and return one metrics dict per function."""
    # One row per function found.
    rows = []
    # Each immediate subdirectory of root is a candidate repo; sorted for stable output.
    for repo in sorted(os.listdir(root)):
        rp = os.path.join(root, repo)
        # Only directories with a .git folder are treated as repos.
        if not os.path.isdir(os.path.join(rp, ".git")):
            continue
        # Walk all files in the repo.
        for dp, dns, fns in os.walk(rp):
            # Prune skipped dirs and test dirs in place so os.walk never enters them.
            dns[:] = [d for d in dns if d not in SKIP and d not in ("tests", "test")]
            # Consider each file in the current directory.
            for fn in fns:
                # Only non-test Python source files are measured.
                if not fn.endswith(".py") or fn.startswith("test_"):
                    continue
                p = os.path.join(dp, fn)
                # Parse the file; files that are not valid Python (e.g. py2 leftovers) are skipped.
                try:
                    tree = ast.parse(open(p, encoding="utf-8", errors="ignore").read())
                except SyntaxError:
                    continue
                # Visit every node in the file looking for function definitions (including nested
                # ones).
                for n in ast.walk(tree):
                    if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        # Shortcut to the function's argument list, used for the parameter count.
                        a = n.args
                        # Record repo, relative file, name, start line, total lines, complexity,
                        # depth,
                        # and parameter count (positional + keyword-only + positional-only).
                        rows.append({
                            "repo": repo, "file": os.path.relpath(p, root), "fn": n.name,
                            "line": n.lineno, "len": (n.end_lineno or n.lineno) - n.lineno + 1,
                            "cc": cyclomatic(n), "depth": depth(n),
                            "params": len(a.args) + len(a.kwonlyargs) + len(a.posonlyargs),
                        })
    return rows


def main():
    """Parse arguments, scan all repos, and print per-repo totals plus the 40 worst functions."""
    # By default scan the folder that holds lm and its sibling repos (two levels up).
    default_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    # Use the module docstring as --help text, keeping its line breaks.
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("root", nargs="?", default=default_root, help="directory holding the sibling repos")
    ap.add_argument("--json", metavar="OUT", help="also write every function's metrics to OUT")
    args = ap.parse_args()
    # Collect metrics for every function in every repo.
    rows = scan(args.root)
    # Optionally save the raw rows for later analysis.
    if args.json:
        json.dump(rows, open(args.json, "w"))
    # Per-repo counters; missing keys start at 0.
    per = collections.defaultdict(lambda: collections.Counter())
    # Tally each function into its repo's counters; True/False add as 1/0.
    for r in rows:
        c = per[r["repo"]]
        c["fns"] += 1
        c["cc>25"] += r["cc"] > 25
        c["cc>50"] += r["cc"] > 50
        c["len>200"] += r["len"] > 200
        c["depth>=6"] += r["depth"] >= 6
    # Header line for the per-repo totals table.
    print(f"{'repo':10s} {'fns':>6s} {'cc>25':>6s} {'cc>50':>6s} {'len>200':>8s} {'depth>=6':>9s}")
    # Repos with the most very complex (cc>25) functions are listed first.
    for repo, c in sorted(per.items(), key=lambda kv: -kv[1]["cc>25"]):
        print(f"{repo:10s} {c['fns']:6d} {c['cc>25']:6d} {c['cc>50']:6d} {c['len>200']:8d} {c['depth>=6']:9d}")
    # Then list the 40 most complex functions across all repos.
    print("\nTop 40 by cyclomatic complexity:")
    for r in sorted(rows, key=lambda r: -r["cc"])[:40]:
        print(f"cc={r['cc']:4d} len={r['len']:5d} depth={r['depth']:2d} params={r['params']:2d}  {r['file']}:{r['line']} {r['fn']}")


# Only run when executed as a script.
if __name__ == "__main__":
    main()
