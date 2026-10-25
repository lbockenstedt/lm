"""Cross-repo code-complexity scanner (see docs/code-simplicity-backlog.md).

Usage: python3 scripts/complexity_scan.py [ROOT] [--json OUT]
Reports per function: cyclomatic complexity (McCabe), length, max nesting depth,
and parameter count; prints the worst offenders and per-repo totals.
"""
import ast, json, os, sys, collections

SKIP = {"venv", ".venv", "node_modules", "__pycache__", ".git", "build", "dist"}
BRANCHES = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.ExceptHandler, ast.With,
            ast.AsyncWith, ast.IfExp, ast.comprehension, ast.Assert)
NESTERS = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.Try, ast.With, ast.AsyncWith)


def _own_nodes(fn):
    """Walk fn's body without descending into nested functions/classes (they are scored separately)."""
    stack = list(ast.iter_child_nodes(fn))
    while stack:
        n = stack.pop()
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        yield n
        stack.extend(ast.iter_child_nodes(n))


def cyclomatic(fn):
    cc = 1
    for n in _own_nodes(fn):
        if isinstance(n, BRANCHES):
            cc += 1
        elif isinstance(n, ast.BoolOp):
            cc += len(n.values) - 1
        elif isinstance(n, ast.match_case if hasattr(ast, "match_case") else ()):
            cc += 1
    return cc


def depth(node, d=0):
    best = d
    for c in ast.iter_child_nodes(node):
        if isinstance(c, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        is_elif = (isinstance(node, ast.If) and isinstance(c, ast.If)
                   and len(node.orelse) == 1 and node.orelse[0] is c)
        nests = isinstance(c, NESTERS) and not is_elif
        best = max(best, depth(c, d + 1 if nests else d))
    return best


def scan(root):
    rows = []
    for repo in sorted(os.listdir(root)):
        rp = os.path.join(root, repo)
        if not os.path.isdir(os.path.join(rp, ".git")):
            continue
        for dp, dns, fns in os.walk(rp):
            dns[:] = [d for d in dns if d not in SKIP and d not in ("tests", "test")]
            for fn in fns:
                if not fn.endswith(".py") or fn.startswith("test_"):
                    continue
                p = os.path.join(dp, fn)
                try:
                    tree = ast.parse(open(p, encoding="utf-8", errors="ignore").read())
                except SyntaxError:
                    continue
                for n in ast.walk(tree):
                    if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        a = n.args
                        rows.append({
                            "repo": repo, "file": os.path.relpath(p, root), "fn": n.name,
                            "line": n.lineno, "len": (n.end_lineno or n.lineno) - n.lineno + 1,
                            "cc": cyclomatic(n), "depth": depth(n),
                            "params": len(a.args) + len(a.kwonlyargs) + len(a.posonlyargs),
                        })
    return rows


def main():
    argv = sys.argv[1:]
    out = None
    if "--json" in argv:
        i = argv.index("--json")
        out = argv[i + 1]
        del argv[i:i + 2]
    args = argv
    root = args[0] if args else os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    rows = scan(root)
    if out:
        json.dump(rows, open(out, "w"))
    per = collections.defaultdict(lambda: collections.Counter())
    for r in rows:
        c = per[r["repo"]]
        c["fns"] += 1
        c["cc>25"] += r["cc"] > 25
        c["cc>50"] += r["cc"] > 50
        c["len>200"] += r["len"] > 200
        c["depth>=6"] += r["depth"] >= 6
    print(f"{'repo':10s} {'fns':>6s} {'cc>25':>6s} {'cc>50':>6s} {'len>200':>8s} {'depth>=6':>9s}")
    for repo, c in sorted(per.items(), key=lambda kv: -kv[1]["cc>25"]):
        print(f"{repo:10s} {c['fns']:6d} {c['cc>25']:6d} {c['cc>50']:6d} {c['len>200']:8d} {c['depth>=6']:9d}")
    print("\nTop 40 by cyclomatic complexity:")
    for r in sorted(rows, key=lambda r: -r["cc"])[:40]:
        print(f"cc={r['cc']:4d} len={r['len']:5d} depth={r['depth']:2d} params={r['params']:2d}  {r['file']}:{r['line']} {r['fn']}")


if __name__ == "__main__":
    main()
