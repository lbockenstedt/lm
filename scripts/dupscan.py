"""Cross-repo duplicate-function scanner (see docs/code-consolidation-backlog.md).

Usage: python3 scripts/dupscan.py [ROOT] [--json OUT]
ROOT is the directory holding the sibling repos (default: lm's parent).
Groups functions (6+ lines, outside tests) whose bodies are identical
("exact") or identical after renaming variables and string literals
("structural"), and prints how many redundant lines each kind accounts for.
"""
import argparse, ast, collections, copy, hashlib, json, os

SKIP_DIRS = {"venv", ".venv", "node_modules", "__pycache__", ".git", "build", "dist", "tests", "test"}
MIN_LINES = 6


class Normalize(ast.NodeTransformer):
    """Blank out names, arguments and strings so renamed copies hash the same."""

    def visit_Name(self, node):
        return ast.copy_location(ast.Name(id="_", ctx=node.ctx), node)

    def visit_arg(self, node):
        node.arg = "_"
        node.annotation = None
        return node

    def visit_Constant(self, node):
        if isinstance(node.value, str):
            return ast.copy_location(ast.Constant(value="S"), node)
        return node


def python_files(root):
    for repo in sorted(os.listdir(root)):
        repo_path = os.path.join(root, repo)
        if not os.path.isdir(os.path.join(repo_path, ".git")):
            continue
        for dirpath, dirnames, filenames in os.walk(repo_path):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for name in filenames:
                if name.endswith(".py") and not name.startswith("test_"):
                    yield repo, os.path.join(dirpath, name)


def body_without_docstring(fn):
    body = fn.body
    first = body[0] if body else None
    if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
        body = body[1:]
    return body


def digest(tree):
    return hashlib.sha1(ast.dump(tree).encode()).hexdigest()


def scan(root):
    exact = collections.defaultdict(list)
    structural = collections.defaultdict(list)
    for repo, path in python_files(root):
        try:
            tree = ast.parse(open(path, encoding="utf-8", errors="ignore").read())
        except SyntaxError:
            continue
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            body = body_without_docstring(fn)
            length = (fn.end_lineno or fn.lineno) - fn.lineno + 1
            if not body or length < MIN_LINES:
                continue
            module = ast.Module(body=body, type_ignores=[])
            record = (repo, os.path.relpath(path, root), fn.name, fn.lineno, length)
            exact[digest(module)].append(record)
            structural[digest(Normalize().visit(copy.deepcopy(module)))].append(record)
    return exact, structural


def cross_file_groups(buckets):
    """Keep buckets whose copies live in more than one file, biggest saving first."""
    groups = [recs for recs in buckets.values() if len({r[1] for r in recs}) > 1]
    return sorted(groups, key=redundant_lines, reverse=True)


def redundant_lines(group):
    return group[0][4] * (len(group) - 1)


def main():
    default_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("root", nargs="?", default=default_root, help="directory holding the sibling repos")
    ap.add_argument("--json", metavar="OUT", default="/tmp/dupscan.json", help="where to write the groups")
    args = ap.parse_args()

    exact, structural = scan(args.root)
    exact_groups = cross_file_groups(exact)
    exact_sets = [set(g) for g in exact_groups]
    # A structural group that is also an exact group adds nothing new.
    structural_groups = [g for g in cross_file_groups(structural) if set(g) not in exact_sets]

    json.dump({"exact": exact_groups, "fuzzy": structural_groups}, open(args.json, "w"))
    for label, groups in (("exact", exact_groups), ("structural (renamed vars)", structural_groups)):
        print(f"## {label}: {len(groups)} groups, {sum(map(redundant_lines, groups))} redundant lines")


if __name__ == "__main__":
    main()
