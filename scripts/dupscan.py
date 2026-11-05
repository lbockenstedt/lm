"""Cross-repo duplicate-function scanner (see docs/code-consolidation-backlog.md).

Usage: python3 scripts/dupscan.py [ROOT] [--json OUT]
ROOT is the directory holding the sibling repos (default: lm's parent).
Groups functions (6+ lines, outside tests) whose bodies are identical
("exact") or identical after renaming variables and string literals
("structural"), and prints how many redundant lines each kind accounts for.
"""
# argparse: CLI; ast: parse code; collections: grouping dicts; copy: deep-copy trees before
# normalising; hashlib: fingerprint bodies; json: write results; os: walk repos.
import argparse, ast, collections, copy, hashlib, json, os

# Directory names never scanned (environments, caches, build output, and tests).
SKIP_DIRS = {"venv", ".venv", "node_modules", "__pycache__", ".git", "build", "dist", "tests", "test"}
# Functions shorter than this many lines are too small to be worth deduplicating.
MIN_LINES = 6


class Normalize(ast.NodeTransformer):
    """Blank out names, arguments and strings so renamed copies hash the same."""

    def visit_Name(self, node):
        """Replace every variable name with "_" so differently-named copies match."""
        return ast.copy_location(ast.Name(id="_", ctx=node.ctx), node)

    def visit_arg(self, node):
        """Replace each argument name with "_" and drop its type annotation."""
        node.arg = "_"
        node.annotation = None
        return node

    def visit_Constant(self, node):
        """Replace every string literal with "S"; other constants (numbers etc.) stay as is."""
        # Only strings are blanked; numbers stay so different numeric logic is not merged.
        if isinstance(node.value, str):
            return ast.copy_location(ast.Constant(value="S"), node)
        return node


def python_files(root):
    """Yield (repo name, file path) for every non-test .py file in each git repo under root."""
    # Each immediate subdirectory of root is a candidate repo; sorted for stable output.
    for repo in sorted(os.listdir(root)):
        repo_path = os.path.join(root, repo)
        # Only directories with a .git folder are repos.
        if not os.path.isdir(os.path.join(repo_path, ".git")):
            continue
        # Walk all directories of the repo.
        for dirpath, dirnames, filenames in os.walk(repo_path):
            # Prune skipped dirs in place so os.walk never enters them.
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            # Yield Python source files, skipping test_*.py modules.
            for name in filenames:
                if name.endswith(".py") and not name.startswith("test_"):
                    yield repo, os.path.join(dirpath, name)


def body_without_docstring(fn):
    """Return fn's body statements with a leading docstring removed, if it has one."""
    # A docstring is a leading expression that is a plain constant (a string).
    body = fn.body
    first = body[0] if body else None
    if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
        body = body[1:]
    return body
# Statements with any docstring already removed.


def digest(tree):
    """Return a SHA-1 hex fingerprint of an AST, so identical code gives identical keys."""
    return hashlib.sha1(ast.dump(tree).encode()).hexdigest()


def scan(root):
    """Group functions by exact and by name-normalised body fingerprint.

    Returns:
        (exact, structural): dicts mapping fingerprint -> list of
        (repo, relative path, function name, line, length) records.
    """
    # fingerprint -> list of functions with that fingerprint.
    exact = collections.defaultdict(list)
    structural = collections.defaultdict(list)
    # Look at every candidate Python file.
    for repo, path in python_files(root):
        # Files that do not parse are skipped.
        try:
            tree = ast.parse(open(path, encoding="utf-8", errors="ignore").read())
        except SyntaxError:
            continue
        # Visit every function (including methods and nested functions).
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            # Compare bodies without docstrings, so differing docs do not hide duplicates.
            body = body_without_docstring(fn)
            # Total source lines of the function, used for the size filter and the savings count.
            length = (fn.end_lineno or fn.lineno) - fn.lineno + 1
            # Skip empty or tiny functions.
            if not body or length < MIN_LINES:
                continue
            # Wrap the body in a Module node so it can be dumped and hashed as one tree.
            module = ast.Module(body=body, type_ignores=[])
            # What we remember about this function for the report.
            record = (repo, os.path.relpath(path, root), fn.name, fn.lineno, length)
            # Exact bucket: byte-for-byte identical AST.
            exact[digest(module)].append(record)
            # Structural bucket: identical after renaming; deep-copy first because Normalize
            # mutates.
            structural[digest(Normalize().visit(copy.deepcopy(module)))].append(record)
    return exact, structural


def cross_file_groups(buckets):
    """Keep buckets whose copies live in more than one file, biggest saving first."""
    # A duplicate only counts if copies are in at least two different files.
    groups = [recs for recs in buckets.values() if len({r[1] for r in recs}) > 1]
    return sorted(groups, key=redundant_lines, reverse=True)


def redundant_lines(group):
    """Lines that could be removed by keeping one copy: size of first copy x extra copies."""
    return group[0][4] * (len(group) - 1)


def main():
    """Parse args, scan the repos, write the groups as JSON, and print a summary per kind."""
    # By default scan the folder holding lm and its sibling repos (two levels up).
    default_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    # Use the module docstring as --help text.
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("root", nargs="?", default=default_root, help="directory holding the sibling repos")
    ap.add_argument("--json", metavar="OUT", default="/tmp/dupscan.json", help="where to write the groups")
    args = ap.parse_args()

    # Bucket all functions, then keep only groups spanning several files.
    exact, structural = scan(args.root)
    exact_groups = cross_file_groups(exact)
    # Sets of records, used to recognise structural groups that are just exact groups.
    exact_sets = [set(g) for g in exact_groups]
    # A structural group that is also an exact group adds nothing new.
    structural_groups = [g for g in cross_file_groups(structural) if set(g) not in exact_sets]

    # Save both kinds of groups for follow-up work.
    json.dump({"exact": exact_groups, "fuzzy": structural_groups}, open(args.json, "w"))
    # Print one summary line per kind: number of groups and total redundant lines.
    for label, groups in (("exact", exact_groups), ("structural (renamed vars)", structural_groups)):
        print(f"## {label}: {len(groups)} groups, {sum(map(redundant_lines, groups))} redundant lines")


# Only run when executed as a script.
if __name__ == "__main__":
    main()
