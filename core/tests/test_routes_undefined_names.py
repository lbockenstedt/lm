"""Static check: no route module references a name it never defined.

Why this exists. `core/src/routes/test_feed.py` shipped calling
`secrets.token_urlsafe(24)` without `import secrets`. Everything that guards
this repo passed it: `py_compile` succeeds (a NameError is a runtime event, not
a syntax error), `import`ing the module succeeds (the name is only resolved when
the endpoint is actually called), and the unit tests never reached it because
starting a feed needs a live app and hub. It failed for the first time in
production, as an opaque 500.

Route handlers are exactly where this hides: each one is a closure that only
runs when someone clicks the thing, so an import that got dropped during an edit
stays invisible until a user finds it. pyflakes resolves names without executing
anything, which is precisely the gap.

Scoped to undefined names only. This is NOT a lint gate — unused imports, style
and shadowing are deliberately ignored, so the suite does not start failing over
cosmetics.
"""
import os
import pathlib
import sys

import pytest

pyflakes = pytest.importorskip("pyflakes",
                               reason="pyflakes not installed; static name check skipped")

from pyflakes import checker  # noqa: E402
from pyflakes import messages as pyflakes_messages  # noqa: E402
import ast  # noqa: E402

_SRC = pathlib.Path(__file__).resolve().parents[1] / "src"

#: The message types that mean "this name will raise at runtime". Everything
#: else pyflakes reports (unused imports, redefinitions, f-string oddities) is
#: style and is not this test's business.
_FATAL = (
    pyflakes_messages.UndefinedName,
    pyflakes_messages.UndefinedLocal,
    pyflakes_messages.UndefinedExport,
)


def _python_files():
    for base in ("routes", ""):
        d = _SRC / base if base else _SRC
        if not d.is_dir():
            continue
        for p in sorted(d.glob("*.py")):
            yield p


def _annotation_only_names(tree):
    """Names that appear ONLY inside annotations.

    Under ``from __future__ import annotations`` (PEP 563) annotations are
    never evaluated, so `def f(x: Optional[str])` without importing Optional is
    legal and harmless. pyflakes still reports it, and several modules here use
    exactly that pattern — flagging them would make this check noise and it
    would get disabled, taking the real coverage with it. So: ignore a name
    only when every one of its occurrences is inside an annotation."""
    in_ann, everywhere = set(), set()

    def collect(node, into):
        for n in ast.walk(node):
            if isinstance(n, ast.Name):
                into.add(n.id)

    for node in ast.walk(tree):
        anns = []
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            anns = [a.annotation for a in
                    node.args.args + node.args.kwonlyargs + node.args.posonlyargs
                    if a.annotation] + ([node.returns] if node.returns else [])
        elif isinstance(node, ast.AnnAssign) and node.annotation:
            anns = [node.annotation]
        for a in anns:
            collect(a, in_ann)

    ann_nodes = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for a in (node.args.args + node.args.kwonlyargs + node.args.posonlyargs):
                if a.annotation:
                    ann_nodes.update(id(x) for x in ast.walk(a.annotation))
            if node.returns:
                ann_nodes.update(id(x) for x in ast.walk(node.returns))
        elif isinstance(node, ast.AnnAssign) and node.annotation:
            ann_nodes.update(id(x) for x in ast.walk(node.annotation))

    for n in ast.walk(tree):
        if isinstance(n, ast.Name) and id(n) not in ann_nodes:
            everywhere.add(n.id)
    return in_ann - everywhere


def _has_future_annotations(tree):
    return any(isinstance(n, ast.ImportFrom) and n.module == "__future__"
               and any(a.name == "annotations" for a in n.names)
               for n in ast.walk(tree))


def _undefined_names(path):
    try:
        tree = ast.parse(path.read_text(), filename=str(path))
    except SyntaxError as e:  # a syntax error is a different (louder) failure
        return [f"{path.name}: SyntaxError: {e}"]
    ignorable = _annotation_only_names(tree) if _has_future_annotations(tree) else set()
    out = []
    for m in checker.Checker(tree, filename=str(path)).messages:
        if not isinstance(m, _FATAL):
            continue
        name = m.message_args[0] if m.message_args else ""
        if name in ignorable:
            continue
        out.append(f"{path.name}:{m.lineno}: {m.message % m.message_args}")
    return out


#: Pre-existing findings, recorded the day this check was added. Every one is a
#: REAL latent NameError in a rarely-taken branch — not a false positive, and
#: not something to leave forever. They are baselined rather than fixed here
#: because they sit in unrelated modules and each needs its own judgement about
#: what the missing name should be:
#:
#:   cert_distribution `_unwrap`  — the LE_LIST_CERTS fallback in the two
#:       distribute_* paths; both sit inside a try/except, so the lookup
#:       silently degrades instead of crashing. Probably meant `unwrap_spoke`.
#:   pxmx `_asyncio`              — three call sites; the module imports
#:       `asyncio` plainly, so these look like a rename left half-applied.
#:   oidc `cfg`                   — one site.
#:   setup_admin `ctx`            — a closure referencing an enclosing-scope
#:       name before assignment; needs care, not a quick import.
#:
#: The list is self-cleaning: fix one and this test FAILS until it is removed
#: from here, so the baseline cannot quietly rot into a permanent exemption.
_BASELINE = {
    ("cert_distribution.py", "_unwrap"),
    ("pxmx.py", "_asyncio"),
    ("oidc.py", "cfg"),
    ("setup_admin.py", "ctx"),
}


def _key(finding):
    fname = finding.split(":", 1)[0]
    name = finding.rsplit("'", 2)[-2] if "'" in finding else finding
    return (fname, name)


@pytest.mark.parametrize("path", list(_python_files()), ids=lambda p: p.name)
def test_no_undefined_names(path):
    """Every name a module uses must be importable/defined in that module.

    A failure here is the `secrets` bug again: code that imports fine, compiles
    fine, and raises NameError the moment a user triggers it."""
    bad = [f for f in _undefined_names(path) if _key(f) not in _BASELINE]
    assert not bad, ("undefined name(s) — a runtime NameError waiting to happen:\n"
                     + "\n".join(bad))


def test_baseline_has_no_stale_entries():
    """Fixing a baselined bug must remove it from _BASELINE.

    Without this, the baseline becomes a permanent exemption list and the next
    genuine bug in one of those modules hides behind an entry that no longer
    describes anything."""
    live = set()
    for p in _python_files():
        live.update(_key(f) for f in _undefined_names(p))
    stale = sorted(_BASELINE - live)
    assert not stale, ("these baselined findings are fixed — delete them from "
                       f"_BASELINE: {stale}")


def test_the_check_actually_catches_the_regression(tmp_path):
    """Guard the guard: prove this test would have caught the shipped bug,
    rather than silently passing because pyflakes was configured out."""
    bug = tmp_path / "regression.py"
    bug.write_text("def f():\n    return secrets.token_urlsafe(24)\n")
    assert _undefined_names(bug), "the check no longer detects a missing import"
