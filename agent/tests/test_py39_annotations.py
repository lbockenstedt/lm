"""Keep agent and core modules importable on the Python 3.9 dev machine.

Production runs 3.11, but the dev machine runs 3.9 (core/src/update_recovery.py).
Python evaluates a function's annotations when the def runs, so an ``X | None``
annotation raises TypeError on 3.9 unless the module has
``from __future__ import annotations``. The repo convention is ``Optional[X]``
(core/src/api.py).
"""

import ast
from pathlib import Path

_LM_ROOT = Path(__file__).resolve().parents[2]


def _defers_annotations(tree):
    """Return True when the module has ``from __future__ import annotations``."""
    return any(
        isinstance(node, ast.ImportFrom) and node.module == "__future__"
        and any(alias.name == "annotations" for alias in node.names)
        for node in tree.body
    )


def _evaluated_annotations(tree):
    """Yield the annotations Python evaluates: signatures and module/class fields."""
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            args = node.args
            params = args.posonlyargs + args.args + args.kwonlyargs + [args.vararg, args.kwarg]
            yield from (p.annotation for p in params if p is not None and p.annotation is not None)
            if node.returns is not None:
                yield node.returns
        if isinstance(node, (ast.Module, ast.ClassDef)):
            yield from (stmt.annotation for stmt in node.body if isinstance(stmt, ast.AnnAssign))


def test_no_pep604_union_in_evaluated_annotations():
    """No agent or core module evaluates an ``X | Y`` annotation."""
    found = []
    for root in ("agent/src", "core/src"):
        for path in sorted((_LM_ROOT / root).rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            if _defers_annotations(tree):
                continue
            for annotation in _evaluated_annotations(tree):
                if any(isinstance(n, ast.BinOp) and isinstance(n.op, ast.BitOr)
                       for n in ast.walk(annotation)):
                    found.append(f"{path.relative_to(_LM_ROOT)}:{annotation.lineno}")
    assert not found, "use Optional[X] / Union[X, Y] for Python 3.9: " + ", ".join(found)
