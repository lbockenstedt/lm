"""WebUI access and placement invariants for System diagnostics."""

import ast
import os
import re


MAIN_JS = os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", "..", "WebUI", "main.js"))


def _src():
    with open(MAIN_JS, encoding="utf-8") as fh:
        return fh.read()


def _function(name):
    src = _src()
    start = src.index(name)
    depth = 0
    for i in range(src.index("{", start), len(src)):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return src[start:i + 1]
    raise AssertionError(f"unbalanced {name}")


def test_diagnostics_is_the_final_system_tab():
    match = re.search(r"^\s*settings:\s*(\[[^\n]+\]),$", _src(), re.MULTILINE)
    assert match
    assert ast.literal_eval(match.group(1))[-1] == "Diagnostics"


def test_diagnostics_navigation_requires_global_admin():
    set_subview = _function("async function setSubView(")
    assert "subMenu === 'Diagnostics' && !isAdmin()" in set_subview

    render_top_nav = _function("function renderTopNav(")
    assert "m === 'Diagnostics' && !isAdmin()" in render_top_nav


def test_diagnostics_status_shortcut_requires_global_admin():
    indicators = _function("function renderSpokeIndicators(")
    assert "_mdWrap && isAdmin() && !_mdWrap._diagBound" in indicators
    assert "classList.toggle('cursor-pointer', isAdmin())" in indicators
