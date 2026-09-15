"""System → Hub Status → mTLS "Per-spoke readiness": spoke/agent names render
UPPERCASE, matching the section header's own ``uppercase tracking-wider``.

Styled, not transformed — the underlying value must stay intact so the ``title``
tooltip, copy/paste and in-page search still work against the real spoke id. A
``.toUpperCase()`` on the data would break all three, so that's pinned too.
"""
from pathlib import Path

_MAIN = Path(__file__).resolve().parents[2] / "WebUI" / "main.js"
_SRC = _MAIN.read_text(encoding="utf-8")


def _readiness_fn():
    i = _SRC.index("async function loadMtlsReadiness(")
    depth, j, started = 0, i, False
    while j < len(_SRC):
        if _SRC[j] == "{":
            depth += 1
            started = True
        elif _SRC[j] == "}":
            depth -= 1
            if started and depth == 0:
                return _SRC[i:j + 1]
        j += 1
    raise AssertionError("unterminated loadMtlsReadiness")


def test_name_span_is_uppercase():
    body = _readiness_fn()
    assert 'class="font-medium uppercase"' in body


def test_name_still_escaped():
    body = _readiness_fn()
    assert "escapeHtml(s.name || s.id)" in body


def test_title_tooltip_keeps_the_raw_id():
    # The dot row's tooltip is how an operator maps a display name back to the
    # real spoke id — uppercasing must not reach it.
    body = _readiness_fn()
    assert 'title="${escapeHtml(s.id)}"' in body


def test_name_is_not_transformed_in_javascript():
    # A .toUpperCase() on the value would defeat copy/paste + Ctrl-F.
    body = _readiness_fn()
    assert "toUpperCase" not in body


def test_section_header_convention_unchanged():
    body = _readiness_fn()
    assert "uppercase tracking-wider font-semibold" in body
    assert "Per-spoke readiness" in body
