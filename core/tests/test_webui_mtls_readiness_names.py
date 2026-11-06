"""System → Hub Status → mTLS "Per-spoke readiness": spoke/agent names render
as-is in sentence case (HPE Design System: no all-caps text).

The underlying value must stay intact so the ``title`` tooltip, copy/paste and
in-page search still work against the real spoke id. A ``.toUpperCase()`` on
the data would break all three, so that's pinned too.
"""
from pathlib import Path
from webui_src import main_js_source

_MAIN = Path(__file__).resolve().parents[2] / "WebUI" / "main.js"
_SRC = main_js_source()


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


def test_name_span_is_not_all_caps():
    body = _readiness_fn()
    assert 'class="font-medium" title=' in body
    assert "uppercase" not in body


def test_name_still_escaped():
    body = _readiness_fn()
    assert "escapeHtml(s.name || s.id)" in body


def test_title_tooltip_keeps_the_raw_id():
    # The dot row's tooltip is how an operator maps a display name back to the
    # real spoke id — any display styling must not reach it.
    body = _readiness_fn()
    assert 'title="${escapeHtml(s.id)}"' in body


def test_name_is_not_transformed_in_javascript():
    # A .toUpperCase() on the value would defeat copy/paste + Ctrl-F.
    body = _readiness_fn()
    assert "toUpperCase" not in body


def test_section_header_is_sentence_case():
    body = _readiness_fn()
    assert 'class="text-xs text-slate-500 mb-1.5 font-semibold">Per-spoke readiness' in body
    assert "Per-spoke readiness" in body
