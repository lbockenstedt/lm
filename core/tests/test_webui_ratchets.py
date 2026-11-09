"""Counts that may only go down as the WebUI moves to the React-lite style
(docs/webui-react-lite-plan.md). When you convert a view, lower the number
to the new count; never raise it -- write new markup with safeHtml and wire
events with data-action / delegate() instead (docs/webui.md)."""
import re

from webui_src import WEBUI


def _sources():
    files = [p for p in WEBUI.rglob("*.js") if "assets" not in p.parts] + [WEBUI / "index.html"]
    return [p.read_text(encoding="utf-8") for p in files]


def _count(pattern, flags=0):
    return sum(len(re.findall(pattern, s, flags)) for s in _sources())


def test_escape_html_calls_only_go_down():
    assert _count(r"\bescapeHtml\(") <= 1118


def test_inline_event_handlers_only_go_down():
    assert _count(r"\son[a-z]+=[\"']") <= 994


def test_window_globals_only_go_down():
    assert _count(r"^\s*window\.\w+\s*=[^=]", re.M) <= 530
