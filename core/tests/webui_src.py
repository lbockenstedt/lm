"""Source of the WebUI main bundle, for tests that read or run it as text.

main.js is split into main.js + js/*.js (docs/webui-react-lite-plan.md).
Tests read the concatenation of every part, in load order, so a test keeps
passing when the code it checks moves to another file. The parts and their
order come from the <script> tags in WebUI/index.html, the single source.
"""
import re
from pathlib import Path

WEBUI = Path(__file__).resolve().parents[2] / "WebUI"

_PART_SRC = re.compile(r'<script src="((?:main|js/[\w-]+)\.js)\?v=__WEBUI_VERSION__"></script>')


def main_js_parts():
    """WebUI-relative paths of main.js and js/*.js, in the order index.html loads them."""
    return _PART_SRC.findall((WEBUI / "index.html").read_text(encoding="utf-8"))


def main_js_paths():
    return [WEBUI / part for part in main_js_parts()]


def main_js_source():
    return "\n".join(p.read_text(encoding="utf-8") for p in main_js_paths())
