"""Source of the WebUI main bundle, for tests that read or run it as text.

main.js is being split into smaller files (docs/webui-react-lite-plan.md).
Tests read the concatenation of every part, in load order, so a test keeps
passing when the code it checks moves to another file. When a part is added
to WebUI/index.html, add it to MAIN_JS_PARTS too.
"""
from pathlib import Path

WEBUI = Path(__file__).resolve().parents[2] / "WebUI"

# WebUI-relative paths, in the order index.html loads them.
MAIN_JS_PARTS = ["main.js"]


def main_js_paths():
    return [WEBUI / part for part in MAIN_JS_PARTS]


def main_js_source():
    return "\n".join(p.read_text(encoding="utf-8") for p in main_js_paths())
