"""Every function an inline handler calls (onclick="foo(...)") must exist.

Inline handlers run in the global scope, so they break silently -- no error
until a user clicks -- when the function they call is renamed, moved into an
ES module, or deleted. The WebUI refactor (docs/webui-react-lite-plan.md)
moves a lot of code between files; this check catches a dropped global before
it ships.
"""
import re

from webui_src import WEBUI

# Names that are not WebUI functions: JS keywords and browser globals.
BUILTINS = set("""
    if for while switch return typeof new this event alert confirm prompt
    encodeURIComponent decodeURIComponent parseInt parseFloat Number String
    Boolean JSON Math Date Object Array setTimeout clearTimeout setInterval
    requestAnimationFrame fetch console document window navigator location
    history Promise isNaN catch function void await async
""".split())

# fn: an example in a code comment (main.js), not a real handler.
ALLOWED_UNDEFINED = {"fn"}

HANDLER = re.compile(r"\bon[a-z]+\s*=\s*(?:\"([^\"]*)\"|'([^']*)')")
CALL = re.compile(r"(?<![\w$.])([A-Za-z_$][\w$]*)\s*\(")


def _sources():
    files = [p for p in sorted(WEBUI.rglob("*.js")) if "assets" not in p.parts]
    files.append(WEBUI / "index.html")
    return {p.relative_to(WEBUI).as_posix(): p.read_text(encoding="utf-8") for p in files}


def _defined_globals(text):
    names = set(re.findall(r"(?:^|[\s;])(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)\s*\(", text))
    names |= set(re.findall(r"window\.([A-Za-z_$][\w$]*)\s*=(?!=)", text))
    names |= set(re.findall(r"^(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=", text, re.M))
    return names


def test_inline_handlers_only_call_defined_functions():
    sources = _sources()
    defined = _defined_globals("\n".join(sources.values()))
    missing = {}
    for name, text in sources.items():
        for m in HANDLER.finditer(text):
            # ${...} builds the name at runtime; it can't be checked statically.
            code = re.sub(r"\$\{[^}]*\}", "", m.group(1) or m.group(2) or "")
            for fn in CALL.findall(code):
                if fn not in defined and fn not in BUILTINS and fn not in ALLOWED_UNDEFINED:
                    missing.setdefault(fn, name)
    assert not missing, f"inline handlers call undefined functions: {missing}"
