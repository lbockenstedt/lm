"""Inline on*="..." handlers in WebUI/sim-views.js must pass interpolated strings
through csJsArg, never as '${...}'.

The browser decodes HTML entities in an attribute before it runs the handler,
so csEscape's &#39; turns back into ' and a value such as x');alert(1);// ends
the JS string. csJsArg JSON-encodes the value first.
"""

import re
from pathlib import Path

JS = Path(__file__).resolve().parents[2] / "WebUI" / "sim-views.js"

# An on*=" attribute whose value reaches a quoted ${ before the closing quote.
_QUOTED_ARG = re.compile(r"""\bon[a-z]+="[^"]*'\$\{""")


def test_no_quoted_interpolation_in_inline_handlers():
    """Every string argument in an inline handler is built with csJsArg."""
    bad = [n for n, line in enumerate(JS.read_text(encoding="utf-8").splitlines(), 1)
           if _QUOTED_ARG.search(line)]
    assert not bad, "quoted ${...} in an inline handler at lines %s; use ${csJsArg(x)}" % bad


def test_scanner_catches_the_unsafe_shape():
    """The pattern flags the old shape and passes the csJsArg shape."""
    assert _QUOTED_ARG.search("""<button onclick="csSpokeDiag('${csEscape(s.spoke_id)}')">""")
    assert _QUOTED_ARG.search("""onchange="${a ? `f('${csEscape(id)}')` : ''}\"""")
    assert not _QUOTED_ARG.search("""<button onclick="csSpokeDiag(${csJsArg(s.spoke_id)})">""")
    assert not _QUOTED_ARG.search("""<button onclick="csAct('ignore', ${i})">""")


def test_handler_args_are_not_escaped_twice():
    """csJsArg escapes for the attribute itself, so a variable passed to it
    must hold the raw value, not one already run through csEscape (the
    handler would then receive a&amp;b instead of a&b). Checks the nearest
    earlier const/let that assigns the variable."""
    lines = JS.read_text(encoding="utf-8").splitlines()
    bad = []
    for n, line in enumerate(lines):
        for name in re.findall(r"csJsArg\(([A-Za-z_]\w*)\)", line):
            assign = re.compile(r"\b(?:const|let|var)\s+%s\s*=\s*(.*)" % name)
            for prev in reversed(lines[max(0, n - 150):n + 1]):
                m = assign.search(prev)
                if m:
                    if m.group(1).lstrip().startswith(("csEscape(", "esc(")):
                        bad.append((n + 1, name))
                    break
    assert not bad, "csJsArg given an already-escaped value: %s" % bad
