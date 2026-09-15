"""`tw`/`th` are FUNCTION-LOCAL aliases, so a top-level helper cannot use them.

Several loader functions open with `const th = tableHead, tw = tableWrap;` and
then use the short names throughout. `_ddMemberEvidence` is not one of them —
it is a top-level function that sits *between* those loaders, so the aliases
are simply not in its scope. It still called `tw(th([...]))` to render the DNS
query-probe table, which threw

    ReferenceError: Can't find variable: tw

and blanked DNS -> Diagnostics. The block only runs for `kind === 'dns'` when a
member reports SUCCESS with probe data, which is why it survived so long.

These tests keep every top-level diagnostics helper on the fully-qualified
`tableWrap`/`tableHead`, which are real globals.
"""

import re
from pathlib import Path

MAIN_JS = Path(__file__).resolve().parents[2] / "WebUI" / "main.js"

# A bare `tw(` / `th(` that is NOT a property access (`x.th(`) and not part of
# a longer identifier (`width(`, `both(`).
_BARE_ALIAS = re.compile(r"(?<![\w.$])(tw|th)\s*\(")


def _source():
    return MAIN_JS.read_text(encoding="utf-8")


def _top_level_function(name):
    """Body of a top-level `function <name>(` up to the next top-level `}`."""
    src = _source()
    start = src.index(f"\nfunction {name}(")
    body = src[start + 1:]
    end = body.index("\n}\n")
    return body[:end]


def test_dd_member_evidence_does_not_use_the_local_aliases():
    body = _top_level_function("_ddMemberEvidence")
    assert not _BARE_ALIAS.search(body), (
        "_ddMemberEvidence is top-level; tw/th are not in its scope. "
        "Use tableWrap/tableHead."
    )


def test_dd_member_evidence_still_renders_the_probe_table():
    body = _top_level_function("_ddMemberEvidence")
    assert "tableWrap(tableHead(['Target', 'Result', 'RCODE', 'Latency'])" in body


def test_the_aliases_are_only_ever_declared_inside_a_function():
    # If one of these ever became a real global the guard above would be
    # pointless — and the bug would come back silently the next time a helper
    # was lifted to top level.
    src = _source()
    for decl in ("\nconst tw ", "\nconst th ", "\nlet tw ", "\nlet th ",
                 "\nvar tw ", "\nvar th ", "\nwindow.tw", "\nwindow.th"):
        assert decl not in src, f"{decl.strip()} is declared globally"


def test_other_top_level_dd_helpers_are_clean_too():
    for name in ("_dhcpHaPanel", "_dnsClusterPanel", "_ddClusterBadge"):
        src = _source()
        if f"\nfunction {name}(" not in src:
            continue
        body = _top_level_function(name)
        assert not _BARE_ALIAS.search(body), (
            f"{name} is top-level; tw/th are not in its scope."
        )
