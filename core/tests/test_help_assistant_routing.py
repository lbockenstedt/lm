"""Help assistant — model-routing roles, escalation signal, and source scoping.

Three behaviours are locked in here, all of which were previously wrong in ways
that produced *plausible but bad* answers rather than visible errors:

1. **Role-based routing.** Every HELP_ASK turn used to be sent with identical
   requirements (cost-first + latency-sensitive), so the cheapest model both
   chose the tools AND wrote the user-visible answer. The loop now tags turns
   ``tool`` / ``tool_hard`` / ``final``; AppBuilder maps the tag to model
   requirements. These tests assert the *hub* emits the tags, since that is the
   half that lives in this repo.

2. **Escalation signal.** ``_empty_result`` decides whether a tool turn found
   nothing, which is the sharper of the two escalation triggers.

3. **Source-search term selection.** ``_source_terms`` strips question words.
   Without this the strict matcher — which requires EVERY term on one line —
   returns zero hits for any natural-language question, which is exactly how
   "what does the collab simulation do" used to miss ``collab.sh`` entirely.

The GitHub-backed corpus itself (``github_source``) is covered by
``test_help_github_source.py``; it is deliberately not exercised here so these
stay offline.
"""

import pytest

from routes.help_assistant import (
    _ESCALATE_AFTER,
    _empty_result,
    _source_terms,
)


def _terms(q):
    """Mirror of the route's own tokenizer (alnum runs, >2 chars)."""
    return [w for w in ''.join(c.lower() if c.isalnum() else ' ' for c in q).split()
            if len(w) > 2]


# ── _empty_result ────────────────────────────────────────────────────────────

def test_empty_result_detects_no_hits():
    assert _empty_result({"query": "x", "total": 0, "results": []}) is True


def test_empty_result_false_when_there_are_hits():
    assert _empty_result({"query": "x", "total": 1,
                          "results": [{"file": "a.sh", "line": 1}]}) is False


def test_empty_result_treats_tool_error_as_empty():
    """An unknown tool / bad args is a failed search, not a successful empty
    one — both mean the model's next query should come from a better model."""
    assert _empty_result({"error": "unknown tool: nope"}) is True


def test_empty_result_uses_an_explicit_total_first():
    """Search payloads carry metadata (corpus stats) alongside results. Those
    are non-empty collections even for a zero-hit search, so scanning values
    alone reported 'not empty' and the escalation never fired."""
    assert _empty_result({"total": 0, "results": [],
                          "sources": {"files": 49, "repos": ["o/cs@main"]}}) is True
    assert _empty_result({"total": 3, "results": [1, 2, 3],
                          "sources": {"files": 49}}) is False


def test_empty_result_ignores_scalar_only_payloads():
    """A dict carrying no collections isn't 'empty' — e.g. a status answer.
    Treating it as empty would escalate on a perfectly good tool result."""
    assert _empty_result({"connected": 3, "status": "ok"}) is False


def test_empty_result_requires_all_collections_empty():
    assert _empty_result({"results": [], "matches": ["a"]}) is False


def test_empty_result_handles_non_dict():
    assert _empty_result(None) is True
    assert _empty_result([]) is True
    assert _empty_result(["hit"]) is False


# ── _source_terms ────────────────────────────────────────────────────────────

def test_source_terms_strips_question_words():
    """The regression that mattered: every term must appear on ONE line for a
    strict match, so leaving 'what'/'does'/'the' in guarantees zero hits."""
    assert _source_terms("what does the collab simulation do", _terms) == \
        ["collab", "simulation"]


def test_source_terms_keeps_identifiers_and_order():
    """The tokenizer splits on non-alphanumerics, so `dns_fail` arrives as two
    terms. That is fine for matching (both appear in any line containing
    `dns_fail`) — what matters is that the content words survive in order and
    the question words don't."""
    assert _source_terms("how is dns_fail triggered", _terms) == \
        ["dns", "fail", "triggered"]


def test_source_terms_falls_back_when_all_stopwords():
    """An all-stopword query must still search something rather than degrade to
    an empty term list (which would match every line)."""
    out = _source_terms("how does it work", _terms)
    assert out and all(isinstance(t, str) for t in out)


def test_source_terms_never_returns_empty_for_nonempty_query():
    for q in ("what", "the the the", "show me"):
        assert _source_terms(q, _terms) != []


# ── escalation threshold ─────────────────────────────────────────────────────

def test_escalate_after_allows_one_healthy_round():
    """One search-then-answer round is the normal path; escalating there would
    pay for a stronger model on every easy question."""
    assert _ESCALATE_AFTER >= 2


def test_escalation_triggers_before_the_tool_budget_is_spent():
    """Escalating only at the very last round would be pointless — there has to
    be budget left for the better model to actually run a query."""
    assert _ESCALATE_AFTER < 8


# ── role tags emitted by the loop ────────────────────────────────────────────

def _loop_source():
    import inspect
    from routes import help_assistant
    return inspect.getsource(help_assistant)


def test_loop_tags_turns_with_a_role():
    src = _loop_source()
    for role in ('"role": role', '"role": "final"'):
        assert role in src, f"missing role tag: {role}"


def test_every_help_ask_relay_carries_a_role():
    """A relay that forgets its role silently falls back to the legacy fast
    model — including, critically, the synthesis turns that write the answer."""
    src = _loop_source()
    relays = src.count('"HELP_ASK"')
    roles = src.count('"role":')
    assert relays > 0 and roles >= relays, (
        f"{relays} HELP_ASK relays but only {roles} role tags")


def test_final_synthesis_disables_tools():
    """The final turn must not be able to start searching again — everything it
    needs is already in the message history."""
    src = _loop_source()
    assert '"tools": None, "system": system, "role": "final"' in src


# ── Ask AI latency + follow-up regressions ────────────────────────────────
# These lock in the two behaviours that made Ask AI slow, both of which were
# invisible in code review and only showed up when the prompt was measured.

def _helpers():
    """Lift the pure decision functions out of the route module.

    Per core/tests/README.md the convention is to keep decision logic at module
    level; _select_docs/_doc_excerpt are nested in the route factory, so they
    are AST-extracted here rather than importing the whole FastAPI app.
    """
    import ast, pathlib
    src = pathlib.Path(__file__).resolve().parents[1] / "src/routes/help_assistant.py"
    tree = ast.parse(src.read_text())
    ns = {}
    # The lifted functions close over module-level constants, so those have to
    # come along or the extraction fails with NameError at call time.
    consts = [n for n in tree.body
              if isinstance(n, ast.Assign)
              and any(isinstance(t, ast.Name) and t.id in
                      {"_STOPWORDS", "_DOC_EXCERPT_BUDGET"} for t in n.targets)]
    want = {"_select_docs", "_doc_excerpt"}
    found = [n for n in ast.walk(tree)
             if isinstance(n, ast.FunctionDef) and n.name in want]
    mod = ast.Module(consts + found, [])
    exec(compile(ast.fix_missing_locations(mod), "<h>", "exec"), ns)
    return ns["_select_docs"], ns["_doc_excerpt"]


def test_select_docs_is_not_biased_by_document_length():
    """A long, irrelevant doc must not outrank a short, on-topic one.

    Regression: scoring by raw term COUNT ranked by size, so the biggest file in
    the corpus came back as the top match for nearly every question.
    """
    select, _ = _helpers()
    docs = {
        "huge-unrelated": ("the system and a the of and the " * 4000),
        "edge-proxy-role": "# Edge proxy\nThe edge proxy terminates TLS certificates.",
    }
    picked = select("how does the edge proxy handle certificates", docs)
    assert picked[0] == "edge-proxy-role", picked


def test_select_docs_matches_on_name():
    select, _ = _helpers()
    docs = {"netbox": "unrelated prose", "other": "netbox " * 50}
    assert "netbox" in select("how do I use netbox", docs)


def test_select_docs_falls_back_when_nothing_matches():
    select, _ = _helpers()
    docs = {"README": "hello", "lm-hub": "hi"}
    assert select("zzzqqq nonexistent xyzzy", docs)


def test_doc_excerpt_stays_within_budget_and_keeps_relevant_passage():
    """Excerpting is what removes ~45k tokens per turn; it must actually bound
    the output while still carrying the passage the question needs."""
    _, excerpt = _helpers()
    text = ("# Title\nIntro line.\n"
            + "\n".join(f"## Section {i}\n" + ("filler text here. " * 60)
                        for i in range(40))
            + "\n## Certificates\nThe proxy renews certificates via ACME.\n")
    out = excerpt(text, {"certificates"}, budget=2600)
    assert len(out) <= 2600 + 200, len(out)
    assert "ACME" in out
    assert len(out) < len(text) / 4


def test_doc_excerpt_returns_short_docs_untouched():
    _, excerpt = _helpers()
    short = "# Small\nnothing to trim."
    assert excerpt(short, {"small"}, budget=2600) == short


def test_doc_excerpt_always_includes_the_opening():
    """The head states what the doc is FOR, which is what makes the excerpted
    passages interpretable."""
    _, excerpt = _helpers()
    text = "# Purpose\nThis doc explains the widget.\n" + \
           "\n".join(f"## S{i}\n" + ("x " * 400) for i in range(20))
    out = excerpt(text, {"s3"}, budget=1200)
    assert "Purpose" in out
