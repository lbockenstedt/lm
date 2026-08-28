"""Front-matter parsing, stripping, and keyword matching.

The stripping tests matter as much as the parsing ones: docs are served as raw
markdown and the client renderer turns '---' into <hr>, so a header that leaks
through is visible garbage on every page.
"""
from routes import frontmatter as fm


DOC = '---\nsummary: "A doc about DNS."\nkeywords: [dns, resolver]\n---\n\n# DNS\n\nBody text.\n'


def test_split_returns_metadata_and_clean_body():
    meta, body = fm.split(DOC)
    assert meta["summary"] == "A doc about DNS."
    assert fm.keywords_of(meta) == ["dns", "resolver"]
    assert body.startswith("# DNS")
    assert "---" not in body


def test_document_without_front_matter_is_returned_unchanged():
    plain = "# Title\n\nBody.\n"
    meta, body = fm.split(plain)
    assert meta == {}
    assert body == plain


def test_a_horizontal_rule_mid_document_is_not_treated_as_front_matter():
    """Only the very top of a file is a header. Eating a mid-document rule would
    silently truncate real content."""
    text = "# Title\n\nIntro.\n\n---\n\nMore prose.\n"
    assert fm.strip(text) == text


def test_malformed_front_matter_does_not_raise():
    """Fail-soft: losing a keyword boost dents ranking, but an exception here
    would take the docs offline."""
    assert fm.parse("---\n\t::: not yaml [\n---\n# T\n") == {}


def test_empty_input_is_safe():
    assert fm.split("") == ({}, "")
    assert fm.split(None) == ({}, "")


def test_keywords_accepts_a_comma_separated_string():
    assert fm.keywords_of({"keywords": "dns, Resolver ,bind"}) == ["dns", "resolver", "bind"]


def test_stem_handles_the_inflections_that_caused_real_misses():
    assert fm.stem("logs") == fm.stem("log")
    assert fm.stem("logging") == "log"
    assert fm.stem("spokes") == "spoke"       # not "spok"
    assert fm.stem("certificates") == "certificate"
    assert fm.stem("policies") == "policy"


def test_stem_does_not_collide_unrelated_words():
    assert fm.stem("class") != fm.stem("cla")
    assert fm.stem("status") != fm.stem("statue")


def test_exact_keyword_match_outranks_a_compound_part_match():
    """A doc keyworded 'get_logs' must not score as highly on "logs" as a doc
    keyworded 'logs' -- that exact bug let the bot pages beat the logging page.
    """
    assert fm.match_score("logs", "logs") == 1.0
    assert fm.match_score("logs", "get_logs") == 0.5
    assert fm.match_score("dns", "dns_fail") == 0.5
    assert fm.match_score("hub", "logging") == 0.0


def test_match_score_is_zero_for_unrelated_words():
    assert fm.match_score("cat", "console") == 0.0
    assert fm.match_score("bus", "bugfixer") == 0.0
