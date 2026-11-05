"""YAML front-matter for the canonical docs.

Docs carry a short metadata header::

    ---
    summary: One sentence on what this document covers.
    keywords: [dns, resolver, spoke, bind]
    ---

Two things depend on this module, and they pull in opposite directions:

* **Retrieval** wants the metadata. Keyword matching over prose alone cannot
  answer a terse follow-up ("what about windows?") or bridge a vocabulary gap
  between what a user calls a thing and what the doc calls it.
* **The reader** must never see it. Docs are served as raw markdown and
  rendered by a small client-side renderer that turns ``---`` into ``<hr>``, so
  an unstripped header would show up as a horizontal rule followed by the raw
  YAML on every single document.

So parsing and stripping live here, once, rather than being re-implemented (and
inconsistently forgotten) at each call site.

Parsing is deliberately fail-soft: a malformed header is treated as "no
metadata" and the document is still returned intact. Losing a keyword boost
degrades ranking slightly; raising an exception would take the docs offline.
"""

# Regex for finding the header.
import re

# The public helpers.
__all__ = ["parse", "strip", "split", "keywords_of", "stem", "matches", "match_score"]

# Matches a "---" ... "---" header at the start of the text (group 1 is the inside).
_FM_RE = re.compile(r"^---[ \t]*\r?\n(.*?)\r?\n---[ \t]*(?:\r?\n|$)", re.DOTALL)


def _parse_block(block):
    """Parse the inside of a front-matter block into a dict.

    Understands the only two shapes our docs use -- ``key: scalar`` and
    ``key: [a, b, c]`` -- so no YAML library is needed.
    """
    def unquote(v):
        """Remove one pair of matching single or double quotes around ``v``."""
        return v[1:-1] if len(v) > 1 and v[0] == v[-1] and v[0] in "'\"" else v

    # Read each "key: value" line, skipping blanks, comments and lines without a colon.
    out = {}
    for line in block.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, _, val = line.partition(":")
        key, val = key.strip(), val.strip()
        if not key:
            continue
        # "[a, b]" becomes a list; anything else is a plain string.
        if val.startswith("[") and val.endswith("]"):
            out[key] = [unquote(v.strip()) for v in val[1:-1].split(",") if v.strip()]
        else:
            out[key] = unquote(val)
    return out


def split(text):
    """Return ``(metadata, body)``.

    ``body`` is always safe to render. When there is no front-matter the text is
    returned unchanged with empty metadata, so callers never need to branch.
    """
    # Empty text has no metadata.
    if not text:
        return {}, text or ""
    # lstrip only leading blank lines: a header is only a header at the very
    # top, and treating a mid-document '---' rule as one would silently eat
    # content.
    lead = len(text) - len(text.lstrip("\r\n"))
    m = _FM_RE.match(text[lead:])
    if not m:
        return {}, text
    # Parse the header (non-dict results count as no metadata).
    meta = _parse_block(m.group(1))
    if not isinstance(meta, dict):
        return {}, text
    # Drop the blank line that conventionally follows the header. It is part of
    # the header's formatting, not the document, and leaving it in wastes the
    # opening of every excerpt on whitespace.
    return meta, text[lead + m.end():].lstrip("\r\n")


def parse(text):
    """The metadata dict only (empty when absent or malformed)."""
    return split(text)[0]


def strip(text):
    """The renderable body only, with any front-matter removed."""
    return split(text)[1]


def keywords_of(meta):
    """Normalised keyword list from parsed metadata.

    Accepts both the list form and a comma-separated string, because hand-edited
    docs drift toward the latter and silently losing those keywords would be
    worse than accepting both.
    """
    # Accept a list or a comma-separated string; lower-case and drop blanks.
    kw = meta.get("keywords") or []
    if isinstance(kw, str):
        kw = [k.strip() for k in kw.split(",")]
    return [str(k).strip().lower() for k in kw if str(k).strip()]


def stem(word):
    """Crudely normalise a word for keyword comparison.

    Users and doc authors pick different inflections of the same term -- a
    question about "how logs are sent" should match a doc keyworded "logging" --
    and exact matching silently misses all of those. This is deliberately not a
    real stemmer: it only strips the few endings that cause this, because an
    aggressive stemmer would collide unrelated terms, and a false keyword match
    is heavily weighted and therefore costly.
    """
    # Lower-case it; short words are left alone.
    w = str(word).lower().strip()
    if len(w) < 4:
        return w
    # "-ies" becomes "-y".
    if w.endswith("ies") and len(w) > 4:
        return w[:-3] + "y"
    # Drop "-ing".
    if w.endswith("ing") and len(w) > 5:
        base = w[:-3]
        # "logging" -> "logg" -> "log": the doubled consonant is an artifact of
        # the -ing form, and leaving it in place defeats the whole match.
        if len(base) > 2 and base[-1] == base[-2] and base[-1] not in "aeiou":
            base = base[:-1]
        return base
    # Strip only the plural "s". Stripping "es" wholesale turns "spokes" into
    # "spok", which then fails to match the singular "spoke".
    if w.endswith("s") and not w.endswith("ss") and len(w) > 3:
        return w[:-1]
    return w


def match_score(word, keyword):
    """How strongly a question word matches a doc keyword: 1.0, 0.5, or 0.

    Matching a *part* of a compound identifier is weaker evidence than matching
    the whole keyword, and treating the two alike caused real misranking: a doc
    keyworded ``get_logs`` and ``hub_agent`` scored full marks on "how are logs
    sent to the hub" and beat the page actually about logging. The part match is
    still worth keeping -- it is what lets "dns" find ``dns_fail`` -- just not at
    the same confidence.
    """
    # Same word (or same stem) is a full match.
    w, k = str(word).lower(), str(keyword).lower()
    if w == k or stem(w) == stem(k):
        return 1.0
    # Matching one part of a multi-part keyword is a half match.
    parts = k.replace("_", " ").replace("-", " ").split()
    if len(parts) > 1 and stem(w) in {stem(p) for p in parts}:
        return 0.5
    return 0.0


def matches(word, keyword):
    """True when a question word refers to the same thing as a doc keyword."""
    return match_score(word, keyword) > 0
