"""Per-repo ".NN" behind-detection (update_pipeline).

Each provisioning repo (lm, cs, pxmx, netbox, opnsense, ldap, nw, cppm, le,
bugfixer) autobumps an INDEPENDENT ``.NN``. A spoke's ``.NN`` is only comparable
to the LATEST ``.NN`` of ITS OWN repo, so the hub resolves that latest locally
and flags a spoke "behind" only when BOTH sides are valid ``.NN`` and the spoke's
is strictly older. The cardinal rule is NEVER false-positive: any unknown /
non-``.NN`` on either side leaves the spoke NOT behind.

Covers the pure comparison helpers (``_parse_nn`` / ``_version_behind``) and the
mixin resolver (``latest_version_for_module``) incl. its mtime read cache.
"""

import os

from update_pipeline import (
    UpdatePipelineMixin,
    _parse_nn,
    _version_behind,
    _IN_LM_REPO_MODULE_TYPES,
    _MODULE_REPO_DIR,
)


def test_parse_nn():
    assert _parse_nn(".486") == 486
    assert _parse_nn(".0") == 0
    assert _parse_nn("  .400 ") == 400
    # Anything not on the .NN numbering → None (no comparison possible).
    for bad in ("unknown", "v.01", "1.2.3", "486", ".", ".x", "", None):
        assert _parse_nn(bad) is None, bad


def test_version_behind_true_when_strictly_older():
    assert _version_behind(".400", ".486") is True
    assert _version_behind(".0", ".1") is True


def test_version_behind_false_when_current_or_ahead():
    assert _version_behind(".486", ".486") is False   # current
    assert _version_behind(".500", ".486") is False   # ahead of a stale checkout


def test_version_behind_never_false_positive_on_unknown():
    # Either side unknown / non-.NN → NEVER behind (the invariant).
    assert _version_behind("unknown", ".486") is False
    assert _version_behind(".400", None) is False
    assert _version_behind(".400", "unknown") is False
    assert _version_behind("v.01", ".486") is False
    assert _version_behind("1.2.3", ".486") is False
    assert _version_behind(None, None) is False


class _StubHub(UpdatePipelineMixin):
    """Bare mixin instance — latest_version_for_module reads only VERSION files
    off disk (via the mtime cache), needing no other Hub state."""


def test_latest_version_for_module_reads_hub_version_for_in_repo_types():
    hub = _StubHub()
    # The hub's own VERSION (lm repo) backs dns/dhcp/console/agent.
    hub_version_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..", "VERSION"))
    expected = open(hub_version_path).read().strip()
    for mt in _IN_LM_REPO_MODULE_TYPES:
        assert hub.latest_version_for_module(mt) == expected


def test_latest_version_for_module_unknown_type_is_none():
    hub = _StubHub()
    # No repo mapping + not an in-lm-repo type → None → caller must not flag.
    assert hub.latest_version_for_module("totally-made-up") is None
    assert hub.latest_version_for_module("") is None
    assert hub.latest_version_for_module(None) is None


def test_latest_version_for_module_sibling_uses_local_checkout(tmp_path, monkeypatch):
    """A sibling repo resolves to a local VERSION checkout when one is present,
    and returns None when none of the candidate paths exist (no false-positive)."""
    hub = _StubHub()
    # "firewall" → opnsense repo per _MODULE_REPO_DIR.
    assert _MODULE_REPO_DIR["firewall"] == "opnsense"

    # No checkout anywhere → unknown latest.
    monkeypatch.setattr(hub, "_sibling_version_candidates",
                        lambda repo: [str(tmp_path / repo / "VERSION")])
    assert hub.latest_version_for_module("firewall") is None

    # Now stand up a local checkout and confirm it is read + cached by mtime.
    vpath = tmp_path / "opnsense" / "VERSION"
    vpath.parent.mkdir(parents=True)
    vpath.write_text(".612\n")
    assert hub.latest_version_for_module("firewall") == ".612"
    # A spoke reporting an older .NN is behind; a matching one is not.
    assert _version_behind(".600", hub.latest_version_for_module("firewall")) is True
    assert _version_behind(".612", hub.latest_version_for_module("firewall")) is False


def test_read_version_cached_reflects_change_on_mtime_bump(tmp_path):
    hub = _StubHub()
    p = tmp_path / "VERSION"
    p.write_text(".100\n")
    assert hub._read_version_cached(str(p)) == ".100"
    # Rewrite with a bumped mtime → cache invalidates and re-reads.
    os.utime(str(p), None)
    p.write_text(".101\n")
    os.utime(str(p), (10**9 + 5, 10**9 + 5))  # force a distinct mtime
    assert hub._read_version_cached(str(p)) == ".101"
    # Missing file → None (never raises).
    assert hub._read_version_cached(str(tmp_path / "nope" / "VERSION")) is None
