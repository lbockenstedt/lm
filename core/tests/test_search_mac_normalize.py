"""MAC-normalization contract for the global search fan-out
(``/api/search`` → ``cross_system_search``).

The hub normalizes a MAC typed in ANY separator form (colon / dash / dot / bare
12-hex) to the canonical lower-colon form before fanning the query to the
spokes, so a spoke that substring-matches on a single form (the netbox spoke's
REST ``q``-search against the colon-form ``mac_address`` custom field) finds it
regardless of how the MAC was typed. This test locks the two pieces of that
contract: the detection regex (matches every separator form + bare hex,
rejects non-MACs) and ``access.norm_mac`` (canonicalizes every form to colon).
The route itself delegates to ``access.norm_mac``, so these unit tests cover the
behavior without standing up FastAPI.
"""
import re

import access

# Mirrors the regex in api.py cross_system_search. Keep in sync.
_MAC_RE = re.compile(
    r'^([0-9a-fA-F]{2}[:\-\.]){5}[0-9a-fA-F]{2}$|^[0-9a-fA-F]{12}$')


def _is_mac(q: str) -> bool:
    return bool(_MAC_RE.match(q))


def test_mac_detection_matches_every_separator_form():
    assert _is_mac("aa:bb:cc:dd:ee:ff")     # colon
    assert _is_mac("AA-BB-CC-DD-EE-FF")      # dash
    assert _is_mac("aa.bb.cc.dd.ee.ff")       # dot
    assert _is_mac("aabbccddeeff")            # bare 12-hex
    assert _is_mac("AABBCCDDEEFF")            # bare upper


def test_mac_detection_rejects_non_macs():
    assert not _is_mac("ks205")                # hostname
    assert not _is_mac("10.20.0.5")            # IPv4 (dot but not a MAC)
    assert not _is_mac("10.20.0.0/24")         # CIDR
    assert not _is_mac("aabbccddeeff00")        # 14 hex — not a MAC
    assert not _is_mac("aa:bb:cc:dd:ee")       # too short
    assert not _is_mac("")


def test_norm_mac_canonicalizes_every_form_to_colon():
    canon = "aa:bb:cc:dd:ee:ff"
    for form in ("aa:bb:cc:dd:ee:ff", "AA-BB-CC-DD-EE-FF",
                 "aa.bb.cc.dd.ee.ff", "aabbccddeeff", "AABBCCDDEEFF"):
        assert access.norm_mac(form) == canon, form


def test_norm_mac_drops_absent():
    assert access.norm_mac("") == ""
    assert access.norm_mac("unknown") == ""
    assert access.norm_mac(None) == ""