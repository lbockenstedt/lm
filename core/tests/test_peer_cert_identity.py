"""H1: ``peer_cert_identity_from_getpeercert`` — the pure, testable surface of
the peer-cert extraction added in ``core/src/security/peer_cert_ws.py``.

The protocol subclass that injects the parsed ``getpeercert()`` dict into the
ASGI scope is transport-coupled (a uvicorn internal-API override) and not
unit-tested; this file covers the pure helper that derives a renewal-stable
identity (SAN DNS names, subject-CN fallback) from that dict. The helper is the
contract the HUB_REQUEST gate relies on: ``None`` ⇒ "no cert / no identity ⇒
deny" (fail-closed), a non-empty tuple ⇒ the cert's DNS names to pin against.
"""

import sys

sys.path.insert(0, "src")
from security.peer_cert_ws import peer_cert_identity_from_getpeercert  # noqa: E402


# ── None / empty / malformed → None (fail-closed) ─────────────────────────────

def test_none_returns_none():
    """``getpeercert()`` returns None when no cert was presented (plaintext /
    browser / mTLS off). No identity → the gate denies."""
    assert peer_cert_identity_from_getpeercert(None) is None


def test_empty_dict_returns_none():
    """``getpeercert()`` returns ``{}`` for an UNvalidated cert (CERT_NONE / no
    CA). Under the hub's PERMISSIVE mTLS an unvalidated cert is rejected at
    handshake, but the helper is defensive: ``{}`` ⇒ no identity ⇒ deny."""
    assert peer_cert_identity_from_getpeercert({}) is None


def test_non_dict_returns_none():
    assert peer_cert_identity_from_getpeercert("not a dict") is None
    assert peer_cert_identity_from_getpeercert(42) is None
    assert peer_cert_identity_from_getpeercert([]) is None


def test_dict_with_no_san_and_no_subject_returns_none():
    assert peer_cert_identity_from_getpeercert({"notBefore": "x", "notAfter": "y"}) is None


def test_malformed_san_does_not_raise():
    """A malformed SAN entry must never raise — the helper is called on the live
    connection path and a bad dict can't be allowed to drop the socket."""
    bad = {"subjectAltName": "oops", "subject": None}
    assert peer_cert_identity_from_getpeercert(bad) is None
    # A SAN with non-DNS entries only → no DNS names → fall through to CN.
    ip_only = {"subjectAltName": [("IP Address", "10.0.0.1"), ("IP Address", "::1")]}
    assert peer_cert_identity_from_getpeercert(ip_only) is None


# ── SAN DNS extraction ─────────────────────────────────────────────────────────

def _cert(san=None, cn=None):
    """Build a minimal ``getpeercert()``-shaped dict. SAN is a tuple of
    ``(type, value)``; subject is a tuple of RDNs, each a tuple of
    ``(attr, value)`` pairs (the shape ``ssl.getpeercert()`` returns)."""
    d = {}
    if san is not None:
        d["subjectAltName"] = tuple(san)
    if cn is not None:
        d["subject"] = ((("commonName", cn),),)
    return d


def test_single_dns_san():
    d = _cert(san=[("DNS", "bugfixer.lm.io")])
    assert peer_cert_identity_from_getpeercert(d) == ("bugfixer.lm.io",)


def test_multiple_dns_sans_preserve_order():
    san = [("DNS", "bugfixer.lm.io"), ("DNS", "fixer.lm.io"), ("DNS", "bf.lm.io")]
    assert peer_cert_identity_from_getpeercert(_cert(san=san)) == (
        "bugfixer.lm.io", "fixer.lm.io", "bf.lm.io")


def test_ip_san_entries_are_dropped():
    """Only DNS names are identity — IP-address SANs are not renewal-stable
    (and not what the LE checkbox pins). They're skipped, not fatal."""
    san = [("DNS", "bugfixer.lm.io"), ("IP Address", "10.0.0.5"),
           ("DNS", "fixer.lm.io"), ("IP Address", "::1")]
    assert peer_cert_identity_from_getpeercert(_cert(san=san)) == (
        "bugfixer.lm.io", "fixer.lm.io")


def test_other_san_types_dropped():
    san = [("DNS", "bugfixer.lm.io"), ("email", "ops@lm.io"), ("URI", "https://x")]
    assert peer_cert_identity_from_getpeercert(_cert(san=san)) == ("bugfixer.lm.io",)


def test_empty_dns_value_skipped():
    san = [("DNS", "bugfixer.lm.io"), ("DNS", ""), ("DNS", "fixer.lm.io")]
    assert peer_cert_identity_from_getpeercert(_cert(san=san)) == (
        "bugfixer.lm.io", "fixer.lm.io")


# ── subject commonName fallback ───────────────────────────────────────────────

def test_cn_fallback_when_no_san():
    """Older / internal certs may carry no SAN — fall back to the subject
    commonName so a single-CN BugFixer cert still yields an identity."""
    d = _cert(cn="bugfixer.lm.io")
    assert peer_cert_identity_from_getpeercert(d) == ("bugfixer.lm.io",)


def test_san_preferred_over_cn():
    """When both SAN and CN are present, SAN wins (SAN is the renewal-stable
    identity; CN is deprecated in modern LE certs)."""
    d = _cert(san=[("DNS", "bugfixer.lm.io")], cn="old-name.lm.io")
    assert peer_cert_identity_from_getpeercert(d) == ("bugfixer.lm.io",)


def test_cn_fallback_skips_non_commonname_attrs():
    """Subject RDNs carry org/OU/etc; only commonName is identity."""
    d = {"subject": ((("countryName", "US"),), (("organizationName", "LM"),),
                     (("commonName", "bugfixer.lm.io"),))}
    assert peer_cert_identity_from_getpeercert(d) == ("bugfixer.lm.io",)


def test_malformed_subject_does_not_raise():
    d = {"subject": "garbage"}
    assert peer_cert_identity_from_getpeercert(d) is None
    d2 = {"subject": ((None,), (123,))}
    assert peer_cert_identity_from_getpeercert(d2) is None


# ── never raises ──────────────────────────────────────────────────────────────

def test_never_raises_on_garbage():
    # None of these raise — the helper is called on the live connection path.
    for bad in [None, {}, [], 1, "x", {"subjectAltName": object()},
                {"subject": object()}, {"subjectAltName": [None, 1, ("DNS",)]}]:
        peer_cert_identity_from_getpeercert(bad)