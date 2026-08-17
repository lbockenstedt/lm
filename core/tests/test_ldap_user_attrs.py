"""``canonicalize_user_attrs`` maps the WebUI's friendly user-attribute keys to
the canonical LDAP names the directory spoke writes.

Regression guard for the create/update path that silently dropped a new user's
name/email: the WebUI sends ``first_name``/``last_name``/``email`` (symmetric
with the spoke's READ side), but the spoke's WRITE side only reads
``givenName``/``sn``/``mail``/``cn`` — so without this translation the saved
user kept only its uid and looked as though nothing was created."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from routes.ldap import canonicalize_user_attrs


def test_friendly_keys_map_to_canonical_ldap_names():
    out = canonicalize_user_attrs(
        {"first_name": "Ada", "last_name": "Lovelace", "email": "ada@x.io"})
    assert out["givenName"] == "Ada"
    assert out["sn"] == "Lovelace"
    assert out["mail"] == "ada@x.io"
    # Friendly keys must not leak through — the spoke ignores them.
    assert "first_name" not in out and "last_name" not in out and "email" not in out


def test_cn_and_displayname_derived_from_name_parts():
    out = canonicalize_user_attrs({"first_name": "Ada", "last_name": "Lovelace"})
    assert out["cn"] == "Ada Lovelace"
    assert out["displayName"] == "Ada Lovelace"


def test_explicit_cn_is_not_overwritten():
    out = canonicalize_user_attrs(
        {"first_name": "Ada", "last_name": "Lovelace", "cn": "Countess"})
    assert out["cn"] == "Countess"


def test_already_canonical_keys_pass_through():
    out = canonicalize_user_attrs(
        {"givenName": "Ada", "sn": "Lovelace", "mail": "ada@x.io",
         "telephoneNumber": "555", "title": "Analyst"})
    assert out["givenName"] == "Ada" and out["sn"] == "Lovelace"
    assert out["mail"] == "ada@x.io"
    assert out["telephoneNumber"] == "555" and out["title"] == "Analyst"


def test_empty_and_none_are_safe():
    assert canonicalize_user_attrs(None) == {}
    assert canonicalize_user_attrs({}) == {}


def test_partial_name_only_sets_supplied_parts():
    out = canonicalize_user_attrs({"first_name": "Ada"})
    assert out["givenName"] == "Ada"
    assert out["cn"] == "Ada" and out["displayName"] == "Ada"
    assert "sn" not in out and "mail" not in out
