"""Tests for the OCI region catalog behind the Region dropdown.

The WebUI's Region field is a <select> populated from GET /setup/oci-regions.
Its contract matters: every id served must be a region string that
``validate_region`` accepts, otherwise the dropdown would hand the operator a
value that fails later as an opaque DNS error — the exact failure mode the
dropdown exists to prevent.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import oci_auth  # noqa: E402


def test_catalog_is_not_empty():
    assert len(oci_auth.list_regions()) > 10


def test_entries_have_id_and_label():
    for r in oci_auth.list_regions():
        assert r.get("id"), r
        assert r.get("label"), r


def test_every_id_passes_validate_region():
    """A dropdown must never offer a region the request layer will reject."""
    for r in oci_auth.list_regions():
        oci_auth.validate_region(r["id"])  # raises on failure


def test_ids_are_unique():
    ids = [r["id"] for r in oci_auth.list_regions()]
    assert len(ids) == len(set(ids))


def test_ids_are_lowercase_and_hyphenated():
    """Region ids are case-sensitive in OCI hostnames."""
    for r in oci_auth.list_regions():
        assert r["id"] == r["id"].lower()
        assert " " not in r["id"]


def test_includes_well_known_regions():
    ids = {r["id"] for r in oci_auth.list_regions()}
    for expected in ("us-ashburn-1", "us-phoenix-1", "eu-frankfurt-1", "uk-london-1"):
        assert expected in ids


def test_list_regions_returns_a_copy():
    """Callers (route handlers) must not be able to mutate the catalog."""
    first = oci_auth.list_regions()
    first.append({"id": "bogus", "label": "bogus"})
    assert "bogus" not in {r["id"] for r in oci_auth.list_regions()}


@pytest.mark.parametrize("bad", ["us ashburn 1", "", "us_ashburn_1", "ashburn", "us-ashburn"])
def test_validate_region_rejects_malformed(bad):
    with pytest.raises(oci_auth.OciAuthError):
        oci_auth.validate_region(bad)


@pytest.mark.parametrize("raw", ["US-Ashburn-1", " us-ashburn-1 ", "Us-AshBurn-1"])
def test_validate_region_normalises_case_and_padding(raw):
    """Accept-and-normalise rather than reject: OCI hostnames need the
    lowercase form, and a case-mangled paste is unambiguous."""
    assert oci_auth.validate_region(raw) == "us-ashburn-1"
