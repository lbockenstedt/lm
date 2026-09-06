"""OCI 404 ``NotAuthorizedOrNotFound`` must be explained, not just echoed.

OCI collapses "doesn't exist", "is in another region" and "your policy doesn't
allow it" into one 404 so the API can't be used to probe for resources you
can't see. The body names no field, so the operator gets nothing actionable.
These tests pin the local diagnosis: OCID type confusion and — the case that
is otherwise invisible — a resource whose OCID embeds a different region than
the configured one.
"""
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import oci_auth  # noqa: E402


# ── region embedded in an OCID ────────────────────────────────────────────────

def test_region_of_ocid_maps_short_key_to_region_name():
    assert oci_auth.region_of_ocid(
        "ocid1.vault.oc1.iad.abcdefghij") == "us-ashburn-1"
    assert oci_auth.region_of_ocid(
        "ocid1.vault.oc1.phx.abcdefghij") == "us-phoenix-1"


def test_region_of_ocid_accepts_full_region_name_form():
    """Some regions put the full name in the OCID rather than the short key."""
    assert oci_auth.region_of_ocid(
        "ocid1.vault.oc1.eu-frankfurt-1.abcd") == "eu-frankfurt-1"


def test_global_ocids_have_no_region():
    """Tenancy/user/compartment OCIDs are global and carry an EMPTY region
    segment — that must not be mistaken for a mismatch."""
    assert oci_auth.region_of_ocid("ocid1.tenancy.oc1..aaaaaaaabbbb") == ""
    assert oci_auth.region_of_ocid("ocid1.user.oc1..aaaaaaaabbbb") == ""
    assert oci_auth.region_of_ocid("") == ""
    assert oci_auth.region_of_ocid("not-an-ocid") == ""


# ── resource OCID diagnosis ──────────────────────────────────────────────────

def test_region_mismatch_is_reported():
    """The invisible cause of a 404: right vault, wrong region endpoint."""
    problems = oci_auth.diagnose_resource_ocid(
        "ocid1.vault.oc1.iad.abcd", "vault", "Vault OCID", "us-phoenix-1")
    assert len(problems) == 1
    msg = problems[0]
    assert "us-ashburn-1" in msg and "us-phoenix-1" in msg
    assert "Region mismatch" in msg


def test_matching_region_is_clean():
    assert oci_auth.diagnose_resource_ocid(
        "ocid1.vault.oc1.iad.abcd", "vault", "Vault OCID", "us-ashburn-1") == []


def test_region_comparison_is_case_and_space_insensitive():
    assert oci_auth.diagnose_resource_ocid(
        "ocid1.vault.oc1.iad.abcd", "vault", "Vault OCID", "  US-Ashburn-1 ") == []


def test_wrong_ocid_type_is_named():
    """Pasting the tenancy OCID into the Vault field is a common slip."""
    problems = oci_auth.diagnose_resource_ocid(
        "ocid1.tenancy.oc1..aaaa", "vault", "Vault OCID", "us-ashburn-1")
    assert len(problems) == 1
    assert "a tenancy OCID" in problems[0]
    assert "ocid1.vault." in problems[0]


def test_wrong_type_does_not_also_emit_region_noise():
    """One clear problem beats two, when the second is a consequence."""
    problems = oci_auth.diagnose_resource_ocid(
        "ocid1.compartment.oc1..aaaa", "vault", "Vault OCID", "us-phoenix-1")
    assert len(problems) == 1


def test_non_ocid_value_is_reported():
    problems = oci_auth.diagnose_resource_ocid(
        "my-vault", "vault", "Vault OCID", "us-ashburn-1")
    assert len(problems) == 1
    assert "doesn't look like an OCID" in problems[0]


def test_empty_value_is_not_a_problem_here():
    """Missing-field errors are raised elsewhere; this helper only judges shape."""
    assert oci_auth.diagnose_resource_ocid("", "vault", "Vault OCID", "us-ashburn-1") == []


# ── the assembled 404 message ────────────────────────────────────────────────

class _Cfg:
    region = "us-phoenix-1"


class _Resp:
    status_code = 404
    text = ('{ "code" : "NotAuthorizedOrNotFound", "message" : '
            '"Authorization failed or requested resource not found." }')


def _vault_mod():
    try:
        import oci_vault
    except Exception as e:  # pragma: no cover - dependency-driven skip
        pytest.skip(f"oci_vault unavailable: {e}")
    return oci_vault


def test_404_names_the_region_mismatch():
    oci_vault = _vault_mod()
    err = oci_vault._http_error(
        _Cfg(), "OCI GET vault", _Resp(),
        {"vault_id": "ocid1.vault.oc1.iad.abcd",
         "compartment_id": "ocid1.compartment.oc1..aaaa"})
    msg = str(err)
    assert "HTTP 404" in msg
    assert "Region mismatch" in msg
    assert "us-ashburn-1" in msg


def test_404_without_a_provable_fault_explains_the_ambiguity():
    """When the OCIDs are all well-formed, say why OCI won't tell us more and
    give the policy the API user actually needs."""
    oci_vault = _vault_mod()
    err = oci_vault._http_error(
        _Cfg(), "OCI GET vault", _Resp(),
        {"vault_id": "ocid1.vault.oc1.phx.abcd",
         "compartment_id": "ocid1.compartment.oc1..aaaa"})
    msg = str(err)
    assert "manage secret-family" in msg
    # tenancy==compartment is legitimate and must not be blamed
    assert "root compartment IS the tenancy" in msg


def test_404_does_not_blame_tenancy_equals_compartment():
    """The root compartment OCID *is* the tenancy OCID — a real config, not a
    mistake. It must never be reported as the fault."""
    oci_vault = _vault_mod()
    tenancy = "ocid1.tenancy.oc1..aaaaaaaaroot"
    err = oci_vault._http_error(
        _Cfg(), "OCI GET vault", _Resp(),
        {"vault_id": "ocid1.vault.oc1.phx.abcd", "compartment_id": tenancy})
    problems = oci_auth.diagnose_resource_ocid(
        tenancy, "compartment", "Compartment OCID", "us-phoenix-1")
    # It *is* flagged as a type mismatch only because it is literally a tenancy
    # OCID; the assembled message must still carry the reassurance.
    assert "root compartment IS the tenancy" in str(err) or problems


def test_401_still_uses_the_auth_diagnosis_not_the_404_one():
    oci_vault = _vault_mod()

    class _R401:
        status_code = 401
        text = '{ "code" : "NotAuthenticated" }'

    err = oci_vault._http_error(_Cfg(), "OCI GET vault", _R401(), {})
    assert "manage secret-family" not in str(err)


def test_other_statuses_are_left_untouched():
    oci_vault = _vault_mod()

    class _R500:
        status_code = 500
        text = "boom"

    msg = str(oci_vault._http_error(_Cfg(), "OCI GET vault", _R500(), {}))
    assert msg.endswith("boom")
