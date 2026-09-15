"""The Hub Status → Restart button must explain WHY it failed, and the
installed lm.service must let sudo become root.

Live regression: the button returned
``502 restart could not be scheduled: self-restart exited 1: sudo: unable to
change to root gid: Operation not permitted``. Root cause was three hops away —
``lm.service``'s ``CapabilityBoundingSet`` gates every child process, and a unit
installed before CAP_SETUID/CAP_SETGID/CAP_SETPCAP/CAP_AUDIT_WRITE were added to
that line leaves setuid-root sudo unable to switch uid/gid, so it dies before it
ever reads ``/etc/sudoers.d/lm``. Because self-update ships code but never
rewrites unit files, an old hub keeps the broken line forever — and the same
sudo powers ``lm-update-restart``, so the hub also silently stopped applying its
own updates.
"""

import os
import re
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from hub_cert_distribution import _diagnose_self_restart_failure  # noqa: E402

_INSTALLER = os.path.join(os.path.dirname(__file__), "..", "..", "install_all.sh")

# Every capability sudo needs to go from the hub's service user to root.
_REQUIRED_CAPS = ("CAP_SETUID", "CAP_SETGID", "CAP_SETPCAP", "CAP_AUDIT_WRITE")


def _hub_unit_bounding_set():
    """The CapabilityBoundingSet line install_all.sh writes into lm.service."""
    with open(_INSTALLER, encoding="utf-8") as fh:
        body = fh.read()
    lines = [ln for ln in body.splitlines()
             if ln.startswith("CapabilityBoundingSet=")]
    assert lines, "install_all.sh no longer writes a CapabilityBoundingSet"
    return lines


@pytest.mark.parametrize("cap", _REQUIRED_CAPS)
def test_installed_unit_grants_every_capability_sudo_needs(cap):
    """Without these, `sudo -n <helper>` dies before reading sudoers — which
    breaks BOTH the restart button and the hub's own self-update restart."""
    assert any(cap in ln for ln in _hub_unit_bounding_set()), (
        f"{cap} missing from lm.service's CapabilityBoundingSet — sudo cannot "
        f"become root, so hub self-restart and self-update both fail")


def test_installed_unit_still_binds_privileged_port():
    """The caps above are ADDITIVE — dropping CAP_NET_BIND_SERVICE would stop
    the hub binding :443."""
    assert any("CAP_NET_BIND_SERVICE" in ln for ln in _hub_unit_bounding_set())


def test_gid_failure_names_the_capability_fix():
    msg = _diagnose_self_restart_failure(
        "sudo: unable to change to root gid: Operation not permitted")
    assert "CapabilityBoundingSet" in msg
    for cap in _REQUIRED_CAPS:
        assert cap in msg
    # The non-obvious part: self-update will NOT fix this for you.
    assert "self-update" in msg
    assert "lm.service" in msg


def test_audit_plugin_failure_is_the_same_diagnosis():
    """The audit-plugin error is the second half of the same capability fault
    and must not be left as a bare, unactionable string."""
    msg = _diagnose_self_restart_failure(
        "sudo: error initializing audit plugin sudoers_audit")
    assert "CapabilityBoundingSet" in msg


def test_missing_helper_points_at_the_off_rename():
    msg = _diagnose_self_restart_failure(
        "sudo: /usr/local/bin/lm-self-restart: command not found")
    assert ".off" in msg
    assert "systemctl restart lm" in msg


def test_missing_file_variant_is_recognized():
    msg = _diagnose_self_restart_failure(
        "sudo: no such file or directory")
    assert ".off" in msg


def test_sudoers_denial_points_at_sudoers_not_capabilities():
    msg = _diagnose_self_restart_failure("sudo: a password is required")
    assert "sudoers.d/lm" in msg
    assert "CapabilityBoundingSet" not in msg


def test_not_allowed_to_execute_is_a_sudoers_denial():
    msg = _diagnose_self_restart_failure(
        "Sorry, user svc_lm is not allowed to execute '/usr/local/bin/lm-self-restart'")
    assert "sudoers.d/lm" in msg


def test_unrecognized_failure_is_passed_through_unchanged():
    """Never invent a diagnosis for a failure we don't recognize — the raw
    stderr is more useful than a confidently wrong remedy."""
    assert _diagnose_self_restart_failure("kernel panic") == "kernel panic"


def test_blank_detail_stays_falsy_so_the_caller_can_substitute():
    """The caller renders ``diagnosis or 'no output captured'`` — a blank input
    must stay falsy rather than becoming a bogus diagnosis."""
    assert not _diagnose_self_restart_failure("")
    assert not _diagnose_self_restart_failure(None)
    assert not _diagnose_self_restart_failure("   ")


def test_diagnosis_is_case_insensitive():
    msg = _diagnose_self_restart_failure(
        "SUDO: UNABLE TO CHANGE TO ROOT GID: OPERATION NOT PERMITTED")
    assert "CapabilityBoundingSet" in msg


def test_original_stderr_is_preserved_in_the_diagnosis():
    """Operators grep for the raw sudo text; the remedy is appended, not
    substituted."""
    raw = "sudo: unable to change to root gid: Operation not permitted"
    assert _diagnose_self_restart_failure(raw).startswith(raw)


def test_installer_documents_why_the_capabilities_are_there():
    """A future hardening pass will try to trim this line back down; the
    comment above it is what stops that."""
    with open(_INSTALLER, encoding="utf-8") as fh:
        body = fh.read()
    idx = body.index("CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_SETUID")
    preamble = body[max(0, idx - 800):idx]
    assert "sudo" in preamble
    assert re.search(r"audit", preamble, re.I)
