"""The hub's cert write must survive an unprovisioned or wrongly-owned cert dir.

A live hub went 6+ hours unable to install ANY cert material — its own server
cert, the mTLS CA bundle, and every spoke's mTLS client cert — because
``/opt/lm/certs`` was ``root:root`` while the hub runs as ``svc_lm``. Nothing in
the installers creates that directory, so it had been made by hand as root.

Two things made it hard to see:

* the existing ``hub.crt``/``hub.key`` were owned by ``svc_lm`` and looked
  perfectly writable — but the ATOMIC write never touches them directly. It
  creates a temp file in the same directory (required so ``os.replace`` stays on
  one filesystem) and renames it over the target, so it needs write permission
  on the DIRECTORY;
* the operator-facing target status said only "write to … failed (see cert
  log)", which is a dead end from the WebUI.
"""
import os
import stat
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from hub_cert_distribution import HubCertDistributionMixin  # noqa: E402

_atomic_write = HubCertDistributionMixin._atomic_write
_hint = HubCertDistributionMixin._write_error_hint


# ── the missing-directory case ──────────────────────────────────────────────

def test_atomic_write_creates_a_missing_parent_directory(tmp_path):
    """A cert target whose dir was never provisioned would otherwise fail every
    sweep forever with a bare FileNotFoundError."""
    path = tmp_path / "certs" / "hub.crt"
    assert not path.parent.exists()
    _atomic_write(str(path), "CERTDATA", 0o644)
    assert path.read_text() == "CERTDATA"


def test_atomic_write_creates_nested_parents(tmp_path):
    path = tmp_path / "a" / "b" / "c" / "hub.key"
    _atomic_write(str(path), "KEY", 0o600)
    assert path.read_text() == "KEY"


def test_atomic_write_applies_the_mode_and_leaves_no_temp_files(tmp_path):
    d = tmp_path / "certs"
    _atomic_write(str(d / "hub.key"), "KEY", 0o600)
    _atomic_write(str(d / "hub.crt"), "CRT", 0o644)
    assert stat.S_IMODE((d / "hub.key").stat().st_mode) == 0o600
    assert stat.S_IMODE((d / "hub.crt").stat().st_mode) == 0o644
    assert sorted(p.name for p in d.iterdir()) == ["hub.crt", "hub.key"]


def test_atomic_write_overwrites_in_place(tmp_path):
    path = tmp_path / "certs" / "hub.crt"
    _atomic_write(str(path), "OLD", 0o644)
    _atomic_write(str(path), "NEW", 0o644)
    assert path.read_text() == "NEW"
    assert sorted(p.name for p in path.parent.iterdir()) == ["hub.crt"]


def test_atomic_write_does_not_leave_a_temp_file_behind_on_failure(tmp_path):
    """The temp file is cleaned up even when the write itself blows up, so a
    failing sweep can't slowly fill the cert dir with tmp*.tmp droppings."""
    d = tmp_path / "certs"
    d.mkdir()
    try:
        _atomic_write(str(d / "hub.crt"), object(), 0o644)  # not a str → TypeError
    except Exception:
        pass
    assert list(d.iterdir()) == []


# ── the wrong-ownership case: the message must be actionable ────────────────

def test_permission_error_hint_names_the_directory_and_the_fix():
    exc = PermissionError(13, "Permission denied")
    msg = _hint("/opt/lm/certs/hub.crt", exc)
    # Points at the DIRECTORY, not the file — that's the non-obvious part.
    assert "/opt/lm/certs" in msg
    assert "DIRECTORY" in msg
    assert "chown" in msg
    # Names the user the hub actually runs as, so the chown is copy-pasteable.
    import pwd
    assert pwd.getpwuid(os.geteuid()).pw_name in msg


def test_non_permission_errors_still_report_the_cause_and_path():
    msg = _hint("/opt/lm/certs/hub.key", OSError("No space left on device"))
    assert "No space left on device" in msg
    assert "/opt/lm/certs/hub.key" in msg


def test_hint_survives_an_unstattable_directory():
    """The hint is best-effort: it must never raise and mask the real error."""
    msg = _hint("/definitely/not/here/hub.crt", PermissionError(13, "Permission denied"))
    assert "chown" in msg
