"""Footer version-indicator disk-vs-running drift (Hub._compute_version_drift).

Pins the fix for "the indicator is not turning yellow when disk vs memory is
different": the running version MUST come from the in-memory
``_startup_version`` (captured once at boot from the VERSION file), NOT by
re-reading the VERSION file. The file is what a ``git pull`` rewrites, so
re-reading it makes ``running == target`` even right after a pull (while the
process still serves the OLD code) and ``behind`` never flips — the dot stays
green while disk != the running process's actual version.

``_startup_version`` only moves on a real restart, so disk-vs-_startup_version
IS disk-vs-running. The footer's ``m.version`` also comes from
``_startup_version`` (see main.py get_system_metrics), so the displayed version
only advances after a restart, not the moment a pull rewrites VERSION.
"""
import builtins
import io
import os
import sys

import pytest

_LM_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _LM_ROOT not in sys.path:
    sys.path.insert(0, _LM_ROOT)

import main as main_mod  # noqa: E402


class _DriftHub:
    """Bare stand-in exposing only what _compute_version_drift reads:
    _startup_version (in-memory running) + _update_available. The disk VERSION
    file read is intercepted via the open/exists monkeypatch in each test."""

    def __init__(self, startup_version=None, update_available=False):
        if startup_version is not None:
            self._startup_version = startup_version
        self._update_available = update_available


def _patch_version_file(monkeypatch, disk_version, exists=True):
    """Redirect the VERSION-file read in _compute_version_drift to a controlled
    string. The method resolves the file via os.path.dirname(__file__) + a
    relative ../../VERSION (or ../VERSION fallback) and open()s it; intercept
    os.path.exists + builtins.open for any path whose basename is VERSION."""
    def _exists(path):
        if os.path.basename(path) == "VERSION":
            return exists
        return os.path.exists(path)  # real for everything else

    _real_open = open

    def _open(path, *args, **kwargs):
        if os.path.basename(path) == "VERSION":
            return io.StringIO(disk_version)
        return _real_open(path, *args, **kwargs)

    monkeypatch.setattr(os.path, "exists", _exists)
    monkeypatch.setattr(builtins, "open", _open)


def test_disk_equals_running_not_behind(monkeypatch):
    # Boot .572, disk still .572, no remote update → green.
    _patch_version_file(monkeypatch, ".572")
    hub = _DriftHub(startup_version=".572")
    target, running, behind, avail = main_mod.LabManagerHub._compute_version_drift(hub)
    assert target == ".572"
    assert running == ".572"
    assert behind is False
    assert avail is False


def test_disk_newer_than_running_is_behind(monkeypatch):
    # THE BUG: a `git pull` bumped VERSION on disk to .573 while the process is
    # still running .572 (no restart). behind MUST flip True so the dot turns
    # yellow. The OLD code re-read the VERSION FILE for running_version, which
    # would have returned .573 (same as disk) → behind False → green dot. The
    # in-memory _startup_version (.572) is what makes this work.
    _patch_version_file(monkeypatch, ".573")
    hub = _DriftHub(startup_version=".572")
    target, running, behind, avail = main_mod.LabManagerHub._compute_version_drift(hub)
    assert target == ".573"
    assert running == ".572"   # in-memory, NOT re-read from disk
    assert behind is True
    assert avail is False


def test_update_available_surfaces_alone(monkeypatch):
    # Remote ahead, not pulled → disk == running (.572) but update_available True.
    _patch_version_file(monkeypatch, ".572")
    hub = _DriftHub(startup_version=".572", update_available=True)
    target, running, behind, avail = main_mod.LabManagerHub._compute_version_drift(hub)
    assert behind is False
    assert avail is True   # the other yellow signal (remote-ahead-not-pulled)


def test_disk_unreadable_never_false_yellows(monkeypatch):
    # VERSION file missing/unreadable → target "" → behind must be False (never
    # false-yellow on an I/O failure).
    _patch_version_file(monkeypatch, "", exists=False)
    hub = _DriftHub(startup_version=".572")
    target, running, behind, avail = main_mod.LabManagerHub._compute_version_drift(hub)
    assert target == ""
    assert behind is False


def test_startup_version_unset_falls_back_to_running_version_file(monkeypatch):
    # If _startup_version is somehow unset (pre-ready poll), fall back to the
    # running-version FILE. Disk .573 vs file .572 → behind True. Intercepts
    # open() for BOTH VERSION and running-version paths.
    _real_open = open

    def _open(path, *args, **kwargs):
        base = os.path.basename(path)
        if base == "VERSION":
            import io as _io
            return _io.StringIO(".573")
        if "running-version" in str(path):
            import io as _io
            return _io.StringIO(".572")
        return _real_open(path, *args, **kwargs)

    monkeypatch.setattr(os.path, "exists", lambda p: True)
    monkeypatch.setattr(builtins, "open", _open)
    hub = _DriftHub()  # NO _startup_version set
    target, running, behind, avail = main_mod.LabManagerHub._compute_version_drift(hub)
    assert target == ".573"
    assert running == ".572"   # from the running-version file fallback
    assert behind is True


def test_startup_version_is_frozen_at_boot_not_reread(monkeypatch):
    # The whole point: _startup_version is set ONCE at boot and never reassigned
    # (only main.py start() writes it). Confirm the attribute is the single
    # source of running_version — no code path re-reads the disk file into it.
    import inspect
    src = inspect.getsource(main_mod.LabManagerHub)
    # Exactly one assignment to self._startup_version in the whole class body
    # (the boot capture in start()). The drift helper only READS it (getattr).
    assigns = src.count("self._startup_version =")
    assert assigns == 1, f"expected exactly one boot capture, found {assigns}"