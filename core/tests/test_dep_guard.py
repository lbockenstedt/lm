"""Runtime dep self-heal — ``dep_guard.ensure_requirements`` (Part A).

Pins the contract: when every declared requirement is importable it does no I/O
(no pip subprocess); when one is missing it runs ``pip install -r`` with the
venv python; a pip failure is logged and the function returns False without
raising; a missing requirements.txt is a no-op True; the pip-name→import-name
map covers the mismatched cases (python-dotenv→dotenv, dnspython→dns).
"""

import importlib.util
import os
import sys

# conftest puts core/src on sys.path so `dep_guard` imports flat.
from dep_guard import _import_name_for, ensure_requirements  # noqa: E402


# ── import-name mapping ──────────────────────────────────────────────────────

def test_import_name_map_mismatches():
    assert _import_name_for("python-dotenv") == "dotenv"
    assert _import_name_for("python-dotenv>=1.0.0") == "dotenv"
    assert _import_name_for("dnspython>=2.4") == "dns"
    assert _import_name_for("pyyaml") == "yaml"


def test_import_name_default_heuristic():
    # No map entry → strip extras/version, replace "-" with "_".
    assert _import_name_for("zeroconf>=0.131,<1.0") == "zeroconf"
    assert _import_name_for("uvicorn[standard]>=0.30") == "uvicorn"
    assert _import_name_for("my-cool-pkg") == "my_cool_pkg"
    assert _import_name_for("") == ""


# ── ensure_requirements ──────────────────────────────────────────────────────

def test_all_present_no_subprocess(tmp_path, monkeypatch):
    """When every declared dep is importable, pip is never invoked."""
    req = tmp_path / "requirements.txt"
    # psutil is a real dep in this venv; websockets too. Use stdlib modules that
    # are guaranteed importable so the test doesn't depend on third-party state.
    req.write_text("os\njson\n")

    calls = []
    monkeypatch.setattr("dep_guard.subprocess.run",
                        lambda *a, **k: calls.append((a, k)) or _Proc(0))

    assert ensure_requirements(str(req)) is True
    assert calls == []  # no pip install


def test_missing_dep_invokes_pip_install(tmp_path, monkeypatch):
    monkeypatch.delenv("LM_DEP_GUARD_DISABLE", raising=False)
    req = tmp_path / "requirements.txt"
    req.write_text("os\nthis-package-does-not-exist-xyz>=1.0\n")

    captured = {}
    installed = {"flag": False}
    class _FakeRun:
        def __init__(self): self.returncode = 0; self.stdout = ""; self.stderr = ""
    def _fake_run(args, **kw):
        captured["args"] = args
        captured["kw"] = kw
        installed["flag"] = True   # pip "installed" it → find_spec now succeeds
        return _FakeRun()

    # find_spec: real lookup for stdlib (os), but None for the fake pkg until pip
    # "installs" it, then a non-None sentinel so the re-check passes.
    real_find_spec = importlib.util.find_spec
    def _fake_find_spec(name, *a, **k):
        if name == "this_package_does_not_exist_xyz":
            return object() if installed["flag"] else None
        return real_find_spec(name, *a, **k)

    monkeypatch.setattr("dep_guard.subprocess.run", _fake_run)
    monkeypatch.setattr("dep_guard.importlib.util.find_spec", _fake_find_spec)

    assert ensure_requirements(str(req)) is True
    args = captured["args"]
    assert args[0] == sys.executable
    assert args[1:5] == ["-m", "pip", "install", "-q"]
    assert args[-1] == str(req)
    assert captured["kw"].get("timeout", 300) == 300


def test_pip_failure_returns_false_no_raise(tmp_path, monkeypatch, caplog):
    import logging
    monkeypatch.delenv("LM_DEP_GUARD_DISABLE", raising=False)
    req = tmp_path / "requirements.txt"
    req.write_text("os\nthis-package-does-not-exist-xyz>=1.0\n")

    class _FakeRun:
        def __init__(self): self.returncode = 1; self.stdout = ""; self.stderr = "no network"
    monkeypatch.setattr("dep_guard.subprocess.run", lambda *a, **k: _FakeRun())
    # find_spec: stdlib present, fake pkg never present (pip failed).
    real_find_spec = importlib.util.find_spec
    monkeypatch.setattr(
        "dep_guard.importlib.util.find_spec",
        lambda n, *a, **k: None if n == "this_package_does_not_exist_xyz" else real_find_spec(n, *a, **k),
    )

    with caplog.at_level(logging.WARNING):
        result = ensure_requirements(str(req))  # must not raise

    assert result is False
    assert any("pip install rc=1" in r.message for r in caplog.records)


def test_missing_requirements_file_is_noop_true(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr("dep_guard.subprocess.run",
                        lambda *a, **k: calls.append(a) or _Proc(0))
    # No file at this path.
    assert ensure_requirements(str(tmp_path / "nope.txt")) is True
    assert calls == []


def test_timeout_passed_through(tmp_path, monkeypatch):
    monkeypatch.delenv("LM_DEP_GUARD_DISABLE", raising=False)
    req = tmp_path / "requirements.txt"
    req.write_text("this-package-does-not-exist-xyz\n")
    captured = {}
    installed = {"flag": False}
    class _FakeRun:
        def __init__(self): self.returncode = 0; self.stdout = ""; self.stderr = ""
    def _fake_run(args, **kw):
        captured["timeout"] = kw.get("timeout")
        installed["flag"] = True
        return _FakeRun()
    real_find_spec = importlib.util.find_spec
    monkeypatch.setattr("dep_guard.subprocess.run", _fake_run)
    monkeypatch.setattr(
        "dep_guard.importlib.util.find_spec",
        lambda n, *a, **k: object() if (n == "this_package_does_not_exist_xyz" and installed["flag"]) else (None if n == "this_package_does_not_exist_xyz" else real_find_spec(n, *a, **k)),
    )

    ensure_requirements(str(req), timeout=42)
    assert captured["timeout"] == 42


# ── helper ───────────────────────────────────────────────────────────────────

class _Proc:
    def __init__(self, rc): self.returncode = rc; self.stdout = ""; self.stderr = ""