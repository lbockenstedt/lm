"""LM_DROP_FERNET_KEY_ENV must actually clear /proc/<pid>/environ.

``os.environ.pop()`` calls ``unsetenv``, which only edits the C ``environ``
pointer array. ``/proc/<pid>/environ`` is served from the immutable
``env_start..env_end`` stack range recorded at ``execve`` time, so a popped
secret stayed fully readable by any root process -- the exact exposure this
control claims to close. The drop path must therefore ALSO scrub that block.

The Linux test here is end-to-end: it re-execs a real interpreter so the value
is genuinely in the original stack block, then asserts the scrub removes it
from /proc/self/environ while leaving other variables intact.
"""

import os
import subprocess
import sys
import textwrap

import pytest

SRC = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from security.encryption import HubEncryption  # noqa: E402

LINUX_ONLY = pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="/proc/self/mem environ scrub is Linux-only")


class _Stub(HubEncryption):
    """Exercise the drop path without building real Fernet keys."""

    def __init__(self, key="stub-key"):  # noqa: D107 - deliberately no super()
        self._primary_key_str = key
        self.scrub_calls = []

    def _scrub_proc_environ(self, names):
        self.scrub_calls.append(tuple(names))
        return list(names)


# ── gating (runs on every platform) ──────────────────────────────────────────

def test_scrub_runs_when_the_flag_is_on(monkeypatch):
    monkeypatch.setenv("LM_DROP_FERNET_KEY_ENV", "1")
    monkeypatch.delenv("LM_KEEP_FERNET_KEY_ENV", raising=False)
    monkeypatch.setenv("LM_FERNET_KEY", "secret")
    enc = _Stub()
    enc._maybe_drop_env_key()
    assert "LM_FERNET_KEY" not in os.environ
    assert enc.scrub_calls == [("LM_FERNET_KEY", "LM_FERNET_KEY_PREVIOUS")]


def test_scrub_runs_even_when_os_environ_no_longer_has_the_var(monkeypatch):
    """The stack block keeps whatever execve() was handed, so a var already
    popped elsewhere is still sitting there in the clear."""
    monkeypatch.setenv("LM_DROP_FERNET_KEY_ENV", "1")
    monkeypatch.delenv("LM_KEEP_FERNET_KEY_ENV", raising=False)
    monkeypatch.delenv("LM_FERNET_KEY", raising=False)
    monkeypatch.delenv("LM_FERNET_KEY_PREVIOUS", raising=False)
    enc = _Stub()
    enc._maybe_drop_env_key()
    assert enc.scrub_calls, "scrub must not be skipped just because pop() found nothing"


@pytest.mark.parametrize("env", [
    {},                                                  # flag off (default)
    {"LM_DROP_FERNET_KEY_ENV": "1", "LM_KEEP_FERNET_KEY_ENV": "1"},  # forced off
])
def test_scrub_is_skipped_when_disabled(monkeypatch, env):
    monkeypatch.delenv("LM_DROP_FERNET_KEY_ENV", raising=False)
    monkeypatch.delenv("LM_KEEP_FERNET_KEY_ENV", raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setenv("LM_FERNET_KEY", "secret")
    enc = _Stub()
    enc._maybe_drop_env_key()
    assert enc.scrub_calls == []
    assert os.environ["LM_FERNET_KEY"] == "secret"


def test_scrub_is_skipped_when_key_capture_failed(monkeypatch):
    """Fail-safe: never scrub if we could not hold the key in-process."""
    monkeypatch.setenv("LM_DROP_FERNET_KEY_ENV", "1")
    monkeypatch.setenv("LM_FERNET_KEY", "secret")
    enc = _Stub(key="")
    enc._maybe_drop_env_key()
    assert enc.scrub_calls == []
    assert os.environ["LM_FERNET_KEY"] == "secret"


def test_scrub_is_a_noop_off_linux(monkeypatch):
    monkeypatch.setattr(sys, "platform", "darwin")
    assert HubEncryption._scrub_proc_environ(
        HubEncryption.__new__(HubEncryption), ["LM_FERNET_KEY"]) == []


# ── real behaviour (Linux) ───────────────────────────────────────────────────

@LINUX_ONLY
def test_proc_env_bounds_matches_the_environ_the_kernel_serves():
    start, end = HubEncryption._proc_env_bounds()
    assert end > start, "failed to parse env_start/env_end from /proc/self/stat"
    with open("/proc/self/environ", "rb") as fh:
        assert end - start == len(fh.read())


_E2E = textwrap.dedent(r"""
    import os, sys
    sys.path.insert(0, %(src)r)
    SENTINEL = "canary-value-do-not-leak"
    if os.environ.get("_LM_STAGE") != "2":
        os.environ["_LM_STAGE"] = "2"
        os.environ["LM_FERNET_KEY"] = SENTINEL
        os.environ["LM_UNRELATED"] = "keep-me"
        os.execv(sys.executable, [sys.executable, __file__])

    from security.encryption import HubEncryption

    def environ_blob():
        with open("/proc/self/environ", "rb") as fh:
            return fh.read()

    before = SENTINEL.encode() in environ_blob()
    os.environ.pop("LM_FERNET_KEY", None)
    after_pop = SENTINEL.encode() in environ_blob()

    enc = HubEncryption.__new__(HubEncryption)
    scrubbed = HubEncryption._scrub_proc_environ(
        enc, ["LM_FERNET_KEY", "LM_FERNET_KEY_PREVIOUS"])

    blob = environ_blob()
    print("before=%%s pop=%%s after=%%s scrubbed=%%s other=%%s" %% (
        before, after_pop, SENTINEL.encode() in blob,
        "LM_FERNET_KEY" in scrubbed, b"LM_UNRELATED=keep-me" in blob))
""")


@LINUX_ONLY
def test_scrub_really_removes_the_key_from_proc_environ(tmp_path):
    script = tmp_path / "e2e.py"
    script.write_text(_E2E % {"src": SRC})
    proc = subprocess.run([sys.executable, str(script)],
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    out = proc.stdout.strip().splitlines()[-1]
    # before=True  : the key really was in the original stack block
    # pop=True     : os.environ.pop() did NOT remove it -- the bug
    # after=False  : the scrub did remove it -- the fix
    # other=True   : unrelated variables survive, so ops keep a usable environ
    assert out == ("before=True pop=True after=False scrubbed=True other=True"), out
