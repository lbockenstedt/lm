"""Atomic .env upsert (`_persist_secret_to_env`) — the fix for roles/secrets
"randomly" disappearing from a busy multi-role agent.

A multi-role agent runs the base agent + one control plane per hosted role, and
they all persist secrets/URLs/LOADED_ROLES to the SAME .env. The old writer did
open("w") (truncate) then rewrite, so a concurrent reader could see an empty or
half-written file and interleaved writers could drop each other's lines. The
writer is now serialized (`_ENV_FILE_LOCK`) and atomic (temp file + os.replace),
so every upsert is a safe read-modify-write and a reader never sees a truncated
.env.
"""

import os
import sys
import threading

_LM_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _LM_ROOT not in sys.path:
    sys.path.insert(0, _LM_ROOT)

from core.src.messaging import control_plane as cp  # noqa: E402


class _EnvHost:
    """Minimal host exposing only `_repo_root`; borrows the real env helpers so
    we exercise the production upsert/read code (not a stub)."""
    def __init__(self, root):
        self._root = str(root)

    def _repo_root(self):
        return self._root

    _persist_secret_to_env = cp.BaseControlPlane._persist_secret_to_env
    _read_env_value = cp.BaseControlPlane._read_env_value
    _atomic_write_lines = staticmethod(cp.BaseControlPlane._atomic_write_lines)


def test_upsert_round_trips_and_creates_file(tmp_path):
    h = _EnvHost(tmp_path)
    assert h._read_env_value("LOADED_ROLES") == ""      # absent → ""
    h._persist_secret_to_env("LOADED_ROLES", "console,cppm,network,proxy")
    assert (tmp_path / ".env").exists()
    assert h._read_env_value("LOADED_ROLES") == "console,cppm,network,proxy"


def test_upsert_updates_in_place_and_preserves_siblings(tmp_path):
    h = _EnvHost(tmp_path)
    h._persist_secret_to_env("SPOKE_SECRET", "s3cr3t")
    h._persist_secret_to_env("LOADED_ROLES", "console")
    h._persist_secret_to_env("HUB_URL", "wss://hub:443")
    # Update one key; the other two must survive untouched.
    h._persist_secret_to_env("LOADED_ROLES", "console,cppm")
    assert h._read_env_value("SPOKE_SECRET") == "s3cr3t"
    assert h._read_env_value("LOADED_ROLES") == "console,cppm"
    assert h._read_env_value("HUB_URL") == "wss://hub:443"
    # Exactly one line per key (no dupes from the upsert).
    body = (tmp_path / ".env").read_text()
    assert body.count("LOADED_ROLES=") == 1
    assert body.count("SPOKE_SECRET=") == 1


def test_new_env_file_is_owner_only(tmp_path):
    h = _EnvHost(tmp_path)
    h._persist_secret_to_env("SPOKE_SECRET", "s3cr3t")
    mode = os.stat(tmp_path / ".env").st_mode & 0o777
    assert mode == 0o600, f"new .env should be 0600, got {oct(mode)}"


def test_concurrent_writers_do_not_lose_lines(tmp_path):
    """Hammer the shared .env from many threads, each upserting its own key.
    With the lock + atomic replace, every key must survive (no lost updates)
    and no reader ever observes a truncated file."""
    h = _EnvHost(tmp_path)
    h._persist_secret_to_env("LOADED_ROLES", "console,cppm,network,proxy")
    n = 40
    seen_truncated = []

    def _writer(i):
        h._persist_secret_to_env(f"KEY_{i}", f"val_{i}")

    def _reader():
        # LOADED_ROLES must never read back empty/partial while writers run.
        for _ in range(200):
            if h._read_env_value("LOADED_ROLES") != "console,cppm,network,proxy":
                seen_truncated.append(True)

    threads = [threading.Thread(target=_writer, args=(i,)) for i in range(n)]
    threads += [threading.Thread(target=_reader) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not seen_truncated, "a reader saw a truncated/partial LOADED_ROLES"
    # Every writer's key survived — no lost updates from interleaving.
    for i in range(n):
        assert h._read_env_value(f"KEY_{i}") == f"val_{i}", f"KEY_{i} was lost"
    # And the seed key is intact.
    assert h._read_env_value("LOADED_ROLES") == "console,cppm,network,proxy"


def test_falls_back_to_in_place_when_atomic_write_fails(tmp_path, monkeypatch):
    """If the atomic path can't create a sibling temp file (e.g. the parent dir
    isn't writable by this process even though the .env file is), the writer must
    fall back to an in-place write rather than silently dropping the update —
    strictly no worse than the legacy behavior."""
    h = _EnvHost(tmp_path)
    h._persist_secret_to_env("SPOKE_SECRET", "orig")

    def _boom(*a, **k):
        raise PermissionError("dir not writable")

    monkeypatch.setattr(cp.tempfile, "mkstemp", _boom)
    # Update must still land via the in-place fallback.
    h._persist_secret_to_env("SPOKE_SECRET", "rotated")
    assert h._read_env_value("SPOKE_SECRET") == "rotated"

