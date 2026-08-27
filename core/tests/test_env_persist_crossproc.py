"""Cross-process safety test for the ``.env`` upsert
(``BaseControlPlane._persist_secret_to_env``).

``_ENV_FILE_LOCK`` only serializes THREADS in one process, but multiple agent
PROCESSES share one ``.env`` (base agent + each hosted role's control plane, and
an overlapping self-update restart). Two processes doing read-modify-write
concurrently used to lose each other's lines — the "roles randomly vanishing
from LOADED_ROLES / per-role secrets" outage. The fix holds an advisory
``fcntl.flock`` on a sidecar ``.env.lock`` across the whole read-modify-write.

These tests spawn real OS processes hammering the same ``.env`` with distinct
keys and assert NO upsert is lost.
"""

import multiprocessing as mp
import os

from messaging.control_plane import BaseControlPlane


def _make_cp(repo_root: str) -> BaseControlPlane:
    # Bypass the heavy __init__ — the persist path only needs _repo_root().
    cp = object.__new__(BaseControlPlane)
    cp._repo_root = lambda: repo_root  # type: ignore[method-assign]
    return cp


def _worker(repo_root: str, key: str, n: int) -> None:
    cp = _make_cp(repo_root)
    for i in range(n):
        cp._persist_secret_to_env(key, f"{key}-{i}")


def _bump(repo_root: str, env_path: str, counter: str, n: int) -> None:
    import time
    for _ in range(n):
        with BaseControlPlane._env_file_flock(env_path):
            with open(counter) as fh:
                v = int(fh.read().strip() or "0")
            time.sleep(0.001)  # widen the race window
            with open(counter, "w") as fh:
                fh.write(str(v + 1))


def _read_env(repo_root: str) -> dict:
    out = {}
    path = os.path.join(repo_root, ".env")
    with open(path) as f:
        for line in f:
            if "=" in line:
                k, _, v = line.partition("=")
                out[k.strip()] = v.strip()
    return out


def test_concurrent_processes_do_not_lose_keys(tmp_path):
    repo_root = str(tmp_path)
    # Seed base keys that must survive (mirror SPOKE_SECRET / HUB_SECRET).
    _make_cp(repo_root)._persist_secret_to_env("SPOKE_SECRET", "base-secret")

    keys = [f"KEY_{i}" for i in range(8)]
    procs = [mp.Process(target=_worker, args=(repo_root, k, 40)) for k in keys]
    for p in procs:
        p.start()
    for p in procs:
        p.join(timeout=60)
        assert p.exitcode == 0

    env = _read_env(repo_root)
    # Every writer's key must be present (none clobbered) AND the pre-existing
    # base secret must survive the concurrent rewrites.
    assert env.get("SPOKE_SECRET") == "base-secret"
    for k in keys:
        assert k in env, f"{k} was lost to a concurrent-process clobber: {sorted(env)}"
        assert env[k].startswith(k + "-")


def test_env_file_flock_serializes_processes(tmp_path):
    # Two processes each hold the flock while incrementing a shared counter file
    # with a read/sleep/write window that WOULD interleave without the lock.
    repo_root = str(tmp_path)
    env_path = os.path.join(repo_root, ".env")
    counter = os.path.join(repo_root, "counter")
    with open(counter, "w") as f:
        f.write("0")

    procs = [mp.Process(target=_bump, args=(repo_root, env_path, counter, 50))
             for _ in range(4)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(timeout=60)
        assert p.exitcode == 0

    with open(counter) as f:
        total = int(f.read().strip())
    # Without cross-process mutual exclusion, lost updates make this < 200.
    assert total == 200, f"flock did not serialize processes: counter={total}"
