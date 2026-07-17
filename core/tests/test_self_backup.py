"""Self-backup subsystem regressions (core/src/self_backup.py).

Covers:
  1. ``seed_self_backup_defaults`` seeds disabled-by-default config ONCE and
     never overwrites an existing config (incl. an explicit enabled=True).
  2. ``run_backup_now`` produces a real archive in ``<data_dir>/self-backup/``
     with the state JSON inside, and updates ``last_backup_at``.
  3. ``_sb_prune`` keeps only the newest ``keep_count`` archives.
  4. ``encrypt_archive`` round-trip: a ``.tgz.enc`` decrypts (hub Fernet) back
     to a valid ``.tar.gz`` containing the state file; a plain ``.tar.gz`` is a
     valid tar with the same content.
  5. scp argv is built with ``create_subprocess_exec`` (no shell): correct
     ``-i keyfile`` / ``-P port`` / ``BatchMode=yes`` / ``StrictHostKeyChecking``
     yes|no / ``user@host:path`` shape; the defense-in-depth charset gate
     rejects a newline in any SSH field; an empty required field errors before
     exec; a missing local backup errors before exec.
  6. ``copy_mode``: ``after_each_backup`` fires the copy inside
     ``run_backup_now``; ``own_schedule`` does NOT (the loop drives it).
  7. The admin route gate: ``/setup/backup/*`` 403s a non-admin session and
     admits a Global Admin (per-handler ``_require_admin`` belt-and-suspenders
     on top of the middleware ``/setup/`` admin gate).

The mixin is exercised through a minimal ``_Hub(SelfBackupMixin)`` with fake
``state`` (``data_dir`` + ``system_state``) + ``key_manager`` (``storage_path``).
``conftest`` generates a throwaway ``LM_FERNET_KEY`` so ``hub_encryption``
imports + encrypts.
"""
import asyncio
import io
import json
import os
import tarfile
import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import self_backup
from self_backup import SelfBackupMixin
from security.encryption import hub_encryption


# ── stubs ──────────────────────────────────────────────────────────────────

class _FakeState:
    """Minimal state: a data_dir on disk + a system_state dict the mixin
    reads global_config from + a save_state() noop."""

    def __init__(self, data_dir, global_config=None):
        self.data_dir = data_dir
        self.system_state = {"global_config": dict(global_config or {})}
        self.save_calls = 0

    def save_state(self):
        self.save_calls += 1

    def _mark_dirty(self):  # parity with StateManager dirty-flag persistence
        pass

    async def save_state_now(self):
        self.save_state()


class _FakeKeyManager:
    def __init__(self, keys_dir):
        os.makedirs(keys_dir, exist_ok=True)
        self.storage_path = os.path.join(keys_dir, "keys.json")


class _Hub(SelfBackupMixin):
    def __init__(self, state, key_manager):
        self.state = state
        self.key_manager = key_manager


def _make_hub(tmp_path, global_config=None, with_keys=True):
    state_dir = tmp_path / "state"
    keys_dir = tmp_path / "keys"
    state_dir.mkdir()
    # Drop real state files so the tarball has content.
    (state_dir / "system.json").write_text(json.dumps({"global_config": {}}))
    (state_dir / "tenants.json").write_text(json.dumps({"tenants": []}))
    # A subdir + a running-version file that must be EXCLUDED.
    (state_dir / "self-backup").mkdir()
    (state_dir / "running-version").write_text("v.999")
    state = _FakeState(str(state_dir), global_config)
    km = _FakeKeyManager(str(keys_dir)) if with_keys else None
    if with_keys:
        (keys_dir / "keys.json").write_text(json.dumps({"spokes": {}}))
        (keys_dir / "hub_secret.json").write_text(json.dumps({"hub_secret": "x"}))
    return _Hub(state, km), state_dir, keys_dir


# ── 1. seed defaults ───────────────────────────────────────────────────────

def test_seed_defaults_disabled_by_default(tmp_path):
    hub, _, _ = _make_hub(tmp_path)
    assert "self_backup" not in hub.state.system_state["global_config"]
    hub.seed_self_backup_defaults()
    cfg = hub.state.system_state["global_config"]["self_backup"]
    assert cfg["enabled"] is False
    assert cfg["encrypt_archive"] is True
    assert cfg["copy_mode"] == "after_each_backup"
    assert cfg["backup_interval_hours"] == 24
    assert cfg["keep_count"] == 7


def test_seed_does_not_overwrite_existing_config(tmp_path):
    hub, _, _ = _make_hub(tmp_path, global_config={"self_backup": {"enabled": True}})
    hub.seed_self_backup_defaults()
    # The explicit enabled=True survives — seeding never overwrites.
    assert hub.state.system_state["global_config"]["self_backup"]["enabled"] is True
    # And the full default key set was NOT injected (existing dict untouched).
    assert "keep_count" not in hub.state.system_state["global_config"]["self_backup"]


# ── 2. run_backup_now produces a real archive ─────────────────────────────

@pytest.mark.asyncio
async def test_run_backup_now_produces_archive_with_state(tmp_path):
    hub, state_dir, keys_dir = _make_hub(tmp_path, global_config={
        "self_backup": {"enabled": True, "encrypt_archive": False,
                        "keep_count": 7, "include_env": False}})
    res = await hub.run_backup_now()
    assert res["status"] == "ok"
    assert res["name"].endswith(".tar.gz")
    assert res["encrypted"] is False
    archive = os.path.join(hub.state.data_dir, "self-backup", res["name"])
    assert os.path.isfile(archive)
    # The tarball carries the state JSON (with its label) but NOT the
    # self-backup subdir or running-version.
    with tarfile.open(archive, "r:gz") as tar:
        names = tar.getnames()
    assert "state/system.json" in names
    assert "state/tenants.json" in names
    assert "keys/keys.json" in names
    assert "keys/hub_secret.json" in names
    assert all("running-version" not in n for n in names)
    assert all("self-backup" not in n for n in names)
    # last_backup_at stamped.
    assert hub._self_backup_cfg()["last_backup_at"] > 0


@pytest.mark.asyncio
async def test_run_backup_now_encrypts_when_enabled(tmp_path):
    hub, _, _ = _make_hub(tmp_path, global_config={
        "self_backup": {"enabled": True, "encrypt_archive": True,
                        "keep_count": 7, "include_env": False}})
    res = await hub.run_backup_now()
    assert res["status"] == "ok"
    assert res["encrypted"] is True
    assert res["name"].endswith(".tgz.enc")
    archive = os.path.join(hub.state.data_dir, "self-backup", res["name"])
    # The .tgz.enc is Fernet ciphertext (not a gzip header).
    with open(archive, "rb") as f:
        head = f.read(2)
    assert head != b"\x1f\x8b"  # not a raw gzip header
    # Round-trip: decrypt → valid tar.gz → state file present.
    with open(archive, "rb") as f:
        blob = hub_encryption.fernet.decrypt(f.read())
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tar:
        assert "state/system.json" in tar.getnames()


# ── 3. prune keeps only the newest N ─────────────────────────────────────

def test_prune_keeps_newest_n(tmp_path):
    hub, _, _ = _make_hub(tmp_path)
    root = os.path.join(hub.state.data_dir, "self-backup")
    os.makedirs(root, exist_ok=True)
    paths = []
    for i in range(5):
        p = os.path.join(root, f"2026010{i}T000000Z.tar.gz")
        with open(p, "wb") as f:
            f.write(b"x")
        # Stagger mtimes so the sort is deterministic (newest = highest index).
        os.utime(p, (time.time() + i, time.time() + i))
        paths.append(p)
    removed = hub._sb_prune(keep=2)
    assert removed == 3
    remaining = sorted(os.listdir(root))
    # The two newest (i=4, i=3) survive.
    assert len(remaining) == 2
    assert "20260104T000000Z.tar.gz" in remaining
    assert "20260103T000000Z.tar.gz" in remaining


# ── 5. scp argv + charset/empty validation ──────────────────────────────────

class _FakeProc:
    def __init__(self, rc=0, err=b""):
        self.returncode = rc
        self._err = err

    async def communicate(self):
        return (b"", self._err)

    def kill(self):
        pass


def _cfg_with_ssh(**overrides):
    cfg = {
        "enabled": True, "encrypt_archive": False, "keep_count": 7,
        "include_env": False, "copy_enabled": True,
        "copy_mode": "after_each_backup", "copy_interval_hours": 24,
        "ssh_host": "backup.example.com", "ssh_port": 2222,
        "ssh_user": "backup", "ssh_path": "/backups/lm/",
        "ssh_keyfile": "/root/.ssh/lm_id", "ssh_strict_hostkey": True,
        "last_backup_at": 0.0, "last_copy_at": 0.0, "last_error": "",
    }
    cfg.update(overrides)
    return {"self_backup": cfg}


@pytest.mark.asyncio
async def test_scp_argv_built_correctly(tmp_path, monkeypatch):
    hub, _, _ = _make_hub(tmp_path, global_config=_cfg_with_ssh())
    # A local backup to copy.
    archive = os.path.join(hub.state.data_dir, "self-backup", "x.tar.gz")
    os.makedirs(os.path.dirname(archive), exist_ok=True)
    with open(archive, "wb") as f:
        f.write(b"backup")
    captured = {}

    async def fake_exec(*argv, **kwargs):
        captured["argv"] = list(argv)
        return _FakeProc(rc=0)

    monkeypatch.setattr(self_backup.asyncio, "create_subprocess_exec", fake_exec)
    res = await hub._sb_run_copy(local_file=archive)
    assert res["status"] == "ok"
    argv = captured["argv"]
    assert argv[0] == "scp"
    assert "-i" in argv and "/root/.ssh/lm_id" in argv
    assert "-P" in argv and "2222" in argv
    assert "BatchMode=yes" in argv
    assert "PasswordAuthentication=no" in argv
    assert any(v == "StrictHostKeyChecking=yes" for v in argv)
    assert argv[-1] == "backup@backup.example.com:/backups/lm/"
    assert archive in argv


@pytest.mark.asyncio
async def test_scp_strict_hostkey_no_when_disabled(tmp_path, monkeypatch):
    hub, _, _ = _make_hub(tmp_path, global_config=_cfg_with_ssh(ssh_strict_hostkey=False))
    archive = os.path.join(hub.state.data_dir, "self-backup", "x.tar.gz")
    os.makedirs(os.path.dirname(archive), exist_ok=True)
    with open(archive, "wb") as f:
        f.write(b"backup")
    captured = {}

    async def fake_exec(*argv, **kwargs):
        captured["argv"] = list(argv)
        return _FakeProc(rc=0)

    monkeypatch.setattr(self_backup.asyncio, "create_subprocess_exec", fake_exec)
    await hub._sb_run_copy(local_file=archive)
    assert "StrictHostKeyChecking=no" in captured["argv"]


@pytest.mark.asyncio
async def test_scp_rejects_bad_charset_field(tmp_path, monkeypatch):
    hub, _, _ = _make_hub(tmp_path, global_config=_cfg_with_ssh(
        ssh_host="bad\nhost; rm -rf /"))  # newline + shell metachars
    archive = os.path.join(hub.state.data_dir, "self-backup", "x.tar.gz")
    os.makedirs(os.path.dirname(archive), exist_ok=True)
    with open(archive, "wb") as f:
        f.write(b"backup")
    called = {"n": 0}

    async def fake_exec(*argv, **kwargs):
        called["n"] += 1
        return _FakeProc(rc=0)

    monkeypatch.setattr(self_backup.asyncio, "create_subprocess_exec", fake_exec)
    res = await hub._sb_run_copy(local_file=archive)
    assert res["status"] == "error"
    assert "invalid characters" in res["error"]
    # The exec must NEVER have run.
    assert called["n"] == 0


@pytest.mark.asyncio
async def test_scp_empty_required_field_errors(tmp_path, monkeypatch):
    hub, _, _ = _make_hub(tmp_path, global_config=_cfg_with_ssh(ssh_user=""))
    archive = os.path.join(hub.state.data_dir, "self-backup", "x.tar.gz")
    os.makedirs(os.path.dirname(archive), exist_ok=True)
    with open(archive, "wb") as f:
        f.write(b"backup")
    called = {"n": 0}

    async def fake_exec(*argv, **kwargs):
        called["n"] += 1
        return _FakeProc(rc=0)

    monkeypatch.setattr(self_backup.asyncio, "create_subprocess_exec", fake_exec)
    res = await hub._sb_run_copy(local_file=archive)
    assert res["status"] == "error"
    assert "not configured" in res["error"]
    assert called["n"] == 0


@pytest.mark.asyncio
async def test_scp_no_local_backup_errors(tmp_path, monkeypatch):
    hub, _, _ = _make_hub(tmp_path, global_config=_cfg_with_ssh())
    called = {"n": 0}

    async def fake_exec(*argv, **kwargs):
        called["n"] += 1
        return _FakeProc(rc=0)

    monkeypatch.setattr(self_backup.asyncio, "create_subprocess_exec", fake_exec)
    # No local_file + empty backup dir → "no local backup to copy".
    res = await hub._sb_run_copy(local_file=None)
    assert res["status"] == "error"
    assert "no local backup" in res["error"]
    assert called["n"] == 0


# ── 6. copy_mode: after_each_backup fires in run_backup_now; own_schedule not

@pytest.mark.asyncio
async def test_after_each_backup_copy_fires_in_run_backup_now(tmp_path, monkeypatch):
    hub, _, _ = _make_hub(tmp_path, global_config=_cfg_with_ssh(
        copy_mode="after_each_backup"))
    copied = {"n": 0, "file": None}

    async def fake_copy(local_file=None):
        copied["n"] += 1
        copied["file"] = local_file
        return {"status": "ok", "file": os.path.basename(local_file or "")}

    monkeypatch.setattr(hub, "_sb_run_copy", fake_copy)
    res = await hub.run_backup_now()
    assert res["status"] == "ok"
    assert copied["n"] == 1
    assert copied["file"] and copied["file"].endswith(".tar.gz")


@pytest.mark.asyncio
async def test_own_schedule_copy_does_not_fire_in_run_backup_now(tmp_path, monkeypatch):
    hub, _, _ = _make_hub(tmp_path, global_config=_cfg_with_ssh(
        copy_mode="own_schedule"))
    copied = {"n": 0}

    async def fake_copy(local_file=None):
        copied["n"] += 1
        return {"status": "ok"}

    monkeypatch.setattr(hub, "_sb_run_copy", fake_copy)
    res = await hub.run_backup_now()
    assert res["status"] == "ok"
    # own_schedule copy is driven by the loop, NOT run_backup_now.
    assert copied["n"] == 0
    assert "copy" not in res


@pytest.mark.asyncio
async def test_copy_disabled_does_not_fire(tmp_path, monkeypatch):
    hub, _, _ = _make_hub(tmp_path, global_config=_cfg_with_ssh(copy_enabled=False))
    copied = {"n": 0}

    async def fake_copy(local_file=None):
        copied["n"] += 1
        return {"status": "ok"}

    monkeypatch.setattr(hub, "_sb_run_copy", fake_copy)
    await hub.run_backup_now()
    assert copied["n"] == 0


# ── status snapshot ────────────────────────────────────────────────────────

def test_get_self_backup_status_lists_archives_and_hides_keymaterial(tmp_path):
    hub, _, _ = _make_hub(tmp_path, global_config=_cfg_with_ssh())
    root = os.path.join(hub.state.data_dir, "self-backup")
    os.makedirs(root, exist_ok=True)
    with open(os.path.join(root, "a.tar.gz"), "wb") as f:
        f.write(b"aa")
    with open(os.path.join(root, "b.tgz.enc"), "wb") as f:
        f.write(b"bb")
    os.utime(os.path.join(root, "a.tar.gz"), (100, 100))
    os.utime(os.path.join(root, "b.tgz.enc"), (200, 200))
    status = hub.get_self_backup_status()
    assert status["backup_count"] == 2
    assert status["total_bytes"] == 4
    # Newest first (b mtime=200).
    assert status["backups"][0]["name"] == "b.tgz.enc"
    assert status["ssh_keyfile"] == "/root/.ssh/lm_id"  # path only — no key material
    assert "last_backup_at" in status and "last_copy_at" in status


# ── 7. admin route gate ────────────────────────────────────────────────────

class _RouteHub:
    """Minimal hub for the route module: records calls + canned replies."""
    def __init__(self):
        self.run_calls = 0
        self.test_calls = 0

    async def run_backup_now(self):
        self.run_calls += 1
        return {"status": "ok", "name": "x.tar.gz", "size": 1,
                "pruned": 0, "ts": "t", "encrypted": False}

    async def test_self_backup_copy(self):
        self.test_calls += 1
        return {"status": "ok", "file": "x.tar.gz"}

    def get_self_backup_status(self):
        return {"enabled": False, "backup_count": 0, "backups": []}


def _build_app(is_admin):
    from types import SimpleNamespace
    from routes import self_backup as rb_routes
    app = FastAPI()
    hub = _RouteHub()
    sess = {"user": "admin"} if is_admin else {"user": "plain"}
    ctx = SimpleNamespace(
        _session_user=lambda request: sess,
        _is_admin=lambda s: is_admin,
    )
    rb_routes.register(app, hub, ctx)
    return TestClient(app), hub


def test_backup_status_route_admits_admin():
    c, hub = _build_app(is_admin=True)
    r = c.get("/setup/backup/status")
    assert r.status_code == 200
    assert r.json()["backup_count"] == 0


def test_backup_status_route_403_for_non_admin():
    c, hub = _build_app(is_admin=False)
    r = c.get("/setup/backup/status")
    assert r.status_code == 403
    assert hub.run_calls == 0  # handler never reached the hub


def test_backup_run_route_admits_admin():
    c, hub = _build_app(is_admin=True)
    r = c.post("/setup/backup/run")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"
    assert hub.run_calls == 1


def test_backup_run_route_403_for_non_admin():
    c, hub = _build_app(is_admin=False)
    r = c.post("/setup/backup/run")
    assert r.status_code == 403
    assert hub.run_calls == 0


def test_backup_test_copy_route_403_for_non_admin():
    c, hub = _build_app(is_admin=False)
    r = c.post("/setup/backup/test-copy")
    assert r.status_code == 403
    assert hub.test_calls == 0


def test_backup_test_copy_route_admits_admin():
    c, hub = _build_app(is_admin=True)
    r = c.post("/setup/backup/test-copy")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"
    assert hub.test_calls == 1