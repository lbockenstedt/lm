"""Purging the extension source must leave nothing behind.

Clearing the stored credential alone leaves the fetched module sitting in the
extension directory, where it is imported and registered on every app build. An
operator who has revoked a credential reasonably believes the code is gone, and
the distance between "revoked" and "removed" is exactly where a private sensor
module would keep running after the decision to stop shipping it as source.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


class _State:
    def __init__(self, tmpdir, cfg):
        self.data_dir = str(tmpdir)
        self.system_state = {"global_config": {"site_ext": cfg}}
        self.saved = False

    def get_global_config(self):
        return self.system_state["global_config"]

    def update_global_config(self, patch):
        self.system_state["global_config"].update(patch)

    async def save_state_now(self):
        self.saved = True


class _Hub:
    def __init__(self, state):
        self.state = state


def _purge_handler(hub):
    """Build the route table and hand back the purge handler.

    The routes register onto a FastAPI app via ``register(app, hub, ctx)``; the
    handler is pulled straight off the app so the test exercises the real one.
    """
    from fastapi import FastAPI
    import routes.security as security

    app = FastAPI()

    class _Ctx:
        @staticmethod
        def _session_user(request):
            return {"username": "admin"}

        @staticmethod
        def _is_admin(sess):
            return True

    security.register(app, hub, _Ctx())
    for route in app.routes:
        if getattr(route, "path", "") == "/api/security/ext-source/purge":
            return route.endpoint
    raise AssertionError("purge route was not registered")


@pytest.mark.asyncio
async def test_purge_removes_the_checkout_not_just_the_python_files(tmp_path):
    """A leftover .git is a working checkout with an upstream: it still holds
    the content in its object store, and a later provisioning run would
    fast-forward it straight back."""
    ext = tmp_path / "site_ext"
    (ext / ".git").mkdir(parents=True)
    (ext / ".git" / "config").write_text("[remote \"origin\"]\n")
    (ext / "ext_tripwire.py").write_text("# module\n")

    hub = _Hub(_State(tmp_path, {"enabled": True,
                                 "repo": "https://github.com/lbockenstedt/tm.git",
                                 "token": "ghp_secret"}))
    out = await _purge_handler(hub)(request=None)

    assert out["status"] == "ok"
    assert out["token_removed"] is True
    assert out["dir_removed"] is True
    assert not ext.exists(), "the whole checkout must go, .git included"


@pytest.mark.asyncio
async def test_purge_uses_the_configured_dir_before_clearing_it(tmp_path):
    """``ext_dir()`` honours a ``dir`` override that lives in the very config
    being wiped. Clearing first would delete the pointer and then remove the
    default location instead of the one actually in use — reporting success
    while leaving the module on disk."""
    custom = tmp_path / "somewhere-else"
    custom.mkdir()
    (custom / "ext_tripwire.py").write_text("# module\n")
    default = tmp_path / "site_ext"
    default.mkdir()
    (default / "keep.py").write_text("# unrelated\n")

    hub = _Hub(_State(tmp_path, {"enabled": True, "dir": str(custom),
                                 "repo": "https://example.invalid/x.git"}))
    out = await _purge_handler(hub)(request=None)

    assert out["dir"] == str(custom)
    assert not custom.exists()
    assert default.exists(), "the default dir was not the configured one"


@pytest.mark.asyncio
async def test_purge_disables_the_source_and_persists_immediately(tmp_path):
    """Leaving it enabled means the next sync re-provisions what was just
    deleted. Persisting immediately matters because the decision to stop
    shipping code must survive a crash that follows it."""
    hub = _Hub(_State(tmp_path, {"enabled": True, "token": "ghp_secret",
                                 "repo": "https://github.com/lbockenstedt/tm.git"}))
    out = await _purge_handler(hub)(request=None)

    cfg = hub.state.get_global_config()["site_ext"]
    assert cfg.get("enabled") is False
    assert not cfg.get("token")
    assert not cfg.get("repo")
    assert hub.state.saved is True
    # Modules are imported at app build, so what is already loaded keeps
    # serving until the process restarts. Claiming otherwise would tell an
    # operator the code is gone while it is still running.
    assert out["restart_required"] is True


@pytest.mark.asyncio
async def test_purge_is_safe_when_nothing_was_ever_provisioned(tmp_path):
    """A fresh install must be able to run this without an error."""
    hub = _Hub(_State(tmp_path, {}))
    out = await _purge_handler(hub)(request=None)
    assert out["status"] == "ok"
    assert out["token_removed"] is False
    assert out["dir_removed"] is False
