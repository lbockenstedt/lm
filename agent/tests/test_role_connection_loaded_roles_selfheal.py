"""``RoleConnection`` self-heals the durable ``LOADED_ROLES`` set.

A runtime-loaded role (e.g. console) persists into ``.env`` as ``LOADED_ROLES``
so the agent re-spawns it on the next self-update restart. If that entry is ever
lost at runtime (a lost cross-process ``.env`` upsert, a manual edit), the role
would strand "out of contact" until a human re-loads it — the recurring
console-vanished outage. Whenever a RoleConnection persists a NON-EMPTY session
secret (i.e. it is live + authenticated), it re-adds its own role to
LOADED_ROLES so the next boot re-adopts it.
"""
import os

import control_plane as cp_module


class _FakeRoleInstance:
    def __init__(self, spoke_id, config):
        self.spoke_id = spoke_id
        self.config = config


def _conn(role, tmp_path):
    conn = cp_module.RoleConnection(
        role, base_id="agent-1", hub_url="ws://hub:8765",
        role_instance=_FakeRoleInstance("agent-1-" + role, {}))
    # Redirect .env to an isolated temp dir for the persist assertions.
    conn._repo_root = lambda: str(tmp_path)  # type: ignore[method-assign]
    return conn


def _loaded_roles(tmp_path):
    path = os.path.join(str(tmp_path), ".env")
    if not os.path.exists(path):
        return None
    with open(path) as f:
        for line in f:
            if line.startswith("LOADED_ROLES="):
                return line.partition("=")[2].strip()
    return None


def test_nonempty_secret_selfheals_loaded_roles(tmp_path):
    conn = _conn("console", tmp_path)
    conn._persist_session_secret("live-key")
    assert _loaded_roles(tmp_path) == "console"
    # The per-role secret is also persisted under its own key (unchanged).
    with open(os.path.join(str(tmp_path), ".env")) as f:
        body = f.read()
    assert "SPOKE_SECRET_CONSOLE=live-key" in body


def test_selfheal_unions_without_dropping_other_roles(tmp_path):
    # A pre-existing LOADED_ROLES with a different role must be preserved.
    with open(os.path.join(str(tmp_path), ".env"), "w") as f:
        f.write("LOADED_ROLES=dns\nSPOKE_SECRET=base\n")
    conn = _conn("console", tmp_path)
    conn._persist_session_secret("live-key")
    roles = set((_loaded_roles(tmp_path) or "").split(","))
    assert roles == {"console", "dns"}


def test_empty_secret_does_not_selfheal(tmp_path):
    # The 1008-fallback blanks the secret; it must NOT re-add the role (that
    # path is also how an unload leaves .env — don't resurrect it).
    conn = _conn("console", tmp_path)
    conn._persist_session_secret("")
    assert _loaded_roles(tmp_path) is None


def test_selfheal_is_idempotent(tmp_path):
    conn = _conn("console", tmp_path)
    conn._persist_session_secret("k1")
    conn._persist_session_secret("k2")
    assert _loaded_roles(tmp_path) == "console"
