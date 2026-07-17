"""Phase 1: device-mode node agent mints, persists, and sends a stable guid.

SpokeClient now derives its identity from a per-install guid (next to the agent
secret), not its observable agent_id/hostname — so a process restart reuses the
SAME guid and the hub can address it by guid. Verifies mint + persist + reuse +
handshake carries the guid + the legacy ""-on-write-failure fail-safe path.
"""
import os
import uuid

import spoke_client
from spoke_client import SpokeClient


def _client(tmp_path, secret="s", iu_path=None):
    return SpokeClient(
        "node-1", "wss://spoke:443", secret=secret,
        secret_path=str(tmp_path / "secret"),
        install_uuid_path=str(iu_path or (tmp_path / "install-uuid")),
    )


def test_mints_and_persists_install_uuid(tmp_path):
    c = _client(tmp_path)
    assert c.install_uuid and uuid.UUID(c.install_uuid)        # minted a guid
    persisted = (tmp_path / "install-uuid").read_text().strip()
    assert persisted == c.install_uuid                          # written to disk
    mode = os.stat(tmp_path / "install-uuid").st_mode & 0o777
    assert mode == 0o600                                        # locked down


def test_reuses_persisted_guid_across_restarts(tmp_path):
    c1 = _client(tmp_path)
    # A second client on the same path (a process restart) reuses the SAME guid.
    c2 = _client(tmp_path, secret="s2")
    assert c2.install_uuid == c1.install_uuid
    assert uuid.UUID(c2.install_uuid) == uuid.UUID(c1.install_uuid)


def test_handshake_carries_install_uuid(tmp_path):
    c = _client(tmp_path)
    hs = c._build_handshake()
    assert hs["agent_id"] == "node-1"
    assert hs["install_uuid"] == c.install_uuid
    assert hs["secret"] == "s"                                  # secret still sent


def test_handshake_omits_install_uuid_when_unwritable(tmp_path):
    """Legacy fail-safe: if the guid can't be persisted, self.install_uuid is ""
    and the handshake omits it (hub treats it as spoke_id-keyed, no per-boot flip)."""
    # Point install_uuid at a path whose parent doesn't exist → write fails → "".
    bad = tmp_path / "nope" / "deep" / "install-uuid"
    c = _client(tmp_path, iu_path=bad)
    assert c.install_uuid == ""
    assert "install_uuid" not in c._build_handshake()
