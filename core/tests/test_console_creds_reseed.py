"""LabManagerHub._forget_console_creds_seed — the console credential re-seed
guard.

A console spoke keeps its auto-login credential list in memory only, so a
restart wipes it. The hub tracks which spokes it has already seeded
(``_console_creds_seeded``) and would otherwise never re-push CONSOLE_SET_
CREDENTIALS to a reconnected process, leaving auto-identify to try only the
factory-default creds and report "auth rejected" for devices whose real
(operator-saved) creds are correct. On every fresh connection install the hub
must forget the seed marker so the next console API touch re-seeds the creds.
"""
from main import LabManagerHub


class _SeedHub:
    """Minimal fake exposing just what _forget_console_creds_seed touches."""

    def __init__(self, seeded, primary=None):
        self._console_creds_seeded = seeded
        self._primary = primary or {}

    def _primary_key(self, sid):
        return self._primary.get(sid, sid)


def test_forget_removes_spoke_so_it_reseeds_on_reconnect():
    seeded = {"lm-agent-console", "other-console"}
    hub = _SeedHub(seeded)
    LabManagerHub._forget_console_creds_seed(hub, "lm-agent-console")
    assert "lm-agent-console" not in seeded  # will be re-pushed on next touch
    assert "other-console" in seeded          # unrelated spoke untouched


def test_forget_also_drops_primary_key_alias():
    # A sub-spoke whose seed marker was stored under its primary key must also
    # be forgotten, so aliasing can't leave a stale marker behind.
    seeded = {"lm-agent"}
    hub = _SeedHub(seeded, primary={"lm-agent-console": "lm-agent"})
    LabManagerHub._forget_console_creds_seed(hub, "lm-agent-console")
    assert seeded == set()


def test_forget_is_noop_when_seeding_never_used():
    class _Bare:
        def _primary_key(self, sid):
            return sid
    # No _console_creds_seeded attribute at all — must not raise.
    LabManagerHub._forget_console_creds_seed(_Bare(), "lm-agent-console")


def test_forget_is_noop_for_unseeded_spoke():
    seeded = {"lm-agent-console"}
    hub = _SeedHub(seeded)
    LabManagerHub._forget_console_creds_seed(hub, "never-seeded")
    assert seeded == {"lm-agent-console"}
