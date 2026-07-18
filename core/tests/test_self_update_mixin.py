"""Feature (b): the git self-update + rollback machinery (_run_git,
_snapshot_for_update, _is_known_bad_commit, _clear_pending_update,
_core_update_lock, _prepare_restart_with_watchdog, _perform_self_update_sync,
the recovery state dir + healthy markers, _prepare_service_restart,
_ensure_git_pull_strategy) now lives on a shared ``SelfUpdateMixin``
(``core/src/messaging/self_update.py``) consumed by BOTH ``BaseControlPlane``
(every spoke + the hub-hosting generic agent) and the device-mode ``SpokeClient``
(the dumb agent, NOT a ``BaseControlPlane`` subclass) — the sibling of the
``CodeDriftWatchdogMixin`` extraction (feature (c)).

Pins: both consumers get the 12 helpers FROM the mixin (single source of truth,
not a private copy); each consumer keeps its own per-layout hooks
(``_repo_root`` / ``_resolve_core_root`` / ``get_service_name`` /
``_flush_log_relay_sync``); and ``_spoke_state_dir`` keys the per-component
recovery dir off ``spoke_id`` (a spoke) OR ``agent_id`` (a device-mode agent) so
the agent gets its own ``/var/lib/lm/<agent_id>`` state dir without a ``spoke_id``.
"""
import os
import sys

_LM_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _LM_ROOT not in sys.path:
    sys.path.insert(0, _LM_ROOT)

from messaging.self_update import SelfUpdateMixin  # noqa: E402
from messaging.control_plane import BaseControlPlane  # noqa: E402


_HELPERS = (
    "_ensure_git_pull_strategy",
    "_run_git",
    "_prepare_service_restart",
    "_spoke_state_dir",
    "_clear_healthy_marker",
    "_touch_healthy_marker",
    "_snapshot_for_update",
    "_is_known_bad_commit",
    "_clear_pending_update",
    "_core_update_lock",
    "_prepare_restart_with_watchdog",
    "_perform_self_update_sync",
)


def test_mixin_holds_all_helpers():
    """The 12 helpers live on the mixin itself."""
    for m in _HELPERS:
        assert m in SelfUpdateMixin.__dict__, f"{m} missing from SelfUpdateMixin"


def test_base_control_plane_resolves_helpers_via_mixin():
    """BaseControlPlane no longer DEFINES the helpers — it inherits them from
    the mixin (MRO), so behavior is unchanged for every spoke + the hub-hosting
    generic agent."""
    for m in _HELPERS:
        assert m not in BaseControlPlane.__dict__, (
            f"{m} still defined on BaseControlPlane (should come from mixin)")
        assert getattr(BaseControlPlane, m) is getattr(SelfUpdateMixin, m), (
            f"{m} not resolved via SelfUpdateMixin")


class _DeviceConsumer(SelfUpdateMixin):
    """Mirrors the device-mode SpokeClient shape: NO ``spoke_id`` (it has
    ``agent_id`` instead), provides the per-layout hooks the mixin calls."""

    def __init__(self, agent_id, repo):
        self.agent_id = agent_id
        self._repo = repo
        self._draining = False
        self._spoke_update_in_progress = False

    def _repo_root(self):
        return self._repo

    def _resolve_core_root(self):
        return None

    def get_service_name(self):
        return "lm-agent"

    def _flush_log_relay_sync(self, timeout=2.0):
        pass


def test_device_consumer_resolves_helpers_via_mixin():
    """The device-mode consumer gets the 12 helpers from the mixin too (does NOT
    re-define them), and provides its OWN hooks (``_repo_root`` etc.)."""
    c = _DeviceConsumer("dev-1", "/tmp/repo")
    for m in _HELPERS:
        assert m not in type(c).__dict__, f"{m} re-defined by device consumer"
        assert getattr(type(c), m) is getattr(SelfUpdateMixin, m), (
            f"{m} not resolved via SelfUpdateMixin for device consumer")
    # hooks the mixin calls are provided by the consumer, not the mixin.
    for hook in ("_repo_root", "_resolve_core_root", "get_service_name",
                "_flush_log_relay_sync"):
        assert hook in type(c).__dict__, f"{hook} not provided by device consumer"


def test_state_dir_keys_off_spoke_id_when_present(tmp_path, monkeypatch):
    """A consumer with ``spoke_id`` (a spoke) keys the recovery dir off it."""
    class _Spoke(SelfUpdateMixin):
        def __init__(self, sid, repo):
            self.spoke_id = sid
            self._repo = repo
        def _repo_root(self):
            return self._repo

    made = []
    monkeypatch.setattr("messaging.self_update.os.makedirs",
                        lambda p, exist_ok=False: made.append(str(p)))
    c = _Spoke("pxmx-1", str(tmp_path))
    c._spoke_state_dir()
    # primary path attempted with the spoke_id (the probe open() then fails →
    # fallback, but the PRIMARY makedirs call records the sid).
    assert any("pxmx-1" in p for p in made), f"spoke_id not used: {made}"


def test_state_dir_falls_back_to_agent_id_without_spoke_id(tmp_path, monkeypatch):
    """A device-mode consumer with ``agent_id`` (no ``spoke_id``) keys the
    recovery dir off ``agent_id`` — the whole point of the fallback so the agent
    gets its own /var/lib/lm/<agent_id> dir."""
    monkeypatch.setattr("messaging.self_update.os.makedirs",
                        lambda p, exist_ok=False: None)
    c = _DeviceConsumer("dev-99", str(tmp_path))
    d = c._spoke_state_dir()
    # agent_id appears in the chosen dir (primary or repo-local fallback).
    assert "dev-99" in d, f"agent_id not used in state dir: {d}"


def test_state_dir_uses_component_sentinel_when_neither_id_present(tmp_path, monkeypatch):
    """A consumer exposing neither id degrades to the ``component`` sentinel
    rather than crashing — defensive."""
    monkeypatch.setattr("messaging.self_update.os.makedirs",
                        lambda p, exist_ok=False: None)
    class _Bare(SelfUpdateMixin):
        def _repo_root(self):
            return str(tmp_path)
    d = _Bare()._spoke_state_dir()
    assert "component" in d, f"sentinel not used: {d}"