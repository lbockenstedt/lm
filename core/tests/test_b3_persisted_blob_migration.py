"""Feature B3: persisted-blob guid migration — mailbox + simulations_cache +
``spoke_last_seen`` re-keyed name→guid, on arm AND as a one-shot boot migration.

B1/B2 lazy-arm the in-memory + persisted state each spoke/agent reconnect. The
two persisted blobs that are guid-keyed at READ sites (``simulations_cache`` —
the Simulations API resolves via ``_primary_key``; mailbox ``spoke_queues`` /
``pending_ack`` — ``clear_spoke`` / ``flush_mailbox`` resolve via ``_primary_key``)
were written RAW in the pre-guid era, so an OFFLINE spoke stays RAW-keyed until
it reconnects + arms. B3 closes that gap two ways:

* ``_arm_guid_primary`` now also re-keys mailbox (sync ``rename_spoke_inplace``)
  + ``simulations_cache`` in-memory on connect (so the running hub sees guid
  keys immediately; persistence is eventual + backstopped by the boot migration).
* ``_migrate_persisted_blobs_to_guid`` is a one-shot boot migration that folds
  OFFLINE spokes' persisted blob entries RAW→guid pivoting on
  ``module_metadata.install_uuid`` — sentinel-guarded, idempotent.

Covers the arm-side mailbox/sim_cache re-key, the boot migration re-key +
sentinel + idempotency + skip-when-guid-equals-name, and the sync
``rename_spoke_inplace`` core directly.
"""
import asyncio
import os
import sys
from collections import deque

_LM_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _LM_ROOT not in sys.path:
    sys.path.insert(0, _LM_ROOT)

import main  # noqa: E402
from messaging.mailbox import Mailbox  # noqa: E402
from messaging.protocol import Message, MessageHeader, MessagePayload  # noqa: E402
from security.key_manager import KeyManager, ManagedKey  # noqa: E402
from state.manager import StateManager  # noqa: E402


def _key(kid, secret):
    return ManagedKey(key_id=kid, secret=secret, created_at=0.0,
                      expires_at=9999999999.0)


def _make_km():
    km = KeyManager("keys_b3.json", "hub_secret_b3.json")
    km.storage_path = os.path.join("/tmp", "lm_keys_b3.json")
    km.hub_secret_path = os.path.join("/tmp", "lm_hub_secret_b3.json")
    for name in ("keys_b3.json", "hub_secret_b3.json"):
        try:
            os.remove(os.path.join(os.path.dirname(__file__), "..", "data", name))
        except OSError:
            pass
    return km


def _msg(dest, mid):
    return Message(header=MessageHeader(message_id=mid, destination_id=dest),
                   payload=MessagePayload(type="COMMAND", data={}))


class _Heartbeat:
    def __init__(self):
        self.last_seen = {}


class _B3Hub:
    """_ArmHub + a real Mailbox + simulations_cache + _sim_cache_dirty so the
    B3 arm/boot-migration code paths (which touch mailbox + sim_cache) run."""

    # Mirrors the LabManagerHub class attr referenced inside the migration.
    _GUID_BLOB_MIGRATION_SENTINEL = main.LabManagerHub._GUID_BLOB_MIGRATION_SENTINEL

    def __init__(self, state, km, tmp_path):
        self.state = state
        self.key_manager = km
        self.install_uuid_index = {}
        self.spoke_id_alias = {}
        self.heartbeat = _Heartbeat()
        self.spoke_event_limit = 100
        self.spoke_events = {}
        self.spoke_module_types = {}
        self.spoke_versions = {}
        self.spoke_telemetry = {}
        self.spoke_recovery = {}
        self.rate_limiters = {}
        self.active_connections = {}
        self.active_connection_key_ids = {}
        self.agent_logs = {}
        self.agent_info = {}
        # B3 additions.
        self.mailbox = Mailbox(state_dir=str(tmp_path))
        self.simulations_cache = {}
        self._sim_cache_dirty = False

    def record_spoke_event(self, spoke_id, event, detail=""):
        if not spoke_id:
            return
        buf = self.spoke_events.setdefault(spoke_id, deque(maxlen=self.spoke_event_limit))
        buf.append({"ts": 0.0, "event": event, "detail": detail})

    def get_spoke_events(self, spoke_id, limit=50):
        buf = self.spoke_events.get(spoke_id)
        return list(reversed(list(buf)[-limit:])) if buf else []

    def _primary_key(self, spoke_id):
        return main.LabManagerHub._primary_key(self, spoke_id)

    def _migrate_spoke_identity(self, old_id, new_id, **kw):
        return main.LabManagerHub._migrate_spoke_identity(self, old_id, new_id, **kw)

    def _arm_guid_primary(self, spoke_id, install_uuid):
        return main.LabManagerHub._arm_guid_primary(self, spoke_id, install_uuid)

    def _migrate_persisted_blobs_to_guid(self):
        return main.LabManagerHub._migrate_persisted_blobs_to_guid(self)


def _fresh_state(tmp_path):
    s = StateManager()
    s.system_path = str(tmp_path / "system.json")
    s.tenants_path = str(tmp_path / "tenants.json")
    s.system_state = {
        "approved_modules": {}, "known_modules": [], "module_names": {},
        "module_metadata": {}, "agent_config": {}, "agent_display_names": {},
        "spoke_last_seen": {},
    }
    return s


def _seed_known_spoke(state, hub, sid, guid, hostname="h"):
    state.system_state["known_modules"].append(sid)
    state.update_module_metadata(sid, {"install_uuid": guid, "hostname": hostname})
    hub.install_uuid_index[guid] = sid


# ── arm re-keys mailbox + simulations_cache in-memory ────────────────────────

def test_arm_rekeys_mailbox_queue_and_sim_cache_inmemory(tmp_path):
    state = _fresh_state(tmp_path)
    km = _make_km()
    km.keys["spoke-A"] = _key("k1", "s")
    hub = _B3Hub(state, km, tmp_path)
    _seed_known_spoke(state, hub, "spoke-A", "GUID-1")
    # RAW-keyed mailbox queue + simulations_cache (the pre-guid state).
    asyncio.run(hub.mailbox.queue_for_spoke("spoke-A", _msg("spoke-A", "m1")))
    hub.simulations_cache["spoke-A"] = {"clients": [1, 2, 3]}

    hub._arm_guid_primary("spoke-A", "GUID-1")

    # Mailbox queue moved name→guid; queued message destination repointed.
    assert "spoke-A" not in hub.mailbox.spoke_queues
    assert "GUID-1" in hub.mailbox.spoke_queues
    assert hub.mailbox.spoke_queues["GUID-1"][0].header.destination_id == "GUID-1"
    # Simulations cache moved name→guid.
    assert "spoke-A" not in hub.simulations_cache
    assert hub.simulations_cache.get("GUID-1") == {"clients": [1, 2, 3]}
    # Alias armed + spoke_last_seen re-keyed (B1) still hold.
    assert hub.spoke_id_alias["spoke-A"] == "GUID-1"


def test_arm_noop_on_mailbox_when_no_queue(tmp_path):
    """An arm with no queued messages / no sim_cache entry is a clean no-op
    (rename_spoke_inplace returns False; sim_cache guard skips)."""
    state = _fresh_state(tmp_path)
    hub = _B3Hub(state, _make_km(), tmp_path)
    _seed_known_spoke(state, hub, "spoke-A", "GUID-1")
    hub._arm_guid_primary("spoke-A", "GUID-1")
    assert hub.mailbox.spoke_queues == {}
    assert hub.simulations_cache == {}


# ── one-shot boot migration ───────────────────────────────────────────────────

def test_boot_migration_rekeys_blobs_and_sets_sentinel(tmp_path):
    state = _fresh_state(tmp_path)
    km = _make_km()
    hub = _B3Hub(state, km, tmp_path)
    # OFFLINE spokes, RAW-keyed across all three blobs; module_metadata carries
    # the guid as a value (the boot pivot).
    state.system_state["module_metadata"]["spoke-A"] = {"install_uuid": "GUID-1",
                                                         "hostname": "hA"}
    state.system_state["module_metadata"]["spoke-B"] = {"install_uuid": "GUID-2",
                                                         "hostname": "hB"}
    hub.simulations_cache["spoke-A"] = {"clients": ["a"]}
    hub.simulations_cache["spoke-B"] = {"clients": ["b"]}
    asyncio.run(hub.mailbox.queue_for_spoke("spoke-A", _msg("spoke-A", "m1")))
    state.system_state["spoke_last_seen"] = {"spoke-A": 100.0, "spoke-B": 200.0}

    hub._migrate_persisted_blobs_to_guid()

    # All three blobs re-keyed name→guid.
    assert "spoke-A" not in hub.simulations_cache and hub.simulations_cache.get("GUID-1") == {"clients": ["a"]}
    assert "spoke-B" not in hub.simulations_cache and hub.simulations_cache.get("GUID-2") == {"clients": ["b"]}
    assert "spoke-A" not in hub.mailbox.spoke_queues and "GUID-1" in hub.mailbox.spoke_queues
    assert hub.mailbox.spoke_queues["GUID-1"][0].header.destination_id == "GUID-1"
    assert state.system_state["spoke_last_seen"] == {"GUID-1": 100.0, "GUID-2": 200.0}
    # Sentinel set (persists via state._mark_dirty).
    assert state.system_state.get(main.LabManagerHub._GUID_BLOB_MIGRATION_SENTINEL) is True


def test_boot_migration_idempotent_after_sentinel(tmp_path):
    """Once the sentinel is set, a second boot migration is a no-op even if
    fresh RAW keys somehow appeared (the sentinel short-circuits)."""
    state = _fresh_state(tmp_path)
    hub = _B3Hub(state, _make_km(), tmp_path)
    state.system_state["module_metadata"]["spoke-A"] = {"install_uuid": "GUID-1"}
    state.system_state[main.LabManagerHub._GUID_BLOB_MIGRATION_SENTINEL] = True
    hub.simulations_cache["spoke-A"] = {"clients": ["a"]}  # would re-key if not guarded

    hub._migrate_persisted_blobs_to_guid()

    # Sentinel short-circuited → RAW key left in place (untouched).
    assert "spoke-A" in hub.simulations_cache
    assert "GUID-1" not in hub.simulations_cache


def test_boot_migration_re_running_without_sentinel_is_idempotent(tmp_path):
    """Even without the sentinel, the migration is idempotent: re-running after
    the first pass finds no RAW keys (they're guid now) → no-op. (A crash before
    the sentinel persisted just re-runs safely.)"""
    state = _fresh_state(tmp_path)
    hub = _B3Hub(state, _make_km(), tmp_path)
    state.system_state["module_metadata"]["spoke-A"] = {"install_uuid": "GUID-1"}
    hub.simulations_cache["spoke-A"] = {"clients": ["a"]}

    hub._migrate_persisted_blobs_to_guid()
    # Clear the sentinel to simulate "lost before persist"; re-run.
    state.system_state.pop(main.LabManagerHub._GUID_BLOB_MIGRATION_SENTINEL, None)
    hub._migrate_persisted_blobs_to_guid()

    # Still guid-keyed (the second pass found no RAW key to move).
    assert hub.simulations_cache.get("GUID-1") == {"clients": ["a"]}
    assert "spoke-A" not in hub.simulations_cache


def test_boot_migration_skips_when_guid_equals_name(tmp_path):
    """A spoke already keyed by its guid (guid == raw name) has nothing to move."""
    state = _fresh_state(tmp_path)
    hub = _B3Hub(state, _make_km(), tmp_path)
    state.system_state["module_metadata"]["GUID-1"] = {"install_uuid": "GUID-1"}
    hub.simulations_cache["GUID-1"] = {"clients": ["a"]}

    hub._migrate_persisted_blobs_to_guid()

    assert hub.simulations_cache.get("GUID-1") == {"clients": ["a"]}


def test_boot_migration_skips_spokes_with_no_install_uuid(tmp_path):
    """A spoke with no install_uuid in metadata (never connected / pre-guid)
    is skipped — it'll arm lazily on first connect."""
    state = _fresh_state(tmp_path)
    hub = _B3Hub(state, _make_km(), tmp_path)
    state.system_state["module_metadata"]["fresh-spoke"] = {"hostname": "h"}
    hub.simulations_cache["fresh-spoke"] = {"clients": ["a"]}

    hub._migrate_persisted_blobs_to_guid()

    assert hub.simulations_cache.get("fresh-spoke") == {"clients": ["a"]}
    assert "GUID-fresh" not in hub.simulations_cache


# ── rename_spoke_inplace (sync core) directly ─────────────────────────────────

def test_rename_spoke_inplace_sync_rekeys_queue_and_dests(tmp_path):
    mb = Mailbox(state_dir=str(tmp_path))
    asyncio.run(mb.queue_for_spoke("old", _msg("old", "m1")))
    mb._last_ack_ts["old"] = 1234.0
    mb.pending_ack["m1"] = (_msg("old", "m1"), 100.0, 0)

    moved = mb.rename_spoke_inplace("old", "new")

    assert moved is True
    assert "old" not in mb.spoke_queues and "new" in mb.spoke_queues
    assert mb.spoke_queues["new"][0].header.destination_id == "new"
    assert mb._last_ack_ts.get("new") == 1234.0 and "old" not in mb._last_ack_ts
    assert mb.pending_ack["m1"][0].header.destination_id == "new"


def test_rename_spoke_inplace_idempotent_noop(tmp_path):
    mb = Mailbox(state_dir=str(tmp_path))
    assert mb.rename_spoke_inplace("x", "x") is False      # old == new
    assert mb.rename_spoke_inplace("ghost", "g2") is False  # no state
    assert mb.spoke_queues == {} and mb._last_ack_ts == {}