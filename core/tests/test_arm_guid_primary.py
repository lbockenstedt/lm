"""Feature B1: ``_arm_guid_primary`` — spoke-side guid-primary arming.

The seam: ``spoke_id_alias[connect_id] = install_uuid`` so ``_primary_key(name)``
resolves to the guid, and the spoke's hub-side state (approval / tenant binding /
keys / telemetry / events / offline contact metadata) is re-keyed name→guid.
The spoke still CONNECTS by its operator-chosen name (the auth-frame id); the
guid is the hub-internal primary key. This is a silent key relocation, NOT a
rename — same box, same install_uuid — so no ``identity_changed`` event fires
and no CC2 secret re-proof is required.

Covers:

* arm re-keys persisted state (approved_modules / known_modules / module_names /
  module_metadata w/ tenant_id preserved) name→guid;
* arm re-keys in-memory mirrors + KeyManager keys + spoke_last_seen;
* arm is idempotent (already-armed → no-op; armed to a different guid → left
  untouched);
* arm does NOT touch agent composites (agent_config / agent_info / agent_logs /
  the ``{spoke}:{agent}`` heartbeat composite) — that is B2;
* the no-reversal invariant: a 2nd connect by name does NOT ping-pong state
  guid↔name (reconcile compares old_id against ``_primary_key(new_id)`` = guid,
  so old_id == new_pk → no migration);
* the CC2 guard: an unproven rename (``migrate_if=False``) does NOT arm.
"""

import os
import sys
from collections import deque

# conftest puts core/src on sys.path so `main` / `security.*` / `state.*` import
# flat; control_plane's relative imports need the lm repo root too.
_LM_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _LM_ROOT not in sys.path:
    sys.path.insert(0, _LM_ROOT)

import main  # noqa: E402
from security.key_manager import KeyManager, ManagedKey  # noqa: E402
from state.manager import StateManager  # noqa: E402


# ── helpers ──────────────────────────────────────────────────────────────────

def _key(kid: str, secret: str) -> ManagedKey:
    return ManagedKey(key_id=kid, secret=secret, created_at=0.0,
                      expires_at=9999999999.0)


def _make_km():
    km = KeyManager("keys_arm_test.json", "hub_secret_arm_test.json")
    km.storage_path = os.path.join("/tmp", "lm_keys_arm_test.json")
    km.hub_secret_path = os.path.join("/tmp", "lm_hub_secret_arm_test.json")
    data_dir = os.path.join(os.path.dirname(__file__), "..", "data")
    for name in ("keys_arm_test.json", "hub_secret_arm_test.json"):
        try:
            os.remove(os.path.join(data_dir, name))
        except OSError:
            pass
    return km


class _Heartbeat:
    def __init__(self):
        self.last_seen = {}


class _ArmHub:
    """Minimal stand-in exposing exactly what _arm_guid_primary /
    _reconcile_spoke_identity / _migrate_spoke_identity touch.

    Uses a REAL StateManager (rename_module / update_module_metadata / save_state
    exercised, not reimplemented) + a REAL KeyManager (redirected storage) so the
    re-key is the production code path. ``spoke_id_alias`` is the B1 seam.
    """

    def __init__(self, state, km):
        self.state = state
        self.key_manager = km
        self.install_uuid_index = {}
        self.spoke_id_alias = {}                       # B1 seam
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

    def record_spoke_event(self, spoke_id, event, detail=""):
        if not spoke_id:
            return
        buf = self.spoke_events.setdefault(spoke_id, deque(maxlen=self.spoke_event_limit))
        buf.append({"ts": 0.0, "event": event, "detail": detail})

    def get_spoke_events(self, spoke_id, limit=50):
        buf = self.spoke_events.get(spoke_id)
        if not buf:
            return []
        out = list(buf)[-limit:]
        out.reverse()
        return out

    # Delegate the production helpers (they call each other via self, so the
    # fake forwards to the real unbound LabManagerHub methods with self = this).
    def _primary_key(self, spoke_id):
        return main.LabManagerHub._primary_key(self, spoke_id)

    def _migrate_spoke_identity(self, old_id, new_id, **kw):
        return main.LabManagerHub._migrate_spoke_identity(self, old_id, new_id, **kw)

    def _arm_guid_primary(self, spoke_id, install_uuid):
        return main.LabManagerHub._arm_guid_primary(self, spoke_id, install_uuid)


def _fresh_state(tmp_path):
    s = StateManager()
    s.system_path = str(tmp_path / "system.json")
    s.tenants_path = str(tmp_path / "tenants.json")
    s.system_state = {
        "approved_modules": {},
        "known_modules": [],
        "module_names": {},
        "module_metadata": {},
        "agent_config": {},
        "agent_display_names": {},
        "spoke_last_seen": {},
    }
    return s


def _events_of(hub, sid, kind):
    return [e for e in hub.get_spoke_events(sid) if e["event"] == kind]


def reconcile(hub, new_id, install_uuid, hostname, **kw):
    return main.LabManagerHub._reconcile_spoke_identity(hub, new_id, install_uuid,
                                                        hostname, **kw)


# ── arm re-keys persisted + in-memory state name→guid ─────────────────────────

def test_arm_rekeys_persisted_state_name_to_guid(tmp_path):
    state = _fresh_state(tmp_path)
    km = _make_km()
    km.keys["spoke-A"] = _key("k1", "the-secret")
    hub = _ArmHub(state, km)

    # Seed an approved, tenant-bound, named spoke.
    state.system_state["approved_modules"]["spoke-A"] = True
    state.system_state["known_modules"].append("spoke-A")
    state.system_state["module_names"]["spoke-A"] = "Display A"
    state.update_module_metadata("spoke-A", {"tenant_id": "tenant-A",
                                             "install_uuid": "GUID-1",
                                             "hostname": "hostA"})
    state.system_state["spoke_last_seen"]["spoke-A"] = 12345.0
    hub.install_uuid_index["GUID-1"] = "spoke-A"

    hub._arm_guid_primary("spoke-A", "GUID-1")

    # Alias armed.
    assert hub.spoke_id_alias["spoke-A"] == "GUID-1"
    assert hub._primary_key("spoke-A") == "GUID-1"
    # Persisted state re-keyed name→guid; tenant binding SURVIVES.
    assert state.system_state["approved_modules"].get("GUID-1") is True
    assert "spoke-A" not in state.system_state["approved_modules"]
    assert "GUID-1" in state.system_state["known_modules"]
    assert "spoke-A" not in state.system_state["known_modules"]
    assert state.system_state["module_names"].get("GUID-1") == "Display A"
    assert "spoke-A" not in state.system_state["module_names"]
    assert state.get_spoke_tenant("GUID-1") == "tenant-A"
    assert state.system_state["module_metadata"]["GUID-1"]["hostname"] == "hostA"
    # Install-UUID index repoints to the guid (the new primary key).
    assert hub.install_uuid_index["GUID-1"] == "GUID-1"
    # KeyManager re-keyed so the guid-keyed spoke authenticates seamlessly.
    assert km.get_valid_key("GUID-1", "the-secret") == "k1"
    assert km.get_valid_key("spoke-A", "the-secret") is None
    # spoke_last_seen re-keyed (offline contact metadata stays accurate).
    assert state.system_state["spoke_last_seen"].get("GUID-1") == 12345.0
    assert "spoke-A" not in state.system_state["spoke_last_seen"]


def test_arm_rekeys_in_memory_mirrors(tmp_path):
    state = _fresh_state(tmp_path)
    km = _make_km()
    hub = _ArmHub(state, km)
    state.system_state["known_modules"].append("spoke-A")
    state.update_module_metadata("spoke-A", {"install_uuid": "GUID-1", "hostname": "h"})
    # Seed in-memory mirrors under the name.
    hub.spoke_module_types["spoke-A"] = "firewall"
    hub.spoke_versions["spoke-A"] = "1.2.3"
    hub.spoke_telemetry["spoke-A"] = {"cpu": 5}
    hub.spoke_recovery["spoke-A"] = {"state": "ok"}
    hub.rate_limiters["spoke-A"] = object()
    hub.spoke_events["spoke-A"] = deque([{"ts": 0.0, "event": "x", "detail": ""}],
                                        maxlen=100)

    hub._arm_guid_primary("spoke-A", "GUID-1")

    assert hub.spoke_module_types == {"GUID-1": "firewall"}
    assert hub.spoke_versions == {"GUID-1": "1.2.3"}
    assert hub.spoke_telemetry == {"GUID-1": {"cpu": 5}}
    assert hub.spoke_recovery == {"GUID-1": {"state": "ok"}}
    assert "GUID-1" in hub.rate_limiters and "spoke-A" not in hub.rate_limiters
    assert "GUID-1" in hub.spoke_events and "spoke-A" not in hub.spoke_events


# ── idempotency ───────────────────────────────────────────────────────────────

def test_arm_idempotent_when_already_armed_to_same_guid(tmp_path):
    state = _fresh_state(tmp_path)
    km = _make_km()
    km.keys["spoke-A"] = _key("k1", "s")
    hub = _ArmHub(state, km)
    state.system_state["approved_modules"]["spoke-A"] = True
    state.system_state["known_modules"].append("spoke-A")
    state.update_module_metadata("spoke-A", {"install_uuid": "GUID-1", "hostname": "h"})

    hub._arm_guid_primary("spoke-A", "GUID-1")
    snapshot = dict(state.system_state["approved_modules"])
    # Second arm is a no-op.
    hub._arm_guid_primary("spoke-A", "GUID-1")
    assert state.system_state["approved_modules"] == snapshot
    assert hub.spoke_id_alias["spoke-A"] == "GUID-1"
    # No identity_changed event (silent relocation).
    assert _events_of(hub, "GUID-1", "identity_changed") == []


def test_arm_ignores_when_armed_to_a_different_guid(tmp_path):
    """A uuid is stable per-install; a mismatch is left untouched, not thrashed."""
    state = _fresh_state(tmp_path)
    km = _make_km()
    hub = _ArmHub(state, km)
    hub.spoke_id_alias["spoke-A"] = "GUID-ORIGINAL"
    state.system_state["known_modules"].append("spoke-A")
    state.update_module_metadata("spoke-A", {"install_uuid": "GUID-ORIGINAL", "hostname": "h"})

    hub._arm_guid_primary("spoke-A", "GUID-DIFFERENT")
    # Alias unchanged; no migration ran (state still name-keyed for the index).
    assert hub.spoke_id_alias["spoke-A"] == "GUID-ORIGINAL"


def test_arm_noop_when_install_uuid_equals_spoke_id(tmp_path):
    """A spoke whose guid IS its name has nothing to relocate."""
    state = _fresh_state(tmp_path)
    hub = _ArmHub(state, _make_km())
    hub._arm_guid_primary("spoke-A", "spoke-A")
    assert hub.spoke_id_alias == {}


def test_arm_noop_when_install_uuid_empty(tmp_path):
    state = _fresh_state(tmp_path)
    hub = _ArmHub(state, _make_km())
    hub._arm_guid_primary("spoke-A", "")
    assert hub.spoke_id_alias == {}


# ── does NOT touch agent composites (B2 territory) ────────────────────────────

def test_arm_does_not_rekey_agent_composites(tmp_path):
    """B1 arms the spoke only. agent_config / agent_info / agent_logs and the
    ``{spoke}:{agent}`` heartbeat composite stay name-keyed (B2 re-keys them)."""
    state = _fresh_state(tmp_path)
    km = _make_km()
    hub = _ArmHub(state, km)
    state.system_state["known_modules"].append("spoke-A")
    state.update_module_metadata("spoke-A", {"install_uuid": "GUID-1", "hostname": "h"})
    # Agent composites keyed by name + a composite heartbeat key.
    state.system_state["agent_config"]["node-agent"] = {"tenant_id": "tA"}
    hub.agent_info["node-agent"] = {"spoke_id": "spoke-A"}
    hub.agent_logs["node-agent"] = deque([{"ts": 0.0, "event": "boot"}], maxlen=100)
    hub.heartbeat.last_seen["spoke-A:node-agent"] = 999.0

    hub._arm_guid_primary("spoke-A", "GUID-1")

    # Agent composites untouched (still name-keyed).
    assert "node-agent" in state.system_state["agent_config"]
    assert hub.agent_info.get("node-agent", {}).get("spoke_id") == "spoke-A"
    assert "node-agent" in hub.agent_logs
    # Composite heartbeat key still name-form (B2 will relocate it).
    assert "spoke-A:node-agent" in hub.heartbeat.last_seen
    assert "GUID-1:node-agent" not in hub.heartbeat.last_seen


# ── the no-reversal invariant: 2nd connect by name does NOT ping-pong ─────────

def test_second_connect_by_name_does_not_reverse_the_arm(tmp_path):
    """The headline invariant. A spoke arms name→guid on first connect; on
    reconnect it DIALS IN BY NAME again. Reconcile must NOT detect that as a
    clone-rename (guid→name) and reverse the arm — otherwise state ping-pongs
    guid↔name every reconnect.

    Fix: reconcile compares old_id against ``_primary_key(new_id)`` (= guid
    once armed), so old_id == new_pk → equal → no migration, no re-migrate.
    """
    state = _fresh_state(tmp_path)
    km = _make_km()
    km.keys["spoke-A"] = _key("k1", "the-secret")
    hub = _ArmHub(state, km)
    state.system_state["approved_modules"]["spoke-A"] = True
    state.system_state["known_modules"].append("spoke-A")
    state.update_module_metadata("spoke-A", {"install_uuid": "GUID-1", "hostname": "hostA"})
    hub.install_uuid_index["GUID-1"] = "spoke-A"

    # First connect by name → arms name→guid.
    reconcile(hub, "spoke-A", "GUID-1", "hostA")
    assert hub.spoke_id_alias["spoke-A"] == "GUID-1"
    assert state.system_state["approved_modules"].get("GUID-1") is True
    assert hub.install_uuid_index["GUID-1"] == "GUID-1"

    # Second connect by the SAME name (a normal reconnect).
    reconcile(hub, "spoke-A", "GUID-1", "hostA")

    # State is STILL guid-keyed — no reversal.
    assert hub.spoke_id_alias["spoke-A"] == "GUID-1"
    assert state.system_state["approved_modules"].get("GUID-1") is True
    assert "spoke-A" not in state.system_state["approved_modules"]
    assert hub.install_uuid_index["GUID-1"] == "GUID-1"
    # No identity_changed fired on the reconnect (no rename happened).
    assert _events_of(hub, "GUID-1", "identity_changed") == []
    assert _events_of(hub, "spoke-A", "identity_changed") == []


def test_reevict_after_arm_then_clone_rename_chain_converges_on_guid(tmp_path):
    """Clone+rename AFTER the arm: the box reuses GUID-1 under a NEW name. The
    reconcile migrate targets ``_primary_key(new_id)`` (the guid), so the chain
    name→guid→(new-name arms to same guid) converges on guid, not a third key."""
    state = _fresh_state(tmp_path)
    km = _make_km()
    km.keys["spoke-A"] = _key("k1", "the-secret")
    hub = _ArmHub(state, km)
    state.system_state["approved_modules"]["spoke-A"] = True
    state.system_state["known_modules"].append("spoke-A")
    state.update_module_metadata("spoke-A", {"install_uuid": "GUID-1", "hostname": "hostA"})
    hub.install_uuid_index["GUID-1"] = "spoke-A"

    reconcile(hub, "spoke-A", "GUID-1", "hostA")          # arms spoke-A → GUID-1
    # Clone+rename: same GUID-1, new name spoke-B, with proof of the old secret.
    km.keys["spoke-B"] = _key("k1", "the-secret")         # clone holds same secret
    reconcile(hub, "spoke-B", "GUID-1", "hostB", migrate_if=True)

    # The clone-rename migrates old_id (GUID-1) → new_pk. new_pk for spoke-B:
    # alias empty for spoke-B yet → _primary_key("spoke-B")="spoke-B", but the
    # migrate target is _primary_key(new_id) computed BEFORE the arm at the end
    # of this reconcile → "spoke-B". Then the arm relocates spoke-B → GUID-1.
    # Net: state converges on GUID-1, and BOTH names alias to GUID-1.
    assert hub.spoke_id_alias.get("spoke-A") == "GUID-1"
    assert hub.spoke_id_alias.get("spoke-B") == "GUID-1"
    assert state.system_state["approved_modules"].get("GUID-1") is True
    assert hub.install_uuid_index["GUID-1"] == "GUID-1"


# ── CC2 guard: unproven rename does NOT arm ───────────────────────────────────

def test_unproven_rename_does_not_arm(tmp_path):
    """CC2: a known install_uuid under a NEW id with NO proof of the old id's
    secret is NOT migrated AND NOT guid-armed — the victim keeps its name-keyed
    state and the attacker's id is left as a fresh, un-approved spoke."""
    state = _fresh_state(tmp_path)
    km = _make_km()
    km.keys["old-spoke"] = _key("k1", "the-secret")
    hub = _ArmHub(state, km)
    state.system_state["approved_modules"]["old-spoke"] = True
    state.system_state["known_modules"].append("old-spoke")
    state.update_module_metadata("old-spoke", {"tenant_id": "tenant-A",
                                               "install_uuid": "UUID-1",
                                               "hostname": "oldhost"})
    hub.install_uuid_index["UUID-1"] = "old-spoke"

    # Attacker: new id + victim's UUID, no proof → migrate_if=False.
    reconcile(hub, "evil-spoke", "UUID-1", "evilhost", migrate_if=False)

    # Victim untouched (still name-keyed, still approved).
    assert state.system_state["approved_modules"].get("old-spoke") is True
    assert km.get_valid_key("old-spoke", "the-secret") == "k1"
    assert hub.install_uuid_index["UUID-1"] == "old-spoke"
    # Attacker NOT armed to the guid, NOT approved.
    assert hub.spoke_id_alias.get("evil-spoke") is None
    assert state.system_state["approved_modules"].get("evil-spoke") is None
    # Refusal surfaced as a lifecycle event.
    assert _events_of(hub, "evil-spoke", "identity_rename_unproven")