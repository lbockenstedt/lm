"""Feature B2: ``_arm_agent_guid_primary`` — agent-relay guid-primary arming
(option b: the guid is the hub-side primary key; the relay envelope
``target_agent_id`` stays the raw name the spoke knows the agent by).

The seam: ``agent_id_alias[connect_id] = install_uuid`` so
``_agent_primary_key(name)`` resolves to the guid, and the agent's hub-side
state (``agent_config`` / ``agent_display_names`` / ``agent_logs`` /
``agent_info`` / the ``{spoke}:{agent}`` composite heartbeat / the
``spoke_telemetry`` nested agent entry) is re-keyed name→guid. The agent still
REPORTS its self-chosen ``agent_id`` (name) on every AGENT_RELAY_UP frame; the
guid is the hub-internal primary key, translated to the raw name at the relay
boundary via ``_agent_relay_name`` (``agent_info[guid]["agent_id"]``).

Covers:

* arm re-keys agent_config / agent_display_names / agent_logs / agent_info /
  the {spoke}:{agent} composite / the spoke_telemetry nested entry name→guid;
* arm is idempotent (already-armed → no-op; armed to a different guid → left
  untouched); noop when uuid==agent_id or empty;
* the no-reversal invariant: a 2nd connect by name does NOT ping-pong state
  guid↔name (reconcile compares old_id against ``_agent_primary_key(new_id)``);
* cold-restart re-arm: alias empty + index guid-keyed + reconnect by name →
  NO migrate / identity_changed (pre-arm guard), just re-arms the alias;
* ``_agent_relay_name`` translates guid→raw name (and is idempotent on names);
* the composite + spoke_telemetry parent half resolves through the spoke
  primary key (``_primary_key(parent)``), matching the write site.
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
    km = KeyManager("keys_agent_arm_test.json", "hub_secret_agent_arm_test.json")
    km.storage_path = os.path.join("/tmp", "lm_keys_agent_arm_test.json")
    km.hub_secret_path = os.path.join("/tmp", "lm_hub_secret_agent_arm_test.json")
    data_dir = os.path.join(os.path.dirname(__file__), "..", "data")
    for name in ("keys_agent_arm_test.json", "hub_secret_agent_arm_test.json"):
        try:
            os.remove(os.path.join(data_dir, name))
        except OSError:
            pass
    return km


class _Heartbeat:
    def __init__(self):
        self.last_seen = {}


class _ArmAgentHub:
    """Minimal stand-in exposing exactly what _arm_agent_guid_primary /
    _reconcile_agent_identity / _migrate_agent_identity / _agent_relay_name
    touch. Uses a REAL StateManager (rename_agent exercised) + a REAL
    KeyManager (redirected storage). ``agent_id_alias`` is the B2 seam;
    ``spoke_id_alias`` is the B1 seam (parent-spoke pk resolution)."""

    def __init__(self, state, km):
        self.state = state
        self.key_manager = km
        self.install_uuid_index = {}
        self.spoke_id_alias = {}                        # B1 seam (parent spoke)
        self.agent_id_alias = {}                        # B2 seam (agent)
        self.heartbeat = _Heartbeat()
        self.spoke_event_limit = 100
        self.spoke_events = {}
        self.spoke_telemetry = {}
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

    def _agent_primary_key(self, agent_id):
        return main.LabManagerHub._agent_primary_key(self, agent_id)

    def _agent_relay_name(self, agent_id):
        return main.LabManagerHub._agent_relay_name(self, agent_id)

    def _migrate_agent_identity(self, old_id, new_id, parent_spoke_id=None, **kw):
        return main.LabManagerHub._migrate_agent_identity(self, old_id, new_id,
                                                          parent_spoke_id)

    def _arm_agent_guid_primary(self, agent_id, install_uuid, parent_spoke_id=None):
        return main.LabManagerHub._arm_agent_guid_primary(self, agent_id, install_uuid,
                                                         parent_spoke_id)

    def _reconcile_agent_identity(self, new_id, install_uuid, hostname, parent_spoke_id):
        return main.LabManagerHub._reconcile_agent_identity(self, new_id, install_uuid,
                                                            hostname, parent_spoke_id)


def _fresh_state(tmp_path):
    s = StateManager()
    s.system_path = str(tmp_path / "system.json")
    s.tenants_path = str(tmp_path / "tenants.json")
    s.system_state = {
        "agent_config": {},
        "agent_display_names": {},
        "spoke_last_seen": {},
        "module_metadata": {},
    }
    return s


def _events_of(hub, sid, kind):
    return [e for e in hub.get_spoke_events(sid) if e["event"] == kind]


def reconcile(hub, new_id, install_uuid, hostname, parent_spoke_id="pxmx-1"):
    return hub._reconcile_agent_identity(new_id, install_uuid, hostname, parent_spoke_id)


# ── arm re-keys agent state name→guid ────────────────────────────────────────

def test_arm_rekeys_agent_state_name_to_guid(tmp_path):
    state = _fresh_state(tmp_path)
    km = _make_km()
    km.keys["node-agent"] = _key("k1", "the-secret")
    hub = _ArmAgentHub(state, km)

    # Seed a name-keyed agent: config + display-name override + logs + info +
    # composite heartbeat + nested telemetry, all under the raw name.
    state.system_state["agent_config"]["node-agent"] = {
        "hostname": "node1", "install_uuid": "AGUID-1",
        "client_simulation": {"tenant_id": "tA", "enabled": True}}
    state.system_state["agent_display_names"]["node-agent"] = "Node One"
    hub.agent_logs["node-agent"] = deque(["boot line"], maxlen=100)
    hub.agent_info["node-agent"] = {"spoke_id": "pxmx-1", "agent_id": "node-agent",
                                    "hostname": "node1"}
    hub.heartbeat.last_seen["pxmx-1:node-agent"] = 999.0
    hub.spoke_telemetry["pxmx-1"] = {"node-agent": {"cpu": 7}}
    hub.install_uuid_index["AGUID-1"] = "node-agent"

    hub._arm_agent_guid_primary("node-agent", "AGUID-1", "pxmx-1")

    # Alias armed.
    assert hub.agent_id_alias["node-agent"] == "AGUID-1"
    assert hub._agent_primary_key("node-agent") == "AGUID-1"
    # Persisted agent_config re-keyed name→guid; client_simulation survives.
    cfg = state.system_state["agent_config"]
    assert "AGUID-1" in cfg and "node-agent" not in cfg
    assert cfg["AGUID-1"]["client_simulation"]["tenant_id"] == "tA"
    # Display-name override re-keyed.
    assert state.system_state["agent_display_names"].get("AGUID-1") == "Node One"
    assert "node-agent" not in state.system_state["agent_display_names"]
    # In-memory logs + info re-keyed; the agent_id field travels (relay name).
    assert "AGUID-1" in hub.agent_logs and "node-agent" not in hub.agent_logs
    assert hub.agent_info["AGUID-1"]["agent_id"] == "node-agent"
    # Composite heartbeat + nested telemetry re-keyed (parent half = spoke pk).
    assert "pxmx-1:AGUID-1" in hub.heartbeat.last_seen
    assert "pxmx-1:node-agent" not in hub.heartbeat.last_seen
    assert hub.spoke_telemetry["pxmx-1"].get("AGUID-1") == {"cpu": 7}
    assert "node-agent" not in hub.spoke_telemetry["pxmx-1"]
    # KeyManager re-keyed; install_uuid_index repoints to the guid.
    assert km.get_valid_key("AGUID-1", "the-secret") == "k1"
    assert km.get_valid_key("node-agent", "the-secret") is None
    assert hub.install_uuid_index["AGUID-1"] == "AGUID-1"


# ── idempotency ──────────────────────────────────────────────────────────────

def test_arm_idempotent_when_already_armed(tmp_path):
    state = _fresh_state(tmp_path)
    km = _make_km()
    hub = _ArmAgentHub(state, km)
    state.system_state["agent_config"]["node-agent"] = {"install_uuid": "AGUID-1"}
    hub.install_uuid_index["AGUID-1"] = "node-agent"

    hub._arm_agent_guid_primary("node-agent", "AGUID-1", "pxmx-1")
    snap = dict(state.system_state["agent_config"])
    hub._arm_agent_guid_primary("node-agent", "AGUID-1", "pxmx-1")
    assert state.system_state["agent_config"] == snap
    assert hub.agent_id_alias["node-agent"] == "AGUID-1"
    assert _events_of(hub, "AGUID-1", "identity_changed") == []


def test_arm_ignores_when_armed_to_a_different_guid(tmp_path):
    state = _fresh_state(tmp_path)
    km = _make_km()
    hub = _ArmAgentHub(state, km)
    hub.agent_id_alias["node-agent"] = "AGUID-ORIGINAL"
    state.system_state["agent_config"]["node-agent"] = {"install_uuid": "AGUID-ORIGINAL"}

    hub._arm_agent_guid_primary("node-agent", "AGUID-DIFFERENT", "pxmx-1")
    assert hub.agent_id_alias["node-agent"] == "AGUID-ORIGINAL"


def test_arm_noop_when_uuid_equals_agent_id(tmp_path):
    state = _fresh_state(tmp_path)
    hub = _ArmAgentHub(state, _make_km())
    hub._arm_agent_guid_primary("node-agent", "node-agent", "pxmx-1")
    assert hub.agent_id_alias == {}


def test_arm_noop_when_uuid_empty(tmp_path):
    state = _fresh_state(tmp_path)
    hub = _ArmAgentHub(state, _make_km())
    hub._arm_agent_guid_primary("node-agent", "", "pxmx-1")
    assert hub.agent_id_alias == {}


# ── no-reversal: 2nd connect by name does NOT ping-pong ───────────────────────

def test_second_connect_by_name_does_not_reverse_the_agent_arm(tmp_path):
    """Headline invariant (agent path). First connect arms name→guid; a
    reconnect dials in BY NAME again. Reconcile must NOT detect that as a
    clone-rename (guid→name) and reverse the arm."""
    state = _fresh_state(tmp_path)
    km = _make_km()
    km.keys["node-agent"] = _key("k1", "the-secret")
    hub = _ArmAgentHub(state, km)
    state.system_state["agent_config"]["node-agent"] = {"install_uuid": "AGUID-1"}
    hub.install_uuid_index["AGUID-1"] = "node-agent"

    reconcile(hub, "node-agent", "AGUID-1", "node1")
    assert hub.agent_id_alias["node-agent"] == "AGUID-1"
    assert "AGUID-1" in state.system_state["agent_config"]
    assert hub.install_uuid_index["AGUID-1"] == "AGUID-1"

    # Reconnect by the SAME name.
    reconcile(hub, "node-agent", "AGUID-1", "node1")

    assert hub.agent_id_alias["node-agent"] == "AGUID-1"
    assert "AGUID-1" in state.system_state["agent_config"]
    assert "node-agent" not in state.system_state["agent_config"]
    assert hub.install_uuid_index["AGUID-1"] == "AGUID-1"
    assert _events_of(hub, "AGUID-1", "identity_changed") == []
    assert _events_of(hub, "node-agent", "identity_changed") == []


# ── cold-restart re-arm: no spurious guid→name reversal ───────────────────────

def test_cold_restart_reconnect_by_name_does_not_reverse(tmp_path):
    """Alias is in-memory (empty after a hub restart) but install_uuid_index is
    rebuilt guid-keyed from persisted agent_config. Reconnecting by name must
    NOT migrate guid→name (spurious identity_changed + double-migration); the
    pre-arm guard re-arms the alias so the reconcile sees old_id == new_pk."""
    state = _fresh_state(tmp_path)
    km = _make_km()
    km.keys["AGUID-1"] = _key("k1", "the-secret")  # already guid-keyed pre-restart
    hub = _ArmAgentHub(state, km)
    # Simulate post-restart persisted state: agent_config guid-keyed, index rebuilt.
    state.system_state["agent_config"]["AGUID-1"] = {"hostname": "node1",
                                                     "install_uuid": "AGUID-1"}
    hub.install_uuid_index["AGUID-1"] = "AGUID-1"   # rebuilt guid-keyed
    # Alias is EMPTY (in-memory, lost on restart).

    reconcile(hub, "node-agent", "AGUID-1", "node1")

    # Re-armed without reversing: state STILL guid-keyed, no identity_changed.
    assert hub.agent_id_alias["node-agent"] == "AGUID-1"
    assert "AGUID-1" in state.system_state["agent_config"]
    assert "node-agent" not in state.system_state["agent_config"]
    assert _events_of(hub, "AGUID-1", "identity_changed") == []
    assert _events_of(hub, "node-agent", "identity_changed") == []


# ── clone+rename after arm converges on guid ─────────────────────────────────

def test_clone_rename_after_arm_converges_on_guid(tmp_path):
    """Clone+rename AFTER the arm: the node reuses AGUID-1 under a NEW name. The
    migrate targets new_pk (guid), so the chain name→guid→(new-name arms to the
    same guid) converges on guid."""
    state = _fresh_state(tmp_path)
    km = _make_km()
    km.keys["node-agent"] = _key("k1", "the-secret")
    hub = _ArmAgentHub(state, km)
    state.system_state["agent_config"]["node-agent"] = {"install_uuid": "AGUID-1"}
    hub.install_uuid_index["AGUID-1"] = "node-agent"

    reconcile(hub, "node-agent", "AGUID-1", "node1")          # arms → AGUID-1
    # Clone+rename: same AGUID-1, new name node-b, holds the same secret.
    km.keys["node-b"] = _key("k1", "the-secret")
    reconcile(hub, "node-b", "AGUID-1", "nodeB")

    # Both names alias to AGUID-1; state converges on the guid.
    assert hub.agent_id_alias.get("node-agent") == "AGUID-1"
    assert hub.agent_id_alias.get("node-b") == "AGUID-1"
    assert "AGUID-1" in state.system_state["agent_config"]
    assert hub.install_uuid_index["AGUID-1"] == "AGUID-1"


# ── _agent_relay_name: guid→name translation ──────────────────────────────────

def test_agent_relay_name_translates_guid_to_raw_name(tmp_path):
    state = _fresh_state(tmp_path)
    hub = _ArmAgentHub(state, _make_km())
    hub.agent_id_alias["node-agent"] = "AGUID-1"
    hub.agent_info["AGUID-1"] = {"agent_id": "node-agent", "spoke_id": "pxmx-1"}

    # guid → raw name (relay envelope translation, option b).
    assert hub._agent_relay_name("AGUID-1") == "node-agent"
    # raw name pre-arm / unknown → itself (idempotent / safe fallback).
    assert hub._agent_relay_name("node-agent") == "node-agent"
    assert hub._agent_relay_name("never-seen") == "never-seen"


# ── composite parent half resolves through the spoke primary key ─────────────

def test_composite_uses_spoke_primary_key_for_parent_half(tmp_path):
    """When the parent spoke is ALSO guid-armed (B1), the composite re-key must
    use the spoke's guid (``_primary_key(parent)``), not the raw name — matching
    the write site ``{spoke_pk}:{agent_pk}``."""
    state = _fresh_state(tmp_path)
    km = _make_km()
    hub = _ArmAgentHub(state, km)
    # Parent spoke armed: pxmx-1 → SGUID-1.
    hub.spoke_id_alias["pxmx-1"] = "SGUID-1"
    state.system_state["agent_config"]["node-agent"] = {"install_uuid": "AGUID-1"}
    hub.heartbeat.last_seen["SGUID-1:node-agent"] = 999.0
    hub.spoke_telemetry["SGUID-1"] = {"node-agent": {"cpu": 1}}
    hub.install_uuid_index["AGUID-1"] = "node-agent"

    hub._arm_agent_guid_primary("node-agent", "AGUID-1", "pxmx-1")

    # Composite + telemetry parent half is the spoke GUID (not the raw name).
    assert "SGUID-1:AGUID-1" in hub.heartbeat.last_seen
    assert "pxmx-1:AGUID-1" not in hub.heartbeat.last_seen
    assert hub.spoke_telemetry["SGUID-1"].get("AGUID-1") == {"cpu": 1}