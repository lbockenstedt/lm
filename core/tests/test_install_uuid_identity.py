"""Install-UUID identity tracking + clone/rename detection (Phases 1–3).

A stable per-install UUID (``INSTALL_UUID`` in the spoke/agent ``.env``, minted
at FIRST START) lets the hub correlate a cloned+renamed box with its original so
its approval / tenant binding / per-agent config carry over and the rename is
reported as a lifecycle event. Three reconnect scenarios:

| id        | UUID     | result                                   |
|-----------|----------|------------------------------------------|
| new       | same     | ``identity_changed`` + migrate old→new   |
| same      | (n/a)    | ``hostname_changed`` (pinned-id rename) |
| reused    | new      | ``reimaged`` (fresh image, no migration) |
| new       | new      | fresh entity (no event)                  |

Covers ``BaseControlPlane._ensure_install_uuid`` (Phase 1) and
``LabManagerHub._reconcile_spoke_identity`` / ``_migrate_spoke_identity`` for
spokes + the agent counterpart (Phases 2–3). The fake hub mirrors only the
attributes these methods touch, the same pattern ``test_signature_rotation_window``
uses for ``_install_active_connection``.
"""

import os
import shutil
import subprocess
import sys
import tempfile
import uuid as _uuid
from collections import deque

# conftest puts core/src on sys.path so `main` / `security.*` / `state.*` import
# flat. control_plane.py uses relative imports (``from ..security.signer``) that
# only resolve when it is imported as ``core.src.messaging.control_plane`` — so
# also put the lm repo root (parent of core/) on sys.path for that one module.
_LM_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _LM_ROOT not in sys.path:
    sys.path.insert(0, _LM_ROOT)

import main  # noqa: E402
from core.src.messaging import control_plane as cp  # noqa: E402
from security.key_manager import KeyManager, ManagedKey  # noqa: E402
from state.manager import StateManager  # noqa: E402


# ── helpers ──────────────────────────────────────────────────────────────────

def _key(kid: str, secret: str) -> ManagedKey:
    return ManagedKey(key_id=kid, secret=secret, created_at=0.0,
                      expires_at=9999999999.0)


def _make_km():
    """KeyManager whose persistence lives in tmp, not core/data."""
    km = KeyManager("keys_identity_test.json", "hub_secret_identity_test.json")
    km.storage_path = os.path.join("/tmp", "lm_keys_identity_test.json")
    km.hub_secret_path = os.path.join("/tmp", "lm_hub_secret_identity_test.json")
    data_dir = os.path.join(os.path.dirname(__file__), "..", "data")
    for name in ("keys_identity_test.json", "hub_secret_identity_test.json"):
        try:
            os.remove(os.path.join(data_dir, name))
        except OSError:
            pass
    return km


class _Heartbeat:
    """Just ``last_seen`` — the only attribute _migrate_*_identity touches."""
    def __init__(self):
        self.last_seen = {}


class _ReconcileHub:
    """Minimal stand-in exposing exactly what _reconcile_*_identity touches.

    Uses a REAL ``StateManager`` (so rename_module/rename_agent/update_module_metadata
    are exercised, not reimplemented) with a clean in-memory system_state and
    redirected on-disk paths, plus a REAL ``KeyManager`` (redirected storage) so
    rename_spoke_keys + get_valid_key are the production code paths.
    """

    def __init__(self, state, km):
        self.state = state
        self.key_manager = km
        self.install_uuid_index = {}
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

    # Mirror the real record_spoke_event: per-spoke deque, most-recent-first read.
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

    # Delegate the production migrate/reconcile helpers (they call each other via
    # self, so the fake must expose them as bound methods forwarding to the real
    # unbound LabManagerHub methods with `self` = this fake).
    def _migrate_spoke_identity(self, old_id, new_id):
        return main.LabManagerHub._migrate_spoke_identity(self, old_id, new_id)

    def _reconcile_agent_identity(self, new_id, install_uuid, hostname, parent_spoke_id):
        return main.LabManagerHub._reconcile_agent_identity(
            self, new_id, install_uuid, hostname, parent_spoke_id)

    def _migrate_agent_identity(self, old_id, new_id, parent_spoke_id):
        return main.LabManagerHub._migrate_agent_identity(
            self, old_id, new_id, parent_spoke_id)


def _fresh_state(tmp_path):
    """A real StateManager with a clean system_state + redirected disk paths."""
    s = StateManager()
    # Redirect disk paths so save_state() never touches real /var/lib/lm state.
    s.system_path = str(tmp_path / "system.json")
    s.tenants_path = str(tmp_path / "tenants.json")
    # Replace whatever loaded from disk with a pristine default-shape state.
    s.system_state = {
        "approved_modules": {},
        "known_modules": [],
        "module_names": {},
        "module_metadata": {},
        "agent_config": {},
        "agent_display_names": {},
    }
    return s


def _events_of(hub, sid, kind):
    return [e for e in hub.get_spoke_events(sid) if e["event"] == kind]


def reconcile(hub, new_id, install_uuid, hostname, **kw):
    return main.LabManagerHub._reconcile_spoke_identity(hub, new_id, install_uuid, hostname, **kw)


# ── Phase 1: BaseControlPlane._ensure_install_uuid ───────────────────────────

def test_install_uuid_mints_and_persists_on_first_start(tmp_path):
    """First call generates a UUID and writes INSTALL_UUID= to the spoke .env."""
    bc = cp.BaseControlPlane.__new__(cp.BaseControlPlane)
    bc._repo_root = lambda: str(tmp_path)          # .env lives in the repo root
    val = bc._ensure_install_uuid()
    assert val and _uuid.UUID(val)                 # a real UUID4-shaped string
    persisted = (tmp_path / ".env").read_text()
    assert f"INSTALL_UUID={val}" in persisted


def test_install_uuid_reuses_persisted_value_on_second_start(tmp_path):
    """A clone that already has a UUID does NOT mint a new one — it reuses it."""
    (tmp_path / ".env").write_text("INSTALL_UUID=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\n")
    bc = cp.BaseControlPlane.__new__(cp.BaseControlPlane)
    bc._repo_root = lambda: str(tmp_path)
    assert bc._ensure_install_uuid() == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    # No second line appended.
    assert (tmp_path / ".env").read_text().count("INSTALL_UUID=") == 1


# ── Phase 2: spoke reconcile (4 scenarios) ───────────────────────────────────

def test_same_uuid_new_id_migrates_approval_tenant_and_keys(tmp_path):
    """The headline case: clone+rename keeps approval, no re-onboard needed."""
    state = _fresh_state(tmp_path)
    km = _make_km()
    km.keys["old-spoke"] = _key("k1", "the-secret")          # spoke holds same secret
    hub = _ReconcileHub(state, km)

    # Seed an approved, tenant-bound original under old-spoke.
    state.system_state["approved_modules"]["old-spoke"] = True
    state.system_state["known_modules"].append("old-spoke")
    state.update_module_metadata("old-spoke", {"tenant_id": "tenant-A",
                                               "install_uuid": "UUID-1",
                                               "hostname": "oldhost"})
    hub.install_uuid_index["UUID-1"] = "old-spoke"

    # The cloned box renamed itself → reconnects with a new id, same UUID.
    reconcile(hub, "new-spoke", "UUID-1", "newhost")

    # Approval + tenant binding carried over to the new id; old id no longer approved.
    assert state.system_state["approved_modules"].get("new-spoke") is True
    assert "old-spoke" not in state.system_state["approved_modules"]
    assert state.get_spoke_tenant("new-spoke") == "tenant-A"
    # Known-modules list re-keyed in place.
    assert "new-spoke" in state.system_state["known_modules"]
    assert "old-spoke" not in state.system_state["known_modules"]
    # Install-UUID index now points at the new id.
    assert hub.install_uuid_index["UUID-1"] == "new-spoke"
    # CRITICAL: key material re-keyed so the renamed spoke authenticates seamlessly.
    assert km.get_valid_key("new-spoke", "the-secret") == "k1"
    assert km.get_valid_key("old-spoke", "the-secret") is None
    # identity_changed lifecycle events: the old timeline is carried onto the
    # new id by the migration, so BOTH events ("was old…" + "migrated from old…")
    # end up on the new-spoke timeline that the banner API reads.
    changed = _events_of(hub, "new-spoke", "identity_changed")
    assert len(changed) == 2
    assert _events_of(hub, "old-spoke", "identity_changed") == []   # moved to new
    # Hostname persisted on the new id.
    assert state.system_state["module_metadata"]["new-spoke"]["hostname"] == "newhost"


def test_same_id_new_hostname_emits_hostname_changed(tmp_path):
    """Pinned-id rename: id frozen, OS host renamed → hostname_changed only."""
    state = _fresh_state(tmp_path)
    hub = _ReconcileHub(state, _make_km())
    state.update_module_metadata("pinned-spoke", {"install_uuid": "UUID-2",
                                                  "hostname": "oldhost"})
    hub.install_uuid_index["UUID-2"] = "pinned-spoke"

    reconcile(hub, "pinned-spoke", "UUID-2", "newhost")

    assert _events_of(hub, "pinned-spoke", "hostname_changed")
    assert not _events_of(hub, "pinned-spoke", "identity_changed")
    # No migration occurred (id unchanged): no new id appeared.
    assert set(state.system_state["approved_modules"]) == set()
    assert hub.install_uuid_index["UUID-2"] == "pinned-spoke"


def test_new_uuid_reusing_known_id_emits_reimaged(tmp_path):
    """prep-for-imaging wiped the UUID; the box reuses its id with a fresh UUID."""
    state = _fresh_state(tmp_path)
    hub = _ReconcileHub(state, _make_km())
    state.update_module_metadata("spoke-1", {"install_uuid": "OLD-UUID",
                                            "hostname": "host"})
    hub.install_uuid_index["OLD-UUID"] = "spoke-1"

    reconcile(hub, "spoke-1", "NEW-UUID", "host")

    assert _events_of(hub, "spoke-1", "reimaged")
    assert not _events_of(hub, "spoke-1", "identity_changed")
    # Index now owned by the new image; old UUID evicted.
    assert hub.install_uuid_index.get("NEW-UUID") == "spoke-1"
    assert "OLD-UUID" not in hub.install_uuid_index


def test_fresh_uuid_unknown_id_emits_no_event(tmp_path):
    """A brand-new box (new UUID, unknown id) is just registered, no rename event."""
    state = _fresh_state(tmp_path)
    hub = _ReconcileHub(state, _make_km())

    reconcile(hub, "brand-new", "UUID-X", "host-x")

    assert hub.spoke_events == {}                 # no lifecycle events at all
    assert hub.install_uuid_index["UUID-X"] == "brand-new"
    assert state.system_state["module_metadata"]["brand-new"]["install_uuid"] == "UUID-X"


def test_empty_install_uuid_records_hostname_only(tmp_path):
    """An unwritable .env (no UUID) degrades to plain id tracking — no correlation."""
    state = _fresh_state(tmp_path)
    hub = _ReconcileHub(state, _make_km())
    reconcile(hub, "noid-spoke", "", "host")
    assert hub.install_uuid_index == {}           # nothing indexed without a UUID
    assert state.system_state["module_metadata"]["noid-spoke"]["hostname"] == "host"


# ── Phase 3: agent reconcile (relay migration) ───────────────────────────────

def test_agent_same_uuid_new_id_migrates_agent_config(tmp_path):
    """A cloned+renamed Proxmox node keeps its per-agent config."""
    state = _fresh_state(tmp_path)
    km = _make_km()
    km.keys["old-node-agent"] = _key("ka", "ag-secret")
    hub = _ReconcileHub(state, km)

    state.system_state["agent_config"]["old-node-agent"] = {
        "client_simulation": {"enabled": True, "tenant_id": "tenant-A"},
        "install_uuid": "A-UUID",
        "hostname": "oldnode",
    }
    hub.install_uuid_index["A-UUID"] = "old-node-agent"

    reconcile(hub, "new-node-agent", "A-UUID", "newnode",
              is_agent=True, parent_spoke_id="pxmx-spoke-1")

    cfg = state.system_state["agent_config"]
    assert "new-node-agent" in cfg and "old-node-agent" not in cfg
    assert cfg["new-node-agent"]["client_simulation"]["tenant_id"] == "tenant-A"
    assert hub.install_uuid_index["A-UUID"] == "new-node-agent"
    # Agent key material re-keyed too.
    assert km.get_valid_key("new-node-agent", "ag-secret") == "ka"
    # Event recorded on the PARENT spoke's timeline (the agents-API filter key).
    assert _events_of(hub, "pxmx-spoke-1", "identity_changed")


# ── Phase 5: prep_for_imaging.sh syntax + behavior ──────────────────────────

PREP_SCRIPT = os.path.join(os.path.dirname(__file__), "..", "..", "prep_for_imaging.sh")


def test_prep_for_imaging_is_syntactically_valid():
    """bash -n guards against syntax regressions in the imaging-prep script."""
    assert os.path.isfile(PREP_SCRIPT), f"missing {PREP_SCRIPT}"
    r = subprocess.run(["bash", "-n", PREP_SCRIPT], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr