"""Bind a verified session key to the install_uuid the hub issued it to.

A valid secret proves possession of key material — not that the box presenting
it is the install the hub keyed. Before this check the install_uuid was consulted
only to EXCUSE a *failed* auth (``_is_approved_install_reconnect``) or to prove a
rename, never to contradict a *successful* one, so a stolen secret replayed from
elsewhere authenticated normally and the differing guid was filed as a benign
``reimaged`` lifecycle event.

``_verify_install_uuid_binding`` closes that. The enforcement split mirrors
``_is_uuid_collision``:

| recorded uuid | presented uuid | owner live | result                    |
|---------------|----------------|------------|---------------------------|
| absent        | any            | n/a        | allow (no baseline)       |
| present       | absent         | n/a        | allow + report            |
| present       | equal          | n/a        | allow, silent             |
| present       | different      | yes        | DENY                      |
| present       | different      | no         | allow + report (observe)  |
| present       | different      | no, strict | DENY                      |
"""

import copy
import os
import sys
import time
from collections import deque

_LM_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _LM_ROOT not in sys.path:
    sys.path.insert(0, _LM_ROOT)

import main  # noqa: E402
from state.manager import StateManager  # noqa: E402


RECORDED = "11111111-2222-3333-4444-555555555555"
OTHER = "99999999-8888-7777-6666-555555555555"


class _TM:
    """Captures note_anomaly calls so tests can assert on the security signal."""

    def __init__(self):
        self.anomalies = []

    def note_anomaly(self, kind, detail="", ip=None, severity="warning", meta=None):
        self.anomalies.append({"kind": kind, "detail": detail, "ip": ip,
                               "severity": severity, "meta": meta or {}})


class _BindingHub:
    """Minimal stand-in exposing exactly what the binding check touches."""

    def __init__(self, state):
        self.state = state
        self.spoke_id_alias = {}
        self.active_connections = {}
        self.spoke_events = {}
        self.spoke_event_limit = 100
        self.threat_monitor = _TM()

    def record_spoke_event(self, spoke_id, event, detail=""):
        if not spoke_id:
            return
        buf = self.spoke_events.setdefault(spoke_id, deque(maxlen=self.spoke_event_limit))
        buf.append({"ts": 0.0, "event": event, "detail": detail})

    def _primary_key(self, spoke_id):
        return main.LabManagerHub._primary_key(self, spoke_id)

    # Methods under test, bound to this fake.
    def _recorded_install_uuid(self, pk):
        return main.LabManagerHub._recorded_install_uuid(self, pk)

    def _uuid_binding_owner_live(self, pk):
        return main.LabManagerHub._uuid_binding_owner_live(self, pk)

    def _uuid_binding_strict(self):
        return main.LabManagerHub._uuid_binding_strict(self)

    def _note_uuid_binding_event(self, *a, **kw):
        return main.LabManagerHub._note_uuid_binding_event(self, *a, **kw)

    def verify(self, spoke_id, presented, prev, peer_ip="203.0.113.9"):
        return main.LabManagerHub._verify_install_uuid_binding(
            self, spoke_id, self._primary_key(spoke_id), presented, prev, peer_ip)


def _fresh_state(tmp_path, last_seen=None, global_config=None):
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
        "spoke_last_seen": dict(last_seen or {}),
        "global_config": dict(global_config or {}),
    }
    return s


def _hub(tmp_path, **kw):
    return _BindingHub(_fresh_state(tmp_path, **kw))


def _events(hub, sid, kind):
    return [e for e in hub.spoke_events.get(sid, []) if e["event"] == kind]


# ── allow paths: never strand a legitimate spoke ─────────────────────────────

def test_no_recorded_uuid_is_allowed(tmp_path):
    """A legacy / first-connect spoke has nothing to bind to. Refusing here
    would lock out every spoke that predates this check."""
    hub = _hub(tmp_path)
    assert hub.verify("sp1", OTHER, "") is True
    assert hub.threat_monitor.anomalies == []


def test_matching_uuid_is_allowed_silently(tmp_path):
    """The normal reconnect: same install, same guid, no noise."""
    hub = _hub(tmp_path)
    assert hub.verify("sp1", RECORDED, RECORDED) is True
    assert hub.threat_monitor.anomalies == []
    assert _events(hub, "sp1", "install_uuid_binding_mismatch") == []


def test_absent_presented_uuid_is_allowed_but_reported(tmp_path):
    """The agent documents returning '' when its guid file cannot be read, so an
    absent uuid is a degraded state rather than a signal — allowed, but surfaced
    because a spoke that previously reported one should normally still do so."""
    hub = _hub(tmp_path)
    assert hub.verify("sp1", "", RECORDED) is True
    assert len(hub.threat_monitor.anomalies) == 1
    assert hub.threat_monitor.anomalies[0]["meta"]["denied"] is False


# ── deny path: the recorded owner is live ────────────────────────────────────

def test_mismatch_denied_when_owner_holds_a_live_connection(tmp_path):
    """Unambiguous: the real box is connected right now, so the challenger
    cannot be that same box returning. Matches the established duplicate-
    connection policy of keeping the live spoke."""
    hub = _hub(tmp_path)
    hub.active_connections["sp1"] = object()
    assert hub.verify("sp1", OTHER, RECORDED) is False
    assert len(_events(hub, "sp1", "install_uuid_binding_mismatch")) == 1
    assert hub.threat_monitor.anomalies[0]["meta"]["denied"] is True


def test_mismatch_denied_when_owner_seen_within_the_live_window(tmp_path):
    """No socket, but seen seconds ago — still concurrent, still a denial."""
    hub = _hub(tmp_path, last_seen={"sp1": time.time() - 5})
    assert hub.verify("sp1", OTHER, RECORDED) is False


def test_mismatch_allowed_when_owner_is_long_gone(tmp_path):
    """Past the window this is indistinguishable from a re-image that preserved
    its secret, so the default posture is observe-only: report, don't deny."""
    hub = _hub(tmp_path, last_seen={"sp1": time.time() - 10_000})
    assert hub.verify("sp1", OTHER, RECORDED) is True
    assert len(hub.threat_monitor.anomalies) == 1
    assert hub.threat_monitor.anomalies[0]["meta"]["denied"] is False


def test_strict_mode_denies_even_without_a_live_owner(tmp_path):
    """Operator opt-in, once the fleet is known to report guids cleanly."""
    hub = _hub(tmp_path, last_seen={"sp1": time.time() - 10_000},
               global_config={"security": {"uuid_binding_strict": True}})
    assert hub.verify("sp1", OTHER, RECORDED) is False
    assert hub.threat_monitor.anomalies[0]["meta"]["denied"] is True


# ── signal quality ───────────────────────────────────────────────────────────

def test_anomaly_never_escalates_to_an_auto_block(tmp_path):
    """``note_anomaly`` drives an NSG block only at ``critical``. The common
    real cause here is a cloning/imaging mistake, so cutting off the site's
    egress would turn a misconfiguration into an outage."""
    hub = _hub(tmp_path)
    hub.active_connections["sp1"] = object()
    hub.verify("sp1", OTHER, RECORDED)
    assert hub.threat_monitor.anomalies[0]["severity"] != "critical"


def test_report_truncates_uuids_and_carries_the_peer_ip(tmp_path):
    """Operators triage by IP; guids are truncated so the logs stay readable and
    a full install guid is never echoed into the event stream."""
    hub = _hub(tmp_path)
    hub.active_connections["sp1"] = object()
    hub.verify("sp1", OTHER, RECORDED, peer_ip="198.51.100.4")
    rec = hub.threat_monitor.anomalies[0]
    assert rec["ip"] == "198.51.100.4"
    assert rec["meta"]["presented_uuid"] == OTHER[:8]
    assert rec["meta"]["recorded_uuid"] == RECORDED[:8]
    assert OTHER not in rec["detail"] and RECORDED not in rec["detail"]


# ── robustness ───────────────────────────────────────────────────────────────

def test_liveness_failure_fails_closed(tmp_path):
    """If liveness cannot be established, prefer denying the challenger over
    admitting a possible thief — the real spoke reconnects on its next retry."""
    hub = _hub(tmp_path)

    def _boom():
        raise RuntimeError("state unavailable")

    hub.state.get_spoke_last_seen = _boom
    assert hub._uuid_binding_owner_live("sp1") is True


def test_check_failure_fails_open_so_a_verified_key_still_connects(tmp_path):
    """The secret already verified; a bookkeeping fault must never strand a
    legitimate spoke."""
    hub = _hub(tmp_path)

    def _boom(*a, **kw):
        raise RuntimeError("boom")

    hub._uuid_binding_owner_live = _boom
    assert hub.verify("sp1", OTHER, RECORDED) is True


def test_recorded_uuid_reads_module_metadata(tmp_path):
    """The sample the whole check depends on — must come from the persisted
    metadata, and must be taken before reconcile overwrites it."""
    hub = _hub(tmp_path)
    hub.state.system_state["module_metadata"]["sp1"] = {"install_uuid": RECORDED}
    assert hub._recorded_install_uuid("sp1") == RECORDED
    assert hub._recorded_install_uuid("unknown") == ""


def test_check_is_wired_ahead_of_reconcile(tmp_path):
    """Ordering regression guard.

    ``_reconcile_spoke_identity`` repoints the uuid index, overwrites the
    recorded uuid and can re-arm the guid. If the binding check ran after it, a
    refused connection would still have persisted the attacker's claim — and the
    LEGITIMATE install would then mismatch on its next reconnect and be denied,
    handing an attacker a permanent lockout from one rejected connect. Pin the
    call order in the source so that cannot silently regress."""
    src = open(os.path.join(_LM_ROOT, "core", "src", "main.py")).read()
    check = src.index("_verify_install_uuid_binding(")
    reconcile = src.index("self._reconcile_spoke_identity(spoke_id, install_uuid")
    assert check < reconcile, \
        "binding check must be adjudicated before reconcile persists the claim"


def test_binding_check_mutates_no_state(tmp_path):
    """It is called mid-auth on a live connection path, so it must be a pure
    decision — the caller relies on being able to deny without side effects."""
    hub = _hub(tmp_path)
    hub.active_connections["sp1"] = object()
    hub.state.system_state["module_metadata"]["sp1"] = {"install_uuid": RECORDED}
    before = copy.deepcopy(hub.state.system_state)
    assert hub.verify("sp1", OTHER, RECORDED) is False
    assert hub.state.system_state == before
    assert hub.spoke_id_alias == {}
