"""End-to-end tests for LabManagerHub.handle_connection (the spoke front door).

These drive the REAL handle_connection and its phase methods through the
scriptable fakes in ``hc_harness`` and pin every ordering rule listed in the
"Spoke connection lifecycle" banner in main.py. Each test names the commit
whose incident/finding the rule came from.

Defaults (``BASE``) describe an uneventful connect of an approved spoke
``spk`` presenting a valid secret; each test overrides only what it is about.
"""
import hashlib
import hmac
import json

import pytest

import main as main_mod
from main import LabManagerHub
from hc_harness import (RAISE, By, FakeWS, Run, Script, WebSocketDisconnect,
                        closed, hub_ok, msg, signed, unsigned)

BASE = {
    "ws.send": None, "ws.close": None, "encryption_enabled": False,
    "_is_quarantined": False, "_recorded_install_uuid": None,
    "_verify_install_uuid_binding": True, "_reconcile_spoke_identity": "noop",
    "get_valid_key": "k1", "record_success": None, "_note_known_ip": None,
    "_install_active_connection": True, "_install_pending_connection": "take",
    "_is_approved_install_reconnect": False, "_within_reconnect_exemption_budget": True,
    "sign_hub_challenge": "sig", "sign_hub_challenge_all": ["s0", "s1"],
    "sign_hub_challenge_recovery": "rsig", "sign_message": "msig",
    "generate_first_secret": "newsec", "_psk_is_valid": False,
    "_maybe_reprovision_hub_secret": None, "_record_hub_identity_rejection": False,
    "_rate_limit_params": (400, 200), "_try_psk_self_provision": False,
    "_parent_vouches": (False, "nope"), "get_spoke_tenant": "t1",
    "_mtls_connect_gate": ("ok", "fine"), "push_config_to_spoke": False,
    "send_to_spoke": None, "_mtls_enrollment_done": None,
    "verify_signature_source": "current", "_check_freshness_and_replay": True,
    "_decrypt_inbound_payload": None, "bucket.consume": True, "bucket.tokens": 400,
    "_handle_agent_relay_up": True, "get_console_session": "sess",
    "_relay_session_owner_ok": True, "console_queue.put": None, "_vm_live_set": None,
    "broadcast": None,
}
AUTH = {"spoke_id": "spk", "secret": "sek", "module_type": "cs", "install_uuid": "u1"}


def connect(auth=None, frames=(), proof=None, end=None, approved=("spk",), pre=None,
            ws_cls=FakeWS, **overrides):
    """Run one connection; returns the finished ``Run``."""
    run = Run(Script(overrides={**BASE, **overrides}))
    for pk in approved:
        run.hub.approved_modules[pk] = True
    if pre:
        pre(run.hub)
    frame = auth if isinstance(auth, str) else json.dumps(AUTH if auth is None else auth)
    ws = ws_cls(run, "main", [frame, hub_ok() if proof is None else proof], frames, end)
    return run.execute(ws)


def names(run):
    return [c[0] for c in run.calls]


def events(run):
    return [c[1][1] for c in run.calls if c[0] == "record_spoke_event"]


def called(run, name):
    return [c for c in run.calls if c[0] == name]


# ── Phase 1/2: auth frame + authentication ──────────────────────────────

def test_malformed_auth_frame_is_refused_and_fed_to_threat_monitor():
    run = connect(auth="not json")
    assert run.closes == [("main", 1008, "Malformed auth frame")]
    assert called(run, "_record_spoke_auth_failure")[0][1] == ["192.0.2.10", None, "malformed_auth_frame"]
    assert run.error is None


def test_non_object_auth_frame_ends_connection_via_error_handler():
    # Long-standing behavior: ``null`` parses, then .get raises → logged error.
    run = connect(auth="null")
    assert run.error is None
    assert any("Error handling connection for None" in log[2] for log in run.logs)


def test_missing_spoke_id_is_refused():
    run = connect(auth={"secret": "sek"})
    assert run.closes == [("main", 1008, "Missing spoke_id")]
    assert called(run, "_record_spoke_auth_failure")[0][1][2] == "missing_spoke_id"


def test_quarantined_spoke_is_told_to_retry_later():
    run = connect(_is_quarantined=True)
    assert run.closes == [("main", 1013, "Quarantined (flooding) — retry later")]
    assert "_reconcile_spoke_identity" not in names(run)


def test_install_binding_checked_before_reconcile_and_refusal_persists_nothing():
    # 1d2f5aae: reconcile persists the claim, so a refused claim must never
    # reach it — else the attacker locks the real spoke out.
    run = connect(_recorded_install_uuid="u-real", _verify_install_uuid_binding=False)
    assert run.closes == [("main", 1008, "Identity mismatch — re-approval required")]
    assert "_reconcile_spoke_identity" not in names(run)
    assert "auth_rejected" in events(run)


def test_install_binding_ok_then_reconcile_runs_after_it():
    run = connect(_recorded_install_uuid="u-real", _verify_install_uuid_binding=True)
    order = names(run)
    assert order.index("_verify_install_uuid_binding") < order.index("_reconcile_spoke_identity")
    assert run.closes == []


def test_install_binding_not_consulted_without_a_valid_secret():
    run = connect(_recorded_install_uuid="u-real", get_valid_key=None)
    assert "_verify_install_uuid_binding" not in names(run)


@pytest.mark.parametrize("secret_for_old_id, expect_migrate", [(True, True), (False, False)])
def test_rename_migrates_only_with_proof_of_old_ids_secret(secret_for_old_id, expect_migrate):
    # CC2 (67ca8701): a bare install_uuid + new spoke_id must never inherit
    # the victim's approval/keys.
    def valid(pk, secret):
        if pk == "oldspk":
            return "k-old" if secret_for_old_id else None
        return "k1"
    run = connect(get_valid_key=By(valid),
                  pre=lambda hub: hub.install_uuid_index.update({"u1": "oldspk"}))
    reconcile = called(run, "_reconcile_spoke_identity")[0]
    assert reconcile[1] == ["spk", "u1", ""]
    assert reconcile[2] == [("'migrate_if'", expect_migrate)]


def test_rename_never_migrates_without_a_secret():
    run = connect(auth={**AUTH, "secret": None},
                  pre=lambda hub: hub.install_uuid_index.update({"u1": "oldspk"}))
    assert called(run, "_reconcile_spoke_identity")[0][2] == [("'migrate_if'", False)]


def test_state_lands_under_guid_when_reconcile_arms_guid_primary():
    # B1 (e72c46f1): pk is re-resolved after reconcile.
    run = connect(_reconcile_spoke_identity="alias", approved=("guid-1",))
    hub = run.hub
    assert "guid-1" in hub.rate_limiters and "spk" not in hub.rate_limiters
    assert called(run, "mailbox.flush_mailbox")[0][1][0] == "guid-1"
    assert called(run, "key_manager.get_valid_key")[-1][1][0] == "guid-1"


def test_valid_secret_authenticates():
    run = connect(frames=[])
    assert "auth_ok" in events(run) and "connected" in events(run)
    assert called(run, "threat_monitor.record_success")
    assert called(run, "_note_known_ip") == []  # no current key on file in this hub


def test_known_ip_recorded_only_for_current_key_while_approved():
    def pre(hub):
        hub.key_manager.keys["spk"] = type("K", (), {"key_id": "k1"})()
    assert called(connect(pre=pre), "_note_known_ip")
    assert not called(connect(pre=pre, get_valid_key="k-old"), "_note_known_ip")
    assert not called(connect(pre=pre, approved=()), "_note_known_ip")


def test_wrong_secret_closes_and_counts_as_attack():
    run = connect(get_valid_key=None)
    assert run.closes == [("main", 1008, "Authentication failed")]
    assert called(run, "_record_spoke_auth_failure")[0][1] == ["192.0.2.10", "spk", "invalid_secret"]
    assert run.hub.spoke_telemetry["spk"]["status"] == "AUTH_FAILED"
    assert run.sends == []  # no hub proof for a refused spoke


@pytest.mark.parametrize("within_budget", [True, False])
def test_stale_secret_from_approved_install_is_budgeted(within_budget):
    # 6b35ad9e / 25d7590d: reboot/rotation glitches are not attacks — up to a budget.
    run = connect(get_valid_key=None, _is_approved_install_reconnect=True,
                  _within_reconnect_exemption_budget=within_budget)
    assert run.closes == [("main", 1008, "Authentication failed")]
    assert bool(called(run, "_record_spoke_auth_failure")) is (not within_budget)
    assert ("auth_glitch_known_install" in events(run)) is within_budget


def test_no_secret_stays_open_and_gets_a_plaintext_session_key():
    run = connect(auth={**AUTH, "secret": None}, proof=main_mod.asyncio.TimeoutError())
    assert run.closes == []
    assert "mutual_auth_skipped" in events(run)
    key_push = called(run, "send_to_spoke")[0]
    assert key_push[2] == [("'signing_secret'", None)]
    assert "SPOKE_UPDATE_SESSION_KEY" in json.dumps(key_push[1])


def test_stale_key_reconnect_cannot_evict_live_connection():
    run = connect(_install_active_connection=False)
    assert run.sends == []  # stopped before the hub proof
    assert "connected" not in events(run)


# ── hub identity proof ──────────────────────────────────────────────────

def _proof(run):
    return json.loads(run.sends[0][1])


def test_hub_proof_additive_fields_never_block_connect():
    # 4a135d01: only ``signature`` is required.
    run = connect(sign_hub_challenge_all=RAISE, sign_hub_challenge_recovery=RAISE,
                  _psk_is_valid=RAISE, auth={**AUTH, "onboarding_psk": "p", "tenant_id_hint": "t1"})
    proof = _proof(run)
    assert proof == {"status": "HUB_VERIFIED", "challenge": "challenge", "signature": "sig"}
    assert "mutual_auth_complete" in events(run)


def test_hub_proof_carries_all_fields_when_available():
    run = connect(encryption_enabled=True, _psk_is_valid=True,
                  auth={**AUTH, "onboarding_psk": " p ", "tenant_id_hint": "t1"})
    proof = _proof(run)
    assert proof["signatures"] == ["s0", "s1"]
    assert proof["recovery_signature"] == "rsig"
    assert proof["enc"] == main_mod.ENC_MARKER
    assert proof["psk_signature"] == hmac.new(b"p", b"challenge", hashlib.sha256).hexdigest()


def test_psk_signature_only_for_a_validated_psk():
    run = connect(_psk_is_valid=False, auth={**AUTH, "onboarding_psk": "p", "tenant_id_hint": "t1"})
    assert "psk_signature" not in _proof(run)


def test_spoke_rejecting_hub_identity_closes():
    run = connect(proof=json.dumps({"status": "NOPE"}))
    assert run.closes == [("main", 1008, "Hub identity rejected")]
    assert "mutual_auth_failed" in events(run)


def test_hub_proof_timeout_closes_only_when_spoke_holds_a_secret():
    run = connect(proof=main_mod.asyncio.TimeoutError())
    assert run.closes == [("main", 1008, "Mutual authentication timed out")]


@pytest.mark.parametrize("identity_rejected, expect_close", [(True, []),
                         (False, [("main", 1008, "Mutual authentication failed")])])
def test_spoke_closing_on_hub_proof_is_recorded(identity_rejected, expect_close):
    run = connect(proof=closed(4001, "hub identity unverified"),
                  _record_hub_identity_rejection=identity_rejected)
    assert called(run, "_record_hub_identity_rejection")[0][1] == ["spk", "spk", 4001, "hub identity unverified"]
    assert run.closes == expect_close


@pytest.mark.parametrize("index, expect", [(None, False), (0, False), (1, True), ("1", False)])
def test_hub_secret_reprovisioned_only_for_older_index(index, expect):
    run = connect(proof=hub_ok(index))
    assert bool(called(run, "_maybe_reprovision_hub_secret")) is expect


# ── Phase 3: admission ──────────────────────────────────────────────────

def test_unapproved_spoke_waits_for_approval_and_only_heartbeats_flow():
    frames = [signed(msg("HEARTBEAT")), signed(msg("CS_TELEMETRY", {"x": 1}))]
    run = connect(approved=(), frames=frames)
    approval = json.loads(run.sends[1][1])
    assert approval["payload"]["type"] == "APPROVAL_REQUIRED" and approval["signature"] == "msig"
    assert "push_config_to_spoke" not in names(run)
    assert called(run, "heartbeat.update_heartbeat")
    assert "_handle_cs_telemetry" not in names(run)


def test_approval_required_still_sent_when_signing_fails():
    run = connect(approved=(), sign_message=RAISE)
    assert json.loads(run.sends[1][1])["signature"] is None


def test_psk_self_provision_failure_is_an_attack_signal():
    run = connect(auth={**AUTH, "onboarding_psk": "bad", "tenant_id_hint": "t1"}, approved=())
    assert called(run, "_record_spoke_auth_failure")[0][1][2] == "invalid_onboarding_psk"
    assert "psk_self_provision_failed" in events(run)


def test_psk_self_provision_approves_before_the_approval_check():
    run = connect(auth={**AUTH, "onboarding_psk": "ok", "tenant_id_hint": "t1"}, approved=(),
                  _try_psk_self_provision=True)
    assert "push_config_to_spoke" in names(run)


@pytest.mark.parametrize("vouched", [True, False])
def test_parent_auto_approve_requires_signed_vouch(vouched):
    # H3 (dbc4e8e4): the child's claim alone is never trusted.
    run = connect(auth={**AUTH, "spoke_id": "par-role", "parent_spoke_id": "par"}, approved=(),
                  _parent_vouches=(vouched, "ok" if vouched else "denied"))
    # spoke_parent_map itself is popped by the owner's cleanup at exit, so
    # the durable link is checked through the persisted metadata.
    assert run.hub.state.system_state["module_metadata"]["par-role"] == {
        "module_type": "cs", "parent_name": "par", "role_name": "role"}
    approvals = called(run, "approve_and_bind_spoke")
    assert approvals == ([("approve_and_bind_spoke", ["par-role", "t1"], [])] if vouched else [])
    assert ("parent_auto_approve" if vouched else "parent_vouch_failed") in events(run)


def test_approved_subspoke_skips_the_vouch():
    run = connect(auth={**AUTH, "spoke_id": "par-role", "parent_spoke_id": "par"},
                  approved=("par-role",))
    assert "_parent_vouches" not in names(run)


def test_capabilities_are_recorded_and_cleared():
    run = connect(auth={**AUTH, "netbox_server": True, "mtls_csr": True, "enc": main_mod.ENC_MARKER},
                  encryption_enabled=True, frames=[])
    # Cleared again on disconnect by the slot owner, so look at the calls'
    # effect through a still-open connection instead:
    assert run.hub.spoke_mtls_csr_capable["spk"] is True
    run2 = connect(pre=lambda hub: hub.netbox_server_agents.add("other"))
    assert run2.hub.netbox_server_agents == {"other"}


def test_module_type_logged_only_when_new():
    run = connect(pre=lambda hub: hub.state.system_state["module_metadata"].update(
        {"spk": {"module_type": "cs"}}))
    assert "registered" not in events(run)
    assert "registered" in events(connect())


def test_no_synchronous_save_state_on_connect():
    # 727ae321: the state stub has no save_state — calling it would error.
    run = connect(frames=[signed(msg("HEARTBEAT"))])
    assert run.error is None and "connection_error" not in events(run)


@pytest.mark.parametrize("gate, expect_close, expect_push", [
    (("reject", "foreign"), None, False),
    (("enroll", "no-cert"), None, False),
    (("ok", "enroll-exhausted"), None, True),
    (RAISE, None, True),  # a gate bug never blocks the connect
])
def test_mtls_gate(gate, expect_close, expect_push):
    run = connect(_mtls_connect_gate=gate)
    assert ("push_config_to_spoke" in names(run)) is expect_push
    if gate is not RAISE and gate[0] == "reject":
        assert "_mtls_reject" in names(run) and "mailbox.flush_mailbox" not in names(run)


def test_mtls_enroll_only_skips_backlog_and_drops_non_replies():
    frames = [signed(msg("CS_TELEMETRY", {"x": 1})),
              signed(msg("COMMAND_RESULT", {}, correlation_id="c1"))]
    run = connect(_mtls_connect_gate=("enroll", "no-cert"), frames=frames,
                  pre=lambda hub: hub._outstanding_requests.update({"c1": "waiter"}))
    assert "mailbox.flush_mailbox" not in names(run)
    assert "_handle_cs_telemetry" not in names(run)
    assert "c1" in run.hub.response_cache


def test_cs_reconnect_push_is_deferred_until_after_mailbox():
    run = connect(push_config_to_spoke=True)
    order = names(run)
    assert order.index("mailbox.flush_mailbox") < order.index("push_cs_full_config")
    assert run.hub._cs_connect_defer == {}


def test_agent_gets_role_readopt_and_mtls_provision_tasks():
    run = connect(auth={**AUTH, "module_type": "agent"})
    tasks = [c[1][0] for c in called(run, "create_task")]
    assert any("_readopt_agent_roles" in t or "async_stub" in t for t in tasks)
    assert "_readopt_agent_roles" in names(run)
    assert "_provision_spoke_mtls_cert_safe" in names(run)


def test_revoked_spoke_gets_no_mtls_cert():
    run = connect(pre=lambda hub: hub.state.system_state["mtls_revoked"].update({"spk": 1}))
    assert "_provision_spoke_mtls_cert_safe" not in names(run)


# ── Phase 5: per-frame filters ──────────────────────────────────────────

def test_signed_frame_order_verify_then_freshness_then_decrypt():
    # f50d1822 / 4e50918f
    run = connect(frames=[signed(msg("CS_TELEMETRY", {"x": 1}))])
    order = names(run)
    v, f = order.index("key_manager.verify_signature_source"), order.index("_check_freshness_and_replay")
    d, h = order.index("_decrypt_inbound_payload"), order.index("_handle_cs_telemetry")
    assert v < f < d < h


@pytest.mark.parametrize("override, stops_before", [
    ({"verify_signature_source": None}, "_check_freshness_and_replay"),
    ({"_check_freshness_and_replay": False}, "_decrypt_inbound_payload"),
    ({"_decrypt_inbound_payload": main_mod._H4_DROP}, "_handle_cs_telemetry"),
])
def test_rejected_signed_frame_is_never_dispatched(override, stops_before):
    run = connect(frames=[signed(msg("CS_TELEMETRY", {"x": 1}))], **override)
    assert stops_before not in names(run)
    assert "_handle_cs_telemetry" not in names(run)


def test_history_signed_frame_triggers_session_key_redelivery():
    run = connect(frames=[signed(msg("HEARTBEAT"))], verify_signature_source="history")
    assert called(run, "_maybe_redeliver_session_key")


def test_unsigned_frames_only_heartbeat():
    run = connect(frames=[unsigned(msg("HEARTBEAT")), unsigned(msg("CS_TELEMETRY", {"x": 1}))])
    assert called(run, "heartbeat.update_heartbeat")
    assert "_handle_cs_telemetry" not in names(run)
    assert called(run, "_maybe_log_unauthenticated_agent")


def test_heartbeat_persists_last_seen_and_clears_absent_clock():
    run = connect(frames=[signed(msg("HEARTBEAT"))],
                  pre=lambda hub: hub._spoke_absent_since.update({"spk": 1.0}))
    assert called(run, "state.set_spoke_last_seen")
    assert "spk" not in run.hub._spoke_absent_since


def test_replies_are_never_rate_limited():
    # Replies route before the limiter (4fe0916e).
    frames = [signed(msg("COMMAND_RESULT", {"version": "9"}, correlation_id="c1")),
              signed(msg("CS_TELEMETRY", {"x": 1}))]
    run = connect(frames=frames, **{"bucket.consume": False, "bucket.tokens": 0},
                  pre=lambda hub: hub._outstanding_requests.update({"c1": "w"}))
    assert run.hub.response_cache["c1"]["correlation_id"] == "c1"
    assert run.hub.spoke_versions["spk"] == "9"
    assert "_handle_cs_telemetry" not in names(run)
    assert run.hub._rl_harddrops["spk"] == 1 and "spk" in run.hub._rl_breached


def test_protect_mode_sheds_only_offenders():
    big = signed(msg("CS_TELEMETRY", {"x": "y" * 200}))

    def offender(hub):
        hub._protect_mode, hub._spoke_offered["spk"] = True, 50
    shed = connect(frames=[big], pre=offender)
    assert "_handle_cs_telemetry" not in names(shed) and shed.hub.rate_limit_drops["spk"] == 1

    def innocent(hub):
        hub._protect_mode = True
    assert "_handle_cs_telemetry" in names(connect(frames=[big], pre=innocent))


@pytest.mark.parametrize("where, expect_mailbox", [
    ("_outstanding_requests", False), ("_recent_request_timeouts", False),
    ("_pending_broadcast_ids", False), (None, True)])
def test_reply_routing(where, expect_mailbox):
    def pre(hub):
        if where:
            getattr(hub, where)["c1"] = 1
    run = connect(frames=[signed(msg("COMMAND_RESULT", {"status": "SUCCESS"}, correlation_id="c1"))],
                  pre=pre)
    acks = called(run, "mailbox.acknowledge")
    assert bool(acks) is expect_mailbox
    if expect_mailbox:
        assert ("'status'", "SUCCESS") in acks[0][1][0][1]


def test_liveness_pong_resolved_before_ack_routing():
    run = connect(frames=[signed(msg("COMMAND_RESULT", {}, correlation_id="n1"))],
                  pre=lambda hub: hub._pending_liveness_nonces.add("n1"))
    assert called(run, "ws.resolve_pong") and not called(run, "mailbox.acknowledge")


def test_spoke_progress_extends_request_deadline():
    def pre(hub):
        hub._progress_deadlines["c1"] = {"soft": 0, "grace": 5.0, "hard": 9999.0}
    run = connect(frames=[signed(msg("SPOKE_PROGRESS", correlation_id="c1"))], pre=pre)
    assert run.hub._progress_deadlines["c1"]["soft"] > 0
    assert not called(run, "mailbox.acknowledge")


def test_loadtest_probe_counts_gaps():
    frames = [signed(msg("LOADTEST_PROBE", {"seq": s})) for s in (0, 1, 4)]
    run = connect(frames=frames)
    assert run.hub._probe_state["spk"] == {"count": 3, "last_seq": 4, "gaps": 2}


def test_non_object_payload_ends_connection_as_before():
    run = connect(frames=[signed({"payload": [1]})])
    assert "connection_error" in events(run)


# ── Phase 5b: dispatch ──────────────────────────────────────────────────

def test_dispatch_table_maps_every_entry_to_an_async_method():
    import inspect
    table = LabManagerHub._SPOKE_MESSAGE_HANDLERS
    for mtype, method in table.items():
        assert inspect.iscoroutinefunction(getattr(LabManagerHub, method)), mtype
    for mtype in main_mod.dot1x_jit.MESSAGE_TYPES:
        assert table[mtype] == "_spoke_msg_dot1x"


@pytest.mark.parametrize("mtype", ["SOMETHING_NEW", ["a", "list"], None, 5])
def test_unknown_or_non_string_type_is_logged_not_fatal(mtype):
    run = connect(frames=[signed({"payload": {"type": mtype, "data": {}}})])
    assert run.error is None and "connection_error" not in events(run)
    assert any(log[2] == f"Received verified message from spk: {mtype}" for log in run.logs)


@pytest.mark.parametrize("handled, expect_log", [(True, False), (False, True), (None, True)])
def test_unmatched_agent_relay_up_falls_back_to_info_log(handled, expect_log):
    run = connect(frames=[signed(msg("AGENT_RELAY_UP", {"sub": 1}))], _handle_agent_relay_up=handled)
    assert called(run, "_handle_agent_relay_up")[0][2] == [("'_dec_secret'", None)]
    logged = any("Received verified message from spk: AGENT_RELAY_UP" in log[2] for log in run.logs)
    assert logged is expect_log


def test_cs_telemetry_coalesced_under_backpressure():
    run = connect(frames=[signed(msg("CS_TELEMETRY", {"n": 1})), signed(msg("CS_TELEMETRY", {"n": 2}))],
                  pre=lambda hub: hub._spoke_backoff.add("spk"))
    assert "_handle_cs_telemetry" not in names(run)
    assert run.hub._coalesce_pending["spk"][0] == {"n": 2}
    assert run.hub._telemetry_coalesced == 1


@pytest.mark.parametrize("ctype, item", [
    ("CONSOLE_DATA_UP", b"hi"), ("CONSOLE_READY", ["ready"]),
    ("CONSOLE_CLOSED", ["disconnect"]), ("CONSOLE_DOWNGRADED", ["downgraded"])])
def test_console_relay(ctype, item):  # (canon() records tuples as lists)
    run = connect(frames=[signed(msg(ctype, {"session_id": "s1", "data": "aGk="}))])
    assert called(run, "console_queue.put")[0][1] == [item]


def test_console_relay_refuses_non_owner():
    run = connect(frames=[signed(msg("CONSOLE_READY", {"session_id": "s1"}))],
                  _relay_session_owner_ok=False)
    assert not called(run, "console_queue.put")


def test_peer_ip_threaded_to_edge_security_handlers():
    frames = [signed(msg(t, {"k": 1})) for t in ("HTTP_PROBE_REPORT", "APP_LOGIN_FAILURE", "NODE_CANARY_HIT")]
    run = connect(frames=frames)
    for name in ("_handle_edge_probe_report", "_handle_app_login_failure", "_handle_node_canary_hit"):
        assert called(run, name)[0][1] == ["spk", "192.0.2.10", [("'k'", 1)]]


def test_dot1x_messages_spawned_with_spoke_id():
    run = connect(frames=[signed(msg("CS_DOT1X_PROVISION", {"mac": "m"}))])
    assert called(run, "dot1x_jit.handle_spoke_message")[0][1][1:] == ["spk", "CS_DOT1X_PROVISION", [("'mac'", "m")]]
    assert called(run, "_spawn_cs_push")


def test_hub_request_gets_peer_cert_identity():
    run = connect(frames=[signed(msg("HUB_REQUEST", {"op": "x"}))])
    assert called(run, "_handle_hub_request")[0][1][3] is None


# ── Phase 6: cleanup ────────────────────────────────────────────────────

def test_owner_cleanup_releases_all_per_connection_state():
    def pre(hub):
        hub.agent_info.update({"a1": {"spoke_id": "spk"}, "a2": {"spoke_id": "other"}})
    run = connect(auth={**AUTH, "module_type": "proxy", "netbox_server": True}, pre=pre,
                  end=closed())
    hub = run.hub
    assert "spk" not in hub.active_connections and "spk" not in hub.spoke_module_types
    assert hub.netbox_server_agents == set() and "spk" not in hub.spoke_enc_capable
    assert hub.agent_info == {"a2": {"spoke_id": "other"}}
    assert "connection_closed" in events(run) and called(run, "_mark_spoke_disconnected")


def test_connection_error_marks_telemetry_error():
    run = connect(end=RuntimeError("kaboom"))
    assert run.hub.spoke_telemetry["spk"]["status"] == "ERROR"
    assert "connection_error" in events(run)


class _ReplacedWS(FakeWS):
    """Gets replaced by a newer connection while still in its frame loop."""

    async def _iter(self):
        self.run.hub.active_connections["spk"] = "replacement"
        self.run.hub.spoke_module_types["spk"] = "cs"
        if False:
            yield
        raise self.end


@pytest.mark.parametrize("end", [closed(), WebSocketDisconnect(1000), RuntimeError("x")])
def test_zombie_connection_never_wipes_its_replacement(end):
    # 9ae39980: an evicted connection's belated exit must not touch the
    # live replacement's state.
    run = connect(end=end, ws_cls=_ReplacedWS)
    hub = run.hub
    assert hub.active_connections["spk"] == "replacement"
    assert hub.spoke_module_types["spk"] == "cs"
    assert not called(run, "_mark_spoke_disconnected")
    assert hub.spoke_telemetry["spk"]["status"] == "CONNECTED"
    assert called(run, "_mtls_enrollment_done")  # always released


def test_mtls_enrollment_released_even_if_release_raises():
    run = connect(_mtls_enrollment_done=RAISE, end=closed())
    assert run.error is None and "spk" not in run.hub.active_connections
