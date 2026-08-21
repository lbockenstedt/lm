"""The Error Log source prefix must show a human-readable spoke/agent NAME, not
the bare UUID primary key the ``agent_logs`` deques are keyed by. ``_log_source_label``
resolves that key via ``module_metadata`` (top-level spokes) then ``agent_info``
(relayed pxmx node-agents), rendering ``name (shortid)`` for correlation and
falling back to the raw id when nothing is registered. ``collect_error_logs``
must apply it to the ``[source]`` prefix.
"""
import types

import main  # noqa: E402  (core/src on sys.path via conftest)


def _hub(module_metadata=None, agent_info=None, logs=None, agent_logs=None):
    h = types.SimpleNamespace()
    h.state = types.SimpleNamespace(
        system_state={"module_metadata": module_metadata or {}})
    h.agent_info = agent_info or {}
    h.logs = logs or []
    h.agent_logs = agent_logs or {}
    return h


def test_label_from_module_metadata_display_name():
    h = _hub(module_metadata={"a25e89a6-1111-2222-3333-444455556666": {
        "display_name": "cs-svr-05"}})
    got = main._log_source_label(h, "a25e89a6-1111-2222-3333-444455556666")
    assert got == "cs-svr-05 (a25e89a6)"


def test_label_from_agent_info_hostname_for_relayed_agent():
    h = _hub(agent_info={"b64df088-c4de-4cfb-8d3d-077f864fe78d": {
        "hostname": "PXMX-CS-SVR-05"}})
    got = main._log_source_label(h, "b64df088-c4de-4cfb-8d3d-077f864fe78d")
    assert got == "PXMX-CS-SVR-05 (b64df088)"


def test_label_falls_back_to_raw_id_when_unknown():
    h = _hub()
    assert main._log_source_label(h, "unknown-uuid") == "unknown-uuid"


def test_label_survives_missing_hub_state():
    # A minimal fake hub (no .state / .agent_info) must not raise.
    bare = types.SimpleNamespace()
    assert main._log_source_label(bare, "x-1") == "x-1"


def test_collect_error_logs_uses_friendly_prefix():
    h = _hub(
        agent_info={"2068df1d-ca75-5dfb-a27e-d661b61485c1": {"hostname": "lm-agent-cppm"}},
        agent_logs={"2068df1d-ca75-5dfb-a27e-d661b61485c1": [
            "2026-08-21 15:36:43 - CPPMClient - ERROR - All OAuth2 attempts failed",
        ]},
    )
    errs = list(main.LabManagerHub.collect_error_logs(h)["logs"])
    assert any(e.startswith("[lm-agent-cppm (2068df1d)] ") for e in errs), errs
    # The raw bare-UUID prefix must NOT survive.
    assert not any(e.startswith("[2068df1d-ca75-5dfb-a27e-d661b61485c1]") for e in errs), errs
