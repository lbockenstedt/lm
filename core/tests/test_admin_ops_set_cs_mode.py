"""``/admin/ops/set-cs-mode`` — the loopback lever that turns a pxmx node's
Client Simulation mode on/off without a browser admin session.

Why this matters: ``agent_config[<agent>].client_simulation.enabled`` is the
flag the hub's CS bridge tests before it will poll a host's command inbox at
all. With it off the bridge logs ``SKIP not-enabled`` and never relays, so VM
start/stop/delete sit ``pending`` forever. A hub state reset empties
``agent_config``; tenant inheritance then re-creates entries carrying ONLY
``tenant_id``, silently disabling every CS host at once.

These tests pin the merge semantics of ``apply_cs_mode_entry``, which must
match the WebUI route's merge in ``routes/pxmx.py`` — in particular that
flipping ``enabled`` never discards the ``usb_config`` / ``protected_vmids``
the bridge stored, and that setting a tenant also pins it.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from routes.admin_ops import apply_cs_mode_entry, _UNSET  # noqa: E402


def test_enabling_on_an_empty_entry_creates_the_block():
    out = apply_cs_mode_entry({}, True)
    assert out["client_simulation"]["enabled"] is True


def test_the_reset_shaped_entry_is_what_this_fixes():
    """The exact shape tenant inheritance leaves behind after a state reset:
    a tenant pin and NO ``enabled`` key at all -> undeliverable."""
    reset_shaped = {"client_simulation": {"tenant_id": "lrb"}}
    assert (reset_shaped["client_simulation"].get("enabled") or False) is False
    out = apply_cs_mode_entry(reset_shaped, True)
    assert out["client_simulation"]["enabled"] is True
    assert out["client_simulation"]["tenant_id"] == "lrb"


@pytest.mark.parametrize("value,expected", [
    (True, True), (False, False),
    (1, True), (0, False),
    ("yes", True), ("", False),
    (None, False),
])
def test_enabled_is_coerced_to_a_real_bool(value, expected):
    out = apply_cs_mode_entry({}, value)
    got = out["client_simulation"]["enabled"]
    assert got is expected
    assert isinstance(got, bool)


def test_bridge_owned_keys_survive_a_toggle():
    """Regression: a naive overwrite would wipe what the CS bridge stored."""
    entry = {"client_simulation": {"enabled": False, "tenant_id": "lrb",
                                   "usb_config": {"slots": 4},
                                   "protected_vmids": [101, 102]},
             "display_name": "pxmx-cs-svr-01",
             "managed_crontab": "* * * * * true"}
    out = apply_cs_mode_entry(entry, True)
    cs = out["client_simulation"]
    assert cs["usb_config"] == {"slots": 4}
    assert cs["protected_vmids"] == [101, 102]
    assert out["display_name"] == "pxmx-cs-svr-01"
    assert out["managed_crontab"] == "* * * * * true"


def test_omitting_tenant_keeps_the_existing_pin():
    entry = {"client_simulation": {"tenant_id": "lrb", "tenant_pinned": True}}
    out = apply_cs_mode_entry(entry, True, _UNSET)
    assert out["client_simulation"]["tenant_id"] == "lrb"
    assert out["client_simulation"]["tenant_pinned"] is True


def test_omitting_tenant_is_the_default():
    entry = {"client_simulation": {"tenant_id": "ra"}}
    assert apply_cs_mode_entry(entry, True)["client_simulation"]["tenant_id"] == "ra"


def test_setting_a_tenant_also_pins_it():
    out = apply_cs_mode_entry({}, True, "lrb")
    assert out["client_simulation"]["tenant_id"] == "lrb"
    assert out["client_simulation"]["tenant_pinned"] is True


def test_tenant_is_stripped():
    out = apply_cs_mode_entry({}, True, "  lrb  ")
    assert out["client_simulation"]["tenant_id"] == "lrb"


@pytest.mark.parametrize("blank", [None, "", "   "])
def test_explicit_blank_tenant_clears_and_unpins(blank):
    entry = {"client_simulation": {"tenant_id": "lrb", "tenant_pinned": True}}
    out = apply_cs_mode_entry(entry, True, blank)
    assert out["client_simulation"]["tenant_id"] is None
    assert out["client_simulation"]["tenant_pinned"] is False


def test_disabling_is_possible_too():
    entry = {"client_simulation": {"enabled": True, "tenant_id": "lrb"}}
    assert apply_cs_mode_entry(entry, False)["client_simulation"]["enabled"] is False


def test_helper_does_not_mutate_its_input():
    entry = {"client_simulation": {"enabled": False, "usb_config": {"slots": 1}}}
    snapshot = {"client_simulation": {"enabled": False, "usb_config": {"slots": 1}}}
    out = apply_cs_mode_entry(entry, True, "lrb")
    assert entry == snapshot, "input entry was mutated"
    assert out is not entry
    assert out["client_simulation"] is not entry["client_simulation"]


def test_none_entry_is_tolerated():
    assert apply_cs_mode_entry(None, True)["client_simulation"]["enabled"] is True


def test_shape_matches_the_webui_route_merge():
    """The UI route and this lever must write the same keys, or the Agents tile
    and the CS bridge would disagree about a host."""
    import re
    src = os.path.join(os.path.dirname(__file__), "..", "src", "routes", "pxmx.py")
    with open(src) as fh:
        body = fh.read()
    # Keys the UI route assigns into its cs_cfg.
    ui_keys = set(re.findall(r'cs_cfg\[[\'"]([a-z_]+)[\'"]\]\s*=', body))
    assert {"enabled", "tenant_id", "tenant_pinned"} <= ui_keys
    ours = set(apply_cs_mode_entry({}, True, "lrb")["client_simulation"])
    assert ours == {"enabled", "tenant_id", "tenant_pinned"}


def test_endpoint_is_registered_and_guarded():
    """The route must exist and go through the same _guard both other levers use."""
    import re
    src = os.path.join(os.path.dirname(__file__), "..", "src", "routes", "admin_ops.py")
    with open(src) as fh:
        body = fh.read()
    assert '@app.post("/admin/ops/set-cs-mode")' in body
    fn = body.split('@app.post("/admin/ops/set-cs-mode")', 1)[1]
    fn = fn.split("@app.post(", 1)[0]
    assert "_guard(request)" in fn, "set-cs-mode must enforce loopback + token"
    # ...and must not invent a second config shape.
    assert "apply_cs_mode_entry" in fn
    assert "push_pxmx_agent_config" in fn
