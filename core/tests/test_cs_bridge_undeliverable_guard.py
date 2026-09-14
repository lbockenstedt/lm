"""A VM action aimed at a host whose CS bridge is disabled must fail loudly.

Regression: every ``pxmx-cs-svr-0X`` agent lost its
``client_simulation.enabled`` flag (a hub state reset re-created agent_config
from tenant inheritance without it), so the CS bridge logged ``SKIP
not-enabled`` for all of them and never polled their inboxes. VM deletes queued
from the VM Server tab therefore sat ``pending`` with ``relay_attempts: 0``
until they expired — while the UI happily reported "delete_vm queued". The
guard turns that silent black hole into a 409 naming the host and the fix.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from simulations.helpers import bridge_undeliverable_message  # noqa: E402


def _row(hostname, decision):
    return {"hostname": hostname, "decision": decision}


SKIP = ("SKIP not-enabled — client_simulation.enabled not set under agent_config "
        "key 'pxmx-cs-svr-04' or 'pxmx-cs-svr-04'")
ACTIVE = "ACTIVE — tenant=lrb cs_spoke=6a0a3f9d"


def test_disabled_host_is_blocked_and_named():
    msg = bridge_undeliverable_message([_row("pxmx-cs-svr-04", SKIP)],
                                       ["pxmx-cs-svr-04"])
    assert msg
    assert "pxmx-cs-svr-04" in msg
    assert "Client Simulation mode is disabled" in msg


def test_active_host_is_not_blocked():
    assert bridge_undeliverable_message([_row("pxmx-cs-svr-04", ACTIVE)],
                                        ["pxmx-cs-svr-04"]) == ""


def test_other_skip_reasons_do_not_block():
    """Only ``SKIP not-enabled`` is the permanent config gate. ``SKIP
    no-cs-spoke`` is transient (the spoke can reconnect), so the command should
    still queue rather than be refused."""
    rows = [_row("pxmx-cs-svr-04",
                 "SKIP no-cs-spoke — client_simulation.enabled=on but no "
                 "client-sim spoke is bound to tenant 'lrb'")]
    assert bridge_undeliverable_message(rows, ["pxmx-cs-svr-04"]) == ""


def test_unknown_host_is_not_blocked():
    """The bridge hasn't seen this host (agent offline / first boot). Queuing is
    exactly the right behavior — the queue exists to ride that out."""
    assert bridge_undeliverable_message([_row("pxmx-cs-svr-04", SKIP)],
                                        ["pxmx-cs-svr-09"]) == ""


def test_no_rows_never_blocks():
    assert bridge_undeliverable_message([], ["pxmx-cs-svr-04"]) == ""
    assert bridge_undeliverable_message(None, ["pxmx-cs-svr-04"]) == ""


def test_bulk_blocks_only_when_every_target_is_disabled():
    rows = [_row("pxmx-cs-svr-04", SKIP), _row("pxmx-cs-svr-05", ACTIVE)]
    # One reachable target → let the whole batch queue (partial delivery beats
    # refusing an operator's multi-host bulk outright).
    assert bridge_undeliverable_message(rows, ["pxmx-cs-svr-04",
                                               "pxmx-cs-svr-05"]) == ""


def test_bulk_all_disabled_names_every_host():
    rows = [_row("pxmx-cs-svr-04", SKIP), _row("pxmx-cs-svr-05", SKIP)]
    msg = bridge_undeliverable_message(rows, ["pxmx-cs-svr-05", "pxmx-cs-svr-04"])
    assert "pxmx-cs-svr-04" in msg and "pxmx-cs-svr-05" in msg


def test_fqdn_and_short_name_match_each_other():
    rows = [_row("pxmx-cs-svr-04.lab.example.com", SKIP)]
    assert bridge_undeliverable_message(rows, ["pxmx-cs-svr-04"])
    rows = [_row("pxmx-cs-svr-04", SKIP)]
    assert bridge_undeliverable_message(rows, ["pxmx-cs-svr-04.lab.example.com"])


def test_hostname_match_is_case_and_dot_insensitive():
    rows = [_row("PXMX-CS-SVR-04", SKIP)]
    assert bridge_undeliverable_message(rows, ["pxmx-cs-svr-04."])


def test_placeholder_target_is_ignored():
    """``proxmox`` is the queue's "the spoke's primary host" placeholder, not a
    hostname the bridge ever reports — it must never be blocked."""
    assert bridge_undeliverable_message([_row("pxmx-cs-svr-04", SKIP)],
                                        ["proxmox"]) == ""
    assert bridge_undeliverable_message([_row("pxmx-cs-svr-04", SKIP)],
                                        ["", None]) == ""


def test_duplicate_rows_block_only_if_all_are_skipped():
    """An agent can appear twice (reconnected under a second id). If ANY row is
    active the host is reachable."""
    rows = [_row("pxmx-cs-svr-04", SKIP), _row("pxmx-cs-svr-04", ACTIVE)]
    assert bridge_undeliverable_message(rows, ["pxmx-cs-svr-04"]) == ""
    rows = [_row("pxmx-cs-svr-04", SKIP), _row("pxmx-cs-svr-04", SKIP)]
    assert bridge_undeliverable_message(rows, ["pxmx-cs-svr-04"])


def test_malformed_rows_are_tolerated():
    rows = ["nope", None, {}, {"hostname": ""}, _row("pxmx-cs-svr-04", SKIP)]
    assert bridge_undeliverable_message(rows, ["pxmx-cs-svr-04"])


def test_message_tells_the_operator_what_to_do():
    msg = bridge_undeliverable_message([_row("pxmx-cs-svr-04", SKIP)],
                                       ["pxmx-cs-svr-04"])
    assert "Client Simulation mode on this host" in msg


@pytest.mark.parametrize("targets", [set(), (), None])
def test_empty_target_set_never_blocks(targets):
    assert bridge_undeliverable_message([_row("pxmx-cs-svr-04", SKIP)],
                                        targets) == ""
