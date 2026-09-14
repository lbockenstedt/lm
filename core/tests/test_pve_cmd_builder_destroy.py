"""``pve_cmd_builder.vm_destroy_cmd`` — the shared builder for the Hypervisors
view's Delete action.

The pxmx spoke builds qm/pct command STRINGS and sends them to the dumb Agent as
RUN_COMMAND. The agent-rework #4 migration ported start/stop/snapshot/reboot/
backup but not ``destroy``, so Delete failed for every VM with "unknown vm
action: destroy". These pin the command the spoke must emit — a golden compare
against the argv the Agent's typed handler ran locally
(``pxmx/agent/src/pve_cmds.py``: ``[bin_, "destroy", str(vid), "--purge"]``).
"""

import pve_cmd_builder


def test_destroy_qemu_uses_qm_with_purge():
    assert pve_cmd_builder.vm_destroy_cmd(9001, "qemu") == "qm destroy 9001 --purge"


def test_destroy_container_uses_pct_with_purge():
    assert pve_cmd_builder.vm_destroy_cmd(9002, "lxc") == "pct destroy 9002 --purge"


def test_destroy_defaults_to_qm_for_unknown_kind():
    # kind_from_probe only ever returns qemu/lxc, but an unset/garbage kind must
    # not silently build a pct command for a VM.
    assert pve_cmd_builder.vm_destroy_cmd(9003, "") == "qm destroy 9003 --purge"


def test_destroy_coerces_string_vmid():
    assert pve_cmd_builder.vm_destroy_cmd("9004", "qemu") == "qm destroy 9004 --purge"


def test_destroy_rejects_non_numeric_vmid():
    # int() guards command injection via the vmid — no shell metacharacter can
    # survive into the RUN_COMMAND string.
    for bad in ("9001; rm -rf /", "abc", None):
        try:
            pve_cmd_builder.vm_destroy_cmd(bad, "qemu")
        except (ValueError, TypeError):
            continue
        raise AssertionError(f"vmid {bad!r} was not rejected")


def test_stop_precedes_destroy_via_vm_action_cmd():
    # destroy FAILS on a running guest; the spoke issues this stop first.
    assert pve_cmd_builder.vm_action_cmd(9001, "stop", "qemu") == "qm stop 9001"
    assert pve_cmd_builder.vm_action_cmd(9002, "stop", "lxc") == "pct stop 9002"
