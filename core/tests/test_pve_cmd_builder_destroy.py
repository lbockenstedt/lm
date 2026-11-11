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


def _run_with_fake_pvesh(cmd, status_json, tmp_path):
    import subprocess
    fake = tmp_path / "pvesh"
    fake.write_text("#!/bin/sh\necho \"$@\" >> \"$(dirname \"$0\")/calls\"\n"
                    "case \"$1\" in create|delete) echo '\"UPID:n:1:2:3:qmsnapshot:1:root@pam:\"';;\n"
                    f"get) echo '{status_json}';; esac\n")
    fake.chmod(0o755)
    env = {"PATH": f"{tmp_path}:/usr/bin:/bin"}
    r = subprocess.run(["sh", "-c", cmd], env=env, capture_output=True, text=True)
    return r, (tmp_path / "calls").read_text()


def test_snapshot_cmd_targets_vm_node_via_cluster_api(tmp_path):
    cmd = pve_cmd_builder.snapshot_cmd("PXMX-R06-01", 10199, "qemu", "lm-prepatch-1")
    r, calls = _run_with_fake_pvesh(cmd, '{"status": "stopped", "exitstatus": "OK"}', tmp_path)
    assert r.returncode == 0, r.stderr
    assert "create /nodes/PXMX-R06-01/qemu/10199/snapshot --snapname lm-prepatch-1" in calls
    assert "get /nodes/PXMX-R06-01/tasks/UPID:n:1:2:3:qmsnapshot:1:root@pam:/status" in calls


def test_snapshot_cmd_fails_when_task_fails(tmp_path):
    cmd = pve_cmd_builder.snapshot_cmd("n1", 5, "lxc", "s")
    r, calls = _run_with_fake_pvesh(cmd, '{"status":"stopped","exitstatus":"snapshot error"}', tmp_path)
    assert r.returncode == 1 and "failed" in r.stderr
    assert "/nodes/n1/lxc/5/snapshot" in calls


def test_delete_snapshot_cmd_uses_node_when_known():
    assert pve_cmd_builder.delete_snapshot_cmd(5, "qemu", "s") == "qm delsnapshot 5 s"
    assert "pvesh delete /nodes/n1/qemu/5/snapshot/s" in pve_cmd_builder.delete_snapshot_cmd(5, "qemu", "s", "n1")


def test_vm_entry_carries_configured_memory():
    # The NetBox VM sync needs maxmem (configured), not mem (live usage).
    e = pve_cmd_builder._vm_entry({"mem": 3_000_000_000, "maxmem": 4294967296},
                                  "n1", "qemu", 100, "A", {})
    assert e["maxmem_bytes"] == 4294967296
