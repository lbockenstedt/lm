"""Failed agent ops (fleet reclone / delete per-VM CS_PROGRESS results and
failed CS_COMMAND_RESULT terminals) must land in hub.log with their reason, so
a "VM 90012 · failed" row is diagnosable from the hub. Only whitelisted fields
are logged — never the raw payload (CS_TOKEN_RESULT can carry a secret)."""
import logging

from main import _log_cs_op_failure


def test_failed_progress_logs_reason(caplog):
    with caplog.at_level(logging.WARNING):
        _log_cs_op_failure("agent=pxmx-cs-svr-01", "CS_PROGRESS", {
            "action": "proxmox_reclone_all", "status": "running", "vmid": 90012,
            "name": "kuser", "result": "failed", "cs_cmd_id": "abc",
            "error": "cloning from template 100 failed: no such VM"})
    msg = caplog.text
    assert "CS op failed" in msg and "vmid=90012" in msg
    assert "cloning from template 100 failed" in msg


def test_failed_terminal_logs_message(caplog):
    with caplog.at_level(logging.WARNING):
        _log_cs_op_failure("agent=a", "CS_COMMAND_RESULT", {
            "action": "delete_vm", "status": "failed", "vmid": 90009,
            "message": "VM 90009 destroy failed (attempt 1/3)"})
    assert "destroy failed (attempt 1/3)" in caplog.text


def test_success_and_secrets_not_logged(caplog):
    with caplog.at_level(logging.DEBUG):
        _log_cs_op_failure("agent=a", "CS_PROGRESS", {
            "action": "proxmox_reclone_all", "status": "running",
            "result": "completed", "vmid": 90001})
        _log_cs_op_failure("agent=a", "CS_COMMAND_RESULT", {
            "action": "token", "status": "failed", "secret": "s3cr3t-token"})
    assert "vmid=90001" not in caplog.text
    assert "s3cr3t-token" not in caplog.text
