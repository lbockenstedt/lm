"""Syslog deploy roles on the generic agent: the role maps, the installer flags
the hub's LOAD_ROLE config becomes, and that secrets never reach a log line."""
import agent_spoke
from agent_spoke import (GenericAgent, _DEPLOY_ROLES, _DEPLOY_ROLE_MARKERS,
                         _DEPLOY_ROLE_PURGE, _DEPLOY_ROLE_UNITS, _ROLE_LOG_PREFIXES,
                         _ROLE_MAP)


def test_syslog_spoke_role_and_deploy_roles_are_registered():
    """The spoke role, both deploy roles and their marker/unit/purge rows exist."""
    assert _ROLE_MAP["syslog"][1:3] == ("SyslogSpoke", "logging")
    assert _ROLE_LOG_PREFIXES["syslog"] == ("Syslog",)
    for role in ("syslog-collector", "syslog-graylog"):
        assert _DEPLOY_ROLES[role]["module_type"] == "agent"
        assert role in _DEPLOY_ROLE_MARKERS and role in _DEPLOY_ROLE_UNITS
        assert role in _DEPLOY_ROLE_PURGE
    # rsyslog is a base package: never purged.
    assert _DEPLOY_ROLE_PURGE["syslog-collector"]["packages"] == ()
    assert "/etc/lm-syslog" in _DEPLOY_ROLE_PURGE["syslog-collector"]["paths"]


def test_collector_flags_write_pems_and_quote_values(tmp_path, monkeypatch):
    """PEMs land on disk; only their paths and the quoted tenant reach the command."""
    monkeypatch.setattr(agent_spoke, "Path", lambda p: tmp_path / p.strip("/"))
    agent = GenericAgent.__new__(GenericAgent)
    cmd = agent._build_deploy_cmd("syslog-collector", _DEPLOY_ROLES["syslog-collector"], {
        "tenant": "acme; rm -rf /", "tls_ca_pem": "CA", "tls_cert_pem": "CERT",
        "tls_key_pem": "PRIVATE-KEY"})
    line = cmd[-1]
    assert "install_syslog_collector.sh" in line
    assert "--tenant 'acme; rm -rf /'" in line
    assert "PRIVATE-KEY" not in line
    key = tmp_path / "etc/lm-syslog/tls/lm-key.pem"
    assert key.read_text() == "PRIVATE-KEY" and oct(key.stat().st_mode)[-3:] == "600"


def test_graylog_passwords_go_in_files_not_the_command_line(tmp_path, monkeypatch):
    """Both Graylog passwords are written to 0600 files; only the paths reach the
    command, which any local user can read in the process list."""
    monkeypatch.setattr(agent_spoke, "Path", lambda p: tmp_path / p.strip("/"))
    agent = GenericAgent.__new__(GenericAgent)
    cmd = agent._build_deploy_cmd("syslog-graylog", _DEPLOY_ROLES["syslog-graylog"], {
        "admin_password": "adm-SECRET", "reader_password": "rdr-SECRET"})
    line = cmd[-1]
    assert "SECRET" not in line
    secrets = tmp_path / "etc/lm-syslog/secrets"
    for key, value in (("admin_password", "adm-SECRET"), ("reader_password", "rdr-SECRET")):
        path = secrets / key
        assert f"--{key.replace('_', '-')}-file {path}" in line
        assert path.read_text() == value and oct(path.stat().st_mode)[-3:] == "600"
    assert oct(secrets.stat().st_mode)[-3:] == "700"


def test_no_config_leaves_the_bare_installer():
    """Without config nothing is appended after --infra-only."""
    agent = GenericAgent.__new__(GenericAgent)
    cmd = agent._build_deploy_cmd("syslog-graylog", _DEPLOY_ROLES["syslog-graylog"], {})
    assert cmd[-1].endswith("--infra-only")
