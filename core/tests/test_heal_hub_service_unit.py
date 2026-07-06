"""update_recovery.heal_hub_service_unit — idempotent lm.service migration.

Legacy lm.service was Type=oneshot running start_all.sh, which nohup-detached
the hub → MainPID=0 (no Restart/watchdog, unclean `systemctl restart`). The heal
migrates it to Type=exec running main.py directly. It runs from `clearpending`
(root-executed by lm-update-restart after every successful self-update), so it
propagates to existing hubs via normal auto-update with no manual step.
"""
import update_recovery as u  # noqa: E402  (core/src on sys.path via conftest)

LEGACY = (
    "[Unit]\nDescription=Lab Manager Orchestrator\n\n"
    "[Service]\nType=oneshot\nRemainAfterExit=yes\nUser=svc_lm\n"
    "WorkingDirectory=/opt/lm\nEnvironmentFile=-/opt/lm/.env\n"
    "Environment=LM_TLS_PORT=443\nAmbientCapabilities=CAP_NET_BIND_SERVICE\n"
    "ExecStart=/bin/bash /opt/lm/start_all.sh\n"
    'ExecStop=/usr/bin/pkill -f "core/src/main.py"\n'
    "Restart=on-failure\nRestartSec=10\n\n[Install]\nWantedBy=multi-user.target\n"
)


def test_heal_migrates_legacy_unit(tmp_path):
    p = tmp_path / "lm.service"
    p.write_text(LEGACY)
    assert u.heal_hub_service_unit(str(p)) is True
    out = p.read_text()
    assert "Type=exec" in out and "Type=oneshot" not in out
    assert "RemainAfterExit" not in out
    assert "ExecStop=" not in out
    assert "ExecStart=/opt/lm/core/venv/bin/python3 /opt/lm/core/src/main.py" in out
    assert "StandardOutput=append:/var/log/lm/hub.log" in out
    # Preserved settings
    assert "Environment=LM_TLS_PORT=443" in out
    assert "User=svc_lm" in out and "Restart=on-failure" in out


def test_heal_is_idempotent(tmp_path):
    p = tmp_path / "lm.service"
    p.write_text(LEGACY)
    assert u.heal_hub_service_unit(str(p)) is True
    assert u.heal_hub_service_unit(str(p)) is False  # already migrated → no-op


def test_heal_missing_unit_is_safe(tmp_path):
    assert u.heal_hub_service_unit(str(tmp_path / "nope.service")) is False


def test_heal_derives_base_from_workingdirectory(tmp_path):
    p = tmp_path / "lm.service"
    p.write_text(LEGACY.replace("/opt/lm", "/srv/lm"))
    assert u.heal_hub_service_unit(str(p)) is True
    assert "ExecStart=/srv/lm/core/venv/bin/python3 /srv/lm/core/src/main.py" in p.read_text()
