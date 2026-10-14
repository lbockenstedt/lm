"""DPA knob persistence/validation (dpa_config.DpaConfigStore)."""
import json
import stat

import dpa_config as dc
import dpa_ssh


def test_defaults_off_ssh_preferred(tmp_path):
    cfg = dc.DpaConfigStore(tmp_path / "dpa.json").effective()
    assert cfg["enabled"] is False
    assert cfg["ssh_enabled"] is True and cfg["telnet_enabled"] is False
    assert cfg["ssh_base"] == 3001 and cfg["telnet_bind"] == "127.0.0.1"


def test_legacy_role_config_still_means_telnet_on(tmp_path):
    cfg = dc.DpaConfigStore(tmp_path / "dpa.json", {
        "console_dpa_enabled": True, "console_dpa_bind": "10.0.0.5",
        "console_dpa_allow": "10.0.0.0/24"}).effective()
    assert cfg["enabled"] and cfg["telnet_enabled"]
    assert cfg["telnet_bind"] == "10.0.0.5" and cfg["allow"] == ["10.0.0.0/24"]


def test_update_persists_and_survives_restart_over_role_config(tmp_path):
    path = tmp_path / "dpa.json"
    st = dc.DpaConfigStore(path, {"console_dpa_enabled": False})
    ok, err = st.update({"enabled": True, "advertise_host": "con01.lab", "allow": "10.1.0.0/16"})
    assert ok, err
    again = dc.DpaConfigStore(path, {"console_dpa_enabled": False}).effective()
    assert again["enabled"] is True  # persisted knob beats load-time role config
    assert again["advertise_host"] == "con01.lab" and again["allow"] == ["10.1.0.0/16"]
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_password_is_hashed_and_never_public(tmp_path):
    st = dc.DpaConfigStore(tmp_path / "dpa.json")
    assert st.update({"password": "correct horse"})[0]
    raw = json.loads((tmp_path / "dpa.json").read_text())
    assert "correct horse" not in json.dumps(raw)
    assert dpa_ssh.verify_password("correct horse", raw["password_hash"])
    assert not dpa_ssh.verify_password("wrong", raw["password_hash"])
    pub = st.public()
    assert pub["has_password"] is True and "password_hash" not in pub
    assert st.update({"clear_password": True})[0]
    assert st.public()["has_password"] is False


def test_validation_errors(tmp_path):
    st = dc.DpaConfigStore(tmp_path / "dpa.json")
    assert not st.update({"password": "short"})[0]
    assert not st.update({"allow": "10.0.0.0/8, bogus"})[0]
    assert not st.update({"ssh_base": 80})[0]
    assert not st.update({"ssh_bind": "not-an-ip"})[0]
    assert not st.update({"advertise_host": "bad host"})[0]
    assert not st.update({"authorized_keys": "garbage"})[0]
    # unauthenticated telnet off-localhost needs an allow-list
    assert not st.update({"telnet_enabled": True, "telnet_bind": "0.0.0.0"})[0]
    assert st.update({"telnet_enabled": True, "telnet_bind": "0.0.0.0", "allow": ["10.0.0.0/8"]})[0]
    # overlapping windows rejected
    assert not st.update({"ssh_base": 2250})[0]


def test_blank_bind_falls_back_to_default(tmp_path):
    st = dc.DpaConfigStore(tmp_path / "dpa.json")
    assert st.update({"ssh_bind": "", "telnet_bind": ""})[0]
    cfg = st.effective()
    assert cfg["ssh_bind"] == "0.0.0.0" and cfg["telnet_bind"] == "127.0.0.1"


def test_detect_advertise_host_returns_non_loopback_or_empty():
    ip = dc.detect_advertise_host("wss://127.0.0.1:443")
    assert not ip.startswith("127.")
