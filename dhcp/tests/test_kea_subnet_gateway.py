"""The scope gateway (NetBox free text) must never break the Kea config-set.

Kea rejects the whole config when one ``routers`` option is malformed and keeps
its old config, so a scope saved with "172.21.0.1/24" never got a gateway.
"""

import kea_manager
from kea_manager import build_subnet4, scope_gateway_findings


def _routers(gateway):
    subnets, _, _ = build_subnet4([{"subnet": "172.21.0.0/24", "gateway": gateway}], [])
    return [o["data"] for o in subnets[0]["option-data"] if o["name"] == "routers"]


def test_gateway_with_a_mask_is_sent_as_a_bare_address():
    assert _routers(" 172.21.0.1/24 ") == ["172.21.0.1"]


def test_unusable_gateway_is_dropped_not_sent_to_kea():
    assert _routers("172.21.0.x") == []
    assert _routers("fe80::1") == []
    assert _routers("") == []


def test_plain_gateway_is_unchanged():
    assert _routers("172.21.0.1") == ["172.21.0.1"]


def test_scope_without_gateway_is_logged_at_sync(caplog):
    build_subnet4([{"subnet": "172.21.0.0/24"}, {"subnet": "10.0.0.0/24", "gateway": "10.0.0.1"}], [])
    assert "no default gateway" in caplog.text and "172.21.0.0/24" in caplog.text
    assert "10.0.0.0/24" not in caplog.text


def test_diagnostics_names_scopes_without_a_usable_gateway():
    config = {"subnet4": [
        {"subnet": "172.21.0.0/24", "option-data": []},
        {"subnet": "10.0.0.0/24", "option-data": [{"name": "routers", "data": "10.0.0.1"}]},
        {"subnet": "10.0.1.0/24", "option-data": [{"name": "routers", "data": "10.0.9.1"}]},
    ]}
    gateways, problems = scope_gateway_findings(config)
    assert gateways == {"172.21.0.0/24": "", "10.0.0.0/24": "10.0.0.1", "10.0.1.0/24": "10.0.9.1"}
    assert len(problems) == 2
    assert "172.21.0.0/24 hands out no default gateway" in problems[0]
    assert "10.0.1.0/24 gateway 10.0.9.1 is outside" in problems[1]


def test_global_router_covers_scopes_without_their_own():
    config = {"option-data": [{"name": "routers", "data": "172.21.0.1"}],
              "subnet4": [{"subnet": "172.21.0.0/24"}]}
    assert scope_gateway_findings(config) == ({"172.21.0.0/24": "172.21.0.1"}, [])


def test_self_heal_aligns_config_dir_mode(tmp_path, monkeypatch):
    conf_dir = tmp_path / "kea"
    conf_dir.mkdir(mode=0o750)
    conf_dir.chmod(0o750)
    monkeypatch.setattr(kea_manager.KeaManager, "_CONFIG_DIR", str(conf_dir))
    km = kea_manager.KeaManager.__new__(kea_manager.KeaManager)
    assert km._heal_config_dir_mode() == [f"set {conf_dir} mode 750 -> 755"]
    assert conf_dir.stat().st_mode & 0o777 == 0o755
    assert km._heal_config_dir_mode() == []


def test_gateway_is_carved_out_of_default_pool():
    subnets, _, _ = build_subnet4([{"subnet": "172.21.0.0/24", "gateway": "172.21.0.254"}], [])
    assert subnets[0]["pools"] == [{"pool": "172.21.0.10 - 172.21.0.253"}]


def test_gateway_outside_pool_leaves_pools_alone():
    subnets, _, _ = build_subnet4([{"subnet": "172.21.0.0/24", "gateway": "172.21.0.1"}], [])
    assert subnets[0]["pools"] == [{"pool": "172.21.0.10 - 172.21.0.254"}]


def test_hold_declined_toggles_probation_and_persists(tmp_path, monkeypatch):
    path = tmp_path / "kea-settings.json"
    monkeypatch.setattr(kea_manager, "DHCP_SETTINGS_PATH", str(path))
    monkeypatch.setitem(kea_manager.DHCP4_COORDINATOR_GLOBALS, "decline-probation-period",
                        kea_manager.DECLINE_PROBATION_SHORT)
    kea_manager.set_hold_declined(True)
    assert kea_manager.DHCP4_COORDINATOR_GLOBALS["decline-probation-period"] == 86400
    assert kea_manager._read_hold_declined() is True
    kea_manager.set_hold_declined(False)
    assert kea_manager.DHCP4_COORDINATOR_GLOBALS["decline-probation-period"] == 60
    assert kea_manager._read_hold_declined() is False


class _DeclineMgr(kea_manager.KeaManager):
    """KeaManager over a fixed lease table; records lease4-del calls."""

    def __init__(self, period):
        self.period, self.deleted = period, []
        self.leases = [
            {"ip-address": "10.21.0.10", "state": 1, "valid-lft": 86400},  # held under the old 24h
            {"ip-address": "10.21.0.11", "state": 1, "valid-lft": 60},     # current probation
            {"ip-address": "10.21.0.12", "state": 0, "valid-lft": 86400},  # active lease
        ]

    def get_config(self):
        return {"decline-probation-period": self.period}

    def list_leases(self, subnet=None):
        return self.leases

    def delete_lease(self, ip):
        self.deleted.append(ip)


def test_declines_held_past_the_current_probation_are_released():
    mgr = _DeclineMgr(period=60)
    assert mgr.release_held_declines()["released"] == ["10.21.0.10"]
    assert mgr.deleted == ["10.21.0.10"]


def test_declines_are_kept_while_hold_is_on():
    mgr = _DeclineMgr(period=86400)
    assert mgr.release_held_declines()["released"] == []


def test_release_all_frees_every_declined_address_but_no_active_lease():
    mgr = _DeclineMgr(period=86400)
    assert mgr.release_held_declines(release_all=True)["released"] == ["10.21.0.10", "10.21.0.11"]
