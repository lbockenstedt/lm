"""Migration: the legacy ``bugfixer_cert_identities`` pinned-identity list is
carried forward to ``ab_cert_identities`` on load, so HUB_REQUEST authz keeps
recognizing the AppBuilder client after the BugFixer->AppBuilder rename."""
import pytest

from state.manager import StateManager


@pytest.fixture
def store(tmp_path):
    s = StateManager()
    s.system_path = str(tmp_path / "system.json")
    s.tenants_path = str(tmp_path / "tenants.json")
    return s


def _seed(store, global_config):
    store.system_state = {"global_config": global_config}
    store._save_file(store.system_path, store.system_state)


def test_legacy_cert_identities_migrated(store):
    _seed(store, {"bugfixer_cert_identities": ["ab.lm.io", "fixer.lm.io"]})
    store.load_state()
    gc = store.system_state["global_config"]
    assert gc.get("ab_cert_identities") == ["ab.lm.io", "fixer.lm.io"]
    assert "bugfixer_cert_identities" not in gc


def test_new_key_not_overwritten_by_legacy(store):
    # If both exist (partial migration), the new key wins and legacy is left as-is.
    _seed(store, {"bugfixer_cert_identities": ["old"], "ab_cert_identities": ["new"]})
    store.load_state()
    gc = store.system_state["global_config"]
    assert gc.get("ab_cert_identities") == ["new"]


def test_no_legacy_key_is_noop(store):
    _seed(store, {"ab_cert_identities": ["ab.lm.io"]})
    store.load_state()
    gc = store.system_state["global_config"]
    assert gc.get("ab_cert_identities") == ["ab.lm.io"]
    assert "bugfixer_cert_identities" not in gc
