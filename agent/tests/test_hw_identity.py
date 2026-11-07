"""Agent hardware-serial collection: junk filtering and DMI read."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import hw_identity  # noqa: E402


def test_sanitize_drops_placeholders_and_vm_serials():
    assert hw_identity.sanitize_serial(" 2m292101k3\n") == "2M292101K3"
    for bad in ("", "Not Specified", "To Be Filled By O.E.M.", "None", "Default string",
                "00000000", "VMware-56 4d 1a", "Not Applicable", "x"):
        assert hw_identity.sanitize_serial(bad) == "", bad


def test_collect_reads_dmi_and_skips_junk(tmp_path, monkeypatch):
    (tmp_path / "product_serial").write_text("CZ2M292101K3\n")
    (tmp_path / "sys_vendor").write_text("HPE\n")
    monkeypatch.setattr(hw_identity, "_DMI", str(tmp_path))
    hw_identity._cache.update(at=0.0, val=None)
    assert hw_identity.collect_hw_identity() == {"hw_serial": "CZ2M292101K3", "hw_manufacturer": "HPE"}
    (tmp_path / "product_serial").write_text("To Be Filled By O.E.M.\n")
    hw_identity._cache.update(at=0.0, val=None)
    monkeypatch.setattr(hw_identity, "_dmidecode", lambda k: "")
    assert hw_identity.collect_hw_identity() == {}
