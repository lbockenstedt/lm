"""Keep Rogue DNS controls and scalar config fields wired into the hub UI."""

from pathlib import Path
import re

import pytest


SIM_VIEWS = Path(__file__).resolve().parents[2] / "WebUI" / "sim-views.js"


@pytest.mark.parametrize(
    "pattern",
    [
        r"names\.push\((.*?)\);",
        r"const CS_CONTROL_FLAGS = \[(.*?)\];",
        r"const CS_ONOFF_KEYS = new Set\(\[(.*?)\]\);",
        r"const CS_SIM_BUCKET_FIELDS = \[(.*?)\n\];",
    ],
    ids=["default-names", "client-controls", "on-off-editor", "bucket-editor"],
)
def test_rogue_dns_flag_lists(pattern):
    """Each explicit sim list exposes the independent Rogue DNS flag once."""
    source = SIM_VIEWS.read_text(encoding="utf-8")
    match = re.search(pattern, source, re.DOTALL)
    assert match, f"UI list not found: {pattern}"
    assert re.findall(r"'([^']+)'", match.group(1)).count("rogue_dns") == 1


@pytest.mark.parametrize(
    "section,key,label",
    [
        ("address", "rogue_dns_server", "Rogue DNS Server IP"),
        ("simulation", "rogue_dns_dhcp_interval", "Rogue DNS DHCP Interval (s)"),
        ("simulation", "rogue_dns_duration", "Rogue DNS Duration (s)"),
        ("simulation", "rogue_dns_browse_interval", "Rogue DNS Browse Interval (s)"),
    ],
)
def test_rogue_dns_scalar_fields(section, key, label):
    """DNS is one server, not a list; all timing fields belong to simulation."""
    source = SIM_VIEWS.read_text(encoding="utf-8")
    schema = source.split("const CS_SIM_SECTION_FIELDS = {", 1)[1].split("\n};", 1)[0]
    match = re.search(rf"\b{section}: \[(.*?)\n    \]", schema, re.DOTALL)
    assert match, f"UI section not found: {section}"
    assert match.group(1).count(f"['{key}', '{label}']") == 1
    assert schema.count(f"['{key}',") == 1
