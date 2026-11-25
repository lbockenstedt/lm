"""Keep Rogue DNS Burst controls and config fields wired into the hub UI."""

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
def test_rogue_dns_burst_flag_lists(pattern):
    """Each explicit sim list exposes the burst flag exactly once."""
    source = SIM_VIEWS.read_text(encoding="utf-8")
    match = re.search(pattern, source, re.DOTALL)
    assert match, f"UI list not found: {pattern}"
    assert re.findall(r"'([^']+)'", match.group(1)).count("rogue_dns_burst") == 1


@pytest.mark.parametrize(
    "section,key,label",
    [
        ("address", "rogue_dns_burst_server", "Rogue DNS Burst Server IP"),
        ("simulation", "rogue_dns_burst_dhcp_interval", "Rogue DNS Burst DHCP Interval (s)"),
        ("simulation", "rogue_dns_burst_duration", "Rogue DNS Burst Duration (s)"),
        ("simulation", "rogue_dns_burst_browse_interval", "Rogue DNS Burst Browse Interval (s)"),
        ("simulation", "rogue_dns_burst_rate", "Rogue DNS Burst Rate (queries/s)"),
        ("simulation", "rogue_dns_burst_max_pending", "Rogue DNS Burst Max In-Flight Queries"),
    ],
)
def test_rogue_dns_burst_scalar_fields(section, key, label):
    """Scalar burst fields sit once in their section."""
    source = SIM_VIEWS.read_text(encoding="utf-8")
    schema = source.split("const CS_SIM_SECTION_FIELDS = {", 1)[1].split("\n};", 1)[0]
    match = re.search(rf"\b{section}: \[(.*?)\n    \]", schema, re.DOTALL)
    assert match, f"UI section not found: {section}"
    assert match.group(1).count(f"['{key}', '{label}']") == 1
    assert schema.count(f"['{key}',") == 1


def test_rogue_dns_burst_domains_is_list():
    """The domain list is a multi-value 'list' field in the address section."""
    source = SIM_VIEWS.read_text(encoding="utf-8")
    assert source.count(
        "['rogue_dns_burst_domains', 'Rogue DNS Burst Domains (one per line)', 'list']"
    ) == 1


def test_on_off_editor_keeps_true_and_one_as_on():
    """true/1 (accepted by the runtime) must render as on, not as the unset default."""
    source = SIM_VIEWS.read_text(encoding="utf-8")
    assert source.count("['on', 'true', '1'].includes(lc)") == 2
    assert "lc === 'on', off" not in source
