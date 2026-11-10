"""Keep the Network Diagnostics flag wired like the existing web-traffic sim."""

from pathlib import Path
import re

import pytest


SIM_VIEWS = Path(__file__).resolve().parents[2] / "WebUI" / "sim-views.js"


@pytest.mark.parametrize(
    "pattern",
    [
        r"const CS_CONTROL_FLAGS = \[(.*?)\];",
        r"const CS_ONOFF_KEYS = new Set\(\[(.*?)\]\);",
        r"const CS_SIM_BUCKET_FIELDS = \[(.*?)\n\];",
        r"randomizable_sims: Array\.isArray\(cfg && cfg\.randomizable_sims\).*?"
        r": \[(.*?)\]",
    ],
    ids=["client-controls", "on-off-editor", "bucket-editor", "randomizable-list"],
)
def test_www_discover_follows_www_traffic(pattern):
    """Every web-traffic UI list exposes the independent discover flag once."""
    source = SIM_VIEWS.read_text(encoding="utf-8")
    match = re.search(pattern, source, re.DOTALL)
    assert match, f"UI list not found: {pattern}"
    keys = re.findall(r"'([^']+)'", match.group(1))
    assert keys.count("www_traffic") == 1
    assert keys.count("www_discover") == 1
    if "WWW Discover - Network Diagnostics" in keys:
        assert keys[keys.index("www_discover") + 1] == "WWW Discover - Network Diagnostics"
    else:
        assert abs(keys.index("www_traffic") - keys.index("www_discover")) == 1
