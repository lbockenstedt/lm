"""Drift guard: hub_discovery.py is vendored byte-identical from pxmx/agent/src/discovery.py."""
import hashlib
from pathlib import Path

# Same constant is pinned in pxmx/agent/tests/test_discovery_sync.py; bump both together.
EXPECTED_SHA = "5664e2693d483f25c37f643114c7dea39a1333bacf0d7fc67d73b322914c179e"


def test_lm_hub_discovery_in_sync():
    # Hash the vendored copy and compare with the pinned canonical hash.
    p = Path(__file__).resolve().parents[1] / "src" / "messaging" / "hub_discovery.py"
    got = hashlib.sha256(p.read_bytes()).hexdigest()
    assert got == EXPECTED_SHA, (
        f"hub_discovery.py ({got}) drifted from pxmx discovery.py ({EXPECTED_SHA}). "
        "Re-copy pxmx/agent/src/discovery.py over it and bump EXPECTED_SHA in both repos."
    )
