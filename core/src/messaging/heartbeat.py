"""LM Hub liveness tracking — the spoke heartbeat traffic-light.

``HeartbeatManager`` records the last-seen timestamp per spoke (updated from
``main.py handle_connection`` on every authenticated frame, including
heartbeats) and derives a GREEN/YELLOW/RED status from the elapsed time. This
status feeds the Setup → Spokes WebUI cards and, critically, the spoke
recovery watchdog.

Sister modules in the messaging layer: ``protocol.py`` defines the message
envelope that carries heartbeats on the wire, and ``mailbox.py`` handles
delivery/retry/ack for non-heartbeat traffic.
"""

# time.time() supplies the wall-clock timestamps used to measure heartbeat age.
import time
# Enum gives the three traffic-light states fixed, comparable names.
from enum import Enum
# Type hints only; they document the shape of the per-spoke timestamp map.
from typing import Dict

class SpokeStatus(Enum):
    """Traffic-light health of a spoke, derived from how long ago it was last heard from."""
    # Each member's value equals its name so it serialises cleanly to JSON for the WebUI.
    GREEN = "GREEN"     # Healthy: < 120s
    YELLOW = "YELLOW"   # Warning: 120s <= t < 300s
    RED = "RED"         # Offline: >= 300s
    # The 300s RED threshold is load-bearing for the recovery/watchdog loop in
    # core/src/main.py run_spoke_recovery_loop: that loop only acts on spokes
    # that are both approved-but-disconnected AND heartbeat-stale (RED,
    # >= ~300s). Lowering this threshold would cause premature recovery
    # attempts; raising it would delay recovery of stranded spokes. Keep the
    # 300s boundary in sync with the watchdog's staleness check.

class HeartbeatManager:
    """Tracks when each spoke was last heard from and turns that into a SpokeStatus."""
    def __init__(self):
        """Start with no spokes tracked; entries appear on the first frame from each spoke."""
        # { spoke_id: last_seen_timestamp }
        self.last_seen: Dict[str, float] = {}

    def update_heartbeat(self, spoke_id: str):
        """Updates the last seen timestamp for a spoke."""
        # Overwrite (not append) because only the most recent contact time matters.
        self.last_seen[spoke_id] = time.time()

    def get_status(self, spoke_id: str) -> SpokeStatus:
        """Calculates the traffic light status based on the last heartbeat."""
        # A spoke that has never been heard from is treated as offline.
        last_seen = self.last_seen.get(spoke_id)
        if last_seen is None:
            return SpokeStatus.RED

        # Seconds since the spoke's last frame.
        elapsed = time.time() - last_seen

        # Under 2 minutes: healthy.
        if elapsed < 120:
            return SpokeStatus.GREEN
        # Between 2 and 5 minutes: probably a hiccup, show a warning.
        elif elapsed < 300:
            return SpokeStatus.YELLOW
        # 5 minutes or more: considered offline (drives the recovery watchdog).
        else:
            return SpokeStatus.RED

    def get_all_statuses(self) -> Dict[str, SpokeStatus]:
        """Returns statuses for all tracked spokes."""
        # Build {spoke_id: status} for every spoke that has ever sent a frame.
        return {spoke_id: self.get_status(spoke_id) for spoke_id in self.last_seen}
