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

import time
from enum import Enum
from typing import Dict

class SpokeStatus(Enum):
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
    def __init__(self):
        # { spoke_id: last_seen_timestamp }
        self.last_seen: Dict[str, float] = {}

    def update_heartbeat(self, spoke_id: str):
        """Updates the last seen timestamp for a spoke."""
        self.last_seen[spoke_id] = time.time()

    def get_status(self, spoke_id: str) -> SpokeStatus:
        """Calculates the traffic light status based on the last heartbeat."""
        last_seen = self.last_seen.get(spoke_id)
        if last_seen is None:
            return SpokeStatus.RED

        elapsed = time.time() - last_seen

        if elapsed < 120:
            return SpokeStatus.GREEN
        elif elapsed < 300:
            return SpokeStatus.YELLOW
        else:
            return SpokeStatus.RED

    def get_all_statuses(self) -> Dict[str, SpokeStatus]:
        """Returns statuses for all tracked spokes."""
        return {spoke_id: self.get_status(spoke_id) for spoke_id in self.last_seen}
