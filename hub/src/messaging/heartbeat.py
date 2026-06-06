import time
from enum import Enum
from typing import Dict

class SpokeStatus(Enum):
    GREEN = "GREEN"     # Healthy: < 120s
    YELLOW = "YELLOW"   # Warning: 120s <= t < 300s
    RED = "RED"         # Offline: >= 300s

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
