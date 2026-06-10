from abc import ABC, abstractmethod
import logging
from typing import Any, Dict

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("BaseSpoke")

class BaseSpoke(ABC):
    """
    Abstract base class for all Lab Manager spokes.
    Every spoke must implement the core lifecycle and command methods.
    """
    def __init__(self, spoke_id: str, config: Dict[str, Any]):
        self.spoke_id = spoke_id
        self.config = config

    @abstractmethod
    async def handle_command(self, command_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Processes a command received from the Hub.
        Should return a result dictionary.
        """
        pass

    @abstractmethod
    async def get_status(self) -> Dict[str, Any]:
        """
        Returns the current status of the spoke's managed resources.
        """
        pass

    def log_info(self, message: str):
        logger.info(f"[{self.spoke_id}] {message}")

    def log_error(self, message: str):
        logger.error(f"[{self.spoke_id}] {message}")
