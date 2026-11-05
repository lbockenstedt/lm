"""Abstract base class shared by every Lab Manager spoke.

A spoke is a worker process that receives commands from the Hub and reports status back. This
module defines the minimum interface (handle_command / get_status) every spoke must provide,
plus small logging helpers that tag messages with the spoke id.
"""
# ABC/abstractmethod let us declare methods that every concrete spoke must override.
from abc import ABC, abstractmethod
# Standard-library logging, used by the log_info/log_error helpers below.
import logging
# Type hints only; they document the dictionary shapes passed to and from spokes.
from typing import Any, Dict

# Root logger is configured once by the process entrypoint (hub main.py, or the
# spoke's own main). Library modules must not call basicConfig — doing so from
# an imported module either no-ops (root already configured) or, worse, pre-empts
# the entrypoint's format/level if imported first. Just grab a named logger.
logger = logging.getLogger("BaseSpoke")

class BaseSpoke(ABC):
    """
    Abstract base class for all Lab Manager spokes.
    Every spoke must implement the core lifecycle and command methods.
    """
    def __init__(self, spoke_id: str, config: Dict[str, Any]):
        """Store the spoke's identity and its configuration for subclasses to use."""
        # Remember which spoke this is so log lines and replies can name it.
        self.spoke_id = spoke_id
        # Keep the spoke's configuration dictionary for subclasses to read settings from.
        self.config = config

    @abstractmethod
    async def handle_command(self, command_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Processes a command received from the Hub.
        Should return a result dictionary.
        """
        # Abstract method: concrete spokes supply the real implementation.
        pass

    @abstractmethod
    async def get_status(self) -> Dict[str, Any]:
        """
        Returns the current status of the spoke's managed resources.
        """
        # Abstract method: concrete spokes supply the real implementation.
        pass

    def log_info(self, message: str):
        """Log an informational message prefixed with this spoke's id."""
        # Prefix with the spoke id so messages from many spokes can be told apart.
        logger.info(f"[{self.spoke_id}] {message}")

    def log_error(self, message: str):
        """Log an error message prefixed with this spoke's id."""
        # Prefix with the spoke id so messages from many spokes can be told apart.
        logger.error(f"[{self.spoke_id}] {message}")
