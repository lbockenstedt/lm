import uuid
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Optional

class MessagePriority(IntEnum):
    LOW = 0
    NORMAL = 1
    HIGH = 2
    CRITICAL = 3

@dataclass
class MessageHeader:
    message_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    correlation_id: Optional[str] = None
    timestamp: float = field(default_factory=time.time)
    sender_id: str = ""
    destination_id: str = ""
    priority: MessagePriority = MessagePriority.NORMAL
    ttl: int = 86400  # 24 hours in seconds

@dataclass
class MessagePayload:
    type: str
    data: Any

@dataclass
class Message:
    header: MessageHeader
    payload: MessagePayload
    signature: Optional[str] = None

@dataclass
class Acknowledgement:
    correlation_id: str
    status: str  # 'SUCCESS' or 'FAILED'
    error: Optional[str] = None
    timestamp: float = field(default_factory=time.time)
