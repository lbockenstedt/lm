"""LM Hub messaging envelope — the wire-level message shape.

Defines the dataclasses that form every message exchanged between the Hub and
a spoke: ``Message`` (the outer envelope) wraps a ``MessageHeader`` (routing
metadata — ids, timestamp, priority, TTL) and a ``MessagePayload`` (a
``type`` discriminator + arbitrary ``data``), plus an optional HMAC
``signature``. ``Acknowledgement`` is the reply shape a spoke sends back to
confirm receipt.

This module is intentionally free of transport/queueing logic — it only
describes the envelope. Delivery, retry, and per-spoke offline queuing live in
``mailbox.py``; liveness tracking (the GREEN/YELLOW/RED traffic-light derived
from message arrivals) lives in ``heartbeat.py``. Signatures are produced and
verified by ``security/signer.py`` and ``security/key_manager.py``.
"""

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
    # Optional routing/diagnostic context. Populated by the receive path
    # (core/src/main.py handle_connection) when the spoke's ack frame carries
    # them, so mailbox.acknowledge() can include spoke_id + message type in its
    # "unknown ack" warning even after the original message has already been
    # retired from pending_ack. Left Optional so older senders that omit them
    # remain compatible.
    spoke_id: Optional[str] = None
    message_type: Optional[str] = None
    timestamp: float = field(default_factory=time.time)
