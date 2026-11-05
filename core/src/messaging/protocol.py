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

# uuid generates globally unique message ids.
import uuid
# time.time() stamps each message with its creation time.
import time
# dataclass/field generate the envelope classes and their per-instance defaults.
from dataclasses import dataclass, field
# IntEnum lets priorities compare numerically (higher number = more urgent).
from enum import IntEnum
# Type hints only; Any/Optional describe the payload and optional fields.
from typing import Any, Optional

class MessagePriority(IntEnum):
    """Delivery urgency of a message; higher values are sent before lower ones."""
    # Four ordered levels, from background traffic up to must-deliver-now.
    LOW = 0
    NORMAL = 1
    HIGH = 2
    CRITICAL = 3

@dataclass
class MessageHeader:
    """Routing metadata carried with every message (ids, timestamp, sender, target, TTL)."""
    # Every message gets a fresh random id so acks and retries can reference it.
    message_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    # Links a reply to the message it answers; None for unsolicited messages.
    correlation_id: Optional[str] = None
    # Creation time, used for ordering and TTL expiry.
    timestamp: float = field(default_factory=time.time)
    # Who sent the message and who it is for (hub or spoke ids).
    sender_id: str = ""
    destination_id: str = ""
    # Default urgency unless the sender says otherwise.
    priority: MessagePriority = MessagePriority.NORMAL
    # Messages older than this are dropped instead of being delivered late.
    ttl: int = 86400  # 24 hours in seconds

@dataclass
class MessagePayload:
    """The body of a message: a ``type`` string saying what it is plus its data."""
    # The type selects the handler on the receiving side; data is handler-specific.
    type: str
    data: Any

@dataclass
class Message:
    """The complete wire envelope: header + payload + optional HMAC signature."""
    # Routing metadata and body are kept separate so routing never needs to parse data.
    header: MessageHeader
    payload: MessagePayload
    # HMAC signature over the message; None when the message is unsigned.
    signature: Optional[str] = None

@dataclass
class Acknowledgement:
    """Reply a spoke sends back to confirm (or reject) receipt of a message."""
    # Which message is being acknowledged (its message_id).
    correlation_id: str
    # Outcome of processing, plus an error description when it failed.
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
    # WebSocket peer address of the sender (captured by the receive path) so the
    # mailbox "unknown ack" warning can name the source even when the ack envelope
    # itself carries no spoke_id (e.g. a late/duplicate response from a spoke).
    source_ip: Optional[str] = None
    # When the ack was created, for latency and diagnostics.
    timestamp: float = field(default_factory=time.time)
