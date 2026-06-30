"""Mailbox unknown-ack warning must name the source (sender spoke_id + frame
type + peer IP) so a stray/late acknowledgement can be triaged. The ack
envelope's own spoke_id is often None for these, so the receive path threads
the sender's identity + remote IP into the Acknowledgement (see main.py
handle_client) and mailbox.acknowledge() includes them in its WARNING.
"""
import asyncio
import logging

from messaging.mailbox import Mailbox
from messaging.protocol import (
    Acknowledgement, Message, MessageHeader, MessagePayload, MessagePriority,
)


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro) if False else asyncio.run(coro)


def test_unknown_ack_warning_names_source_spoke_type_and_ip(caplog):
    mb = Mailbox()
    with caplog.at_level(logging.WARNING, logger="Mailbox"):
        asyncio.run(mb.acknowledge(Acknowledgement(
            correlation_id="838a423e-cf9b-4849-94ef-2684f880329f",
            status="FAILED",
            spoke_id="netbox-spoke-1",
            message_type="COMMAND_RESULT",
            source_ip="10.0.0.5",
        )))
    warns = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert warns, "expected a WARNING for an unknown ack"
    msg = warns[0].getMessage()
    assert "unknown message ID" in msg
    assert "838a423e" in msg
    assert "spoke_id=netbox-spoke-1" in msg
    assert "message_type=COMMAND_RESULT" in msg
    assert "source_ip=10.0.0.5" in msg
    assert "status=FAILED" in msg


def test_known_ack_retires_no_unknown_warning(caplog):
    mb = Mailbox()
    m = Message(
        header=MessageHeader(message_id="m1", destination_id="s1",
                             priority=MessagePriority.NORMAL),
        payload=MessagePayload(type="COMMAND", data={}),
    )
    mb.pending_ack["m1"] = (m, 0.0, 0)
    with caplog.at_level(logging.WARNING, logger="Mailbox"):
        asyncio.run(mb.acknowledge(Acknowledgement(
            correlation_id="m1", status="SUCCESS",
            spoke_id="s1", source_ip="10.0.0.9",
        )))
    # Retired from pending_ack, no unknown-ack WARNING emitted.
    assert "m1" not in mb.pending_ack
    assert not [r for r in caplog.records if r.levelno == logging.WARNING
                and "unknown message ID" in r.getMessage()]