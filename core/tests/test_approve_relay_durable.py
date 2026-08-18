"""The 'approve → back to pending' flap when the agent-hosting sim/pxmx spoke
reconnects (self-update churn): the approve path used a fire-and-forget
send_to_spoke, so an APPROVAL_SUCCESS that raced with a disconnect was lost and
never redelivered. ``_deliver_agent_approval`` now routes it through the mailbox
— pushed (retried until acked) when the spoke is online, queued for the
reconnect flush when it is offline. Pin both dispositions.
"""
import asyncio

from routes.setup import _deliver_agent_approval


class _FakeMailbox:
    def __init__(self):
        self.pushed = []      # (msg, send_func)
        self.queued = []      # (pk, msg)

    async def push(self, msg, send_func):
        self.pushed.append((msg, send_func))

    async def queue_for_spoke(self, pk, msg):
        self.queued.append((pk, msg))


class _FakeHub:
    def __init__(self, connected):
        self.mailbox = _FakeMailbox()
        self.active_connections = {"spoke-guid": object()} if connected else {}
        self.sent = []

    def _primary_key(self, sid):
        return sid  # guid in, guid out

    def _agent_relay_name(self, agent_id):
        return agent_id

    async def send_to_spoke(self, msg):
        self.sent.append(msg)


def _relay_payload(msg):
    return msg.payload.data


def test_online_spoke_uses_durable_mailbox_push():
    """Spoke connected → mailbox.push (durable, acked, retried), NOT a raw
    fire-and-forget send that a reconnect could drop."""
    hub = _FakeHub(connected=True)
    disp = asyncio.run(_deliver_agent_approval(hub, "spoke-guid", "pxmx-cs-svr-06"))
    assert disp == "pushed"
    assert len(hub.mailbox.pushed) == 1
    assert hub.mailbox.queued == []
    msg, send_func = hub.mailbox.pushed[0]
    assert send_func == hub.send_to_spoke
    d = _relay_payload(msg)
    assert d["command"] == "APPROVAL_SUCCESS"
    assert d["target_agent_id"] == "pxmx-cs-svr-06"


def test_offline_spoke_queues_for_reconnect_flush():
    """Spoke offline → queue under its primary key for flush_mailbox on
    reconnect, instead of the old warn-and-drop dead-end."""
    hub = _FakeHub(connected=False)
    disp = asyncio.run(_deliver_agent_approval(hub, "spoke-guid", "pxmx-cs-svr-06"))
    assert disp == "queued"
    assert hub.mailbox.pushed == []
    assert len(hub.mailbox.queued) == 1
    pk, msg = hub.mailbox.queued[0]
    assert pk == "spoke-guid"
    assert _relay_payload(msg)["command"] == "APPROVAL_SUCCESS"


def test_never_uses_fire_and_forget_send():
    """Neither path calls the low-level send_to_spoke directly — delivery is
    ALWAYS via the mailbox so nothing is lost on a flap."""
    for connected in (True, False):
        hub = _FakeHub(connected=connected)
        asyncio.run(_deliver_agent_approval(hub, "spoke-guid", "agent-x"))
        assert hub.sent == [], "must not fire-and-forget; go through the mailbox"
