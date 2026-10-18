"""Clustered DNS_STATS must forward ``source_prefixes=[]`` (a tenant with no
NetBox prefixes) to every member so they fail CLOSED; dropping it made the
members return every tenant's queries."""
import asyncio
import os
import sys

# dns_spoke imports core.src.base_spoke, so the lm repo root must be importable.
_LM_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _LM_ROOT not in sys.path:
    sys.path.insert(0, _LM_ROOT)

from dns_spoke import DNSSpoke


class _Transport:
    def __init__(self):
        self.sent = []

    async def fanout(self, op, payload, timeout=None):
        self.sent.append((op, payload))
        return {"results": {}}


def _stats(**kw):
    spoke = DNSSpoke.__new__(DNSSpoke)
    spoke._transport = _Transport()
    asyncio.run(spoke._cluster_stats(**kw))
    return spoke._transport.sent[0][1]


def test_empty_source_prefixes_is_forwarded():
    assert _stats(source_prefixes=[]) == {"source_prefixes": []}


def test_prefixes_forwarded_and_none_stays_unfiltered():
    assert _stats(source_prefixes=["10.1.0.0/24"]) == {"source_prefixes": ["10.1.0.0/24"]}
    assert "source_prefixes" not in _stats()
