"""Phase 2a: the _primary_key resolve point (inert until 2b arms the alias).

_primary_key is the single point that maps the spoke_id a spoke CONNECTS with to
the key its routing/approval/crypto/mailbox state lives under. In Phase 2a the
spoke_id_alias is empty, so it is the identity function — the zero-behavior-change
guarantee that lets every lookup be converted to _primary_key(spoke_id) without
flipping any spoke to guid-keyed state yet.
"""
from hub_identity import HubIdentityMixin


class _Hub(HubIdentityMixin):
    """Minimal host exposing only the attribute _primary_key reads."""
    def __init__(self):
        self.spoke_id_alias = {}


def test_primary_key_returns_spoke_id_when_alias_empty():
    h = _Hub()
    assert h._primary_key("spoke-1") == "spoke-1"
    assert h._primary_key("agent-7-network") == "agent-7-network"
    assert h._primary_key("") == ""


def test_primary_key_returns_guid_once_aliased():
    h = _Hub()
    h.spoke_id_alias["spoke-1"] = "GUID-1"
    assert h._primary_key("spoke-1") == "GUID-1"
    # An un-migrated spoke still resolves to its spoke_id (fail-safe).
    assert h._primary_key("spoke-2") == "spoke-2"
