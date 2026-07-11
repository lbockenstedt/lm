"""Multi-role log-relay scoping on a shared/generic agent.

A generic agent process hosts N role sub-spokes, each a BaseControlPlane that
installs ``_SpokeLogRelayHandler`` on the ROOT logger. Without scoping, every
handler captures the whole process stream and relays it under its own spoke_id,
so the hub's ``agent_logs[{base}-cppm]`` and ``[{base}-opnsense]`` both hold the
FULL mixed stream — CPPM logs appear under OPNSense and vice versa.

The fix (``_SpokeLogRelayHandler._include_prefixes`` / ``_exclude_prefixes``):
each role sub-spoke relays only its own role's logger-name stems; the base agent
excludes the union of all role stems (catch-all for agent/process/non-role
lines, incl. shared-infra loggers like HubDiscovery/DepGuard/UpdateRecovery that
live in BOTH lm/core and a role repo and so can't be attributed by name).

These tests exercise the handler filter directly + the partition invariant
(every record lands in exactly one bucket) + that ``_ROLE_LOG_PREFIXES`` covers
the logger names each role repo actually defines.
"""
import queue

from core.src.messaging.control_plane import _SpokeLogRelayHandler
from agent_spoke import _ROLE_LOG_PREFIXES


def _handler():
    q = queue.Queue(maxsize=500)
    return _SpokeLogRelayHandler(q), q


def _emit(h, name, level="INFO", msg="x"):
    import logging
    rec = logging.LogRecord(name=name, level=getattr(logging, level), pathname=__file__,
                            lineno=0, msg=msg, args=(), exc_info=None)
    h.emit(rec)


def _drain(q):
    out = []
    try:
        while True:
            out.append(q.get_nowait())
    except queue.Empty:
        return out


# ── 1. no filter (standalone spoke) relays everything ───────────────────────

def test_no_filter_relays_all():
    h, q = _handler()
    for n in ("CPPMSpoke", "OpnSpoke", "GenericAgent", "httpx"):
        _emit(h, n)
    drained = _drain(q)
    assert len(drained) == 4  # standalone spoke: one process, one bucket, all logs


# ── 2. include filter (a role sub-spoke) relays only matching stems ─────────

def test_include_prefix_relays_only_role_stems():
    h, q = _handler()
    h.set_include_prefixes(("CPPM",))
    for n in ("CPPMSpoke", "CPPMClient", "CPPMQueries", "CPPMControlPlane",
             "OpnSpoke", "GenericAgent", "BaseControlPlane"):
        _emit(h, n)
    drained = _drain(q)
    names = [d for d in drained]
    assert len(names) == 4  # exactly the four CPPM* records
    assert all("CPPM" in d for d in names)


def test_include_prefix_stem_match_catches_children():
    # startswith semantics: "CPPM" catches "CPPMSpoke" but not "acme_CPPM".
    h, q = _handler()
    h.set_include_prefixes(("CPPM",))
    _emit(h, "CPPMSpoke")
    _emit(h, "acme_CPPM")  # stem is NOT a prefix of this name
    assert len(_drain(q)) == 1


def test_empty_include_prefixes_means_relay_all():
    # set_include_prefixes(()) / None both clear the filter → standalone behavior.
    h, q = _handler()
    h.set_include_prefixes(())
    for n in ("CPPMSpoke", "OpnSpoke", "GenericAgent"):
        _emit(h, n)
    assert len(_drain(q)) == 3


# ── 3. exclude filter (base agent) drops role stems, relays the rest ────────

def test_exclude_prefix_drops_role_stems():
    h, q = _handler()
    h.set_exclude_prefixes(("CPPM", "Opn"))
    for n in ("CPPMSpoke", "OpnSpoke", "OpnsenseEngine",
              "GenericAgent", "HubDiscovery", "httpx"):
        _emit(h, n)
    drained = _drain(q)
    # CPPMSpoke + Opn* dropped; GenericAgent + HubDiscovery + httpx relayed.
    assert len(drained) == 3
    assert any("GenericAgent" in d for d in drained)
    assert any("HubDiscovery" in d for d in drained)
    assert any("httpx" in d for d in drained)


# ── 4. partition invariant: each record → exactly one bucket ───────────────

def test_partition_each_record_lands_in_exactly_one_bucket():
    # Mirror the real multi-role agent: a base handler (exclude union) + a cppm
    # role handler (include CPPM) + an opnsense role handler (include Opn), all
    # on the same root stream. Every record must land in exactly one bucket.
    base_h, base_q = _handler()
    base_h.set_exclude_prefixes(("CPPM", "Opn"))
    cppm_h, cppm_q = _handler()
    cppm_h.set_include_prefixes(("CPPM",))
    opn_h, opn_q = _handler()
    opn_h.set_include_prefixes(("Opn",))

    records = ("CPPMSpoke", "CPPMClient", "OpnSpoke", "OpnsenseEngine",
               "GenericAgent", "BaseControlPlane", "HubDiscovery", "httpx")
    for n in records:
        _emit(base_h, n)
        _emit(cppm_h, n)
        _emit(opn_h, n)

    base = _drain(base_q)
    cppm = _drain(cppm_q)
    opn = _drain(opn_q)

    # No record appears in two buckets — the OPNSense bucket has ZERO CPPM lines
    # and vice versa (the exact bug being fixed).
    assert not any("CPPM" in d for d in opn), "CPPM leaked into OPNSense bucket"
    assert not any("Opn" in d for d in cppm), "OPNSense leaked into CPPM bucket"
    # Role buckets hold only their own stems.
    assert len(cppm) == 2  # CPPMSpoke, CPPMClient
    assert len(opn) == 2    # OpnSpoke, OpnsenseEngine
    # Base bucket holds the non-role lines (agent + shared-infra + libs).
    assert len(base) == 4  # GenericAgent, BaseControlPlane, HubDiscovery, httpx
    # Together: every record relayed exactly once across the three buckets.
    assert len(base) + len(cppm) + len(opn) == len(records)


# ── 5. _ROLE_LOG_PREFIXES covers the real logger names each role repo defines ─

def test_role_prefixes_cover_known_role_loggers():
    # Logger names actually defined in each role repo (verified against the
    # repos at fix time). Each must be caught by its role's prefix tuple so a
    # shared agent routes them to the right bucket instead of the base catch-all.
    known = {
        "cppm":     ["CPPMClient", "CPPMControlPlane", "CPPMQueries", "CPPMSpoke"],
        "opnsense": ["OpnControlPlane", "OpnsenseEngine", "OpnSpoke"],
        "ldap":     ["LdapControlPlane", "LdapManager", "LdapSpoke"],
        "dns":      ["DNSControlPlane", "DNSSpoke", "UnboundManager"],
        "dhcp":     ["DHCPControlPlane", "DHCPSpoke", "KeaManager"],
        "netbox":   ["NetboxControlPlane", "NetboxEngine", "NetboxSpoke"],
        "network":  ["NwCli", "NwControlPlane", "NwEngine", "NwRest", "NwSnmp", "NwSpoke"],
        "le":       ["LEAcme", "LEControlPlane", "LELedger", "LESpoke", "le.dns_credentials"],
        "proxmox":  ["ProxmoxSpoke", "PxmxAgent", "PxmxControlPlane"],
    }
    for role, names in known.items():
        prefixes = _ROLE_LOG_PREFIXES.get(role, ())
        assert prefixes, f"role {role!r} missing from _ROLE_LOG_PREFIXES"
        for n in names:
            assert any(n == p or n.startswith(p) for p in prefixes), (
                f"role {role!r} logger {n!r} not covered by prefixes {prefixes}")


def test_shared_loggers_not_claimed_by_any_role():
    # HubDiscovery/DepGuard/UpdateRecovery live in BOTH lm/core and pxmx → they
    # must NOT be matched by any role's prefix list, so they fall to the base
    # agent bucket (process-infra), not mis-routed to the pxmx bucket. This
    # guards against a too-greedy stem like "Hub" catching "HubDiscovery".
    shared = ["HubDiscovery", "DepGuard", "UpdateRecovery"]
    for role, prefixes in _ROLE_LOG_PREFIXES.items():
        for s in shared:
            assert not any(s == p or s.startswith(p) for p in prefixes), (
                f"shared logger {s!r} would be caught by role {role!r} ({prefixes})")


def test_all_role_map_roles_have_prefix_entries():
    # Every role in _ROLE_MAP should have a prefix entry (even if minimal) so the
    # agent never silently relays a role's logs under the wrong bucket.
    from agent_spoke import _ROLE_MAP
    for role in _ROLE_MAP:
        assert role in _ROLE_LOG_PREFIXES, (
            f"role {role!r} in _ROLE_MAP has no _ROLE_LOG_PREFIXES entry")