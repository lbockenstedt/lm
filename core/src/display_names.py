"""One resolver for "what do we call this spoke/agent id in the UI".

module_metadata.display_name DEFAULTS to the id itself (state.manager
register_module), so the obvious ``display_name or hostname or id`` returns the
UUID for every unnamed node and never reaches the hostname. Every copy of that
one-liner leaked UUIDs to the UI. Route name lookups through here instead.
"""


def node_name(system_state, node_id, agent_info=None) -> str:
    """Friendly name for a spoke or relayed-agent id, else the id itself.

    Spokes: module_metadata. Relayed agents: live ``agent_info`` (hub memory),
    then the persisted agent_config / agent_display_names, which survive the
    parent spoke dropping — exactly when an offline/alert view needs the name.
    """
    # Normalise the id to a string; None becomes "" so comparisons below are safe.
    sid = str(node_id or "")
    # Everything that touches state is guarded so a bad lookup can never crash the caller.
    try:
        # Treat a missing system_state as empty so the .get() chains below still work.
        ss = system_state or {}
        # Spoke metadata for this id (display_name / name / hostname), or {} if unknown.
        meta = (ss.get("module_metadata") or {}).get(sid) or {}
        # Live relayed-agent info held in hub memory, or {} if not provided / unknown.
        info = (agent_info or {}).get(sid) or {}
        # Persisted per-agent config; survives the parent spoke going offline.
        cfg = (ss.get("agent_config") or {}).get(sid) or {}
        # Walk candidate names in priority order: spoke metadata first, then live agent info,
        # then persisted agent config and the saved display-name table.
        for nm in (meta.get("display_name"), meta.get("name"), meta.get("hostname"),
                   info.get("agent_id"), info.get("hostname"),
                   cfg.get("display_name"),
                   (ss.get("agent_display_names") or {}).get(sid),
                   cfg.get("hostname"), cfg.get("agent_id")):
            # Turn None into "" and trim whitespace so blank names are skipped.
            nm = str(nm or "").strip()
            # Use the first real name that is not just the id echoed back (the UUID-leak bug).
            if nm and nm != sid:
                return nm
    # Any unexpected data shape just means "no friendly name"; fall back to the id below.
    except Exception:  # noqa: BLE001 — a name lookup must never break a caller
        pass
    # Nothing better was found, so show the raw id.
    return sid
