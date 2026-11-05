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
    sid = str(node_id or "")
    try:
        ss = system_state or {}
        meta = (ss.get("module_metadata") or {}).get(sid) or {}
        info = (agent_info or {}).get(sid) or {}
        cfg = (ss.get("agent_config") or {}).get(sid) or {}
        for nm in (meta.get("display_name"), meta.get("name"), meta.get("hostname"),
                   info.get("agent_id"), info.get("hostname"),
                   cfg.get("display_name"),
                   (ss.get("agent_display_names") or {}).get(sid),
                   cfg.get("hostname"), cfg.get("agent_id")):
            nm = str(nm or "").strip()
            if nm and nm != sid:
                return nm
    except Exception:  # noqa: BLE001 — a name lookup must never break a caller
        pass
    return sid
