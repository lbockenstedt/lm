"""One-form LDAP directory setup.

The operator gives only a domain name and an admin account. The hub works out
everything else:

* base DN / admin DN from the domain (``orange-tme.com`` ->
  ``dc=orange-tme,dc=com`` / ``cn=<user>,dc=orange-tme,dc=com``);
* which hosts are LDAP servers — every agent that has the ``ldap-server``
  deploy role loaded;
* each server's replication id (an id a node already has is kept) and its
  peers (all the OTHER servers), pushed as a forced ``LOAD_ROLE ldap-server`` so
  ``install_ldap.sh`` re-applies the admin password and the syncrepl mirror;
* the Directory spoke's connection URL — every server, space separated, which
  libldap treats as an ordered failover list.

The admin password is generated when not given, then stored in the Credential
Vault (``__admin__`` / :data:`VAULT_SECRET`, automation-readable) and in the
encrypted ``global_config["ldap"]`` the spoke config push reads from.
"""
import logging
import secrets
from typing import Any, Dict, List, Optional

logger = logging.getLogger("Hub")

VAULT_SECRET = "ldap-directory-admin"
_ROLE = "ldap-server"
_LDAP_PORT = 389


class LdapSetupError(Exception):
    """A setup request that can't be applied (bad input or offline server)."""


def base_dn_from_domain(domain: str) -> str:
    """``orange-tme.com`` -> ``dc=orange-tme,dc=com``. Raises on a bad domain."""
    labels = [p.strip() for p in str(domain or "").strip().lower().split(".")]
    if len(labels) < 2 or not all(labels):
        raise LdapSetupError(f"'{domain}' is not a valid domain name (e.g. orange-tme.com)")
    for label in labels:
        if not all(c.isalnum() or c == "-" for c in label):
            raise LdapSetupError(f"'{domain}' is not a valid domain name")
    return ",".join(f"dc={p}" for p in labels)


def admin_dn_for(admin_user: str, base_dn: str) -> str:
    user = str(admin_user or "").strip()
    if not user or any(c in user for c in ",=+<>#;\\\""):
        raise LdapSetupError("admin username must be a plain name (e.g. Administrator)")
    return f"cn={user},{base_dn}"


def node_url(address: str) -> str:
    return f"ldap://{address}:{_LDAP_PORT}"


def assign_server_ids(nodes: List[Dict[str, Any]]) -> Dict[str, str]:
    """Give every node a unique replication id. A node keeps the id it already
    has (so a running mirror isn't renumbered); duplicates and nodes without an
    id get the lowest free number. Nodes are taken in ``spoke_id`` order so the
    result is stable."""
    ids: Dict[str, str] = {}
    used = set()
    ordered = sorted(nodes, key=lambda n: n["spoke_id"])
    for n in ordered:
        sid = str(n.get("server_id") or "").strip()
        if sid.isdigit() and 0 < int(sid) < 4096 and sid not in used:
            ids[n["spoke_id"]] = sid
            used.add(sid)
    nxt = 1
    for n in ordered:
        if n["spoke_id"] in ids:
            continue
        while str(nxt) in used:
            nxt += 1
        ids[n["spoke_id"]] = str(nxt)
        used.add(str(nxt))
    return ids


def build_node_configs(nodes: List[Dict[str, Any]], base_dn: str, admin_dn: str,
                       admin_pw: str) -> Dict[str, Dict[str, Any]]:
    """The ``LOAD_ROLE ldap-server`` config for every node: shared bind
    identity, its own id + URL, and every OTHER node as a replication peer."""
    ids = assign_server_ids(nodes)
    urls = {n["spoke_id"]: node_url(n["address"]) for n in nodes}
    out = {}
    for n in nodes:
        pk = n["spoke_id"]
        out[pk] = {
            "base_dn": base_dn,
            "admin_dn": admin_dn,
            "admin_pw": admin_pw,
            "server_id": ids[pk],
            "server_url": urls[pk],
            "peers": [urls[o] for o in sorted(urls) if o != pk],
        }
    return out


def client_server_url(configs: Dict[str, Dict[str, Any]]) -> str:
    """Every server's URL in replication-id order, space separated — libldap
    tries them in turn, so the Directory spoke fails over to the next node."""
    ordered = sorted(configs.values(), key=lambda c: int(c["server_id"]))
    return " ".join(c["server_url"] for c in ordered)


def _display_name(hub, pk: str) -> str:
    for raw, guid in (getattr(hub, "spoke_id_alias", {}) or {}).items():
        if guid == pk and raw != pk:
            return raw
    return pk


def ldap_server_pks(hub) -> List[str]:
    return sorted(pk for pk, roles in (hub._agent_roles_store() or {}).items()
                  if _ROLE in (roles or []))


async def discover(hub, extra_pk: Optional[str] = None) -> List[Dict[str, Any]]:
    """Every ldap-server node with its connection state, address and current
    replication id (read from its ``/opt/lm/ldap/.env``). ``extra_pk`` adds a
    node whose role is being loaded right now and isn't recorded yet."""
    from routes.agents import _agent_primary_address, _read_ldap_server_env
    pks = ldap_server_pks(hub)
    if extra_pk and extra_pk not in pks:
        pks.append(extra_pk)
    conns = getattr(hub, "active_connections", {}) or {}
    nodes = []
    for pk in sorted(pks):
        node = {"spoke_id": pk, "name": _display_name(hub, pk),
                "connected": pk in conns, "address": None, "server_id": ""}
        if node["connected"]:
            node["address"] = await _agent_primary_address(hub, pk)
            env = await _read_ldap_server_env(hub, pk)
            node["server_id"] = env.get("LDAP_SERVER_ID", "")
        nodes.append(node)
    return nodes


async def _push_node(hub, pk: str, cfg: Dict[str, Any]) -> Dict[str, Any]:
    from routes.agents import _enrich_ldap_server_config
    try:
        res = await hub.request_response(
            pk, "LOAD_ROLE",
            {"role": _ROLE, "config": _enrich_ldap_server_config(hub, cfg), "force": True},
            timeout=120.0)
        pl = res.get("payload", {}).get("data", res) if isinstance(res, dict) else res
        ok = isinstance(pl, dict) and pl.get("status") == "SUCCESS"
        return {"status": "SUCCESS" if ok else "ERROR",
                "message": (pl or {}).get("message", "") if isinstance(pl, dict) else str(pl)}
    except Exception as e:  # noqa: BLE001 — report per node
        return {"status": "ERROR", "message": str(e)}


async def _save_and_push_client(hub, stored: Dict[str, Any]) -> None:
    gc = hub.state.system_state.setdefault("global_config", {})
    gc["ldap"] = stored
    hub.state._mark_dirty()
    try:
        await hub.push_ldap_config_all()
    except Exception:  # noqa: BLE001 — a reconnect re-pushes
        logger.debug("ldap setup: directory spoke re-push skipped", exc_info=True)


def stored_setup(hub) -> Dict[str, Any]:
    gc = hub.state.system_state.get("global_config", {}) or {}
    return dict(gc.get("ldap") or {})


async def apply_setup(hub, domain: str, admin_user: str, admin_pw: str = "",
                      psk: str = "", actor: str = "") -> Dict[str, Any]:
    """Apply the one-form setup to every ldap-server node and the Directory
    spoke(s). A blank ``admin_pw`` generates a new one. Every node must be
    online: they all get the new password, and a node that misses it would
    break replication."""
    base_dn = base_dn_from_domain(domain)
    admin_user = str(admin_user or "").strip() or "Administrator"
    admin_dn = admin_dn_for(admin_user, base_dn)
    admin_pw = admin_pw or secrets.token_urlsafe(24)

    nodes = await discover(hub)
    offline = [n["name"] for n in nodes if not (n["connected"] and n["address"])]
    if offline:
        raise LdapSetupError("LDAP server(s) offline or without an address: "
                             + ", ".join(offline) + " — bring them online and retry")

    # Vault first: if the write is refused (e.g. wrong pass-phrase) nothing
    # has been changed on the servers yet.
    import cred_vault as _cv
    try:
        await _cv.put_secret(
            hub, _cv.ADMIN_BUCKET, VAULT_SECRET,
            {"username": admin_user, "password": admin_pw, "bind_dn": admin_dn,
             "domain": domain.strip().lower()},
            mode="hub", sec_type="ldap", psk=psk, actor=actor,
            description="LDAP directory admin (set by Setup -> Directory)")
    except _cv.CredVaultError as e:
        raise LdapSetupError(f"could not store the password in the vault: {e}")

    configs = build_node_configs(nodes, base_dn, admin_dn, admin_pw)
    results = []
    for n in nodes:
        res = await _push_node(hub, n["spoke_id"], configs[n["spoke_id"]])
        results.append({"name": n["name"], "spoke_id": n["spoke_id"],
                        "server_id": configs[n["spoke_id"]]["server_id"],
                        "address": n["address"], **res})

    prev = stored_setup(hub)
    await _save_and_push_client(hub, {
        "domain": domain.strip().lower(),
        "admin_user": admin_user,
        "base_dn": base_dn,
        "admin_dn": admin_dn,
        "admin_pw": admin_pw,
        "server_url": client_server_url(configs) if configs else prev.get("server_url", ""),
        "server_id": "",
        "mirror_peers": [],
    })
    logger.info("ldap setup: %s applied to %d server(s) by %s",
                base_dn, len(nodes), actor or "?")
    return {"base_dn": base_dn, "admin_dn": admin_dn, "servers": results}


async def join_config(hub, spoke_id: str, cfg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Config for an ldap-server role being loaded on ``spoke_id`` once the
    one-form setup exists: the node gets the stored bind identity, and every
    other online node is re-pushed so it adds the newcomer as a peer. Returns
    None when the one-form setup hasn't been done (legacy flow applies)."""
    stored = stored_setup(hub)
    if not (stored.get("domain") and stored.get("admin_pw")):
        return None
    pk = hub._primary_key(spoke_id)
    found = await discover(hub, extra_pk=pk)
    nodes = [n for n in found if n["connected"] and n["address"]]
    offline = [n["name"] for n in found if n not in nodes]
    # An offline server's replication id can't be read, so assigning ids now
    # could hand the newcomer a duplicate. Load it standalone with the shared
    # bind identity instead; re-running Apply (all servers online) peers it.
    if offline:
        logger.warning("ldap setup: %s offline/unaddressable — loading %s standalone; "
                       "re-run Setup -> Directory Apply to add it to replication",
                       ", ".join(offline), pk)
        return {**(cfg or {}), "base_dn": stored["base_dn"],
                "admin_dn": stored["admin_dn"], "admin_pw": stored["admin_pw"]}
    configs = build_node_configs(nodes, stored["base_dn"], stored["admin_dn"],
                                 stored["admin_pw"])
    for n in nodes:
        if n["spoke_id"] != pk:
            res = await _push_node(hub, n["spoke_id"], configs[n["spoke_id"]])
            if res["status"] != "SUCCESS":
                logger.warning("ldap setup: re-peering %s failed: %s",
                               n["name"], res["message"])
    await _save_and_push_client(hub, {**stored, "server_url": client_server_url(configs)})
    return {**(cfg or {}), **configs[pk]}
