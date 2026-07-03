"""Hub-brokered certificate distribution — pure transport helpers.

The hub is the transport for cert material from the le (Let's Encrypt) spoke to
the target spoke/agent/device that needs the cert. Spokes can't address each
other (every outbound frame hard-codes ``destination_id: "hub"``), so for each
managed cert the hub pulls fullchain+key from le via ``LE_GET_CERT`` and pushes
``INSTALL_CERT`` to each target spoke resolved by ``module_type``; each target
spoke applies the cert to its own device via the SSH/REST/console access it
already has (it's in the device's vicinity). ``LE_MARK_DISTRIBUTED`` records the
push on the le ledger so ``last_pushed_hash`` gates re-pushes.

These helpers are pure (take the hub's ``request_response`` + ``get_spoke_by_type``
callables + the capable-modules set) so the transport logic is unit-testable
without constructing a LabManagerHub (which pulls in at-rest encryption).
``LabManagerHub._distribute_one_cert`` / ``_distribute_all_certs`` are thin
wrappers that pass ``self.request_response`` / ``self.get_spoke_by_type`` /
``self.CERT_CAPABLE_MODULES``.
"""
import logging
from typing import Any, Callable, Dict, List, Optional, Set

logger = logging.getLogger("CertDistribution")

# Module types whose spokes implement INSTALL_CERT. v1: opnsense (firewall) +
# pxmx (hypervisor — the spoke relays INSTALL_CERT to the per-node agent, which
# runs `pvenode cert set` on its local pveproxy) + ldap (directory — the spoke
# writes PEM to /etc/ldap/tls, points slapd's olcTLS* via ldapmodify -Y EXTERNAL
# over ldapi, restarts slapd; runs as root). Adding a spoke = implement
# INSTALL_CERT on it + add its module_type here.
CERT_CAPABLE_MODULES: Set[str] = {"firewall", "hypervisor", "directory"}


def _unwrap(result: Any) -> Dict[str, Any]:
    """Pull the spoke's return dict out of a request_response result."""
    return result.get("payload", {}).get("data", result) if isinstance(result, dict) else {}


async def distribute_cert_to_targets(rr: Callable, get_by_type: Callable,
                                     capable: Set[str], le_spoke_id: str,
                                     domain: str, targets: List[Dict[str, Any]]
                                     ) -> List[Dict[str, Any]]:
    """Pull cert material for ``domain`` from the le spoke (``rr``) and push
    ``INSTALL_CERT`` to each target spoke (resolved by ``get_by_type``). Returns
    a per-target summary. Self-filters: a target whose ``last_pushed_hash``
    already equals the current ``material_hash`` (and ``last_status`` SUCCESS) is
    skipped, so both the inline issue/renew path (fresh targets → pushed) and the
    hourly loop (stale-only) can call this with the full target list."""
    summary: List[Dict[str, Any]] = []
    if not targets or not domain:
        return summary
    mat = await rr(le_spoke_id, "LE_GET_CERT", {"domain": domain}, timeout=15.0)
    mat_ret = _unwrap(mat)
    if not (isinstance(mat_ret, dict) and mat_ret.get("status") == "SUCCESS"):
        msg = mat_ret.get("message") if isinstance(mat_ret, dict) else "LE_GET_CERT failed"
        return [{"module_type": None, "identifier": None,
                 "status": "ERROR", "message": msg}]
    cert = mat_ret.get("data") or {}
    fullchain = cert.get("fullchain", "")
    privkey = cert.get("privkey", "")
    chain = cert.get("chain", "")
    material_hash = cert.get("material_hash")

    for t in targets:
        mt = t.get("module_type")
        ident = t.get("identifier", "") or ""
        entry: Dict[str, Any] = {"module_type": mt, "identifier": ident}
        # Up-to-date target — skip the push (idempotent distribution).
        if (t.get("last_pushed_hash") == material_hash
                and t.get("last_status") == "SUCCESS" and material_hash):
            entry.update(status="SUCCESS", message="already up to date", skipped=True)
            summary.append(entry)
            continue

        if mt not in capable:
            entry.update(status="ERROR",
                         message=f"module type '{mt}' does not support cert install yet")
        else:
            target_sid = get_by_type(mt)
            if not target_sid:
                entry.update(status="ERROR", message=f"no connected {mt} spoke")
            else:
                res = await rr(target_sid, "INSTALL_CERT", {
                    "domain": domain, "fullchain": fullchain,
                    "privkey": privkey, "chain": chain, "identifier": ident,
                }, timeout=20.0)
                rret = _unwrap(res)
                if isinstance(rret, dict) and rret.get("status") == "SUCCESS":
                    entry.update(status="SUCCESS",
                                 message=rret.get("message") or "installed")
                else:
                    entry.update(status="ERROR",
                                 message=(rret.get("message") if isinstance(rret, dict)
                                          else "INSTALL_CERT failed"))

        # Record the push on the le ledger (gates re-pushes + surfaces in UI).
        try:
            await rr(le_spoke_id, "LE_MARK_DISTRIBUTED", {
                "domain": domain, "module_type": mt, "identifier": ident,
                "hash": material_hash, "status": entry["status"],
                "message": entry["message"]}, timeout=5.0)
        except Exception as e:
            logger.debug("LE_MARK_DISTRIBUTED failed for %s/%s: %s", domain, mt, e)
        summary.append(entry)
    return summary


async def distribute_all_certs(rr: Callable, get_by_type: Callable,
                               capable: Set[str], le_spoke_id: str) -> None:
    """Distribute every managed cert whose targets are stale. Skips the
    ``LE_GET_CERT`` pull entirely when every target of a cert is current."""
    res = await rr(le_spoke_id, "LE_LIST_CERTS", {}, timeout=15.0)
    ret = _unwrap(res)
    if not (isinstance(ret, dict) and ret.get("status") == "SUCCESS"):
        return
    for cert in ret.get("certs") or []:
        domain = cert.get("domain")
        targets = cert.get("targets") or []
        if not domain or not targets:
            continue
        cur_hash = cert.get("material_hash")
        if cur_hash and all(t.get("last_pushed_hash") == cur_hash
                            and t.get("last_status") == "SUCCESS" for t in targets):
            continue  # every target current — skip the LE_GET_CERT pull
        await distribute_cert_to_targets(rr, get_by_type, capable,
                                         le_spoke_id, domain, targets)