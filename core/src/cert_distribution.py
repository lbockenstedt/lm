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

# Hub-side cert distribution logs to the "le.distribution" logger so they surface
# under the WebUI Logs → Certificates tab (the hub routes le.* loggers into a
# dedicated buffer merged into /setup/logs/le; see main.py CertDistLogHandler +
# setup_admin.get_module_logs). The le SPOKE's own logs relay up via SPOKE_LOG
# into the same tab, so the cert authority + the hub's transport activity share
# one Logs view — an operator sees issue, distribution, and per-target install
# outcomes in one place.
logger = logging.getLogger("le.distribution")

# Module types whose spokes implement INSTALL_CERT. v1: opnsense (firewall) +
# pxmx (hypervisor — the spoke relays INSTALL_CERT to the per-node agent, which
# runs `pvenode cert set` on its local pveproxy) + ldap (directory — the spoke
# writes PEM to /etc/ldap/tls, points slapd's olcTLS* via ldapmodify -Y EXTERNAL
# over ldapi, restarts slapd; runs as root). Adding a spoke = implement
# INSTALL_CERT on it + add its module_type here. ``"hub"`` is special: the hub
# is not a spoke, so it has no get_spoke_by_type resolution — instead the hub
# installs the cert on ITSELF (writes LM_TLS_CERT/LM_TLS_KEY + schedules
# lm-self-restart) via the ``install_on_hub`` callable threaded in by the
# HubCertDistributionMixin._distribute_one_cert wrapper.
CERT_CAPABLE_MODULES: Set[str] = {"firewall", "hypervisor", "directory", "hub", "statuspage"}


def _unwrap(result: Any) -> Dict[str, Any]:
    """Pull the spoke's return dict out of a request_response result."""
    return result.get("payload", {}).get("data", result) if isinstance(result, dict) else {}


async def distribute_cert_to_targets(rr: Callable, get_by_type: Callable,
                                     capable: Set[str], le_spoke_id: str,
                                     domain: str, targets: List[Dict[str, Any]],
                                     install_on_hub: Optional[Callable] = None
                                     ) -> List[Dict[str, Any]]:
    """Pull cert material for ``domain`` from the le spoke (``rr``) and push
    ``INSTALL_CERT`` to each target spoke (resolved by ``get_by_type``). Returns
    a per-target summary. Self-filters: a target whose ``last_pushed_hash``
    already equals the current ``material_hash`` (and ``last_status`` SUCCESS) is
    skipped, so both the inline issue/renew path (fresh targets → pushed) and the
    hourly loop (stale-only) can call this with the full target list.

    ``install_on_hub`` is the special-case callable for a ``module_type == "hub"``
    target (the hub installing a cert on ITSELF — there is no hub spoke to
    resolve). Signature: ``async def(domain, fullchain, privkey, chain,
    identifier) -> {"status", "message"}``. When None, a hub target records an
    ERROR (so the absence is visible rather than silently dropped)."""
    summary: List[Dict[str, Any]] = []
    if not targets or not domain:
        return summary
    logger.info("[cert] distributing %s to %d target(s)", domain, len(targets))
    mat = await rr(le_spoke_id, "LE_GET_CERT", {"domain": domain}, timeout=15.0)
    mat_ret = _unwrap(mat)
    if not (isinstance(mat_ret, dict) and mat_ret.get("status") == "SUCCESS"):
        msg = mat_ret.get("message") if isinstance(mat_ret, dict) else "LE_GET_CERT failed"
        logger.warning("[cert] %s: LE_GET_CERT failed — %s", domain, msg)
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
        tgt_label = f"{mt}{('/' + ident) if ident else ''}"
        # Up-to-date target — skip the push (idempotent distribution).
        if (t.get("last_pushed_hash") == material_hash
                and t.get("last_status") == "SUCCESS" and material_hash):
            entry.update(status="SUCCESS", message="already up to date", skipped=True)
            logger.info("[cert] %s → %s: up to date (skipped)", domain, tgt_label)
            summary.append(entry)
            continue

        if mt not in capable:
            entry.update(status="ERROR",
                         message=f"module type '{mt}' does not support cert install yet")
            logger.warning("[cert] %s → %s: not cert-capable (no INSTALL_CERT handler "
                           "for module_type '%s')", domain, tgt_label, mt)
        elif mt == "hub":
            # The hub is not a spoke — install on itself via the threaded
            # callable. No get_by_type resolution; no INSTALL_CERT relay.
            if install_on_hub is None:
                entry.update(status="ERROR",
                             message="hub self-install not wired on this hub")
                logger.warning("[cert] %s → hub: self-install not wired on this hub", domain)
            else:
                try:
                    hret = await install_on_hub(domain, fullchain, privkey, chain, ident)
                except Exception as e:  # never let a self-install crash distribution
                    hret = {"status": "ERROR", "message": str(e)}
                if isinstance(hret, dict) and hret.get("status") == "SUCCESS":
                    entry.update(status="SUCCESS",
                                 message=hret.get("message") or "installed on hub")
                    logger.info("[cert] %s → hub: installed — %s", domain, entry["message"])
                else:
                    entry.update(status="ERROR",
                                 message=(hret.get("message") if isinstance(hret, dict)
                                          else "hub self-install failed"))
                    logger.warning("[cert] %s → hub: FAILED — %s", domain, entry["message"])
        else:
            target_sid = get_by_type(mt)
            if not target_sid:
                entry.update(status="ERROR", message=f"no connected {mt} spoke")
                logger.warning("[cert] %s → %s: no connected %s spoke", domain, tgt_label, mt)
            else:
                res = await rr(target_sid, "INSTALL_CERT", {
                    "domain": domain, "fullchain": fullchain,
                    "privkey": privkey, "chain": chain, "identifier": ident,
                }, timeout=20.0)
                rret = _unwrap(res)
                if isinstance(rret, dict) and rret.get("status") == "SUCCESS":
                    entry.update(status="SUCCESS",
                                 message=rret.get("message") or "installed")
                    logger.info("[cert] %s → %s: installed — %s", domain, tgt_label, entry["message"])
                else:
                    entry.update(status="ERROR",
                                 message=(rret.get("message") if isinstance(rret, dict)
                                          else "INSTALL_CERT failed"))
                    logger.warning("[cert] %s → %s: FAILED — %s", domain, tgt_label, entry["message"])

        # Record the push on the le ledger (gates re-pushes + surfaces in UI).
        try:
            await rr(le_spoke_id, "LE_MARK_DISTRIBUTED", {
                "domain": domain, "module_type": mt, "identifier": ident,
                "hash": material_hash, "status": entry["status"],
                "message": entry["message"]}, timeout=5.0)
        except Exception as e:
            logger.debug("LE_MARK_DISTRIBUTED failed for %s/%s: %s", domain, mt, e)
        summary.append(entry)
    ok = sum(1 for s in summary if s.get("status") == "SUCCESS")
    logger.info("[cert] distributed %s: %d/%d target(s) OK", domain, ok, len(summary))
    return summary


async def distribute_all_certs(rr: Callable, get_by_type: Callable,
                               capable: Set[str], le_spoke_id: str,
                               install_on_hub: Optional[Callable] = None) -> None:
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
                                         le_spoke_id, domain, targets,
                                         install_on_hub=install_on_hub)