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
CERT_CAPABLE_MODULES: Set[str] = {"firewall", "hypervisor", "directory", "hub", "statuspage", "ipam"}


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
        # A cert with no targets (or no domain) is a SILENT no-op without this
        # line — the operator sees "no distribution logs" and can't tell whether
        # distribution ran, was skipped, or was never wired. Surface it.
        logger.info("[cert] %s: no targets configured — nothing to distribute",
                     domain or "<unknown>")
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
                # 120s matches the pxmx spoke's own relay timeout: the
                # hypervisor path forwards INSTALL_CERT to a per-node agent
                # that runs `pvenode cert set` + restarts pveproxy (a slow
                # service restart). 20s (the old value) timed the hub out
                # while the spoke was still waiting on the agent → a spurious
                # "Timed out waiting for spoke response" ERROR even though the
                # install was still in progress. Fast targets (firewall/ipam)
                # return well under this; the timeout is just the upper bound.
                res = await rr(target_sid, "INSTALL_CERT", {
                    "domain": domain, "fullchain": fullchain,
                    "privkey": privkey, "chain": chain, "identifier": ident,
                }, timeout=120.0)
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
                               install_on_hub: Optional[Callable] = None,
                               wildcard_enabled: bool = False,
                               get_all_by_type: Optional[Callable] = None,
                               push_state: Optional[Dict[str, str]] = None,
                               ) -> List[Dict[str, Any]]:
    """Distribute every managed cert whose targets are stale. Skips the
    ``LE_GET_CERT`` pull entirely when every target of a cert is current.

    Returns a flat per-target summary (each entry tagged with its ``domain``)
    so the /api/le/distribute route can show a per-target toast — certs with no
    targets or all targets current contribute a synthetic ``SKIPPED`` entry so
    the operator sees them in the toast instead of a silent no-op. The hourly
    run_cert_distribution_loop caller ignores the return.

    ``wildcard_enabled`` (default False — the operator's testing toggle) gates
    the wildcard fan-out: when True AND a cert's domain is a wildcard, the cert
    is also pushed to EVERY connected cert-capable spoke (see
    ``distribute_wildcard_to_all_spokes``) in addition to its explicit targets.
    False → the wildcard path is never invoked (no-op while the operator is
    still testing cert distribution)."""
    aggregate: List[Dict[str, Any]] = []
    res = await rr(le_spoke_id, "LE_LIST_CERTS", {}, timeout=15.0)
    ret = _unwrap(res)
    if not (isinstance(ret, dict) and ret.get("status") == "SUCCESS"):
        # The last silent skip: if the le spoke can't enumerate certs, there's
        # nothing to distribute — surface it instead of returning an empty list
        # the UI can't distinguish from "everything current".
        logger.warning("[cert] LE_LIST_CERTS failed — cannot enumerate certs to distribute")
        return aggregate
    # The le spoke returns ``{"status":"SUCCESS", "data":{"certs":[...]}}`` —
    # certs are nested under ``data`` (the table path's _le_inner unwraps it;
    # _unwrap only strips the request_response payload envelope, NOT the spoke's
    # own ``data`` wrapper). Without this unwrap the loop saw ``ret.get("certs")``
    # == None → zero iterations → "no certs to distribute" + no per-cert logs,
    # even though the cert table (which DOES unwrap) showed the certs.
    list_data = ret.get("data") if isinstance(ret.get("data"), dict) else ret
    for cert in list_data.get("certs") or []:
        domain = cert.get("domain") or ""
        targets = cert.get("targets") or []
        cur_hash = cert.get("material_hash")
        is_wc = wildcard_enabled and _is_wildcard(domain)

        # Explicit-target path (skip the LE_GET_CERT pull when all current).
        explicit_summary: List[Dict[str, Any]] = []
        if not targets:
            logger.info("[cert] %s: no targets configured — skipping",
                         domain or "<unknown>")
            explicit_summary.append({"domain": domain or "<unknown>", "module_type": None,
                                      "identifier": None, "status": "SKIPPED",
                                      "message": "no targets configured", "skipped": True})
        elif cur_hash and all(t.get("last_pushed_hash") == cur_hash
                              and t.get("last_status") == "SUCCESS" for t in targets):
            logger.info("[cert] %s: all %d target(s) current — skipping",
                         domain, len(targets))
            explicit_summary.append({"domain": domain, "module_type": None, "identifier": None,
                                      "status": "SKIPPED",
                                      "message": f"all {len(targets)} target(s) current",
                                      "skipped": True})
        else:
            explicit_summary = await distribute_cert_to_targets(
                rr, get_by_type, capable, le_spoke_id, domain, targets,
                install_on_hub=install_on_hub)
            for e in explicit_summary:
                e["domain"] = domain
        aggregate.extend(explicit_summary)

        # Wildcard fan-out (gated; no-op when disabled). Runs even when the
        # explicit path skipped (all current / no targets) — wildcard targets
        # are separate spokes, tracked by hub-side push-state, and the skip
        # check uses cur_hash from the cert list (no LE_GET_CERT pull when all
        # wildcard spokes are current).
        if is_wc and get_all_by_type is not None and push_state is not None:
            wc_summary = await distribute_wildcard_to_all_spokes(
                rr, get_all_by_type, capable, le_spoke_id, domain, cur_hash,
                push_state, install_on_hub=install_on_hub)
            aggregate.extend(wc_summary)
    return aggregate


def _is_wildcard(domain: str) -> bool:
    """A wildcard cert domain — leftmost label is ``*`` (e.g. ``*.lab.example.com``).
    certbot issues these via a DNS-01 challenge; the resulting cert matches every
    subdomain, so the hub can fan it out to ALL cert-capable spokes without each
    one being an explicit target."""
    return bool(domain) and domain.lstrip().startswith("*.")


async def distribute_wildcard_to_all_spokes(
        rr: Callable, get_all_by_type: Callable, capable: Set[str],
        le_spoke_id: str, domain: str,
        material_hash: Optional[str],
        push_state: Dict[str, str],
        install_on_hub: Optional[Callable] = None,
        ) -> List[Dict[str, Any]]:
    """Fan a wildcard cert out to EVERY connected cert-capable spoke (resolved
    directly by ``spoke_id`` — so multiple spokes of the same module_type each
    get it, unlike ``distribute_cert_to_targets`` which resolves one spoke per
    module_type) plus the hub itself. Gated hub-side: the caller only invokes
    this when the hub's ``wildcard_all_spokes`` flag is ON and the domain is a
    wildcard, so this is a no-op while the operator is still testing cert
    distribution (flag default OFF).

    Skip: ``push_state`` is a mutable ``{f"{domain}|{spoke_id}": hash}`` dict
    the hub owns + persists. When a spoke's recorded hash already equals the
    current ``material_hash`` the push is skipped (no re-push storm on the
    hourly loop). ``material_hash`` from ``LE_LIST_CERTS`` lets us skip the
    ``LE_GET_CERT`` pull entirely when every spoke is current; pass None to
    force a pull (the issue path, which has no pre-listed hash).

    Returns a per-target summary (each entry tagged with ``domain`` + ``wildcard``
    so the UI toast can distinguish wildcard fan-out from explicit-target pushes).
    """
    summary: List[Dict[str, Any]] = []
    if not _is_wildcard(domain):
        return summary

    # Enumerate every connected cert-capable spoke (direct by spoke_id, so all
    # instances of a module_type are covered). "hub" is not a spoke — handled
    # via install_on_hub below.
    spoke_targets: List[Dict[str, Any]] = []
    for mt in capable:
        if mt == "hub":
            continue
        for sid in get_all_by_type(mt):
            spoke_targets.append({"module_type": mt, "identifier": sid, "spoke_id": sid})
    include_hub = "hub" in capable and install_on_hub is not None

    if not spoke_targets and not include_hub:
        logger.info("[cert] wildcard %s: no connected cert-capable spokes — nothing to fan out", domain)
        return summary

    # Skip check against hub-side push-state. material_hash may be None (issue
    # path) → treat as "stale" so we pull + push (issue is rare + the cert is fresh).
    def _current(sid: str) -> bool:
        return bool(material_hash) and push_state.get(f"{domain}|{sid}") == material_hash

    stale_spokes = [t for t in spoke_targets if not _current(t["spoke_id"])]
    hub_current = (not include_hub) or (bool(material_hash)
                                        and push_state.get(f"{domain}|hub") == material_hash)
    if not stale_spokes and hub_current:
        logger.info("[cert] wildcard %s: all %d target(s) current — skipping",
                     domain, len(spoke_targets) + (1 if include_hub else 0))
        return [{"domain": domain, "module_type": None, "identifier": None,
                 "status": "SUCCESS",
                 "message": f"all {len(spoke_targets) + (1 if include_hub else 0)} wildcard target(s) current",
                 "skipped": True, "wildcard": True}]

    # Pull material (only when something is stale). material_hash from the list
    # avoids the pull when every target is current; here at least one is stale.
    mat = await rr(le_spoke_id, "LE_GET_CERT", {"domain": domain}, timeout=15.0)
    mat_ret = _unwrap(mat)
    if not (isinstance(mat_ret, dict) and mat_ret.get("status") == "SUCCESS"):
        msg = mat_ret.get("message") if isinstance(mat_ret, dict) else "LE_GET_CERT failed"
        logger.warning("[cert] wildcard %s: LE_GET_CERT failed — %s", domain, msg)
        return [{"domain": domain, "module_type": None, "identifier": None,
                 "status": "ERROR", "message": msg, "wildcard": True}]
    cert = mat_ret.get("data") or {}
    fullchain = cert.get("fullchain", "")
    privkey = cert.get("privkey", "")
    chain = cert.get("chain", "")
    cur_hash = material_hash or cert.get("material_hash")

    logger.info("[cert] wildcard %s: fanning out to %d spoke(s)%s",
                domain, len(stale_spokes), " + hub" if (include_hub and not hub_current) else "")

    for t in stale_spokes:
        sid = t["spoke_id"]; mt = t["module_type"]
        entry = {"domain": domain, "module_type": mt, "identifier": sid, "wildcard": True}
        res = await rr(sid, "INSTALL_CERT", {
            "domain": domain, "fullchain": fullchain, "privkey": privkey,
            "chain": chain, "identifier": sid,
        }, timeout=120.0)
        rret = _unwrap(res)
        if isinstance(rret, dict) and rret.get("status") == "SUCCESS":
            entry.update(status="SUCCESS", message=rret.get("message") or "installed")
            if cur_hash:
                push_state[f"{domain}|{sid}"] = cur_hash
            logger.info("[cert] wildcard %s → %s/%s: installed — %s",
                         domain, mt, sid, entry["message"])
        else:
            entry.update(status="ERROR",
                         message=(rret.get("message") if isinstance(rret, dict)
                                  else "INSTALL_CERT failed"))
            logger.warning("[cert] wildcard %s → %s/%s: FAILED — %s",
                           domain, mt, sid, entry["message"])
        # Record on the le ledger (gates explicit-target re-push + surfaces in UI).
        try:
            await rr(le_spoke_id, "LE_MARK_DISTRIBUTED", {
                "domain": domain, "module_type": mt, "identifier": sid,
                "hash": cur_hash, "status": entry["status"],
                "message": entry["message"], "wildcard": True}, timeout=5.0)
        except Exception as e:
            logger.debug("LE_MARK_DISTRIBUTED failed for wildcard %s/%s: %s", domain, sid, e)
        summary.append(entry)

    # Hub self-install (one TLS endpoint; identifier "hub").
    if include_hub and not hub_current:
        hentry = {"domain": domain, "module_type": "hub", "identifier": "hub", "wildcard": True}
        try:
            hret = await install_on_hub(domain, fullchain, privkey, chain, "hub")
        except Exception as e:  # never let a self-install crash the fan-out
            hret = {"status": "ERROR", "message": str(e)}
        if isinstance(hret, dict) and hret.get("status") == "SUCCESS":
            hentry.update(status="SUCCESS", message=hret.get("message") or "installed on hub")
            if cur_hash:
                push_state[f"{domain}|hub"] = cur_hash
            logger.info("[cert] wildcard %s → hub: installed — %s", domain, hentry["message"])
        else:
            hentry.update(status="ERROR",
                          message=(hret.get("message") if isinstance(hret, dict)
                                   else "hub self-install failed"))
            logger.warning("[cert] wildcard %s → hub: FAILED — %s", domain, hentry["message"])
        try:
            await rr(le_spoke_id, "LE_MARK_DISTRIBUTED", {
                "domain": domain, "module_type": "hub", "identifier": "hub",
                "hash": cur_hash, "status": hentry["status"],
                "message": hentry["message"], "wildcard": True}, timeout=5.0)
        except Exception as e:
            logger.debug("LE_MARK_DISTRIBUTED failed for wildcard %s/hub: %s", domain, e)
        summary.append(hentry)

    ok = sum(1 for s in summary if s.get("status") == "SUCCESS")
    logger.info("[cert] wildcard %s: fanned out %d/%d target(s) OK",
                domain, ok, len(summary))
    return summary
    return aggregate