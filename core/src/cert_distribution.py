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
# HubCertDistributionMixin._distribute_one_cert wrapper. ``nac`` (ClearPass)
# installs the cert via the ClearPass REST server-cert API (PKCS12 hosted at a
# URL ClearPass fetches — see cppm spoke ``import_cert``). ``nw`` (network
# devices) currently installs certs only on ``cx_switch`` (AOS-CX REST v10);
# other nw families (aos_switch/ex_switch/gateway) return a clear ERROR from
# the spoke (external-key / SSH-SFTP plumbing not yet built). Both are fast
# REST targets → 120s install tier (no pvenode wait).
CERT_CAPABLE_MODULES: Set[str] = {"firewall", "hypervisor", "directory", "hub", "statuspage", "ipam", "simulation", "nac", "nw", "netbox-server"}


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
    ERROR (so the absence is visible rather than silently dropped).

    ``get_by_type(module_type, identifier)`` resolves the target spoke. The
    identifier is passed so agent-hosting types (hypervisor/simulation) can
    route to the spoke that actually OWNS the target pxmx agent — in the split
    topology the agents dial the cs (simulation) spoke, so a 'hypervisor'
    target must route there, not to a connected-but-agent-less pxmx spoke
    (which would return 'No agent resolved for cert install'). Non-agent-
    hosting types ignore the identifier and resolve by module_type."""
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
        entry: Dict[str, Any] = {"domain": domain, "module_type": mt, "identifier": ident}
        tgt_label = f"{mt}{('/' + ident) if ident else ''}"
        # Up-to-date target — skip the push (idempotent distribution).
        if (t.get("last_pushed_hash") == material_hash
                and t.get("last_status") == "SUCCESS" and material_hash):
            entry.update(status="SUCCESS", message="already up to date", skipped=True)
            logger.info("[cert] %s → %s: up to date (skipped)", domain, tgt_label)
            summary.append(entry)
            continue

        # Not skipped → say WHY we're (re)pushing so a distribution loop is
        # visible in WebUI Logs → Certificates without SSHing to a node.
        _prev = t.get("last_status")
        if _prev and _prev != "SUCCESS":
            logger.info("[cert] %s → %s: (re)pushing — previous push %s%s",
                        domain, tgt_label, _prev,
                        (": " + str(t.get("last_message"))) if t.get("last_message") else "")
        elif _prev == "SUCCESS" and t.get("last_pushed_hash") != material_hash:
            logger.info("[cert] %s → %s: pushing — cert material changed since last push",
                        domain, tgt_label)

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
            target_sid = get_by_type(mt, ident)
            if not target_sid:
                entry.update(status="ERROR", message=f"no connected {mt} spoke")
                logger.warning("[cert] %s → %s: no connected %s spoke", domain, tgt_label, mt)
            else:
                # The hypervisor + simulation paths forward INSTALL_CERT to a
                # per-node pxmx agent that runs `pvenode cert set --restart`; on
                # a loaded node the pveproxy restart can take many minutes and
                # we can't predict it, so give those paths a generous window
                # (640s > the spoke's 620s relay > the agent's 600s pvenode
                # wait) so the hub never times out first and masks a deploy
                # that's still in progress (the agent verifies the cert by
                # fingerprint on its own timeout, so a slow restart still
                # reports SUCCESS, not ERROR). In the split topology the
                # simulation (cs/lm-spoke) owns the pxmx agents directly and
                # relays INSTALL_CERT to each — same pvenode wait, so it shares
                # the 640s window. Fast targets (firewall/ipam/directory/
                # statuspage) stay at 120s — the timeout is just the upper
                # bound, not the time they take.
                install_timeout = 640.0 if mt in ("hypervisor", "simulation") else 120.0
                res = await rr(target_sid, "INSTALL_CERT", {
                    "domain": domain, "fullchain": fullchain,
                    "privkey": privkey, "chain": chain, "identifier": ident,
                    "module_type": mt,
                }, timeout=install_timeout)
                rret = _unwrap(res)
                # Fleet spokes (nw) return a per-device breakdown — carry it so the
                # hub can stash it for the drill-down report.
                if isinstance(rret, dict) and rret.get("devices") is not None:
                    entry["devices"] = rret["devices"]
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
                               mtls_auto_provision: bool = False,
                               get_primary_spokes: Optional[Callable] = None,
                               push: Optional[Callable] = None,
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
    still testing cert distribution).

    ``mtls_auto_provision`` (default False — ``global_config["mtls"][
    "auto_provision"]``) gates a SEPARATE mTLS-materials fan-out: when True AND
    a cert's domain is a wildcard, the cert's chain + client cert/key are
    pushed to every connected PRIMARY spoke (all types) + the hub as
    ``SPOKE_SET_MTLS_MATERIALS`` (see ``distribute_mtls_materials_to_all_spokes``)
    so the fleet can mutually verify once mTLS is enabled. Requires
    ``get_primary_spokes`` + ``push`` (a durable push_or_queue_to_spoke-style
    callable). No-op when disabled."""
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
        is_mtls = (mtls_auto_provision and _is_wildcard(domain)
                   and get_primary_spokes is not None and push is not None
                   and push_state is not None)

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

        # mTLS-materials fan-out (gated; no-op when disabled). Separate from the
        # wildcard fan-out above: that pushes the per-DEVICE cert (INSTALL_CERT)
        # to cert-capable spokes; this pushes the TRANSPORT mTLS materials
        # (SPOKE_SET_MTLS_MATERIALS) to every PRIMARY spoke (all types) so the
        # fleet can mutually verify once mTLS is enabled. Shares push_state
        # (keyed "mtls|…" so the two flows don't collide).
        if is_mtls:
            mtls_summary = await distribute_mtls_materials_to_all_spokes(
                rr, push, get_primary_spokes, le_spoke_id, domain, cur_hash,
                push_state, install_on_hub=install_on_hub)
            aggregate.extend(mtls_summary)
    return aggregate


def _is_wildcard(domain: str) -> bool:
    """A wildcard cert domain — leftmost label is ``*`` (e.g. ``*.lab.example.com``).
    certbot issues these via a DNS-01 challenge; the resulting cert matches every
    subdomain, so the hub can fan it out to ALL cert-capable spokes without each
    one being an explicit target."""
    return bool(domain) and domain.lstrip().startswith("*.")


# Push-state key prefix for mTLS-materials distribution (kept separate from the
# wildcard server-cert push_state so the two flows — device-serving cert vs mTLS
# client cert — don't shadow each other's per-spoke hash).
_MTLS_PUSH_PREFIX = "mtls"


async def distribute_mtls_materials_to_all_spokes(
        rr: Callable, push: Callable, get_primary_spokes: Callable,
        le_spoke_id: str, domain: str,
        material_hash: Optional[str],
        push_state: Dict[str, str],
        install_on_hub: Optional[Callable] = None,
        ) -> List[Dict[str, Any]]:
    """Fan the LE wildcard's mTLS materials (the chain as the CA bundle + the
    wildcard as the client cert/key) to EVERY connected PRIMARY spoke (all
    module types — every spoke dials the hub, so every spoke needs them, not
    just CERT_CAPABLE_MODULES) plus the hub itself. Gated hub-side by
    ``global_config["mtls"]["auto_provision"]``; the caller only invokes this
    for a wildcard domain when auto-provision is on.

    Why a separate flow from ``distribute_wildcard_to_all_spokes``: that flow
    pushes ``INSTALL_CERT`` (a per-DEVICE cert install, only to cert-capable
    spokes) so each spoke's webui/agent listener serves the LE cert. This flow
    pushes ``SPOKE_SET_MTLS_MATERIALS`` (a TRANSPORT-LAYER material install, to
    every primary spoke) so each spoke can mutually verify with the hub once
    mTLS is enabled. Role sub-spokes are excluded (the hub's
    ``get_primary_spokes`` filters by ``spoke_parent_map``); they share their
    parent agent's process + cert, so the parent's push covers them.

    ``push`` is a durable ``push_or_queue_to_spoke``-style callable so an
    offline spoke is queued (mailbox) and provisioned on reconnect — never
    orphaned. ``install_on_hub`` is the hub self-install (writes the wildcard
    to LM_TLS_CERT/KEY + the chain to LM_MTLS_CA via _install_cert_on_hub); the
    hub is the hub↔spoke SERVER so it needs the CA (to verify spokes) + the
    wildcard as its server cert (so spokes can verify it), NOT a client cert.

    Skip: ``push_state`` keyed ``f"mtls|{spoke_id}"`` / ``"mtls|hub"``; when a
    target's recorded hash already equals ``material_hash`` it's skipped (no
    re-push storm on the hourly loop). ``material_hash`` from ``LE_LIST_CERTS``
    skips the LE_GET_CERT pull when every target is current; pass None to force.

    Returns a per-target summary (each entry tagged with ``domain`` + ``mtls``
    so the UI can distinguish this flow from a cert push).
    """
    summary: List[Dict[str, Any]] = []
    if not _is_wildcard(domain):
        return summary

    primary = list(get_primary_spokes() or [])
    include_hub = install_on_hub is not None
    if not primary and not include_hub:
        logger.info("[mtls] %s: no connected primary spokes — nothing to fan out",
                    domain)
        return summary

    def _key(sid: str) -> str:
        return f"{_MTLS_PUSH_PREFIX}|{sid}"

    def _current(sid: str) -> bool:
        return bool(material_hash) and push_state.get(_key(sid)) == material_hash

    stale_spokes = [(sid, mt) for (sid, mt) in primary if not _current(sid)]
    hub_current = (not include_hub) or (bool(material_hash)
                                        and push_state.get(_key("hub")) == material_hash)
    if not stale_spokes and hub_current:
        logger.info("[mtls] %s: all %d target(s) current — skipping",
                    domain, len(primary) + (1 if include_hub else 0))
        return [{"domain": domain, "module_type": None, "identifier": None,
                 "status": "SUCCESS",
                 "message": f"all {len(primary) + (1 if include_hub else 0)} mTLS target(s) current",
                 "skipped": True, "mtls": True}]

    # Pull material (only when something is stale).
    mat = await rr(le_spoke_id, "LE_GET_CERT", {"domain": domain}, timeout=15.0)
    mat_ret = _unwrap(mat)
    if not (isinstance(mat_ret, dict) and mat_ret.get("status") == "SUCCESS"):
        msg = mat_ret.get("message") if isinstance(mat_ret, dict) else "LE_GET_CERT failed"
        logger.warning("[mtls] %s: LE_GET_CERT failed — %s", domain, msg)
        return [{"domain": domain, "module_type": None, "identifier": None,
                 "status": "ERROR", "message": msg, "mtls": True}]
    cert = mat_ret.get("data") or {}
    fullchain = cert.get("fullchain", "")
    privkey = cert.get("privkey", "")
    chain = cert.get("chain", "")
    cur_hash = material_hash or cert.get("material_hash")

    if not fullchain or not privkey or not chain:
        logger.warning("[mtls] %s: LE_GET_CERT returned incomplete material "
                       "(fullchain/privkey/chain) — cannot provision mTLS", domain)
        return [{"domain": domain, "module_type": None, "identifier": None,
                 "status": "ERROR",
                 "message": "incomplete cert material (need fullchain+privkey+chain)",
                 "mtls": True}]

    logger.info("[mtls] %s: fanning out mTLS materials to %d primary spoke(s)%s",
                domain, len(stale_spokes),
                " + hub" if (include_hub and not hub_current) else "")

    payload = {"ca_bundle": chain, "client_cert": fullchain, "client_key": privkey}

    for sid, mt in stale_spokes:
        entry = {"domain": domain, "module_type": mt, "identifier": sid, "mtls": True}
        # Durable push: an offline spoke is queued (mailbox) and provisioned on
        # reconnect instead of orphaned. 120s upper bound for the live path; a
        # queued push returns immediately.
        res = await push(sid, "SPOKE_SET_MTLS_MATERIALS", payload, timeout=120.0)
        queued = bool(isinstance(res, dict) and res.get("queued"))
        rret = res.get("result") if isinstance(res, dict) else None
        rret = _unwrap(rret) if rret is not None else {}
        if queued:
            # Pushed to the durable mailbox — will land on the spoke's next
            # reconnect. Not an error and not yet confirmed-installed: don't
            # stamp the push-state hash (so the next loop re-attempts the live
            # push once the spoke is back, then stamps it on a live SUCCESS).
            entry.update(status="QUEUED",
                         message=(res.get("message") if isinstance(res, dict)
                                  else "queued for delivery on reconnect"),
                         queued=True)
            logger.info("[mtls] %s → %s/%s: queued (offline) — delivers on reconnect",
                        domain, mt, sid)
        elif isinstance(rret, dict) and rret.get("status") == "SUCCESS":
            entry.update(status="SUCCESS",
                         message=(rret.get("message") or "installed"),
                         queued=False)
            if cur_hash:
                push_state[_key(sid)] = cur_hash
            logger.info("[mtls] %s → %s/%s: installed — %s",
                        domain, mt, sid, entry["message"])
        else:
            msg = (rret.get("message") if isinstance(rret, dict)
                   else (res.get("message") if isinstance(res, dict) else "push failed"))
            entry.update(status="ERROR", message=msg, queued=False)
            logger.warning("[mtls] %s → %s/%s: FAILED — %s", domain, mt, sid, msg)
        summary.append(entry)

    # Hub self-install (the wildcard as the hub server cert + the chain as
    # LM_MTLS_CA). One hub TLS endpoint; identifier "hub".
    if include_hub and not hub_current:
        hentry = {"domain": domain, "module_type": "hub", "identifier": "hub", "mtls": True}
        try:
            hret = await install_on_hub(domain, fullchain, privkey, chain, "hub")
        except Exception as e:  # never let a self-install crash the fan-out
            hret = {"status": "ERROR", "message": str(e)}
        if isinstance(hret, dict) and hret.get("status") == "SUCCESS":
            hentry.update(status="SUCCESS", message=hret.get("message") or "installed on hub")
            if cur_hash:
                push_state[_key("hub")] = cur_hash
            logger.info("[mtls] %s → hub: %s", domain, hentry["message"])
        else:
            hentry.update(status="ERROR",
                          message=(hret.get("message") if isinstance(hret, dict)
                                   else "hub self-install failed"))
            logger.warning("[mtls] %s → hub: FAILED — %s", domain, hentry["message"])
        summary.append(hentry)

    ok = sum(1 for s in summary if s.get("status") == "SUCCESS")
    logger.info("[mtls] %s: fanned out mTLS materials %d/%d target(s) OK",
                domain, ok, len(summary))
    return summary


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
        # Same generous window as the explicit-target path: hypervisor +
        # simulation relay INSTALL_CERT to a per-node pxmx agent that runs
        # `pvenode cert set --restart`, and a loaded pveproxy restart can take
        # minutes. 640s (> spoke 620s relay > agent 600s pvenode wait) keeps the
        # hub from timing out FIRST and recording ERROR for a deploy that
        # actually succeeded on the node — the "installed to Proxmox but UI says
        # failed" symptom. Fast targets stay at 120s (upper bound, not duration).
        install_timeout = 640.0 if mt in ("hypervisor", "simulation") else 120.0
        res = await rr(sid, "INSTALL_CERT", {
            "domain": domain, "fullchain": fullchain, "privkey": privkey,
            "chain": chain, "identifier": sid, "module_type": mt,
        }, timeout=install_timeout)
        rret = _unwrap(res)
        if isinstance(rret, dict) and rret.get("devices") is not None:
            entry["devices"] = rret["devices"]
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


def build_available_targets(spoke_module_types: Dict[str, str],
                            active_connections, module_names: Dict[str, str],
                            capable: Set[str],
                            agents: List[Dict[str, Any]],
                            netbox_server_agents=None) -> List[Dict[str, Any]]:
    """Build the click-to-add list of cert distribution targets from live hub
    state — the ``GET /api/le/targets/available`` payload. One entry per
    cert-capable CONNECTED spoke (by ``module_type``), EXCEPT agent-hosting
    types (``hypervisor``/``simulation``) which list EACH connected pxmx agent
    as a per-node target (``identifier`` = ``agent_id``) plus an "all nodes"
    broadcast entry per connected agent-hosting spoke. Offline / non-cert-capable
    spokes are omitted — they'd only ERROR on distribute.

    Pure (no hub/relay deps) so the route is thin and this is unit-testable.

    ``spoke_module_types``: ``{spoke_id: module_type}`` (live registrations).
    ``active_connections``: container supporting ``in`` for connected spoke_ids.
    ``module_names``: ``{spoke_id: display_name}``.
    ``capable``: ``CERT_CAPABLE_MODULES`` set.
    ``agents``: pxmx ``GET_AGENTS`` aggregate entries
    (``{agent_id, spoke_id, display_name?, hostname?}``); may be empty/None.

    Returns a list of ``{module_type, identifier, label, ...}`` (``spoke_id`` on
    spoke-level entries, ``agent_id`` on per-node entries). A connected
    agent-hosting spoke with ZERO agents emits NO entry (it has no device to
    install a cert on — the "no device added" case). The hub itself is always
    installed, so a ``hub`` self-install entry is always present."""
    agent_hosting = {"hypervisor", "simulation"}
    names = module_names if isinstance(module_names, dict) else {}
    targets: List[Dict[str, Any]] = []
    # The hub is always installed — its self-install target (install_on_hub in
    # distribute_cert_to_targets) is always selectable. No spoke advertises
    # module_type "hub", so without this it wouldn't appear in the live registry.
    targets.append({"module_type": "hub", "identifier": "",
                    "label": "hub (LM WebUI)"})
    # Connected agent-hosting spokes that actually have ≥1 agent (used to gate
    # the "all nodes" broadcast below — a spoke with zero agents has no device).
    agent_spoke_ids = {a.get("spoke_id") for a in (agents or []) if a.get("spoke_id")}
    # Non-agent-hosting cert-capable connected spokes: one entry each.
    for sid, mt in spoke_module_types.items():
        if sid not in active_connections:
            continue
        if mt not in capable or mt in agent_hosting:
            continue
        label = names.get(sid, sid) or sid
        targets.append({"module_type": mt, "identifier": "",
                        "label": f"{mt} — {label}", "spoke_id": sid})
    # Agent-hosting: each connected pxmx agent = a per-node target.
    for a in agents or []:
        mt = spoke_module_types.get(a.get("spoke_id"))
        if mt not in capable:
            continue
        aid = a.get("agent_id") or ""
        label = a.get("display_name") or a.get("hostname") or aid
        targets.append({"module_type": mt, "identifier": aid,
                        "label": f"{mt}/{label}", "agent_id": aid})
    # "all nodes" broadcast entry per connected agent-hosting spoke. Include the
    # spoke's display name so multiple spokes of the SAME agent-hosting type
    # (e.g. three "simulation" cs spokes) render as DISTINCT entries instead of
    # three identical "simulation — all nodes" rows — each broadcasts to the
    # nodes under that ONE spoke, so they are genuinely different targets. The
    # name is appended only when there is more than one spoke of this type.
    _by_type = {}
    for _sid, _mt in spoke_module_types.items():
        # A connected agent-hosting spoke with ZERO agents (no device added) is
        # omitted entirely — skip it so it can't be selected as a target.
        if (_sid in active_connections and _mt in capable and _mt in agent_hosting
                and _sid in agent_spoke_ids):
            _by_type.setdefault(_mt, []).append(_sid)
    for mt, sids in _by_type.items():
        multi = len(sids) > 1
        for sid in sids:
            nm = names.get(sid, sid) or sid
            label = f"{mt} — all nodes ({nm})" if multi else f"{mt} — all nodes"
            targets.append({"module_type": mt, "identifier": "",
                            "label": label, "spoke_id": sid})
    # NetBox web server: a generic agent that ran the netbox-server deploy role
    # (module_type "agent", so not in the loops above). It has the local nginx
    # cert helper, so it — not the API-only IPAM spoke — is the correct cert
    # target for the NetBox HTTPS endpoint. identifier = the agent's spoke_id.
    for sid in (netbox_server_agents or []):
        if sid not in active_connections:
            continue
        nm = names.get(sid, sid) or sid
        targets.append({"module_type": "netbox-server", "identifier": sid,
                        "label": f"netbox-server — {nm}", "spoke_id": sid})
    return targets