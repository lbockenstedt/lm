"""Hub-side mTLS ENFORCEMENT for ``/ws/spoke`` connections.

The hub's internal CA (``security/mtls_ca.py``) issues every remote spoke a
``clientAuth`` cert; this module makes that cert *mean* something.

The TLS listener is CERT_OPTIONAL because the unified :443 socket also serves
cert-less browsers, so enforcement happens here, per spoke, after the spoke
has authenticated:

* **Binding.** A presented cert that chains to the hub CA (checked
  cryptographically, see ``mtls_ca.inspect_client_cert``) must name THIS spoke:
  a SAN equal to its spoke_id / primary key / parent agent, or a serial the hub
  issued to this primary key. A hub-CA cert issued to another spoke → reject.
* **Revocation.** A presented cert whose serial was revoked → reject.
* **Wait for the cert (enrollment).** An approved, remote spoke that connects
  WITHOUT a hub-CA cert is put in enrollment-only mode: the hub issues its
  cert (CSR when the spoke supports it) and processes nothing else on that
  connection — no config push, no mailbox flush, no inbound commands — until
  the spoke reconnects presenting the cert. Unapproved spokes were already
  limited to the approval handshake.
* **Ratchet.** Once a spoke has presented a verified cert it is *bound*: a later
  cert-less connect is refused outright (a stolen session secret alone can no
  longer impersonate it or enroll a new cert). An admin re-issue
  (``/api/mtls/reprovision``) re-arms enrollment for a spoke that legitimately
  lost its cert.

Escape hatches: ``LM_MTLS_ENFORCE=0`` (env) or ``global_config.mtls_enforce =
False`` turn enforcement off; ``LM_MTLS_DISABLE=1`` turns mTLS off entirely.
A never-bound spoke that fails ``_MTLS_ENROLL_MAX`` enrollments (e.g. TLS is
terminated by an intermediary so its cert can never reach the hub) falls back
to degraded cert-less operation with a loud event, unless
``global_config.mtls_require_cert`` is True (strict: it stays enrollment-only).
"""

import asyncio
import logging
import os
import time
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger("Hub")

#: Close code when a bound/revoked spoke connects without a valid cert.
CLOSE_CERT_REQUIRED = 4401
#: Close code when a presented hub-CA cert belongs to another spoke / is revoked.
CLOSE_CERT_REJECTED = 4403

_MTLS_ENROLL_MAX = 3
#: How long an enrollment-only connection may linger before the hub closes it
#: (the spoke normally restarts itself seconds after installing the cert).
_MTLS_ENROLL_TIMEOUT_S = 180.0


def _mtls_mod():
    try:
        from security import mtls as _m
    except Exception:  # noqa: BLE001
        import mtls as _m  # type: ignore
    return _m


def _mtls_ca_mod():
    try:
        from security import mtls_ca as _m
    except Exception:  # noqa: BLE001
        import mtls_ca as _m  # type: ignore
    return _m


class HubMtlsEnforcementMixin:
    """Connect-time cert↔spoke binding, revocation and enrollment gating."""

    # ── policy knobs ──────────────────────────────────────────────────────
    def _mtls_enforcing(self) -> bool:
        if str(os.getenv("LM_MTLS_ENFORCE", "")).strip().lower() in ("0", "false", "no", "off"):
            return False
        try:
            m = _mtls_mod()
            if not m.mtls_enabled():
                return False
            # Only enforce when THIS process's listener actually requests client
            # certs. mTLS toggled on at runtime arms the listener on the next
            # restart; enforcing before then would see every spoke as cert-less
            # (and refuse every already-bound one).
            if not m.listener_client_auth_armed():
                return False
        except Exception:  # noqa: BLE001
            return False
        gc = self.state.get_global_config() or {}
        return bool(gc.get("mtls_enforce", True))

    def _mtls_strict(self) -> bool:
        gc = self.state.get_global_config() or {}
        return bool(gc.get("mtls_require_cert", False))

    # ── persisted per-spoke records ──────────────────────────────────────
    def _mtls_records(self, key: str) -> Dict[str, Any]:
        return self.state.system_state.setdefault(key, {})

    def _mtls_mark_dirty(self) -> None:
        try:
            self.state._mark_dirty()
        except Exception:  # noqa: BLE001
            pass

    def _mtls_revoked_serials(self) -> Dict[str, Any]:
        """serial(hex) → {pk, revoked_at, not_after_ts}; expired entries pruned."""
        rs = self._mtls_records("mtls_revoked_serials")
        now = time.time()
        for s in [s for s, v in rs.items()
                  if float((v or {}).get("not_after_ts") or 0) and float(v["not_after_ts"]) < now]:
            rs.pop(s, None)
        return rs

    def _mtls_record_revoked_serial(self, pk: str, serial: str, not_after_ts: float = 0.0) -> None:
        serial = (serial or "").strip().lower().lstrip("0") or ""
        if not serial:
            return
        self._mtls_revoked_serials()[serial] = {
            "pk": pk, "revoked_at": time.time(), "not_after_ts": float(not_after_ts or 0)}
        self._mtls_mark_dirty()

    def _mtls_allow_reenroll(self, pk: str) -> None:
        """Admin re-issue: let the spoke enroll once more — a bound spoke that
        lost its cert, a revoked spoke, or one still presenting a cert the gate
        rejects (revoked while offline / pre-rename SAN). The flag is one-shot
        (consumed when enrollment starts)."""
        bound = self._mtls_records("mtls_bound")
        b = bound.setdefault(pk, {})
        b["reenroll"] = True
        self._mtls_records("mtls_enroll").pop(pk, None)
        (self.state.system_state.get("mtls_revoked") or {}).pop(pk, None)
        self._mtls_mark_dirty()

    # ── identity checks ──────────────────────────────────────────────────
    def _mtls_peer_info(self, websocket) -> Optional[Dict[str, Any]]:
        der = getattr(websocket, "peer_cert_der", None)
        if not der:
            return None
        try:
            return _mtls_ca_mod().inspect_client_cert(der)
        except Exception:  # noqa: BLE001
            return None

    def _mtls_cert_names_spoke(self, spoke_id: str, pk: str, info: Dict[str, Any]) -> bool:
        names = {n for n in (spoke_id, pk) if n}
        pm = getattr(self, "spoke_parent_map", None) or {}
        parent = pm.get(pk) or pm.get(spoke_id)
        if parent:
            names.add(parent)
            try:
                names.add(self._primary_key(parent))
            except Exception:  # noqa: BLE001
                pass
        if any(s in names for s in (info.get("sans") or ())):
            return True
        serial = (info.get("serial") or "").lower().lstrip("0")
        reg = (self.state.system_state.get("mtls_client_certs", {}) or {}).get(pk) or {}
        known = {str(reg.get("serial") or "").lower().lstrip("0"),
                 str(reg.get("prev_serial") or "").lower().lstrip("0")} - {""}
        return bool(serial and serial in known)

    def _mtls_exempt_reason(self, spoke_id: str, pk: str, module_type: str) -> str:
        """Why this spoke can't be required to present a hub-CA cert ('' = not exempt)."""
        try:
            if self._is_loopback_spoke(spoke_id):
                return "loopback"
        except Exception:  # noqa: BLE001
            pass
        try:
            if self._is_role_subspoke(spoke_id):
                return "role-subspoke"
        except Exception:  # noqa: BLE001
            pass
        try:
            from hub_cert_distribution import CLIENT_ONLY_MTLS_TYPES
        except Exception:  # noqa: BLE001
            CLIENT_ONLY_MTLS_TYPES = frozenset({"ab"})
        if module_type in CLIENT_ONLY_MTLS_TYPES:
            return "client-only-type"
        gc = self.state.get_global_config() or {}
        if not gc.get("mtls_ca_auto_provision", True):
            return "auto-provision-off"
        return ""

    def _mtls_connect_gate(self, spoke_id: str, pk: str, websocket,
                           module_type: str = "") -> Tuple[str, str]:
        """Decide what an APPROVED spoke's connection may do.

        Returns ``(decision, reason)`` with decision one of ``ok`` (normal
        operation), ``enroll`` (cert issuance only) or ``reject`` (close)."""
        enforcing = self._mtls_enforcing()
        info = self._mtls_peer_info(websocket)
        if info and info.get("hub_ca"):
            serial = (info.get("serial") or "").lower().lstrip("0")
            bad = ""
            if enforcing and serial and serial in self._mtls_revoked_serials():
                bad = "revoked-cert"
            elif enforcing and not self._mtls_cert_names_spoke(spoke_id, pk, info):
                bad = "cert-identity-mismatch"
            if bad:
                # Admin re-armed this identity → replace the bad cert via
                # enrollment instead of refusing forever.
                if (self._mtls_records("mtls_bound").get(pk) or {}).get("reenroll"):
                    return "enroll", f"reenroll:{bad}"
                return "reject", bad
            bound = self._mtls_records("mtls_bound")
            prev = bound.get(pk) or {}
            bound[pk] = {"spoke_id": spoke_id, "serial": serial,
                         "first_bound_at": prev.get("first_bound_at") or time.time(),
                         "last_seen": time.time()}
            self._mtls_records("mtls_enroll").pop(pk, None)
            self._mtls_mark_dirty()
            return "ok", "verified"
        if not enforcing:
            return "ok", "not-enforcing"
        exempt = self._mtls_exempt_reason(spoke_id, pk, module_type or "")
        if exempt:
            return "ok", f"exempt:{exempt}"
        if pk in (self.state.system_state.get("mtls_revoked", {}) or {}):
            return "reject", "revoked-identity"
        b = self._mtls_records("mtls_bound").get(pk)
        if b and not b.get("reenroll"):
            return "reject", "cert-required"
        attempts = int((self._mtls_records("mtls_enroll").get(pk) or {}).get("attempts") or 0)
        if attempts >= _MTLS_ENROLL_MAX and not self._mtls_strict():
            return "ok", "enroll-exhausted"
        return "enroll", "no-cert"

    # ── actions ──────────────────────────────────────────────────────────
    async def _mtls_reject(self, spoke_id: str, pk: str, websocket, reason: str) -> None:
        code = CLOSE_CERT_REQUIRED if reason in ("cert-required", "revoked-identity") \
            else CLOSE_CERT_REJECTED
        text = {
            "cert-required": "mTLS client cert required (re-issue from the hub to re-enroll)",
            "revoked-identity": "mTLS cert revoked (re-issue from the hub to re-enroll)",
            "revoked-cert": "mTLS client cert revoked",
            "cert-identity-mismatch": "mTLS client cert does not belong to this spoke",
        }.get(reason, "mTLS rejected")
        logger.warning(f"[mtls] refusing {spoke_id}: {text} ({reason})")
        try:
            self.record_spoke_event(spoke_id, "mtls_rejected", reason)
        except Exception:  # noqa: BLE001
            pass
        tm = getattr(self, "threat_monitor", None)
        if tm is not None and reason in ("cert-identity-mismatch", "revoked-cert"):
            try:
                ip = ((self.spoke_telemetry or {}).get(pk) or {}).get("remote_ip")
                tm.note_anomaly("mtls_cert_rejected",
                                f"spoke={spoke_id} pk={pk} reason={reason}", ip,
                                severity="warning")
            except Exception:  # noqa: BLE001
                pass
        try:
            await websocket.close(code, text)
        except Exception:  # noqa: BLE001
            pass

    async def _mtls_begin_enrollment(self, spoke_id: str, pk: str, websocket) -> None:
        """Issue the cert to a cert-less approved spoke and hold the connection in
        enrollment-only mode until the spoke restarts presenting it."""
        rec = self._mtls_records("mtls_enroll").setdefault(pk, {})
        rec["attempts"] = int(rec.get("attempts") or 0) + 1
        rec["last"] = time.time()
        attempts = rec["attempts"]
        b = self._mtls_records("mtls_bound").get(pk)
        if b is not None:
            b.pop("reenroll", None)  # one re-enrollment per admin re-issue
        self._mtls_mark_dirty()
        enrolling = getattr(self, "_mtls_enrolling", None)
        if enrolling is None:
            enrolling = self._mtls_enrolling = {}
        enrolling[pk] = websocket
        logger.info(f"[mtls] {spoke_id} connected without a hub-CA client cert — "
                    f"enrollment-only until it presents one (attempt {attempts}/"
                    f"{_MTLS_ENROLL_MAX}{', strict' if self._mtls_strict() else ''})")
        try:
            self.record_spoke_event(spoke_id, "mtls_enrollment", f"attempt={attempts}")
        except Exception:  # noqa: BLE001
            pass
        asyncio.create_task(self._mtls_enrollment_task(spoke_id, pk, websocket))

    async def _mtls_enrollment_task(self, spoke_id: str, pk: str, websocket) -> None:
        try:
            r = await self._provision_spoke_mtls_cert(spoke_id, force=True)
            if (r or {}).get("status") not in ("SUCCESS",):
                logger.warning(f"[mtls] enrollment issue for {spoke_id} failed: {r}")
            deadline = time.time() + _MTLS_ENROLL_TIMEOUT_S
            while time.time() < deadline:
                if (getattr(self, "_mtls_enrolling", {}) or {}).get(pk) is not websocket:
                    return
                await asyncio.sleep(2.0)
            if (getattr(self, "_mtls_enrolling", {}) or {}).get(pk) is websocket:
                logger.warning(f"[mtls] {spoke_id} did not reconnect with its cert "
                               f"within {int(_MTLS_ENROLL_TIMEOUT_S)}s — closing")
                try:
                    await websocket.close(CLOSE_CERT_REQUIRED, "mTLS enrollment incomplete")
                except Exception:  # noqa: BLE001
                    pass
        except Exception as e:  # noqa: BLE001
            logger.warning(f"[mtls] enrollment for {spoke_id} errored: {e}")

    def _mtls_enrollment_done(self, pk: str, websocket) -> None:
        enrolling = getattr(self, "_mtls_enrolling", None) or {}
        if enrolling.get(pk) is websocket:
            enrolling.pop(pk, None)
