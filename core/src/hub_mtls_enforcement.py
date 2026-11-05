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

# asyncio runs the background enrollment task and its polling sleeps.
import asyncio
# Standard-library logging for accept/reject/enrollment messages.
import logging
# os reads the LM_MTLS_ENFORCE environment override.
import os
# time.time() timestamps bindings, revocations and enrollment deadlines.
import time
# Type hints only.
from typing import Any, Dict, Optional, Tuple

# Use the hub's main logger so mTLS decisions appear with other hub output.
logger = logging.getLogger("Hub")

#: Close code when a bound/revoked spoke connects without a valid cert.
CLOSE_CERT_REQUIRED = 4401
#: Close code when a presented hub-CA cert belongs to another spoke / is revoked.
CLOSE_CERT_REJECTED = 4403

# Failed enrollments allowed before a never-bound spoke falls back to cert-less mode.
_MTLS_ENROLL_MAX = 3
#: How long an enrollment-only connection may linger before the hub closes it
#: (the spoke normally restarts itself seconds after installing the cert).
_MTLS_ENROLL_TIMEOUT_S = 180.0


def _mtls_mod():
    """Return the hub's mtls module, whether imported as a package or as a flat module."""
    # Prefer the package import; fall back to the flat layout used by some tests/tools.
    try:
        from security import mtls as _m
    except Exception:  # noqa: BLE001
        import mtls as _m  # type: ignore
    return _m


def _mtls_ca_mod():
    """Return the hub's mtls_ca module, whether imported as a package or as a flat module."""
    # Prefer the package import; fall back to the flat layout used by some tests/tools.
    try:
        from security import mtls_ca as _m
    except Exception:  # noqa: BLE001
        import mtls_ca as _m  # type: ignore
    return _m


class HubMtlsEnforcementMixin:
    """Connect-time cert↔spoke binding, revocation and enrollment gating."""

    # ── policy knobs ──────────────────────────────────────────────────────
    def _mtls_enforcing(self) -> bool:
        """Return True when cert binding/enrollment should actually be enforced right now."""
        # Environment override: an explicit "off" value disables enforcement.
        if str(os.getenv("LM_MTLS_ENFORCE", "")).strip().lower() in ("0", "false", "no", "off"):
            return False
        # Any problem reading mTLS status means "do not enforce" (fail open to avoid lockouts).
        try:
            m = _mtls_mod()
            # mTLS switched off entirely: nothing to enforce.
            if not m.mtls_enabled():
                return False
            # Only enforce when THIS process's listener actually requests client
            # certs. mTLS toggled on at runtime arms the listener on the next
            # restart; enforcing before then would see every spoke as cert-less
            # (and refuse every already-bound one).
            if not m.listener_client_auth_armed():
                return False
        # Could not determine status: do not enforce.
        except Exception:  # noqa: BLE001
            return False
        # Finally honour the admin setting (default on).
        gc = self.state.get_global_config() or {}
        return bool(gc.get("mtls_enforce", True))

    def _mtls_strict(self) -> bool:
        """Return True in strict mode, where a spoke must eventually present a cert (no
        fallback).
        """
        # Read the strict-mode setting (default off).
        gc = self.state.get_global_config() or {}
        return bool(gc.get("mtls_require_cert", False))

    # ── persisted per-spoke records ──────────────────────────────────────
    def _mtls_records(self, key: str) -> Dict[str, Any]:
        """Return the persisted per-spoke record dict stored under ``key`` (created if missing)."""
        # Lives in system_state so it is saved and survives restarts.
        return self.state.system_state.setdefault(key, {})

    def _mtls_mark_dirty(self) -> None:
        """Flag hub state as changed so it is persisted; failures are ignored."""
        # Best-effort: a failure here only delays persistence.
        try:
            self.state._mark_dirty()
        except Exception:  # noqa: BLE001
            pass

    def _mtls_revoked_serials(self) -> Dict[str, Any]:
        """serial(hex) → {pk, revoked_at, not_after_ts}; expired entries pruned."""
        # The revoked-serial table.
        rs = self._mtls_records("mtls_revoked_serials")
        # Drop entries whose certificate has expired anyway (nothing left to revoke).
        now = time.time()
        for s in [s for s, v in rs.items()
                  if float((v or {}).get("not_after_ts") or 0) and float(v["not_after_ts"]) < now]:
            rs.pop(s, None)
        # Return the pruned table.
        return rs

    def _mtls_record_revoked_serial(self, pk: str, serial: str, not_after_ts: float = 0.0) -> None:
        """Record a certificate serial as revoked for primary key ``pk``."""
        # Normalise the serial: lower-case hex without leading zeros, so comparisons match.
        serial = (serial or "").strip().lower().lstrip("0") or ""
        # Nothing to record without a serial.
        if not serial:
            return
        # Store who it belonged to, when it was revoked and when it would expire.
        self._mtls_revoked_serials()[serial] = {
            "pk": pk, "revoked_at": time.time(), "not_after_ts": float(not_after_ts or 0)}
        # Persist the change.
        self._mtls_mark_dirty()

    def _mtls_allow_reenroll(self, pk: str) -> None:
        """Admin re-issue: let the spoke enroll once more — a bound spoke that
        lost its cert, a revoked spoke, or one still presenting a cert the gate
        rejects (revoked while offline / pre-rename SAN). The flag is one-shot
        (consumed when enrollment starts)."""
        # Set the one-shot re-enroll flag on the spoke's binding record.
        bound = self._mtls_records("mtls_bound")
        b = bound.setdefault(pk, {})
        b["reenroll"] = True
        # Reset its enrollment attempt counter.
        self._mtls_records("mtls_enroll").pop(pk, None)
        # Lift any identity-level revocation.
        (self.state.system_state.get("mtls_revoked") or {}).pop(pk, None)
        # Persist the change.
        self._mtls_mark_dirty()

    # ── identity checks ──────────────────────────────────────────────────
    def _mtls_peer_info(self, websocket) -> Optional[Dict[str, Any]]:
        """Return details of the client certificate the spoke presented, or None if
        none/unreadable.
        """
        # Raw certificate bytes captured by the TLS layer, if any.
        der = getattr(websocket, "peer_cert_der", None)
        if not der:
            return None
        # Parse and verify it; an unparseable cert counts as no cert.
        try:
            return _mtls_ca_mod().inspect_client_cert(der)
        except Exception:  # noqa: BLE001
            return None

    def _mtls_cert_names_spoke(self, spoke_id: str, pk: str, info: Dict[str, Any]) -> bool:
        """Return True if the certificate's names or serial tie it to this spoke."""
        # Acceptable identities: the spoke id and its primary key...
        names = {n for n in (spoke_id, pk) if n}
        # ...plus its parent agent (and the parent's primary key), for relayed spokes.
        pm = getattr(self, "spoke_parent_map", None) or {}
        parent = pm.get(pk) or pm.get(spoke_id)
        if parent:
            names.add(parent)
            # Resolving the parent's primary key is optional.
            try:
                names.add(self._primary_key(parent))
            except Exception:  # noqa: BLE001
                pass
        # Any matching Subject Alternative Name binds the cert to this spoke.
        if any(s in names for s in (info.get("sans") or ())):
            return True
        # Otherwise accept a serial the hub itself issued to this primary key (current or previous).
        serial = (info.get("serial") or "").lower().lstrip("0")
        reg = (self.state.system_state.get("mtls_client_certs", {}) or {}).get(pk) or {}
        known = {str(reg.get("serial") or "").lower().lstrip("0"),
                 str(reg.get("prev_serial") or "").lower().lstrip("0")} - {""}
        return bool(serial and serial in known)

    def _mtls_exempt_reason(self, spoke_id: str, pk: str, module_type: str) -> str:
        """Why this spoke can't be required to present a hub-CA cert ('' = not exempt)."""
        # Loopback (same-host) spokes cannot present certs over the local socket.
        try:
            if self._is_loopback_spoke(spoke_id):
                return "loopback"
        except Exception:  # noqa: BLE001
            pass
        # Role sub-spokes ride their parent agent's connection.
        try:
            if self._is_role_subspoke(spoke_id):
                return "role-subspoke"
        except Exception:  # noqa: BLE001
            pass
        # Some module types only use mTLS as clients; default list if the import fails.
        try:
            from hub_cert_distribution import CLIENT_ONLY_MTLS_TYPES
        except Exception:  # noqa: BLE001
            CLIENT_ONLY_MTLS_TYPES = frozenset({"ab"})
        # Those types are exempt.
        if module_type in CLIENT_ONLY_MTLS_TYPES:
            return "client-only-type"
        # If the admin turned off automatic cert issuance, spokes cannot be expected to have one.
        gc = self.state.get_global_config() or {}
        if not gc.get("mtls_ca_auto_provision", True):
            return "auto-provision-off"
        # Not exempt.
        return ""

    def _mtls_connect_gate(self, spoke_id: str, pk: str, websocket,
                           module_type: str = "") -> Tuple[str, str]:
        """Decide what an APPROVED spoke's connection may do.

        Returns ``(decision, reason)`` with decision one of ``ok`` (normal
        operation), ``enroll`` (cert issuance only) or ``reject`` (close)."""
        # Is enforcement on, and what cert (if any) did the spoke present?
        enforcing = self._mtls_enforcing()
        info = self._mtls_peer_info(websocket)
        # A cert signed by our CA was presented.
        if info and info.get("hub_ca"):
            # Normalised serial for revocation lookups.
            serial = (info.get("serial") or "").lower().lstrip("0")
            # Reason the cert is unacceptable ("" = fine).
            bad = ""
            # Revoked serial.
            if enforcing and serial and serial in self._mtls_revoked_serials():
                bad = "revoked-cert"
            # Cert issued to some other spoke.
            elif enforcing and not self._mtls_cert_names_spoke(spoke_id, pk, info):
                bad = "cert-identity-mismatch"
            if bad:
                # Admin re-armed this identity → replace the bad cert via
                # enrollment instead of refusing forever.
                if (self._mtls_records("mtls_bound").get(pk) or {}).get("reenroll"):
                    return "enroll", f"reenroll:{bad}"
                return "reject", bad
            # Valid cert: record (or refresh) this spoke's binding so cert-less connects are refused
            # later.
            bound = self._mtls_records("mtls_bound")
            prev = bound.get(pk) or {}
            bound[pk] = {"spoke_id": spoke_id, "serial": serial,
                         "first_bound_at": prev.get("first_bound_at") or time.time(),
                         "last_seen": time.time()}
            # Clear any enrollment counter and persist.
            self._mtls_records("mtls_enroll").pop(pk, None)
            self._mtls_mark_dirty()
            return "ok", "verified"
        # No hub cert presented and not enforcing: allow.
        if not enforcing:
            return "ok", "not-enforcing"
        # Spokes that cannot hold a cert are allowed through.
        exempt = self._mtls_exempt_reason(spoke_id, pk, module_type or "")
        if exempt:
            return "ok", f"exempt:{exempt}"
        # Admin revoked this spoke's identity: refuse.
        if pk in (self.state.system_state.get("mtls_revoked", {}) or {}):
            return "reject", "revoked-identity"
        # Already bound (has used a cert before) and not re-armed: refuse cert-less connect.
        b = self._mtls_records("mtls_bound").get(pk)
        if b and not b.get("reenroll"):
            return "reject", "cert-required"
        # How many enrollments this spoke has already failed.
        attempts = int((self._mtls_records("mtls_enroll").get(pk) or {}).get("attempts") or 0)
        # Too many failures and not strict: fall back to degraded cert-less operation.
        if attempts >= _MTLS_ENROLL_MAX and not self._mtls_strict():
            return "ok", "enroll-exhausted"
        # Otherwise hold it in enrollment-only mode.
        return "enroll", "no-cert"

    # ── actions ──────────────────────────────────────────────────────────
    async def _mtls_reject(self, spoke_id: str, pk: str, websocket, reason: str) -> None:
        """Log, record and close a spoke connection refused by the mTLS gate."""
        # "Cert required" style reasons get 4401; bad presented certs get 4403.
        code = CLOSE_CERT_REQUIRED if reason in ("cert-required", "revoked-identity") \
            else CLOSE_CERT_REJECTED
        # Human-readable close reason.
        text = {
            "cert-required": "mTLS client cert required (re-issue from the hub to re-enroll)",
            "revoked-identity": "mTLS cert revoked (re-issue from the hub to re-enroll)",
            "revoked-cert": "mTLS client cert revoked",
            "cert-identity-mismatch": "mTLS client cert does not belong to this spoke",
        }.get(reason, "mTLS rejected")
        # Log the refusal.
        logger.warning(f"[mtls] refusing {spoke_id}: {text} ({reason})")
        # Record an event on the spoke's timeline (best-effort).
        try:
            self.record_spoke_event(spoke_id, "mtls_rejected", reason)
        except Exception:  # noqa: BLE001
            pass
        # Bad presented certs may indicate an attack, so tell the threat monitor.
        tm = getattr(self, "threat_monitor", None)
        if tm is not None and reason in ("cert-identity-mismatch", "revoked-cert"):
            # Include the spoke's last known IP for context; failures are ignored.
            try:
                ip = ((self.spoke_telemetry or {}).get(pk) or {}).get("remote_ip")
                tm.note_anomaly("mtls_cert_rejected",
                                f"spoke={spoke_id} pk={pk} reason={reason}", ip,
                                severity="warning")
            except Exception:  # noqa: BLE001
                pass
        # Close the websocket with the chosen code and message.
        try:
            await websocket.close(code, text)
        except Exception:  # noqa: BLE001
            pass

    async def _mtls_begin_enrollment(self, spoke_id: str, pk: str, websocket) -> None:
        """Issue the cert to a cert-less approved spoke and hold the connection in
        enrollment-only mode until the spoke restarts presenting it."""
        # Bump the attempt counter and remember when this attempt started.
        rec = self._mtls_records("mtls_enroll").setdefault(pk, {})
        rec["attempts"] = int(rec.get("attempts") or 0) + 1
        rec["last"] = time.time()
        attempts = rec["attempts"]
        # Consume the one-shot admin re-enroll flag.
        b = self._mtls_records("mtls_bound").get(pk)
        if b is not None:
            b.pop("reenroll", None)  # one re-enrollment per admin re-issue
        # Persist the change.
        self._mtls_mark_dirty()
        # Map of primary key -> websocket currently in enrollment, created on first use.
        enrolling = getattr(self, "_mtls_enrolling", None)
        if enrolling is None:
            enrolling = self._mtls_enrolling = {}
        # Remember this connection so a later reconnect can be recognised.
        enrolling[pk] = websocket
        # Log the enrollment.
        logger.info(f"[mtls] {spoke_id} connected without a hub-CA client cert — "
                    f"enrollment-only until it presents one (attempt {attempts}/"
                    f"{_MTLS_ENROLL_MAX}{', strict' if self._mtls_strict() else ''})")
        # Record an event on the spoke's timeline (best-effort).
        try:
            self.record_spoke_event(spoke_id, "mtls_enrollment", f"attempt={attempts}")
        except Exception:  # noqa: BLE001
            pass
        # Issue the cert and watch for reconnection in the background.
        asyncio.create_task(self._mtls_enrollment_task(spoke_id, pk, websocket))

    async def _mtls_enrollment_task(self, spoke_id: str, pk: str, websocket) -> None:
        """Issue a cert to the spoke, then close the connection if it does not reconnect with it
        in time.
        """
        # Any unexpected failure is logged; this is a background task.
        try:
            # Issue (or re-issue) the client cert to the spoke.
            r = await self._provision_spoke_mtls_cert(spoke_id, force=True)
            # Issuance problems are logged; the wait below still applies.
            if (r or {}).get("status") not in ("SUCCESS",):
                logger.warning(f"[mtls] enrollment issue for {spoke_id} failed: {r}")
            # Wait up to the enrollment timeout.
            deadline = time.time() + _MTLS_ENROLL_TIMEOUT_S
            while time.time() < deadline:
                # The spoke reconnected (this websocket is no longer the enrolling one): done.
                if (getattr(self, "_mtls_enrolling", {}) or {}).get(pk) is not websocket:
                    return
                await asyncio.sleep(2.0)
            # Still the same connection after the deadline: close it.
            if (getattr(self, "_mtls_enrolling", {}) or {}).get(pk) is websocket:
                logger.warning(f"[mtls] {spoke_id} did not reconnect with its cert "
                               f"within {int(_MTLS_ENROLL_TIMEOUT_S)}s — closing")
                # Closing can fail if the socket is already dead; ignore that.
                try:
                    await websocket.close(CLOSE_CERT_REQUIRED, "mTLS enrollment incomplete")
                except Exception:  # noqa: BLE001
                    pass
        # Log unexpected errors.
        except Exception as e:  # noqa: BLE001
            logger.warning(f"[mtls] enrollment for {spoke_id} errored: {e}")

    def _mtls_enrollment_done(self, pk: str, websocket) -> None:
        """Clear the enrollment marker when this websocket's connection ends."""
        # Map of connections currently in enrollment (may not exist yet).
        enrolling = getattr(self, "_mtls_enrolling", None) or {}
        # Only clear it if it still refers to this exact websocket.
        if enrolling.get(pk) is websocket:
            enrolling.pop(pk, None)
