"""Peer (client) cert extraction for the unified :443 WebSocket server.

The hub's mTLS leg is PERMISSIVE (``CERT_OPTIONAL`` + ``ssl_ca_certs``) so a
presented client cert is *verified* at the TLS layer — but uvicorn's default
WebSocket protocol never surfaces the peer cert to the ASGI app: the ``scope``
built in ``websockets_impl.process_request`` has no ssl/peer-cert field, and
starlette's ``WebSocket`` exposes no transport. So nothing in the app can tell
*which* cert a connection presented — only that a valid one was (or wasn't).

H1 needs that identity: the reverse ``HUB_REQUEST`` channel is gated to a
*pinned* BugFixer cert, not just "a valid fleet cert" (every spoke presents the
same LE wildcard, so chain-validity alone can't distinguish BugFixer). This
module bridges that gap with a thin uvicorn WS-protocol subclass that reads the
peer cert off the transport's ``ssl_object`` and stashes the ``getpeercert()``
dict on ``scope["extensions"]["x_peer_cert"]`` for the ``/ws/spoke`` route to
read. The subclass is **fail-safe**: all extraction is wrapped so it can never
raise out of ``run_asgi`` (an exception before ``super().run_asgi()`` would skip
the app call and drop the connection). A failed/absent extraction leaves
``x_peer_cert = None``; the H1 gate treats ``None`` as "no cert → deny"
(fail-closed). Normal spokes never send ``HUB_REQUEST``, so the worst case is
"BugFixer denied," never a fleet-wide break.

The pure helper ``peer_cert_identity_from_getpeercert`` is the testable surface
(the protocol subclass is transport-coupled and not unit-tested). It derives a
renewal-stable identity — the cert's SAN DNS names (subject-CN fallback) — from
the parsed ``getpeercert()`` dict.
"""

from __future__ import annotations

import logging
from typing import Any, Optional, Tuple

logger = logging.getLogger("Hub")

# The uvicorn ws-protocol class is an internal API (not part of uvicorn's public
# surface), so import it defensively: if a uvicorn upgrade moves/renames it, we
# fall back to the default protocol (``ws="auto"``) rather than brick the hub
# boot. The H1 gate then simply sees no peer cert → denies HUB_REQUEST until the
# import path is restored.
_PeerCertProtocol: Optional[type] = None
try:
    from uvicorn.protocols.websockets.websockets_impl import (
        WebSocketProtocol as _UvicornWebSocketProtocol,
    )

    class PeerCertWebSocketProtocol(_UvicornWebSocketProtocol):
        """``WebSocketProtocol`` that injects the verified peer cert into scope.

        Overrides ``run_asgi`` (the race-free injection point: ``self.scope`` is
        already built by ``process_request`` and this coroutine is the one that
        hands it to the app, so mutating it here is single-threaded and arrives
        before the app sees scope). Does NOT touch handshake, verification, or
        connection admission — uvicorn still does ``CERT_OPTIONAL`` verify — it
        only ADDS one key to ``scope["extensions"]``. Harmless for routes that
        don't read it (``/ws/agent`` proxy, plaintext/browser connections →
        ``ssl_object`` is None → ``x_peer_cert = None``).
        """

        async def run_asgi(self) -> None:  # type: ignore[override]
            # Fail-safe prelude: never let extraction raise into the app dispatch
            # (an exception before super().run_asgi() would drop the connection).
            try:
                transport = getattr(self, "transport", None)
                ssl_obj = transport.get_extra_info("ssl_object") if transport else None
                peer_cert = ssl_obj.getpeercert() if ssl_obj is not None else None
            except Exception:  # noqa: BLE001 - extraction is best-effort, fail-closed
                peer_cert = None
            try:
                self.scope.setdefault("extensions", {})["x_peer_cert"] = peer_cert
            except Exception:  # noqa: BLE001 - scope may be absent in odd paths
                pass
            await super().run_asgi()

    _PeerCertProtocol = PeerCertWebSocketProtocol
except Exception:  # noqa: BLE001 - never brick the boot on an internal-API move
    logger.warning(
        "[H1] could not import uvicorn WebSocketProtocol; peer-cert extraction "
        "disabled (HUB_REQUEST will deny until the import path is restored)."
    )


def peer_cert_identity_from_getpeercert(d: Any) -> Optional[Tuple[str, ...]]:
    """Derive a renewal-stable cert identity from a parsed ``getpeercert()`` dict.

    Returns the cert's SAN DNS names (subject commonName fallback) as a tuple,
    or ``None`` if there is no usable identity (``None``/``{}``/malformed). The
    identity is stable across LE renewals — the same domain(s) are re-issued —
    unlike a fingerprint, which rotates every 60–90 days. Never raises.

    ``getpeercert()`` (binary_form=False) returns:
    - ``None``  — no cert presented (plaintext / browser / mTLS off).
    - ``{}``    — a cert was presented but NOT validated (CERT_NONE / no CA).
    - a dict with ``'subject'`` (tuple of RDNs of ``(type, value)`` pairs) and
      ``'subjectAltName'`` (tuple of ``('DNS', name)`` / ``('IP Address', ip)``
      / …) when a cert was verified — the only case with a real identity.

    Under the hub's PERMISSIVE mTLS (``ssl_ca_certs`` + ``CERT_OPTIONAL``) a
    presented cert that fails verification is rejected at handshake, so a
    non-empty dict here implies the cert was CA-verified.
    """
    if not isinstance(d, dict) or not d:
        return None
    names: list = []
    try:
        san = d.get("subjectAltName") or ()
        for entry in san:
            # Each entry is a (type, value) tuple, e.g. ('DNS', 'bugfixer.lm.io').
            if isinstance(entry, tuple) and len(entry) == 2 and entry[0] == "DNS":
                val = entry[1]
                if isinstance(val, str) and val:
                    names.append(val)
    except Exception:  # noqa: BLE001 - never raise on a malformed dict
        names = []
    if not names:
        # Fallback to the subject commonName when there are no DNS SANs.
        try:
            for rdn in d.get("subject") or ():
                for attr in rdn or ():
                    if (
                        isinstance(attr, tuple)
                        and len(attr) == 2
                        and attr[0] == "commonName"
                        and isinstance(attr[1], str)
                        and attr[1]
                    ):
                        names.append(attr[1])
        except Exception:  # noqa: BLE001
            names = []
    return tuple(names) if names else None