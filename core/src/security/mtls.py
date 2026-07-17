"""mTLS plumbing for the Hub↔Spoke and Spoke↔Agent legs — PLUMBED, default-OFF.

Everything needed for mutual TLS is wired here but stays inert until
``LM_MTLS_ENABLED`` is turned on (after the LE wildcard is distributed to the
hub + spokes + /ws/agent listeners). Default behavior is unchanged: encrypted
but unverified (``ssl._create_unverified_context``) on the client side, no
client-cert requirement on the server side.

Activation flips two things with zero code change:
  * clients verify the server against the CA and present a client cert;
  * servers require + verify a client cert.

Env knobs (all optional):
  LM_MTLS_ENABLED=1        master switch (default off)
  LM_MTLS_CA=<path>        trusted CA bundle (the LE chain) for verification
  LM_MTLS_CLIENT_CERT      client cert this node presents (the wildcard)
  LM_MTLS_CLIENT_KEY       client key
  LM_TLS_CERT / LM_TLS_KEY server cert/key (already used by the listeners)

A leaf: stdlib only. Audience: transport developers.
"""

import os
import ssl


# Runtime override set by the hub from global_config.mtls_enabled (the WebUI knob),
# so enabling doesn't require an env change + restart. None → fall back to the env.
_runtime_enabled = None


def set_runtime_enabled(value) -> None:
    """Hub applies global_config.mtls_enabled here (startup + on the WebUI knob)."""
    global _runtime_enabled
    _runtime_enabled = None if value is None else bool(value)


def mtls_enabled() -> bool:
    """Master switch. Default OFF. Turn on only when every spoke/agent has the
    wildcard (see the readiness check) so enabling can't orphan a node."""
    # HARD kill-switch — wins over the runtime override AND the env master switch.
    # Lets an operator force mTLS fully OFF from the systemd env when the WebUI is
    # locked out (e.g. strict client-cert auth armed the unified :443 socket)
    # WITHOUT editing the Fernet-encrypted hub state or reaching the WebUI knob.
    if str(os.getenv("LM_MTLS_DISABLE", "")).strip().lower() in ("1", "true", "yes", "on"):
        return False
    if _runtime_enabled is not None:
        return _runtime_enabled
    return str(os.getenv("LM_MTLS_ENABLED", "")).strip().lower() in ("1", "true", "yes", "on")


def _paths():
    return (os.getenv("LM_MTLS_CA", "").strip(),
            os.getenv("LM_MTLS_CLIENT_CERT", "").strip(),
            os.getenv("LM_MTLS_CLIENT_KEY", "").strip())


def client_context(is_wss: bool):
    """SSL context for a client leg (spoke→hub, agent→spoke).

    Default (mTLS off): today's behavior — unverified-but-encrypted for wss,
    None for ws. mTLS on: verify the server against the CA and present the
    client cert (mutual auth), falling back safely if a path is missing so a
    misconfig can't hard-break the transport before activation is complete."""
    if not is_wss:
        return None
    if not mtls_enabled():
        return ssl._create_unverified_context()
    ca, cert, key = _paths()
    try:
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH,
                                         cafile=ca or None)
        ctx.check_hostname = bool(ca)  # only meaningful with a CA to verify against
        ctx.verify_mode = ssl.CERT_REQUIRED if ca else ssl.CERT_NONE
        if cert and key:
            ctx.load_cert_chain(cert, key)   # present our client cert (mutual)
        return ctx
    except Exception:  # noqa: BLE001 - never brick the transport on a bad path
        return ssl._create_unverified_context()


def server_verify_mode():
    """Client-cert verify mode for a server listener when mTLS is on.

    PERMISSIVE by default (``CERT_OPTIONAL``): the listener REQUESTS a client
    cert and VERIFIES it against the CA when a peer presents one (spokes/agents
    present the LE wildcard → authenticated), but does NOT reject a peer that
    presents none. This is deliberate — the unified :443 socket also serves the
    browser WebUI, and browsers have no client cert; permissive keeps them in
    FALLBACK (they still connect) so enabling mTLS can never lock the WebUI out.
    It also lets the agent cert self-heal fallback (a cert-refresh reconnect that
    presents no client cert) reach the spoke's custodian. mTLS is an EXTRA layer
    here, not a gate; the spoke/agent still use a cert whenever one is available.

    STRICT (``CERT_REQUIRED``) is opt-in via ``LM_MTLS_STRICT`` — turn it on ONLY
    for a dedicated, non-WebUI listener (a separate spoke-only port), because on
    a shared socket it locks out every cert-less browser/fallback."""
    if str(os.getenv("LM_MTLS_STRICT", "")).strip().lower() in ("1", "true", "yes", "on"):
        return ssl.CERT_REQUIRED
    return ssl.CERT_OPTIONAL


def apply_server_client_auth(ctx: ssl.SSLContext):
    """Arm a server SSL context (hub WS, spoke /ws/agent) to verify a client
    cert — ONLY when mTLS is enabled and a CA is configured. PERMISSIVE by
    default (verify-if-presented, fall back otherwise; see server_verify_mode);
    strict is opt-in via LM_MTLS_STRICT. Default (mTLS off): leaves the context
    as-is (no client-cert request). Call after the server context loads its
    own cert/key."""
    if ctx is None or not mtls_enabled():
        return ctx
    ca, _cert, _key = _paths()
    if not ca:
        return ctx
    try:
        ctx.load_verify_locations(cafile=ca)
        ctx.verify_mode = server_verify_mode()
    except Exception:  # noqa: BLE001 - don't brick the listener
        pass
    return ctx


def status() -> dict:
    """Introspection for the readiness check / UI: is mTLS on, and are the
    materials present so it *would* work?"""
    ca, cert, key = _paths()
    return {
        "enabled": mtls_enabled(),
        "ca_present": bool(ca and os.path.exists(ca)),
        "client_cert_present": bool(cert and os.path.exists(cert)),
        "client_key_present": bool(key and os.path.exists(key)),
        "server_cert_present": bool(os.getenv("LM_TLS_CERT") and
                                    os.path.exists(os.getenv("LM_TLS_CERT", ""))),
    }
