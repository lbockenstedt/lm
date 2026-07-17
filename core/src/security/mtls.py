"""mTLS plumbing for the Hub↔Spoke and Spoke↔Agent legs — PLUMBED, default-OFF.

Everything needed for mutual TLS is wired here but stays inert until
``LM_MTLS_ENABLED`` is turned on (after the LE wildcard is distributed to the
hub + spokes + /ws/agent listeners). Default behavior is unchanged: encrypted
but unverified (``ssl._create_unverified_context``) on the client side, no
client-cert requirement on the server side.

Activation flips two things with zero code change:
  * clients verify the server against the CA and present a client cert;
  * servers require + verify a client cert.

Env knobs (all optional; the runtime registry set by distribution takes
precedence over env for the material paths — see set_runtime_materials):
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

# Runtime material paths set by the hub/spoke when cert distribution writes the
# CA bundle + client cert/key to disk (see HubCertDistributionMixin.
# _install_cert_on_hub / the SPOKE_SET_MTLS_MATERIALS handler). Lets the readiness
# check go green the moment the files land — without waiting for an env reload on
# the next restart — and lets distribution choose the on-disk path by convention
# (next to LM_TLS_CERT) instead of requiring the operator to pre-set env vars.
# Each entry is None → fall back to the env for that path. Set via
# set_runtime_materials(); persisted by the hub into global_config["mtls"] so a
# restart re-registers them (mirrors set_runtime_enabled).
_runtime_materials = {"ca": None, "client_cert": None, "client_key": None}


def set_runtime_enabled(value) -> None:
    """Hub applies global_config.mtls_enabled here (startup + on the WebUI knob)."""
    global _runtime_enabled
    _runtime_enabled = None if value is None else bool(value)


def set_runtime_materials(ca=None, client_cert=None, client_key=None) -> None:
    """Hub/spoke applies the on-disk mTLS material paths here (startup from
    global_config["mtls"], and after distribution writes the files). Any arg
    left None keeps its current value, so a caller can set just the CA bundle
    (the hub — it has no client leg) without clobbering client paths. Pass an
    empty string to explicitly clear a path back to the env fallback."""
    if ca is not None:
        _runtime_materials["ca"] = ca or None
    if client_cert is not None:
        _runtime_materials["client_cert"] = client_cert or None
    if client_key is not None:
        _runtime_materials["client_key"] = client_key or None


def mtls_enabled() -> bool:
    """Master switch. Default OFF. Turn on only when every spoke/agent has the
    wildcard (see the readiness check) so enabling can't orphan a node."""
    # HARD kill-switch — wins over the runtime override AND global_config. Lets an
    # operator force mTLS fully OFF from the systemd env when the WebUI is locked
    # out (e.g. client-cert auth armed the unified :443 socket) WITHOUT editing the
    # Fernet-encrypted hub state or reaching the (now-unreachable) WebUI knob.
    if str(os.getenv("LM_MTLS_DISABLE", "")).strip().lower() in ("1", "true", "yes", "on"):
        return False
    if _runtime_enabled is not None:
        return _runtime_enabled
    return str(os.getenv("LM_MTLS_ENABLED", "")).strip().lower() in ("1", "true", "yes", "on")


def _paths():
    # Runtime registry first (set by distribution at run time), then env (the
    # operator's static knobs). A runtime path wins even if the env is unset, so
    # the readiness check reflects a just-distributed bundle immediately.
    ca = _runtime_materials.get("ca") or os.getenv("LM_MTLS_CA", "").strip()
    cert = _runtime_materials.get("client_cert") or os.getenv("LM_MTLS_CLIENT_CERT", "").strip()
    key = _runtime_materials.get("client_key") or os.getenv("LM_MTLS_CLIENT_KEY", "").strip()
    return (ca or "", cert or "", key or "")


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


def apply_server_client_auth(ctx: ssl.SSLContext):
    """Arm a server SSL context (hub WS, spoke /ws/agent) to require+verify a
    client cert — ONLY when mTLS is enabled and a CA is configured. Default:
    leaves the context as-is (no client-cert requirement). Call after the server
    context loads its own cert/key."""
    if ctx is None or not mtls_enabled():
        return ctx
    ca, _cert, _key = _paths()
    if not ca:
        return ctx
    try:
        ctx.load_verify_locations(cafile=ca)
        ctx.verify_mode = ssl.CERT_REQUIRED
    except Exception:  # noqa: BLE001 - don't brick the listener
        pass
    return ctx


def status() -> dict:
    """Introspection for the readiness check / UI: is mTLS on, and are the
    materials present so it *would* work? The ``*_path`` fields expose the
    resolved paths (runtime registry or env) so an operator can see WHICH file
    each check is looking at, not just whether it exists."""
    ca, cert, key = _paths()
    server = os.getenv("LM_TLS_CERT", "").strip()
    return {
        "enabled": mtls_enabled(),
        "ca_present": bool(ca and os.path.exists(ca)),
        "client_cert_present": bool(cert and os.path.exists(cert)),
        "client_key_present": bool(key and os.path.exists(key)),
        "server_cert_present": bool(server and os.path.exists(server)),
        "ca_path": ca,
        "client_cert_path": cert,
        "client_key_path": key,
        "server_cert_path": server,
    }
