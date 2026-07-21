"""mTLS plumbing for the Hub↔Spoke and Spoke↔Agent legs — PLUMBED, default-OFF.

Everything needed for mutual TLS is wired here but stays inert until
``LM_MTLS_ENABLED`` is turned on (after the LE wildcard is distributed to the
hub + spokes + /ws/agent listeners). Default behavior is unchanged: encrypted
but unverified (``ssl._create_unverified_context``) on the client side, no
client-cert requirement on the server side.

Activation flips two things with zero code change:
  * clients verify the server against the CA and present a client cert;
  * servers require + verify a client cert.

Why this is OFF by default and intentionally optional (chicken-and-egg):
mTLS needs the LE wildcard + its CA bundle present on the hub AND on every
spoke, but spokes receive those materials THROUGH their connection to the hub
(``SPOKE_SET_MTLS_MATERIALS``, brokered from the ``le`` spoke). The fleet
therefore has to come up first under plain TLS, the hub distributes the
wildcard + CA, and only then can mTLS be switched on — there is no way to
bootstrap the fleet already pinned to mTLS (the first connection must succeed
without it). Do NOT enable mTLS before every connected spoke holds the
materials: a spoke without the wildcard + CA can no longer authenticate and is
orphaned, and because it can't reach the hub it can't be fixed remotely
(manual on-box recovery). Use Auto-provision (``global_config.mtls.auto_provision``)
or wait for per-spoke readiness green (``/setup/mtls-readiness``) before
flipping ``LM_MTLS_ENABLED``. mTLS authenticates fleet members to each other
once on; it does NOT replace ``LM_HUB_TLS_VERIFY`` (spoke verifying the hub's
cert on the wss dial) — for a full close both must be on: materials everywhere
AND hub-cert verification.

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
import tempfile


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


def server_verify_mode():
    """Client-cert verify mode for a server listener when mTLS is on.

    PERMISSIVE by default (``CERT_OPTIONAL``): the listener REQUESTS a client
    cert and VERIFIES it against the CA when a peer presents one (spokes/agents
    present the LE wildcard → authenticated), but does NOT reject a peer that
    presents none. This is deliberate — the unified :443 socket also serves the
    browser WebUI, and browsers have no client cert; permissive keeps them in
    FALLBACK (they still connect) so enabling mTLS can never lock the WebUI out.
    mTLS is an EXTRA layer here, not a gate.

    STRICT (``CERT_REQUIRED``) is opt-in via ``LM_MTLS_STRICT`` — turn it on ONLY
    for a dedicated, non-WebUI listener (a separate spoke-only port), because on
    a shared socket it locks out every cert-less browser. See build_server()."""
    if str(os.getenv("LM_MTLS_STRICT", "")).strip().lower() in ("1", "true", "yes", "on"):
        return ssl.CERT_REQUIRED
    return ssl.CERT_OPTIONAL


def apply_server_client_auth(ctx: ssl.SSLContext):
    """Arm a server SSL context (hub WS, spoke /ws/agent) to verify a client
    cert — ONLY when mTLS is enabled and a CA is configured. PERMISSIVE by
    default (verify-if-presented, fall back otherwise; see server_verify_mode);
    strict is opt-in via LM_MTLS_STRICT. Default (mTLS off): leaves the context
    as-is (no client-cert request). Call after the context loads its cert/key."""
    if ctx is None or not mtls_enabled():
        return ctx
    ca, _cert, _key = _paths()
    if not ca:
        return ctx
    try:
        ctx.load_verify_locations(cafile=ca)
        # Also trust the system store (LE/ISRG roots) so an LE-issued, SAN-pinned
        # identity (the BugFixer cert deployed from the LE module) verifies without
        # having to live in the private mTLS CA — mirrors the client leg, which
        # already trusts system+CA via create_default_context. See
        # server_client_ca_file() for the rationale (widening trust is safe: the
        # handshake is not the gate).
        try:
            ctx.load_default_certs(ssl.Purpose.CLIENT_AUTH)
        except Exception:  # noqa: BLE001
            pass
        ctx.verify_mode = server_verify_mode()
    except Exception:  # noqa: BLE001 - don't brick the listener
        pass
    return ctx


_combined_ca_path = None


def server_client_ca_file():
    """CA bundle path for VERIFYING presented client certs on a server leg
    (the hub's :443 listener). It is ``LM_MTLS_CA`` (the private mTLS wildcard
    chain that authenticates ordinary spokes) concatenated with the system trust
    store, so an LE-issued, SAN-pinned identity — the BugFixer cert deployed from
    the LE module — also verifies without having to live in the private mTLS CA.

    Why widening trust here is safe: under the permissive model the TLS handshake
    is NOT the gate (see server_verify_mode). CERT_OPTIONAL only decides whether a
    presented cert is *readable*; actual authority is app-layer — ordinary spokes
    by session key, and the reverse HUB_REQUEST channel by BugFixer SAN pinning
    (``_hub_request_authorized``). A peer presenting any publicly-trusted cert
    therefore passes TLS but gains nothing unless it is explicitly pinned. This
    also restores the symmetry the client leg already has (create_default_context
    trusts system+CA). Returns the raw ``LM_MTLS_CA`` path if the combine fails,
    so a bad system-store read can never brick the listener."""
    global _combined_ca_path
    ca, _, _ = _paths()
    if not ca or not os.path.exists(ca):
        return ca or ""
    if _combined_ca_path and os.path.exists(_combined_ca_path):
        return _combined_ca_path
    try:
        parts = []
        with open(ca, "r") as f:
            parts.append(f.read())
        dvp = ssl.get_default_verify_paths()
        sys_ca = dvp.cafile or dvp.openssl_cafile
        if sys_ca and os.path.exists(sys_ca):
            with open(sys_ca, "r") as f:
                parts.append(f.read())
        else:
            try:
                import certifi
                with open(certifi.where(), "r") as f:
                    parts.append(f.read())
            except Exception:  # noqa: BLE001
                pass
        combined = "\n".join(p.strip() for p in parts if p.strip()) + "\n"
        out = os.path.join(tempfile.gettempdir(), "lm_mtls_client_ca_combined.pem")
        with open(out, "w") as f:
            f.write(combined)
        _combined_ca_path = out
        return out
    except Exception:  # noqa: BLE001 - fall back to the private CA only
        return ca


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
