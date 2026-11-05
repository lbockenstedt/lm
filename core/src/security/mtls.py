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

# Standard-library logging for trust reload and bundle-building messages.
import logging
# os: env-var knobs, file existence checks and path joining.
import os
# ssl builds the client/server TLS contexts and verify modes.
import ssl
# tempfile locates the temp directory where the combined CA bundle is written.
import tempfile

# Logger named after this module.
logger = logging.getLogger(__name__)


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
    # None clears the override (back to env); anything else becomes a strict bool.
    global _runtime_enabled
    _runtime_enabled = None if value is None else bool(value)


def set_runtime_materials(ca=None, client_cert=None, client_key=None) -> None:
    """Hub/spoke applies the on-disk mTLS material paths here (startup from
    global_config["mtls"], and after distribution writes the files). Any arg
    left None keeps its current value, so a caller can set just the CA bundle
    (the hub — it has no client leg) without clobbering client paths. Pass an
    empty string to explicitly clear a path back to the env fallback."""
    # Note whether the CA path really changes, so we only hot-reload when needed.
    ca_changed = ca is not None and _runtime_materials.get("ca") != (ca or None)
    # Update only the paths the caller supplied; "" clears a path back to the env fallback.
    if ca is not None:
        _runtime_materials["ca"] = ca or None
    if client_cert is not None:
        _runtime_materials["client_cert"] = client_cert or None
    if client_key is not None:
        _runtime_materials["client_key"] = client_key or None
    # When the client-verify CA changes (cert renewal, a new device's chain), hot-
    # reload the LIVE listener's SSL trust so it takes effect WITHOUT a hub restart.
    if ca_changed:
        try:
            reload_client_ca()
        except Exception:  # noqa: BLE001 - never let a reload hiccup break distribution
            pass


# Reference to the running server's client-verify SSLContext, registered by
# build_server(). Lets reload_client_ca() refresh the LIVE listener's trust in
# place when materials change — so a cert/trust update never needs a hub restart.
_server_ctx = None


def register_server_ctx(ctx) -> None:
    """build_server() hands us the listener's SSLContext so we can hot-reload its
    client-verify trust later (see reload_client_ca)."""
    # Remember the listener's context for later hot reloads.
    global _server_ctx
    _server_ctx = ctx


def reload_client_ca() -> bool:
    """Rebuild the combined client-verify CA and reload it into the LIVE listener
    SSLContext, so a changed trust chain (renewal, a newly-deployed device cert)
    is honored on the NEXT handshake without restarting the hub. Adds the current
    anchors to the running context (OpenSSL de-dups); existing connections are
    unaffected. Returns True if the live context was refreshed. NOTE: this ADDS
    trust — a fully-rotated CA leaves the old anchors trusted until the next
    restart, which is safe (old certs simply stay valid)."""
    global _combined_ca_path
    # Nothing to reload until a listener has registered its context.
    ctx = _server_ctx
    if ctx is None:
        return False
    _combined_ca_path = None  # force a fresh rebuild from current materials
    # Rebuild the combined bundle; give up if it could not be produced.
    combined = server_client_ca_file()
    if not combined or not os.path.exists(combined):
        return False
    # Add the new trust anchors to the live context; failures leave the old trust in place.
    try:
        ctx.load_verify_locations(cafile=combined)
        logger.info("[mtls] live listener client-verify trust reloaded from %s "
                    "(no hub restart needed)", combined)
        return True
    except Exception as e:  # noqa: BLE001
        logger.warning("[mtls] live trust reload failed (%s) — a hub restart will "
                       "still pick up the new trust", e)
        return False


def mtls_enabled() -> bool:
    """Master switch. Default OFF. Turn on only when every spoke/agent has the
    wildcard (see the readiness check) so enabling can't orphan a node."""
    # HARD kill-switch — wins over the runtime override AND global_config. Lets an
    # operator force mTLS fully OFF from the systemd env when the WebUI is locked
    # out (e.g. client-cert auth armed the unified :443 socket) WITHOUT editing the
    # Fernet-encrypted hub state or reaching the (now-unreachable) WebUI knob.
    if str(os.getenv("LM_MTLS_DISABLE", "")).strip().lower() in ("1", "true", "yes", "on"):
        return False
    # Next priority: the hub's runtime setting (WebUI knob).
    if _runtime_enabled is not None:
        return _runtime_enabled
    # Finally the env var; any common "true" spelling turns mTLS on.
    return str(os.getenv("LM_MTLS_ENABLED", "")).strip().lower() in ("1", "true", "yes", "on")


def _paths():
    """Resolve the (CA bundle, client cert, client key) paths; "" for any that is unset."""
    # Runtime registry first (set by distribution at run time), then env (the
    # operator's static knobs). A runtime path wins even if the env is unset, so
    # the readiness check reflects a just-distributed bundle immediately.
    ca = _runtime_materials.get("ca") or os.getenv("LM_MTLS_CA", "").strip()
    cert = _runtime_materials.get("client_cert") or os.getenv("LM_MTLS_CLIENT_CERT", "").strip()
    key = _runtime_materials.get("client_key") or os.getenv("LM_MTLS_CLIENT_KEY", "").strip()
    return (ca or "", cert or "", key or "")


def client_context(is_wss: bool):
    """SSL context for a client leg (spoke→hub, agent→spoke).

    Default (mTLS off): unverified-but-encrypted for wss (None for ws) — BUT still
    present our hub-issued client cert if we have one, so fleet mTLS works via
    hub-minted certs without flipping LM_MTLS_ENABLED on every spoke (the hub decides
    whether to require it — CERT_OPTIONAL). mTLS on: also verify the server against
    the CA (mutual auth), falling back safely if a path is missing so a misconfig
    can't hard-break the transport before activation is complete."""
    # Plain ws:// has no TLS at all, so no context.
    if not is_wss:
        return None
    # We can present a client cert only if both the cert and key files exist.
    ca, cert, key = _paths()
    have_client = bool(cert and key and os.path.exists(cert) and os.path.exists(key))

    def _present(ctx):
        """Load our client cert/key into ``ctx`` when available (best effort) and return it."""
        if have_client:
            try:
                ctx.load_cert_chain(cert, key)   # present our client cert
            except Exception:  # noqa: BLE001
                pass
        return ctx

    # mTLS off: encrypt without verifying the server, but still present our cert if any.
    if not mtls_enabled():
        return _present(ssl._create_unverified_context())
    # mTLS on: verify the server against the configured CA (or system store if none).
    try:
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH,
                                         cafile=ca or None)
        ctx.check_hostname = bool(ca)  # only meaningful with a CA to verify against
        ctx.verify_mode = ssl.CERT_REQUIRED if ca else ssl.CERT_NONE
        return _present(ctx)
    except Exception:  # noqa: BLE001 - never brick the transport on a bad path
        return _present(ssl._create_unverified_context())


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
    # Strict mode only when explicitly requested; otherwise permissive.
    if str(os.getenv("LM_MTLS_STRICT", "")).strip().lower() in ("1", "true", "yes", "on"):
        return ssl.CERT_REQUIRED
    return ssl.CERT_OPTIONAL


# Whether this process's listener asks clients for certificates.
_listener_armed = False


def mark_listener_client_auth_armed() -> None:
    """Record that this process's hub listener requests client certs (set where
    the server SSL config is built). App-layer enforcement keys off it."""
    global _listener_armed
    _listener_armed = True


def listener_client_auth_armed() -> bool:
    """True when this process's hub listener has been set up to request client certs."""
    return _listener_armed


def apply_server_client_auth(ctx: ssl.SSLContext):
    """Arm a server SSL context (hub WS, spoke /ws/agent) to verify a client
    cert — ONLY when mTLS is enabled and a CA is configured. PERMISSIVE by
    default (verify-if-presented, fall back otherwise; see server_verify_mode);
    strict is opt-in via LM_MTLS_STRICT. Default (mTLS off): leaves the context
    as-is (no client-cert request). Call after the context loads its cert/key."""
    # Leave the context untouched when there is none or mTLS is off.
    if ctx is None or not mtls_enabled():
        return ctx
    # Without a CA bundle there is nothing to verify client certs against.
    ca, _cert, _key = _paths()
    if not ca:
        return ctx
    # Trust the configured CA for client verification.
    try:
        ctx.load_verify_locations(cafile=ca)
        # Also trust the system store (LE/ISRG roots) so an LE-issued, SAN-pinned
        # identity (the AppBuilder cert deployed from the LE module) verifies without
        # having to live in the private mTLS CA — mirrors the client leg, which
        # already trusts system+CA via create_default_context. See
        # server_client_ca_file() for the rationale (widening trust is safe: the
        # handshake is not the gate).
        try:
            ctx.load_default_certs(ssl.Purpose.CLIENT_AUTH)
        except Exception:  # noqa: BLE001
            pass
        # Request (permissive) or require (strict) client certs.
        ctx.verify_mode = server_verify_mode()
    except Exception:  # noqa: BLE001 - don't brick the listener
        pass
    return ctx


# Cached path of the combined client-verify bundle once built.
_combined_ca_path = None


def server_client_ca_file():
    """CA bundle path for VERIFYING presented client certs on a server leg
    (the hub's :443 listener). It is ``LM_MTLS_CA`` (the private mTLS wildcard
    chain that authenticates ordinary spokes) concatenated with the system trust
    store, so an LE-issued, SAN-pinned identity — the AppBuilder cert deployed from
    the LE module — also verifies without having to live in the private mTLS CA.

    Why widening trust here is safe: under the permissive model the TLS handshake
    is NOT the gate (see server_verify_mode). CERT_OPTIONAL only decides whether a
    presented cert is *readable*; actual authority is app-layer — ordinary spokes
    by session key, and the reverse HUB_REQUEST channel by AppBuilder SAN pinning
    (``_hub_request_authorized``). A peer presenting any publicly-trusted cert
    therefore passes TLS but gains nothing unless it is explicitly pinned. This
    also restores the symmetry the client leg already has (create_default_context
    trusts system+CA). Returns the raw ``LM_MTLS_CA`` path if the combine fails,
    so a bad system-store read can never brick the listener."""
    global _combined_ca_path
    # Reuse a previously built bundle while its file still exists.
    if _combined_ca_path and os.path.exists(_combined_ca_path):
        return _combined_ca_path
    ca, _, _ = _paths()
    try:
        # PEM blocks to concatenate into the combined bundle.
        parts = []
        # Hub Local mTLS CA — the internal CA that mints the clientAuth client certs
        # every spoke (incl. AppBuilder) presents for mTLS (public CAs no longer issue
        # clientAuth). ALWAYS trusted so hub-issued certs verify, even when LM_MTLS_CA
        # (the legacy LE wildcard chain) is unset. Generated on first use.
        # Import the hub CA module whether the package root or core/src is on sys.path.
        try:
            import mtls_ca as _mtls_ca
        except Exception:  # noqa: BLE001
            try:
                from security import mtls_ca as _mtls_ca  # noqa: F401
            except Exception:  # noqa: BLE001
                _mtls_ca = None
        if _mtls_ca is not None:
            # Include the hub CA (created on first use).
            try:
                cap = _mtls_ca.ensure_ca()
                if cap and cap.strip():
                    parts.append(cap)
            except Exception:  # noqa: BLE001
                pass
            # Retired CA certs (from a CA rollover) — still trusted so client certs
            # the previous CA issued verify through the overlap until they expire.
            try:
                retired = _mtls_ca.retired_ca_pems()
                if retired and retired.strip():
                    parts.append(retired)
            except Exception:  # noqa: BLE001
                pass
        # Legacy LM_MTLS_CA (LE wildcard chain) — still trusted if present.
        if ca and os.path.exists(ca):
            with open(ca, "r") as f:
                parts.append(f.read())
        # Locate the system ROOT bundle (holds ISRG/LE roots). Try certifi first —
        # it ships a complete PEM bundle and is almost always installed (requests/
        # httpx depend on it) — then OpenSSL's configured paths, then the common
        # distro locations. ssl.get_default_verify_paths().cafile is frequently
        # None on Debian (it uses a capath dir, not a single file), which is why a
        # single-source lookup silently produced a root-less bundle and every
        # LE-issued client cert got rejected.
        sys_ca = ""
        # Prefer the certifi bundle when installed.
        try:
            import certifi
            if os.path.exists(certifi.where()):
                sys_ca = certifi.where()
        except Exception:  # noqa: BLE001
            pass
        # certifi unavailable: try OpenSSL's configured file, then well-known distro paths.
        if not sys_ca:
            dvp = ssl.get_default_verify_paths()
            for cand in (dvp.cafile, dvp.openssl_cafile,
                         "/etc/ssl/certs/ca-certificates.crt",   # Debian/Ubuntu
                         "/etc/pki/tls/certs/ca-bundle.crt",     # RHEL/CentOS
                         "/etc/ssl/cert.pem"):                   # Alpine/BSD
                if cand and os.path.exists(cand):
                    sys_ca = cand
                    break
        # Append the system roots we found.
        if sys_ca:
            with open(sys_ca, "r") as f:
                parts.append(f.read())
        # No trust material at all: fall back to the raw CA path (or nothing).
        if not [p for p in parts if p.strip()]:
            return ca or ""   # nothing to trust — leave the listener as-is
        # Join the non-empty parts and write them to a fixed file in the temp directory.
        combined = "\n".join(p.strip() for p in parts if p.strip()) + "\n"
        out = os.path.join(tempfile.gettempdir(), "lm_mtls_client_ca_combined.pem")
        with open(out, "w") as f:
            f.write(combined)
        # Cache the path and log how many certificates the bundle trusts.
        _combined_ca_path = out
        n_certs = combined.count("-----BEGIN CERTIFICATE-----")
        logger.info("[mtls] client-verify CA = LM_MTLS_CA + system store (%s): "
                    "%d trusted cert(s) at %s", sys_ca or "system store NOT FOUND",
                    n_certs, out)
        return out
    except Exception as e:  # noqa: BLE001 - fall back to the private CA only
        logger.warning("[mtls] combined client-verify CA build failed (%s) — "
                       "falling back to LM_MTLS_CA only; LE-issued client certs "
                       "(e.g. AppBuilder) will be REJECTED", e)
        return ca


def _parse_pem_certs(path):
    """Subject/issuer/self_signed for every cert in a PEM file (leaf→root),
    for the trust-diagnostic UI. Empty on any read/parse error."""
    # One summary dict per certificate found.
    certs = []
    # A missing file yields an empty list.
    if not path or not os.path.exists(path):
        return certs
    # Read the file and split it on END markers to get each PEM certificate.
    try:
        from cryptography import x509
        with open(path, "rb") as f:
            raw = f.read()
        end = b"-----END CERTIFICATE-----"
        for seg in raw.split(end):
            # Skip the trailing fragment after the last certificate.
            if b"-----BEGIN CERTIFICATE-----" not in seg:
                continue
            # Record subject, issuer and whether the cert signs itself (a root).
            try:
                c = x509.load_pem_x509_certificate(seg + end)
                s = c.subject.rfc4514_string()
                i = c.issuer.rfc4514_string()
                certs.append({"subject": s, "issuer": i, "self_signed": s == i})
            except Exception:  # noqa: BLE001
                continue
    except Exception:  # noqa: BLE001
        pass
    return certs


def trust_diagnostics() -> dict:
    """What the hub's mTLS client-verify path actually trusts — so an operator can
    see, from the WebUI, whether a private-CA chain (e.g. YR2/Root YR) is present
    in LM_MTLS_CA and whether the combined bundle also pulled the public system
    store (which can COLLIDE with a private root of the same name, e.g. two
    'ISRG Root X1'). LM_MTLS_CA certs are listed in full; the combined bundle is
    summarized by count (it may hold 100+ system roots)."""
    # Build (or reuse) the combined bundle only when a CA is configured, then parse both.
    ca, _, _ = _paths()
    combined = server_client_ca_file() if (ca and os.path.exists(ca)) else ""
    lm_ca_certs = _parse_pem_certs(ca)
    combined_certs = _parse_pem_certs(combined) if combined else []
    # Flag same-subject collisions (the real vs private ISRG Root X1 hazard).
    subj_counts = {}
    for c in combined_certs:
        subj_counts[c["subject"]] = subj_counts.get(c["subject"], 0) + 1
    collisions = sorted(s for s, n in subj_counts.items() if n > 1)
    # Summary for the WebUI trust diagnostics panel.
    return {
        "mtls_enabled": mtls_enabled(),
        "lm_mtls_ca_path": ca or "",
        "lm_mtls_ca_certs": lm_ca_certs,           # the private chain, in full
        "combined_ca_path": combined,
        "combined_ca_count": len(combined_certs),  # LM_MTLS_CA + system store
        "duplicate_subjects": collisions,          # same-name root hazard
    }



def status() -> dict:
    """Introspection for the readiness check / UI: is mTLS on, and are the
    materials present so it *would* work? The ``*_path`` fields expose the
    resolved paths (runtime registry or env) so an operator can see WHICH file
    each check is looking at, not just whether it exists."""
    # Resolve material paths and the server certificate path.
    ca, cert, key = _paths()
    server = os.getenv("LM_TLS_CERT", "").strip()
    # Whether mTLS is on, whether each file exists, and which file each check looked at.
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
