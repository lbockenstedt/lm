"""Internal mTLS CLIENT CA for the hub.

Let's Encrypt (and public CAs generally) no longer issue the ``clientAuth`` EKU, so
a spoke that needs a VERIFIED mTLS CLIENT identity — AppBuilder, whose reverse
HUB_REQUEST channel (hub-log reads + fleet update triggers) is gated on a pinned,
verified client cert — cannot obtain one publicly. This module makes the HUB a tiny
CA: a self-signed CA generated ONCE that mints short-ish ``clientAuth`` leaf certs
for a specific SAN. The hub then (a) trusts its own CA on the client-verify leg (see
mtls.server_client_ca_file) and (b) SAN-pins the identity (ab_cert_identities),
so only a cert the hub itself issued for the pinned name is accepted.

Security: only the hub holds the CA private key, so a cert bearing the pinned SAN
can't be forged elsewhere; combined with the existing SAN pin the authorization is
as strong as before. This cert is used ONLY as the spoke's mTLS CLIENT identity to
the hub — the spoke keeps its LE cert for the WebUI/server role.

Stdlib + ``cryptography`` (already a hub dependency). Files are root-owned, key 0600.
"""

# datetime sets certificate validity windows and reads expiry times.
import datetime
# os: env-var configuration, file paths, directory creation and key permissions.
import os

# Directory holding the CA files: explicit override, else next to the hub's TLS cert,
# else the standard /opt/lm/certs location.
_CA_DIR = os.getenv(
    "LM_MTLS_CLIENT_CA_DIR",
    (os.path.dirname(os.getenv("LM_TLS_CERT", "").strip()) or "/opt/lm/certs"),
)
# Paths of the CA certificate and its private key (each overridable via env).
CA_CERT_PATH = os.getenv("LM_MTLS_CLIENT_CA_CERT", os.path.join(_CA_DIR, "mtls-client-ca.pem"))
CA_KEY_PATH = os.getenv("LM_MTLS_CLIENT_CA_KEY", os.path.join(_CA_DIR, "mtls-client-ca.key"))
# Retired CA certs (no keys — we never sign with them again) accumulate here on
# rollover so client certs the OLD CA issued keep verifying during the overlap
# (a leaf lives ≤397d, so an old CA stays useful until its last leaf expires).
# mtls.server_client_ca_file() folds these into the hub's client-verify bundle.
RETIRED_CA_PATH = os.getenv("LM_MTLS_CLIENT_CA_RETIRED",
                            os.path.join(_CA_DIR, "mtls-client-ca-retired.pem"))
# Common name written into the CA certificate's subject.
_CA_CN = os.getenv("LM_MTLS_CLIENT_CA_CN", "LM Hub mTLS Client CA")


def _now():
    """Current time as a timezone-aware UTC datetime."""
    # Fixed-offset UTC; avoids naive/aware mixups in cryptography's validity checks.
    return datetime.datetime.now(datetime.timezone.utc)


def ca_exists() -> bool:
    """True when both the CA certificate and its private key files are present."""
    # Both paths must be configured and both files must exist.
    return bool(CA_CERT_PATH and CA_KEY_PATH
               and os.path.exists(CA_CERT_PATH) and os.path.exists(CA_KEY_PATH))


def ca_cert_pem() -> str:
    """The CA certificate PEM (to add to the hub's client-verify trust). '' if none."""
    # Read the PEM text; a missing or unreadable file means "no CA".
    try:
        with open(CA_CERT_PATH, "r") as f:
            return f.read()
    except Exception:  # noqa: BLE001
        return ""


def _write_new_ca():
    """Generate a fresh self-signed CA and write it to CA_CERT_PATH/CA_KEY_PATH
    (overwriting). Shared by ensure_ca (first create) and rollover_ca (renewal)."""
    # cryptography is imported lazily so importing this module stays cheap.
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    # New P-256 elliptic-curve key pair for the CA.
    key = ec.generate_private_key(ec.SECP256R1())
    # Self-signed: the subject and issuer are the same name.
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, _CA_CN)])
    # Build a 10-year CA cert (backdated 5 minutes for clock skew), restricted to signing
    # certificates and CRLs, with no intermediate CAs allowed beneath it (path_length=0).
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now() - datetime.timedelta(minutes=5))
        .not_valid_after(_now() + datetime.timedelta(days=3650))  # 10y CA
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, key_cert_sign=True, crl_sign=True,
            key_encipherment=False, content_commitment=False, data_encipherment=False,
            key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    # Make sure the directory exists, then write the cert and the unencrypted PKCS#8 key.
    os.makedirs(_CA_DIR, exist_ok=True)
    with open(CA_CERT_PATH, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(CA_KEY_PATH, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
    # Restrict the key file to its owner; ignore filesystems that refuse chmod.
    try:
        os.chmod(CA_KEY_PATH, 0o600)
    except OSError:
        pass
    # Return the PEM just written, read back from disk.
    return ca_cert_pem()


def ensure_ca():
    """Create the self-signed mTLS client CA if it doesn't exist. Idempotent.
    Returns the CA cert PEM (or '' on failure). Renewal near expiry is handled
    separately by rollover_ca (called from the hub's mTLS renewal loop) so a
    plain ensure_ca on the hot path never regenerates the CA under a live fleet."""
    # Already created: reuse the existing CA.
    if ca_exists():
        return ca_cert_pem()
    return _write_new_ca()


def ca_not_after_ts() -> float:
    """Epoch seconds of the current CA cert's expiry (0.0 if no CA / parse error).
    Drives the renewal loop's 'CA about to expire?' check."""
    # Load the CA cert and read its expiry; any failure counts as 0.0 ("no CA").
    try:
        # Lazy import: the x509 loader is only needed when the expiry is actually checked.
        from cryptography import x509
        with open(CA_CERT_PATH, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
        # Newer cryptography exposes a timezone-aware expiry; older versions need it added.
        try:
            return cert.not_valid_after_utc.timestamp()
        except Exception:  # noqa: BLE001 - older cryptography
            return cert.not_valid_after.replace(tzinfo=datetime.timezone.utc).timestamp()
    except Exception:  # noqa: BLE001
        return 0.0


def retired_ca_pems() -> str:
    """Concatenated PEM of all RETIRED CA certs (empty string if none). Folded into
    the hub's client-verify bundle so client certs an old CA issued keep verifying
    through the rollover overlap."""
    # Read the retired-CA bundle; missing file means none.
    try:
        with open(RETIRED_CA_PATH, "r") as f:
            return f.read()
    except Exception:  # noqa: BLE001
        return ""


def rollover_ca() -> str:
    """Renew the CA: append the CURRENT CA cert to the retired store (so its
    already-issued leaf certs keep verifying until they expire), then mint a fresh
    CA in its place. Returns the NEW CA cert PEM ('' on failure). The caller must
    then reload the hub's client-verify trust (mtls.reload_client_ca) and re-issue
    connected spokes so they get leaves signed by the new CA. Idempotent per
    expiry: after this the CA is 10y out, so the near-expiry trigger won't refire."""
    # Grab the current CA before it is replaced.
    old_pem = ca_cert_pem()
    # Append it to the retired bundle (ensuring it ends with a newline).
    if old_pem.strip():
        try:
            os.makedirs(_CA_DIR, exist_ok=True)
            with open(RETIRED_CA_PATH, "a") as f:
                f.write(("" if old_pem.endswith("\n") else "\n").join([old_pem, ""]))
        except Exception:  # noqa: BLE001 - if we can't retire it, still roll (old leaves lose trust)
            pass
    # Generate and install the replacement CA.
    return _write_new_ca()


def _load_ca():
    """Load the CA private key and certificate from disk; returns (key, cert)."""
    # Lazy imports for loading certificates and private keys.
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    # Read the unencrypted private key, then the certificate.
    with open(CA_KEY_PATH, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(CA_CERT_PATH, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    return ca_key, ca_cert


def _sign_leaf(public_key, common_name: str, sans=None, days: int = 397, server_auth: bool = False) -> str:
    """Sign a ``clientAuth`` leaf for ``public_key`` with the hub CA and return the
    fullchain PEM (leaf + CA). Subject/SANs are chosen by the HUB, never taken from
    the requester."""
    # Make sure a CA exists before signing with it.
    ensure_ca()
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

    # Load the signing CA, then build the SAN list (defaults to just the common name).
    ca_key, ca_cert = _load_ca()
    cn = (common_name or "").strip()
    san_names = [str(s).strip() for s in (sans or [cn]) if str(s).strip()]
    # Describe the leaf: hub-chosen CN, issued by our CA, valid for ``days`` (backdated
    # 5 minutes for clock skew), not a CA, signature-only key usage.
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(ca_cert.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now() - datetime.timedelta(minutes=5))
        .not_valid_after(_now() + datetime.timedelta(days=int(days)))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, key_encipherment=False, content_commitment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        # THE point of this whole module: the clientAuth EKU LE won't issue.
        # server_auth adds serverAuth for peers that are both ends of a TLS link
        # (Zabbix server/proxy/agent), which OpenSSL otherwise rejects.
        .add_extension(x509.ExtendedKeyUsage(
            [ExtendedKeyUsageOID.CLIENT_AUTH] + ([ExtendedKeyUsageOID.SERVER_AUTH] if server_auth else [])),
            critical=False)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in san_names]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
    )
    # Sign with the CA key and return leaf + CA as one fullchain PEM string.
    leaf = builder.sign(ca_key, hashes.SHA256())
    leaf_pem = leaf.public_bytes(serialization.Encoding.PEM).decode()
    ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode()
    return leaf_pem + ca_pem


def issue_client_cert(common_name: str, sans=None, days: int = 397):
    """LEGACY path: mint a ``clientAuth`` leaf AND its private key on the hub.
    Returns ``(fullchain_pem, key_pem)``. Used only for spokes that predate the
    CSR flow (``sign_csr``) — the hub then has to ship the private key over the
    wire, which is why CSR-capable spokes never take this path."""
    # Lazy imports: key serialisation and elliptic-curve key generation.
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    # Generate the key pair here on the hub, then have the CA sign its public half.
    key = ec.generate_private_key(ec.SECP256R1())
    fullchain = _sign_leaf(key.public_key(), common_name, sans=sans, days=days)
    # Export the private key so it can be shipped to the spoke.
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()).decode()
    return fullchain, key_pem


def issue_service_cert(common_name: str, sans=None, days: int = 397):
    """Client+server leaf and its key for a service that is both ends of a TLS
    link. Returns ``(leaf_pem, key_pem, ca_pem)``. The key is minted on the hub
    and shipped over the authenticated hub channel, like the legacy client path."""
    # Lazy imports: key serialisation and elliptic-curve key generation.
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    # Generate the key pair and sign a cert valid for both client and server auth.
    key = ec.generate_private_key(ec.SECP256R1())
    fullchain = _sign_leaf(key.public_key(), common_name, sans=sans, days=days, server_auth=True)
    # Split the fullchain back into its leaf and CA certificates.
    marker = "-----BEGIN CERTIFICATE-----"
    leaf, ca = fullchain.split(marker)[1:3]
    # Export the private key as PEM text.
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption()).decode()
    return marker + leaf, key_pem, marker + ca


def sign_csr(csr_pem: str, common_name: str, sans=None, days: int = 397, server_auth: bool = False) -> str:
    """Sign a spoke-generated CSR (the private key never leaves the spoke).

    The CSR's own subject/SANs are IGNORED — only its public key is used, and the
    hub sets CN/SAN to the identity it authenticated. Rejects a CSR whose
    self-signature does not verify (proof of key possession) or whose key is weak.
    Returns the fullchain PEM. Raises ValueError on a bad CSR."""
    # Lazy imports: CSR parsing and the key types we accept.
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec, rsa

    # Parse the PEM CSR; parsing errors become ValueError.
    try:
        csr = x509.load_pem_x509_csr((csr_pem or "").strip().encode())
    except Exception as e:  # noqa: BLE001
        raise ValueError(f"unparseable CSR: {e}")
    # The CSR must be signed by its own key, proving the requester holds it.
    if not csr.is_signature_valid:
        raise ValueError("CSR signature invalid (no proof of key possession)")
    # Enforce a minimum strength: RSA >= 2048 bits or EC >= 256 bits; other types refused.
    pub = csr.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        if pub.key_size < 2048:
            raise ValueError("CSR RSA key too small (<2048)")
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        if pub.curve.key_size < 256:
            raise ValueError("CSR EC key too small (<256)")
    else:
        raise ValueError("CSR key type not supported (EC P-256+ or RSA 2048+)")
    # Sign a leaf for the CSR's public key using hub-chosen names.
    return _sign_leaf(pub, common_name, sans=sans, days=days, server_auth=server_auth)


def _ca_certs():
    """Current + retired CA certs (parsed). Empty list if none."""
    # Lazy import of the certificate parser.
    from cryptography import x509
    # Gather certs from both the current CA file and the retired bundle.
    out = []
    # Look at the current CA first, then the retired ones.
    for pem in (ca_cert_pem(), retired_ca_pems()):
        # Skip empty sources.
        if not pem or "BEGIN CERTIFICATE" not in pem:
            continue
        # Split the bundle on END markers and parse each certificate in turn.
        end = "-----END CERTIFICATE-----"
        for chunk in pem.split(end):
            if "BEGIN CERTIFICATE" not in chunk:
                continue
            # Unparseable fragments are skipped.
            try:
                out.append(x509.load_pem_x509_certificate((chunk.strip() + "\n" + end + "\n").encode()))
            except Exception:  # noqa: BLE001
                continue
    return out


def inspect_client_cert(der: bytes):
    """Inspect a presented client cert (DER, from ``getpeercert(binary_form=True)``).

    Returns ``{"hub_ca": bool, "sans": tuple, "cn": str, "serial": str}`` or None
    when ``der`` is empty/unparseable. ``hub_ca`` is True only when the leaf's
    signature verifies against the hub CA (current or retired) — a cryptographic
    check, not an issuer-name compare, so a publicly-trusted cert that merely
    claims the same issuer name can't pass. ``serial`` is lower-case hex, matching
    the registry's ``format(serial, "x")``."""
    # Nothing presented, nothing to inspect.
    if not der:
        return None
    # Parse the DER certificate; garbage input yields None.
    try:
        from cryptography import x509
        leaf = x509.load_der_x509_certificate(bytes(der))
    except Exception:  # noqa: BLE001
        return None
    # Check the leaf's signature against each current/retired hub CA until one verifies.
    hub_ca = False
    for ca in _ca_certs():
        try:
            leaf.verify_directly_issued_by(ca)
            hub_ca = True
            break
        except Exception:  # noqa: BLE001
            continue
    # Read the DNS Subject Alternative Names, if any.
    sans = ()
    try:
        # Lazy import of the SAN extension identifier.
        from cryptography.x509.oid import ExtensionOID
        ext = leaf.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        sans = tuple(ext.value.get_values_for_type(x509.DNSName))
    except Exception:  # noqa: BLE001
        sans = ()
    # Read the subject common name, if any.
    cn = ""
    try:
        # Lazy import of the common-name attribute identifier.
        from cryptography.x509.oid import NameOID
        attrs = leaf.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        cn = str(attrs[0].value) if attrs else ""
    except Exception:  # noqa: BLE001
        cn = ""
    # Return the findings with the serial as lower-case hex.
    return {"hub_ca": hub_ca, "sans": sans, "cn": cn,
            "serial": format(leaf.serial_number, "x")}
