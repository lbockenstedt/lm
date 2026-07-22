"""Internal mTLS CLIENT CA for the hub.

Let's Encrypt (and public CAs generally) no longer issue the ``clientAuth`` EKU, so
a spoke that needs a VERIFIED mTLS CLIENT identity — BugFixer, whose reverse
HUB_REQUEST channel (hub-log reads + fleet update triggers) is gated on a pinned,
verified client cert — cannot obtain one publicly. This module makes the HUB a tiny
CA: a self-signed CA generated ONCE that mints short-ish ``clientAuth`` leaf certs
for a specific SAN. The hub then (a) trusts its own CA on the client-verify leg (see
mtls.server_client_ca_file) and (b) SAN-pins the identity (bugfixer_cert_identities),
so only a cert the hub itself issued for the pinned name is accepted.

Security: only the hub holds the CA private key, so a cert bearing the pinned SAN
can't be forged elsewhere; combined with the existing SAN pin the authorization is
as strong as before. This cert is used ONLY as the spoke's mTLS CLIENT identity to
the hub — the spoke keeps its LE cert for the WebUI/server role.

Stdlib + ``cryptography`` (already a hub dependency). Files are root-owned, key 0600.
"""

import datetime
import os

_CA_DIR = os.getenv(
    "LM_MTLS_CLIENT_CA_DIR",
    (os.path.dirname(os.getenv("LM_TLS_CERT", "").strip()) or "/opt/lm/certs"),
)
CA_CERT_PATH = os.getenv("LM_MTLS_CLIENT_CA_CERT", os.path.join(_CA_DIR, "mtls-client-ca.pem"))
CA_KEY_PATH = os.getenv("LM_MTLS_CLIENT_CA_KEY", os.path.join(_CA_DIR, "mtls-client-ca.key"))
# Retired CA certs (no keys — we never sign with them again) accumulate here on
# rollover so client certs the OLD CA issued keep verifying during the overlap
# (a leaf lives ≤397d, so an old CA stays useful until its last leaf expires).
# mtls.server_client_ca_file() folds these into the hub's client-verify bundle.
RETIRED_CA_PATH = os.getenv("LM_MTLS_CLIENT_CA_RETIRED",
                            os.path.join(_CA_DIR, "mtls-client-ca-retired.pem"))
_CA_CN = os.getenv("LM_MTLS_CLIENT_CA_CN", "LM Hub mTLS Client CA")


def _now():
    # Fixed-offset UTC; avoids naive/aware mixups in cryptography's validity checks.
    return datetime.datetime.now(datetime.timezone.utc)


def ca_exists() -> bool:
    return bool(CA_CERT_PATH and CA_KEY_PATH
               and os.path.exists(CA_CERT_PATH) and os.path.exists(CA_KEY_PATH))


def ca_cert_pem() -> str:
    """The CA certificate PEM (to add to the hub's client-verify trust). '' if none."""
    try:
        with open(CA_CERT_PATH, "r") as f:
            return f.read()
    except Exception:  # noqa: BLE001
        return ""


def _write_new_ca():
    """Generate a fresh self-signed CA and write it to CA_CERT_PATH/CA_KEY_PATH
    (overwriting). Shared by ensure_ca (first create) and rollover_ca (renewal)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, _CA_CN)])
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
    os.makedirs(_CA_DIR, exist_ok=True)
    with open(CA_CERT_PATH, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(CA_KEY_PATH, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
    try:
        os.chmod(CA_KEY_PATH, 0o600)
    except OSError:
        pass
    return ca_cert_pem()


def ensure_ca():
    """Create the self-signed mTLS client CA if it doesn't exist. Idempotent.
    Returns the CA cert PEM (or '' on failure). Renewal near expiry is handled
    separately by rollover_ca (called from the hub's mTLS renewal loop) so a
    plain ensure_ca on the hot path never regenerates the CA under a live fleet."""
    if ca_exists():
        return ca_cert_pem()
    return _write_new_ca()


def ca_not_after_ts() -> float:
    """Epoch seconds of the current CA cert's expiry (0.0 if no CA / parse error).
    Drives the renewal loop's 'CA about to expire?' check."""
    try:
        from cryptography import x509
        with open(CA_CERT_PATH, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
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
    old_pem = ca_cert_pem()
    if old_pem.strip():
        try:
            os.makedirs(_CA_DIR, exist_ok=True)
            with open(RETIRED_CA_PATH, "a") as f:
                f.write(("" if old_pem.endswith("\n") else "\n").join([old_pem, ""]))
        except Exception:  # noqa: BLE001 - if we can't retire it, still roll (old leaves lose trust)
            pass
    return _write_new_ca()


def issue_client_cert(common_name: str, sans=None, days: int = 397):
    """Mint a ``clientAuth`` leaf cert for ``common_name`` (+ optional SANs), signed
    by the hub mTLS CA. Returns ``(fullchain_pem, key_pem)`` where fullchain is the
    leaf + the CA cert (so the presenter sends a complete chain). Raises on failure.

    ``days`` default 397 (~13 months) — short enough to rotate, long enough to not
    churn; re-issue any time (the hub re-delivers)."""
    ensure_ca()
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

    with open(CA_KEY_PATH, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(CA_CERT_PATH, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    cn = (common_name or "").strip()
    san_names = [str(s).strip() for s in (sans or [cn]) if str(s).strip()]
    key = ec.generate_private_key(ec.SECP256R1())
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now() - datetime.timedelta(minutes=5))
        .not_valid_after(_now() + datetime.timedelta(days=int(days)))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, key_encipherment=False, content_commitment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        # THE point of this whole module: the clientAuth EKU LE won't issue.
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in san_names]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    )
    leaf = builder.sign(ca_key, hashes.SHA256())
    leaf_pem = leaf.public_bytes(serialization.Encoding.PEM).decode()
    ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()).decode()
    return leaf_pem + ca_pem, key_pem
