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


def ensure_ca():
    """Create the self-signed mTLS client CA if it doesn't exist. Idempotent.
    Returns the CA cert PEM (or '' on failure)."""
    if ca_exists():
        return ca_cert_pem()
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
