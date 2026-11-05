"""Private PKI for Kea DHCP High Availability peers.

Keeps a small self-signed CA on disk and issues each HA member a TLS certificate signed
by it, so the two Kea servers can authenticate each other over HTTPS. Existing valid
certificates are reused instead of being re-issued.
"""
# hashlib turns member ids into safe, fixed-length file names.
import hashlib
# ipaddress decides whether a host is an IP (IP SAN) or a hostname (DNS SAN).
import ipaddress
# os provides chmod and atomic file replace.
import os
# Date helpers for certificate validity windows.
from datetime import datetime, timedelta, timezone
# Path builds file locations inside the PKI directory.
from pathlib import Path

# cryptography library: X.509 certificates, signature checks, hashing, key encoding,
# RSA keys and certificate name OIDs.
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID


def _write(path: Path, data: bytes, mode: int) -> None:
    """Atomically write data to path with the given file permissions.

    Args:
        path: Destination file.
        data: Bytes to write.
        mode: Permission bits, e.g. 0o600 for private keys.
    """
    # Make sure the parent directory exists.
    path.parent.mkdir(parents=True, exist_ok=True)
    # Write to a temp file, set permissions, then rename so readers never see a partial file.
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(data)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def _load_or_create_ca(root: Path):
    """Load the HA CA key/cert from root, or create a new CA if missing or mismatched.

    Args:
        root: PKI directory holding ha-ca.key and ha-ca.pem.

    Returns:
        (private_key, certificate) for the CA.
    """
    # File locations of the CA private key and certificate.
    key_path = root / "ha-ca.key"
    cert_path = root / "ha-ca.pem"
    # Reuse the existing CA if both files are present and readable.
    if key_path.exists() and cert_path.exists():
        # Load both files; any parse error falls through to creating a new CA.
        try:
            key = serialization.load_pem_private_key(
                key_path.read_bytes(), password=None)
            cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
            # Only reuse them if the key really belongs to the certificate.
            if key.public_key().public_numbers() == cert.public_key().public_numbers():
                return key, cert
        # Corrupt or unreadable files: ignore them and generate a fresh CA below.
        except (OSError, TypeError, ValueError):
            pass

    # Create a new 3072-bit RSA key for the CA.
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    # The CA's name; it is self-signed, so subject and issuer are the same.
    subject = x509.Name([x509.NameAttribute(
        NameOID.COMMON_NAME, "LM DHCP HA root")])
    # Current UTC time anchors the validity window.
    now = datetime.now(timezone.utc)
    # Build a self-signed CA certificate valid for ~10 years (backdated 5 minutes for
    # clock skew), allowed only to sign certificates and CRLs.
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_encipherment=False,
                content_commitment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=None, decipher_only=None),
            critical=True)
        .sign(key, hashes.SHA256())
    )
    # Save the CA key unencrypted but readable only by the owner (0600).
    _write(
        key_path,
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()),
        0o600)
    # Save the CA certificate world-readable, then return the pair.
    _write(cert_path, cert.public_bytes(serialization.Encoding.PEM), 0o644)
    return key, cert


def issue_member_material(pki_dir: str, member_id: str, host: str) -> dict:
    """Issue one node-specific certificate from the persistent DHCP HA CA."""
    # Normalise inputs to trimmed strings (None becomes "").
    member_id = str(member_id or "").strip()
    host = str(host or "").strip()
    # Both values are required to build a certificate.
    if not member_id or not host:
        raise ValueError("member id and host are required")

    # Load (or create) the CA that will sign this member's certificate.
    root = Path(pki_dir)
    ca_key, ca_cert = _load_or_create_ca(root)
    # Hash the member id into a safe file name, since ids may contain odd characters.
    safe_id = hashlib.sha256(member_id.encode("utf-8")).hexdigest()[:24]
    cert_path = root / f"{safe_id}.crt"
    key_path = root / f"{safe_id}.key"
    # If this member already has a certificate, check whether it can be reused.
    if cert_path.exists() and key_path.exists():
        # Any validation failure below falls through to issuing a fresh certificate.
        try:
            # Load the existing certificate, key and Subject Alternative Names.
            cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
            key = serialization.load_pem_private_key(
                key_path.read_bytes(), password=None)
            names = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName).value
            # Work out which SAN this host should appear as (IP or DNS name).
            try:
                expected = x509.IPAddress(ipaddress.ip_address(host))
            # Not a valid IP address, so treat the host as a DNS name.
            except ValueError:
                expected = x509.DNSName(host)
            # Verify the certificate was really signed by our current CA (raises if not).
            ca_cert.public_key().verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
            # Reuse only if: issued by our CA, matches its key, covers this host, and is valid
            # for at least another 30 days.
            if (
                cert.issuer == ca_cert.subject
                and key.public_key().public_numbers()
                == cert.public_key().public_numbers()
                and expected in names
                and cert.not_valid_after_utc
                > datetime.now(timezone.utc) + timedelta(days=30)
            ):
                # Return the CA, certificate and key as PEM text.
                return {
                    "ha_ca_pem": ca_cert.public_bytes(
                        serialization.Encoding.PEM).decode("ascii"),
                    "ha_cert_pem": cert_path.read_text(encoding="ascii"),
                    "ha_key_pem": key_path.read_text(encoding="ascii"),
                }
        # Bad signature, unreadable file, or missing SAN: fall through and re-issue.
        except (
            InvalidSignature, OSError, TypeError, ValueError,
            x509.ExtensionNotFound,
        ):
            pass

    # Create a new 3072-bit RSA key for this member.
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    # Name the certificate after the hashed member id.
    subject = x509.Name([x509.NameAttribute(
        NameOID.COMMON_NAME, f"lm-dhcp-{safe_id}")])
    # Put the host in the SAN as an IP address if it is one, otherwise as a DNS name.
    try:
        san = x509.IPAddress(ipaddress.ip_address(host))
    except ValueError:
        san = x509.DNSName(host)
    # Current UTC time anchors the validity window.
    now = datetime.now(timezone.utc)
    # Build a certificate signed by the CA, valid ~825 days (the common max for TLS certs),
    # usable for both server and client authentication because HA peers act as both.
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=825))
        .add_extension(x509.SubjectAlternativeName([san]), critical=False)
        .add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
            ]),
            critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    # Encode the certificate and unencrypted key as PEM.
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())
    # Save the certificate world-readable and the key owner-only.
    _write(cert_path, cert_pem, 0o644)
    _write(key_path, key_pem, 0o600)
    # Return the CA, certificate and key as PEM text for the caller to deploy.
    return {
        "ha_ca_pem": ca_cert.public_bytes(
            serialization.Encoding.PEM).decode("ascii"),
        "ha_cert_pem": cert_pem.decode("ascii"),
        "ha_key_pem": key_pem.decode("ascii"),
    }
