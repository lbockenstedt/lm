"""Shared Oracle Cloud Infrastructure (OCI) API request-signing primitives.

Factored out of ``oci_nsg.py`` so a second OCI integration (``oci_vault.py`` —
the Vault/Secrets credential-store parity feature) doesn't duplicate the
Signature Version 1 signing logic. Each OCI feature module still owns its OWN
:class:`OciAuthConfig`-shaped auth block in ``global_config`` (e.g.
``oci_nsg`` vs ``oci_vault``) — a customer may reasonably want a different,
narrower-scoped OCI user/API key per integration — only the crypto/HTTP
plumbing is shared here.

See https://docs.oracle.com/en-us/iaas/Content/API/Concepts/signingrequests.htm
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import re
from email.utils import formatdate
from typing import Any, Dict, Optional
from urllib.parse import urlsplit

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from security.credential_store import resolve_private_key_material

logger = logging.getLogger("OciAuth")

# Generous cap for an uploaded OCI API signing key PEM (~1.7 KB typical).
MAX_KEY_UPLOAD_BYTES = 64 * 1024


class OciAuthError(Exception):
    """Raised for any OCI request-signing/auth failure."""


def _clean(v) -> str:
    """Strip every whitespace character from a pasted identifier.

    OCIDs and fingerprints are copied out of the OCI console, which wraps long
    values across lines. A stray newline or space inside the value corrupts the
    ``keyId`` and the ONLY symptom is a 401 NotAuthenticated that looks exactly
    like a wrong credential — so normalise rather than trust the paste."""
    return re.sub(r"\s+", "", str(v or ""))


class OciAuthConfig:
    """Resolved OCI API-signing-key auth (tenancy/user/fingerprint/key/region).

    Every OCI feature module builds one of these from its own
    ``global_config`` block (fields are identically named/shaped across all
    of them so the admin UI stays consistent)."""

    def __init__(self, stored: Optional[dict] = None):
        stored = stored or {}
        # Strip ALL internal whitespace, not just the ends: OCIDs and
        # fingerprints are routinely copy-pasted out of the OCI console, which
        # line-wraps them. An embedded newline/space silently corrupts keyId
        # and the only symptom is an opaque 401 NotAuthenticated.
        self.tenancy_ocid = _clean(stored.get("tenancy_ocid"))
        self.user_ocid = _clean(stored.get("user_ocid"))
        self.fingerprint = _clean(stored.get("fingerprint")).lower()
        # Resolved via credential_store: kv:<name> / filesystem path / bare
        # secret name — same shape as the Entra OIDC client-key path.
        self.key_path = str(stored.get("key_path") or "").strip()
        self.region = str(stored.get("region") or "").strip()

    @property
    def key_id(self) -> str:
        return f"{self.tenancy_ocid}/{self.user_ocid}/{self.fingerprint}"

    @property
    def ready(self) -> bool:
        return bool(self.tenancy_ocid and self.user_ocid and self.fingerprint
                    and self.key_path and self.region)


# Curated list of OCI commercial ("OC1" realm) region identifiers + a
# human-friendly label, so the WebUI can offer a dropdown instead of a
# freeform text field (a mistyped/mis-cased region silently produces a
# hostname that can't resolve — e.g. "iaas.US-Ashburn-1.oraclecloud.com" —
# which surfaces as an opaque DNS error far from the actual mistake). There is
# no unauthenticated OCI API to fetch this list (ListRegions requires a
# working signing key + a bootstrap region — chicken-and-egg for a NEW
# integration), so it is hand-maintained here; government/sovereign-realm
# regions are out of scope. Shared by ``routes/oci_nsg.py`` and
# ``routes/oci_vault.py`` (one dropdown source for both integrations).
# Source: https://docs.oracle.com/en-us/iaas/Content/General/Concepts/regions.htm
OCI_REGIONS = [
    ("us-ashburn-1", "US East (Ashburn)"),
    ("us-phoenix-1", "US West (Phoenix)"),
    ("us-sanjose-1", "US West (San Jose)"),
    ("us-chicago-1", "US Midwest (Chicago)"),
    ("ca-toronto-1", "Canada Southeast (Toronto)"),
    ("ca-montreal-1", "Canada Southeast (Montreal)"),
    ("mx-queretaro-1", "Mexico Central (Queretaro)"),
    ("mx-monterrey-1", "Mexico Northeast (Monterrey)"),
    ("sa-saopaulo-1", "Brazil East (Sao Paulo)"),
    ("sa-vinhedo-1", "Brazil Southeast (Vinhedo)"),
    ("sa-santiago-1", "Chile Central (Santiago)"),
    ("sa-valparaiso-1", "Chile West (Valparaiso)"),
    ("sa-bogota-1", "Colombia Central (Bogota)"),
    ("uk-london-1", "UK South (London)"),
    ("uk-cardiff-1", "UK West (Cardiff/Newport)"),
    ("eu-frankfurt-1", "Germany Central (Frankfurt)"),
    ("eu-milan-1", "Italy Northwest (Milan)"),
    ("eu-paris-1", "France Central (Paris)"),
    ("eu-marseille-1", "France South (Marseille)"),
    ("eu-zurich-1", "Switzerland North (Zurich)"),
    ("eu-amsterdam-1", "Netherlands Northwest (Amsterdam)"),
    ("eu-madrid-1", "Spain Central (Madrid)"),
    ("eu-stockholm-1", "Sweden Central (Stockholm)"),
    ("eu-jovanovac-1", "Serbia Central (Jovanovac)"),
    ("il-jerusalem-1", "Israel Central (Jerusalem)"),
    ("me-riyadh-1", "Saudi Arabia Central (Riyadh)"),
    ("me-jeddah-1", "Saudi Arabia West (Jeddah)"),
    ("me-abudhabi-1", "UAE Central (Abu Dhabi)"),
    ("me-dubai-1", "UAE East (Dubai)"),
    ("af-johannesburg-1", "South Africa Central (Johannesburg)"),
    ("ap-hyderabad-1", "India South (Hyderabad)"),
    ("ap-mumbai-1", "India West (Mumbai)"),
    ("ap-tokyo-1", "Japan East (Tokyo)"),
    ("ap-osaka-1", "Japan Central (Osaka)"),
    ("ap-seoul-1", "South Korea Central (Seoul)"),
    ("ap-chuncheon-1", "South Korea North (Chuncheon)"),
    ("ap-sydney-1", "Australia East (Sydney)"),
    ("ap-melbourne-1", "Australia Southeast (Melbourne)"),
    ("ap-singapore-1", "Singapore"),
    ("ap-singapore-2", "Singapore West"),
    ("ap-batam-1", "Indonesia (Batam)"),
]


def list_regions() -> list:
    """The curated OCI region catalog as ``[{id, label}, ...]`` for the WebUI
    dropdown, sorted by label for a stable, readable picker."""
    return sorted(
        ({"id": rid, "label": f"{label} ({rid})"} for rid, label in OCI_REGIONS),
        key=lambda r: r["label"],
    )


# An OCI region identifier is lowercase ``<area>-<city>-<n>``, e.g. us-ashburn-1,
# eu-frankfurt-1, ap-tokyo-1. Anything else can't resolve, so we reject it BEFORE
# building a URL out of it rather than emitting a bare DNS failure.
_REGION_RE = re.compile(r"^[a-z]{2,3}-[a-z]+(?:-[a-z]+)*-[0-9]+$")


def validate_region(region: str) -> str:
    """Return the normalised region id, or raise :class:`OciAuthError` with an
    actionable message.

    Every OCI endpoint host is built by interpolating the region into
    ``<service>.<region>.oraclecloud.com``. A typo'd or empty region therefore
    surfaces as a bare ``[Errno -2] Name or service not known`` from the DNS
    resolver, which tells the operator nothing about WHAT was wrong. Catching
    the malformed case here turns that into "not a valid OCI region identifier"
    and names the region we were handed.

    A well-formed but unknown region is allowed through with no error: OCI adds
    regions regularly and :data:`OCI_REGIONS` is a hand-maintained snapshot, so
    refusing anything not in the list would break new regions.
    """
    r = (region or "").strip().lower()
    if not r:
        raise OciAuthError(
            "no OCI region configured — set the region (e.g. 'us-ashburn-1') "
            "in the OCI integration settings.")
    if not _REGION_RE.match(r):
        raise OciAuthError(
            f"{region!r} is not a valid OCI region identifier. Expected a form "
            f"like 'us-ashburn-1' or 'eu-frankfurt-1'.")
    return r


def _transport_error_detail(url: str, exc: Exception) -> str:
    """Turn an httpx transport failure into a message that names the host we
    actually tried to reach.

    ``httpx.ConnectError`` for a DNS miss stringifies to just
    ``[Errno -2] Name or service not known`` — no hostname, no URL. Surfaced
    through a route's generic ``except Exception`` that leaves an operator with
    no way to tell a mistyped region from a genuine egress/DNS problem."""
    try:
        host = httpx.URL(url).host
    except Exception:  # noqa: BLE001
        host = url
    base = f"could not reach OCI endpoint {host}: {exc}"
    name_err = ("name or service not known" in str(exc).lower()
                or "nodename nor servname" in str(exc).lower()
                or "temporary failure in name resolution" in str(exc).lower())
    if name_err:
        return (f"{base}. DNS could not resolve that host — check the OCI region "
                f"is spelled correctly, and that this hub can resolve and reach "
                f"*.oraclecloud.com.")
    return f"{base}. Check network egress from the hub to *.oraclecloud.com."


# ── request signing (Signature Version 1) ───────────────────────────────────
# Only the subset needed here: plain GET / POST with a JSON body, no
# query-string params, no on-behalf-of token.

_key_cache: Dict[str, Any] = {}  # key_path -> loaded RSAPrivateKey


def _load_private_key(key_path: str):
    key = _key_cache.get(key_path)
    if key is not None:
        return key
    pem = resolve_private_key_material(key_path)
    if not pem:
        raise OciAuthError(f"could not resolve OCI API private key {key_path!r}")
    try:
        key = serialization.load_pem_private_key(pem, password=None)
    except Exception as e:  # noqa: BLE001
        raise OciAuthError(f"could not parse OCI API private key {key_path!r}: {e}")
    _key_cache[key_path] = key
    return key


def write_uploaded_private_key(hub, subdir: str, filename: str, data: bytes) -> str:
    """Validate an uploaded OCI API signing key (unencrypted PEM) and write it
    to ``<hub data_dir>/<subdir>/<filename>`` (0600), returning the path.

    Shared by ``routes/oci_nsg.py`` and ``routes/oci_vault.py`` so an admin
    can upload the private key via the WebUI instead of hand-copying it onto
    the hub / typing a path into ``key_path``. Not vault-backed: the OCI
    Vault credential-store backend needs its OWN resolvable private key just
    to authenticate to OCI in the first place, so it can't be the bootstrap
    target for this key without a chicken-and-egg problem — a plain,
    tightly-permissioned file is what ``key_path`` already supports via
    ``resolve_private_key_material``'s filesystem-path branch.

    Raises :class:`OciAuthError` on validation or write failure; never
    partially writes (validated fully before anything touches disk)."""
    if not data:
        raise OciAuthError("empty upload")
    if len(data) > MAX_KEY_UPLOAD_BYTES:
        raise OciAuthError("key upload exceeds 64 KB limit")
    try:
        serialization.load_pem_private_key(data, password=None)
    except Exception as e:  # noqa: BLE001
        raise OciAuthError(f"not a valid, unencrypted PEM private key: {e}")
    path = os.path.join(hub.state.data_dir, subdir, filename)
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "wb") as f:
            f.write(data)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except OSError as e:
        raise OciAuthError(f"could not write key file: {e}")
    return path


def public_key_fingerprint(key_path: str) -> str:
    """The OCI API-key fingerprint OF THE CONFIGURED PRIVATE KEY.

    OCI's fingerprint is the MD5 of the DER-encoded SubjectPublicKeyInfo,
    formatted as colon-separated hex — identical to
    ``openssl rsa -pubout -outform DER | openssl md5 -c``. Computing it locally
    lets us tell an operator definitively whether the key they uploaded is the
    one the pasted fingerprint refers to, which is the single most common cause
    of a 401 NotAuthenticated that "looks right"."""
    key = _load_private_key(key_path)
    der = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    digest = hashlib.md5(der).hexdigest()  # noqa: S324 — OCI defines MD5 here
    return ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))


_OCID_RE = re.compile(r"^ocid1\.[a-z0-9]+\.[a-z0-9-]*\.[a-z0-9-]*\.?[a-zA-Z0-9._-]*$")
_FINGERPRINT_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){15}$")
_OCID_TYPE_RE = re.compile(r"^ocid1\.([a-z0-9]+)\.")

# Friendly names for the OCID types that actually get pasted into the wrong
# field. 'domain' is the big one: the newer OCI console puts Identity Domains
# front-and-centre and their detail page shows an OCID that reads like an
# account-level identifier — but it is NOT the tenancy.
_OCID_TYPE_NAMES = {
    "domain": "an Identity Domain OCID",
    "compartment": "a compartment OCID",
    "user": "a user OCID",
    "tenancy": "a tenancy OCID",
    "group": "a group OCID",
    "policy": "a policy OCID",
    "vcn": "a VCN OCID",
    "networksecuritygroup": "a network security group OCID",
    "vault": "a Vault OCID",
    "key": "a KMS key OCID",
    "secret": "a secret OCID",
    "bucket": "a bucket OCID",
    "instance": "a compute instance OCID",
    "subnet": "a subnet OCID",
}

# Region identifier → the region KEY that appears inside an OCID. An OCID looks
# like ocid1.<type>.<realm>.<region>.<unique>, and the region segment is
# normally the short airport-style key (us-ashburn-1 → "iad"), though some
# regions carry the full region name there instead. Both forms are accepted.
_OCID_REGION_KEYS = {
    "us-ashburn-1": "iad", "us-phoenix-1": "phx", "us-sanjose-1": "sjc",
    "us-chicago-1": "ord", "ca-toronto-1": "yyz", "ca-montreal-1": "yul",
    "mx-queretaro-1": "qro", "mx-monterrey-1": "mty", "sa-saopaulo-1": "gru",
    "sa-vinhedo-1": "vcp", "sa-santiago-1": "scl", "sa-valparaiso-1": "vap",
    "sa-bogota-1": "bog", "uk-london-1": "lhr", "uk-cardiff-1": "cwl",
    "eu-frankfurt-1": "fra", "eu-milan-1": "lin", "eu-paris-1": "cdg",
    "eu-marseille-1": "mrs", "eu-zurich-1": "zrh", "eu-amsterdam-1": "ams",
    "eu-madrid-1": "mad", "eu-stockholm-1": "arn", "eu-jovanovac-1": "beg",
    "il-jerusalem-1": "mtz", "me-riyadh-1": "ruh", "me-jeddah-1": "jed",
    "me-abudhabi-1": "auh", "me-dubai-1": "dxb", "af-johannesburg-1": "jnb",
    "ap-hyderabad-1": "hyd", "ap-mumbai-1": "bom", "ap-tokyo-1": "nrt",
    "ap-osaka-1": "kix", "ap-seoul-1": "icn", "ap-chuncheon-1": "yny",
    "ap-sydney-1": "syd", "ap-melbourne-1": "mel", "ap-singapore-1": "sin",
    "ap-singapore-2": "xsp", "ap-batam-1": "btm",
}
_REGION_KEY_TO_NAME = {v: k for k, v in _OCID_REGION_KEYS.items()}

# Where to get the four signing fields, consistently, in one place.
_CONFIG_PREVIEW_HINT = (
    "The reliable source for all of these is the API key's Configuration File "
    "Preview: OCI Console → Profile → User settings → API keys → Add API key, "
    "which prints tenancy/user/fingerprint/region together and guaranteed "
    "consistent. For the tenancy OCID alone: Profile → Tenancy.")


def _describe_ocid(value: str) -> str:
    """Name the resource type an OCID actually refers to, for error messages."""
    m = _OCID_TYPE_RE.match(value)
    if not m:
        return "not an OCID"
    return _OCID_TYPE_NAMES.get(m.group(1), f"an OCID of type '{m.group(1)}'")


def diagnose_auth(cfg: OciAuthConfig) -> list:
    """Config problems detectable WITHOUT calling OCI, most-likely first.

    A 401 ``NotAuthenticated`` from OCI is deliberately vague — it never says
    which part was wrong. Everything checkable locally is checked here so the
    operator gets a specific pointer instead of "the required information ...
    was not provided or was incorrect"."""
    problems = []

    if cfg.tenancy_ocid and not cfg.tenancy_ocid.startswith("ocid1.tenancy."):
        problems.append(
            f"The Tenancy OCID is wrong: you pasted "
            f"{_describe_ocid(cfg.tenancy_ocid)}, but this field needs the "
            f"tenancy OCID (it starts with 'ocid1.tenancy.'). Got "
            f"'{cfg.tenancy_ocid[:40]}…'. {_CONFIG_PREVIEW_HINT}")
    if cfg.user_ocid and not cfg.user_ocid.startswith("ocid1.user."):
        problems.append(
            f"The User OCID is wrong: you pasted "
            f"{_describe_ocid(cfg.user_ocid)}, but this field needs the OCID of "
            f"the USER the API key belongs to (it starts with 'ocid1.user.'). "
            f"Got '{cfg.user_ocid[:40]}…'. {_CONFIG_PREVIEW_HINT}")
    if cfg.tenancy_ocid and cfg.tenancy_ocid == cfg.user_ocid:
        problems.append("Tenancy OCID and User OCID are identical — they must "
                        "be two different values.")
    if cfg.fingerprint and not _FINGERPRINT_RE.match(cfg.fingerprint):
        problems.append(
            f"Fingerprint '{cfg.fingerprint}' isn't in OCI's expected form "
            f"(16 lowercase hex pairs separated by colons, e.g. "
            f"'a1:b2:c3:…'). Copy it from the API key row in the OCI console.")

    # The decisive check: does the uploaded key actually match the fingerprint?
    if cfg.key_path:
        try:
            actual = public_key_fingerprint(cfg.key_path)
        except OciAuthError as e:
            problems.append(f"Private key could not be loaded: {e}")
        else:
            if cfg.fingerprint and actual != cfg.fingerprint:
                problems.append(
                    f"The private key does NOT match the configured "
                    f"fingerprint. Key's actual fingerprint is '{actual}', but "
                    f"'{cfg.fingerprint}' is configured. Either upload the "
                    f"private key that pairs with that API key, or paste the "
                    f"fingerprint OCI shows for the key you uploaded.")
    return problems


def region_of_ocid(value: str) -> str:
    """The region segment embedded in an OCID, normalised to a region name.

    ``ocid1.<type>.<realm>.<region>.<unique>``. Returns "" when the OCID has no
    region segment — which is normal and not an error: tenancy, user, group and
    compartment OCIDs are global and carry an empty region field
    (``ocid1.tenancy.oc1..aaaa…``)."""
    parts = (value or "").split(".")
    if len(parts) < 5:
        return ""
    key = parts[3].strip().lower()
    if not key:
        return ""
    return _REGION_KEY_TO_NAME.get(key, key)


def diagnose_resource_ocid(value: str, expected_type: str, label: str,
                           region: str = "") -> list:
    """Locally-detectable problems with a *resource* OCID (vault, key, NSG…).

    OCI answers a GET for a resource you can't see with **404
    NotAuthorizedOrNotFound** whether it doesn't exist, lives in another
    region, or your policy simply doesn't grant access — it deliberately
    refuses to distinguish those so it can't be used to probe for resources.
    That makes the error useless on its own, so anything provable from the
    OCID's own structure is reported here."""
    problems = []
    value = (value or "").strip()
    if not value:
        return problems

    m = _OCID_TYPE_RE.match(value)
    if not m:
        problems.append(f"The {label} doesn't look like an OCID at all (an "
                        f"OCID starts with 'ocid1.'). Got '{value[:40]}…'.")
        return problems
    if m.group(1) != expected_type:
        problems.append(
            f"The {label} is wrong: you pasted {_describe_ocid(value)}, but "
            f"this field needs an OCID starting with 'ocid1.{expected_type}.'. "
            f"Got '{value[:40]}…'.")
        return problems  # type is wrong, so the region check would just add noise

    # A resource in region A is invisible to region B's endpoint, and OCI
    # reports that as a plain 404 rather than a redirect.
    ocid_region = region_of_ocid(value)
    want = (region or "").strip().lower()
    if ocid_region and want and ocid_region != want:
        problems.append(
            f"Region mismatch: the {label} lives in '{ocid_region}', but this "
            f"config is set to region '{want}'. OCI resources are regional, "
            f"and querying the wrong region's endpoint returns exactly this "
            f"404 NotAuthorizedOrNotFound. Set the region to '{ocid_region}', "
            f"or paste the OCID of the resource in '{want}'.")
    return problems


def _clock_skew_hint() -> str:
    """OCI rejects a request whose Date header is more than ~5 minutes off as
    NotAuthenticated — indistinguishable from a bad credential. Surfaced as a
    hint because the hub can't measure OCI's clock without a successful call."""
    return (f"If the credentials are definitely correct, check this hub's "
            f"clock: OCI rejects requests skewed more than ~5 minutes and the "
            f"error looks identical. Hub UTC is now "
            f"{formatdate(usegmt=True)}.")


def auth_failure_help(cfg: OciAuthConfig) -> str:
    """A human-actionable explanation to append to an OCI 401/NotAuthenticated.

    Returns the specific local problems when there are any, otherwise the
    checklist of causes that can only be confirmed against OCI itself."""
    problems = diagnose_auth(cfg)
    if problems:
        return " Detected: " + " ".join(problems)
    return (" Everything checkable locally looks correct (OCID formats are "
            "valid and the private key matches the fingerprint), so the cause "
            "is on the OCI side. Check, in order: (1) the API key is still "
            "ACTIVE on that user in the OCI console; (2) the user is in a "
            "group with a policy granting this action; (3) the key was added "
            "to the SAME user as the User OCID above; (4) the tenancy is the "
            "one that user belongs to. " + _clock_skew_hint())


def signed_headers(cfg: OciAuthConfig, method: str, url: str,
                   body: Optional[bytes]) -> Dict[str, str]:
    """Build the ``Authorization`` header (+ every header it covers) for one
    signed OCI API request."""
    if not cfg.ready:
        raise OciAuthError("OCI auth incomplete: tenancy_ocid/user_ocid/"
                           "fingerprint/key_path/region are all required")
    parsed = urlsplit(url)
    method_lc = method.lower()
    request_target = parsed.path + (f"?{parsed.query}" if parsed.query else "")
    headers: Dict[str, str] = {
        "date": formatdate(usegmt=True),
        "host": parsed.netloc,
        "(request-target)": f"{method_lc} {request_target}",
    }
    signed = ["(request-target)", "date", "host"]
    if body is not None:
        digest = base64.b64encode(hashlib.sha256(body).digest()).decode("ascii")
        headers["content-length"] = str(len(body))
        headers["content-type"] = "application/json"
        headers["x-content-sha256"] = digest
        signed += ["content-length", "content-type", "x-content-sha256"]
    signing_string = "\n".join(f"{h}: {headers[h]}" for h in signed)
    key = _load_private_key(cfg.key_path)
    signature = key.sign(signing_string.encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
    sig_b64 = base64.b64encode(signature).decode("ascii")
    auth = (f'Signature version="1",headers="{" ".join(signed)}",'
           f'keyId="{cfg.key_id}",algorithm="rsa-sha256",signature="{sig_b64}"')
    out = {k: v for k, v in headers.items() if k != "(request-target)"}
    out["Authorization"] = auth
    return out


async def oci_request(cfg: OciAuthConfig, client: httpx.AsyncClient, method: str, url: str, *,
                      json_body: Optional[dict] = None) -> httpx.Response:
    """Issue ONE signed request on an already-open ASYNC client. Callers own
    the client's lifecycle (opened once per public entry point) — this must
    NOT close it, since a multi-request operation reuses the same client
    across several calls.

    Transport failures are re-raised as :class:`OciAuthError` naming the host,
    so a DNS miss reads as "could not reach OCI endpoint <host>" instead of a
    context-free ``[Errno -2] Name or service not known``."""
    body = json.dumps(json_body, separators=(",", ":")).encode("utf-8") if json_body is not None else None
    headers = signed_headers(cfg, method, url, body)
    try:
        return await client.request(method, url, headers=headers, content=body)
    except httpx.HTTPStatusError:
        raise
    except httpx.TransportError as e:
        raise OciAuthError(_transport_error_detail(url, e)) from e


def oci_request_sync(cfg: OciAuthConfig, client: httpx.Client, method: str, url: str, *,
                     json_body: Optional[dict] = None) -> httpx.Response:
    """Issue ONE signed request on an already-open SYNC client. Used by the
    ``security.credential_store`` provider, whose ``get_secret`` interface is
    synchronous (called from both sync and async call sites across the hub).

    Transport failures are wrapped the same way as :func:`oci_request`."""
    body = json.dumps(json_body, separators=(",", ":")).encode("utf-8") if json_body is not None else None
    headers = signed_headers(cfg, method, url, body)
    try:
        return client.request(method, url, headers=headers, content=body)
    except httpx.HTTPStatusError:
        raise
    except httpx.TransportError as e:
        raise OciAuthError(_transport_error_detail(url, e)) from e
