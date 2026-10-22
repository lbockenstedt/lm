"""Cert Expiry Monitor — daily TLS certificate check of the public Aruba
Central / HPE GreenLake and Juniper Mist cloud endpoints (plus operator-added
custom hosts).

Each host is probed on its TLS port with SNI; the leaf certificate is captured
even when chain verification fails (Mist device terminators and Aruba device
endpoints present private device-CA certs), and ``trusted`` records whether it
validated against the system trust store. Results are written to
``$LM_STATE_DIR/cert_monitor.json``; the scheduler (routes/cert_monitor.py)
runs a check at most once every 24h while the feature is enabled.
"""
import concurrent.futures
import datetime as _dt
import json
import logging
import os
import socket
import ssl
import tempfile

logger = logging.getLogger("Hub")

STATE_DIR = os.environ.get("LM_STATE_DIR", "/var/lib/lm/state")
RESULTS_FILE = "cert_monitor.json"
CHECK_INTERVAL_S = 24 * 3600
RED_DAYS = 30
YELLOW_DAYS = 90
PROBE_TIMEOUT_S = 8.0
MAX_WORKERS = 16
MAX_CUSTOM_HOSTS = 200

_MIST_REGIONS = [
    ("", "Global 01"), ("gc1.", "Global 02"), ("ac2.", "Global 03"),
    ("gc2.", "Global 04"), ("gc4.", "Global 05"), ("gc5.", "Global 06"),
    ("gc6.", "Global 07"), ("gc7.", "Global 08"), ("eu.", "EMEA 01"),
    ("gc3.", "EMEA 02"), ("ac6.", "EMEA 03"), ("ac5.", "APAC 01"),
]
_MIST_ROLES = [
    ("manage", "Portal"), ("api", "API"), ("api-ws", "API WebSocket"),
    ("portal", "Guest portal"), ("ep-terminator", "Device terminator"),
    ("jma-terminator", "Junos agent terminator"), ("ztp", "ZTP"),
]

# (cluster, ui, api gateway, device endpoints...) — classic Aruba Central.
_CENTRAL_CLUSTERS = [
    ("US-1", "portal", "app1-apigw", ["app", "app1", "app1-h2"]),
    ("US-2", "portal-prod2", "apigw-prod2",
     ["app-prod2", "device-prod2", "device-prod2-h2"]),
    ("US-East-1", "portal-us-east-1", "apigw-us-east-1", []),
    ("US-West-4", "portal-uswest4", "apigw-uswest4",
     ["app-uswest4", "device-uswest4", "device-uswest4-h2"]),
    ("US-West-5", "portal-uswest5", "apigw-uswest5",
     ["app-uswest5", "device-uswest5"]),
    ("EU-1", "portal-eu", "eu-apigw", ["app2-eu", "device-eu", "device-eu-h2"]),
    ("EU-Central-2", "portal-eucentral2", "apigw-eucentral2",
     ["app-eucentral2", "device-eucentral2"]),
    ("EU-Central-3", "portal-eucentral3", "apigw-eucentral3",
     ["app-eucentral3", "device-eucentral3"]),
    ("Canada-1", "portal-ca", "apigw-ca", ["app-ca", "device-ca"]),
    ("APAC-1", "portal-apac", "api-ap", ["app1-ap", "app2-ap"]),
    ("APAC-East-1", "portal-apaceast", "apigw-apaceast",
     ["app-apaceast", "device-apaceast"]),
    ("APAC-South-1", "portal-apacsouth", "apigw-apacsouth",
     ["app-apacsouth", "device-apacsouth"]),
    ("UAE-North-1", "portal-uaenorth1", "apigw-uaenorth1",
     ["app-uaenorth1", "device-uaenorth1"]),
]
_NEW_CENTRAL_GATEWAYS = ["us1", "us2", "us4", "us5", "us6", "de1", "de2", "de3",
                         "ca1", "in", "jp1", "au1", "ae1"]


def _build_builtin_hosts():
    hosts = []
    for prefix, region in _MIST_REGIONS:
        for sub, role in _MIST_ROLES:
            # Global 01 terminators live under mistsys.net (added below).
            if not prefix and sub in ("ep-terminator", "jma-terminator"):
                continue
            hosts.append({"host": f"{sub}.{prefix}mist.com", "port": 443,
                          "service": "Juniper Mist", "region": region,
                          "role": role})
    for h, role in (("ep-terminator.mistsys.net", "Device terminator"),
                    ("jma-terminator.mistsys.net", "Junos agent terminator"),
                    ("redirect.mist.com", "Device redirect"),
                    ("www.mist.com", "Website")):
        hosts.append({"host": h, "port": 443, "service": "Juniper Mist",
                      "region": "Global", "role": role})

    sfx = ".central.arubanetworks.com"
    for cluster, ui, gw, devices in _CENTRAL_CLUSTERS:
        hosts.append({"host": ui + sfx, "port": 443, "service": "Aruba Central",
                      "region": cluster, "role": "Portal"})
        hosts.append({"host": gw + sfx, "port": 443, "service": "Aruba Central",
                      "region": cluster, "role": "API gateway"})
        for d in devices:
            hosts.append({"host": d + sfx, "port": 443,
                          "service": "Aruba Central", "region": cluster,
                          "role": "Device connectivity"})
    for cn_sub, role in (("portal", "Portal"), ("apigw", "API gateway"),
                         ("app", "Device connectivity")):
        hosts.append({"host": f"{cn_sub}.central.arubanetworks.com.cn",
                      "port": 443, "service": "Aruba Central",
                      "region": "China-1", "role": role})
    for r in _NEW_CENTRAL_GATEWAYS:
        hosts.append({"host": f"{r}.api.central.arubanetworks.com", "port": 443,
                      "service": "Aruba Central (New Central)",
                      "region": r.upper(), "role": "API gateway"})
    for h, role in (("common.cloud.hpe.com", "GreenLake portal"),
                    ("sso.common.cloud.hpe.com", "GreenLake SSO"),
                    ("global.api.greenlake.hpe.com", "GreenLake API"),
                    ("auth.hpe.com", "HPE auth"),
                    ("activate.arubanetworks.com", "Activate (ZTP)"),
                    ("device.arubanetworks.com", "Device provisioning")):
        hosts.append({"host": h, "port": 443, "service": "HPE GreenLake / Aruba",
                      "region": "Global", "role": role})
    return hosts


BUILTIN_HOSTS = _build_builtin_hosts()


# ── config ──────────────────────────────────────────────────────────────────

def parse_host_entry(raw):
    """``host`` / ``host:port`` / ``https://host[:port]/path`` → (host, port).
    Returns None for anything that is not a plausible DNS name / IPv4."""
    s = str(raw or "").strip().lower()
    if not s:
        return None
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("/", 1)[0].split("?", 1)[0]
    port = 443
    if s.count(":") == 1:
        s, p = s.split(":", 1)
        if not p.isdigit() or not (0 < int(p) < 65536):
            return None
        port = int(p)
    s = s.strip(".")
    if not s or len(s) > 253:
        return None
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789-.")
    if any(c not in allowed for c in s) or ".." in s:
        return None
    if any(not lbl or len(lbl) > 63 or lbl.startswith("-") or lbl.endswith("-")
           for lbl in s.split(".")):
        return None
    return s, port


def normalize_config(cfg):
    cfg = dict(cfg or {})
    custom, seen = [], set()
    for entry in cfg.get("custom_hosts") or []:
        p = parse_host_entry(entry)
        if p and p not in seen:
            seen.add(p)
            custom.append(p[0] if p[1] == 443 else f"{p[0]}:{p[1]}")
    builtin_names = {h["host"] for h in BUILTIN_HOSTS}
    disabled = sorted({str(h).strip().lower()
                       for h in (cfg.get("disabled_builtin") or [])
                       if str(h).strip().lower() in builtin_names})
    return {"enabled": bool(cfg.get("enabled")),
            "custom_hosts": custom[:MAX_CUSTOM_HOSTS],
            "disabled_builtin": disabled}


def effective_hosts(cfg):
    cfg = normalize_config(cfg)
    disabled = set(cfg["disabled_builtin"])
    hosts = [dict(h) for h in BUILTIN_HOSTS if h["host"] not in disabled]
    have = {(h["host"], h["port"]) for h in hosts}
    for entry in cfg["custom_hosts"]:
        host, port = parse_host_entry(entry)
        if (host, port) in have:
            continue
        have.add((host, port))
        hosts.append({"host": host, "port": port, "service": "Custom",
                      "region": "", "role": "Custom"})
    return hosts


# ── probe ───────────────────────────────────────────────────────────────────

def classify(days_left, error=None):
    if days_left is None:
        return "error" if error else "unknown"
    if days_left < RED_DAYS:
        return "red"
    if days_left < YELLOW_DAYS:
        return "yellow"
    return "green"


def _name_attr(name, oid):
    try:
        vals = name.get_attributes_for_oid(oid)
        return vals[0].value if vals else ""
    except Exception:  # noqa: BLE001
        return ""


def parse_cert(der, now=None):
    """DER leaf certificate → summary dict (subject, issuer/provider, key type,
    signature algorithm, validity, days left)."""
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
    from cryptography.x509.oid import ExtensionOID, NameOID

    cert = x509.load_der_x509_certificate(der)
    now = now or _dt.datetime.now(_dt.timezone.utc)
    try:
        not_after = cert.not_valid_after_utc
        not_before = cert.not_valid_before_utc
    except AttributeError:  # cryptography < 42
        not_after = cert.not_valid_after.replace(tzinfo=_dt.timezone.utc)
        not_before = cert.not_valid_before.replace(tzinfo=_dt.timezone.utc)

    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        key_type = f"RSA {pub.key_size}"
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        key_type = f"ECDSA {pub.curve.name}"
    elif isinstance(pub, ed25519.Ed25519PublicKey):
        key_type = "Ed25519"
    elif isinstance(pub, ed448.Ed448PublicKey):
        key_type = "Ed448"
    elif isinstance(pub, dsa.DSAPublicKey):
        key_type = f"DSA {pub.key_size}"
    else:
        key_type = type(pub).__name__

    try:
        sig_alg = cert.signature_algorithm_oid._name
    except Exception:  # noqa: BLE001
        sig_alg = ""
    try:
        san = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(x509.DNSName)
    except Exception:  # noqa: BLE001
        san = []

    # Cert type: DV/OV/EV from the certificate-policy OIDs (CA/B Forum).
    cert_type = ""
    try:
        policies = cert.extensions.get_extension_for_oid(
            ExtensionOID.CERTIFICATE_POLICIES).value
        oids = {p.policy_identifier.dotted_string for p in policies}
        if "2.23.140.1.1" in oids:
            cert_type = "EV"
        elif "2.23.140.1.2.2" in oids or "2.23.140.1.2.3" in oids:
            cert_type = "OV"
        elif "2.23.140.1.2.1" in oids:
            cert_type = "DV"
    except Exception:  # noqa: BLE001
        pass
    if san and any(s.startswith("*.") for s in san):
        cert_type = (cert_type + " wildcard").strip()

    issuer_o = _name_attr(cert.issuer, NameOID.ORGANIZATION_NAME)
    issuer_cn = _name_attr(cert.issuer, NameOID.COMMON_NAME)
    days_left = int((not_after - now).total_seconds() // 86400)
    return {
        "subject_cn": _name_attr(cert.subject, NameOID.COMMON_NAME),
        "san": san[:50],
        "san_count": len(san),
        "issuer_cn": issuer_cn,
        "issuer_org": issuer_o,
        "provider": issuer_o or issuer_cn,
        "cert_type": cert_type,
        "key_type": key_type,
        "signature_algorithm": sig_alg,
        "serial": format(cert.serial_number, "X"),
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "days_left": days_left,
        "self_signed": cert.issuer == cert.subject,
    }


def _handshake(host, port, verify, timeout):
    if verify:
        ctx = ssl.create_default_context()
    else:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            return tls.getpeercert(binary_form=True), tls.version()


def probe_host(entry, timeout=PROBE_TIMEOUT_S, now=None):
    host, port = entry["host"], int(entry.get("port") or 443)
    out = {k: entry.get(k, "") for k in ("host", "service", "region", "role")}
    out.update({"port": port, "checked_at": _dt.datetime.now(
        _dt.timezone.utc).isoformat(timespec="seconds"),
        "trusted": False, "verify_error": "", "error": "", "tls_version": ""})
    try:
        socket.getaddrinfo(host, port)
    except socket.gaierror as e:
        out.update({"error": f"DNS: {e.strerror or e}", "status": "error",
                    "days_left": None})
        return out
    der = None
    try:
        der, out["tls_version"] = _handshake(host, port, True, timeout)
        out["trusted"] = True
    except ssl.SSLCertVerificationError as e:
        out["verify_error"] = (getattr(e, "verify_message", None) or str(e))[:200]
    except Exception as e:  # noqa: BLE001
        out["error"] = f"{type(e).__name__}: {e}"[:200]
    if der is None and not out["error"]:
        try:
            der, out["tls_version"] = _handshake(host, port, False, timeout)
        except Exception as e:  # noqa: BLE001
            out["error"] = f"{type(e).__name__}: {e}"[:200]
    if der:
        try:
            out.update(parse_cert(der, now=now))
        except Exception as e:  # noqa: BLE001
            out["error"] = f"parse: {e}"[:200]
    out.setdefault("days_left", None)
    out["status"] = classify(out.get("days_left"), out["error"])
    return out


_STATUS_RANK = {"red": 0, "yellow": 1, "error": 2, "unknown": 3, "green": 4}


def sort_results(results):
    def key(r):
        d = r.get("days_left")
        return (_STATUS_RANK.get(r.get("status"), 9),
                d if d is not None else 10 ** 6, r.get("host", ""))
    return sorted(results, key=key)


def run_checks(hosts, timeout=PROBE_TIMEOUT_S, workers=MAX_WORKERS):
    started = _dt.datetime.now(_dt.timezone.utc)
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        for r in ex.map(lambda h: probe_host(h, timeout=timeout), hosts):
            results.append(r)
    results = sort_results(results)
    counts = {s: 0 for s in ("red", "yellow", "green", "error", "unknown")}
    for r in results:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    finished = _dt.datetime.now(_dt.timezone.utc)
    return {"last_run": finished.isoformat(timespec="seconds"),
            "duration_s": round((finished - started).total_seconds(), 1),
            "thresholds": {"red_days": RED_DAYS, "yellow_days": YELLOW_DAYS},
            "counts": counts, "results": results}


# ── storage ─────────────────────────────────────────────────────────────────

def results_path(state_dir=None):
    return os.path.join(state_dir or STATE_DIR, RESULTS_FILE)


def load_results(state_dir=None):
    try:
        with open(results_path(state_dir), "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except FileNotFoundError:
        return {}
    except Exception as e:  # noqa: BLE001
        logger.warning("[certmon] could not read %s: %s", results_path(state_dir), e)
        return {}


def save_results(data, state_dir=None):
    path = results_path(state_dir)
    d = os.path.dirname(path)
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".cert_monitor.", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.chmod(tmp, 0o640)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def is_due(data, now=None, interval_s=CHECK_INTERVAL_S):
    last = (data or {}).get("last_run")
    if not last:
        return True
    try:
        ts = _dt.datetime.fromisoformat(last)
    except ValueError:
        return True
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=_dt.timezone.utc)
    now = now or _dt.datetime.now(_dt.timezone.utc)
    return (now - ts).total_seconds() >= interval_s
