"""Cert Expiry Monitor — daily TLS certificate check of the public Aruba
Central / HPE GreenLake and Juniper Mist cloud endpoints (plus operator-added
custom hosts).

Each host is probed on its TLS port with SNI; the leaf certificate is captured
even when chain verification fails (Mist device terminators and Aruba device
endpoints present private device-CA certs), and ``trusted`` records whether it
validated against the system trust store. Results are written to
``$LM_STATE_DIR/cert_monitor.json``; the scheduler (routes/cert_monitor.py)
runs a check at most once every 24h while the feature is enabled.

The built-in Mist / Central host list is a hard-coded seed; once a day the
parts the vendors publish (see SOURCES) are re-read and replace the seed's
matching hosts, so new endpoints are added and retired ones dropped.
"""
import concurrent.futures
import datetime as _dt
import html as _html
import json
import logging
import os
import re
import socket
import ssl
import tempfile
import urllib.request

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
                         "ca1", "gb1", "in1", "jp1", "au1", "ae1", "cn1"]


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
        tld = ".com.cn" if r == "cn1" else ".com"
        hosts.append({"host": f"{r}.api.central.arubanetworks{tld}", "port": 443,
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


# ── host list auto-update ───────────────────────────────────────────────────
# Each source is a vendor page listing endpoints. A source "owns" the seed
# hosts with its service (and role, if set): once it has been read, those seed
# hosts are replaced by what the page lists. A read that finds too few hosts
# (page moved / redesigned) is not used, so the list never collapses.

SOURCES_FILE = "cert_monitor_sources.json"
SOURCE_REFRESH_S = 24 * 3600
SOURCE_TIMEOUT_S = 20
_HOST_RE = r"[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)*"
SOURCES = [
    {"id": "mist", "service": "Juniper Mist", "role": None,
     "url": "https://www.juniper.net/documentation/us/en/software/mist/"
            "mist-management/topics/ref/firewall-ports-to-open.html",
     "pattern": _HOST_RE + r"\.(?:mist\.com|mistsys\.net)",
     # oc-term (TCP 2200) is Junos outbound SSH, not TLS.
     "skip_ports": {2200}},
    {"id": "central-apigw", "service": "Aruba Central", "role": "API gateway",
     "url": "https://developer.arubanetworks.com/aruba-central/docs/api-oauth-access-token",
     "pattern": _HOST_RE + r"\.central\.arubanetworks\.com(?:\.cn)?",
     "keep": lambda h: "apigw" in h or h.startswith("api-")},
    {"id": "new-central", "service": "Aruba Central (New Central)", "role": None,
     "url": "https://developer.arubanetworks.com/new-central/docs/getting-started-with-rest-apis",
     "pattern": r"[a-z0-9]+\.api\.central\.arubanetworks\.com(?:\.cn)?"},
]
_MIN_SOURCE_HOSTS = 3
_MIST_REGION_BY_PREFIX = {p.rstrip("."): r for p, r in _MIST_REGIONS}
_MIST_ROLE_BY_SUB = dict(_MIST_ROLES, **{
    "srx-log-terminator": "SRX log terminator", "radsec": "Access Assurance RadSec",
    "radsec-eu": "Access Assurance RadSec", "redirect": "Device redirect",
    "support-portal": "Support portal"})
_CENTRAL_CLUSTER_BY_GW = {gw: c for c, _ui, gw, _d in _CENTRAL_CLUSTERS}


def _owned(src, h):
    return h["service"] == src["service"] and (src["role"] is None or h["role"] == src["role"])


def _label(src, host):
    """→ (region, role) for a host found on a source page."""
    if src["id"] == "mist":
        sub, _, rest = host.partition(".")
        inst = rest.rsplit(".", 2)[0] if rest.count(".") >= 2 else ""
        role = _MIST_ROLE_BY_SUB.get(sub, sub)
        if not inst:
            region = "Global 01" if sub in _MIST_ROLE_BY_SUB and rest == "mist.com" else "Global"
        else:
            region = _MIST_REGION_BY_PREFIX.get(inst, inst.upper())
        return region, role
    first = host.split(".")[0]
    if src["id"] == "central-apigw":
        if host.endswith(".cn"):
            return "China-1", "API gateway"
        region = _CENTRAL_CLUSTER_BY_GW.get(first) or first.replace("apigw", "").strip("-").upper()
        return region, "API gateway"
    return first.upper(), "API gateway"


def parse_source(src, page):
    """Vendor page (HTML) → host entries it lists. ``host (TCP n)`` sets the port."""
    text = _html.unescape(re.sub(r"<[^>]+>", " ", page or "")).lower()
    found, seen = [], set()
    for m in re.finditer(r"(?<![a-z0-9.-])(" + src["pattern"] + r")(?![a-z0-9-])"
                         r"(?:\s*\(tcp\s*(\d+)\))?", text):
        host, port = m.group(1), int(m.group(2) or 443)
        if (host.startswith(("internal", "www.")) or port in src.get("skip_ports", ())
                or not src.get("keep", lambda h: True)(host) or (host, port) in seen):
            continue
        seen.add((host, port))
        region, role = _label(src, host)
        found.append({"host": host, "port": port, "service": src["service"],
                      "region": region, "role": role})
    return found


def sources_path(state_dir=None):
    return os.path.join(state_dir or STATE_DIR, SOURCES_FILE)


def load_sources(state_dir=None):
    """source id → {"hosts", "updated_at", "checked_at", "error", "added", "removed", "changed_at"}."""
    try:
        with open(sources_path(state_dir), "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except FileNotFoundError:
        return {}
    except Exception as e:  # noqa: BLE001
        logger.warning("[certmon] could not read %s: %s", sources_path(state_dir), e)
        return {}


def _fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (LM cert monitor)"})
    with urllib.request.urlopen(req, timeout=SOURCE_TIMEOUT_S) as resp:
        return resp.read(4 * 1024 * 1024).decode("utf-8", "replace")


def refresh_sources(state_dir=None, fetch=_fetch, now=None):
    """Re-read every source page and store its host list. Returns the new
    sources data. Keeps a source's previous list when the read fails or
    finds less than half as many hosts as before."""
    now = (now or _dt.datetime.now(_dt.timezone.utc)).isoformat(timespec="seconds")
    data = load_sources(state_dir)
    for src in SOURCES:
        cur = dict(data.get(src["id"]) or {})
        old = cur.get("hosts") or [h for h in BUILTIN_HOSTS if _owned(src, h)]
        cur["checked_at"] = now
        try:
            hosts = parse_source(src, fetch(src["url"]))
            if len(hosts) < max(_MIN_SOURCE_HOSTS, len(old) // 2):
                raise ValueError(f"only {len(hosts)} host(s) found on the page (had {len(old)})")
        except Exception as e:  # noqa: BLE001
            cur["error"] = str(e)[:200]
            logger.warning("[certmon] host list source %s not updated: %s", src["id"], e)
            data[src["id"]] = cur
            continue
        old_keys = {cert_key(h) for h in old}
        new_keys = {cert_key(h) for h in hosts}
        cur.update({"hosts": hosts, "updated_at": now, "error": "", "url": src["url"]})
        added, removed = sorted(new_keys - old_keys), sorted(old_keys - new_keys)
        if added or removed:  # keep the last real change on show
            cur.update({"added": added, "removed": removed, "changed_at": now})
            logger.info("[certmon] host list source %s: +%d -%d (%s)", src["id"], len(added),
                        len(removed), ", ".join(["+" + k for k in added] + ["-" + k for k in removed])[:500])
        data[src["id"]] = cur
    _write_json(sources_path(state_dir), data, ".cert_monitor_sources.")
    return data


def sources_due(data, now=None):
    times = [(data.get(s["id"]) or {}).get("checked_at") for s in SOURCES]
    if not all(times):
        return True
    now = now or _dt.datetime.now(_dt.timezone.utc)
    try:
        oldest = min(_dt.datetime.fromisoformat(t) for t in times)
    except ValueError:
        return True
    return (now - oldest).total_seconds() >= SOURCE_REFRESH_S


def builtin_hosts(state_dir=None):
    """The seed list with each read source's hosts swapped in for the seed's."""
    data = load_sources(state_dir)
    live = [s for s in SOURCES if (data.get(s["id"]) or {}).get("hosts")]
    hosts = [dict(h) for h in BUILTIN_HOSTS if not any(_owned(s, h) for s in live)]
    have = {cert_key(h) for h in hosts}
    for s in live:
        for h in data[s["id"]]["hosts"]:
            if cert_key(h) not in have:
                have.add(cert_key(h))
                hosts.append(dict(h))
    return hosts


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
    builtin_names = {h["host"] for h in BUILTIN_HOSTS} | {h["host"] for h in builtin_hosts()}
    disabled = sorted({str(h).strip().lower()
                       for h in (cfg.get("disabled_builtin") or [])
                       if str(h).strip().lower() in builtin_names})
    return {"enabled": bool(cfg.get("enabled")),
            "custom_hosts": custom[:MAX_CUSTOM_HOSTS],
            "disabled_builtin": disabled}


def effective_hosts(cfg):
    cfg = normalize_config(cfg)
    disabled = set(cfg["disabled_builtin"])
    hosts = [h for h in builtin_hosts() if h["host"] not in disabled]
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


# ── per-cert ignore ─────────────────────────────────────────────────────────
# Operators can mark a monitored endpoint "ignored": it stays in the list (with
# its real status) but is left out of the status counts and alert rules. The
# list lives in global_config["cert_monitor_ignored"] = {"host:port": {by, at}}
# and is keyed by host:port — the identity the monitor (and its alert edge
# state) already uses for a result.

IGNORE_KEY = "cert_monitor_ignored"
MAX_IGNORED = 1000
STATUSES = ("red", "yellow", "green", "error", "unknown")


def cert_key(r):
    return f"{r.get('host', '')}:{int(r.get('port') or 443)}"


def normalize_ignored(raw):
    out = {}
    if not isinstance(raw, dict):
        return out
    for k, v in raw.items():
        host, _, port = str(k).rpartition(":")
        p = parse_host_entry(f"{host}:{port}") if host and port.isdigit() else None
        if not p:
            continue
        v = v if isinstance(v, dict) else {}
        out[f"{p[0]}:{p[1]}"] = {"by": str(v.get("by") or "")[:120],
                                 "at": str(v.get("at") or "")[:40]}
        if len(out) >= MAX_IGNORED:
            break
    return out


def apply_ignored(results, ignored):
    """Copy of ``results`` with ``ignored`` (and who/when) set on each row;
    ignored rows sort after the active ones, keeping their own order."""
    ignored = ignored or {}
    active, muted = [], []
    for r in results or []:
        r = dict(r)
        meta = ignored.get(cert_key(r))
        r["ignored"] = meta is not None
        if meta is not None:
            r["ignored_by"] = meta.get("by", "")
            r["ignored_at"] = meta.get("at", "")
            muted.append(r)
        else:
            r.pop("ignored_by", None)
            r.pop("ignored_at", None)
            active.append(r)
    return active + muted


def active_results(results):
    return [r for r in results or [] if not r.get("ignored")]


def count_statuses(results):
    """Status counts over non-ignored results, plus an ``ignored`` total."""
    counts = {s: 0 for s in STATUSES}
    counts["ignored"] = 0
    for r in results or []:
        if r.get("ignored"):
            counts["ignored"] += 1
            continue
        s = r.get("status", "unknown")
        counts[s] = counts.get(s, 0) + 1
    return counts


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
    _write_json(results_path(state_dir), data, ".cert_monitor.")


def _write_json(path, data, prefix):
    d = os.path.dirname(path)
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=prefix, dir=d)
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
