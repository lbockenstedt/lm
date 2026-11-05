"""Cert Expiry Monitor — daily TLS certificate check of the public Aruba
Central / HPE GreenLake and Juniper Mist cloud endpoints (plus operator-added
custom hosts).

Each host is probed on its TLS port with SNI; the leaf certificate is captured
even when chain verification fails (Mist device terminators and Aruba device
endpoints present private device-CA certs), and ``trusted`` records whether it
validated against the system trust store. Results are written to
``$LM_STATE_DIR/cert_monitor.json``; the scheduler (routes/cert_monitor.py)
runs a check at most once every 24h while the feature is enabled.

The endpoint list is data: ``cert_monitor_catalog.json`` (baseline hosts plus
the vendor pages to re-read). Once a day each source page is re-read and
replaces the baseline's matching hosts, so new endpoints are added; ones a
vendor stops listing are flagged deprecated (monitored for 30 days but never
alerted on), then dropped.
"""
# Thread pool to probe many hosts in parallel.
import concurrent.futures
# datetime for check timestamps and certificate validity maths.
import datetime as _dt
# html.unescape cleans vendor pages before host names are extracted.
import html as _html
# json reads the catalog and reads/writes the results and sources files.
import json
# Standard-library logging for [certmon] warnings.
import logging
# os for file paths, atomic writes and the LM_STATE_DIR setting.
import os
# re matches host names on vendor pages and in label rules.
import re
# socket resolves names and opens TCP connections for the TLS probe.
import socket
# ssl performs the TLS handshake (with and without verification).
import ssl
# tempfile creates a unique temp file for atomic JSON writes.
import tempfile
# urllib fetches the vendor pages that list endpoints.
import urllib.request

# Use the hub's main logger so [certmon] lines appear with other hub output.
logger = logging.getLogger("Hub")

# Where results are stored (overridable with LM_STATE_DIR).
STATE_DIR = os.environ.get("LM_STATE_DIR", "/var/lib/lm/state")
RESULTS_FILE = "cert_monitor.json"
# Normal check interval: once a day.
CHECK_INTERVAL_S = 24 * 3600
# Hourly while any cert expires within a day (or has expired), so a renewal
# shows up — and stops the reminder emails — within the hour.
URGENT_CHECK_S = 3600
URGENT_WINDOW_S = 24 * 3600
# Days-left thresholds for red (critical) and yellow (warning).
RED_DAYS = 30
YELLOW_DAYS = 90
# Per-host TLS timeout, probe concurrency, and cap on operator-added hosts.
PROBE_TIMEOUT_S = 8.0
MAX_WORKERS = 16
MAX_CUSTOM_HOSTS = 200

# The endpoint catalog shipped next to this file.
CATALOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cert_monitor_catalog.json")
# How long a host the vendor stopped listing stays visible (flagged deprecated).
DEPRECATED_KEEP_DAYS = 30
# Regex for a DNS host name; replaces "{host}" in each source's pattern.
_HOST_RE = r"[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)*"


def load_catalog(path=None):
    """The shipped endpoint catalog: {"hosts": [...], "sources": [...]}. It is
    data, not code: add a vendor or endpoint by editing the JSON."""
    # Read the catalog JSON.
    with open(path or CATALOG_FILE, "r", encoding="utf-8") as f:
        cat = json.load(f)
    # Prepare each source: expand the host pattern, make skip_ports a set, default role.
    sources = []
    for src in cat.get("sources") or []:
        src = dict(src)
        src["pattern"] = src["pattern"].replace("{host}", _HOST_RE)
        src["skip_ports"] = set(src.get("skip_ports") or ())
        src.setdefault("role", None)
        sources.append(src)
    # Copy the hosts so callers cannot change the loaded catalog.
    return {"hosts": [dict(h) for h in cat.get("hosts") or []], "sources": sources}


# Load the catalog once at import; expose its baseline hosts and sources.
_CATALOG = load_catalog()
BUILTIN_HOSTS = _CATALOG["hosts"]
SOURCES = _CATALOG["sources"]


def _deprecated_since(h, now=None):
    """Date a catalog/source host was deprecated, or None."""
    return h.get("deprecated") or None


def _past_keep_window(date_s, now=None):
    """Return True if the ISO date ``date_s`` is at least DEPRECATED_KEEP_DAYS in the past."""
    # Parse the date (first 19 chars, i.e. without a time zone); unparseable means "not yet".
    try:
        d = _dt.datetime.fromisoformat(str(date_s)[:19])
    except ValueError:
        return False
    # Treat a naive date as UTC.
    if d.tzinfo is None:
        d = d.replace(tzinfo=_dt.timezone.utc)
    # Compare against now.
    now = now or _dt.datetime.now(_dt.timezone.utc)
    return (now - d).days >= DEPRECATED_KEEP_DAYS


# ── host list auto-update ───────────────────────────────────────────────────
# Each source is a vendor page listing endpoints. A source "owns" the seed
# hosts with its service (and role, if set): once it has been read, those seed
# hosts are replaced by what the page lists. A read that finds too few hosts
# (page moved / redesigned) is not used, so the list never collapses.

# File holding each source's last-read host list; sources are re-read daily.
SOURCES_FILE = "cert_monitor_sources.json"
SOURCE_REFRESH_S = 24 * 3600
# Page fetch timeout (s) and the minimum hosts a page must list to be trusted.
SOURCE_TIMEOUT_S = 20
_MIN_SOURCE_HOSTS = 3


def _owned(src, h):
    """Return True if source ``src`` owns seed host ``h`` (same service, and role if set)."""
    return h["service"] == src["service"] and (src["role"] is None or h["role"] == src["role"])


def _label(src, host):
    """→ (region, role) for a host found on a source page, from the source's
    ``labels`` rules (first matching regex wins). Without a match the region is
    the first DNS label upper-cased and the role is the source's."""
    # Try each label rule in order; the first one whose regex matches wins.
    for rule in src.get("labels") or []:
        m = re.search(rule["re"], host)
        if not m:
            continue
        # Substitute "{N}" in a template with regex group N from the match.
        fill = lambda t: re.sub(r"\{(\d+)\}", lambda g: m.group(int(g.group(1))), t or "")
        # Role from the template, translated through role_map if present.
        role_raw = fill(rule.get("role"))
        role = (rule.get("role_map") or {}).get(role_raw, role_raw)
        # Region from the template; mapped, or cleaned of strip words and upper-cased.
        region = fill(rule.get("region"))
        rmap = rule.get("region_map") or {}
        if region in rmap:
            region = rmap[region]
        elif "{" in (rule.get("region") or ""):
            for strip in rule.get("region_strip") or []:
                region = region.replace(strip, "")
            region = region.strip("-").upper()
        # Some rules force a region when the role is a known one.
        if rule.get("region_if_role_known") and role_raw in (rule.get("role_map") or {}):
            region = rule["region_if_role_known"]
        return region, role
    # No rule matched: region is the first DNS label, role is the source's.
    return host.split(".")[0].upper(), src.get("role") or ""


def parse_source(src, page):
    """Vendor page (HTML) → host entries it lists. ``host (TCP n)`` sets the port."""
    # Strip HTML tags, decode entities and lower-case the page text.
    text = _html.unescape(re.sub(r"<[^>]+>", " ", page or "")).lower()
    # Results and (host, port) pairs already seen.
    found, seen = [], set()
    # Find every host matching the source's pattern, optionally followed by "(TCP n)".
    for m in re.finditer(r"(?<![a-z0-9.-])(" + src["pattern"] + r")(?![a-z0-9-])"
                         r"(?:\s*\(tcp\s*(\d+)\))?", text):
        # Port defaults to 443.
        host, port = m.group(1), int(m.group(2) or 443)
        # Skip internal/www hosts, skipped ports, hosts failing the "keep" filter, and duplicates.
        if (host.startswith(("internal", "www.")) or port in src.get("skip_ports", ())
                or (src.get("keep") and not re.search(src["keep"], host))
                or (host, port) in seen):
            continue
        # Record it with its region and role.
        seen.add((host, port))
        region, role = _label(src, host)
        found.append({"host": host, "port": port, "service": src["service"],
                      "region": region, "role": role})
    return found


def sources_path(state_dir=None):
    """Return the full path of the sources state file."""
    return os.path.join(state_dir or STATE_DIR, SOURCES_FILE)


def load_sources(state_dir=None):
    """source id → {"hosts", "updated_at", "checked_at", "error", "added", "removed", "changed_at"}."""
    # Parse the file; only a dict is accepted.
    try:
        with open(sources_path(state_dir), "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    # No file yet: empty.
    except FileNotFoundError:
        return {}
    # Unreadable: warn and treat as empty.
    except Exception as e:  # noqa: BLE001
        logger.warning("[certmon] could not read %s: %s", sources_path(state_dir), e)
        return {}


def _fetch(url):
    """Download ``url`` (max 4 MB) and return it as text."""
    # Send a browser-like User-Agent; some vendor sites block unknown clients.
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (LM cert monitor)"})
    with urllib.request.urlopen(req, timeout=SOURCE_TIMEOUT_S) as resp:
        return resp.read(4 * 1024 * 1024).decode("utf-8", "replace")


def refresh_sources(state_dir=None, fetch=_fetch, now=None):
    """Re-read every source page and store its host list. Returns the new
    sources data. Keeps a source's previous list when the read fails or
    finds less than half as many hosts as before."""
    # Timestamp for this refresh, and the previously stored data.
    now = (now or _dt.datetime.now(_dt.timezone.utc)).isoformat(timespec="seconds")
    data = load_sources(state_dir)
    # Re-read each source.
    for src in SOURCES:
        # This source's stored record and its previous host list (baseline if never read).
        cur = dict(data.get(src["id"]) or {})
        old = cur.get("hosts") or [h for h in BUILTIN_HOSTS if _owned(src, h)]
        cur["checked_at"] = now
        # Fetch and parse; too few hosts suggests the page moved, so treat it as a failure.
        try:
            hosts = parse_source(src, fetch(src["url"]))
            if len(hosts) < max(_MIN_SOURCE_HOSTS, len(old) // 2):
                raise ValueError(f"only {len(hosts)} host(s) found on the page (had {len(old)})")
        # On failure keep the previous list and record the error.
        except Exception as e:  # noqa: BLE001
            cur["error"] = str(e)[:200]
            logger.warning("[certmon] host list source %s not updated: %s", src["id"], e)
            data[src["id"]] = cur
            continue
        # Compare the old and new host sets.
        old_keys = {cert_key(h) for h in old}
        new_keys = {cert_key(h) for h in hosts}
        # Store the new list.
        cur.update({"hosts": hosts, "updated_at": now, "error": "", "url": src["url"]})
        added, removed = sorted(new_keys - old_keys), sorted(old_keys - new_keys)
        # A URL the vendor stopped listing is deprecated, not deleted: it stays
        # visible (never alerted on) for DEPRECATED_KEEP_DAYS, then drops off.
        dep = {k: v for k, v in (cur.get("deprecated") or {}).items() if k not in new_keys}
        # Add newly dropped hosts to the deprecated set with today's date.
        for h in old:
            k = cert_key(h)
            if k not in new_keys and k not in dep:
                dep[k] = {**h, "deprecated": now}
        # Forget deprecated hosts older than the keep window.
        cur["deprecated"] = {k: v for k, v in dep.items() if not _past_keep_window(v["deprecated"])}
        if added or removed:  # keep the last real change on show
            cur.update({"added": added, "removed": removed, "changed_at": now})
            logger.info("[certmon] host list source %s: +%d -%d (%s)", src["id"], len(added),
                        len(removed), ", ".join(["+" + k for k in added] + ["-" + k for k in removed])[:500])
        # Save this source's record.
        data[src["id"]] = cur
    # Persist all sources atomically and return them.
    _write_json(sources_path(state_dir), data, ".cert_monitor_sources.")
    return data


def sources_due(data, now=None):
    """Return True if any source has never been read or the oldest read is over a day old."""
    # When each source was last checked.
    times = [(data.get(s["id"]) or {}).get("checked_at") for s in SOURCES]
    if not all(times):
        return True
    # Find the oldest check; unparseable dates count as due.
    now = now or _dt.datetime.now(_dt.timezone.utc)
    try:
        oldest = min(_dt.datetime.fromisoformat(t) for t in times)
    except ValueError:
        return True
    # Due once the oldest is at least SOURCE_REFRESH_S old.
    return (now - oldest).total_seconds() >= SOURCE_REFRESH_S


def builtin_hosts(state_dir=None):
    """The catalog's baseline list with each read source's hosts swapped in for
    the baseline's. Hosts a source stopped listing, and catalog hosts carrying
    a ``deprecated`` date, are kept flagged ``deprecated`` for 30 days."""
    # Sources that have a stored host list.
    data = load_sources(state_dir)
    live = [s for s in SOURCES if (data.get(s["id"]) or {}).get("hosts")]
    # Start from baseline hosts not owned by any read source.
    hosts = [dict(h) for h in BUILTIN_HOSTS if not any(_owned(s, h) for s in live)]
    have = {cert_key(h) for h in hosts}
    # Add each read source's current and deprecated hosts, without duplicates.
    for s in live:
        for h in data[s["id"]]["hosts"] + list((data[s["id"]].get("deprecated") or {}).values()):
            if cert_key(h) not in have:
                have.add(cert_key(h))
                hosts.append(dict(h))
    # Drop hosts deprecated longer than the keep window.
    out = []
    for h in hosts:
        since = _deprecated_since(h)
        if since and _past_keep_window(since):
            continue
        out.append(h)
    return out


# ── config ──────────────────────────────────────────────────────────────────

def parse_host_entry(raw):
    """``host`` / ``host:port`` / ``https://host[:port]/path`` → (host, port).
    Returns None for anything that is not a plausible DNS name / IPv4."""
    # Normalise; empty input is invalid.
    s = str(raw or "").strip().lower()
    if not s:
        return None
    # Strip a URL scheme and any path or query.
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("/", 1)[0].split("?", 1)[0]
    # Optional ":port" (exactly one colon, so IPv6 is not accepted).
    port = 443
    if s.count(":") == 1:
        s, p = s.split(":", 1)
        if not p.isdigit() or not (0 < int(p) < 65536):
            return None
        port = int(p)
    # Validate the name: overall length, allowed characters, no empty labels.
    s = s.strip(".")
    if not s or len(s) > 253:
        return None
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789-.")
    if any(c not in allowed for c in s) or ".." in s:
        return None
    # Each label must be 1-63 chars and not start or end with "-".
    if any(not lbl or len(lbl) > 63 or lbl.startswith("-") or lbl.endswith("-")
           for lbl in s.split(".")):
        return None
    return s, port


def normalize_config(cfg):
    """Validate a Cert Monitor config dict, returning a clean copy with known keys only."""
    # Copy so the caller's dict is not changed.
    cfg = dict(cfg or {})
    custom, seen = [], set()
    # Custom hosts: parse, de-duplicate, and store as "host" or "host:port".
    for entry in cfg.get("custom_hosts") or []:
        p = parse_host_entry(entry)
        if p and p not in seen:
            seen.add(p)
            custom.append(p[0] if p[1] == 443 else f"{p[0]}:{p[1]}")
    # Disabled built-in hosts must be names the monitor actually knows.
    builtin_names = {h["host"] for h in BUILTIN_HOSTS} | {h["host"] for h in builtin_hosts()}
    disabled = sorted({str(h).strip().lower()
                       for h in (cfg.get("disabled_builtin") or [])
                       if str(h).strip().lower() in builtin_names})
    # Hosts the operator manually marked deprecated, stored as "host:port".
    deprecated = []
    for entry in cfg.get("deprecated_hosts") or []:
        p = parse_host_entry(entry)
        if p:
            deprecated.append(f"{p[0]}:{p[1]}")
    # Return the clean config (custom hosts capped).
    return {"enabled": bool(cfg.get("enabled")),
            "custom_hosts": custom[:MAX_CUSTOM_HOSTS],
            "disabled_builtin": disabled,
            "deprecated_hosts": sorted(set(deprecated))}


def effective_hosts(cfg):
    """Return the list of hosts to check for ``cfg``: built-ins (minus disabled) plus custom."""
    # Normalise the config first.
    cfg = normalize_config(cfg)
    # Built-in hosts the operator has not disabled.
    disabled = set(cfg["disabled_builtin"])
    hosts = [h for h in builtin_hosts() if h["host"] not in disabled]
    # Apply manual "deprecated" marks.
    manual = set(cfg["deprecated_hosts"])
    for h in hosts:
        if cert_key(h) in manual and not h.get("deprecated"):
            h["deprecated"] = "manual"
    # Add custom hosts that are not already in the list.
    have = {(h["host"], h["port"]) for h in hosts}
    for entry in cfg["custom_hosts"]:
        host, port = parse_host_entry(entry)
        if (host, port) in have:
            continue
        have.add((host, port))
        hosts.append({"host": host, "port": port, "service": "Custom",
                      "region": "", "role": "Custom",
                      **({"deprecated": "manual"} if f"{host}:{port}" in manual else {})})
    return hosts


# ── probe ───────────────────────────────────────────────────────────────────

def classify(days_left, error=None):
    """Return "red", "yellow" or "green" from days left, or "error"/"unknown" without a cert."""
    # No cert data: error if a probe error occurred, else unknown.
    if days_left is None:
        return "error" if error else "unknown"
    # Compare against the thresholds.
    if days_left < RED_DAYS:
        return "red"
    if days_left < YELLOW_DAYS:
        return "yellow"
    return "green"


def _name_attr(name, oid):
    """Return the first value of attribute ``oid`` in X.509 name ``name``, or ""."""
    # Missing or unreadable attributes give "".
    try:
        vals = name.get_attributes_for_oid(oid)
        return vals[0].value if vals else ""
    except Exception:  # noqa: BLE001
        return ""


def parse_cert(der, now=None):
    """DER leaf certificate → summary dict (subject, issuer/provider, key type,
    signature algorithm, validity, days left)."""
    # Imported lazily: the cryptography package is only needed when a cert is parsed.
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
    from cryptography.x509.oid import ExtensionOID, NameOID

    # Parse the certificate.
    cert = x509.load_der_x509_certificate(der)
    now = now or _dt.datetime.now(_dt.timezone.utc)
    # Validity dates as aware UTC datetimes (older cryptography has no *_utc properties).
    try:
        not_after = cert.not_valid_after_utc
        not_before = cert.not_valid_before_utc
    except AttributeError:  # cryptography < 42
        not_after = cert.not_valid_after.replace(tzinfo=_dt.timezone.utc)
        not_before = cert.not_valid_before.replace(tzinfo=_dt.timezone.utc)

    # Describe the public key type and size.
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

    # Signature algorithm name, if available.
    try:
        sig_alg = cert.signature_algorithm_oid._name
    except Exception:  # noqa: BLE001
        sig_alg = ""
    # DNS names from the Subject Alternative Name extension, if present.
    try:
        san = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(x509.DNSName)
    except Exception:  # noqa: BLE001
        san = []

    # Cert type: DV/OV/EV from the certificate-policy OIDs (CA/B Forum).
    cert_type = ""
    # Look up the policy OIDs; missing extension leaves the type blank.
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
    # Note wildcard certificates.
    if san and any(s.startswith("*.") for s in san):
        cert_type = (cert_type + " wildcard").strip()

    # Issuer organisation/common name and whole days left.
    issuer_o = _name_attr(cert.issuer, NameOID.ORGANIZATION_NAME)
    issuer_cn = _name_attr(cert.issuer, NameOID.COMMON_NAME)
    days_left = int((not_after - now).total_seconds() // 86400)
    # Build the summary.
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
    """Do a TLS handshake to host:port and return (DER leaf cert, TLS version)."""
    # Verified mode uses the system trust store and checks the hostname.
    if verify:
        ctx = ssl.create_default_context()
    # Unverified mode accepts any cert so we can still read it.
    else:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    # Connect, handshake with SNI, and return the peer cert and protocol version.
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            return tls.getpeercert(binary_form=True), tls.version()


def probe_host(entry, timeout=PROBE_TIMEOUT_S, now=None):
    """Probe one host entry and return its result row (cert details, trust, status)."""
    # Host and port (default 443).
    host, port = entry["host"], int(entry.get("port") or 443)
    # Copy the identifying fields.
    out = {k: entry.get(k, "") for k in ("host", "service", "region", "role")}
    # Carry over the deprecated flag.
    if entry.get("deprecated"):
        out["deprecated"] = True
        out["deprecated_at"] = str(entry["deprecated"])
    # Defaults before probing.
    out.update({"port": port, "checked_at": _dt.datetime.now(
        _dt.timezone.utc).isoformat(timespec="seconds"),
        "trusted": False, "verify_error": "", "error": "", "tls_version": ""})
    # Resolve the name first so DNS failures are reported clearly.
    try:
        socket.getaddrinfo(host, port)
    except socket.gaierror as e:
        out.update({"error": f"DNS: {e.strerror or e}", "status": "error",
                    "days_left": None})
        return out
    # First try a verified handshake; success means the cert is trusted.
    der = None
    try:
        der, out["tls_version"] = _handshake(host, port, True, timeout)
        out["trusted"] = True
    # Verification failed: remember why (we will still read the cert below).
    except ssl.SSLCertVerificationError as e:
        out["verify_error"] = (getattr(e, "verify_message", None) or str(e))[:200]
    # Any other failure (timeout, refused) is a probe error.
    except Exception as e:  # noqa: BLE001
        out["error"] = f"{type(e).__name__}: {e}"[:200]
    # If verification failed, handshake again without verification to read the cert.
    if der is None and not out["error"]:
        try:
            der, out["tls_version"] = _handshake(host, port, False, timeout)
        except Exception as e:  # noqa: BLE001
            out["error"] = f"{type(e).__name__}: {e}"[:200]
    # Parse the certificate into the row.
    if der:
        try:
            out.update(parse_cert(der, now=now))
        except Exception as e:  # noqa: BLE001
            out["error"] = f"parse: {e}"[:200]
    # Set days left (None if unknown) and the colour status.
    out.setdefault("days_left", None)
    out["status"] = classify(out.get("days_left"), out["error"])
    return out


# Sort order for statuses: worst first.
_STATUS_RANK = {"red": 0, "yellow": 1, "error": 2, "unknown": 3, "green": 4}


def sort_results(results):
    """Return ``results`` sorted worst status first, then fewest days left, then host name."""
    def key(r):
        """Sort key: status rank, days left (unknown last), host name."""
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

# global_config key for ignored hosts, its size cap, and the statuses counted.
IGNORE_KEY = "cert_monitor_ignored"
MAX_IGNORED = 1000
STATUSES = ("red", "yellow", "green", "error", "unknown")


def cert_key(r):
    """Return the "host:port" key that identifies a monitored endpoint."""
    return f"{r.get('host', '')}:{int(r.get('port') or 443)}"


def normalize_ignored(raw):
    """Validate the stored ignore map, keeping well-formed "host:port" keys (capped)."""
    # Result; anything but a dict is treated as empty.
    out = {}
    if not isinstance(raw, dict):
        return out
    # Check each key.
    for k, v in raw.items():
        # Split "host:port" and validate it.
        host, _, port = str(k).rpartition(":")
        p = parse_host_entry(f"{host}:{port}") if host and port.isdigit() else None
        if not p:
            continue
        # Keep who/when (trimmed).
        v = v if isinstance(v, dict) else {}
        out[f"{p[0]}:{p[1]}"] = {"by": str(v.get("by") or "")[:120],
                                 "at": str(v.get("at") or "")[:40]}
        # Stop at the cap.
        if len(out) >= MAX_IGNORED:
            break
    return out


def apply_ignored(results, ignored):
    """Copy of ``results`` with ``ignored`` (and who/when) set on each row;
    ignored rows sort after the active ones, keeping their own order."""
    # Treat None as no ignored hosts.
    ignored = ignored or {}
    active, muted = [], []
    # Mark each row (on a copy) and split into active and ignored.
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
    # Ignored rows go last.
    return active + muted


def active_results(results):
    """Return only results that are neither ignored nor deprecated."""
    return [r for r in results or [] if not r.get("ignored") and not r.get("deprecated")]


def count_statuses(results):
    """Status counts over non-ignored results, plus an ``ignored`` total."""
    # Start every known status at zero.
    counts = {s: 0 for s in STATUSES}
    counts["ignored"] = 0
    # Count each row once: ignored, deprecated, or its status.
    for r in results or []:
        if r.get("ignored"):
            counts["ignored"] += 1
            continue
        if r.get("deprecated"):
            counts["deprecated"] = counts.get("deprecated", 0) + 1
            continue
        s = r.get("status", "unknown")
        counts[s] = counts.get(s, 0) + 1
    return counts


def run_checks(hosts, timeout=PROBE_TIMEOUT_S, workers=MAX_WORKERS):
    """Probe every host in parallel and return the run summary (timing, counts, results)."""
    # Start time.
    started = _dt.datetime.now(_dt.timezone.utc)
    results = []
    # Probe hosts in a thread pool (I/O-bound).
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        for r in ex.map(lambda h: probe_host(h, timeout=timeout), hosts):
            results.append(r)
    # Sort and count by status.
    results = sort_results(results)
    counts = {s: 0 for s in ("red", "yellow", "green", "error", "unknown")}
    for r in results:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    # Return the summary with timings and thresholds.
    finished = _dt.datetime.now(_dt.timezone.utc)
    return {"last_run": finished.isoformat(timespec="seconds"),
            "duration_s": round((finished - started).total_seconds(), 1),
            "thresholds": {"red_days": RED_DAYS, "yellow_days": YELLOW_DAYS},
            "counts": counts, "results": results}


# ── storage ─────────────────────────────────────────────────────────────────

def results_path(state_dir=None):
    """Return the full path of the results file."""
    return os.path.join(state_dir or STATE_DIR, RESULTS_FILE)


def load_results(state_dir=None):
    """Load the last results; returns {} if missing or unreadable."""
    # Parse the file; only a dict is accepted.
    try:
        with open(results_path(state_dir), "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    # No file yet: empty.
    except FileNotFoundError:
        return {}
    # Unreadable: warn and treat as empty.
    except Exception as e:  # noqa: BLE001
        logger.warning("[certmon] could not read %s: %s", results_path(state_dir), e)
        return {}


def save_results(data, state_dir=None):
    """Atomically save the check results."""
    _write_json(results_path(state_dir), data, ".cert_monitor.")


def _write_json(path, data, prefix):
    """Write ``data`` as JSON to ``path`` atomically (temp file + rename)."""
    # Make sure the directory exists.
    d = os.path.dirname(path)
    os.makedirs(d, exist_ok=True)
    # Unique temp file in the same directory so the final rename is atomic.
    fd, tmp = tempfile.mkstemp(prefix=prefix, dir=d)
    # Write, restrict permissions, then atomically replace the old file.
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.chmod(tmp, 0o640)
        os.replace(tmp, path)
    # On any failure remove the temp file, then re-raise.
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def check_interval(data, ignored=None, now=None):
    """Seconds between checks: URGENT_CHECK_S while a non-ignored cert expires
    within URGENT_WINDOW_S (or has expired), else CHECK_INTERVAL_S."""
    # Current time (tests may pass their own).
    now = now or _dt.datetime.now(_dt.timezone.utc)
    # Look for any non-ignored cert expiring soon.
    for r in (data or {}).get("results") or []:
        if not r.get("not_after") or cert_key(r) in (ignored or {}):
            continue
        # Parse the expiry; skip unparseable dates.
        try:
            ts = _dt.datetime.fromisoformat(r["not_after"])
        except ValueError:
            continue
        # Treat a naive date as UTC.
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=_dt.timezone.utc)
        # One expiring soon (or expired): check hourly.
        if (ts - now).total_seconds() < URGENT_WINDOW_S:
            return URGENT_CHECK_S
    # Otherwise daily.
    return CHECK_INTERVAL_S


def is_due(data, now=None, interval_s=None, ignored=None):
    """Return True if a new check run is due (never run, or the interval has passed)."""
    # Pick the interval (hourly if something is about to expire).
    if interval_s is None:
        interval_s = check_interval(data, ignored, now)
    # Never run: due now.
    last = (data or {}).get("last_run")
    if not last:
        return True
    # Parse the last run time; unparseable means due.
    try:
        ts = _dt.datetime.fromisoformat(last)
    except ValueError:
        return True
    # Treat a naive time as UTC.
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=_dt.timezone.utc)
    # Due once the interval has elapsed.
    now = now or _dt.datetime.now(_dt.timezone.utc)
    return (now - ts).total_seconds() >= interval_s
