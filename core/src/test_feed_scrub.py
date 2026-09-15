"""Filtering + reshaping for the test-data feed (``scripts/hub_feed.py`` and
``routes/test_feed.py`` share this module).

Lives in ``core/src`` rather than beside the script because BOTH ends of the
feed need it and they must not drift: the SOURCE hub filters before serving
``/api/test-feed/snapshot``, and the receiving feeder runs the same pass on the
way in (so a snapshot from an older source hub, or a hand-fed fixture, is still
covered). Running it twice is harmless in either mode.

TWO RULES, and they are not the same kind of rule:

* **Secrets are always dropped** (``DROP_FIELDS``). Not a toggle, not a
  default — no path through this module forwards a password, token, key or
  certificate. Duplicating *fleet* data faithfully never requires them, and
  the receiving hub is by design less hardened than the source.
* **Identifiers are forwarded verbatim** unless the operator opts into
  ``pseudonymise=True``. The feed exists to duplicate a production fleet so an
  issue reproduces against the hostnames and addresses actually seen in the
  field; rewriting them defeats the purpose. Anonymising remains available for
  when the shape of the fleet is wanted without the identities.

``IDENTIFYING_FIELDS``/``IDENTIFYING_SUBSTRINGS`` are deliberately over-broad,
so that when anonymising IS on, a schema addition upstream does not quietly
start leaking a new identifier.
"""
import hashlib

#: Client/VM fields replaced wholesale with a pseudonym derived from the value.
#: Anything identifying a person, a machine or a network location belongs here.
IDENTIFYING_FIELDS = (
    "hostname", "host", "name", "user", "username", "owner", "display_name",
    "mac", "mac_address", "ip", "ip_address", "ipv4", "ipv6", "serial",
    "serial_number", "asset_tag", "ssid", "connected_ssid", "site", "wsite",
    "tenant", "tenant_id", "location", "description", "notes", "comment",
)

#: Substrings that mark a key as identifying even when the exact name is not in
#: IDENTIFYING_FIELDS. Catches the long tail (``client_mac``, ``mgmt_ip``,
#: ``primary_hostname``) so a schema addition upstream does not silently start
#: leaking. Deliberately broad: over-scrubbing a test feed costs nothing,
#: under-scrubbing ships real data to a lab hub.
IDENTIFYING_SUBSTRINGS = (
    "hostname", "mac", "_ip", "ip_", "serial", "ssid", "user", "email",
    "tenant", "site", "owner", "addr",
    # ``spoke`` and ``node`` catch the attribution the aggregate API stamps onto
    # every row (SimulationsService._meta adds spoke_id / spoke_name /
    # spoke_hostname; proxmox rows carry node). Pseudonymising the synthetic
    # SPOKE ID alone is not enough — these ride INSIDE the client dicts, so
    # without this the real fleet's spoke names reach the target in the payload
    # body even though the id on the envelope was scrubbed.
    "spoke", "node",
)

#: Keys never forwarded at all — credentials and tokens have no business in a
#: test feed even pseudonymised, because a pseudonym of a secret is still a
#: secret-shaped value someone may try to use.
DROP_FIELDS = (
    "password", "passwd", "secret", "token", "api_key", "apikey", "psk",
    "private_key", "key", "cert", "certificate", "credential", "credentials",
    "auth", "authorization", "session", "cookie",
)

_PLATFORM_WORDS = ("kbell", "ibennett", "xmendoza", "tstewart", "qwu", "jlee",
                   "amorgan", "dkhan", "rpatel", "lnovak", "cmartin", "sokafor")


def _pseudonym(value, salt, kind="host"):
    """Deterministic, non-reversible stand-in for ``value``.

    Stable per (value, salt) so a client keeps one identity across polls — the
    hub dedups clients by hostname, so a value that churned every cycle would
    inflate the roster instead of reproducing it. ``--salt`` (random per run
    unless pinned) means the mapping is not consistent across runs either, so
    two feeds cannot be correlated back to the same real fleet."""
    if value is None:
        return None
    digest = hashlib.sha256(f"{salt}\x00{value}".encode()).hexdigest()
    n = int(digest[:8], 16)
    if kind == "mac":
        # Locally-administered unicast (02:...) — never a real vendor OUI.
        tail = ":".join(digest[i:i + 2] for i in range(0, 10, 2))
        return f"02:{tail}"
    if kind == "ip":
        # TEST-NET-3 (RFC 5737) — reserved for documentation, never routable.
        return f"203.0.113.{n % 254 + 1}"
    if kind == "serial":
        return f"SN{digest[:10].upper()}"
    return f"{_PLATFORM_WORDS[n % len(_PLATFORM_WORDS)]}{n % 900 + 100}"


def _kind_for(key):
    k = key.lower()
    if "mac" in k:
        return "mac"
    if k.endswith("ip") or "ip_" in k or "_ip" in k or "addr" in k:
        return "ip"
    if "serial" in k:
        return "serial"
    return "host"


def _is_identifying(key):
    k = key.lower()
    return k in IDENTIFYING_FIELDS or any(s in k for s in IDENTIFYING_SUBSTRINGS)


def _is_dropped(key):
    k = key.lower()
    return any(d == k or d in k for d in DROP_FIELDS)


def scrub_snapshot(obj, salt, pseudonymise=False):
    """Drop secret-bearing fields and — when ``pseudonymise`` is True — replace
    identifying ones with stable stand-ins.

    Structure is preserved exactly: counts, nesting, list lengths, non-string
    values. Only leaf values ever change, because the structure IS what the
    target is reproducing.

    ``pseudonymise`` defaults to **False** (verbatim). This feature exists to
    duplicate a production fleet into a test hub so a real issue can be
    reproduced against the real identifiers, and pseudonymised hostnames and
    addresses defeat that — so the operator chose verbatim as the default.
    Passing True restores the anonymising behaviour (Setup → Test Data Feed).

    Dropping secrets is NOT optional in either mode. Copying real hostnames to
    a test hub is a judgement the operator makes about their own estate;
    copying live credentials onto a less-hardened box is a different category
    of exposure, and duplicating *fleet* data faithfully never requires it."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if _is_dropped(k):
                continue
            if pseudonymise and _is_identifying(k) and isinstance(v, str) and v:
                out[k] = _pseudonym(v, salt, _kind_for(k))
            else:
                out[k] = scrub_snapshot(v, salt, pseudonymise)
        return out
    if isinstance(obj, list):
        return [scrub_snapshot(v, salt, pseudonymise) for v in obj]
    return obj



def shard_by_spoke(snapshot):
    """Group the flat client/VM lists back into per-spoke buckets.

    The aggregate endpoints return the tenant's fleet already merged across
    spokes (that is what "aggregate" means), but the target has to receive it as
    per-spoke CS_TELEMETRY — one frame per synthetic spoke — or the hub's
    dedup/fan-out path never runs the way it does in production. Clients carry
    the spoke that reported them; anything unattributed lands in a single
    catch-all so it is still represented rather than silently dropped."""
    clients = snapshot.get("clients") or {}
    if isinstance(clients, dict):
        clients = clients.get("clients") or clients.get("data") or []
    vms = snapshot.get("proxmox") or {}
    if isinstance(vms, dict):
        vms = vms.get("vms") or vms.get("proxmox_vms") or vms.get("data") or []

    buckets = {}
    for c in clients if isinstance(clients, list) else []:
        if not isinstance(c, dict):
            continue
        sid = c.get("spoke_id") or c.get("spoke") or c.get("source_spoke") or "unattributed"
        buckets.setdefault(str(sid), {"clients": [], "vms": []})["clients"].append(c)
    for v in vms if isinstance(vms, list) else []:
        if not isinstance(v, dict):
            continue
        sid = v.get("spoke_id") or v.get("spoke") or v.get("node") or "unattributed"
        buckets.setdefault(str(sid), {"clients": [], "vms": []})["vms"].append(v)
    return buckets



def build_payloads(snapshot, salt, prefix):
    """Scrub → shard → per-spoke CS_TELEMETRY bodies, keyed by synthetic id.

    A snapshot under ``_preserved`` was already built AND scrubbed by a source
    hub's ``/api/test-feed/snapshot``, which groups per spoke itself. Pass that
    grouping through rather than re-sharding — re-deriving ids here would make
    the two paths disagree about what a given spoke is called. It is still
    scrubbed once more on the way through: cheap, and it means a snapshot from
    an older source hub (or a hand-made fixture) is covered by the current
    rules rather than whatever the sender happened to apply."""
    preserved = snapshot.get("_preserved") if isinstance(snapshot, dict) else None
    if isinstance(preserved, dict) and isinstance(preserved.get("spokes"), dict):
        return {sid: scrub_snapshot(body, salt)
                for sid, body in preserved["spokes"].items()}

    scrubbed = scrub_snapshot(snapshot, salt)
    payloads = {}
    for real_sid, bucket in shard_by_spoke(scrubbed).items():
        sid = f"{prefix}{_pseudonym(real_sid, salt)}"
        payloads[sid] = {
            "clients": bucket["clients"],
            "proxmox_vms": bucket["vms"],
            "usb_devices": [],
            "vm_count": len(bucket["vms"]),
            "usb_count": 0,
        }
    return payloads


