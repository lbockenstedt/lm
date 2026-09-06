"""security/tm_client.py — Subscription Service participant client.

An install reports what its own sensors saw to the Subscription Service and
receives, in return, a decoy set to arm :mod:`security.decoy_engine` with and a
corroborated feed of attacker addresses. That exchange is what lets a
participant run honeypot routes and benefit from the network without ever
holding the private sensor code — the mechanism is public, the content is data.

**This client is the only way an install may obtain that content.** The sensor
code used to be delivered as a private git checkout, which meant every
participating install held a copy of the honeypot itself: the decoy paths, the
bait format, the detection logic. One leaked deploy key disclosed the sensor
for everyone at once, and nothing about a git pull is revocable after the fact.
Moving to a data subscription makes the disclosure per-install, attributable
and — because the credential can be revoked centrally — reversible.

The service is reached as an ordinary HTTPS API client with its own credential,
NOT as a spoke: a spoke connection is a control plane that can carry commands,
and no amount of later hardening walks back having given a third party one.

The endpoint is a constant, not configuration. A tenant chooses *whether* to
subscribe, never *where* to subscribe: an operator-supplied URL is an operator-
supplied place to send this install's sensor observations, and a typo or a
tampered config file would silently redirect the feed to a third party. There
is one exchange, so there is one address.

What leaves this process is deliberately narrow
-----------------------------------------------
Reports carry an address, a tier and a timestamp. They do **not** carry the
decoy path that was hit. The decoy set is the sensor; publishing which path
tripped tells an attacker exactly what is watched and burns the set for every
participant at once — including the ones who did not report it.

Every candidate address is filtered before it is sent (:func:`is_publishable`).
Publishing an address is asking other people to block it, so the cost of a wrong
entry is borne by the whole network: an RFC1918 address means something
different at every site, and a shared NAT or CDN egress is an outage waiting to
happen. The filter is applied on the way OUT rather than trusted to the server,
because the server cannot know which addresses are this operator's own
infrastructure.

Failure posture: every network path here is best-effort and swallows its errors.
The service being unreachable, slow or wrong must never change how the local
install handles its own traffic — the local sensors and threat monitor are the
authority for this install, and the feed is an enrichment.
"""
from __future__ import annotations

import ipaddress
import logging
import time
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import httpx

logger = logging.getLogger("Security")

# The one address of the exchange. Deliberately not read from global_config:
# see the module docstring. Tests override it per-instance, which is why the
# constructor still accepts a base_url at all.
SERVICE_URL = "https://ss.ext.lrbtechnologies.com"

# Channel names as the service registers them. An install publishes to and
# subscribes from these by name; the service decides what it is allowed to see.
CHANNEL_THREAT = "threat_monitor"
CHANNEL_SIMULATIONS = "client_simulations"
CHANNEL_DECOYS = "decoys"

# Ordered strongest-first. A single bait hit is definitive: the value is unique
# per install and has exactly one way to reach an attacker's hands. A generic
# probe is a statistic, so it is published only after it has already earned a
# local block, and consumers are expected to treat it as observation.
TIERS = ("bait_used", "extra_path", "default_decoy", "http_probe")
_TIER_RANK = {t: i for i, t in enumerate(TIERS)}

_DEFAULT_TIMEOUT = 10.0


# ── publication filter ───────────────────────────────────────────────────────

def is_publishable(ip: str,
                   never_publish: Optional[Iterable[str]] = None) -> Tuple[bool, str]:
    """Whether ``ip`` may be reported to the service.

    Returns ``(ok, reason)``; ``reason`` explains the refusal and is empty when
    publishable. Refuses anything whose meaning is not global, because a
    published address is a request for other people to block it:

    * **private / loopback / link-local / reserved** — these name a different
      machine at every site. Publishing one asks other participants to block
      their own infrastructure.
    * **carrier-grade NAT (100.64/10)** — not globally meaningful either, and
      shared by many unrelated subscribers.
    * **multicast / unspecified / broadcast** — never a source worth sharing.
    * **operator never-publish entries** — the addresses and CIDRs this operator
      knows are shared or their own: NAT and CDN egress, update mirrors, source
      forges, their own hub and spokes. A shared egress is the dangerous case,
      since blocking it takes out every unrelated tenant behind it.

    Fails CLOSED: anything unparseable is refused. A malformed address in a
    report helps nobody and could carry an injection into a consumer's blocklist.
    """
    raw = (ip or "").strip()
    if not raw:
        return False, "empty address"
    try:
        addr = ipaddress.ip_address(raw)
    except ValueError:
        return False, "unparseable address"
    if addr.is_unspecified:
        return False, "unspecified address"
    if addr.is_loopback:
        return False, "loopback"
    if addr.is_link_local:
        return False, "link-local"
    if addr.is_multicast:
        return False, "multicast"
    if addr.is_private:
        # Covers RFC1918, unique-local v6 and the other private ranges. Checked
        # after the more specific cases above so the reason stays informative.
        return False, "private address (means something different at every site)"
    if addr.is_reserved:
        return False, "reserved"
    if addr.version == 4 and addr in ipaddress.ip_network("100.64.0.0/10"):
        return False, "carrier-grade NAT (shared by unrelated subscribers)"
    for entry in (never_publish or ()):
        try:
            net = ipaddress.ip_network(str(entry).strip(), strict=False)
        except ValueError:
            continue
        if addr.version == net.version and addr in net:
            return False, f"operator never-publish entry {net}"
    return True, ""


def build_report(ip: str, tier: str, *, first_seen: Optional[float] = None,
                 count: int = 1) -> Dict[str, Any]:
    """The wire record for one observation.

    Deliberately excludes the decoy path that tripped. ``tier`` carries the
    confidence — which is the part a consumer needs — without disclosing the
    sensor that produced it.
    """
    t = tier if tier in _TIER_RANK else "http_probe"
    return {
        "ip": (ip or "").strip(),
        "tier": t,
        "first_seen": float(first_seen if first_seen is not None else time.time()),
        "count": max(1, int(count or 1)),
    }


def filter_reports(records: Sequence[Dict[str, Any]],
                   never_publish: Optional[Iterable[str]] = None
                   ) -> Tuple[List[Dict[str, Any]], List[Tuple[str, str]]]:
    """Split ``records`` into publishable and refused ``(ip, reason)``.

    Collapses duplicates by address, keeping the STRONGEST tier seen and summing
    counts: reporting one address under several tiers would let a single
    attacker inflate its own corroboration count, and the strongest signal is
    the one a consumer should act on.
    """
    keep: Dict[str, Dict[str, Any]] = {}
    refused: List[Tuple[str, str]] = []
    for rec in (records or ()):
        ip = str((rec or {}).get("ip", "")).strip()
        ok, why = is_publishable(ip, never_publish)
        if not ok:
            refused.append((ip, why))
            continue
        cur = keep.get(ip)
        if cur is None:
            keep[ip] = dict(rec)
            continue
        cur["count"] = int(cur.get("count", 1)) + int(rec.get("count", 1))
        if _TIER_RANK.get(str(rec.get("tier")), 99) < _TIER_RANK.get(str(cur.get("tier")), 99):
            cur["tier"] = rec["tier"]
        cur["first_seen"] = min(float(cur.get("first_seen", 0) or 0),
                                float(rec.get("first_seen", 0) or 0)) or cur.get("first_seen")
    return list(keep.values()), refused


# ── service client ───────────────────────────────────────────────────────────

class TMClient:
    """HTTPS client for the Subscription Service.

    Holds the participant credential and the two identifiers the service needs:
    a per-install ``install_uuid`` the credential is bound to, and a
    ``tenant_id`` used only for grouping. They are separate on purpose — one
    credential per install keeps the binding 1:1, while the tenant tag lets the
    service count independent reporters instead of mistaking one org's several
    installs for several confirmations.
    """

    def __init__(self, tenant_id: str, install_uuid: str,
                 credential: str = "", enrollment_psk: str = "",
                 never_publish: Optional[Iterable[str]] = None,
                 timeout: float = _DEFAULT_TIMEOUT,
                 verify: bool = True,
                 enabled: bool = True,
                 base_url: str = SERVICE_URL) -> None:
        # Opting in used to be expressed by leaving the service URL empty. With
        # one hardcoded endpoint there is no such thing as an unconfigured URL,
        # so the opt-in has to be stated outright: an install that has not
        # subscribed makes no outbound request at all, rather than quietly
        # contacting the exchange because a default happened to be present.
        self.enabled = bool(enabled)
        # base_url is last and defaulted because callers are not expected to
        # pass it. It exists so tests can point at a local instance; a
        # deployment that overrode it would be sending its sensor data
        # somewhere other than the exchange.
        self.base_url = (base_url or SERVICE_URL).rstrip("/")
        self.tenant_id = (tenant_id or "").strip()
        self.install_uuid = (install_uuid or "").strip()
        self.credential = (credential or "").strip()
        self.enrollment_psk = (enrollment_psk or "").strip()
        self.never_publish = list(never_publish or ())
        self.timeout = float(timeout)
        # Exposed for tests/pinning only. Never default this to False: the
        # credential is bearer material on the wire.
        self.verify = verify

    # -- plumbing ---------------------------------------------------------

    def _headers(self) -> Dict[str, str]:
        h = {"Content-Type": "application/json",
             "X-SS-Install": self.install_uuid,
             "X-SS-Tenant": self.tenant_id}
        if self.credential:
            h["Authorization"] = f"Bearer {self.credential}"
        return h

    async def _post(self, path: str, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        return await self._call("POST", path, payload)

    async def _get(self, path: str,
                   params: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        return await self._call("GET", path, None, params)

    async def _call(self, method: str, path: str,
                    payload: Optional[Dict[str, Any]] = None,
                    params: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        """One request. Returns the decoded body, or ``None`` on any failure.

        Swallows everything by design: the service is an enrichment, so an
        outage, a timeout or a malformed reply must leave this install behaving
        exactly as it would with no service configured at all.
        """
        if not self.enabled or not self.base_url:
            return None
        url = f"{self.base_url}{path}"
        try:
            async with httpx.AsyncClient(timeout=self.timeout, verify=self.verify) as c:
                r = await c.request(method, url, json=payload, params=params,
                                    headers=self._headers())
            if r.status_code >= 400:
                logger.warning("tm_client: %s %s returned %s", method, path, r.status_code)
                return None
            return r.json()
        except Exception as e:  # noqa: BLE001
            logger.warning("tm_client: %s %s failed: %s", method, path, e)
            return None

    # -- API --------------------------------------------------------------

    async def enroll(self, subscriptions: Optional[Sequence[str]] = None,
                     contact_email: str = "",
                     contact_message: str = "") -> Dict[str, Any]:
        """Register this install with the exchange.

        With an enrollment PSK the service may approve immediately; without one
        the install lands in a pending queue for manual approval. Both are
        expected outcomes — a participant that cannot safely hold a PSK is not
        thereby excluded, it just waits for a human.

        ``contact_email`` and ``contact_message`` are how an unvouched install
        introduces itself, since approval is a person deciding whether to admit
        a stranger. They are ignored when a PSK is presented.

        Returns ``{"status": "approved"|"pending"|"denied"|"error", ...}``. On
        approval the credential is stored on the instance; the CALLER is
        responsible for persisting it, since this module owns no storage.
        """
        body = await self._post("/v1/enroll", {
            "tenant_id": self.tenant_id,
            "install_uuid": self.install_uuid,
            "psk": self.enrollment_psk or None,
            "kind": "hub",
            "contact_email": contact_email or "",
            "contact_message": contact_message or "",
            "subscriptions": list(subscriptions or ()),
        })
        if not body:
            return {"status": "error", "reason": "service unreachable"}
        status = str(body.get("status") or "").lower()
        cred = str(body.get("credential") or "").strip()
        if status == "approved" and cred:
            self.credential = cred
        return body

    async def request_subscription(self, channel: str,
                                   mode: str = "subscribe") -> Dict[str, Any]:
        """Ask for a feed after enrolment, as modules are turned on.

        Enrolment does not have to know every channel an install will ever
        want; a tenant enabling the threat or simulation database later says so
        here rather than re-enrolling, which would mean a second credential for
        the same install.
        """
        body = await self._post("/v1/subscriptions",
                                {"channel": channel, "mode": mode})
        if body is None:
            return {"status": "error", "channel": channel}
        return body

    async def report(self, records: Sequence[Dict[str, Any]],
                     channel: str = CHANNEL_THREAT) -> Dict[str, Any]:
        """Publish observations, after filtering.

        The filter runs here rather than server-side because only this install
        knows which addresses are its operator's own infrastructure. Refusals
        are logged, not silently dropped — an operator whose never-publish list
        is too broad should be able to see that they are contributing nothing.

        The service re-validates everything published; this filter is not a
        substitute for that, it is the part the service cannot do.
        """
        keep, refused = filter_reports(records, self.never_publish)
        if refused:
            logger.info("tm_client: withheld %d record(s) from publication (%s)",
                        len(refused),
                        "; ".join(f"{ip}: {why}" for ip, why in refused[:5]))
        if not keep:
            return {"status": "SKIPPED", "published": 0, "withheld": len(refused)}
        body = await self._post(f"/v1/publish/{channel}", {"records": keep})
        if body is None:
            return {"status": "ERROR", "published": 0, "withheld": len(refused)}
        # The service reports what it actually stored. Trusting the local count
        # would hide a channel that is silently rejecting everything sent.
        return {"status": "SUCCESS",
                "published": int(body.get("accepted", 0)),
                "rejected": int(body.get("rejected", 0)),
                "withheld": len(refused), "response": body}

    async def fetch_decoys(self) -> Optional[List[Dict[str, Any]]]:
        """The decoy set to arm the local engine with.

        Served as a subscription channel like any other, so the pool stays with
        the exchange and this install only ever holds the subset it was given.
        Each participant receives a different subset drawn from its own install
        id: if one install's set surfaces publicly the leak is attributable and
        it discloses nothing about what anyone else is watching.

        Returns ``None`` when unavailable, which the caller must distinguish
        from an empty list: ``None`` means "keep the current set" (a fetch
        failure must not disarm a working sensor), while ``[]`` is a deliberate
        instruction to stand down.
        """
        body = await self._get(f"/v1/feed/{CHANNEL_DECOYS}")
        if body is None:
            return None
        records = body.get("records")
        return list(records) if isinstance(records, list) else []

    async def fetch_feed(self, since: Optional[float] = None,
                         channel: str = CHANNEL_THREAT
                         ) -> Optional[List[Dict[str, Any]]]:
        """Corroborated attacker records from the network.

        Each record carries a corroboration count rather than the identities of
        the reporters, so a consumer gets the confidence signal without learning
        who else participates or what they are being hit by.
        """
        body = await self._get(f"/v1/feed/{channel}",
                               {"since": since} if since else None)
        if body is None:
            return None
        records = body.get("records")
        return list(records) if isinstance(records, list) else []
