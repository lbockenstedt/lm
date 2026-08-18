"""Read-only scraper for the Hurricane Electric (dns.he.net) web control panel.

HE's dyndns update API (``dyn.dns.he.net/nic/update``) is push-only — it cannot
*list* the records in a zone, so the HE.NET module only ever knew about records
it created itself. To bring records that already exist in a zone (added directly
in the dns.he.net UI, or by another tool) under management, we log into the
**web panel** with the HE account credentials and read the zone's record table —
exactly the same account login the certificate module already uses for HE
DNS-01. Nothing here writes to HE; it only enumerates existing records so the
hub can hand them to the henet spoke to merge into its managed set.

Runs on the HUB (the henet spoke may have no outbound path to dns.he.net, while
the hub — which resolves the vault credential — does). ``fetch`` is injectable
so unit tests drive the scraper against captured HTML without any network.

The panel's HTML contract (stable for years; see the dns-lexicon henet provider):
  * login   — POST ``/`` with ``{email, pass}``; a failed login still renders
              the login form (``<input name="email">``).
  * zones   — GET ``/`` → one ``<img alt="delete" name="<domain>" value="<id>">``
              per hosted zone (name = domain, value = numeric zone id).
  * records — GET ``/?hosted_dns_zoneid=<id>&menu=edit_zone&hosted_dns_editzone``
              → ``<tr class="dns_tr...">`` rows whose ``<td>`` cells are, in
              order: zone-id, record-id, name, type (a ``<span class="rrlabel">``
              carrying ``data="A"``), ttl, priority, value (``data="1.2.3.4"``),
              is-dynamic (``0``/``1``).
"""
from __future__ import annotations

import html
import http.cookiejar
import logging
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("HENetScrape")

BASE_URL = "https://dns.he.net/"
# HE's dyndns endpoint only updates A/AAAA, so those are the only record types
# the henet module can actually manage — the scraper surfaces the rest as a
# skipped-count so the operator knows why a CNAME/MX/TXT wasn't imported.
MANAGEABLE_TYPES = ("A", "AAAA")

# A fetcher takes (method, url, data|None) and returns (status, body_text),
# transparently carrying cookies across calls.
Fetch = Callable[[str, str, Optional[Dict[str, str]]], Tuple[int, str]]


class _ZoneListParser(HTMLParser):
    """Collect ``<img alt="delete" name=<domain> value=<zone_id>>`` — one per
    hosted zone on the account home page."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.zones: List[Dict[str, str]] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        if tag != "img":
            return
        a = {k: (v or "") for k, v in attrs}
        if a.get("alt", "").lower() != "delete":
            return
        name = a.get("name", "").strip().rstrip(".")
        value = a.get("value", "").strip()
        if name and value:
            self.zones.append({"name": name, "zone_id": value})


class _RecordTableParser(HTMLParser):
    """Walk ``<tr class="dns_tr...">`` rows in the edit-zone page and emit one
    record dict per row: ``{name, type, value, ttl, is_dynamic}``."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.records: List[Dict[str, Any]] = []
        self._in_row = False
        self._in_td = False
        self._cells: List[Dict[str, Any]] = []
        self._cur_data: Optional[str] = None
        self._text: List[str] = []
        self._rtype: Optional[str] = None

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        a = {k: (v or "") for k, v in attrs}
        if tag == "tr":
            cls = a.get("class", "")
            if "dns_tr" in cls:
                self._in_row = True
                self._cells = []
                self._rtype = None
            return
        if not self._in_row:
            return
        if tag == "td":
            self._in_td = True
            self._cur_data = a.get("data")
            self._text = []
        elif tag == "span" and "rrlabel" in a.get("class", ""):
            # The type lives in the rrlabel span's ``data`` attr (e.g. data="A").
            self._rtype = (a.get("data") or a.get("alt") or "").strip() or self._rtype

    def handle_data(self, data: str) -> None:
        if self._in_td:
            self._text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "td" and self._in_row:
            self._cells.append({"data": self._cur_data,
                                "text": "".join(self._text).strip()})
            self._in_td = False
            self._cur_data = None
            self._text = []
        elif tag == "tr" and self._in_row:
            self._finish_row()
            self._in_row = False

    def _finish_row(self) -> None:
        cells = self._cells
        # Columns: 0 zone-id, 1 rec-id, 2 name, 3 type, 4 ttl, 5 priority,
        # 6 value, 7 is-dynamic. A malformed/short row is skipped rather than
        # raising — this is best-effort enumeration of a live third-party page.
        if len(cells) < 7:
            return
        name = html.unescape(cells[2]["text"]).strip().rstrip(".")
        rtype = (self._rtype or html.unescape(cells[3]["text"])).strip().upper()
        # The value's full form is in the cell's ``data`` attr (text may be
        # truncated for long records); fall back to the visible text.
        vcell = cells[6]
        value = html.unescape((vcell.get("data") or vcell.get("text") or "")).strip()
        ttl = cells[4]["text"].strip()
        is_dynamic = len(cells) > 7 and cells[7]["text"].strip() == "1"
        try:
            ttl_i = int(ttl)
        except (TypeError, ValueError):
            ttl_i = 300
        if not name or not rtype or not value:
            return
        self.records.append({"name": name, "type": rtype, "value": value,
                             "ttl": ttl_i, "is_dynamic": is_dynamic})


class HENetScraper:
    """Log into dns.he.net and enumerate a zone's existing records (read-only)."""

    def __init__(self, fetch: Optional[Fetch] = None, timeout: float = 20.0):
        self.timeout = timeout
        if fetch is not None:
            self._fetch = fetch
        else:
            cj = http.cookiejar.CookieJar()
            self._opener = urllib.request.build_opener(
                urllib.request.HTTPCookieProcessor(cj))
            self._fetch = self._default_fetch

    def _default_fetch(self, method: str, url: str,
                       data: Optional[Dict[str, str]] = None) -> Tuple[int, str]:
        body = urllib.parse.urlencode(data).encode("utf-8") if data else None
        req = urllib.request.Request(url, data=body, method=method,
                                     headers={"User-Agent": "lm-henet/1.0"})
        with self._opener.open(req, timeout=self.timeout) as resp:  # noqa: S310 — fixed HE endpoint
            status = getattr(resp, "status", 200) or 200
            return status, resp.read().decode("utf-8", "replace")

    # ── steps ─────────────────────────────────────────────────────────

    def login(self, username: str, password: str) -> bool:
        """Authenticate the session. Returns True on success. A failed login
        re-renders the login form, so the presence of ``name="email"`` in the
        POST response is treated as failure (also covers 2FA-blocked accounts,
        which never reach the record table)."""
        self._fetch("GET", BASE_URL, None)  # seed the session cookie
        _status, body = self._fetch("POST", BASE_URL,
                                    {"email": username or "", "pass": password or ""})
        low = body.lower()
        if 'name="email"' in low and 'name="pass"' in low:
            return False
        return True

    def list_zones(self) -> List[Dict[str, str]]:
        _status, body = self._fetch("GET", BASE_URL, None)
        p = _ZoneListParser()
        p.feed(body)
        return p.zones

    def list_zone_records(self, zone_id: str) -> List[Dict[str, Any]]:
        url = (f"{BASE_URL}?hosted_dns_zoneid={urllib.parse.quote(str(zone_id))}"
               "&menu=edit_zone&hosted_dns_editzone")
        _status, body = self._fetch("GET", url, None)
        p = _RecordTableParser()
        p.feed(body)
        return p.records

    # ── orchestration ─────────────────────────────────────────────────

    def import_all(self, username: str, password: str,
                   zone_filter: Optional[str] = None) -> Dict[str, Any]:
        """Log in and enumerate every A/AAAA record across the account's zones
        (optionally restricted to ``zone_filter``, a domain name).

        Returns ``{status, records:[...], zones:[...], skipped_types:{TYPE:n}}``
        on success, or ``{status:"ERROR", message}``. ``records`` are the
        manageable (A/AAAA) records only; ``skipped_types`` tallies the
        non-A/AAAA records that HE's dyndns API cannot manage."""
        if not username or not password:
            return {"status": "ERROR",
                    "message": "HE.NET account login (email + password) is required "
                               "to read existing zone records"}
        try:
            if not self.login(username, password):
                return {"status": "ERROR",
                        "message": "HE.NET login failed — check the account email/"
                                   "password in the Credential Vault (2-factor auth "
                                   "must be disabled for the web panel)"}
        except Exception as exc:  # noqa: BLE001 — network/transport
            logger.warning("henet scrape: login request failed: %s", exc)
            return {"status": "ERROR", "message": f"could not reach dns.he.net: {exc}"}

        try:
            zones = self.list_zones()
        except Exception as exc:  # noqa: BLE001
            logger.warning("henet scrape: zone list failed: %s", exc)
            return {"status": "ERROR", "message": f"could not list HE.NET zones: {exc}"}

        want = (zone_filter or "").strip().rstrip(".").lower() or None
        if want:
            zones = [z for z in zones if z["name"].lower() == want]
        if not zones:
            return {"status": "ERROR",
                    "message": ("no matching HE.NET zone found on the account"
                                if want else
                                "no HE.NET zones found on the account (is 2-factor "
                                "auth enabled, or the account empty?)")}

        records: List[Dict[str, Any]] = []
        skipped: Dict[str, int] = {}
        for z in zones:
            try:
                rows = self.list_zone_records(z["zone_id"])
            except Exception as exc:  # noqa: BLE001 — per-zone, keep going
                logger.warning("henet scrape: records for %s failed: %s", z["name"], exc)
                continue
            for r in rows:
                if r["type"] in MANAGEABLE_TYPES:
                    records.append({**r, "zone": z["name"]})
                else:
                    skipped[r["type"]] = skipped.get(r["type"], 0) + 1
        return {"status": "SUCCESS", "records": records, "zones": zones,
                "skipped_types": skipped}
