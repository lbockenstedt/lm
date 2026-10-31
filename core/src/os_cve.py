"""CVE lookup for the OS-updates panel: "who is affected by CVE-XXXX-YYYY?".

Nodes report their installed packages with each OS-update check
(``os_update.installed_packages``) and the hub keeps that inventory. A search
matches it against Debian's security-tracker feed for each node's release —
the same per-release feed and matching rules ``debsecan`` uses:
https://security-tracker.debian.org/tracker/debsecan/release/1/<codename>

One feed per release (~2 MB compressed) is fetched by the hub and cached,
rather than every node downloading it. The feed is only indexed by CVE and
package at load time; entries are parsed when a search touches them, which
keeps a release's feed to tens of MB in memory instead of hundreds.

Proxmox hosts are Debian underneath, so their Debian packages are covered; the
``pve-*``/``proxmox-*`` packages are not in Debian's tracker and never match.
"""
from __future__ import annotations

import logging
import os
import re
import time
import urllib.request
import zlib
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("OsCve")

FEED_URL = "https://security-tracker.debian.org/tracker/debsecan/release/1/{codename}"
FEED_MAX_AGE_S = 12 * 3600
FEED_TIMEOUT_S = 60

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
_URGENCY = {"L": "low", "M": "medium", "H": "high"}


# ── Debian version comparison (dpkg's verrevcmp) ─────────────────────────────
def _order(c: str) -> int:
    if not c or c.isdigit():
        return 0
    if c.isascii() and c.isalpha():
        return ord(c)
    if c == "~":
        return -1
    return ord(c) + 256


def _compare_part(a: str, b: str) -> int:
    i = j = 0
    while i < len(a) or j < len(b):
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _order(a[i] if i < len(a) else "")
            bc = _order(b[j] if j < len(b) else "")
            if ac != bc:
                return ac - bc
            i += 1
            j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        first_diff = 0
        while i < len(a) and j < len(b) and a[i].isdigit() and b[j].isdigit():
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first_diff:
            return first_diff
    return 0


def _split_version(v: str) -> Tuple[int, str, str]:
    epoch = 0
    if ":" in v:
        e, v = v.split(":", 1)
        epoch = int(e) if e.isdigit() else 0
    upstream, _, revision = v.rpartition("-")
    if not upstream:
        upstream, revision = revision, ""
    return epoch, upstream, revision


def version_compare(a: str, b: str) -> int:
    """<0, 0 or >0 as Debian version ``a`` sorts before, equal to or after ``b``."""
    ea, ua, ra = _split_version(a)
    eb, ub, rb = _split_version(b)
    if ea != eb:
        return ea - eb
    return _compare_part(ua, ub) or _compare_part(ra, rb)


# ── feed ─────────────────────────────────────────────────────────────────────
class Feed:
    """One release's debsecan feed, indexed by CVE and by package.

    Feed layout: ``VERSION 1``, then ``cve,flags,description`` lines, a blank
    line, then ``package,cve_index,flags,fixed_version,other_versions`` lines.
    Flags are: B = entry names a binary (not source) package; urgency
    L/M/H; R = remotely exploitable (? = unknown); F = a fix exists for this
    release."""

    def __init__(self, raw: bytes):
        lines = zlib.decompress(raw).decode("utf-8", "replace").split("\n")
        if not lines or lines[0] != "VERSION 1":
            raise ValueError("unknown debsecan feed format")
        pos = 1
        self.cves: List[str] = []
        self.descriptions: Dict[str, str] = {}
        while pos < len(lines) and lines[pos]:
            name, _flags, desc = lines[pos].split(",", 2)
            self.cves.append(name)
            self.descriptions[name] = desc
            pos += 1
        pos += 1
        self.by_cve: Dict[str, List[str]] = {}
        self.by_package: Dict[str, List[str]] = {}
        while pos < len(lines) and lines[pos]:
            line = lines[pos]
            package, vnum, _rest = line.split(",", 2)
            self.by_cve.setdefault(self.cves[int(vnum)], []).append(line)
            self.by_package.setdefault(package, []).append(line)
            pos += 1

    def entry(self, line: str) -> Dict[str, Any]:
        package, vnum, flags, fixed, other = line.split(",", 4)
        flags = flags.ljust(4)
        return {
            "package": package,
            "cve": self.cves[int(vnum)],
            "binary": flags[0] == "B",
            "urgency": _URGENCY.get(flags[1], ""),
            "remote": {"R": True, " ": False}.get(flags[2]),
            "fix_available": flags[3] == "F",
            "fixed": fixed,
            "other": other.split(),
        }


def is_vulnerable(entry: Dict[str, Any], name: str, version: str,
                  source: str, source_version: str) -> bool:
    """debsecan's Vulnerability.is_vulnerable for one installed binary package."""
    if entry["binary"] and name == entry["package"]:
        return not entry["fixed"] or version_compare(version, entry["fixed"]) < 0
    if source != entry["package"]:
        return False
    if any(version_compare(source_version, o) == 0 for o in entry["other"]):
        return False
    return not entry["fixed"] or version_compare(source_version, entry["fixed"]) < 0


def match_node(feed: Feed, installed: List[List[str]], entries: List[Dict[str, Any]],
               pending: Optional[List[str]] = None) -> Dict[str, List[Dict[str, Any]]]:
    """Check one node's installed packages against chosen feed entries.

    ``installed`` rows are ``[package, version]`` or ``[package, version,
    source, source_version]``. Like debsecan, a binary package is looked up
    under its source package when the feed knows that source, else under its
    own name. Returns ``{"affected": [...], "patched": [...]}``, one item per
    (CVE, feed package): the node has the package and is / is not vulnerable.
    """
    pending_set = set(pending or [])
    wanted = {e["package"] for e in entries}
    by_pkg: Dict[str, List[Tuple[str, str, str, str]]] = {}
    for row in installed:
        if len(row) < 2:
            continue
        name, version = row[0], row[1]
        source = row[2] if len(row) > 2 and row[2] else name
        source_version = row[3] if len(row) > 3 and row[3] else version
        key = source if source in feed.by_package else name
        if key in wanted:
            by_pkg.setdefault(key, []).append((name, version, source, source_version))
    out: Dict[str, List[Dict[str, Any]]] = {"affected": [], "patched": []}
    for e in entries:
        rows = by_pkg.get(e["package"])
        if not rows:
            continue
        hit = [r for r in rows if is_vulnerable(e, *r)]
        binaries = sorted({r[0] for r in (hit or rows)})
        out["affected" if hit else "patched"].append({
            "cve": e["cve"], "package": e["package"],
            "version": (hit or rows)[0][3],
            "binaries": binaries,
            "urgency": e["urgency"], "remote": e["remote"],
            "fix_available": e["fix_available"],
            "update_pending": bool(hit) and any(b in pending_set for b in binaries),
        })
    return out


class FeedCache:
    """Per-release feeds, cached in memory and on disk, refreshed every 12 h.

    A failed download keeps serving the last good copy — a tracker outage
    should age the data, not blank the lookup."""

    def __init__(self, cache_dir: Optional[str] = None):
        self.cache_dir = cache_dir
        self._feeds: Dict[str, Tuple[float, Feed]] = {}
        self.errors: Dict[str, str] = {}

    def _path(self, codename: str) -> Optional[str]:
        if not self.cache_dir:
            return None
        return os.path.join(self.cache_dir, f"cve_feed_{codename}.zlib")

    def _download(self, codename: str) -> bytes:
        req = urllib.request.Request(FEED_URL.format(codename=codename),
                                     headers={"User-Agent": "lm-os-updates"})
        with urllib.request.urlopen(req, timeout=FEED_TIMEOUT_S) as r:
            return r.read()

    def _load_file(self, path: str) -> Optional[Tuple[float, Feed]]:
        try:
            with open(path, "rb") as f:
                return os.path.getmtime(path), Feed(f.read())
        except Exception as exc:  # noqa: BLE001 — a bad cache file is just re-downloaded
            logger.warning("cve: cached feed %s unreadable: %s", path, exc)
            return None

    def get(self, codename: str) -> Optional[Feed]:
        """The release's feed, or None if it was never obtained. Blocking."""
        if not codename or not codename.isalnum():
            return None
        now = time.time()
        cached = self._feeds.get(codename)
        path = self._path(codename)
        if cached is None and path and os.path.exists(path):
            cached = self._load_file(path)
            if cached:
                self._feeds[codename] = cached
        if cached and now - cached[0] < FEED_MAX_AGE_S:
            return cached[1]
        try:
            raw = self._download(codename)
            feed = Feed(raw)
        except Exception as exc:  # noqa: BLE001
            self.errors[codename] = f"{type(exc).__name__}: {exc}"
            logger.warning("cve: feed for %s unavailable: %s", codename, exc)
            return cached[1] if cached else None
        if path:
            try:
                tmp = path + ".tmp"
                with open(tmp, "wb") as f:
                    f.write(raw)
                os.replace(tmp, path)
            except OSError as exc:
                logger.warning("cve: could not cache feed %s: %s", path, exc)
        self._feeds[codename] = (now, feed)
        self.errors.pop(codename, None)
        return feed

    def fetched_at(self, codename: str) -> float:
        cached = self._feeds.get(codename)
        return cached[0] if cached else 0.0
