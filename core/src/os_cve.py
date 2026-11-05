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

# logging for diagnostics; os for cache file paths; re validates CVE ids.
import logging
import os
import re
# time stamps feed freshness; urllib downloads feeds; zlib decompresses them.
import time
import urllib.request
import zlib
# Type hints only.
from typing import Any, Dict, List, Optional, Tuple

# Named logger for CVE lookup messages.
logger = logging.getLogger("OsCve")

# Per-release feed URL, refresh age (12 h), and download timeout.
FEED_URL = "https://security-tracker.debian.org/tracker/debsecan/release/1/{codename}"
FEED_MAX_AGE_S = 12 * 3600
FEED_TIMEOUT_S = 60

# Valid CVE id shape, and feed urgency letter -> label.
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
_URGENCY = {"L": "low", "M": "medium", "H": "high"}


# ── Debian version comparison (dpkg's verrevcmp) ─────────────────────────────
def _order(c: str) -> int:
    """Return dpkg's sort weight for one non-digit character.

    Digits and the end of string weigh 0, letters their code, "~" sorts before everything,
    and other characters sort after letters.
    """
    # End of string or a digit: neutral.
    if not c or c.isdigit():
        return 0
    # ASCII letters sort by character code.
    if c.isascii() and c.isalpha():
        return ord(c)
    # Tilde sorts before even the end of string.
    if c == "~":
        return -1
    # Everything else sorts after all letters.
    return ord(c) + 256


def _compare_part(a: str, b: str) -> int:
    """Compare two upstream or revision strings the way dpkg does (verrevcmp).

    Returns <0, 0 or >0. Alternates between non-digit runs (by _order) and digit runs (numeric).
    """
    # Walk both strings in step.
    i = j = 0
    while i < len(a) or j < len(b):
        # Non-digit run: compare character weights one by one.
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _order(a[i] if i < len(a) else "")
            bc = _order(b[j] if j < len(b) else "")
            if ac != bc:
                return ac - bc
            i += 1
            j += 1
        # Digit run: skip leading zeros.
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        # Compare equal-length digits, remembering the first difference.
        first_diff = 0
        while i < len(a) and j < len(b) and a[i].isdigit() and b[j].isdigit():
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        # A longer digit run is the larger number.
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        # Same length: the first differing digit decides.
        if first_diff:
            return first_diff
    return 0


def _split_version(v: str) -> Tuple[int, str, str]:
    """Split a Debian version into (epoch, upstream, revision).

    A missing epoch is 0 and a missing revision is "".
    """
    # Optional "epoch:" prefix; a non-numeric epoch counts as 0.
    epoch = 0
    if ":" in v:
        e, v = v.split(":", 1)
        epoch = int(e) if e.isdigit() else 0
    # Revision is after the last "-"; with no "-" the whole thing is upstream.
    upstream, _, revision = v.rpartition("-")
    if not upstream:
        upstream, revision = revision, ""
    return epoch, upstream, revision


def version_compare(a: str, b: str) -> int:
    """<0, 0 or >0 as Debian version ``a`` sorts before, equal to or after ``b``."""
    # Epoch decides first, then upstream, then revision.
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
        """Parse a zlib-compressed feed and index its lines by CVE and by package.

        Raises ValueError for an unknown feed format.
        """
        # Decompress and split into lines; check the format header.
        lines = zlib.decompress(raw).decode("utf-8", "replace").split("\n")
        if not lines or lines[0] != "VERSION 1":
            raise ValueError("unknown debsecan feed format")
        # First section: one line per CVE, in index order.
        pos = 1
        self.cves: List[str] = []
        self.descriptions: Dict[str, str] = {}
        while pos < len(lines) and lines[pos]:
            name, _flags, desc = lines[pos].split(",", 2)
            self.cves.append(name)
            self.descriptions[name] = desc
            pos += 1
        # Skip the blank separator line.
        pos += 1
        # Second section: index raw package lines by CVE and by package, unparsed.
        self.by_cve: Dict[str, List[str]] = {}
        self.by_package: Dict[str, List[str]] = {}
        while pos < len(lines) and lines[pos]:
            line = lines[pos]
            package, vnum, _rest = line.split(",", 2)
            self.by_cve.setdefault(self.cves[int(vnum)], []).append(line)
            self.by_package.setdefault(package, []).append(line)
            pos += 1

    def entry(self, line: str) -> Dict[str, Any]:
        """Parse one raw package line into an entry dict (package, cve, flags, fixed versions)."""
        # Split the five fields; pad flags so missing ones read as blanks.
        package, vnum, flags, fixed, other = line.split(",", 4)
        flags = flags.ljust(4)
        # Map flag letters to named fields.
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
    # Binary-package entry for this exact package: vulnerable if older than the fix.
    if entry["binary"] and name == entry["package"]:
        return not entry["fixed"] or version_compare(version, entry["fixed"]) < 0
    # Otherwise the entry must name this package's source.
    if source != entry["package"]:
        return False
    # A version listed as unaffected is not vulnerable.
    if any(version_compare(source_version, o) == 0 for o in entry["other"]):
        return False
    # Vulnerable if there is no fix yet or the source is older than it.
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
    # Packages with an update pending, and the feed packages being searched.
    pending_set = set(pending or [])
    wanted = {e["package"] for e in entries}
    # feed package -> installed rows that map to it.
    by_pkg: Dict[str, List[Tuple[str, str, str, str]]] = {}
    # Map each installed row to its source or own name.
    for row in installed:
        if len(row) < 2:
            continue
        # Fill in source and source version when the row omits them.
        name, version = row[0], row[1]
        source = row[2] if len(row) > 2 and row[2] else name
        source_version = row[3] if len(row) > 3 and row[3] else version
        # Prefer the source name when the feed knows it.
        key = source if source in feed.by_package else name
        if key in wanted:
            by_pkg.setdefault(key, []).append((name, version, source, source_version))
    # Classify each entry as affected or patched for this node.
    out: Dict[str, List[Dict[str, Any]]] = {"affected": [], "patched": []}
    for e in entries:
        rows = by_pkg.get(e["package"])
        if not rows:
            continue
        # Which installed rows are vulnerable; report those binaries (or all if none).
        hit = [r for r in rows if is_vulnerable(e, *r)]
        binaries = sorted({r[0] for r in (hit or rows)})
        # One result row per (CVE, package).
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
        """Create an empty cache; cache_dir (optional) is where feeds are stored on disk."""
        # Disk location, codename -> (fetched time, Feed), and last error per codename.
        self.cache_dir = cache_dir
        self._feeds: Dict[str, Tuple[float, Feed]] = {}
        self.errors: Dict[str, str] = {}

    def _path(self, codename: str) -> Optional[str]:
        """Return the on-disk cache path for a release's feed, or None without a cache dir."""
        # No cache dir: memory only.
        if not self.cache_dir:
            return None
        return os.path.join(self.cache_dir, f"cve_feed_{codename}.zlib")

    def _download(self, codename: str) -> bytes:
        """Download the raw (compressed) feed bytes for a release. Blocking."""
        # GET the release's feed with an identifying User-Agent.
        req = urllib.request.Request(FEED_URL.format(codename=codename),
                                     headers={"User-Agent": "lm-os-updates"})
        with urllib.request.urlopen(req, timeout=FEED_TIMEOUT_S) as r:
            return r.read()

    def _load_file(self, path: str) -> Optional[Tuple[float, Feed]]:
        """Load a cached feed file as (mtime, Feed), or None if it is unreadable."""
        # Parse the file; any error is logged and treated as no cache.
        try:
            with open(path, "rb") as f:
                return os.path.getmtime(path), Feed(f.read())
        except Exception as exc:  # noqa: BLE001 — a bad cache file is just re-downloaded
            logger.warning("cve: cached feed %s unreadable: %s", path, exc)
            return None

    def get(self, codename: str) -> Optional[Feed]:
        """The release's feed, or None if it was never obtained. Blocking."""
        # Codename must be a plain alphanumeric word (it goes into a URL and file name).
        if not codename or not codename.isalnum():
            return None
        # Current time, the in-memory copy, and the disk path.
        now = time.time()
        cached = self._feeds.get(codename)
        path = self._path(codename)
        # On first use, load the disk copy into memory.
        if cached is None and path and os.path.exists(path):
            cached = self._load_file(path)
            if cached:
                self._feeds[codename] = cached
        # Fresh enough: use it.
        if cached and now - cached[0] < FEED_MAX_AGE_S:
            return cached[1]
        # Download and parse a new copy; on failure keep serving the old one.
        try:
            raw = self._download(codename)
            feed = Feed(raw)
        except Exception as exc:  # noqa: BLE001
            self.errors[codename] = f"{type(exc).__name__}: {exc}"
            logger.warning("cve: feed for %s unavailable: %s", codename, exc)
            return cached[1] if cached else None
        # Write the new copy to disk atomically; disk errors only warn.
        if path:
            try:
                tmp = path + ".tmp"
                with open(tmp, "wb") as f:
                    f.write(raw)
                os.replace(tmp, path)
            except OSError as exc:
                logger.warning("cve: could not cache feed %s: %s", path, exc)
        # Remember the new copy and clear any error.
        self._feeds[codename] = (now, feed)
        self.errors.pop(codename, None)
        return feed

    def fetched_at(self, codename: str) -> float:
        """Return when the release's feed was fetched (epoch seconds), or 0.0 if never."""
        # Timestamp of the cached copy, if any.
        cached = self._feeds.get(codename)
        return cached[0] if cached else 0.0
