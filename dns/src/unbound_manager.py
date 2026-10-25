"""Unbound DNS daemon manager.

Twin of lbockenstedt/dns (src/unbound_manager.py). Synchronized with PR #56
for multi-line forwarder block parsing, atomic merge/rollback, and diagnostics.
"""
import subprocess
import logging
import os
import re
import shutil
import ipaddress
import socket
import struct
import time
from collections import deque

logger = logging.getLogger("UnboundManager")

LM_CONF = "/etc/unbound/conf.d/lm-netbox.conf"
UNBOUND_CONF_DIR = "/etc/unbound/conf.d"
LOGGING_CONF = "/etc/unbound/conf.d/lm-logging.conf"
# Unbound's main config. We never edit it in place; we only read it to learn
# which directory it actually parses, and bridge our own dir into that.
MAIN_CONF = "/etc/unbound/unbound.conf"
# Name of the one-line bridge file we drop into the distro's included dir.
BRIDGE_CONF_NAME = "lm-include.conf"
QUERY_LOG = "/var/log/unbound/lm-queries.log"


def worker_code_version() -> dict:
    """Best-effort ``{commit, commit_time, dirty}`` for the running worker's
    own checkout — mirrors ``kea_manager.worker_code_version`` so operators
    can tell "still running old code" apart from "the fix is deployed but
    the failure is real" without separate manual git access to the host,
    since this worker's only code-update path is re-running the installer."""
    repo_root = os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))))
    out = {"commit": "", "commit_time": "", "dirty": None}
    if not shutil.which("git") or not os.path.isdir(os.path.join(repo_root, ".git")):
        return out
    try:
        commit = subprocess.run(
            ["git", "-C", repo_root, "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=10)
        if commit.returncode == 0:
            out["commit"] = commit.stdout.strip()
        ctime = subprocess.run(
            ["git", "-C", repo_root, "log", "-1", "--format=%cI"],
            capture_output=True, text=True, timeout=10)
        if ctime.returncode == 0:
            out["commit_time"] = ctime.stdout.strip()
        dirty = subprocess.run(
            ["git", "-C", repo_root, "status", "--porcelain"],
            capture_output=True, text=True, timeout=10)
        if dirty.returncode == 0:
            out["dirty"] = bool(dirty.stdout.strip())
    except Exception:  # noqa: BLE001 — best-effort only
        pass
    return out

# unbound-control's stats_noreset is aggregate-only (per-type/rcode/etc.) and
# cannot report counts per queried NAME. The only way to get that is Unbound's
# own query log (`log-queries: yes`), tailed incrementally. Cap the number of
# distinct names tracked in memory so a noisy/adversarial resolver can't grow
# this unbounded; once the cap is hit, stop accepting brand-new names until the
# next reset (an operator can always bump/relax this via get_stats(reset=True)
# or a service restart) rather than silently evicting existing counts.
MAX_TRACKED_NAMES = 5000
# The API response itself is further truncated to the top-N by count so large
# trees don't get shipped to the WebUI on every poll; the in-memory table
# still holds up to MAX_TRACKED_NAMES for search to work against.
TOP_NAMES_LIMIT = 200
# Timestamped per-query events retained for the per-client ("Pi-hole style")
# query log, independent of the per-name counters above.
MAX_QUERY_EVENTS = 200000
CLIENT_QUERY_LIMIT = 1000

# WebUI day/week/month selector for the "Queries by Destination" breakdown.
# Counts are kept in per-day buckets (see _query_counts) so a window can be
# summed on read; MAX_RETENTION_DAYS caps how much history is kept at all —
# once a bucket is older than that it is pruned regardless of which window
# is currently selected.
RANGE_DAYS = {"day": 1, "week": 7, "month": 30}
MAX_RETENTION_DAYS = 30

_QUERY_LOG_RE = re.compile(
    r"info:\s+(?P<ip>[0-9a-fA-F.:]+)\s+(?P<name>\S+?)\.?\s+(?P<type>\w+)\s+IN\s*$"
)


class UnboundManager:
    def __init__(self, conf_path: str = LM_CONF):
        self.conf_path = conf_path
        self.forwarders_path = os.path.join(
            os.path.dirname(self.conf_path), "lm-forwarders.conf")
        self.overrides_path = os.path.join(
            os.path.dirname(self.conf_path), "lm-overrides.conf")
        os.makedirs(os.path.dirname(self.conf_path), exist_ok=True)
        self._ensure_conf_included()
        # mtime-keyed memo for list_records(): status/add/update/delete all
        # call list_records (some indirectly via sync), and each call re-reads
        # + regex-parses the whole conf. Cache the parsed list keyed on the
        # conf's st_mtime so it's reused until the file changes; sync() writes
        # the file and clears the memo so the next read re-parses.
        self._records_cache = None      # list
        self._records_cache_mtime = None  # float | None

        # Per-(name,type,source-ip) query counters fed by _tail_query_log().
        # Keyed by "name|TYPE|source_ip" -> count so the per-destination
        # breakdown can also report WHICH client(s) asked for it (needed for
        # per-tenant filtering upstream, keyed on the source IP's subnet).
        # self._query_log_offset is the byte offset we last read up to, so
        # repeated get_stats() polls only parse newly appended lines instead
        # of re-reading the whole log each time. Counts are bucketed by
        # calendar day ({day_epoch: count}) so the day/week/month window and
        # the MAX_RETENTION_DAYS drop are possible; _day_buckets() also
        # accepts a legacy bare-int count (pre-bucketing format).
        self._query_counts = {}       # "name|TYPE|source_ip" -> {day: int}
        self._query_log_offset = 0
        self._query_log_inode = None
        # (epoch, client_ip, name, type), oldest first — feeds the per-client
        # ("Pi-hole style") query log, which needs individual timestamped
        # events rather than the aggregate counters above.
        self._query_events = deque(maxlen=MAX_QUERY_EVENTS)
        # Set after a successful restart/AppArmor apply in this process so a
        # host whose logfile never appears is not restarted on every sync.
        self._logging_restarted = False
        self._apparmor_applied = False

    def _ensure_conf_included(self) -> dict:
        """Guarantee Unbound actually PARSES the directory we write into.

        We write every managed file (records, forwarders, query logging) to
        ``/etc/unbound/conf.d/``. Debian/Ubuntu's packaged ``unbound.conf``
        includes ``/etc/unbound/unbound.conf.d/*.conf`` — a DIFFERENT directory
        (note the ``unbound.`` prefix). On a host where nothing else bridges the
        two, every file we write is silently ignored: ``sync()`` reports
        SUCCESS and ``unbound-control reload`` succeeds, because both are
        truthfully describing a write and a reload of a config Unbound never
        reads. The resolver then answers recursively for public names while
        every lab record and forwarder is missing — which presents as "DNS is
        broken" with a completely healthy-looking service and a clean sync.

        Rather than edit the packaged ``unbound.conf`` (an apt upgrade would
        revert it, and rewriting a distro file is a poor neighbour), drop a
        one-line bridge file into whichever directory Unbound already includes.
        ``include-toplevel`` is the correct directive: our files declare their
        own top-level clauses (``server:``, ``forward-zone:``).

        Idempotent and best-effort — never raises, so a read-only or unusual
        layout degrades to today's behaviour instead of breaking startup.
        """
        conf_dir = os.path.dirname(self.conf_path)
        try:
            with open(MAIN_CONF) as fh:
                main_text = fh.read()
        except OSError as e:
            logger.debug("unbound include check: cannot read %s: %s", MAIN_CONF, e)
            return {"ok": False, "reason": "main conf unreadable"}

        include_globs = re.findall(
            r'^\s*include(?:-toplevel)?:\s*"?([^"\s]+)"?', main_text, re.M)

        def _covers(glob_path):
            """True if this glob pulls in *.conf from our directory."""
            return os.path.dirname(glob_path.rstrip()) == conf_dir.rstrip("/")

        if any(_covers(g) for g in include_globs):
            return {"ok": True, "action": "already-included"}

        # Follow the distro's own include dir(s) and check whether a bridge is
        # already in place there (ours from a previous run, or an operator's).
        bridge_dirs = [os.path.dirname(g) for g in include_globs
                       if os.path.isdir(os.path.dirname(g))]
        for d in bridge_dirs:
            try:
                for name in os.listdir(d):
                    if not name.endswith(".conf"):
                        continue
                    with open(os.path.join(d, name)) as fh:
                        if any(_covers(g) for g in re.findall(
                                r'^\s*include(?:-toplevel)?:\s*"?([^"\s]+)"?',
                                fh.read(), re.M)):
                            return {"ok": True, "action": "already-bridged"}
            except OSError:
                continue

        if not bridge_dirs:
            logger.warning(
                "unbound: %s includes no directory we can bridge into; managed "
                "config in %s may not be loaded", MAIN_CONF, conf_dir)
            return {"ok": False, "reason": "no include dir"}

        bridge = os.path.join(bridge_dirs[0], BRIDGE_CONF_NAME)
        try:
            with open(bridge, "w") as fh:
                fh.write("# Managed by Lab Manager — do not edit manually\n"
                         "# Bridges LM's managed config dir into Unbound, which\n"
                         "# otherwise only parses this directory.\n"
                         'include-toplevel: "%s/*.conf"\n' % conf_dir.rstrip("/"))
        except OSError as e:
            logger.warning("unbound: could not write include bridge %s: %s", bridge, e)
            return {"ok": False, "reason": str(e)}
        logger.warning("unbound: wrote include bridge %s so %s is actually parsed",
                       bridge, conf_dir)
        return {"ok": True, "action": "bridged", "path": bridge}

    # ── Public API ────────────────────────────────────────────────────

    def sync(self, records: list) -> dict:
        """
        Replace all LM-managed DNS records with the provided list.

        Each record: {"name": "host.example.com", "type": "A", "value": "10.0.1.5", "ttl": 300}
        Forward (A/AAAA) and reverse (PTR) records are both written.
        """
        lines = ["# Managed by Lab Manager — do not edit manually\n", "server:\n"]
        for r in records:
            name = r.get("name", "").strip().rstrip(".")
            rtype = r.get("type", "A").upper()
            value = r.get("value", "").strip()
            ttl = int(r.get("ttl", 300))
            if not name or not value:
                continue

            if rtype in ("A", "AAAA"):
                lines.append(f'    local-data: "{name}. {ttl} IN {rtype} {value}"\n')
                ptr = self._ptr_name(value)
                if ptr:
                    lines.append(f'    local-data-ptr: "{value} {ttl} {name}."\n')

            elif rtype == "CNAME":
                lines.append(f'    local-data: "{name}. {ttl} IN CNAME {value.rstrip(".")}."\n')

            elif rtype == "PTR":
                lines.append(f'    local-data: "{name}. {ttl} IN PTR {value.rstrip(".")}."\n')

        with open(self.conf_path, "w") as f:
            f.writelines(lines)

        count = len(records)
        # Query logging is on by default: every sync (NetBox auto-sync runs
        # regularly) idempotently guarantees it, not just a WebUI stats view.
        # A restart performed here already loaded the new records, so an
        # immediate reload would only race the restarting daemon.
        logging_result = self._ensure_query_logging()
        if logging_result.get("restarted"):
            self._records_cache = None
            self._records_cache_mtime = None
            logger.info("Synced %d DNS records to Unbound via restart", count)
            return {"status": "SUCCESS", "records_written": count, "reloaded": True}
        # A write that Unbound never reloaded has NOT taken effect: the file on
        # disk says one thing and the running resolver answers another. Report
        # the reload failure instead of a SUCCESS the caller cannot act on —
        # the clustered coordinator relies on this to avoid recording a version
        # a resolver is not actually serving.
        reload_result = self._reload()
        # We just rewrote the conf — drop the parsed-list memo so the next
        # list_records re-reads the new contents rather than returning stale.
        self._records_cache = None
        self._records_cache_mtime = None
        if not reload_result["ok"]:
            logger.error("Wrote %d DNS records but unbound-control reload failed: %s",
                         count, reload_result["error"])
            return {"status": "ERROR", "records_written": count,
                    "reloaded": False, "error": reload_result["error"],
                    "message": (f"{count} record(s) written to {self.conf_path} but "
                                f"unbound-control reload failed: "
                                f"{reload_result['error']} — the running resolver "
                                f"is still serving the previous set")}
        logger.info("Synced %d DNS records to Unbound", count)
        return {"status": "SUCCESS", "records_written": count, "reloaded": True}

    def list_records(self) -> list:
        """Parse the managed conf file and return records.

        Memoized on the conf file's mtime: a hit (same mtime as last parse)
        returns the cached list without re-reading/re-parsing — status/add/
        update/delete all flow through here, and the conf only changes when
        sync() rewrites it (which clears the memo)."""
        try:
            mtime = os.stat(self.conf_path).st_mtime
        except FileNotFoundError:
            self._records_cache = None
            self._records_cache_mtime = None
            return []
        if self._records_cache is not None and self._records_cache_mtime == mtime:
            return self._records_cache
        records = []
        with open(self.conf_path) as f:
            for line in f:
                line = line.strip()
                m = re.match(r'local-data:\s+"(.+?)\.\s+(\d+)\s+IN\s+(\w+)\s+(.+?)"', line)
                if m:
                    records.append({
                        "name":  m.group(1),
                        "ttl":   int(m.group(2)),
                        "type":  m.group(3),
                        "value": m.group(4),
                    })
                m2 = re.match(r'local-data-ptr:\s+"(\S+)\s+(\d+)\s+(.+?)"', line)
                if m2:
                    records.append({
                        "name":  m2.group(1),
                        "ttl":   int(m2.group(2)),
                        "type":  "PTR",
                        "value": m2.group(3).rstrip("."),
                    })
        self._records_cache = records
        self._records_cache_mtime = mtime
        return records

    def add_record(self, name: str, rtype: str, value: str, ttl: int = 300) -> dict:
        existing = self.list_records()
        existing.append({"name": name, "type": rtype, "value": value, "ttl": ttl})
        return self.sync(existing)

    def update_record(self, name: str, rtype: str, value: str, ttl: int = 300) -> dict:
        """Replace an existing record's value/ttl (matched by name + type).

        Implemented as a filtered re-sync: the first matching record is swapped
        for the new value/ttl, duplicates are dropped, and any non-matching
        records are preserved. If no match exists the record is added. The
        re-sync regenerates the companion PTR for A/AAAA records automatically.
        """
        existing = self.list_records()
        updated: list = []
        replaced = False
        for r in existing:
            if r["name"] == name and r["type"] == rtype:
                if not replaced:
                    updated.append({"name": name, "type": rtype, "value": value, "ttl": ttl})
                    replaced = True
                # drop duplicate matches
            else:
                updated.append(r)
        if not replaced:
            updated.append({"name": name, "type": rtype, "value": value, "ttl": ttl})
        return self.sync(updated)

    def delete_record(self, name: str, rtype: str = None) -> dict:
        existing = self.list_records()
        filtered = [
            r for r in existing
            if not (r["name"] == name and (rtype is None or r["type"] == rtype))
        ]
        return self.sync(filtered)

    def status(self) -> dict:
        try:
            result = subprocess.run(
                ["unbound-control", "status"],
                capture_output=True, text=True, timeout=5
            )
            running = result.returncode == 0
        except Exception:
            running = False
        return {
            "running":      running,
            "record_count": len(self.list_records()),
            "conf_path":    self.conf_path,
        }

    def _self_heal(self) -> list:
        """Best-effort, fixed-argv repair of conditions diagnostics() can fully
        explain and safely fix without operator action — never anything that
        touches DNS record/forwarder data. Mirrors the DHCP-side
        ``KeaManager._self_heal()``/``_heal_inactive_units()`` pattern: a
        crash-looped or one-off-killed ``unbound`` unit used to require the
        operator to notice and manually restart it (or uninstall/reinstall
        the whole role) — ``systemctl restart`` is the same fixed,
        argument-free recovery a reinstall ultimately performs, without
        touching any configuration. Returns the list of repair actions taken
        (each a short human-readable string) for the UI/log.
        """
        actions = []
        try:
            actions.extend(self._heal_inactive_unbound())
        except Exception as e:  # noqa: BLE001 — self-heal must never crash diagnostics
            logger.warning("self-heal (unbound unit) failed: %s", e)
        return actions

    def _heal_inactive_unbound(self) -> list:
        state = self._unit_status("unbound")
        active = state.get("ActiveState")
        load = state.get("LoadState")
        if load != "loaded" or active == "active":
            return []
        if active not in ("failed", "inactive"):
            return []
        result = self._run_diag(["systemctl", "restart", "unbound"], timeout=20)
        if result["ok"]:
            logger.info("self-heal: restarted unbound (was %s)", active)
            return [f"restarted unbound (was {active})"]
        logger.warning("self-heal: restart of unbound failed: %s", result["error"])
        return []

    def _unit_status(self, unit):
        result = self._run_diag([
            "systemctl", "show", unit,
            "--property=LoadState,ActiveState,SubState,NRestarts,ExecMainStatus",
        ])
        values = {}
        for line in result["output"].splitlines():
            key, sep, value = line.partition("=")
            if sep:
                values[key] = value
        values["error"] = result["error"]
        return values

    def diagnostics(self) -> dict:
        """Return actionable Unbound service, config, listener, and query checks."""
        repairs = self._self_heal()
        service = self._run_diag(["systemctl", "is-active", "unbound"])
        config = self._run_diag(["unbound-checkconf"])
        control = self._run_diag(["unbound-control", "status"])
        sockets = self._run_diag(["ss", "-H", "-lntup"])
        if not sockets["ok"]:
            sockets = self._run_diag(["ss", "-H", "-lntu"])

        listener_lines = [
            line.strip() for line in sockets["output"].splitlines()
            if re.search(r"(?:\]:|:)53(?:\s|$)", line)
        ]
        lan_addresses = self._local_ipv4s()
        probes = [self._dns_probe("127.0.0.1")]
        probes.extend(self._dns_probe(addr) for addr in lan_addresses)

        root_conf = "/etc/unbound/unbound.conf"
        interfaces = []
        access_controls = []
        try:
            with open(root_conf, encoding="utf-8") as fh:
                for line in fh:
                    m = re.match(r"\s*interface:\s*(\S+)", line)
                    if m:
                        interfaces.append(m.group(1))
                    m = re.match(r"\s*access-control:\s*(\S+\s+\S+)", line)
                    if m:
                        access_controls.append(m.group(1))
        except OSError:
            pass

        has_listener = bool(listener_lines)
        listener_hosts = [self._listener_host(line) for line in listener_lines]
        has_lan_listener = any(
            host and not host.startswith("127.") and host != "::1"
            for host in listener_hosts
        )
        lan_probe_ok = any(
            p["responded"] for p in probes if p["server"] != "127.0.0.1"
        )
        recommendations = []
        for action in repairs:
            recommendations.append(f"Self-healed: {action}. Re-checking findings above.")
        if not service["ok"]:
            recommendations.append(
                "Unbound is not active; inspect the service error and restart it.")
        if not config["ok"]:
            recommendations.append(
                "Unbound configuration is invalid; fix the reported checkconf error.")
        if not has_listener:
            recommendations.append(
                "Nothing is listening on TCP/UDP port 53.")
        elif not has_lan_listener:
            recommendations.append(
                "Port 53 is only bound to loopback; configure a LAN listener.")
        if lan_addresses and not lan_probe_ok:
            recommendations.append(
                "The local LAN-address DNS probe received no response; check the "
                "listener owner, Unbound access-control, and host firewall.")

        return {
            "status": "SUCCESS",
            "worker_code_version": worker_code_version(),
            "healthy": (
                service["ok"] and config["ok"] and has_lan_listener
                and (lan_probe_ok if lan_addresses else False)
            ),
            "self_healed": repairs,
            "service": service,
            "config": config,
            "control": control,
            "sockets": {
                "ok": sockets["ok"],
                "error": sockets["error"],
                "listeners": listener_lines,
                "has_port_53_listener": has_listener,
                "has_lan_listener": has_lan_listener,
            },
            "configured_interfaces": interfaces,
            "access_controls": access_controls,
            "local_ipv4s": lan_addresses,
            "probes": probes,
            "recommendations": recommendations,
            "conf_path": self.conf_path,
            "query_logging": self._safe_query_log_diagnostics(),
        }

    def _safe_query_log_diagnostics(self) -> dict:
        try:
            return self.query_log_diagnostics()
        except Exception as e:
            logger.warning("query log diagnostics failed: %s", e)
            return {"error": str(e), "findings": [f"query-log diagnostics failed: {e}"]}

    def query_log_diagnostics(self) -> dict:
        """Read-only evidence for why the query log / "Queries by Destination"
        / per-client log might be empty. Never changes any state."""
        info = {"query_log": QUERY_LOG, "logging_conf": LOGGING_CONF}
        findings = []

        def tail(path, n=8, size=65536):
            try:
                with open(path, "rb") as fh:
                    fh.seek(0, os.SEEK_END)
                    end = fh.tell()
                    fh.seek(max(0, end - size))
                    return fh.read().decode("utf-8", "replace").splitlines()[-n:]
            except OSError:
                return []

        def stat_of(path):
            try:
                st = os.stat(path)
            except OSError as e:
                return {"exists": False, "error": str(e)}
            owner = group = None
            try:
                import pwd, grp
                owner = pwd.getpwuid(st.st_uid).pw_name
                group = grp.getgrgid(st.st_gid).gr_name
            except Exception:
                pass
            return {"exists": True, "size": st.st_size, "mode": oct(st.st_mode & 0o7777),
                    "owner": owner, "group": group,
                    "age_seconds": round(time.time() - st.st_mtime, 1)}

        info["log_dir"] = stat_of(os.path.dirname(QUERY_LOG))
        info["log_file"] = stat_of(QUERY_LOG)
        log_tail = tail(QUERY_LOG)
        info["log_tail"] = log_tail
        info["log_tail_parsed"] = sum(1 for ln in log_tail if _QUERY_LOG_RE.search(ln))
        try:
            info["logging_conf_content"] = open(LOGGING_CONF).read()
        except OSError as e:
            info["logging_conf_content"] = None
            findings.append(f"{LOGGING_CONF} is missing ({e}); logging was never enabled.")

        conf_dir = os.path.dirname(self.conf_path)
        try:
            main_text = open(MAIN_CONF, encoding="utf-8").read()
        except OSError:
            main_text = ""
        info["conf_dir_included"] = bool(
            re.search(r"^\s*include(?:-toplevel)?:\s*\"?%s" % re.escape(conf_dir),
                      main_text, re.M))
        if not info["conf_dir_included"]:
            findings.append(f"{MAIN_CONF} does not include {conf_dir}/*; lm-logging.conf is never read.")

        # What the RUNNING daemon uses (not just what the file says).
        for opt in ("log-queries", "logfile", "use-syslog"):
            r = self._run_diag(["unbound-control", "get_option", opt])
            info[f"running_{opt.replace('-', '_')}"] = (
                r["output"].strip() if r["ok"] else (r["error"].strip() or "unavailable"))
        cf = self._run_diag(["unbound-checkconf", "-o", "log-queries"])
        info["configured_log_queries"] = cf["output"].strip() if cf["ok"] else (cf["error"].strip() or "unavailable")
        cf = self._run_diag(["unbound-checkconf", "-o", "logfile"])
        info["configured_logfile"] = cf["output"].strip() if cf["ok"] else (cf["error"].strip() or "unavailable")
        ver = self._run_diag(["unbound", "-V"])
        info["unbound_version"] = (ver["output"] or ver["error"]).splitlines()[0] if (ver["output"] or ver["error"]) else ""
        pid = self._run_diag(["systemctl", "show", "-p", "ActiveEnterTimestamp", "--value", "unbound"])
        info["unbound_active_since"] = pid["output"].strip()

        # AppArmor: override present, profile mode, recent denials.
        override = "/etc/apparmor.d/local/usr.sbin.unbound"
        try:
            ov = open(override).read()
        except OSError:
            ov = None
        info["apparmor_profile_present"] = os.path.exists("/etc/apparmor.d/usr.sbin.unbound")
        info["apparmor_override_present"] = ov is not None
        info["apparmor_override_has_rule"] = bool(ov and f"{os.path.dirname(QUERY_LOG)}/**" in ov)
        aa = self._run_diag(["aa-status"])
        info["apparmor_unbound_status"] = ("loaded" if re.search(r"unbound", aa["output"])
                                           else ("aa-status unavailable" if not aa["ok"] else "not loaded"))
        den = self._run_diag(["journalctl", "-k", "--no-pager", "-n", "400", "-o", "cat"])
        info["apparmor_denials"] = [ln.strip() for ln in den["output"].splitlines()
                                    if "DENIED" in ln and "unbound" in ln][-5:]

        # Journal fallback: is unbound logging queries there instead?
        jr = self._run_diag(["journalctl", "-u", "unbound", "--no-pager", "-n", "300", "-o", "cat"])
        jlines = jr["output"].splitlines()
        info["journal_query_lines"] = sum(1 for ln in jlines if _QUERY_LOG_RE.search(ln))
        info["journal_tail"] = [ln for ln in jlines if "info:" in ln or "error" in ln.lower()][-6:]

        # In-memory state of this process.
        info["memory"] = {
            "events": len(self._query_events), "tracked_names": len(self._query_counts),
            "log_offset": self._query_log_offset, "log_inode": self._query_log_inode,
        }

        if info["log_file"].get("exists") and info["log_file"].get("size", 0) == 0:
            findings.append("Query log exists but is empty: unbound is not writing to it "
                            "(check running logfile/log-queries below, and AppArmor).")
        if not info["log_file"].get("exists"):
            findings.append("Query log file does not exist: unbound never created it.")
        if info["apparmor_denials"]:
            findings.append("AppArmor is denying unbound; see denials below.")
        if info["apparmor_profile_present"] and not info["apparmor_override_has_rule"]:
            findings.append("AppArmor profile present but the lm override rule is missing.")
        if str(info.get("running_log_queries", "")).lower() not in ("yes", "unavailable", ""):
            findings.append("Running unbound has log-queries off; it needs a restart (not reload).")
        if info["running_logfile"] and QUERY_LOG not in info["running_logfile"] \
                and info["running_logfile"] != "unavailable":
            findings.append(f"Running unbound logfile is {info['running_logfile']!r}, not {QUERY_LOG}.")
        if info["journal_query_lines"] and not info["log_tail_parsed"]:
            findings.append("Queries are appearing in the journal, not the logfile.")
        if info["log_tail"] and not info["log_tail_parsed"]:
            findings.append("Log has lines but none match the parser regex; see log_tail for the real format.")
        info["findings"] = findings
        return info

    # ── Statistics & forwarders ───────────────────────────────────────

    def _restart_unbound(self, reason: str) -> dict:
        """Restart Unbound and report a structured ``{"ok", "error"}`` outcome."""
        try:
            subprocess.run(["systemctl", "restart", "unbound"], check=True,
                           capture_output=True, timeout=30)
            logger.info("Unbound restarted (%s)", reason)
            return {"ok": True, "error": ""}
        except Exception as e:
            logger.warning("unbound restart failed (%s): %s", reason, e)
            return {"ok": False, "error": str(e)}

    def _ensure_apparmor_log_access(self) -> dict:
        """Let the confined ``unbound`` daemon create/write the query log.

        Debian/Ubuntu ship an AppArmor profile for unbound that does NOT allow
        /var/log/unbound/. With it enforcing, unbound's mknod of QUERY_LOG is
        DENIED, so the logfile directive silently produces nothing (the lines go
        to the journal instead) and the per-destination breakdown stays empty
        forever even though the conf and directory ownership are correct. The
        supported hook is the ``local/`` override.

        Returns ``{"status": noop|applied|failed, "changed", "restarted", "ok",
        "reason"}`` so callers do not confuse "nothing to do" with "still
        broken". A rule that is present but not yet proven active (no logfile)
        is re-applied — once per process after a successful apply, so a
        transient first failure self-heals without restarting unbound on every
        sync."""
        local_dir = "/etc/apparmor.d/local"
        profile = "/etc/apparmor.d/usr.sbin.unbound"
        rule = f"{os.path.dirname(QUERY_LOG)}/** rw,\n"
        if not os.path.isdir(local_dir) or not os.path.exists(profile):
            return {"status": "noop", "changed": False, "restarted": False,
                    "ok": True, "reason": "apparmor-unavailable"}
        override = os.path.join(local_dir, "usr.sbin.unbound")
        try:
            current = open(override).read() if os.path.exists(override) else ""
            changed = False
            if rule not in current:
                with open(override, "a") as f:
                    if current and not current.endswith("\n"):
                        f.write("\n")
                    f.write("# Managed by Lab Manager — unbound query log (DNS stats)\n" + rule)
                changed = True
        except Exception as e:
            logger.warning("could not update AppArmor override %s: %s", override, e)
            return {"status": "failed", "changed": False, "restarted": False,
                    "ok": False, "reason": f"override-write-failed: {e}"}

        if rule in current and (os.path.exists(QUERY_LOG) or getattr(self, "_apparmor_applied", False)):
            return {"status": "noop", "changed": False, "restarted": False,
                    "ok": True, "reason": "rule-already-active"}
        try:
            subprocess.run(["apparmor_parser", "-r", profile], check=True,
                           capture_output=True, timeout=30)
        except Exception as e:
            logger.warning("AppArmor override written but profile reload failed: %s", e)
            return {"status": "failed", "changed": changed, "restarted": False,
                    "ok": False, "reason": f"apply-failed: {e}"}
        restart = self._restart_unbound("AppArmor query-log access")
        if not restart["ok"]:
            return {"status": "failed", "changed": changed, "restarted": False,
                    "ok": False, "reason": f"apply-failed: {restart['error']}"}
        self._apparmor_applied = True
        logger.info("AppArmor: allowed unbound to write %s; profile reloaded, unbound restarted",
                    QUERY_LOG)
        return {"status": "applied", "changed": changed, "restarted": True,
                "ok": True, "reason": "override-applied"}

    def _ensure_query_logging(self) -> dict:
        """Self-enable Unbound query logging (idempotent; called on every sync
        and every stats/client-query read).

        ``unbound-control stats`` has no per-name counters, so per-destination
        breakdowns require Unbound's own query log. Rather than hand-edit the
        main unbound.conf, drop a managed conf.d snippet (same pattern as
        LM_CONF) enabling ``log-queries``.

        Returns ``{"status": unchanged|restarted|failed, "changed",
        "restarted", "ok", "reason"}``. ``restarted`` tells callers that
        unbound was already restarted in this call (so an immediate reload
        would only race it); ``ok=False`` means logging is still not in effect.
        """
        # Unbound defaults to use-syslog: yes, which makes it IGNORE the
        # logfile directive entirely (see log_init() — syslog wins over a
        # configured filename) — without disabling it here, log-queries/
        # logfile above silently write nothing and get_query_names() stays
        # permanently empty even though this snippet "looks" correct.
        want = (f'server:\n    log-queries: yes\n'
                f'    use-syslog: no\n    logfile: "{QUERY_LOG}"\n')
        log_dir = os.path.dirname(QUERY_LOG)
        try:
            os.makedirs(log_dir, exist_ok=True)
        except Exception as e:
            logger.warning("could not create unbound log dir: %s", e)
        # The daemon that actually opens QUERY_LOG is the "unbound" system
        # user (not whoever runs this coordinator process, e.g. svc_lm), and
        # os.makedirs() above creates the dir owned by US. If unbound can't
        # write into it, it silently drops the logfile directive (no error,
        # no log line — see log_init()) and get_query_names() stays
        # permanently empty even though the conf snippet below is correct.
        # chown it to the unbound user/group (mode 0755 so this process can
        # still read/tail the files unbound creates inside it) every call —
        # cheap, and self-heals if the dir gets recreated with wrong owners.
        try:
            import pwd
            pw = pwd.getpwnam("unbound")
            os.chown(log_dir, pw.pw_uid, pw.pw_gid)
            os.chmod(log_dir, 0o755)
        except (KeyError, ImportError):
            pass  # no "unbound" system user on this host (e.g. test env)
        except Exception as e:
            logger.warning("could not chown unbound log dir to unbound user: %s", e)
        try:
            current = open(LOGGING_CONF).read() if os.path.exists(LOGGING_CONF) else ""
        except Exception:
            current = ""
        conf_changed = current != want
        if conf_changed:
            try:
                with open(LOGGING_CONF, "w") as f:
                    f.write(want)
                logger.info("Enabled unbound query logging via %s", LOGGING_CONF)
            except Exception as e:
                logger.warning("failed to write %s: %s", LOGGING_CONF, e)
                return {"status": "failed", "changed": False, "restarted": False,
                        "ok": False, "reason": f"logging-conf-write-failed: {e}"}

        apparmor_result = self._ensure_apparmor_log_access()
        if not apparmor_result["ok"]:
            return {"status": "failed",
                    "changed": bool(conf_changed or apparmor_result["changed"]),
                    "restarted": False, "ok": False,
                    "reason": apparmor_result["reason"]}
        if apparmor_result["restarted"]:
            self._logging_restarted = True
            return {"status": "restarted",
                    "changed": bool(conf_changed or apparmor_result["changed"]),
                    "restarted": True, "ok": True,
                    "reason": apparmor_result["reason"]}

        # ``logfile`` is only opened at process startup — a plain reload
        # leaves Unbound still logging to its old destination (syslog, or
        # nowhere), so the query log would stay empty until the next
        # incidental restart. Restart when the conf changed, and also when the
        # conf already matched but unbound has never opened QUERY_LOG (the
        # snippet predates a restart, so it is correct but inert). The latter
        # is done once per process after a successful restart so a host where
        # the logfile never materialises is not restarted on every sync.
        log_missing = not os.path.exists(QUERY_LOG) and not getattr(self, "_logging_restarted", False)
        if conf_changed or log_missing:
            restart = self._restart_unbound("query logging enabled")
            if not restart["ok"]:
                return {"status": "failed", "changed": conf_changed, "restarted": False,
                        "ok": False, "reason": f"restart-failed: {restart['error']}"}
            self._logging_restarted = True
            return {"status": "restarted", "changed": conf_changed, "restarted": True,
                    "ok": True,
                    "reason": "logging-conf-written" if conf_changed else "logfile-missing"}

        return {"status": "unchanged", "changed": False, "restarted": False,
                "ok": True, "reason": "already-enabled"}

    def _tail_query_log(self) -> None:
        """Incrementally parse newly-appended lines of the unbound query log
        into ``self._query_counts``, tracking a byte offset so repeated
        get_stats() calls don't re-read the whole file.

        Handles log rotation: if the file's inode changed (or it shrank),
        treat it as a fresh file and restart from offset 0.
        """
        try:
            st = os.stat(QUERY_LOG)
        except FileNotFoundError:
            return
        except Exception as e:
            logger.debug("stat query log failed: %s", e)
            return

        if self._query_log_inode is not None and st.st_ino != self._query_log_inode:
            self._query_log_offset = 0  # rotated
        self._query_log_inode = st.st_ino
        if st.st_size < self._query_log_offset:
            self._query_log_offset = 0  # truncated/rotated in place

        try:
            with open(QUERY_LOG, "r", errors="replace") as f:
                f.seek(self._query_log_offset)
                for line in f:
                    m = _QUERY_LOG_RE.search(line)
                    if not m:
                        continue
                    name = m.group("name").lower()
                    rtype = m.group("type").upper()
                    ip = m.group("ip")
                    key = f"{name}|{rtype}|{ip}"
                    self._query_events.append((self._line_epoch(line), ip, name, rtype))
                    if key not in self._query_counts and len(self._query_counts) >= MAX_TRACKED_NAMES:
                        continue  # cap reached; keep counting names already tracked
                    day = int(time.time() // 86400)
                    bucket = self._day_buckets(key)
                    bucket[day] = bucket.get(day, 0) + 1
                self._query_log_offset = f.tell()
        except Exception as e:
            logger.warning("failed tailing unbound query log: %s", e)
        self._prune_query_counts()

    def _day_buckets(self, key: str) -> dict:
        """The ``{day_epoch: count}`` buckets for ``key``, creating them if
        needed. A legacy bare-int lifetime count (the pre-bucketing format) is
        migrated in place into today's bucket so it keeps counting and ages
        out under MAX_RETENTION_DAYS like everything else."""
        bucket = self._query_counts.get(key)
        if isinstance(bucket, dict):
            return bucket
        today = int(time.time() // 86400)
        bucket = {today: int(bucket)} if isinstance(bucket, (int, float)) and bucket else {}
        self._query_counts[key] = bucket
        return bucket

    def _prune_query_counts(self) -> None:
        """Age out day-buckets older than MAX_RETENTION_DAYS so tracked query
        history never grows unbounded and drops on its own, independent of
        whichever day/week/month window the WebUI happens to be viewing."""
        cutoff = int(time.time() // 86400) - MAX_RETENTION_DAYS + 1
        empty_keys = []
        for key in list(self._query_counts):
            buckets = self._day_buckets(key)
            for day in [d for d in buckets if d < cutoff]:
                del buckets[day]
            if not buckets:
                empty_keys.append(key)
        for key in empty_keys:
            del self._query_counts[key]

    @staticmethod
    def _line_epoch(line: str) -> float:
        """Epoch for a query-log/journal line: Unbound's own ``[epoch]``
        prefix, or a leading ``journalctl -o short-unix`` timestamp, else
        now() as a last resort (still bucketable, just slightly late)."""
        m = re.match(r"\s*\[(\d{9,})\]", line) or re.match(r"\s*(\d{9,})(?:\.\d+)?\s", line)
        return float(m.group(1)) if m else time.time()

    def _journal_events(self, minutes: int) -> list:
        """Fallback source when the logfile is absent or still empty (e.g. an
        AppArmor denial, or query logging was just enabled and the restart
        above hasn't landed yet): Unbound logs to the journal in that case."""
        try:
            r = subprocess.run(
                ["journalctl", "-u", "unbound", "--no-pager", "-o", "short-unix",
                 "--since", f"{int(minutes)} min ago"],
                capture_output=True, text=True, timeout=15)
        except Exception as e:
            logger.debug("journalctl fallback failed: %s", e)
            return []
        events = []
        for line in r.stdout.splitlines():
            m = _QUERY_LOG_RE.search(line)
            if m:
                events.append((self._line_epoch(line), m.group("ip"),
                               m.group("name").lower(), m.group("type").upper()))
        return events

    def get_client_queries(self, client: str = None, minutes: int = 10,
                           search: str = None, limit: int = CLIENT_QUERY_LIMIT,
                           source_prefixes: list = None) -> dict:
        """Pi-hole-style per-device query log: every query made by ``client``
        (exact source IP, or every client when omitted) in the trailing
        ``minutes``, newest first, plus a per-destination-name summary of the
        returned window. ``search``/``source_prefixes`` mirror
        ``get_query_names`` (substring match on name / tenant subnet scoping).
        """
        logging_result = self._ensure_query_logging()
        if not logging_result.get("ok") and not logging_result.get("restarted"):
            self._reload()
        self._tail_query_log()
        try:
            minutes = max(1, min(int(minutes or 10), 30 * 1440))
        except (TypeError, ValueError):
            minutes = 10
        cutoff = time.time() - minutes * 60
        source = "logfile"
        events = list(self._query_events)
        # Fall back to the journal both when the logfile is wholly absent/
        # empty (a freshly-enabled logger that hasn't produced anything yet)
        # AND when it exists with history but nothing falls inside the
        # requested window. That second case used to be read as "truly no
        # queries" — but a stale/stuck logfile (rotation hiccup, AppArmor
        # re-denial, tailing wedged after a restart) looks identical to real
        # silence unless the journal is also consulted.
        if not os.path.exists(QUERY_LOG) or not events or not any(
                ts >= cutoff for ts, *_ in events):
            journal = self._journal_events(minutes)
            if journal:
                events = journal
                source = "journal"
        client = (client or "").strip()
        needle = (search or "").strip().lower()
        nets = None
        if source_prefixes is not None:
            nets = []
            for p in source_prefixes:
                try:
                    nets.append(ipaddress.ip_network(p, strict=False))
                except ValueError:
                    continue
        rows = []
        for ts, ip, name, rtype in events:
            if ts < cutoff:
                continue
            if client and ip != client:
                continue
            if needle and needle not in name:
                continue
            if nets is not None:
                try:
                    addr = ipaddress.ip_address(ip)
                except ValueError:
                    continue
                if not any(addr in n for n in nets):
                    continue  # source outside this tenant's subnets
            rows.append({"time": ts, "client": ip, "name": name, "type": rtype})
        rows.sort(key=lambda r: r["time"], reverse=True)
        summary = {}
        for r in rows:
            k = (r["name"], r["type"])
            summary[k] = summary.get(k, 0) + 1
        top_names = sorted(
            ({"name": n, "type": t, "count": c} for (n, t), c in summary.items()),
            key=lambda x: x["count"], reverse=True)[:100]
        return {"status": "SUCCESS", "client": client, "minutes": minutes,
                "source": source, "total": len(rows),
                "queries": rows[:(limit or CLIENT_QUERY_LIMIT)],
                "top_names": top_names}

    def get_query_names(self, search: str = None, limit: int = TOP_NAMES_LIMIT,
                         source_prefixes: list = None, range_days: int = None) -> list:
        """Per-(name,type) query counters, sorted by count desc, each carrying
        its breakdown of source client IPs.

        ``search`` is a case-insensitive substring match against the queried
        name. ``source_prefixes`` (a list of ``ipaddress.ip_network``-parsable
        CIDR strings), when given, scopes both which rows are returned AND
        their counts to only the sources that fall inside those prefixes —
        this is how a tenant's DNS statistics view is restricted to queries
        made by their own devices (mirrors the subnet-based tenant filtering
        used elsewhere, e.g. ``access.filter_items_by_prefixes``). ``limit``
        truncates the *returned* list only — the full counter table (up to
        MAX_TRACKED_NAMES distinct name/type/source entries) is retained in
        memory so repeated/narrower searches don't lose data. ``range_days``
        (1/7/30 for the WebUI's day/week/month selector) sums only the
        trailing N days of buckets; omitted/None sums everything still
        retained (at most MAX_RETENTION_DAYS, enforced by _prune_query_counts).
        """
        self._tail_query_log()
        needle = (search or "").strip().lower()
        nets = None
        if source_prefixes is not None:
            nets = []
            for p in source_prefixes:
                try:
                    nets.append(ipaddress.ip_network(p, strict=False))
                except ValueError:
                    continue
        cutoff_day = None
        if range_days:
            try:
                cutoff_day = int(time.time() // 86400) - int(range_days) + 1
            except (TypeError, ValueError):
                cutoff_day = None
        grouped = {}  # "name|TYPE" -> {"name":, "type":, "count":, "sources": {ip: count}}
        for key in list(self._query_counts):
            buckets = self._day_buckets(key)
            name, rtype, ip = key.split("|", 2)
            if needle and needle not in name:
                continue
            if nets is not None:
                try:
                    addr = ipaddress.ip_address(ip)
                except ValueError:
                    continue
                if not any(addr in n for n in nets):
                    continue  # source outside this tenant's subnets
            count = sum(c for d, c in buckets.items() if cutoff_day is None or d >= cutoff_day)
            if not count:
                continue
            gkey = f"{name}|{rtype}"
            g = grouped.setdefault(gkey, {"name": name, "type": rtype, "count": 0, "sources": {}})
            g["count"] += count
            g["sources"][ip] = g["sources"].get(ip, 0) + count
        rows = []
        for g in grouped.values():
            sources = sorted(
                ({"ip": ip, "count": c} for ip, c in g["sources"].items()),
                key=lambda s: s["count"], reverse=True,
            )
            rows.append({"name": g["name"], "type": g["type"], "count": g["count"], "sources": sources})
        rows.sort(key=lambda r: r["count"], reverse=True)
        if limit:
            rows = rows[:limit]
        return rows

    def get_stats(self, search: str = None, source_prefixes: list = None,
                  range_days: int = None) -> dict:
        """Unbound query statistics via ``unbound-control stats_noreset``.

        Parses the flat ``key=value`` output into headline metrics (total
        queries, cache hit/miss + ratio, recursion latency, uptime) plus a
        per-record-type query breakdown for the UI — the DNS analog of the
        OPNsense resolver stats. ``stats_noreset`` leaves Unbound's counters
        intact so repeated polls don't zero them.

        Also enables (on first call) and tails Unbound's query log to build a
        per-destination-name breakdown (each with its querying source IPs),
        since stats_noreset has no per-name counters. ``search`` filters that
        breakdown by substring match on the queried name; ``source_prefixes``
        scopes it to only queries whose source IP falls in those CIDRs (used
        for per-tenant filtering — see ``get_query_names``).

        ``range_days`` only narrows the ``query_names`` (per-destination)
        breakdown — the ``global``/``query_types`` counters come straight
        from unbound-control's own lifetime totals, which Unbound itself does
        not bucket by day.
        """
        reload_error = None
        logging_result = self._ensure_query_logging()
        restarted = bool(logging_result.get("restarted"))
        if not logging_result.get("ok"):
            if not restarted:
                reload_result = self._reload()
                if not reload_result.get("ok"):
                    reload_error = reload_result.get("error", "Unbound is not running")
            if not reload_error:
                reload_error = logging_result.get("reason", "query logging setup failed")

        query_names = self.get_query_names(search=search, source_prefixes=source_prefixes,
                                            range_days=range_days)
        # A restart in this same call may still be settling, so give
        # unbound-control one retry before reporting it as down.
        attempts = 2 if restarted else 1
        for attempt in range(attempts):
            try:
                result = subprocess.run(
                    ["unbound-control", "stats_noreset"],
                    capture_output=True, text=True, timeout=8,
                )
            except Exception as e:
                if attempt + 1 < attempts:
                    time.sleep(0.5)
                    continue
                logger.error("get_stats failed: %s", e)
                return {"status": "ERROR", "message": str(e)}
            if result.returncode == 0:
                break
            if attempt + 1 < attempts:
                time.sleep(0.5)
                continue
            return {"status": "ERROR", "message": result.stderr.strip() or "unbound-control failed"}

        raw = {}
        for line in result.stdout.splitlines():
            if "=" in line:
                k, _, v = line.partition("=")
                try:
                    raw[k.strip()] = float(v.strip())
                except ValueError:
                    raw[k.strip()] = v.strip()

        def n(key):
            v = raw.get(key, 0)
            return v if isinstance(v, (int, float)) else 0

        hits   = n("total.num.cachehits")
        misses = n("total.num.cachemiss")
        total  = n("total.num.queries")
        hit_ratio = round(hits / total * 100, 1) if total else 0.0

        aggregate_types = {}
        threaded_types = {}
        for k, v in raw.items():
            m = re.match(r"(?:total\.)?num\.query\.type\.([A-Za-z0-9_-]+)$", k)
            if m and isinstance(v, (int, float)) and v:
                aggregate_types[m.group(1)] = int(v)
                continue
            m = re.match(
                r"thread\d+\.num\.query\.type\.([A-Za-z0-9_-]+)$", k)
            if m and isinstance(v, (int, float)) and v:
                threaded_types[m.group(1)] = (
                    threaded_types.get(m.group(1), 0) + int(v))
        query_types = aggregate_types or threaded_types

        response = {
            "status": "SUCCESS",
            "global": {
                "total_queries":     int(total),
                "cache_hits":        int(hits),
                "cache_misses":      int(misses),
                "cache_hit_ratio":   hit_ratio,
                "num_recursive":     int(n("total.num.recursivereplies")),
                "recursion_time_avg": round(n("total.recursion.time.avg"), 4),
                "prefetch":          int(n("total.num.prefetch")),
                "uptime_seconds":    int(n("time.up")),
            },
            "query_types": query_types,
            "query_names": query_names,
            "query_names_tracked": len(self._query_counts),
        }
        if reload_error:
            response["warning"] = reload_error
        return response

    def list_forwarders(self) -> dict:
        """Configured upstream forwarders via ``unbound-control list_forwards``.

        Output lines look like ``. IN forward 8.8.8.8 8.8.4.4`` (zone, class,
        ``forward``, then the upstream servers). Normalized to a per-zone list
        of upstreams for the UI's Upstream Servers panel.
        """
        try:
            result = subprocess.run(
                ["unbound-control", "list_forwards"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode != 0:
                return {"status": "ERROR", "message": result.stderr.strip() or "unbound-control failed"}
        except Exception as e:
            logger.error("list_forwarders failed: %s", e)
            return {"status": "ERROR", "message": str(e)}

        forwarders = []
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[2] == "forward":
                forwarders.append({
                    "zone":      parts[0],
                    "class":     parts[1],
                    "upstreams": parts[3:],
                })
        return {"status": "SUCCESS", "forwarders": forwarders}

    @staticmethod
    def _normalize_forward_zone(zone: str) -> str:
        zone = str(zone or "").strip().lower()
        if zone == ".":
            return zone
        zone = zone.rstrip(".")
        if not zone or len(zone) > 253:
            raise ValueError("zone must be '.' or a valid DNS domain")
        labels = zone.split(".")
        if any(not re.fullmatch(r"(?!-)[a-z0-9-]{1,63}(?<!-)", label)
               for label in labels):
            raise ValueError("zone must be '.' or a valid DNS domain")
        return zone + "."

    @staticmethod
    def _normalize_upstreams(upstreams) -> list:
        if isinstance(upstreams, str):
            upstreams = re.split(r"[\s,]+", upstreams.strip())
        values = []
        for raw in upstreams or []:
            raw = str(raw).strip()
            if not raw:
                continue
            try:
                values.append(str(ipaddress.ip_address(raw)))
            except ValueError as exc:
                raise ValueError(f"invalid forwarder address: {raw}") from exc
        if not values:
            raise ValueError("at least one forwarder address is required")
        if len(values) > 8:
            raise ValueError("no more than 8 forwarder addresses are allowed")
        return list(dict.fromkeys(values))

    def _managed_forwarders(self) -> list:
        if not os.path.exists(self.forwarders_path):
            return []
        forwarders = []
        current = None
        with open(self.forwarders_path, encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                match = re.match(r'name:\s*"([^"]+)"$', line)
                if match:
                    current = {"zone": match.group(1), "upstreams": []}
                    forwarders.append(current)
                    continue
                match = re.match(r"forward-addr:\s*(\S+)$", line)
                if match and current is not None:
                    current["upstreams"].append(match.group(1))
        return forwarders

    @staticmethod
    def _coalesce_forwarders(forwarders: list) -> list:
        """One ``forward-zone`` block per zone name.

        Unbound takes a zone's upstreams from a single block, and a repeated
        name is dropped with only a ``duplicate forward zone ... ignored`` in
        its own log. The writer used to render one block per list entry, so
        repeated adds for the same zone (the UI defaults the zone field to
        ".") piled up duplicate stanzas. Merging here also heals a file that
        already drifted, on the next successful write."""
        merged: dict = {}
        for item in forwarders or []:
            zone = str((item or {}).get("zone") or "").strip()
            if not zone:
                continue
            bucket = merged.setdefault(zone, [])
            for address in (item or {}).get("upstreams") or []:
                if address not in bucket:
                    bucket.append(address)
        return [{"zone": zone, "upstreams": upstreams}
                for zone, upstreams in merged.items()]

    def _safe_zone(self, zone) -> str:
        """``_normalize_forward_zone`` that returns "" instead of raising, for
        zone names we did not write and cannot vouch for."""
        try:
            return self._normalize_forward_zone(zone)
        except ValueError:
            return ""

    def _write_forwarders(self, forwarders: list) -> dict:
        old = None
        if os.path.exists(self.forwarders_path):
            with open(self.forwarders_path, "rb") as fh:
                old = fh.read()
        tmp_path = self.forwarders_path + ".tmp"
        lines = ["# Managed by Lab Manager — do not edit manually\n"]
        for item in self._coalesce_forwarders(forwarders):
            lines.extend([
                "forward-zone:\n",
                f'    name: "{item["zone"]}"\n',
                *[f"    forward-addr: {address}\n"
                  for address in item["upstreams"]],
            ])
        try:
            with open(tmp_path, "w", encoding="utf-8") as fh:
                fh.writelines(lines)
            os.replace(tmp_path, self.forwarders_path)
            result = self._reload()
            if result["ok"]:
                return {"status": "SUCCESS", "reloaded": True}
            if old is None:
                os.remove(self.forwarders_path)
            else:
                with open(self.forwarders_path, "wb") as fh:
                    fh.write(old)
            self._reload()
            return {"status": "ERROR", "reloaded": False,
                    "message": result["error"]}
        except Exception as exc:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            return {"status": "ERROR", "reloaded": False,
                    "message": str(exc)}

    def add_forwarder(self, zone: str, upstreams) -> dict:
        """Persist a new forwarding zone and reload Unbound.

        ``unbound-control reload``'s "ok" reply is NOT proof the new config
        was actually accepted: Unbound's own ``do_reload()`` sends "ok"
        immediately and only re-parses/rebuilds the forwards tree
        afterward, off the RPC thread — a duplicate zone name (e.g. a
        distro-default root forward already present elsewhere in
        unbound.conf/conf.d) is silently dropped with only a
        ``log_err("duplicate forward zone ... ignored")`` in Unbound's own
        log, never surfaced back over the control channel. That produced
        exactly the reported symptom: "add forwarder" returns SUCCESS but
        the zone never appears in the list. Re-reading ``list_forwarders()``
        after reload (the same live ``list_forwards`` RPC the UI itself
        polls) confirms the zone is ACTUALLY active before reporting
        success — if Unbound silently dropped it, this now returns a clear
        ERROR instead of a false SUCCESS.
        Adding to a zone LM already manages MERGES the new addresses in. It
        used to fail outright with "forwarder zone X already exists", which
        made the common case impossible: the UI's zone field defaults to ".",
        so "add an upstream server" is almost always an add against the
        already-present root zone.
        """
        try:
            zone = self._normalize_forward_zone(zone)
            upstreams = self._normalize_upstreams(upstreams)
        except ValueError as exc:
            return {"status": "ERROR", "message": str(exc), "changed": False}
        managed = self._coalesce_forwarders(self._managed_forwarders())
        current = next((item for item in managed
                        if self._safe_zone(item.get("zone")) == zone), None)
        if current is None:
            live = self.list_forwarders()
            if live.get("status") != "SUCCESS":
                return {**live, "changed": False}
            if any(self._safe_zone(item.get("zone")) == zone
                   for item in live.get("forwarders") or []):
                return {"status": "ERROR", "changed": False,
                        "message": f"forwarder zone {zone} is already served by "
                                   "Unbound from configuration Lab Manager does "
                                   "not manage"}
            desired = [*managed, {"zone": zone, "upstreams": upstreams}]
            final = upstreams
        else:
            known = list(current.get("upstreams") or [])
            added = [a for a in upstreams if a not in known]
            if not added:
                return {"status": "SUCCESS", "changed": False, "zone": zone,
                        "upstreams": known,
                        "message": f"forwarder zone {zone} already forwards to "
                                   + ", ".join(upstreams)}
            final = known + added
            if len(final) > 8:
                return {"status": "ERROR", "changed": False, "zone": zone,
                        "message": f"forwarder zone {zone} would exceed the "
                                   "8-address limit"}
            desired = [{**item, "upstreams": final} if item is current else item
                       for item in managed]
        result = self._write_forwarders(desired)
        if result.get("status") != "SUCCESS":
            return {**result, "zone": zone, "upstreams": final, "changed": False}
        confirm = self.list_forwarders()
        applied = confirm.get("status") == "SUCCESS" and any(
            self._safe_zone(item.get("zone")) == zone
            for item in confirm.get("forwarders") or [])
        if not applied:
            # Roll the file back to what it was before this call so a silently
            # rejected zone doesn't linger in our own managed config forever.
            self._write_forwarders(managed)
            return {
                "status": "ERROR", "changed": False, "zone": zone,
                "upstreams": final,
                "message": (
                    f"Unbound reloaded but forwarder zone {zone} did not take "
                    f"effect — it is likely a duplicate of an existing "
                    f"forward-zone already defined outside Lab Manager's "
                    f"managed config (check /etc/unbound/unbound.conf and "
                    f"other files in conf.d for an existing '{zone}' "
                    f"forward-zone, and the unbound journal for "
                    f"'duplicate forward zone ... ignored')"),
            }
        return {**result, "zone": zone, "upstreams": final, "changed": True}

    def update_forwarder(self, zone: str, upstreams, old_zone: str = None) -> dict:
        """Replace an LM-managed forwarding zone's upstreams in-place.

        Unlike ``add_forwarder`` this REPLACES rather than merges the upstream
        list, and supports renaming a zone via ``old_zone`` (looked up instead
        of ``zone`` when given). Mirrors ``add_forwarder``'s
        reload-then-verify-then-rollback pattern: ``unbound-control reload``'s
        "ok" reply is not proof the edited zone actually took effect, so the
        live ``list_forwards`` result is re-checked before reporting success.
        """
        try:
            zone = self._normalize_forward_zone(zone)
            upstreams = self._normalize_upstreams(upstreams)
            if old_zone is not None:
                old_zone = self._normalize_forward_zone(old_zone)
        except ValueError as exc:
            return {"status": "ERROR", "message": str(exc), "changed": False}

        managed = self._coalesce_forwarders(self._managed_forwarders())
        target_zone = old_zone if old_zone is not None else zone
        current = next((item for item in managed
                        if self._safe_zone(item.get("zone")) == target_zone), None)
        if current is None:
            return {"status": "ERROR", "changed": False,
                    "message": f"forwarder zone {target_zone} not found"}
        if old_zone is not None and old_zone != zone and any(
                self._safe_zone(item.get("zone")) == zone for item in managed):
            return {"status": "ERROR", "changed": False,
                    "message": f"forwarder zone {zone} already exists"}

        renaming = old_zone is not None and old_zone != zone
        changed = renaming or (list(current.get("upstreams") or []) != upstreams)
        desired = [{"zone": zone, "upstreams": upstreams} if item is current else item
                   for item in managed]

        result = self._write_forwarders(desired)
        if result.get("status") != "SUCCESS":
            return {**result, "zone": zone, "upstreams": upstreams, "changed": False}
        confirm = self.list_forwarders()
        applied = confirm.get("status") == "SUCCESS" and any(
            self._safe_zone(item.get("zone")) == zone
            for item in confirm.get("forwarders") or [])
        if not applied:
            # Roll back to the pre-edit state so a silently rejected rename/
            # upstream change doesn't leave our managed config out of sync
            # with what Unbound is actually serving.
            self._write_forwarders(managed)
            return {
                "status": "ERROR", "changed": False, "zone": zone,
                "upstreams": upstreams,
                "message": (
                    f"Unbound reloaded but forwarder zone {zone} did not take "
                    f"effect — it is likely a duplicate of an existing "
                    f"forward-zone already defined outside Lab Manager's "
                    f"managed config (check /etc/unbound/unbound.conf and "
                    f"other files in conf.d for an existing '{zone}' "
                    f"forward-zone, and the unbound journal for "
                    f"'duplicate forward zone ... ignored')"),
            }
        return {**result, "zone": zone, "upstreams": upstreams, "changed": changed}

    def remove_forwarder(self, zone: str) -> dict:
        """Remove an LM-managed forwarding zone. Used for cluster rollback."""
        try:
            zone = self._normalize_forward_zone(zone)
        except ValueError as exc:
            return {"status": "ERROR", "message": str(exc)}
        existing = self._managed_forwarders()
        kept = [item for item in existing if item.get("zone") != zone]
        if len(kept) == len(existing):
            return {"status": "SUCCESS", "changed": False, "zone": zone}
        result = self._write_forwarders(kept)
        return {**result, "changed": result.get("status") == "SUCCESS",
                "zone": zone}

    # ── Per-client override views ─────────────────────────────────────

    def read_overrides(self):
        """Current managed override file contents, or ``None`` if absent."""
        try:
            with open(self.overrides_path, encoding="utf-8") as fh:
                return fh.read()
        except FileNotFoundError:
            return None

    def _checkconf(self) -> dict:
        """Validate the full config Unbound would load. Skipped (ok) when
        ``unbound-checkconf`` is not installed — reload is then the only gate."""
        if not shutil.which("unbound-checkconf"):
            return {"ok": True, "error": "", "skipped": True}
        result = self._run_diag(["unbound-checkconf"], timeout=20)
        return {"ok": result["ok"], "error": result["error"]}

    def write_overrides(self, text: str) -> dict:
        """Atomically replace ``lm-overrides.conf``, validate, and reload.

        A rejected config is put back before Unbound ever reloads it: an
        ``unbound-control reload`` of an invalid file stops the resolver, so the
        file is checked with ``unbound-checkconf`` first. Any failure restores
        the previous file and reports ``rejected`` so the coordinator rolls the
        whole cluster back instead of retrying a config that can never load.
        """
        old = self.read_overrides()
        if old == text:
            return {"status": "SUCCESS", "changed": False, "reloaded": True}
        tmp_path = self.overrides_path + ".tmp"

        def _restore():
            if old is None:
                if os.path.exists(self.overrides_path):
                    os.remove(self.overrides_path)
            else:
                with open(self.overrides_path, "w", encoding="utf-8") as fh:
                    fh.write(old)

        try:
            with open(tmp_path, "w", encoding="utf-8") as fh:
                fh.write(text)
            os.replace(tmp_path, self.overrides_path)
        except Exception as exc:  # noqa: BLE001
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            return {"status": "ERROR", "rejected": True, "reloaded": False,
                    "message": f"could not write {self.overrides_path}: {exc}"}
        check = self._checkconf()
        if not check["ok"]:
            _restore()
            return {"status": "ERROR", "rejected": True, "reloaded": False,
                    "message": f"unbound-checkconf rejected the override config: {check['error']}"}
        result = self._reload()
        if not result["ok"]:
            _restore()
            self._reload()
            return {"status": "ERROR", "rejected": True, "reloaded": False,
                    "message": f"unbound-control reload failed: {result['error']}"}
        return {"status": "SUCCESS", "changed": True, "reloaded": True}

    # ── Helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _run_diag(cmd, timeout=5):
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout)
            output = (result.stdout or result.stderr or "").strip()[:2000]
            return {
                "ok": result.returncode == 0,
                "exit_code": result.returncode,
                "output": output,
                "error": "" if result.returncode == 0 else (output or "command failed"),
            }
        except Exception as e:
            return {"ok": False, "exit_code": None, "output": "", "error": str(e)}

    @staticmethod
    def _listener_host(line):
        for token in line.split():
            if re.search(r":53$", token):
                host = token.rsplit(":", 1)[0].strip("[]")
                return host.split("%", 1)[0]
        return ""

    def _local_ipv4s(self):
        result = self._run_diag(["ip", "-o", "-4", "addr", "show", "scope", "global"])
        if not result["ok"]:
            return []
        addresses = []
        for line in result["output"].splitlines():
            match = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+)/", line)
            if match and not ipaddress.ip_address(match.group(1)).is_loopback:
                addresses.append(match.group(1))
        return sorted(set(addresses))

    @staticmethod
    def _dns_probe(server, name="localhost"):
        started = time.monotonic()
        txid = time.monotonic_ns() & 0xFFFF
        labels = name.rstrip(".").split(".")
        question = b"".join(
            bytes([len(label)]) + label.encode("ascii") for label in labels
        ) + b"\x00" + struct.pack("!HH", 1, 1)
        packet = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + question
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        try:
            sock.sendto(packet, (server, 53))
            response, _ = sock.recvfrom(4096)
            if len(response) < 12:
                raise ValueError("short DNS response")
            reply_id, flags, _, answers, _, _ = struct.unpack("!HHHHHH", response[:12])
            if reply_id != txid:
                raise ValueError("DNS transaction ID mismatch")
            return {
                "server": server,
                "responded": True,
                "rcode": flags & 0xF,
                "answers": answers,
                "latency_ms": round((time.monotonic() - started) * 1000, 1),
                "error": "",
            }
        except Exception as e:
            return {
                "server": server,
                "responded": False,
                "rcode": None,
                "answers": 0,
                "latency_ms": round((time.monotonic() - started) * 1000, 1),
                "error": str(e),
            }
        finally:
            sock.close()

    def _reload(self) -> dict:
        """Reload Unbound. Returns ``{"ok": bool, "error": str}``.

        Previously swallowed the failure with a WARNING, so a conf write whose
        reload never happened still reported SUCCESS upstream. Callers need the
        distinction: the file changed but the resolver did not."""
        try:
            subprocess.run(["unbound-control", "reload"], check=True, timeout=10)
            logger.info("Unbound reloaded")
            return {"ok": True, "error": ""}
        except Exception as e:
            logger.warning("unbound-control reload failed: %s", e)
            return {"ok": False, "error": str(e)}

    def _ptr_name(self, ip: str) -> str:
        try:
            return ipaddress.ip_address(ip).reverse_pointer
        except ValueError:
            return ""
