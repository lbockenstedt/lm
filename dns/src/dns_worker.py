"""``lm-dns-worker`` — the resolver-host half of a clustered DNS deployment.

Runs on each Unbound host and dials its coordinator's ``/ws/agent`` listener
(the ``dns`` module spoke). It is intentionally NOT a generic agent: the op
table below is the complete set of things this process can be asked to do. There
is no ``RUN_COMMAND``, no ``WRITE_FILE``, no caller-supplied path — the conf path
is fixed at start from local config, and the only writable content is a record
set that the coordinator already validated and that this worker re-validates
before touching disk.

Applied state (``version`` + ``digest``) is persisted next to the conf so the
coordinator can tell a rebooted resolver from a drifted one.
"""

# argparse reads worker settings from the command line.
import argparse
# asyncio runs the WebSocket client loop.
import asyncio
# hashlib fingerprints the rendered override file to detect out-of-band edits.
import hashlib
# json reads and writes the applied-state file.
import json
# Standard-library logging (logger defined below).
import logging
# os handles file paths, atomic replace and environment settings.
import os
# subprocess runs journalctl and unbound-control for override verification.
import subprocess
# time stamps applied-state records.
import time
# Type hints only; they document payload shapes.
from typing import Any, Dict

# UnboundManager does the actual conf writing/reloading; QUERY_LOG is its query-log path.
# The import path differs when run as a script vs loaded as a package.
try:
    from unbound_manager import QUERY_LOG, UnboundManager
# Package layout: import through src.
except ImportError:  # loaded as a package (src.X)
    from src.unbound_manager import QUERY_LOG, UnboundManager

# Record-set validation and digest helpers shared with the coordinator.
try:
    from dns_cluster import (
        derive_managed_records, digest_of_parsed, records_digest, validate_records)
# Package layout: import through src.
except ImportError:  # loaded as a package (src.X)
    from src.dns_cluster import (  # type: ignore
        derive_managed_records, digest_of_parsed, records_digest, validate_records)

# Per-client override validation, rendering and digest helpers shared with the coordinator.
try:
    from dns_overrides import (
        EMPTY_DIGEST, RENDER_REVISION, DnsOverrideError, override_hits,
        overrides_digest, parse_rendered, render_unbound, validate_overrides)
# Package layout: import through src.
except ImportError:  # loaded as a package (src.X)
    from src.dns_overrides import (  # type: ignore
        EMPTY_DIGEST, RENDER_REVISION, DnsOverrideError, override_hits,
        overrides_digest, parse_rendered, render_unbound, validate_overrides)

# One named logger so all worker messages can be filtered together.
logger = logging.getLogger("DNSWorker")

# Default managed Unbound conf, applied-state file, and coordinator agent port (DNS role).
DEFAULT_CONF = "/etc/unbound/conf.d/lm-netbox.conf"
DEFAULT_STATE = "/var/lib/lm-dns-worker/applied.json"
DEFAULT_COORDINATOR_PORT = 8769


class DnsWorkerOps:
    """The fixed operation table exposed to the coordinator."""

    def __init__(self, mgr: UnboundManager, state_path: str = DEFAULT_STATE):
        """Bind the ops to an Unbound manager and load the last applied state.

        Args:
            mgr: Manager for the local Unbound instance.
            state_path: JSON file recording the last applied version and digest.
        """
        # Keep the manager and state path, then read what was last applied.
        self.mgr = mgr
        self.state_path = state_path
        self.applied: Dict[str, Any] = self._load_applied()

    # ── Applied-state bookkeeping ───────────────────────────────────────────

    def _load_applied(self) -> Dict[str, Any]:
        """Read the applied-state marker; return an empty marker if missing or unreadable."""
        # Read the JSON marker; only a dict is a valid marker.
        try:
            with open(self.state_path) as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                return data
        # No marker yet (fresh install): fall through to the empty marker.
        except FileNotFoundError:
            pass
        # Corrupt or unreadable marker: warn and treat as empty.
        except Exception as e:  # noqa: BLE001
            logger.warning("Could not read applied state %s: %s", self.state_path, e)
        # Empty marker: nothing applied yet.
        return {"version": None, "digest": None, "record_count": 0, "at": 0}

    def _save_applied(self, version: Any, digest: str, count: int) -> None:
        """Remember and persist what was just applied.

        Args:
            version: Coordinator's record-set version.
            digest: Digest of the applied records.
            count: Number of records applied.
        """
        # Update the in-memory marker first so status reflects the apply even if the save fails.
        self.applied = {"version": version, "digest": digest,
                        "record_count": count, "at": time.time()}
        # Persist atomically: create the folder, write a temp file, then rename over the marker.
        try:
            directory = os.path.dirname(self.state_path)
            if directory:
                os.makedirs(directory, exist_ok=True)
            tmp = self.state_path + ".tmp"
            with open(tmp, "w") as fh:
                json.dump(self.applied, fh)
            os.replace(tmp, self.state_path)
        except Exception as e:  # noqa: BLE001 — a lost memo is recoverable, a
            # crash here is not: the records are already on disk.
            logger.warning("Could not persist applied state %s: %s",
                           self.state_path, e)

    # ── Operations ──────────────────────────────────────────────────────────

    def apply(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """``DNSW_APPLY`` — write + reload one versioned record set.

        Re-validates and re-digests locally. A payload whose digest does not
        match its own records is rejected: it means the frame was built by
        something that is not the coordinator's desired state, and applying it
        would make the cluster's convergence check meaningless.
        """
        # Version and claimed digest sent by the coordinator.
        version = data.get("version")
        claimed = str(data.get("digest") or "")
        # Re-validate the records locally; never trust the frame blindly.
        try:
            records = validate_records(data.get("records") or [])
        # Invalid records: refuse the whole set.
        except ValueError as e:
            return {"status": "ERROR", "message": f"invalid record set: {e}"}
        # Recompute the digest and reject the frame if it does not match the claimed one.
        digest = records_digest(records)
        if claimed and claimed != digest:
            return {"status": "ERROR",
                    "message": (f"record-set digest mismatch (coordinator "
                                f"{claimed[:12]}…, local {digest[:12]}…)")}
        # Write the records into Unbound's conf and reload it.
        result = self.mgr.sync(records)
        # ``sync`` now reports a reload failure instead of swallowing it: the
        # conf file changed but the RUNNING resolver did not. Record the applied
        # version only after a confirmed reload, so the coordinator sees this
        # member as drifted (and reconciles it) rather than believing it is on a
        # version it is not serving.
        if result.get("status") != "SUCCESS" or result.get("reloaded") is False:
            return {"status": "ERROR", "reloaded": bool(result.get("reloaded")),
                    "records_written": result.get("records_written", 0),
                    "message": (result.get("message") or result.get("error")
                                or "unbound sync failed")}
        # Reload confirmed: record the new version and report success.
        self._save_applied(version, digest, len(records))
        return {"status": "SUCCESS", "version": version, "digest": digest,
                "record_count": len(records), "reloaded": True,
                "records_written": result.get("records_written", 0)}

    def state(self, _data: Dict[str, Any]) -> Dict[str, Any]:
        """``DNSW_STATE`` — what this resolver is ACTUALLY serving right now.

        The digest is computed from the managed conf file on disk, not from the
        applied-state marker this worker wrote about itself. Those diverge in
        exactly the cases that matter: someone edited the conf out of band, a
        write partially landed, or the marker survived a conf that did not. A
        digest sourced from the marker would report "converged" for a resolver
        serving something else entirely.

        ``records`` carries the derived set so a coordinator being enabled for
        the first time can adopt what is already live (see ``seed``).
        """
        # Parse what is actually in the conf file and derive the managed record set from it.
        parsed = self.mgr.list_records()
        derived = derive_managed_records(parsed)
        # Report the live digest alongside the recorded one so drift is visible.
        return {"status": "SUCCESS",
                "version": self.applied.get("version"),
                "digest": digest_of_parsed(parsed),
                "recorded_digest": self.applied.get("digest"),
                "records": derived,
                "record_count": len(derived),
                "applied_at": self.applied.get("at"),
                "running": bool(self.mgr.status().get("running"))}

    def standdown(self, _data: Dict[str, Any]) -> Dict[str, Any]:
        """``DNSW_STANDDOWN`` — leave the cluster cleanly.

        Issued when the operator removes this resolver from the topology. Clears
        the applied-version marker so the worker no longer claims membership.
        The RECORDS are deliberately left in place: deleting them would
        blackhole DNS for every client still pointed at this host."""
        # Forget the applied version in memory.
        self.applied = {"version": None, "digest": None, "record_count": 0,
                        "at": time.time()}
        # Delete the on-disk marker; a failure is reported because membership would linger.
        try:
            if os.path.exists(self.state_path):
                os.remove(self.state_path)
        # Could not delete the marker: report it so the operator can fix it.
        except Exception as e:  # noqa: BLE001
            return {"status": "ERROR",
                    "message": f"could not clear the applied-state marker: {e}"}
        # Success: left the cluster but records remain.
        return {"status": "SUCCESS", "changed": True,
                "message": "left the cluster; records left in place"}

    def status(self, _data: Dict[str, Any]) -> Dict[str, Any]:
        """``DNSW_STATUS`` — return the local Unbound status."""
        # Wrap the manager's status in a SUCCESS envelope.
        return {"status": "SUCCESS", **self.mgr.status()}

    def diagnostics(self, _data: Dict[str, Any]) -> Dict[str, Any]:
        """``DNSW_DIAGNOSTICS`` — return the local Unbound diagnostics report."""
        return self.mgr.diagnostics()

    def stats(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """``DNSW_STATS`` — return query statistics, optionally filtered.

        Args:
            data: Optional search, source_prefixes, range_days and range_seconds filters.
        """
        # Treat a missing payload as empty, then pass the filters through.
        d = data or {}
        return self.mgr.get_stats(search=d.get("search"), source_prefixes=d.get("source_prefixes"),
                                  range_days=d.get("range_days"),
                                  range_seconds=d.get("range_seconds"))

    def client_queries(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """``DNSW_CLIENT_QUERIES`` — return recent queries from one client.

        Args:
            data: client, minutes (default 10), search and source_prefixes filters.
        """
        # Treat a missing payload as empty, then pass the filters through.
        d = data or {}
        return self.mgr.get_client_queries(
            client=d.get("client"), minutes=d.get("minutes", 10),
            search=d.get("search"), source_prefixes=d.get("source_prefixes"))

    def forwarders(self, _data: Dict[str, Any]) -> Dict[str, Any]:
        """``DNSW_FORWARDERS`` — this resolver's own upstream forwarders.

        Forwarders are per-resolver configuration, so the coordinator asks each
        member rather than reporting its own box's (which may not even run
        Unbound)."""
        return self.mgr.list_forwarders()

    def add_forwarder(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """``DNSW_ADD_FORWARDER`` — add upstream servers for a zone ("." = all queries)."""
        return self.mgr.add_forwarder(
            data.get("zone", "."), data.get("upstreams", []))

    def update_forwarder(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Replace an existing forwarder zone's upstreams in-place (not merging)."""
        return self.mgr.update_forwarder(
            data.get("zone", "."), data.get("upstreams", []),
            old_zone=data.get("old_zone"))

    def remove_forwarder(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """``DNSW_REMOVE_FORWARDER`` — remove the forwarder for a zone."""
        return self.mgr.remove_forwarder(data.get("zone", ""))

    # ── Per-client override views ───────────────────────────────────────────

    @property
    def _overrides_marker_path(self) -> str:
        """Path of the override applied-marker file, kept next to the applied-state file."""
        # Same folder as the applied-state file (or the cwd if it has no folder).
        return os.path.join(os.path.dirname(self.state_path) or ".",
                            "overrides-applied.json")

    def _load_overrides_marker(self) -> Dict[str, Any]:
        """Read the override applied-marker; return {} if missing or unreadable."""
        # Read the JSON marker; only a dict is a valid marker.
        try:
            with open(self._overrides_marker_path) as fh:
                data = json.load(fh)
            return data if isinstance(data, dict) else {}
        # No marker yet: nothing has been applied.
        except FileNotFoundError:
            return {}
        # Corrupt or unreadable marker: warn and treat as missing.
        except Exception as e:  # noqa: BLE001
            logger.warning("Could not read override marker: %s", e)
            return {}

    @staticmethod
    def _text_sha(text: Any) -> str:
        """Return the SHA-256 hex digest of text (None counts as empty)."""
        return hashlib.sha256((text or "").encode()).hexdigest()

    def overrides_apply(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """``DNSW_OVERRIDES_APPLY`` — re-validate, render and serve an override set."""
        # Re-validate the overrides locally; reject the set if anything is invalid.
        try:
            clean = validate_overrides(data.get("overrides"))
        # Invalid override set: refuse it and say why.
        except DnsOverrideError as e:
            return {"status": "ERROR", "rejected": True,
                    "message": f"invalid override set: {e}"}
        # Recompute the digest and reject the frame if it does not match the claimed one.
        digest = overrides_digest(clean)
        claimed = str(data.get("digest") or "")
        if claimed and claimed != digest:
            logger.warning("Rejected DNS override set v%s: digest mismatch", data.get("version"))
            return {"status": "ERROR", "rejected": True,
                    "message": (f"override digest mismatch (coordinator "
                                f"{claimed[:12]}…, local {digest[:12]}…)")}
        # Render the Unbound config text and hand it to the manager to write and reload.
        text = render_unbound(clean)
        result = self.mgr.write_overrides(text)
        # Write/reload failed: log it and pass the manager's error back.
        if result.get("status") != "SUCCESS":
            logger.warning("DNS override set v%s failed to apply: %s",
                           data.get("version"), result.get("message") or result)
            return result
        # Log what is now being served.
        logger.info("Serving DNS overrides v%s: %d profile(s), %d assignment(s)%s",
                    data.get("version"), len(clean["profiles"]), len(clean["assignments"]),
                    "" if result.get("changed") else " (unchanged)")
        # Marker records the version, digest, a hash of the exact file text, and render revision,
        # so overrides_state can later detect stale or edited files.
        marker = {"version": data.get("version"), "digest": digest,
                  "file_sha": self._text_sha(text), "render": RENDER_REVISION,
                  "at": time.time()}
        # Persist the marker atomically: create the folder, write a temp file, then rename.
        try:
            directory = os.path.dirname(self._overrides_marker_path)
            if directory:
                os.makedirs(directory, exist_ok=True)
            tmp = self._overrides_marker_path + ".tmp"
            with open(tmp, "w") as fh:
                json.dump(marker, fh)
            os.replace(tmp, self._overrides_marker_path)
        # Saving the marker failed; the overrides are already live, so just warn.
        except Exception as e:  # noqa: BLE001 — the config is already live
            logger.warning("Could not persist override marker: %s", e)
        # Report success with counts.
        return {"status": "SUCCESS", "digest": digest,
                "version": data.get("version"), "changed": result.get("changed"),
                "profiles": len(clean["profiles"]),
                "assignments": len(clean["assignments"])}

    def overrides_state(self, _data: Dict[str, Any]) -> Dict[str, Any]:
        """``DNSW_OVERRIDES_STATE`` — the override set this resolver is serving.

        The digest is only trusted while the file on disk still matches what
        this worker wrote; an out-of-band edit reports ``digest: None`` so the
        coordinator re-pushes."""
        # Read the current override file and our marker about it.
        text = self.mgr.read_overrides()
        marker = self._load_overrides_marker()
        # No file and no marker: nothing is configured, which is the known empty digest.
        if text is None and not marker:
            digest = EMPTY_DIGEST
        # Marker from an older renderer: report unknown so the coordinator re-pushes.
        elif marker.get("render", 1) != RENDER_REVISION:
            digest = None  # rendered by an older worker: ask for a re-push
        # File unchanged since we wrote it: trust the recorded digest.
        elif marker.get("file_sha") == self._text_sha(text):
            digest = marker.get("digest")
        # File was edited out of band: report unknown.
        else:
            digest = None
        # Report the digest (or None), version and whether a file exists.
        return {"status": "SUCCESS", "digest": digest,
                "version": marker.get("version"),
                "present": text is not None}

    def _read_log_tail(self, max_bytes: int = 8 * 1024 * 1024):
        """Return the last max_bytes (default 8 MiB) of Unbound's query log as lines.

        Returns:
            A list of lines, or None if the log file does not exist.
        """
        # Seek to near the end so huge logs are not read whole, then decode tolerantly.
        try:
            with open(QUERY_LOG, "rb") as fh:
                fh.seek(0, os.SEEK_END)
                fh.seek(max(0, fh.tell() - max_bytes))
                return fh.read().decode("utf-8", "replace").splitlines()
        # No query log file: let the caller fall back to the journal.
        except FileNotFoundError:
            return None

    @staticmethod
    def _read_journal(minutes: int):
        """Return Unbound's journal lines from the last minutes minutes ([] on any error)."""
        # Ask journalctl for unbound's recent log in unix-timestamp format.
        try:
            r = subprocess.run(["journalctl", "-u", "unbound", "--no-pager", "-o", "short-unix",
                                "--since", f"{int(minutes)} min ago"],
                               capture_output=True, text=True, timeout=15)
            return r.stdout.splitlines()
        # journalctl missing or timed out: return no lines.
        except Exception:  # noqa: BLE001
            return []

    def overrides_verify(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """``DNSW_OVERRIDES_VERIFY`` — live proof the overrides work here: each
        view as loaded in the RUNNING Unbound, plus recent queries from assigned
        clients that were answered (or blocked) from their view."""
        # Lookback window in minutes, default 60, clamped to 1 minute..7 days.
        try:
            minutes = max(1, min(int((data or {}).get("minutes") or 60), 7 * 1440))
        # Non-numeric value: use the default.
        except (TypeError, ValueError):
            minutes = 60
        # Parse the rendered override file to learn which views and clients it defines.
        rendered = parse_rendered(self.mgr.read_overrides() or "")
        # Check each view against the running Unbound.
        views = []
        for view in rendered["views"]:
            # Ask Unbound for the view's local data; success means the view is loaded.
            try:
                r = subprocess.run(["unbound-control", "view_list_local_data", view],
                                   capture_output=True, text=True, timeout=10)
                loaded = r.returncode == 0
                error = "" if loaded else (r.stderr or r.stdout or "unbound-control failed").strip()[:300]
                answers = len([ln for ln in r.stdout.splitlines() if ln.strip()]) if loaded else 0
            # unbound-control missing or timed out: mark the view not loaded.
            except Exception as e:  # noqa: BLE001
                loaded, error, answers = False, str(e), 0
            # Record the view's load result.
            views.append({"view": view, "loaded": loaded, "answers": answers, "error": error})
        # Check whether Unbound logs local-data answers (needed to see override hits).
        opt = self.mgr._run_diag(["unbound-control", "get_option", "log-local-actions"])
        # Start of the lookback window, and the query log tail to search.
        since = time.time() - minutes * 60
        lines, source = self._read_log_tail(), QUERY_LOG
        # Find queries from assigned clients answered from their view.
        hits = override_hits(lines or [], rendered, since, self.mgr._line_epoch)
        # No hits in the log file: try the journal instead.
        if not hits:
            # Unbound logs to the journal when its logfile is unusable (AppArmor).
            journal = self._read_journal(minutes)
            journal_hits = override_hits(journal, rendered, since, self.mgr._line_epoch)
            # Use the journal if it found hits, or if there was no log file at all.
            if journal_hits or lines is None:
                hits, source = journal_hits, ("journal" if journal else "")
        # Return view load status, hits, logging setting and where hits came from.
        return {"status": "SUCCESS", "views": views, "hits": hits,
                "log_local_actions": opt["output"].strip() == "yes" if opt["ok"] else None,
                "log_source": source}

    def op_table(self) -> Dict[str, Any]:
        """Return the complete map of command names this worker accepts to handler methods."""
        # Anything not in this table is rejected by the transport.
        return {
            "DNSW_APPLY": self.apply,
            "DNSW_STATE": self.state,
            "DNSW_STATUS": self.status,
            "DNSW_DIAGNOSTICS": self.diagnostics,
            "DNSW_STATS": self.stats,
            "DNSW_CLIENT_QUERIES": self.client_queries,
            "DNSW_FORWARDERS": self.forwarders,
            "DNSW_FORWARDER_ADD": self.add_forwarder,
            "DNSW_FORWARDER_UPDATE": self.update_forwarder,
            "DNSW_FORWARDER_REMOVE": self.remove_forwarder,
            "DNSW_OVERRIDES_APPLY": self.overrides_apply,
            "DNSW_OVERRIDES_STATE": self.overrides_state,
            "DNSW_OVERRIDES_VERIFY": self.overrides_verify,
            "DNSW_STANDDOWN": self.standdown,
        }


def build_worker(member_id: str, coordinator_url: str, secret: str,
                 conf_path: str = DEFAULT_CONF,
                 state_path: str = DEFAULT_STATE):
    """Wire the op table into the shared cluster worker transport."""
    # Import the shared worker transport; its path differs between layouts.
    try:
        from core.src.messaging.service_cluster import ServiceWorkerClient
    # Flat layout: core/src is on sys.path directly.
    except ImportError:
        from messaging.service_cluster import ServiceWorkerClient  # type: ignore
    # Create the Unbound manager; stats history lives next to the applied-state file.
    mgr = UnboundManager(conf_path=conf_path, stats_history_path=os.path.join(
        os.path.dirname(state_path) or ".", "stats_history.json"))
    # Start sampling query statistics in the background.
    mgr.start_stats_sampler()
    # Build the operation table on top of the manager.
    ops = DnsWorkerOps(mgr, state_path=state_path)
    # default_port drives the URL normalization, which REJECTS a plaintext
    # ws:// to a remote coordinator (the PSK rides in the handshake).
    return ServiceWorkerClient(member_id, coordinator_url, secret,
                               ops.op_table(), hostname=os.uname().nodename,
                               default_port=DEFAULT_COORDINATOR_PORT)


def main() -> None:
    """Parse settings from command line/environment and run the worker until stopped."""
    # Each option falls back to an environment variable so systemd can configure it.
    parser = argparse.ArgumentParser(description="Lab Manager DNS cluster worker")
    parser.add_argument("--id", default=os.getenv("LM_DNS_MEMBER_ID", ""),
                        help="cluster member id (must match the module's member list)")
    parser.add_argument("--coordinator", default=os.getenv("LM_DNS_COORDINATOR", ""),
                        help="wss://<dns-module-host>:8769/ws/agent")
    parser.add_argument("--secret", default=os.getenv("LM_DNS_WORKER_SECRET", ""),
                        help="shared worker secret (matches the module's agent_secret)")
    parser.add_argument("--conf", default=os.getenv("UNBOUND_CONF", DEFAULT_CONF))
    parser.add_argument("--state", default=os.getenv("LM_DNS_WORKER_STATE", DEFAULT_STATE))
    # Parse the command line into args.
    args = parser.parse_args()
    # Member id, coordinator URL and secret are all required.
    if not args.id:
        parser.error("--id is required (or LM_DNS_MEMBER_ID in the environment)")
    if not args.coordinator or not args.secret:
        parser.error("--coordinator and --secret are required "
                     "(or LM_DNS_COORDINATOR / LM_DNS_WORKER_SECRET)")
    # Log to stderr with timestamps; force replaces any handlers installed earlier.
    logging.basicConfig(
        level=logging.INFO, force=True,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    # Build the worker and run its connection loop until the process is stopped.
    worker = build_worker(args.id, args.coordinator, args.secret,
                          conf_path=args.conf, state_path=args.state)
    asyncio.run(worker.run())


# Run main() when executed as a script.
if __name__ == "__main__":
    main()
