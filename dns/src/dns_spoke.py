"""Lab Manager DNS spoke: manages Unbound records and override profiles via DNS workers.

The spoke is the coordinator. It owns the versioned record set and per-client override
profiles, fans changes out to the resolver workers that connect to it, and runs a
background loop that re-pushes to any worker that has drifted.
"""
# Background reconcile loop.
import asyncio
# Logging.
import logging
# Paths and environment variables.
import os
# Path handling.
from pathlib import Path
# Generating worker secrets.
import secrets
# Host name lookups.
import socket
# Type hints.
from typing import Any, Dict, List, Optional

# Base spoke class; the import path differs between deployment layouts.
try:
    from base_spoke import BaseSpoke
except ImportError:
    from core.src.base_spoke import BaseSpoke

# Unbound config manager.
from unbound_manager import UnboundManager

# Record-set cluster coordination.
from dns_cluster import (
    DEFAULT_CLUSTER_CONFIG, DEFAULT_DESIRED_STATE, DNS_WORKER_OPS,
    DnsClusterCoordinator, DnsDesiredState, DnsRecordError,
    DnsStateUnavailable, load_cluster_config, save_cluster_config,
)
# Per-client override profiles.
from dns_overrides import (
    DEFAULT_OVERRIDES_STATE, DnsOverrideCoordinator, DnsOverrideError,
    DnsOverrideState, DnsOverrideStateUnavailable, assign, delete_profile,
    unassign, upsert_profile,
)

# Module logger.
logger = logging.getLogger("DNSSpoke")

#: How often the coordinator re-checks every worker's applied record set and
#: re-pushes to any that drifted. Also the reconnect-convergence window: a
#: resolver that reboots is brought back to the desired set within one pass.
RECONCILE_INTERVAL_S = 30.0

# Commands that manage override profiles.
_OVERRIDE_COMMANDS = (
    "DNS_OVERRIDES", "DNS_OVERRIDE_PROFILE_SET", "DNS_OVERRIDE_PROFILE_DELETE",
    "DNS_OVERRIDE_ASSIGN", "DNS_OVERRIDE_UNASSIGN", "DNS_OVERRIDES_VERIFY",
)


class _DisabledTransport:
    """Null transport used when the core cluster module isn't available.

    ``dns`` and ``lm`` deploy independently, so a spoke can be newer than the
    core beside it. Degrading to single-host is correct; crashing is not.
    """

    enabled = False

    def set_members(self, members):
        """Accept a member list and ignore it; returns no members."""
        # No members are ever stored.
        return []

    def member_ids(self):
        """Return no member ids."""
        # There are never members.
        return []

    def member_links(self):
        """Return no member links."""
        # There are never links.
        return []

    async def fanout(self, command, data, timeout=20.0, member_ids=None):
        """Fail every fan-out because no transport exists."""
        # Report the missing transport as an error.
        return {"status": "ERROR", "results": {}, "ok": [], "failed": [],
                "message": "cluster transport unavailable"}

    async def call(self, member_id, command, data, timeout=20.0):
        """Fail every single-member call because no transport exists."""
        # Report the missing transport as an error.
        return {"status": "ERROR", "message": "cluster transport unavailable"}


class DNSSpoke(BaseSpoke):
    """
    Unbound DNS spoke.

    Two deployment shapes, one command surface:

    * **Management only.** This spoke never manages a local Unbound service.
      With no configured workers it reports that DNS Server is not configured.
    * **Server workers.** One or more resolver hosts run ``lm-dns-worker`` and dial
      this spoke's ``/ws/agent`` listener. The spoke becomes the authoritative
      owner of a versioned record set and fans every change out to all members —
      see ``dns_cluster.py``. Two or more workers provide resolver redundancy.

    Commands:
      DNS_SYNC          — replace all managed records (list of record dicts)
      DNS_LIST          — return all managed records
      DNS_ADD           — add a single record
      DNS_DELETE        — delete a record by name (+ optional type)
      DNS_STATUS        — Unbound process status + record count
      DNS_DIAGNOSTICS   — service/config/listener/query health evidence
      DNS_STATS         — unbound-control stats_noreset + per-name breakdown
      DNS_CLIENT_QUERIES — timestamped per-client query log ("Pi-hole style")
      DNS_CLUSTER_STATUS    — member stats, convergence, drift, recommendations
      DNS_CLUSTER_CONFIG    — set the resolver member list (+ worker secret)
      DNS_CLUSTER_RECONCILE — force an immediate reconcile pass
      DNS_OVERRIDES               — per-client override profiles + assignments
      DNS_OVERRIDE_PROFILE_SET    — create/replace/rename an override profile
      DNS_OVERRIDE_PROFILE_DELETE — delete an (unassigned) override profile
      DNS_OVERRIDE_ASSIGN         — apply a profile to a client IP or subnet
      DNS_OVERRIDES_VERIFY        — live check: views loaded + recent override answers
      DNS_OVERRIDE_UNASSIGN       — remove a client's override
    """

    def __init__(self, spoke_id: str, config: Dict[str, Any]):
        """Build the spoke, its Unbound manager, cluster coordinator and override coordinator.

        Args:
            spoke_id: This spoke's id.
            config: Spoke configuration.
        """
        # Base spoke setup.
        super().__init__(spoke_id, config)
        # Local Unbound manager for the managed conf file.
        conf_path = config.get("unbound_conf", "/etc/unbound/conf.d/lm-netbox.conf")
        self.mgr = UnboundManager(conf_path=conf_path)

        # Where the member list is persisted.
        self._cluster_config_path = config.get(
            "cluster_config",
            os.getenv("LM_DNS_CLUSTER_CONFIG", DEFAULT_CLUSTER_CONFIG))
        # Member list from config, else from the persisted file.
        members = config.get("cluster_members")
        if members is None:
            members = load_cluster_config(self._cluster_config_path).get("members", [])
        # Persisted desired record set.
        self.desired = DnsDesiredState(config.get(
            "desired_state",
            os.getenv("LM_DNS_DESIRED_STATE", DEFAULT_DESIRED_STATE)))
        # Worker transport and the record-set coordinator on top of it.
        self._transport = self._build_transport(members)
        self.cluster = DnsClusterCoordinator(self._transport, self.desired)
        # Override state lives next to the desired state unless configured otherwise.
        desired_path = self.desired.state_path or DEFAULT_DESIRED_STATE
        self.overrides = DnsOverrideCoordinator(
            self._transport,
            DnsOverrideState(config.get(
                "overrides_state",
                os.getenv("LM_DNS_OVERRIDES_STATE", os.path.join(
                    os.path.dirname(desired_path) or ".",
                    os.path.basename(DEFAULT_OVERRIDES_STATE))))),
            self.cluster.transaction)
        # Background reconcile task, started later by the control plane.
        self._reconcile_task: Optional[asyncio.Task] = None

    # ── Cluster plumbing ────────────────────────────────────────────────────

    def _build_transport(self, members):
        """Wrap the shared coordinator transport around this spoke's listener.

        Imported lazily: the transport lives in the LM ``core`` repo, which
        deploys independently of this one. A core without it leaves the cluster
        disabled instead of crashing a working single-host spoke.
        """
        # Import the shared transport; its path differs between layouts.
        try:
            try:
                from core.src.messaging.service_cluster import ClusterCoordinator
            except ImportError:
                from messaging.service_cluster import ClusterCoordinator  # type: ignore
        # No transport in this core: stay single-host.
        except ImportError:
            logger.info("Cluster transport unavailable in this core build — "
                        "DNS stays single-host")
            return _DisabledTransport()
        # Coordinator for the "dns" service, limited to the DNS worker ops.
        return ClusterCoordinator("dns", DNS_WORKER_OPS,
                                  lambda: getattr(self, "control_plane", None),
                                  members=members)

    def cluster_listener_required(self) -> bool:
        """Tells the control plane whether to bind the DNS ``/ws/agent`` port.

        One or more DNS Server workers require the management listener.
        """
        # Listener needed when any worker is configured.
        return bool(self.cluster.enabled)

    def start_background_loops(self) -> None:
        """Process-scoped hook invoked by the control plane (standalone spoke or
        the generic agent's ``RoleConnection``). Starts the reconcile loop."""
        # Already running: do nothing.
        if self._reconcile_task and not self._reconcile_task.done():
            return
        # Need a running event loop to start the task.
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            logger.debug("No running loop — DNS reconcile loop not started")
            return
        # Start the loop.
        self._reconcile_task = loop.create_task(self._reconcile_loop())

    def stop_background_loops(self) -> None:
        """Cancel the reconcile loop. Called by the control plane when the role
        is unloaded, so the task does not survive the sub-spoke and keep
        re-pushing to workers a torn-down coordinator no longer owns."""
        # Detach the task, then cancel it if it is still running.
        task = self._reconcile_task
        self._reconcile_task = None
        if task is not None and not task.done():
            task.cancel()
        # Return the task so the caller can await it.
        return task

    async def _reconcile_loop(self) -> None:
        """Every interval, reconcile records and overrides on all workers until cancelled."""
        # Run forever.
        while True:
            # Wait one interval.
            await asyncio.sleep(RECONCILE_INTERVAL_S)
            # No workers: skip this pass.
            if not self.cluster.enabled:
                continue
            # Reconcile records, then overrides; a failure is logged and the loop continues.
            try:
                result = await self.cluster.reconcile()
                if result.get("reconciled"):
                    logger.info("DNS reconcile re-pushed v%s to %s",
                                result.get("version"), result["reconciled"])
                await self.overrides.reconcile()
            # Let cancellation stop the loop.
            except asyncio.CancelledError:
                raise
            except Exception as e:  # noqa: BLE001 — a bad pass must not kill the loop
                logger.warning("DNS reconcile pass failed: %s", e)

    async def _apply_cluster_config(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """``DNS_CLUSTER_CONFIG`` — declare which resolver hosts this module owns.

        ``worker_secret`` is write-only: it sets the PSK the workers
        authenticate with and is never echoed back. Enabling a cluster for the
        first time REQUIRES one — the spoke will not mint a value the operator
        can never read and therefore could never give to the workers.

        Topology changes are candidate-first: the previous member list is
        restored in memory on any failure, so a rejected save never leaves the
        live coordinator on a topology it did not persist.

        On the transition single-host → cluster the current managed record set is
        ADOPTED as v1 before the listener comes up, so the first reconcile pass
        cannot push an empty default over resolvers that are already answering.
        """
        # Members must be supplied as a list.
        raw = data.get("members")
        if raw is None:
            return {"status": "ERROR", "message": "members is required"}
        if not isinstance(raw, list):
            return {"status": "ERROR", "message": "members must be a list"}
        # ONE critical section for validate → persist → rebind → seed → stand
        # down, sharing the lock every apply/reconcile takes: a topology edit
        # must never interleave with a record fan-out.
        async with self.cluster.transaction():
            return await self._apply_cluster_config_locked(raw, data)

    async def _enroll_worker(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Add one LM-discovered DNS Server and return its ephemeral bootstrap."""
        # Need a member object with an id.
        raw = data.get("member")
        if not isinstance(raw, dict):
            return {"status": "ERROR", "message": "member is required"}
        member_id = str(raw.get("id") or raw.get("member_id") or "").strip()
        if not member_id:
            return {"status": "ERROR", "message": "member.id is required"}

        # Get the current worker secret from the control plane, if any.
        cp = getattr(self, "control_plane", None)
        secret = (cp.snapshot_agent_secret()
                  if cp is not None and hasattr(cp, "snapshot_agent_secret")
                  else "")
        # Use the existing secret, or generate one if none is set yet.
        secret = str(secret or "").strip() or secrets.token_urlsafe(32)
        # Under the shared lock, replace any entry for this id and add the new member.
        async with self.cluster.transaction():
            members = [dict(m) for m in self._transport.members
                       if str(m.get("id") or "") != member_id]
            members.append({
                "id": member_id,
                "host": str(raw.get("host") or "").strip(),
                "role": str(raw.get("role") or "").strip(),
            })
            # Apply the new member list; seeding is deferred until the worker connects.
            result = await self._apply_cluster_config_locked(
                members, {"worker_secret": secret}, defer_seed=True)
        # Stop if the topology change failed.
        if result.get("status") not in ("SUCCESS", "PARTIAL"):
            return result

        # Read the coordinator's TLS certificate so the worker can trust it.
        cert_path = Path(
            str(getattr(cp, "_listener_cert", "") or
                "/etc/lm-dns/tls/coordinator.crt"))
        try:
            ca_pem = cert_path.read_text(encoding="utf-8")
        # Certificate unreadable: fail.
        except OSError as exc:
            return {"status": "ERROR",
                    "message": f"could not read DNS coordinator certificate: {exc}"}
        # Must look like a PEM certificate.
        if "-----BEGIN CERTIFICATE-----" not in ca_pem:
            return {"status": "ERROR",
                    "message": "DNS coordinator certificate is invalid"}

        # This host's name, for the worker's coordinator URL.
        coordinator = socket.getfqdn() or socket.gethostname()
        # Return the bootstrap bundle for the worker.
        return {
            "status": result.get("status", "SUCCESS"),
            "member": member_id,
            "coordinator": coordinator,
            "worker_secret": secret,
            "coordinator_ca_pem": ca_pem,
        }

    async def _finalize_worker_enrollment(self) -> Dict[str, Any]:
        """Adopt live worker records before allowing the first DNS mutation."""
        # Under the shared lock, at least one worker must be connected.
        async with self.cluster.transaction():
            connected = self._transport.connected_ids()
            if not connected:
                return {"status": "ERROR",
                        "message": "No enrolled DNS Server worker is connected yet"}
            # Seed from every worker; fail if any cannot be read.
            seeded = await self.cluster.seed(
                [], locked=True, require_all_members=True)
            if seeded.get("status") == "ERROR":
                return seeded
            # Nothing to adopt: commit an empty set as v1 so mutations can start.
            if self.desired.version == 0:
                version, _changed = self.desired.set_records([])
                seeded = {
                    "status": "SUCCESS",
                    "seeded": True,
                    "source": "connected-empty-workers",
                    "version": version,
                    "record_count": 0,
                }
            # Report the connected workers and the seed result.
            return {"status": "SUCCESS", "connected": connected,
                    "seed": seeded, "version": self.desired.version}

    async def _apply_cluster_config_locked(
            self, raw, data, *, defer_seed=False) -> Dict[str, Any]:
        """Apply a new worker list; caller holds the transaction lock.

        Args:
            raw: New member list.
            data: Request data, possibly including worker_secret.
            defer_seed: Skip seeding (enrollment seeds later, once workers connect).

        Returns:
            Result dict; on any failure the previous topology and secret are restored.
        """
        # Remember the old topology so failures can restore it.
        previous_members = [dict(m) for m in self._transport.members]
        was_enabled = self.cluster.enabled

        # Install the candidate members; reject a list with no usable entries.
        members = self._transport.set_members(raw)
        if raw and not members:
            self._transport.set_members(previous_members)
            return {"status": "ERROR",
                    "message": "no usable members — each needs a non-empty id"}

        # A secret must exist (new or current) to enable the cluster.
        cp = getattr(self, "control_plane", None)
        secret = str(data.get("worker_secret") or "").strip()
        enabling = bool(members)
        have_secret = bool(getattr(cp, "agent_secret", "") or "")
        if enabling and not secret and not have_secret:
            self._transport.set_members(previous_members)
            return {"status": "ERROR", "secret_required": True,
                    "message": ("A worker secret is required to enable the DNS "
                                "resolver cluster. Supply the same value here and "
                                "to each resolver's installer (--worker-secret); "
                                "it is stored write-only and never displayed "
                                "again.")}

        # Refuse topology changes while the desired state is broken.
        if self.cluster.state_error:
            self._transport.set_members(previous_members)
            return {"status": "ERROR", "state_unavailable": True,
                    "message": self.cluster.state_error}

        # Members being removed in this change.
        removing = [m["id"] for m in previous_members
                    if m.get("id") not in {n["id"] for n in members}]
        # Persist the new list; restore the old one in memory if that fails.
        try:
            save_cluster_config(self._cluster_config_path, members)
        except Exception as e:  # noqa: BLE001
            self._transport.set_members(previous_members)
            return {"status": "ERROR",
                    "message": f"could not persist cluster config: {e}"}

        # Stage the PSK: capture the one in force so any later failure can put
        # it back. Overwriting it and then rolling the topology back left every
        # already-provisioned resolver unable to authenticate.
        previous_secret = None
        if secret and cp is not None and hasattr(cp, "set_agent_secret"):
            if hasattr(cp, "snapshot_agent_secret"):
                previous_secret = cp.snapshot_agent_secret()
            cp.set_agent_secret(secret)

        def _restore_secret():
            """Put back the secret that was in force before this change, if one was replaced."""
            # Only when we actually replaced one.
            if previous_secret is not None and hasattr(cp, "restore_agent_secret"):
                cp.restore_agent_secret(previous_secret)

        # Make sure the worker listener is running (default: no listener needed).
        listener = {"ok": True, "serving": False, "endpoint": "", "error": ""}
        if cp is not None and hasattr(cp, "ensure_cluster_listener"):
            listener = await cp.ensure_cluster_listener() or listener
            if isinstance(listener, bool):        # older core: no readiness
                listener = {"ok": listener, "serving": listener,
                            "endpoint": "", "error": ""}
        # Enabling without a working listener: roll everything back.
        if enabling and not listener.get("ok"):
            # The workers can never reach a listener that did not start, so
            # reporting SUCCESS here would be a lie the operator only discovers
            # when nothing converges.
            self._transport.set_members(previous_members)
            _restore_secret()
            try:
                save_cluster_config(self._cluster_config_path, previous_members)
            except Exception:  # noqa: BLE001
                pass
            return {"status": "ERROR", "listener": listener,
                    "message": (f"the DNS cluster listener did not start: "
                                f"{listener.get('error') or 'unknown error'}")}

        # Turning the cluster on: adopt the existing records as v1.
        seeded = {}
        if enabling and not was_enabled and not defer_seed:
            try:
                seeded = await self._seed_desired_state()
            except DnsStateUnavailable as e:
                # The seed could not be recorded: roll the topology back rather
                # than run a cluster whose authoritative set is unknown.
                self._transport.set_members(previous_members)
                _restore_secret()
                try:
                    save_cluster_config(self._cluster_config_path,
                                        previous_members)
                except Exception:  # noqa: BLE001
                    pass
                return {"status": "ERROR", "state_unavailable": True,
                        "message": (f"could not adopt the existing record set: "
                                    f"{e} — the cluster was not enabled")}
            if seeded.get("status") == "ERROR":
                # Divergent resolvers: adopting either set would erase the
                # other's unique records. Leave the module single-host until an
                # operator reconciles them.
                self._transport.set_members(previous_members)
                _restore_secret()
                try:
                    save_cluster_config(self._cluster_config_path,
                                        previous_members)
                except Exception:  # noqa: BLE001
                    pass
                return {"status": "ERROR", "seed": seeded,
                        "divergent": True, "message": seeded["message"]}

        # Tell removed workers to leave, then build the result.
        stood_down, unreachable = await self._standdown_removed(removing)
        result = {"status": "SUCCESS", "members": members,
                  "cluster_enabled": self.cluster.enabled,
                  "seed": seeded,
                  "listener": {**self._listener_hint(), **listener}}
        # Report removals; unreachable removed workers make the result PARTIAL.
        if removing:
            result["removed"] = removing
            result["removed_stood_down"] = stood_down
            result["removed_unreachable"] = unreachable
            if unreachable:
                result["status"] = "PARTIAL"
                result["message"] = (
                    "Topology saved, but these removed resolver(s) could not be "
                    "deconfigured and still hold their cluster marker: "
                    + ", ".join(unreachable)
                    + ". Stop lm-dns-worker on them (their records are left in "
                      "place so they keep answering).")
        # Return the result.
        return result

    async def _seed_desired_state(self) -> Dict[str, Any]:
        """Adopt records already served by the configured DNS Server workers."""
        # Already inside the coordinator transaction (see
        # _apply_cluster_config_locked), so do not re-take the lock.
        return await self.cluster.seed([], locked=True)

    async def _standdown_removed(self, removed):
        """Ask removed resolvers to drop their cluster marker; report failures."""
        # Ask each removed worker to stand down and sort them by outcome.
        stood_down, unreachable = [], []
        for member_id in removed or []:
            reply = await self._transport.call(member_id, "DNSW_STANDDOWN", {},
                                               timeout=20.0)
            if isinstance(reply, dict) and reply.get("status") == "SUCCESS":
                stood_down.append(member_id)
            else:
                unreachable.append(member_id)
        # Return both lists.
        return stood_down, unreachable

    def _listener_hint(self) -> Dict[str, Any]:
        """Return the worker listener's port, path and whether it is running."""
        # Control plane, if attached.
        cp = getattr(self, "control_plane", None)
        # Port from the environment (default 8769) and whether the server task exists.
        return {"port": int(os.environ.get("LM_DNS_AGENT_PORT", "8769")),
                "path": "/ws/agent",
                "serving": bool(getattr(cp, "_agent_server_task", None))}

    async def _cluster_status(self) -> Dict[str, Any]:
        """``DNS_CLUSTER_STATUS`` — refresh worker state and return the cluster report."""
        # Refresh, then report.
        await self.cluster.refresh_state()
        return {"status": "SUCCESS", **self.cluster.cluster_report()}

    async def _cluster_diagnostics(self) -> Dict[str, Any]:
        """Per-member diagnostics + the convergence view.

        The top-level evidence keys are carried from ONE named member
        (``diagnostics_source``) so the existing Diagnostics panels keep
        rendering real data, while ``members`` holds every resolver's own
        evidence and ``healthy`` requires all of them AND convergence.
        """
        # Refresh convergence and build the cluster report.
        await self.cluster.refresh_state()
        report = self.cluster.cluster_report()
        # Collect every worker's diagnostics; non-dict replies become errors.
        fan = await self._transport.fanout("DNSW_DIAGNOSTICS", {}, timeout=25.0)
        per_member: Dict[str, Any] = {}
        for member_id, reply in (fan.get("results") or {}).items():
            per_member[member_id] = reply if isinstance(reply, dict) else {
                "status": "ERROR", "message": "malformed reply"}

        # Take top-level evidence from the first worker that answered successfully.
        source = next((m["id"] for m in report["members"]
                       if (per_member.get(m["id"]) or {}).get("status") == "SUCCESS"), "")
        base: Dict[str, Any] = dict(per_member.get(source) or {})
        base.pop("member_id", None)
        # Merge recommendations: per-worker ones (prefixed) then the cluster's.
        recommendations: List[str] = []
        for member_id, diag in per_member.items():
            if diag.get("status") != "SUCCESS":
                recommendations.append(
                    f"[{member_id}] diagnostics unavailable: "
                    f"{diag.get('message') or 'no response'}")
                continue
            for rec in diag.get("recommendations") or []:
                recommendations.append(f"[{member_id}] {rec}")
        recommendations.extend(report["recommendations"])

        # Healthy only if every worker is healthy and the cluster has converged.
        members_healthy = bool(per_member) and all(
            d.get("status") == "SUCCESS" and d.get("healthy")
            for d in per_member.values())
        # Return the combined diagnostics.
        return {
            **base,
            "status": "SUCCESS",
            "healthy": bool(members_healthy and report["converged"]),
            "diagnostics_source": source,
            "cluster": report,
            "members": per_member,
            "recommendations": recommendations,
        }

    async def _cluster_stats(self, search: str = None, source_prefixes: list = None,
                             range_days: int = None,
                             range_seconds: int = None) -> Dict[str, Any]:
        """Cluster stats: per-member counters plus the summed headline totals.
        With a range, each member's counters are already that window's
        increase; the combined ``window`` is partial if any member's is."""
        # Build the request payload from only the filters that were given.
        payload = {}
        if search:
            payload["search"] = search
        # `is not None`: an empty list is a tenant with no prefixes and must
        # reach each member so it fails CLOSED, not be dropped (= unfiltered).
        if source_prefixes is not None:
            payload["source_prefixes"] = source_prefixes
        # Optional time window.
        if range_days:
            payload["range_days"] = range_days
        if range_seconds:
            payload["range_seconds"] = range_seconds
        # Ask every worker for its stats.
        fan = await self._transport.fanout("DNSW_STATS", payload, timeout=20.0)
        # Per-worker replies, errors, and summed headline counters.
        per_member: Dict[str, Any] = {}
        member_errors: Dict[str, str] = {}
        totals = {"total_queries": 0, "cache_hits": 0, "cache_misses": 0,
                  "num_recursive": 0, "prefetch": 0}
        # recursion_time_avg is an AVERAGE, so it cannot be summed like the
        # counters above. Summing was not the bug -- it was never carried at
        # all, so a clustered Statistics page reported "avg 0s" no matter what
        # either resolver measured. Combine it the only correct way: weight
        # each member's average by the recursions it actually served.
        recursion_time_weighted = 0.0
        # Sum each successful worker's counters.
        for member_id, reply in (fan.get("results") or {}).items():
            # Keep every reply; record failures and skip them.
            per_member[member_id] = reply
            if not isinstance(reply, dict) or reply.get("status") != "SUCCESS":
                member_errors[member_id] = (
                    (reply.get("message") if isinstance(reply, dict) else None)
                    or "no response")
                continue
            # Add this worker's global counters.
            g = reply.get("global") or {}
            for key in totals:
                totals[key] += int(g.get(key) or 0)
            # Add this worker's recursion time, weighted by its recursion count.
            try:
                recursion_time_weighted += (float(g.get("recursion_time_avg") or 0.0)
                                            * int(g.get("num_recursive") or 0))
            except (TypeError, ValueError):
                pass
        # Derive cache hit ratio and the weighted average recursion time.
        total = totals["total_queries"]
        totals["cache_hit_ratio"] = (round(totals["cache_hits"] / total * 100, 1)
                                     if total else 0.0)
        totals["recursion_time_avg"] = (
            round(recursion_time_weighted / totals["num_recursive"], 4)
            if totals["num_recursive"] else 0.0)
        # Merge query-type counts across workers.
        merged_types: Dict[str, int] = {}
        # query_names is merged across members by (name, type): different
        # resolvers in the same cluster serve the same desired record set, so
        # a name queried against multiple members should show a combined
        # count rather than one arbitrary member's view. Per-source counts are
        # merged the same way so the "who queried this" breakdown stays
        # accurate across the cluster.
        merged_names: Dict[tuple, dict] = {}
        # Combine each successful worker's query types, names and per-source counts.
        for reply in per_member.values():
            if isinstance(reply, dict) and reply.get("status") == "SUCCESS":
                for qtype, count in (reply.get("query_types") or {}).items():
                    merged_types[qtype] = merged_types.get(qtype, 0) + int(count or 0)
                for entry in reply.get("query_names") or []:
                    key = (entry.get("name"), entry.get("type"))
                    g = merged_names.setdefault(key, {"count": 0, "sources": {}})
                    g["count"] += int(entry.get("count") or 0)
                    for s in entry.get("sources") or []:
                        ip = s.get("ip")
                        g["sources"][ip] = g["sources"].get(ip, 0) + int(s.get("count") or 0)
        # Turn merged names into rows, busiest first, with sources sorted by count.
        query_names = sorted(
            ({"name": n, "type": t, "count": g["count"],
              "sources": sorted(
                  ({"ip": ip, "count": c} for ip, c in g["sources"].items()),
                  key=lambda s: s["count"], reverse=True)}
             for (n, t), g in merged_names.items()),
            key=lambda r: r["count"], reverse=True,
        )
        # Build the combined reply.
        out = {"status": "SUCCESS", "global": totals, "query_types": merged_types,
                "query_names": query_names, "cluster": True, "members": per_member,
                # Totals are a SUM across resolvers. If one did not answer the
                # headline numbers silently under-report, so say how many fed
                # them rather than letting the page look authoritative.
                "member_count": len(per_member),
                "members_reporting": len(per_member) - len(member_errors),
                "member_errors": member_errors}
        # With a time window, report how much of it the workers actually covered.
        window_s = range_seconds or (int(range_days) * 86400 if range_days else None)
        if window_s:
            # Successful replies, and the ones that include window info.
            ok = [r for r in per_member.values()
                  if isinstance(r, dict) and r.get("status") == "SUCCESS"]
            wins = [r["window"] for r in ok if isinstance(r.get("window"), dict)]
            # A pre-windowing worker returns lifetime totals: flag it so the
            # page does not present those as the selected window.
            out["window"] = {
                "seconds": window_s,
                "covered_seconds": min((int(w.get("covered_seconds") or 0) for w in wins),
                                       default=0),
                "partial": len(wins) < len(ok) or any(w.get("partial") for w in wins),
                "unsupported_members": len(ok) - len(wins),
            }
        # Return the combined stats.
        return out

    async def _cluster_client_queries(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Merge every member's per-client query log, newest first."""
        # Ask every worker for its query log.
        fan = await self._transport.fanout("DNSW_CLIENT_QUERIES", data, timeout=20.0)
        # Merged queries, per-worker errors, and the number of successful workers.
        queries: List[dict] = []
        errors: Dict[str, str] = {}
        successes = 0
        # Tag each successful worker's queries with the resolver; record failures.
        for member_id, reply in (fan.get("results") or {}).items():
            if not isinstance(reply, dict) or reply.get("status") != "SUCCESS":
                errors[member_id] = (
                    (reply.get("message") if isinstance(reply, dict) else None)
                    or "no response")
                continue
            successes += 1
            for q in reply.get("queries") or []:
                queries.append({**q, "resolver": member_id})
        # Newest first.
        queries.sort(key=lambda q: q.get("time", 0), reverse=True)
        # Count queries per (name, type) for the top-names list.
        summary: Dict[tuple, int] = {}
        for q in queries:
            key = (q.get("name"), q.get("type"))
            summary[key] = summary.get(key, 0) + 1
        # Top 100 names by count.
        top_names = sorted(
            ({"name": n, "type": t, "count": c} for (n, t), c in summary.items()),
            key=lambda x: x["count"], reverse=True)[:100]
        # Pre-fix this was hardcoded "SUCCESS" even when EVERY member failed
        # (e.g. the whole cluster unreachable) -- the headline "0 queries" and
        # a genuine outage were indistinguishable to the caller. Mirrors the
        # PARTIAL convention used elsewhere in this module (status-conflation
        # is exactly what the skeptical review panel flagged). Every member
        # failing is ERROR, not PARTIAL: there is no data at all.
        status = "SUCCESS"
        if errors:
            status = "PARTIAL" if successes else "ERROR"
        # Return up to 1000 queries plus the summary.
        return {"status": status,
                "client": data.get("client", ""),
                "minutes": data.get("minutes", 10), "total": len(queries),
                "queries": queries[:1000], "top_names": top_names,
                "cluster": True, "member_errors": errors}

    async def _cluster_forwarders(self) -> Dict[str, Any]:
        """Upstream forwarders per resolver.

        Forwarders are per-resolver configuration and the coordinator box may
        not run Unbound at all, so this is an allowlisted worker op fanned out
        and aggregated — never the coordinator's own ``unbound-control``.
        Entries are tagged with the member they came from; a member that failed
        is surfaced in ``member_errors`` rather than silently shrinking the
        list."""
        # Ask every worker for its forwarders.
        fan = await self._transport.fanout("DNSW_FORWARDERS", {}, timeout=20.0)
        # Merged forwarders, raw replies, and per-worker errors.
        forwarders: List[Dict[str, Any]] = []
        per_member: Dict[str, Any] = {}
        errors: Dict[str, str] = {}
        # Tag each successful worker's forwarders with its id; record failures.
        for member_id, reply in (fan.get("results") or {}).items():
            per_member[member_id] = reply
            if not isinstance(reply, dict) or reply.get("status") != "SUCCESS":
                errors[member_id] = ((reply or {}).get("message")
                                     or (reply or {}).get("error")
                                     or "no response")
                continue
            for entry in reply.get("forwarders") or []:
                if isinstance(entry, dict):
                    forwarders.append({**entry, "member_id": member_id})
        # Return the combined list.
        return {"status": "SUCCESS", "forwarders": forwarders, "cluster": True,
                "members": per_member, "member_errors": errors}

    async def _cluster_add_forwarder(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Add one forwarding zone to every resolver, rolling back partial writes."""
        # Add the zone on every worker.
        fan = await self._transport.fanout(
            "DNSW_FORWARDER_ADD", data, timeout=20.0)
        # All succeeded.
        if not fan.get("failed"):
            return {"status": "SUCCESS", "zone": data.get("zone"),
                    "upstreams": data.get("upstreams"), "members": fan["results"]}
        # Failed workers whose reply does not say whether they changed anything.
        ambiguous = [
            member_id for member_id in (fan.get("failed") or [])
            if "changed" not in (fan.get("results", {}).get(member_id) or {})
        ]
        # Roll back the workers that applied it and those whose state is unknown.
        rollback_ids = [*(fan.get("ok") or []), *ambiguous]
        rollback = {"status": "SUCCESS", "ok": [], "failed": [], "results": {}}
        if rollback_ids:
            rollback = await self._transport.fanout(
                "DNSW_FORWARDER_REMOVE", {"zone": data.get("zone")},
                timeout=20.0, member_ids=rollback_ids)
        # Build an error with the failed workers and their unique reasons.
        failed = ", ".join(fan.get("failed") or [])
        # Without the members' own messages this reads "not added to all
        # resolvers (<uuid>, <uuid>)" and nothing else, so the actual cause
        # ("already forwards to ...", a bad address, a reload failure) is only
        # recoverable by reading each resolver's log by hand.
        reasons = []
        for member_id in (fan.get("failed") or []):
            reason = str(((fan.get("results") or {}).get(member_id)
                          or {}).get("message") or "").strip()
            if reason and reason not in reasons:
                reasons.append(reason)
        message = f"forwarder was not added to all resolvers ({failed})"
        if reasons:
            message += ": " + "; ".join(reasons)
        # Mention rollback failures too.
        if rollback.get("failed"):
            message += "; rollback also failed on " + ", ".join(rollback["failed"])
        # Return the error with all details.
        return {"status": "ERROR", "message": message,
                "members": fan["results"], "rollback": rollback}

    async def _cluster_remove_forwarder(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Remove one forwarding zone from every resolver."""
        # Zone to remove (default: the root).
        zone = data.get("zone", ".")
        # Remove it on every worker.
        fan = await self._transport.fanout(
            "DNSW_FORWARDER_REMOVE", {"zone": zone}, timeout=20.0)
        # All succeeded.
        if not fan.get("failed"):
            return {"status": "SUCCESS", "zone": zone, "members": fan["results"]}
        # Build an error with the failed workers and their unique reasons.
        failed = ", ".join(fan.get("failed") or [])
        reasons = []
        for member_id in (fan.get("failed") or []):
            reason = str(((fan.get("results") or {}).get(member_id)
                          or {}).get("message") or "").strip()
            if reason and reason not in reasons:
                reasons.append(reason)
        message = f"forwarder was not removed from all resolvers ({failed})"
        if reasons:
            message += ": " + "; ".join(reasons)
        # Return the error.
        return {"status": "ERROR", "message": message, "members": fan["results"]}

    async def _cluster_update_forwarder(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Replace one forwarding zone's upstreams (or rename it) on every resolver."""
        # New zone settings, plus the old name when renaming.
        payload = {
            "zone": data.get("zone", "."),
            "upstreams": data.get("upstreams", []),
            "old_zone": data.get("old_zone"),
        }
        # Update on every worker.
        fan = await self._transport.fanout(
            "DNSW_FORWARDER_UPDATE", payload, timeout=20.0)
        # All succeeded.
        if not fan.get("failed"):
            return {"status": "SUCCESS", "zone": payload["zone"],
                    "upstreams": payload["upstreams"], "members": fan["results"]}
        # Build an error with the failed workers and their unique reasons.
        failed = ", ".join(fan.get("failed") or [])
        reasons = []
        for member_id in (fan.get("failed") or []):
            reason = str(((fan.get("results") or {}).get(member_id)
                          or {}).get("message") or "").strip()
            if reason and reason not in reasons:
                reasons.append(reason)
        message = f"forwarder was not updated on all resolvers ({failed})"
        if reasons:
            message += ": " + "; ".join(reasons)
        # Return the error.
        return {"status": "ERROR", "message": message, "members": fan["results"]}

    async def _cluster_status_summary(self) -> Dict[str, Any]:
        """DNS_STATUS in cluster mode — never one host's answer for the pair."""
        # Refresh convergence and build the report.
        await self.cluster.refresh_state()
        report = self.cluster.cluster_report()
        # Workers reporting Unbound as running.
        running = [m["id"] for m in report["members"] if m.get("unbound_running")]
        # Running only if every worker's Unbound is running.
        return {
            "status": "SUCCESS",
            "running": bool(running) and len(running) == report["member_count"],
            "record_count": self.desired.snapshot()["record_count"],
            "conf_path": self.mgr.conf_path,
            "cluster": report,
        }

    async def _handle_override(self, cmd: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Per-client override profiles (Unbound views) across every worker."""
        # Validation and state errors become error replies.
        try:
            # Read-only commands return directly.
            if cmd == "DNS_OVERRIDES":
                return await self.overrides.snapshot()
            if cmd == "DNS_OVERRIDES_VERIFY":
                return await self.overrides.verify(data.get("minutes") or 60)
            # Build the change for each write command.
            if cmd == "DNS_OVERRIDE_PROFILE_SET":
                change = upsert_profile(data.get("profile") or {},
                                        old_name=data.get("old_name") or None)
            elif cmd == "DNS_OVERRIDE_PROFILE_DELETE":
                change = delete_profile(data.get("name") or "",
                                        force=bool(data.get("force")))
            elif cmd == "DNS_OVERRIDE_ASSIGN":
                change = assign(data.get("target") or data.get("ip"),
                                data.get("profile") or "", data.get("label") or "",
                                data.get("comment") or "", data.get("old_target") or None)
            # Anything else here is DNS_OVERRIDE_UNASSIGN.
            else:
                change = unassign(data.get("target") or data.get("ip"))
            # Apply the change on every worker.
            return await self.overrides.mutate(change)
        # Invalid input.
        except DnsOverrideError as e:
            return {"status": "ERROR", "message": str(e)}
        # Override state is broken: fail closed.
        except DnsOverrideStateUnavailable as e:
            return {"status": "ERROR", "message": str(e), "state_unavailable": True}

    # ── Command dispatch ────────────────────────────────────────────────────

    async def handle_command(self, command_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatch one hub command to its handler.

        Args:
            command_type: Command name (case-insensitive).
            data: Command payload.

        Returns:
            Result dict for the hub.
        """
        # Commands are matched upper-case.
        cmd = command_type.upper()

        # Version query.
        if cmd == "GET_VERSION":
            return {"status": "SUCCESS", "version": self.get_version()}

        # Cluster topology and enrollment commands.
        if cmd == "DNS_CLUSTER_CONFIG":
            return await self._apply_cluster_config(data)

        if cmd == "DNS_CLUSTER_ENROLL_WORKER":
            return await self._enroll_worker(data)

        if cmd == "DNS_CLUSTER_FINALIZE_ENROLLMENT":
            return await self._finalize_worker_enrollment()

        # Cluster status: error on broken state, disabled reply with no workers.
        if cmd == "DNS_CLUSTER_STATUS":
            if self.cluster.state_error:
                return {"status": "ERROR", "enabled": True,
                        "state_unavailable": True,
                        "message": self.cluster.state_error}
            if not self.cluster.enabled:
                return {"status": "SUCCESS", "enabled": False, "members": [],
                        "member_count": 0,
                        "reason": "no DNS Server workers configured"}
            return await self._cluster_status()

        # Forced reconcile requires an enabled cluster.
        if cmd == "DNS_CLUSTER_RECONCILE":
            if not self.cluster.enabled:
                return {"status": "ERROR", "message": "DNS cluster is not enabled"}
            return await self.cluster.reconcile()

        # ── Clustered path: the coordinator owns the record set ──────────────
        if self.cluster.enabled:
            # Bad records and broken state become error replies.
            try:
                # Writes are blocked until enrollment has committed a first version.
                if cmd in ("DNS_SYNC", "DNS_DELETE", "DNS_ADD", "DNS_UPDATE") \
                        and self.desired.version == 0:
                    return {
                        "status": "ERROR",
                        "initializing": True,
                        "message": (
                            "DNS Server enrollment is still initializing. "
                            "Wait for a worker to connect so its existing records "
                            "can be adopted safely."),
                    }
                # Replace the whole record set.
                if cmd == "DNS_SYNC":
                    return await self.cluster.apply_records(data.get("records", []))
                # Delete by name (and optional type).
                if cmd == "DNS_DELETE":
                    if not data.get("name"):
                        return {"status": "ERROR", "message": "name is required"}
                    return await self.cluster.mutate("delete", data)
                # Add or update a single record.
                if cmd in ("DNS_ADD", "DNS_UPDATE"):
                    if not data.get("name") or not data.get("value"):
                        return {"status": "ERROR",
                                "message": "name and value are required"}
                    return await self.cluster.mutate(
                        "add" if cmd == "DNS_ADD" else "update", data)
            # Invalid record.
            except DnsRecordError as e:
                return {"status": "ERROR", "message": str(e)}
            except DnsStateUnavailable as e:
                # Fail closed: the authoritative record set is untrustworthy, so
                # no resolver is touched until an operator repairs it.
                return {"status": "ERROR", "message": str(e),
                        "state_unavailable": True}
            # Read and diagnostic commands answered from the cluster.
            if cmd == "DNS_LIST":
                return {"status": "SUCCESS", "records": list(self.desired.records),
                        "cluster": True, "version": self.desired.version}
            if cmd == "DNS_STATUS":
                return await self._cluster_status_summary()
            if cmd == "DNS_DIAGNOSTICS":
                return await self._cluster_diagnostics()
            if cmd == "DNS_STATS":
                return await self._cluster_stats(search=data.get("search"),
                                                 source_prefixes=data.get("source_prefixes"),
                                                 range_days=data.get("range_days"),
                                                 range_seconds=data.get("range_seconds"))
            if cmd == "DNS_CLIENT_QUERIES":
                return await self._cluster_client_queries(data)
            if cmd == "DNS_FORWARDERS":
                return await self._cluster_forwarders()
            if cmd == "DNS_FORWARDER_ADD":
                return await self._cluster_add_forwarder(data)
            if cmd in ("DNS_FORWARDER_REMOVE", "DNS_FORWARDER_DELETE"):
                return await self._cluster_remove_forwarder(data)
            if cmd in ("DNS_FORWARDER_UPDATE", "DNS_FORWARDER_EDIT"):
                return await self._cluster_update_forwarder(data)
            if cmd in _OVERRIDE_COMMANDS:
                return await self._handle_override(cmd, data or {})

        # Known DNS commands but no workers configured.
        if cmd in {
            "DNS_SYNC", "DNS_LIST", "DNS_ADD", "DNS_UPDATE", "DNS_DELETE",
            "DNS_STATUS", "DNS_DIAGNOSTICS", "DNS_STATS", "DNS_CLIENT_QUERIES",
            "DNS_FORWARDERS", "DNS_FORWARDER_ADD", "DNS_FORWARDER_REMOVE",
            "DNS_FORWARDER_DELETE", "DNS_FORWARDER_UPDATE", "DNS_FORWARDER_EDIT",
            *_OVERRIDE_COMMANDS,
        }:
            return {
                "status": "ERROR",
                "message": ("No DNS Server workers configured. Install the DNS "
                            "Server role and add it to DNS Management."),
            }

        # Anything else is unknown.
        return {"status": "ERROR", "error": f"Unknown command: {command_type}"}

    async def get_status(self) -> Dict[str, Any]:
        """Return this spoke's health summary for the hub.

        Returns:
            Status dict; HEALTHY only when every worker is reachable and converged.
        """
        # Cluster mode: summarize worker reachability and convergence.
        if self.cluster.enabled:
            report = self.cluster.cluster_report()
            # Workers currently reachable.
            reachable = report["member_count"] - len(report["unreachable"])
            return {
                "spoke_id":     self.spoke_id,
                "module":       "dns",
                "unbound":      "cluster",
                "record_count": self.desired.snapshot()["record_count"],
                "cluster": {
                    "members":   report["member_count"],
                    "connected": reachable,
                    "converged": report["converged"],
                    "state":     report["state"],
                    "version":   self.desired.version,
                },
                # Converged AND fully reachable is the only healthy state — a
                # half-applied record set must never render green.
                "status": ("HEALTHY"
                           if report["converged"] and reachable == report["member_count"]
                           else "DEGRADED"),
            }
        # No workers: not configured.
        return {
            "spoke_id":     self.spoke_id,
            "module":       "dns",
            "unbound":      "not-configured",
            "record_count": self.desired.snapshot()["record_count"],
            "status":       "DEGRADED",
            "message":      "No DNS Server workers configured",
        }

    def get_version(self) -> str:
        """Return the module version from the VERSION file, or "unknown"."""
        # Local import keeps this self-contained.
        from pathlib import Path
        # VERSION sits one directory above src/.
        try:
            return (Path(__file__).parent.parent / "VERSION").read_text().strip()
        # Missing or unreadable file.
        except Exception:
            return "unknown"
