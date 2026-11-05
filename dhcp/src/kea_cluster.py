"""Kea HA orchestration — the coordinator half of a two-node DHCP pair.

Owns the *shared* DHCP intent (subnets + reservations), renders the two
node-specific configs **on top of each node's own running configuration**, and
drives the apply as a single serialized transaction:

1. **Install hooks** on both nodes (idempotent). A node missing
   ``libdhcp_ha.so``/``libdhcp_lease_cmds.so`` cannot be part of a pair, so this
   is checked before anything is generated.
2. **Read each node's full config** (``KEAW_GET_CONFIG``) and replace ONLY the
   coordinator-owned keys (``subnet4``) plus the HA hook entries. Interfaces,
   lease database, loggers, client classes and every other node-local setting
   survive verbatim — rendering from ``{}`` would wipe them.
3. **Validate both** candidate configs with Kea's own ``config-test``. If either
   node rejects its config, NOTHING is applied.
4. **Apply standby/secondary first, then primary.** A failure aborts and rolls
   back every node that could have been mutated — including the node that just
   failed, whose ``config-set`` may have landed before its ``config-write``.

The desired intent + version are a **candidate** until the whole transaction
succeeds: a failed apply cannot poison a later mutation, and the promoted state
is persisted durably before the verdict is returned.

Every mutation runs under one asyncio lock, so two concurrent syncs can never
interleave a validate from one with an apply from the other.
"""

# Transaction lock.
import asyncio
# JSON for the persisted desired state.
import json
# Logging.
import logging
# Paths, environment variables and atomic file replacement.
import os
# Timestamps.
import time
# Type hints.
from typing import Any, Dict, Iterable, List, Optional

# Import HA helpers and subnet builders; the import path differs between layouts.
try:
    from kea_ha import (
        DEFAULT_DESIRED_STATE, DEFAULT_DESIRED_STATE6, KeaHAConfigError,
        apply_order, build_node_config, build_node_config6, build_peers,
        coerce_mode, config_fingerprint, parse_ha_status, resolve_hook_dir,
        summarize_ha,
    )
    from kea_manager import DHCP4_COORDINATOR_GLOBALS, build_subnet4, build_subnet6
except ImportError:  # loaded as a package (src.X) by the sibling entrypoint
    from src.kea_ha import (  # type: ignore
        DEFAULT_DESIRED_STATE, DEFAULT_DESIRED_STATE6, KeaHAConfigError,
        apply_order, build_node_config, build_node_config6, build_peers,
        coerce_mode, config_fingerprint, parse_ha_status, resolve_hook_dir,
        summarize_ha,
    )
    from src.kea_manager import (  # type: ignore
        DHCP4_COORDINATOR_GLOBALS, build_subnet4, build_subnet6,
    )

# Module logger.
logger = logging.getLogger("KeaCluster")


class KeaHACoordinator:
    """Renders + applies a two-node HA config over the cluster transport.

    ``transport`` is anything exposing the ``ClusterCoordinator`` surface
    (``enabled``, ``member_ids``, ``member_links``, ``fanout``, ``call``), so the
    orchestration is testable without a websocket.
    """

    def __init__(self, transport, mode: str = "", hook_dir: str = "",
                 state_path: str = "", state_path6: str = ""):
        """Create the coordinator and load any persisted desired state.

        Args:
            transport: Cluster transport used to reach workers.
            mode: HA mode (coerced to a supported one).
            hook_dir: Optional explicit Kea hook directory.
            state_path: DHCPv4 desired-state file (env/default if empty).
            state_path6: DHCPv6 desired-state file (env/default if empty).
        """
        # Keep the transport and the supported HA mode.
        self.transport = transport
        self.mode = coerce_mode(mode)
        # Empty means "resolve on the node" — the multiarch triplet differs per
        # host, so the coordinator must not bake in its own.
        self.hook_dir = hook_dir or ""
        # Desired-state file paths, from arguments, environment or defaults.
        self.state_path = state_path or os.getenv("LM_DHCP_DESIRED_STATE",
                                                  DEFAULT_DESIRED_STATE)
        self.state_path6 = state_path6 or os.getenv("LM_DHCP_DESIRED_STATE6",
                                                     DEFAULT_DESIRED_STATE6)
        #: Last COMMITTED shared intent — only ever advanced by a fully
        #: successful apply, so a failed transaction cannot poison the next one.
        self.desired: Dict[str, Any] = {"subnets": [], "reservations": []}
        # Committed DHCPv4 version and last apply result.
        self.version = 0
        self.last_apply: Dict[str, Any] = {}
        #: The DHCPv6 mirror of the above. Kept fully separate: v4 and v6 are
        #: independent Kea daemons/config trees with independent scopes and
        #: independent versioning, so conflating them into one journal/version
        #: would make a v6-only apply bump the v4 version (or vice versa) and
        #: make crash-recovery ambiguous about which daemon a pending
        #: candidate belongs to.
        self.desired6: Dict[str, Any] = {"subnets": [], "reservations": []}
        self.version6 = 0
        self.last_apply6: Dict[str, Any] = {}
        #: A candidate journalled to disk but not yet promoted. Set on load when
        #: the process died mid-transaction; the pair may be running it, the
        #: committed record may be a version behind, and only a re-apply can
        #: resolve that. Surfaced in :meth:`report` until an apply clears it.
        self.pending_candidate: Optional[Dict[str, Any]] = None
        self.pending_candidate6: Optional[Dict[str, Any]] = None
        # Last reported config digests and HA status per member, for v4 and v6.
        self.config_digests: Dict[str, str] = {}
        self.config_digests6: Dict[str, str] = {}
        self.ha_status: Dict[str, Dict[str, Any]] = {}
        self.ha_status6: Dict[str, Dict[str, Any]] = {}
        #: Serializes the whole install→read→validate→apply transaction. Two
        #: concurrent syncs would otherwise interleave one's validate with the
        #: other's apply and leave the pair on a config neither node validated.
        #: Created lazily: the coordinator is constructed at module-load time,
        #: which on 3.9-era loop semantics is outside any running loop.
        self._lock: Optional[asyncio.Lock] = None
        # Load persisted v4 and v6 state.
        self._load_state()
        self._load_state6()

    def _get_lock(self) -> asyncio.Lock:
        """Return the shared transaction lock, creating it on first use inside the loop."""
        # Create the lock lazily.
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    def transaction(self):
        """The SAME lock every apply/reservation/status-apply takes.

        Exposed so the spoke can run a topology change (validate → persist →
        rebind → stand down removed nodes) as one critical section with the
        config applies. Without it a topology edit could land between an apply's
        validate and its commit, and the apply would then push to a member list
        that no longer exists — or stand down a node mid-apply."""
        # Return the shared lock.
        return self._get_lock()

    # ── Durable desired state ───────────────────────────────────────────────

    def _load_state(self) -> None:
        """Reload the committed intent + any un-promoted candidate.

        A corrupt/unreadable file leaves the coordinator at version 0 with no
        intent, which the ``DHCP_HA_APPLY`` guard treats as "nothing to
        re-apply" — never as "apply an empty config".

        A ``pending`` block means the process died between journalling a
        candidate and promoting it: the nodes may already be running the
        candidate while the committed record is a version behind. That is
        surfaced (not silently discarded) so an operator re-applies rather than
        trusting a version nobody verified.
        """
        # No path or file yet: keep the empty defaults.
        if not self.state_path or not os.path.exists(self.state_path):
            return
        # Any read/validation error resets to "no committed intent".
        try:
            # Read the JSON document.
            with open(self.state_path) as fh:
                data = json.load(fh)
            # Top level must be an object with list-valued subnets and reservations.
            if not isinstance(data, dict):
                raise ValueError("desired state is not an object")
            subnets = data.get("subnets")
            reservations = data.get("reservations")
            if not isinstance(subnets, list) or not isinstance(reservations, list):
                raise ValueError("desired state subnets/reservations must be lists")
            # Adopt the committed intent and version.
            self.desired = {"subnets": subnets, "reservations": reservations}
            self.version = int(data.get("version") or 0)
            # A leftover candidate means a crash mid-apply: keep it and warn loudly.
            pending = data.get("pending")
            if isinstance(pending, dict) and pending.get("version"):
                self.pending_candidate = pending
                logger.error(
                    "DHCP HA desired state carries an un-promoted candidate "
                    "(v%s journalled at %s): the pair may be running it while "
                    "the committed record is v%s. Re-apply to converge.",
                    pending.get("version"), pending.get("started_at"),
                    self.version)
        # Unusable file: start empty at version 0.
        except Exception as e:  # noqa: BLE001
            logger.warning("Could not load DHCP desired state from %s: %s — "
                           "starting with no committed intent",
                           self.state_path, e)
            self.desired = {"subnets": [], "reservations": []}
            self.version = 0
            self.pending_candidate = None

    def _write_state(self, payload: Dict[str, Any]) -> None:
        """Atomic + fsynced write of the whole state document. Raises."""
        # No path: memory-only, nothing to write.
        if not self.state_path:
            return
        # Create the parent directory if needed.
        directory = os.path.dirname(self.state_path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        # Write to a temp file and fsync it.
        tmp = self.state_path + ".tmp"
        with open(tmp, "w") as fh:
            json.dump(payload, fh)
            fh.flush()
            os.fsync(fh.fileno())
        # Atomically replace the real file.
        os.replace(tmp, self.state_path)

    def _journal_candidate(self, subnets: List[Any], reservations: List[Any],
                           version: int) -> None:
        """Durably record the candidate BEFORE any node is touched. Raises.

        Without this, a coordinator that crashed mid-apply came back believing
        the OLD version was live while one or both nodes were running the new
        one — and the next mutation would build on the wrong base. The journal
        makes that state detectable on restart.
        """
        # Keep the committed state and add the candidate as "pending".
        self._write_state({
            "version": self.version, "mode": self.mode,
            "subnets": self.desired.get("subnets") or [],
            "reservations": self.desired.get("reservations") or [],
            "updated_at": time.time(),
            "pending": {"version": version, "subnets": subnets,
                        "reservations": reservations, "started_at": time.time()},
        })

    def _promote_candidate(self, subnets: List[Any], reservations: List[Any],
                           version: int) -> None:
        """Commit the candidate and clear the journal. Raises on failure."""
        # Store the candidate as committed with no pending block.
        self._write_state({
            "version": version, "mode": self.mode, "subnets": subnets,
            "reservations": reservations, "updated_at": time.time(),
            "pending": None,
        })

    def _retain_candidate(self, version: int, unrestored: List[str]) -> None:
        """Persist the un-promoted candidate + which nodes may still hold it."""
        # Keep the committed state and record a pending block naming nodes that may be ahead.
        try:
            self._write_state({
                "version": self.version, "mode": self.mode,
                "subnets": self.desired.get("subnets") or [],
                "reservations": self.desired.get("reservations") or [],
                "updated_at": time.time(),
                "pending": {"version": version, "started_at": time.time(),
                            "unrestored": list(unrestored),
                            "subnets": self.desired.get("subnets") or [],
                            "reservations": self.desired.get("reservations") or []},
            })
        # A failed write is logged; the caller still reports the failure.
        except Exception as e:  # noqa: BLE001
            logger.error("Could not retain the DHCP HA candidate journal at %s: "
                         "%s — a restart will not know %s may be ahead",
                         self.state_path, e, ", ".join(unrestored))

    def _clear_candidate(self) -> None:
        """Best-effort journal clear after a CONFIRMED full restore."""
        # Rewrite committed state with no pending block.
        try:
            self._write_state({
                "version": self.version, "mode": self.mode,
                "subnets": self.desired.get("subnets") or [],
                "reservations": self.desired.get("reservations") or [],
                "updated_at": time.time(), "pending": None,
            })
            self.pending_candidate = None
        # A failed write is logged; the next start will report the leftover.
        except Exception as e:  # noqa: BLE001
            logger.error("Could not clear the DHCP HA candidate journal at %s: "
                         "%s — the next start will report a pending candidate",
                         self.state_path, e)

    # ── Durable desired state (DHCPv6) ──────────────────────────────────────
    # Exact mirror of the v4 methods above, against ``self.state_path6`` /
    # ``self.desired6`` / ``self.version6`` / ``self.pending_candidate6``.

    def _load_state6(self) -> None:
        """DHCPv6 version of _load_state: reload committed intent and any pending candidate."""
        # No path or file yet: keep the empty defaults.
        if not self.state_path6 or not os.path.exists(self.state_path6):
            return
        # Any read/validation error resets to "no committed intent".
        try:
            # Read the JSON document.
            with open(self.state_path6) as fh:
                data = json.load(fh)
            # Top level must be an object with list-valued subnets and reservations.
            if not isinstance(data, dict):
                raise ValueError("desired state is not an object")
            subnets = data.get("subnets")
            reservations = data.get("reservations")
            if not isinstance(subnets, list) or not isinstance(reservations, list):
                raise ValueError("desired state subnets/reservations must be lists")
            # Adopt the committed intent and version.
            self.desired6 = {"subnets": subnets, "reservations": reservations}
            self.version6 = int(data.get("version") or 0)
            # A leftover candidate means a crash mid-apply: keep it and warn loudly.
            pending = data.get("pending")
            if isinstance(pending, dict) and pending.get("version"):
                self.pending_candidate6 = pending
                logger.error(
                    "DHCPv6 HA desired state carries an un-promoted candidate "
                    "(v%s journalled at %s): the pair may be running it while "
                    "the committed record is v%s. Re-apply to converge.",
                    pending.get("version"), pending.get("started_at"),
                    self.version6)
        # Unusable file: start empty at version 0.
        except Exception as e:  # noqa: BLE001
            logger.warning("Could not load DHCPv6 desired state from %s: %s — "
                           "starting with no committed intent",
                           self.state_path6, e)
            self.desired6 = {"subnets": [], "reservations": []}
            self.version6 = 0
            self.pending_candidate6 = None

    def _write_state6(self, payload: Dict[str, Any]) -> None:
        """DHCPv6 version of _write_state: atomic, fsynced write. Raises on failure.

        Args:
            payload: Whole state document to write.
        """
        # No path: memory-only, nothing to write.
        if not self.state_path6:
            return
        # Create the parent directory if needed.
        directory = os.path.dirname(self.state_path6)
        if directory:
            os.makedirs(directory, exist_ok=True)
        # Write to a temp file and fsync it.
        tmp = self.state_path6 + ".tmp"
        with open(tmp, "w") as fh:
            json.dump(payload, fh)
            fh.flush()
            os.fsync(fh.fileno())
        # Atomically replace the real file.
        os.replace(tmp, self.state_path6)

    def _journal_candidate6(self, subnets: List[Any], reservations: List[Any],
                            version: int) -> None:
        """DHCPv6 version of _journal_candidate: record the candidate before touching nodes.

        Args:
            subnets: Candidate subnets.
            reservations: Candidate reservations.
            version: Candidate version.
        """
        # Keep the committed state and add the candidate as "pending".
        self._write_state6({
            "version": self.version6, "mode": self.mode,
            "subnets": self.desired6.get("subnets") or [],
            "reservations": self.desired6.get("reservations") or [],
            "updated_at": time.time(),
            "pending": {"version": version, "subnets": subnets,
                        "reservations": reservations, "started_at": time.time()},
        })

    def _promote_candidate6(self, subnets: List[Any], reservations: List[Any],
                            version: int) -> None:
        """DHCPv6 version of _promote_candidate: commit the candidate and clear the journal.

        Args:
            subnets: Committed subnets.
            reservations: Committed reservations.
            version: Committed version.
        """
        # Store the candidate as committed with no pending block.
        self._write_state6({
            "version": version, "mode": self.mode, "subnets": subnets,
            "reservations": reservations, "updated_at": time.time(),
            "pending": None,
        })

    def _retain_candidate6(self, version: int, unrestored: List[str]) -> None:
        """DHCPv6 version of _retain_candidate: keep a pending block naming nodes that may be ahead.

        Args:
            version: Candidate version.
            unrestored: Members that could not be restored.
        """
        # A failed write is logged; the caller still reports the failure.
        try:
            self._write_state6({
                "version": self.version6, "mode": self.mode,
                "subnets": self.desired6.get("subnets") or [],
                "reservations": self.desired6.get("reservations") or [],
                "updated_at": time.time(),
                "pending": {"version": version, "started_at": time.time(),
                            "unrestored": list(unrestored),
                            "subnets": self.desired6.get("subnets") or [],
                            "reservations": self.desired6.get("reservations") or []},
            })
        except Exception as e:  # noqa: BLE001
            logger.error("Could not retain the DHCPv6 HA candidate journal at "
                         "%s: %s — a restart will not know %s may be ahead",
                         self.state_path6, e, ", ".join(unrestored))

    def _clear_candidate6(self) -> None:
        """DHCPv6 version of _clear_candidate: best-effort journal clear after a full restore."""
        # Rewrite committed state with no pending block; log if that fails.
        try:
            self._write_state6({
                "version": self.version6, "mode": self.mode,
                "subnets": self.desired6.get("subnets") or [],
                "reservations": self.desired6.get("reservations") or [],
                "updated_at": time.time(), "pending": None,
            })
            self.pending_candidate6 = None
        except Exception as e:  # noqa: BLE001
            logger.error("Could not clear the DHCPv6 HA candidate journal at "
                         "%s: %s — the next start will report a pending "
                         "candidate", self.state_path6, e)

    @property
    def enabled(self) -> bool:
        """True when the transport has HA members configured."""
        # Read the transport's flag, defaulting to False.
        return bool(getattr(self.transport, "enabled", False))

    def members(self) -> List[Dict[str, Any]]:
        """Return a copy of the transport's configured HA members."""
        # Copy so callers cannot change the transport's list.
        return list(getattr(self.transport, "members", []) or [])

    def peers(self) -> List[Dict[str, Any]]:
        """The validated Kea peer list. Raises :class:`KeaHAConfigError`."""
        # Validate the members and build peers for the current mode.
        return build_peers(self.members(), self.mode)

    # ── Config rendering ────────────────────────────────────────────────────

    def owned_config(self, subnets: Iterable[Any],
                     reservations: Iterable[Any]) -> Dict[str, Any]:
        """The coordinator-owned slice both nodes must share, identically."""
        # Build Kea subnet4 entries plus how many reservations were applied or skipped.
        kea_subnets, applied, skipped = build_subnet4(list(subnets or []),
                                                      list(reservations or []))
        # Shared subnets and globals, plus private counters the caller pops off.
        return {"subnet4": kea_subnets, **DHCP4_COORDINATOR_GLOBALS,
                "_applied": applied, "_skipped": skipped}

    def render(self, subnets: Iterable[Any], reservations: Iterable[Any],
               node_configs: Optional[Dict[str, Dict[str, Any]]] = None
               ) -> Dict[str, Any]:
        """Build the per-node configs from one shared scope/reservation set.

        ``node_configs`` maps member id → that node's CURRENT ``Dhcp4`` config;
        everything the coordinator does not own is carried through from it.
        :meth:`apply` always reads every node first and refuses to proceed if any
        read failed, so a real apply never renders from an empty base.
        """
        # Validate the pair and build the shared slice.
        peers = build_peers(self.members(), self.mode)
        owned = self.owned_config(subnets, reservations)
        # Remove the private counters.
        applied, skipped = owned.pop("_applied"), owned.pop("_skipped")
        node_configs = node_configs or {}
        # Build each node's config on top of its current config.
        configs = {
            p["name"]: build_node_config(node_configs.get(p["name"]) or {},
                                         p["name"], peers, self.mode,
                                         self.hook_dir, owned=owned)
            for p in peers
        }
        # Return peers, configs, apply order, counts and the shared-slice digest.
        return {
            "peers": peers,
            "configs": configs,
            "order": apply_order(peers),
            "subnets": len(owned["subnet4"]),
            "reservations": applied,
            "reservations_skipped": skipped,
            "digest": config_fingerprint(owned),
        }

    # ── Config rendering (DHCPv6) ────────────────────────────────────────────

    def owned_config6(self, subnets: Iterable[Any],
                      reservations: Iterable[Any]) -> Dict[str, Any]:
        """The coordinator-owned DHCPv6 slice both nodes must share, identically."""
        # Build Kea subnet6 entries plus reservation counts.
        kea_subnets, applied, skipped = build_subnet6(list(subnets or []),
                                                       list(reservations or []))
        # Shared subnets plus private counters the caller pops off.
        return {"subnet6": kea_subnets, "_applied": applied, "_skipped": skipped}

    def render6(self, subnets: Iterable[Any], reservations: Iterable[Any],
               node_configs: Optional[Dict[str, Dict[str, Any]]] = None
               ) -> Dict[str, Any]:
        """The DHCPv6 mirror of :meth:`render` — see there for the rationale.

        ``node_configs`` maps member id → that node's CURRENT ``Dhcp6`` config.
        """
        # Validate the pair and build the shared slice.
        peers = build_peers(self.members(), self.mode)
        owned = self.owned_config6(subnets, reservations)
        # Remove the private counters.
        applied, skipped = owned.pop("_applied"), owned.pop("_skipped")
        node_configs = node_configs or {}
        # Build each node's Dhcp6 config on top of its current config.
        configs = {
            p["name"]: build_node_config6(node_configs.get(p["name"]) or {},
                                          p["name"], peers, self.mode,
                                          self.hook_dir, owned=owned)
            for p in peers
        }
        # Return peers, configs, apply order, counts and the shared-slice digest.
        return {
            "peers": peers,
            "configs": configs,
            "order": apply_order(peers),
            "subnets": len(owned["subnet6"]),
            "reservations": applied,
            "reservations_skipped": skipped,
            "digest": config_fingerprint(owned),
        }

    # ── Apply ───────────────────────────────────────────────────────────────

    async def apply(self, subnets: Iterable[Any], reservations: Iterable[Any],
                    timeout: float = 40.0) -> Dict[str, Any]:
        """Serialized transaction: hooks → read → validate both → standby, primary."""
        # Run the whole transaction under the shared lock.
        async with self._get_lock():
            return await self._apply_locked(list(subnets or []),
                                            list(reservations or []), timeout)

    async def mutate_reservation(self, action: str, data: Dict[str, Any],
                                 timeout: float = 40.0) -> Dict[str, Any]:
        """Add/update/delete one reservation, read-modify-write UNDER the lock.

        The read (of ``self.desired``) and the write must be inside the same
        critical section as the apply: computing the new list before taking the
        lock let two concurrent reservation edits each start from the same base
        and the second silently drop the first.
        """
        # Read, edit and apply under one lock.
        async with self._get_lock():
            # Reservations need synchronized subnets first.
            desired = self.desired
            if not desired.get("subnets"):
                return {"status": "ERROR", "cluster": True, "message":
                        "The HA pair has no synchronised subnets yet — run a DHCP "
                        "sync before managing reservations."}
            # An IP is required.
            ip = data.get("ip")
            if not ip:
                return {"status": "ERROR", "cluster": True,
                        "message": "ip is required"}
            # Drop entries for the old and new IP.
            old_ip = data.get("old_ip") or ip
            reservations = [r for r in (desired.get("reservations") or [])
                            if r.get("ip") not in (old_ip, ip)]
            # Add or update needs a MAC; delete just leaves the entry out.
            if action != "delete":
                mac = data.get("mac")
                if not mac:
                    return {"status": "ERROR", "cluster": True,
                            "message": "mac is required"}
                reservations.append({"ip": ip, "mac": mac,
                                     "hostname": data.get("hostname", ""),
                                     "subnet": data.get("subnet", "")})
            # Apply the shared subnets with the edited reservations.
            return await self._apply_locked(list(desired.get("subnets") or []),
                                            reservations, timeout)

    async def _apply_locked(self, subnets: List[Any], reservations: List[Any],
                            timeout: float) -> Dict[str, Any]:
        """Run the full DHCPv4 apply transaction; caller holds the lock.

        Args:
            subnets: Shared subnets.
            reservations: Shared reservations.
            timeout: Per-call timeout in seconds.

        Returns:
            The verdict dict (SUCCESS, PARTIAL or ERROR with per-node details).
        """
        # Validate the topology first.
        try:
            peers = self.peers()
        except KeaHAConfigError as e:
            return self._verdict("ERROR", self._empty_plan([]), applied=[],
                                 failed=[], errors={}, stage="topology",
                                 message=str(e))
        # Apply order: partner first, then primary.
        order: List[str] = apply_order(peers)

        # Make sure both nodes have the HA hook libraries.
        hooks = await self.transport.fanout(
            "KEAW_INSTALL_HOOKS", {"hook_dir": self.hook_dir}, timeout=timeout)
        missing = [mid for mid in order
                   if ((hooks.get("results") or {}).get(mid) or {}).get("status") != "SUCCESS"]
        # Any node without hooks aborts before anything is changed.
        if missing:
            return self._verdict("ERROR", self._empty_plan(order), applied=[],
                                 failed=order, errors={
                mid: ((((hooks.get("results") or {}).get(mid) or {}).get("message"))
                      or "HA hook libraries unavailable") for mid in missing},
                stage="install-hooks")

        # Read each node's FULL running config so the render preserves
        # everything the coordinator does not own.
        node_configs: Dict[str, Dict[str, Any]] = {}
        read_errors: Dict[str, str] = {}
        # Request each node's config in apply order.
        for member_id in order:
            reply = await self.transport.call(member_id, "KEAW_GET_CONFIG", {},
                                              timeout=timeout)
            # A failed or malformed reply is recorded as a read error.
            cfg = reply.get("config") if isinstance(reply, dict) else None
            if not isinstance(reply, dict) or reply.get("status") != "SUCCESS" \
                    or not isinstance(cfg, dict):
                read_errors[member_id] = (
                    (reply or {}).get("message")
                    or "could not read the running configuration")
                continue
            # Keep the node's config.
            node_configs[member_id] = cfg
        # Any read failure aborts before rendering.
        if read_errors:
            return self._verdict("ERROR", self._empty_plan(order), applied=[],
                                 failed=order, errors=read_errors,
                                 stage="read-config")

        # Render both node configs; topology problems abort.
        try:
            plan = self.render(subnets, reservations, node_configs)
        except KeaHAConfigError as e:
            return self._verdict("ERROR", self._empty_plan(order), applied=[],
                                 failed=order, errors={}, stage="render",
                                 message=str(e))
        # Per-node candidate configs.
        configs: Dict[str, Any] = plan["configs"]

        # Validate EVERY node before touching ANY node.
        validation_errors: Dict[str, str] = {}
        # Ask each node to config-test its candidate.
        for member_id in order:
            reply = await self.transport.call(
                member_id, "KEAW_VALIDATE", {"config": configs[member_id]},
                timeout=timeout)
            if reply.get("status") != "SUCCESS":
                validation_errors[member_id] = (
                    reply.get("message") or "config-test rejected the configuration")
        # Any rejection aborts with nothing applied.
        if validation_errors:
            return self._verdict("ERROR", plan, applied=[], failed=order,
                                 errors=validation_errors, stage="validate")

        # Next version number.
        candidate_version = self.version + 1
        # Journal the candidate BEFORE touching any node: a crash after this
        # point is recoverable (the pending block is detected on restart);
        # a crash before it means nothing was applied.
        try:
            self._journal_candidate(subnets, reservations, candidate_version)
        except Exception as e:  # noqa: BLE001
            return self._verdict(
                "ERROR", plan, applied=[], failed=order, stage="journal",
                errors={"coordinator": f"could not journal the candidate: {e}"})

        # Apply node by node in order; the first failure triggers rollback.
        applied: List[str] = []
        errors: Dict[str, str] = {}
        for member_id in order:
            reply = await self.transport.call(
                member_id, "KEAW_APPLY",
                {"config": configs[member_id], "version": candidate_version,
                 "hook_dir": self.hook_dir},
                timeout=timeout)
            # Applied on this node: continue to the next.
            if reply.get("status") == "SUCCESS":
                applied.append(member_id)
                continue
            # Record the failure and roll back every possibly-changed node.
            errors[member_id] = reply.get("message") or "apply failed"
            return await self._rollback(order, applied, member_id, reply,
                                        errors, plan, timeout)

        # Every node confirmed. Promote the candidate ONLY now, and only once it
        # is durably on disk. If the promote write fails the pair is running a
        # version the coordinator cannot remember, so BOTH nodes are rolled
        # back rather than left ahead of the record.
        try:
            self._promote_candidate(subnets, reservations, candidate_version)
        # Promote failed: roll back every applied node.
        except Exception as e:  # noqa: BLE001
            errors = {"coordinator":
                      f"both nodes applied v{candidate_version} but the "
                      f"coordinator could not persist it ({e}); rolling both "
                      f"back to v{self.version}"}
            rolled_back = []
            # Roll back each applied node, noting which ones succeeded.
            for node in list(applied):
                undo = await self.transport.call(node, "KEAW_ROLLBACK", {},
                                                 timeout=timeout)
                if undo.get("status") == "SUCCESS":
                    rolled_back.append(node)
                    self.config_digests.pop(node, None)
                # Rollback failed: this node may still be ahead.
                else:
                    errors[node] = (
                        f"may still hold v{candidate_version} — rollback failed: "
                        f"{undo.get('message') or 'unknown error'}")
            # Nodes that may still hold the candidate.
            remaining = [m for m in applied if m not in rolled_back]
            # Keep the journal (and in-memory marker) while any node may be ahead.
            if remaining:
                self._retain_candidate(candidate_version, remaining)
                self.pending_candidate = {
                    "version": candidate_version, "started_at": time.time(),
                    "unrestored": list(remaining),
                }
                logger.error("Kea HA promote failed and %s could not be rolled "
                             "back — retaining the candidate journal",
                             ", ".join(remaining))
            # All restored: clear the journal.
            else:
                self._clear_candidate()
            # Report ERROR if all restored, PARTIAL otherwise.
            return self._verdict(
                "ERROR" if not remaining else "PARTIAL", plan,
                applied=remaining,
                failed=[m for m in order if m not in remaining],
                errors=errors, stage="promote", rolled_back=rolled_back)
        # Success: promote in memory and record each node's digest.
        self.version = candidate_version
        self.desired = {"subnets": list(subnets), "reservations": list(reservations)}
        self.pending_candidate = None
        for member_id in applied:
            self.config_digests[member_id] = plan["digest"]
        # Report success.
        return self._verdict("SUCCESS", plan, applied=applied, failed=[],
                             errors={}, stage="apply")

    async def _rollback(self, order: List[str], applied: List[str],
                        failed_member: str, reply: Dict[str, Any],
                        errors: Dict[str, str], plan: Dict[str, Any],
                        timeout: float) -> Dict[str, Any]:
        """Undo a mid-chain failure across every POSSIBLY-mutated node.

        The failing node itself is a rollback candidate: its ``config-set`` can
        land and its ``config-write`` (or its own local restore) then fail, so it
        may be running the new configuration despite reporting ERROR. It is
        excluded only when the worker positively asserts it did not mutate
        (``mutated=False``) — an older worker that says nothing is treated as
        possibly mutated.
        """
        # Nodes that may have changed: those applied, plus the failing node unless it said
        # otherwise.
        suspect = list(applied)
        if reply.get("mutated") is not False:
            suspect.append(failed_member)
        # Roll each one back.
        rolled_back: List[str] = []
        for node in suspect:
            undo = await self.transport.call(node, "KEAW_ROLLBACK", {},
                                             timeout=timeout)
            # Restored: its old digest is no longer known.
            if undo.get("status") == "SUCCESS":
                rolled_back.append(node)
                self.config_digests.pop(node, None)
            # Rollback failed: append to that node's error.
            else:
                errors[node] = (
                    (errors.get(node, "") + "; " if errors.get(node) else "")
                    + f"may still hold the new configuration — rollback failed: "
                      f"{undo.get('message') or 'unknown error'}")
        # Nodes still possibly ahead decide ERROR vs PARTIAL.
        remaining = [m for m in suspect if m not in rolled_back]
        status = "ERROR" if not remaining else "PARTIAL"
        if remaining:
            # At least one node may STILL be running the candidate. Keeping the
            # journal is the whole point: a restart must know the pair can be
            # ahead of the committed record. Clearing it here (the previous
            # behaviour) threw away the only evidence of a half-applied pair.
            self._retain_candidate(self.version + 1, remaining)
            self.pending_candidate = {
                "version": self.version + 1,
                "started_at": time.time(),
                "unrestored": list(remaining),
            }
            logger.error("Kea HA rollback incomplete — %s may still hold the "
                         "candidate; the journal is retained for recovery",
                         ", ".join(remaining))
        else:
            # Every touched node was confirmed restored: the journal has served
            # its purpose and would otherwise raise a false alarm on restart.
            self._clear_candidate()
        # Return the verdict.
        return self._verdict(status, plan, applied=remaining,
                             failed=[m for m in order if m not in remaining],
                             errors=errors, stage="apply",
                             rolled_back=rolled_back)

    # ── Apply (DHCPv6) ───────────────────────────────────────────────────────
    # Exact mirror of the v4 apply/_apply_locked/_rollback trio above, targeting
    # the dhcp6 daemon's own RPCs (``KEAW_*6``), journal (``self.state_path6``)
    # and version counter (``self.version6``) — kept as separate methods rather
    # than parameterizing the v4 ones so this addition cannot change the
    # behaviour of the already-proven v4 transaction.

    async def apply6(self, subnets: Iterable[Any], reservations: Iterable[Any],
                     timeout: float = 40.0) -> Dict[str, Any]:
        """Serialized DHCPv6 transaction: hooks → read → validate both → apply."""
        # Run the whole DHCPv6 transaction under the shared lock.
        async with self._get_lock():
            return await self._apply_locked6(list(subnets or []),
                                             list(reservations or []), timeout)

    async def mutate_reservation6(self, action: str, data: Dict[str, Any],
                                  timeout: float = 40.0) -> Dict[str, Any]:
        """The DHCPv6 mirror of :meth:`mutate_reservation`.

        DHCPv6 reservations are keyed the same way as v4 in this codebase
        (hw-address, via ``ip-addresses``/``ip`` — see ``build_subnet6``), so
        the read-modify-write shape is identical; only the desired-state
        object and version counter differ.
        """
        # Read, edit and apply under one lock.
        async with self._get_lock():
            # Reservations need synchronized v6 subnets first.
            desired = self.desired6
            if not desired.get("subnets"):
                return {"status": "ERROR", "cluster": True, "message":
                        "The HA pair has no synchronised DHCPv6 subnets yet — "
                        "run a DHCPv6 sync before managing reservations."}
            # An IP is required.
            ip = data.get("ip")
            if not ip:
                return {"status": "ERROR", "cluster": True,
                        "message": "ip is required"}
            # Drop entries for the old and new IP.
            old_ip = data.get("old_ip") or ip
            reservations = [r for r in (desired.get("reservations") or [])
                            if r.get("ip") not in (old_ip, ip)]
            # Add or update needs a MAC; delete just leaves the entry out.
            if action != "delete":
                mac = data.get("mac")
                if not mac:
                    return {"status": "ERROR", "cluster": True,
                            "message": "mac is required"}
                reservations.append({"ip": ip, "mac": mac,
                                     "hostname": data.get("hostname", ""),
                                     "subnet": data.get("subnet", "")})
            # Apply the shared v6 subnets with the edited reservations.
            return await self._apply_locked6(list(desired.get("subnets") or []),
                                             reservations, timeout)

    async def _apply_locked6(self, subnets: List[Any], reservations: List[Any],
                             timeout: float) -> Dict[str, Any]:
        """Run the full DHCPv6 apply transaction; caller holds the lock.

        Args:
            subnets: Shared v6 subnets.
            reservations: Shared v6 reservations.
            timeout: Per-call timeout in seconds.

        Returns:
            The verdict dict (SUCCESS, PARTIAL or ERROR with per-node details).
        """
        # Validate the topology first.
        try:
            peers = self.peers()
        except KeaHAConfigError as e:
            return self._verdict6("ERROR", self._empty_plan([]), applied=[],
                                  failed=[], errors={}, stage="topology",
                                  message=str(e))
        # Apply order: partner first, then primary.
        order: List[str] = apply_order(peers)

        # Make sure both nodes have the HA hook libraries (shared by dhcp4 and dhcp6).
        hooks = await self.transport.fanout(
            "KEAW_INSTALL_HOOKS", {"hook_dir": self.hook_dir}, timeout=timeout)
        missing = [mid for mid in order
                   if ((hooks.get("results") or {}).get(mid) or {}).get("status") != "SUCCESS"]
        # Any node without hooks aborts before anything is changed.
        if missing:
            return self._verdict6("ERROR", self._empty_plan(order), applied=[],
                                  failed=order, errors={
                mid: ((((hooks.get("results") or {}).get(mid) or {}).get("message"))
                      or "HA hook libraries unavailable") for mid in missing},
                stage="install-hooks")

        # Read each node's full running Dhcp6 config so non-owned settings are kept.
        node_configs: Dict[str, Dict[str, Any]] = {}
        read_errors: Dict[str, str] = {}
        # Request each node's config in apply order.
        for member_id in order:
            reply = await self.transport.call(member_id, "KEAW_GET_CONFIG6", {},
                                              timeout=timeout)
            # A failed or malformed reply is recorded as a read error.
            cfg = reply.get("config") if isinstance(reply, dict) else None
            if not isinstance(reply, dict) or reply.get("status") != "SUCCESS" \
                    or not isinstance(cfg, dict):
                read_errors[member_id] = (
                    (reply or {}).get("message")
                    or "could not read the running DHCPv6 configuration")
                continue
            # Keep the node's config.
            node_configs[member_id] = cfg
        # Any read failure aborts before rendering.
        if read_errors:
            return self._verdict6("ERROR", self._empty_plan(order), applied=[],
                                  failed=order, errors=read_errors,
                                  stage="read-config")

        # Render both node configs; topology problems abort.
        try:
            plan = self.render6(subnets, reservations, node_configs)
        except KeaHAConfigError as e:
            return self._verdict6("ERROR", self._empty_plan(order), applied=[],
                                  failed=order, errors={}, stage="render",
                                  message=str(e))
        # Per-node candidate configs.
        configs: Dict[str, Any] = plan["configs"]

        # Validate every node before touching any node.
        validation_errors: Dict[str, str] = {}
        # Ask each node to config-test its candidate.
        for member_id in order:
            reply = await self.transport.call(
                member_id, "KEAW_VALIDATE6", {"config": configs[member_id]},
                timeout=timeout)
            if reply.get("status") != "SUCCESS":
                validation_errors[member_id] = (
                    reply.get("message") or "config-test rejected the DHCPv6 configuration")
        # Any rejection aborts with nothing applied.
        if validation_errors:
            return self._verdict6("ERROR", plan, applied=[], failed=order,
                                  errors=validation_errors, stage="validate")

        # Journal the candidate before touching any node, so a crash is detectable on restart.
        candidate_version = self.version6 + 1
        try:
            self._journal_candidate6(subnets, reservations, candidate_version)
        except Exception as e:  # noqa: BLE001
            return self._verdict6(
                "ERROR", plan, applied=[], failed=order, stage="journal",
                errors={"coordinator": f"could not journal the DHCPv6 candidate: {e}"})

        # Apply node by node in order; the first failure triggers rollback.
        applied: List[str] = []
        errors: Dict[str, str] = {}
        for member_id in order:
            reply = await self.transport.call(
                member_id, "KEAW_APPLY6",
                {"config": configs[member_id], "version": candidate_version,
                 "hook_dir": self.hook_dir},
                timeout=timeout)
            # Applied on this node: continue to the next.
            if reply.get("status") == "SUCCESS":
                applied.append(member_id)
                continue
            # Record the failure and roll back every possibly-changed node.
            errors[member_id] = reply.get("message") or "apply failed"
            return await self._rollback6(order, applied, member_id, reply,
                                         errors, plan, timeout)

        # Promote only after every node confirmed; if that fails, roll both nodes back.
        try:
            self._promote_candidate6(subnets, reservations, candidate_version)
        except Exception as e:  # noqa: BLE001
            errors = {"coordinator":
                      f"both nodes applied DHCPv6 v{candidate_version} but the "
                      f"coordinator could not persist it ({e}); rolling both "
                      f"back to v{self.version6}"}
            # Roll back each applied node, noting which ones succeeded.
            rolled_back = []
            for node in list(applied):
                undo = await self.transport.call(node, "KEAW_ROLLBACK6", {},
                                                 timeout=timeout)
                if undo.get("status") == "SUCCESS":
                    rolled_back.append(node)
                    # Restored: its old digest is no longer known.
                    self.config_digests6.pop(node, None)
                # Rollback failed: this node may still be ahead.
                else:
                    errors[node] = (
                        f"may still hold v{candidate_version} — rollback failed: "
                        f"{undo.get('message') or 'unknown error'}")
            # Nodes that may still hold the candidate.
            remaining = [m for m in applied if m not in rolled_back]
            # Keep the journal (and in-memory marker) while any node may be ahead.
            if remaining:
                self._retain_candidate6(candidate_version, remaining)
                self.pending_candidate6 = {
                    "version": candidate_version, "started_at": time.time(),
                    "unrestored": list(remaining),
                }
                logger.error("Kea DHCPv6 HA promote failed and %s could not be "
                             "rolled back — retaining the candidate journal",
                             ", ".join(remaining))
            # All restored: clear the journal.
            else:
                self._clear_candidate6()
            # Report ERROR if all restored, PARTIAL otherwise.
            return self._verdict6(
                "ERROR" if not remaining else "PARTIAL", plan,
                applied=remaining,
                failed=[m for m in order if m not in remaining],
                errors=errors, stage="promote", rolled_back=rolled_back)
        # Success: promote in memory and record each node's digest.
        self.version6 = candidate_version
        self.desired6 = {"subnets": list(subnets), "reservations": list(reservations)}
        self.pending_candidate6 = None
        for member_id in applied:
            self.config_digests6[member_id] = plan["digest"]
        # Report success.
        return self._verdict6("SUCCESS", plan, applied=applied, failed=[],
                              errors={}, stage="apply")

    async def _rollback6(self, order: List[str], applied: List[str],
                         failed_member: str, reply: Dict[str, Any],
                         errors: Dict[str, str], plan: Dict[str, Any],
                         timeout: float) -> Dict[str, Any]:
        """The DHCPv6 mirror of :meth:`_rollback` — see there for the rationale."""
        # Nodes that may have changed: those applied, plus the failing node unless it said
        # otherwise.
        suspect = list(applied)
        if reply.get("mutated") is not False:
            suspect.append(failed_member)
        # Roll each one back.
        rolled_back: List[str] = []
        for node in suspect:
            undo = await self.transport.call(node, "KEAW_ROLLBACK6", {},
                                             timeout=timeout)
            # Restored: its old digest is no longer known.
            if undo.get("status") == "SUCCESS":
                rolled_back.append(node)
                self.config_digests6.pop(node, None)
            # Rollback failed: append to that node's error.
            else:
                errors[node] = (
                    (errors.get(node, "") + "; " if errors.get(node) else "")
                    + f"may still hold the new DHCPv6 configuration — rollback "
                      f"failed: {undo.get('message') or 'unknown error'}")
        # Nodes still possibly ahead decide ERROR vs PARTIAL.
        remaining = [m for m in suspect if m not in rolled_back]
        status = "ERROR" if not remaining else "PARTIAL"
        # Keep the journal while any node may be ahead.
        if remaining:
            self._retain_candidate6(self.version6 + 1, remaining)
            self.pending_candidate6 = {
                "version": self.version6 + 1,
                "started_at": time.time(),
                "unrestored": list(remaining),
            }
            logger.error("Kea DHCPv6 HA rollback incomplete — %s may still "
                         "hold the candidate; the journal is retained for "
                         "recovery", ", ".join(remaining))
        # All restored: clear the journal.
        else:
            self._clear_candidate6()
        # Return the verdict.
        return self._verdict6(status, plan, applied=remaining,
                              failed=[m for m in order if m not in remaining],
                              errors=errors, stage="apply",
                              rolled_back=rolled_back)

    def _empty_plan(self, order: List[str]) -> Dict[str, Any]:
        """A plan placeholder for failures that abort before rendering."""
        # Empty plan with only the apply order.
        return {"peers": [], "configs": {}, "order": list(order), "subnets": 0,
                "reservations": 0, "reservations_skipped": 0, "digest": ""}

    def _verdict(self, status: str, plan: Dict[str, Any], applied: List[str],
                 failed: List[str], errors: Dict[str, str], stage: str,
                 rolled_back: Optional[List[str]] = None,
                 message: str = "") -> Dict[str, Any]:
        """Build, log and remember the DHCPv4 apply result.

        Args:
            status: SUCCESS, PARTIAL or ERROR.
            plan: Rendered plan (or empty plan).
            applied: Nodes now running the candidate.
            failed: Nodes that did not end up on the candidate.
            errors: Per-node error messages.
            stage: Transaction stage that produced this verdict.
            rolled_back: Nodes that were rolled back.
            message: Optional explicit message.

        Returns:
            A copy of the verdict (also stored in last_apply).
        """
        # Common fields from the plan and the outcome.
        verdict = {
            "status": status,
            "cluster": True,
            "mode": self.mode,
            "stage": stage,
            "version": self.version,
            "applied": applied,
            "failed": failed,
            "errors": errors,
            "rolled_back": rolled_back or [],
            "order": plan["order"],
            "subnets": plan["subnets"],
            "reservations": plan["reservations"],
            "reservations_skipped": plan["reservations_skipped"],
            "digest": plan["digest"],
            "at": time.time(),
        }
        # On failure, build a readable message and log it.
        if status != "SUCCESS":
            nodes = ", ".join(failed) or "unknown"
            err_details = "; ".join(f"{k}: {v}" for k, v in errors.items() if v)
            detail_str = f" ({err_details})" if err_details else ""
            verdict["message"] = message or (
                f"Kea HA {stage} failed on: {nodes}{detail_str}"
                + (f"; rolled back {', '.join(rolled_back)}" if rolled_back else "")
                + (f"; still applied on {', '.join(applied)}" if applied else ""))
            logger.error("Kea HA apply %s at stage %s — applied=%s failed=%s",
                         status, stage, applied, failed)
        # Remember it for the UI and return a copy.
        self.last_apply = verdict
        return dict(verdict)

    def _verdict6(self, status: str, plan: Dict[str, Any], applied: List[str],
                  failed: List[str], errors: Dict[str, str], stage: str,
                  rolled_back: Optional[List[str]] = None,
                  message: str = "") -> Dict[str, Any]:
        """The DHCPv6 mirror of :meth:`_verdict` — see there for the shape."""
        # Common fields from the plan and the outcome.
        verdict = {
            "status": status,
            "cluster": True,
            "mode": self.mode,
            "stage": stage,
            "version": self.version6,
            "applied": applied,
            "failed": failed,
            "errors": errors,
            "rolled_back": rolled_back or [],
            "order": plan["order"],
            "subnets": plan["subnets"],
            "reservations": plan["reservations"],
            "reservations_skipped": plan["reservations_skipped"],
            "digest": plan["digest"],
            "at": time.time(),
        }
        # On failure, build a readable message and log it.
        if status != "SUCCESS":
            nodes = ", ".join(failed) or "unknown"
            err_details = "; ".join(f"{k}: {v}" for k, v in errors.items() if v)
            detail_str = f" ({err_details})" if err_details else ""
            verdict["message"] = message or (
                f"Kea DHCPv6 HA {stage} failed on: {nodes}{detail_str}"
                + (f"; rolled back {', '.join(rolled_back)}" if rolled_back else "")
                + (f"; still applied on {', '.join(applied)}" if applied else ""))
            logger.error("Kea DHCPv6 HA apply %s at stage %s — applied=%s failed=%s",
                         status, stage, applied, failed)
        # Remember it for the UI and return a copy.
        self.last_apply6 = verdict
        return dict(verdict)

    # ── Status ──────────────────────────────────────────────────────────────

    async def refresh_status(self, timeout: float = 15.0) -> Dict[str, Any]:
        """Collect ``status-get``-derived HA state from every node.

        A node that does not answer (or answers without a digest) has its
        remembered digest DROPPED, so ``config_converged`` cannot be satisfied
        by a stale value from a node that is no longer reporting.
        """
        # Ask every node for its HA status.
        fan = await self.transport.fanout("KEAW_HA_STATUS", {}, timeout=timeout)
        results = fan.get("results") or {}
        # Rebuild the status map from scratch.
        self.ha_status = {}
        # Record each reply.
        for member_id, reply in results.items():
            # Malformed reply: error, and forget its digest.
            if not isinstance(reply, dict):
                self.ha_status[member_id] = {"status": "ERROR",
                                             "message": "malformed reply"}
                self.config_digests.pop(member_id, None)
                continue
            # Copy the reply, adding parsed HA fields.
            record = dict(reply)
            raw = reply.get("status_get")
            if reply.get("status") == "SUCCESS" and isinstance(raw, dict):
                record["ha"] = parse_ha_status(raw)
            elif isinstance(reply.get("ha"), dict):
                record["ha"] = reply["ha"]
            # Keep the digest only from a successful reply that includes one.
            if reply.get("status") == "SUCCESS" and reply.get("digest"):
                self.config_digests[member_id] = reply["digest"]
            else:
                self.config_digests.pop(member_id, None)
            # Store this node's status.
            self.ha_status[member_id] = record
        # A member that did not answer at all must not keep a stale digest.
        for member_id in list(self.config_digests):
            if member_id not in self.ha_status:
                self.config_digests.pop(member_id, None)
        # Return the raw fan-out result.
        return fan

    def report(self) -> Dict[str, Any]:
        """The HA view the Diagnostics page renders. Pure."""
        # Invalid topology: report it as an invalid state with a recommendation.
        try:
            peers = self.peers()
        except KeaHAConfigError as e:
            return {"enabled": True, "mode": self.mode, "state": "invalid",
                    "healthy": False, "updating": False, "updating_members": [],
                    "serving": False, "serving_count": 0,
                    "config_converged": False,
                    "config_digests_missing": [m["id"] for m in self.members()],
                    "peers": [], "members": [], "member_count": len(self.members()),
                    "healthy_count": 0, "degraded": [], "unreachable": [],
                    "last_apply": dict(self.last_apply),
                    "recommendations": [f"Kea HA topology is invalid: {e}"]}
        # Build the summary from peers, links, statuses, digests and last apply.
        report = summarize_ha(self.mode, peers,
                              list(self.transport.member_links()),
                              self.ha_status, self.config_digests,
                              self.last_apply)
        # A leftover journal makes the pair degraded with a re-apply recommendation.
        if self.pending_candidate:
            report["pending_candidate"] = {
                "version": self.pending_candidate.get("version"),
                "started_at": self.pending_candidate.get("started_at"),
            }
            report["healthy"] = False
            # An unconfirmed journalled config is a REAL fault (the coordinator
            # died mid-apply), not the benign mid-apply window — so it must
            # also clear "updating", which would otherwise excuse it.
            report["updating"] = False
            if report["state"] in ("healthy", "updating"):
                report["state"] = "degraded"
            # Name nodes that may still be running the unconfirmed config.
            unrestored = self.pending_candidate.get("unrestored") or []
            report["pending_candidate"]["unrestored"] = list(unrestored)
            detail = (" These node(s) may still be running it: "
                      + ", ".join(unrestored) + "." if unrestored else "")
            report["recommendations"] = list(report["recommendations"]) + [
                f"A DHCP configuration v{self.pending_candidate.get('version')} "
                f"was journalled but never confirmed — the coordinator restarted "
                f"mid-apply or a rollback did not complete.{detail} Re-apply the "
                f"configuration to converge the pair."]
        # Return the report.
        return report

    async def status(self) -> Dict[str, Any]:
        """Refresh HA status from every node and return the DHCPv4 HA report."""
        # Refresh, then report.
        await self.refresh_status()
        return {"status": "SUCCESS", **self.report()}

    # ── Status (DHCPv6) ──────────────────────────────────────────────────────

    async def refresh_status6(self, timeout: float = 15.0) -> Dict[str, Any]:
        """The DHCPv6 mirror of :meth:`refresh_status`."""
        # Ask every node for its DHCPv6 HA status.
        fan = await self.transport.fanout("KEAW_HA_STATUS6", {}, timeout=timeout)
        results = fan.get("results") or {}
        # Rebuild the status map from scratch.
        self.ha_status6 = {}
        # Record each reply.
        for member_id, reply in results.items():
            # Malformed reply: error, and forget its digest.
            if not isinstance(reply, dict):
                self.ha_status6[member_id] = {"status": "ERROR",
                                              "message": "malformed reply"}
                self.config_digests6.pop(member_id, None)
                continue
            # Copy the reply, adding parsed HA fields.
            record = dict(reply)
            raw = reply.get("status_get")
            if reply.get("status") == "SUCCESS" and isinstance(raw, dict):
                record["ha"] = parse_ha_status(raw)
            elif isinstance(reply.get("ha"), dict):
                record["ha"] = reply["ha"]
            # Keep the digest only from a successful reply that includes one.
            if reply.get("status") == "SUCCESS" and reply.get("digest"):
                self.config_digests6[member_id] = reply["digest"]
            else:
                self.config_digests6.pop(member_id, None)
            # Store this node's status.
            self.ha_status6[member_id] = record
        # A node that did not answer must not keep a stale digest.
        for member_id in list(self.config_digests6):
            if member_id not in self.ha_status6:
                self.config_digests6.pop(member_id, None)
        # Return the raw fan-out result.
        return fan

    def report6(self) -> Dict[str, Any]:
        """The DHCPv6 mirror of :meth:`report`."""
        # Invalid topology: report it as an invalid state with a recommendation.
        try:
            peers = self.peers()
        except KeaHAConfigError as e:
            return {"enabled": True, "mode": self.mode, "state": "invalid",
                    "healthy": False, "updating": False, "updating_members": [],
                    "serving": False, "serving_count": 0,
                    "config_converged": False,
                    "config_digests_missing": [m["id"] for m in self.members()],
                    "peers": [], "members": [], "member_count": len(self.members()),
                    "healthy_count": 0, "degraded": [], "unreachable": [],
                    "last_apply": dict(self.last_apply6),
                    "recommendations": [f"Kea DHCPv6 HA topology is invalid: {e}"]}
        # Build the summary from peers, links, statuses, digests and last apply.
        report = summarize_ha(self.mode, peers,
                              list(self.transport.member_links()),
                              self.ha_status6, self.config_digests6,
                              self.last_apply6)
        # A leftover journal makes the pair degraded with a re-apply recommendation.
        if self.pending_candidate6:
            report["pending_candidate"] = {
                "version": self.pending_candidate6.get("version"),
                "started_at": self.pending_candidate6.get("started_at"),
            }
            report["healthy"] = False
            report["updating"] = False
            if report["state"] in ("healthy", "updating"):
                report["state"] = "degraded"
            # Name nodes that may still be running the unconfirmed config.
            unrestored = self.pending_candidate6.get("unrestored") or []
            report["pending_candidate"]["unrestored"] = list(unrestored)
            detail = (" These node(s) may still be running it: "
                      + ", ".join(unrestored) + "." if unrestored else "")
            report["recommendations"] = list(report["recommendations"]) + [
                f"A DHCPv6 configuration v{self.pending_candidate6.get('version')} "
                f"was journalled but never confirmed — the coordinator restarted "
                f"mid-apply or a rollback did not complete.{detail} Re-apply the "
                f"configuration to converge the pair."]
        # Return the report.
        return report

    async def status6(self) -> Dict[str, Any]:
        """Refresh DHCPv6 HA status from every node and return the DHCPv6 HA report."""
        # Refresh, then report.
        await self.refresh_status6()
        return {"status": "SUCCESS", **self.report6()}
