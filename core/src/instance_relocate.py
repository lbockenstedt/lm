"""Coordinator-role instance pool failover + load rebalancing for the Hub.

A self-contained subsystem gathered here as a **mixin** (same pattern as
``spoke_alert_sync.py``/``fleet_health_alert.py``) so the Hub class body
doesn't grow with per-loop logic.

Three-part design (see project memory
``coordinator-role-pool-and-failover-design.md``):

- **PR1** (routes/role_pool.py) let an operator bind a coordinator-role
  instance (NAC/ClearPass, IPAM/NetBox, LDAP/directory) to a spoke and have
  LOAD_ROLE fire automatically.
- **PR2** (this file, failover half) added an optional ``spoke_pool`` (a
  checkbox-selected, unordered list of candidate base-agent ids) to an
  instance record: when the CURRENTLY active spoke (``spoke_id``, resolved by
  PR1 to a role sub-spoke id) goes out of contact, relocate the instance to
  another connected pool candidate — cold switch, single-writer at all times
  (never splits/shares one instance across multiple spokes), and deliberately
  **no auto-failback**: once relocated, the instance simply stays on its new
  spoke; a returned original node is just an ordinary candidate again for a
  FUTURE relocation, never automatically reclaimed.
- **PR3** (this file, rebalance half) adds a much slower, separate pass that
  proactively moves an instance to a less-loaded pool candidate when
  everything is HEALTHY (not reacting to a failure) — same single-writer
  relocation primitive, different trigger. "Load" is deliberately the
  simplest signal that needs no new telemetry: how many instances (across all
  three products) currently have their active spoke resolving to a given
  base agent. Only relocates when the gap is large enough
  (``_REBALANCE_THRESHOLD``) and only every ``_REBALANCE_EVERY_N_CYCLES``
  failover-loop ticks, specifically to avoid thrashing — a small 1-count
  imbalance is not worth an automatic move.

A record with no ``spoke_pool`` (or an empty one) is untouched by either
pass — that's the plain PR1 single-spoke behavior, unchanged.

A nice emergent property worth calling out in the failover pass: candidates
are tried in stored order, INCLUDING the currently-active one's own base
agent. If only that spoke's role *sub*-connection died (the role process
crashed) while its base-agent connection is still alive, this self-heals in
place — LOAD_ROLE just restarts the role on the same box — rather than
needlessly moving to a different one. Only a base agent that's actually
unreachable gets skipped.

A leaf: stdlib only. MUST NOT import ``main``, ``api``, or ``routes.*``
(dependency direction is ``main -> instance_relocate`` only, mirroring
spoke_alert_sync.py's convention) — talks to spokes only via
``self.request_response``/``self._primary_key``/``self.active_connections``
(available on ``self`` once mixed into LabManagerHub). This means the
LOAD_ROLE/UNLOAD_ROLE calls below are a deliberately-duplicated, minimal
subset of routes/role_pool.py's ensure_role_loaded/maybe_unload_orphaned_role
— not imported, to keep this module import-clean. If that duplication ever
drifts, keep this file's behavior in sync with role_pool.py's by hand (same
as the tenant_devices.py/nw.py "MIRROR" convention it inherited from).

Audience: Hub developers.
"""

# Postpone evaluation of type hints (keeps this leaf module cheap to import).
from __future__ import annotations

# logging records relocations and failures.
import logging

# Shared helper that runs a guarded, periodic loop with staggered start and error handling.
from sync_loop import run_sync_loop  # sibling leaf

# Use the hub's logger so relocation messages appear with other hub logs.
logger = logging.getLogger("Hub")

# storage_key (global_config list) -> (LOAD_ROLE/UNLOAD_ROLE role name, module_type
# the resulting sub-spoke self-reports). Mirrors routes/role_pool.py's
# PRODUCT_ROLE, keyed by storage_key instead of route-prefix since this loop
# reads global_config directly rather than going through a CRUD route.
_INSTANCE_ROLE = {
    "nac_instances":  ("cppm", "nac"),
    "ipam_instances": ("netbox", "ipam"),
    "ldap_instances": ("ldap", "directory"),
}

# Seconds between failover checks.
_RELOCATE_LOOP_S = 30.0

# Rebalancing runs far less often than the failover check (every Nth tick of
# the same loop, not a separate asyncio loop — simplest way to guarantee the
# two passes never run concurrently against the same records) and only moves
# an instance when the load gap clears this threshold, to avoid thrashing on
# a trivial 1-count difference.
_REBALANCE_EVERY_N_CYCLES = 10  # 10 * 30s = 5 min
# Minimum load gap (instance count) before a rebalance move is worth making.
_REBALANCE_THRESHOLD = 2


class InstanceRelocateMixin:

    """Mixin adding coordinator-instance failover and load rebalancing to the Hub."""
    async def run_instance_relocate_loop(self) -> None:
        """Run the periodic failover check, with a slower rebalance pass every Nth tick."""
        # Mutable tick counter shared with the nested body function.
        tick = {"n": 0}

        def _guard():
            """Return True when the relocation feature is enabled in global config."""
            cfg = self.state.system_state.get("global_config", {}).get("instance_relocate", {})
            return bool(cfg.get("enabled", True))  # on by default — opt-in is per-record (spoke_pool)

        async def _body():
            """One loop iteration: failover check, then rebalance every Nth tick if enabled."""
            await self._instance_relocate_cycle()
            # Count ticks and re-read config so the rebalance switch takes effect live.
            tick["n"] += 1
            cfg = self.state.system_state.get("global_config", {}).get("instance_relocate", {})
            # Every Nth tick (and only if enabled) run the rebalance pass.
            if tick["n"] % _REBALANCE_EVERY_N_CYCLES == 0 and cfg.get("rebalance_enabled", True):
                await self._instance_rebalance_cycle()

        def _delay():
            """Return the fixed delay between loop iterations."""
            return _RELOCATE_LOOP_S

        # Hand the three callbacks to the shared loop runner, which logs any cycle failure.
        await run_sync_loop(
            stagger=30, guard=_guard, body=_body, delay=_delay,
            on_error=lambda e: logger.warning("[instance-relocate] loop cycle failed: %s", e))

    async def _instance_relocate_cycle(self) -> None:
        """Relocate every pooled instance whose active spoke is out of contact."""
        # Global config holds the instance lists for each product.
        gc = self.state.system_state.get("global_config", {})
        # Check every instance of every product.
        for storage_key, (role, module_type) in _INSTANCE_ROLE.items():
            for inst in list(gc.get(storage_key, []) or []):
                # Skip malformed records.
                if not isinstance(inst, dict):
                    continue
                pool = inst.get("spoke_pool") or []
                if not pool:
                    continue  # no failover candidates configured — plain PR1 behavior
                # The instance is healthy if its active spoke is connected.
                active = inst.get("spoke_id")
                if active and self._primary_key(active) in self.active_connections:
                    continue  # healthy
                # Active spoke is gone: try to move the instance to another pool candidate.
                await self._relocate_instance(inst, storage_key, role, module_type, pool)

    async def _relocate_instance(self, inst, storage_key, role, module_type, pool) -> None:
        """Move one instance to the first viable pool candidate (failover path)."""
        # Remember where it was and a readable name for logs.
        old_active = inst.get("spoke_id")
        name = inst.get("name") or inst.get("id") or "?"
        new_sub_id = None
        # Try pool candidates in stored order until one hosts the role.
        for base_id in pool:
            # Skip blank/invalid entries and candidates outside the instance's tenant.
            if not isinstance(base_id, str) or not base_id:
                continue
            if not self._pool_candidate_allowed(inst, base_id):
                continue
            # Try loading the role on this candidate.
            try:
                new_sub_id = await self._relocate_load_role(base_id, role, module_type)
            except Exception as e:  # noqa: BLE001 — one candidate's failure tries the next
                # A failing candidate is logged and the next one is tried.
                logger.debug("[instance-relocate] %s candidate %s not viable: %s",
                             storage_key, base_id, e)
                new_sub_id = None
            # Stop at the first candidate that worked.
            if new_sub_id:
                break
        # No candidate worked: stay put and warn.
        if not new_sub_id:
            logger.warning("[instance-relocate] %s '%s': all %d pool candidate(s) unavailable — "
                           "staying on %s (unreachable)", storage_key, name, len(pool), old_active)
            return
        # Commit the move.
        await self._activate_relocation(inst, storage_key, role, old_active, new_sub_id,
                                        reason="failover")

    async def _activate_relocation(self, inst, storage_key, role, old_active, new_sub_id,
                                   *, reason: str) -> None:
        """Common tail of a relocation, whichever pass decided to make one:
        write the new spoke_id, push its config (the same plumbing a normal
        reconnect already uses), and best-effort unload the old spoke if
        nothing else still references it."""
        # Point the instance at the new spoke and mark state for saving.
        name = inst.get("name") or inst.get("id") or "?"
        inst["spoke_id"] = new_sub_id
        self.state._mark_dirty()
        # Log the move prominently (it changes where the product runs).
        logger.warning("[instance-relocate] %s '%s': %s from %s to %s",
                       storage_key, name, reason, old_active, new_sub_id)
        # Push the instance's config to the new spoke.
        try:
            await self.push_config_to_spoke(new_sub_id)
        except Exception as e:  # noqa: BLE001
            # A config push failure is logged; the next reconnect will push again.
            logger.warning("[instance-relocate] config push to %s failed: %s", new_sub_id, e)
        # Clean up the old spoke if it is a different one.
        if old_active and old_active != new_sub_id:
            await self._relocate_unload_orphan(old_active, role, storage_key, inst.get("id"))

    def _pool_candidate_allowed(self, inst, base_id) -> bool:
        """A spoke_pool candidate may only host this instance's role if it is
        in the instance's own tenant or the shared tenant (access.
        tenant_may_manage). spoke_pool is saved without validation, so the
        automatic failover/rebalance passes must enforce it — otherwise they
        LOAD_ROLE onto another tenant's agent that nobody asked for."""
        # Imported lazily so this module stays a leaf with no import-time dependencies.
        from access import tenant_may_manage  # lazy: keep this mixin a leaf
        # Compare the candidate spoke's tenant with the instance's tenant.
        candidate_tenant = self.state.get_spoke_tenant(self._primary_key(base_id)) or ""
        target_tenant = inst.get("tenant_id") or ""
        # Allowed when the candidate's tenant may manage the instance's tenant.
        if tenant_may_manage(candidate_tenant, target_tenant):
            return True
        # Otherwise warn and refuse the candidate.
        logger.warning("[instance-relocate] '%s': pool candidate %s (tenant %r) is outside "
                       "the instance's tenant %r — skipped",
                       inst.get("name") or inst.get("id") or "?", base_id,
                       candidate_tenant, target_tenant)
        return False

    async def _relocate_load_role(self, base_id, role, module_type):
        """Minimal inline LOAD_ROLE — see module docstring for why this
        isn't just a call to routes/role_pool.py's ensure_role_loaded."""
        # Work out the base agent and the role sub-spoke ids.
        pk = self._primary_key(base_id)
        sub_id = f"{base_id}-{role}"
        sub_pk = self._primary_key(sub_id)
        # Role sub-spoke already connected with the right type: nothing to load.
        if sub_pk in self.active_connections and self.spoke_module_types.get(sub_pk) == module_type:
            return sub_id
        # Base agent is offline, so this candidate cannot host the role.
        if pk not in self.active_connections:
            return None  # this candidate's base agent isn't even up
        # Ask the base agent to load the role (can take a while, hence 120s).
        res = await self.request_response(base_id, "LOAD_ROLE",
                                          {"role": role, "config": {}}, timeout=120.0)
        # Unwrap the response envelope and require an explicit SUCCESS.
        payload = res.get("payload", {}).get("data", res) if isinstance(res, dict) else res
        if not isinstance(payload, dict) or payload.get("status") != "SUCCESS":
            return None
        # Prefer the sub-spoke id the agent reports, else the conventional one.
        return payload.get("sub_spoke_id") or sub_id

    async def _relocate_unload_orphan(self, old_sub_id, role, storage_key, excluding_id) -> None:
        """Best-effort UNLOAD_ROLE on the old spoke's base agent, if no OTHER
        instance in this product still references it — never raises, a
        cleanup failure must not disrupt the relocation that already
        happened. Mirrors routes/role_pool.py's maybe_unload_orphaned_role."""
        # Is any other instance of this product still using the old spoke?
        others = self.state.system_state.get("global_config", {}).get(storage_key, []) or []
        still_used = any(isinstance(r, dict) and r.get("id") != excluding_id
                        and r.get("spoke_id") == old_sub_id for r in others)
        # Still in use: leave the role loaded.
        if still_used:
            return
        # Derive the base agent id from the role sub-spoke id.
        base_id = self._relocate_base_id(old_sub_id, role)
        if base_id == old_sub_id or self._primary_key(base_id) not in self.active_connections:
            return  # unrecognized shape, or the old base agent isn't reachable — nothing to send to
        # Ask the base agent to unload the role; failures are only logged.
        try:
            await self.request_response(base_id, "UNLOAD_ROLE", {"role": role}, timeout=60.0)
        except Exception as e:  # noqa: BLE001
            logger.debug("[instance-relocate] unload %s on %s failed: %s", role, base_id, e)

    @staticmethod
    def _relocate_base_id(sub_id, role) -> str:
        """Strip the "-<role>" suffix from a sub-spoke id to get its base agent id."""
        suffix = f"-{role}"
        return sub_id[:-len(suffix)] if sub_id.endswith(suffix) else sub_id

    # ── load-based rebalancing (PR3) ─────────────────────────────────────────

    def _compute_instance_load(self, gc) -> dict:
        """{base_agent_id: count of instances (across all 3 products) whose
        CURRENTLY CONNECTED active spoke resolves to that base agent}. The
        simplest load signal available with no new telemetry — deliberately
        not resource-based (see module docstring)."""
        # Count connected active instances per base agent across all products.
        load: dict = {}
        for storage_key, (role, _module_type) in _INSTANCE_ROLE.items():
            for inst in gc.get(storage_key, []) or []:
                # Skip malformed records and instances whose active spoke is offline.
                if not isinstance(inst, dict):
                    continue
                active = inst.get("spoke_id")
                if not active or self._primary_key(active) not in self.active_connections:
                    continue
                # Attribute the instance to its base agent.
                base_id = self._relocate_base_id(active, role)
                load[base_id] = load.get(base_id, 0) + 1
        return load

    def _candidate_viable(self, base_id, role, module_type) -> bool:
        """Cheap, side-effect-free check for whether a pool candidate is at
        least worth considering as a rebalance target — the actual LOAD_ROLE
        (if needed) only happens for the one candidate finally chosen."""
        # Role sub-spoke already connected with the right type: definitely viable.
        sub_pk = self._primary_key(f"{base_id}-{role}")
        if sub_pk in self.active_connections and self.spoke_module_types.get(sub_pk) == module_type:
            return True
        # Otherwise viable only if the base agent is up (the role can be loaded).
        return self._primary_key(base_id) in self.active_connections

    async def _instance_rebalance_cycle(self) -> None:
        """Move healthy pooled instances to a less-loaded candidate when the gap is big enough."""
        # Read config and compute the current per-agent load.
        gc = self.state.system_state.get("global_config", {})
        load = self._compute_instance_load(gc)
        # Consider every instance of every product.
        for storage_key, (role, module_type) in _INSTANCE_ROLE.items():
            for inst in list(gc.get(storage_key, []) or []):
                # Skip malformed records and instances without a pool.
                if not isinstance(inst, dict):
                    continue
                pool = inst.get("spoke_pool") or []
                if not pool:
                    continue
                # Only healthy instances are rebalanced.
                active = inst.get("spoke_id")
                if not active or self._primary_key(active) not in self.active_connections:
                    continue  # unhealthy — the failover pass owns this, not rebalancing
                # Current base agent and its load.
                current_base = self._relocate_base_id(active, role)
                current_load = load.get(current_base, 0)
                # Find the least-loaded viable, allowed candidate other than the current one.
                best_base, best_load = None, None
                for base_id in pool:
                    # Skip invalid entries and the current base agent.
                    if not isinstance(base_id, str) or not base_id or base_id == current_base:
                        continue
                    # Skip offline candidates and candidates outside the tenant.
                    if not self._candidate_viable(base_id, role, module_type):
                        continue
                    if not self._pool_candidate_allowed(inst, base_id):
                        continue
                    # Track the lowest-load candidate seen so far.
                    candidate_load = load.get(base_id, 0)
                    if best_load is None or candidate_load < best_load:
                        best_base, best_load = base_id, candidate_load
                if best_base is None or best_load > current_load - _REBALANCE_THRESHOLD:
                    continue  # no candidate clears the threshold — leave it alone
                # Load the role on the chosen candidate; skip this instance on failure.
                try:
                    new_sub_id = await self._relocate_load_role(best_base, role, module_type)
                except Exception as e:  # noqa: BLE001
                    logger.debug("[instance-relocate] rebalance candidate %s not viable: %s",
                                 best_base, e)
                    continue
                # Loading did not succeed; leave the instance where it is.
                if not new_sub_id:
                    continue
                # Commit the move.
                await self._activate_relocation(inst, storage_key, role, active, new_sub_id,
                                                reason="rebalanced")
                # Update the in-memory load so later decisions this pass see the move.
                load[current_base] = max(0, current_load - 1)
                load[best_base] = best_load + 1
