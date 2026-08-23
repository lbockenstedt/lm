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

from __future__ import annotations

import logging

from sync_loop import run_sync_loop  # sibling leaf

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

_RELOCATE_LOOP_S = 30.0

# Rebalancing runs far less often than the failover check (every Nth tick of
# the same loop, not a separate asyncio loop — simplest way to guarantee the
# two passes never run concurrently against the same records) and only moves
# an instance when the load gap clears this threshold, to avoid thrashing on
# a trivial 1-count difference.
_REBALANCE_EVERY_N_CYCLES = 10  # 10 * 30s = 5 min
_REBALANCE_THRESHOLD = 2


class InstanceRelocateMixin:

    async def run_instance_relocate_loop(self) -> None:
        tick = {"n": 0}

        def _guard():
            cfg = self.state.system_state.get("global_config", {}).get("instance_relocate", {})
            return bool(cfg.get("enabled", True))  # on by default — opt-in is per-record (spoke_pool)

        async def _body():
            await self._instance_relocate_cycle()
            tick["n"] += 1
            cfg = self.state.system_state.get("global_config", {}).get("instance_relocate", {})
            if tick["n"] % _REBALANCE_EVERY_N_CYCLES == 0 and cfg.get("rebalance_enabled", True):
                await self._instance_rebalance_cycle()

        def _delay():
            return _RELOCATE_LOOP_S

        await run_sync_loop(
            stagger=30, guard=_guard, body=_body, delay=_delay,
            on_error=lambda e: logger.warning("[instance-relocate] loop cycle failed: %s", e))

    async def _instance_relocate_cycle(self) -> None:
        gc = self.state.system_state.get("global_config", {})
        for storage_key, (role, module_type) in _INSTANCE_ROLE.items():
            for inst in list(gc.get(storage_key, []) or []):
                if not isinstance(inst, dict):
                    continue
                pool = inst.get("spoke_pool") or []
                if not pool:
                    continue  # no failover candidates configured — plain PR1 behavior
                active = inst.get("spoke_id")
                if active and self._primary_key(active) in self.active_connections:
                    continue  # healthy
                await self._relocate_instance(inst, storage_key, role, module_type, pool)

    async def _relocate_instance(self, inst, storage_key, role, module_type, pool) -> None:
        old_active = inst.get("spoke_id")
        name = inst.get("name") or inst.get("id") or "?"
        new_sub_id = None
        for base_id in pool:
            if not isinstance(base_id, str) or not base_id:
                continue
            try:
                new_sub_id = await self._relocate_load_role(base_id, role, module_type)
            except Exception as e:  # noqa: BLE001 — one candidate's failure tries the next
                logger.debug("[instance-relocate] %s candidate %s not viable: %s",
                             storage_key, base_id, e)
                new_sub_id = None
            if new_sub_id:
                break
        if not new_sub_id:
            logger.warning("[instance-relocate] %s '%s': all %d pool candidate(s) unavailable — "
                           "staying on %s (unreachable)", storage_key, name, len(pool), old_active)
            return
        await self._activate_relocation(inst, storage_key, role, old_active, new_sub_id,
                                        reason="failover")

    async def _activate_relocation(self, inst, storage_key, role, old_active, new_sub_id,
                                   *, reason: str) -> None:
        """Common tail of a relocation, whichever pass decided to make one:
        write the new spoke_id, push its config (the same plumbing a normal
        reconnect already uses), and best-effort unload the old spoke if
        nothing else still references it."""
        name = inst.get("name") or inst.get("id") or "?"
        inst["spoke_id"] = new_sub_id
        self.state._mark_dirty()
        logger.warning("[instance-relocate] %s '%s': %s from %s to %s",
                       storage_key, name, reason, old_active, new_sub_id)
        try:
            await self.push_config_to_spoke(new_sub_id)
        except Exception as e:  # noqa: BLE001
            logger.warning("[instance-relocate] config push to %s failed: %s", new_sub_id, e)
        if old_active and old_active != new_sub_id:
            await self._relocate_unload_orphan(old_active, role, storage_key, inst.get("id"))

    async def _relocate_load_role(self, base_id, role, module_type):
        """Minimal inline LOAD_ROLE — see module docstring for why this
        isn't just a call to routes/role_pool.py's ensure_role_loaded."""
        pk = self._primary_key(base_id)
        sub_id = f"{base_id}-{role}"
        sub_pk = self._primary_key(sub_id)
        if sub_pk in self.active_connections and self.spoke_module_types.get(sub_pk) == module_type:
            return sub_id
        if pk not in self.active_connections:
            return None  # this candidate's base agent isn't even up
        res = await self.request_response(base_id, "LOAD_ROLE",
                                          {"role": role, "config": {}}, timeout=120.0)
        payload = res.get("payload", {}).get("data", res) if isinstance(res, dict) else res
        if not isinstance(payload, dict) or payload.get("status") != "SUCCESS":
            return None
        return payload.get("sub_spoke_id") or sub_id

    async def _relocate_unload_orphan(self, old_sub_id, role, storage_key, excluding_id) -> None:
        """Best-effort UNLOAD_ROLE on the old spoke's base agent, if no OTHER
        instance in this product still references it — never raises, a
        cleanup failure must not disrupt the relocation that already
        happened. Mirrors routes/role_pool.py's maybe_unload_orphaned_role."""
        others = self.state.system_state.get("global_config", {}).get(storage_key, []) or []
        still_used = any(isinstance(r, dict) and r.get("id") != excluding_id
                        and r.get("spoke_id") == old_sub_id for r in others)
        if still_used:
            return
        base_id = self._relocate_base_id(old_sub_id, role)
        if base_id == old_sub_id or self._primary_key(base_id) not in self.active_connections:
            return  # unrecognized shape, or the old base agent isn't reachable — nothing to send to
        try:
            await self.request_response(base_id, "UNLOAD_ROLE", {"role": role}, timeout=60.0)
        except Exception as e:  # noqa: BLE001
            logger.debug("[instance-relocate] unload %s on %s failed: %s", role, base_id, e)

    @staticmethod
    def _relocate_base_id(sub_id, role) -> str:
        suffix = f"-{role}"
        return sub_id[:-len(suffix)] if sub_id.endswith(suffix) else sub_id

    # ── load-based rebalancing (PR3) ─────────────────────────────────────────

    def _compute_instance_load(self, gc) -> dict:
        """{base_agent_id: count of instances (across all 3 products) whose
        CURRENTLY CONNECTED active spoke resolves to that base agent}. The
        simplest load signal available with no new telemetry — deliberately
        not resource-based (see module docstring)."""
        load: dict = {}
        for storage_key, (role, _module_type) in _INSTANCE_ROLE.items():
            for inst in gc.get(storage_key, []) or []:
                if not isinstance(inst, dict):
                    continue
                active = inst.get("spoke_id")
                if not active or self._primary_key(active) not in self.active_connections:
                    continue
                base_id = self._relocate_base_id(active, role)
                load[base_id] = load.get(base_id, 0) + 1
        return load

    def _candidate_viable(self, base_id, role, module_type) -> bool:
        """Cheap, side-effect-free check for whether a pool candidate is at
        least worth considering as a rebalance target — the actual LOAD_ROLE
        (if needed) only happens for the one candidate finally chosen."""
        sub_pk = self._primary_key(f"{base_id}-{role}")
        if sub_pk in self.active_connections and self.spoke_module_types.get(sub_pk) == module_type:
            return True
        return self._primary_key(base_id) in self.active_connections

    async def _instance_rebalance_cycle(self) -> None:
        gc = self.state.system_state.get("global_config", {})
        load = self._compute_instance_load(gc)
        for storage_key, (role, module_type) in _INSTANCE_ROLE.items():
            for inst in list(gc.get(storage_key, []) or []):
                if not isinstance(inst, dict):
                    continue
                pool = inst.get("spoke_pool") or []
                if not pool:
                    continue
                active = inst.get("spoke_id")
                if not active or self._primary_key(active) not in self.active_connections:
                    continue  # unhealthy — the failover pass owns this, not rebalancing
                current_base = self._relocate_base_id(active, role)
                current_load = load.get(current_base, 0)
                best_base, best_load = None, None
                for base_id in pool:
                    if not isinstance(base_id, str) or not base_id or base_id == current_base:
                        continue
                    if not self._candidate_viable(base_id, role, module_type):
                        continue
                    candidate_load = load.get(base_id, 0)
                    if best_load is None or candidate_load < best_load:
                        best_base, best_load = base_id, candidate_load
                if best_base is None or best_load > current_load - _REBALANCE_THRESHOLD:
                    continue  # no candidate clears the threshold — leave it alone
                try:
                    new_sub_id = await self._relocate_load_role(best_base, role, module_type)
                except Exception as e:  # noqa: BLE001
                    logger.debug("[instance-relocate] rebalance candidate %s not viable: %s",
                                 best_base, e)
                    continue
                if not new_sub_id:
                    continue
                await self._activate_relocation(inst, storage_key, role, active, new_sub_id,
                                                reason="rebalanced")
                load[current_base] = max(0, current_load - 1)
                load[best_base] = best_load + 1
