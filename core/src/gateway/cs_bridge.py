"""CSBridgePoller — the hub bridge between the cs (Client-Simulation) spoke's
command queue and the unified pxmx agents (Phase D2).

Architecture invariant (see the unify plan): a pxmx agent opens exactly one
socket — either to a dedicated pxmx (hypervisor) spoke, or directly to a cs
(simulation) spoke's own ``/ws/agent`` listener (the split-topology case,
``AgentHostingControlPlane`` shared by both spoke types). It never contacts
the cs spoke for command relay in either case — the hub mediates. This loop
is the mediator's "command delivery + USB-config sync" half
(``_relay_cs_event`` in ``main.py`` is the other half — agent events → cs spoke).

Each tick (``CS_POLL_INTERVAL_S``, default 5s):

  1. Resolve every connected agent-hosting spoke — hypervisor (pxmx) AND
     simulation (cs) types, since either can hold an agent's live WS.
  2. ``GET_AGENTS`` on each for its connected-agent list (with hostnames).
  3. For every agent whose ``agent_config[aid].client_simulation.enabled`` is
     true, resolve its cs spoke (``get_client_sim_spoke(tenant_id)``) and
     ``CS_POLL_AGENT_INBOX{hostname}`` — the cs spoke returns pending commands
     (already marked ``delivered``) and resets stale (>30s, unacked) ones.
  4. Relay each command to the agent as ``CS_COMMAND`` through the owning
     spoke's ``SPOKE_RELAY`` (``{target_agent_id, command:"CS_COMMAND", data}``).
     The spoke's ``send_to_agent`` enforces a 15s sync window, so the relay
     waits up to ``CS_RELAY_TIMEOUT_S`` (16s). Fast commands return
     ``{status:SUCCESS|ERROR}``; long ops return ``{status:ACCEPTED}`` (Phase E
     streams ``CS_PROGRESS`` + a terminal ``CS_COMMAND_RESULT`` that the agent
     emits up and the D1 relay maps to ``CS_INGEST_COMMAND_RESULT`` → ack).
  5. On a synchronous terminal result, ``CS_ACK_COMMAND{id, status, message}``
     back to the cs spoke (``completed``/``failed``). ``ACCEPTED`` is left
     ``delivered`` (no ack) for Phase E to close out.

Every ``CS_USB_CONFIG_INTERVAL_S`` (default 60s) per agent, ``CS_GET_USB_CONFIG``
is fetched from the cs spoke, diffed against the last pushed blob, and on change
pushed to the agent via ``SET_AGENT_CONFIG`` → ``UPDATE_CONFIG`` so
``agent.config["client_simulation"]["usb_config"]`` stays in sync. The cs spoke
is authoritative for USB-provision knobs; the hub store is not touched (the
spoke persists the merged config spoke-side for reconnect re-push).

Best-effort throughout: a missing agent-host/cs spoke, an offline agent, or a
relay failure is logged at debug and skipped — it never breaks the loop or the
agent's own telemetry/heartbeat.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from typing import Any, Dict, Optional

logger = logging.getLogger("CSBridge")


def _env_int(name: str, default: int, minimum: int = 1) -> int:
    try:
        return max(minimum, int(os.environ.get(name, str(default))))
    except Exception:
        return default


def _unwrap(result: Any) -> Dict[str, Any]:
    """Unwrap a spoke reply the way api.py does: result["payload"]["data"]."""
    if isinstance(result, dict):
        data = result.get("payload", {}).get("data", result)
        return data if isinstance(data, dict) else (result if isinstance(result, dict) else {})
    return {}


class CSBridgePoller:
    """One long-lived hub task. Polls the cs spoke's inbox for every
    CS-enabled connected agent — whether it's hosted by a pxmx (hypervisor)
    spoke or a cs (simulation) spoke's own agent listener — and relays
    commands + USB config to whichever spoke actually holds its connection."""

    def __init__(self, hub) -> None:
        self.hub = hub
        self.poll_interval = _env_int("CS_POLL_INTERVAL_S", 5, 2)
        self.usb_interval = _env_int("CS_USB_CONFIG_INTERVAL_S", 60, 30)
        # Re-push the agent's config even when UNCHANGED at least this often, so
        # an agent that restarted (self-update) and lost its in-memory config —
        # and therefore client-simulation mode + its CS_TELEMETRY (VM Server VMs
        # + USB) — gets it back within one interval instead of never (the hub's
        # change-detection cache survives the agent restart, so "unchanged"
        # would otherwise mean "never re-sent"). UPDATE_CONFIG is idempotent on
        # the agent (same enabled state → no restart), so this is cheap.
        self.repush_interval = _env_int("CS_CONFIG_REPUSH_S", 120, 30)
        # Slightly above the pxmx spoke's send_to_agent 15s sync window so a
        # slow-but-successful fast command isn't falsely timed out by the hub.
        self.relay_timeout = _env_int("CS_RELAY_TIMEOUT_S", 16, 5) + 0.0
        # Per-agent USB-config sync state.
        self._last_usb_cfg: Dict[str, str] = {}   # agent_id -> canonical blob sig
        self._last_usb_push: Dict[str, float] = {}  # agent_id -> ts (last check)
        self._last_actual_push: Dict[str, float] = {}  # agent_id -> ts (last SEND)
        self._last_diag: Dict[str, str] = {}  # agent_id -> last [cs-bridge] decision (throttle)
        self._last_cycle_diag: str = ""  # last [cs-bridge] cycle summary (throttle)

    # ── main loop ──────────────────────────────────────────────────────────

    async def run(self) -> None:
        # Let spokes/agents connect before the first poll.
        await asyncio.sleep(5)
        logger.info("CS bridge loop started (poll=%ds, usb=%ds)",
                    self.poll_interval, self.usb_interval)
        while True:
            try:
                await self._tick()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                logger.warning("CS bridge tick error: %s", exc)
            await asyncio.sleep(self.poll_interval)

    async def _tick(self) -> None:
        hub = self.hub
        # An agent can connect through a dedicated pxmx (hypervisor) spoke OR
        # directly to a cs (simulation) spoke's own /ws/agent listener (the
        # split-topology case). Hardcoding a single hypervisor spoke here meant
        # a cs-hosted agent's queued commands (VM start/stop/delete/...) were
        # NEVER relayed at all when no separate pxmx spoke was connected — the
        # loop returned before it ever looked at GET_AGENTS, so they just sat
        # in the cs spoke's local queue until the 15-minute expiry. Mirrors
        # get_spoke_for_agent's fallback_hypervisor=False contract (see its
        # docstring — this loop is the caller it names) by resolving agents
        # from every agent-hosting spoke, not just one.
        agent_spokes = list(dict.fromkeys(
            hub.get_all_spokes_by_type("hypervisor") + hub.get_all_spokes_by_type("simulation")
        ))
        now = time.time()
        n_agents = n_active = 0
        for host_spoke in agent_spokes:
            agents = await self._connected_agents(host_spoke)
            if not agents:
                continue
            for a in agents:
                n_agents += 1
                aid = a.get("agent_id")
                hostname = a.get("hostname") or aid
                if not aid:
                    continue
                cfg_key, ac_entry = self._agent_config_entry(aid, hostname)
                # Heal a hostname-keyed (or otherwise stale-keyed) entry to the
                # runtime agent_id ONCE, so this stops recurring and the tolerant
                # lookup becomes belt-and-suspenders. Safe no-op when already
                # keyed by agent_id or when nothing is stored.
                if cfg_key != aid and ac_entry:
                    self._migrate_agent_config_key(cfg_key, aid)
                    cfg_key, ac_entry = self._agent_config_entry(aid, hostname)
                cs_cfg = ac_entry.get("client_simulation") or {}
                enabled = bool(cs_cfg.get("enabled"))
                tenant_id = cs_cfg.get("tenant_id") or self._spoke_tenant(host_spoke)
                cs_spoke = hub.get_client_sim_spoke(tenant_id) if enabled else None

                # Emit the provisioning decision (and WHY it skipped) as a
                # greppable [cs-bridge] line, relayed to the hub log / WebUI Logs
                # so "CS-enabled agents: N but nothing provisions" is diagnosable
                # WITHOUT SSH+jq. Throttled to state-changes (INFO on change,
                # DEBUG when steady) so it doesn't spam every 60s cycle.
                if not enabled:
                    decision = (f"SKIP not-enabled — client_simulation.enabled not set "
                                f"under agent_config key {aid!r} or {hostname!r} "
                                f"(if the UI shows CS-enabled>0 it was saved under a "
                                f"different key)")
                elif not cs_spoke:
                    decision = (f"SKIP no-cs-spoke — client_simulation.enabled=on but no "
                                f"client-sim spoke is bound to tenant {tenant_id!r}")
                else:
                    keynote = "" if cfg_key == aid else f" [config keyed by {cfg_key!r}, not agent_id — re-save to normalize]"
                    decision = f"ACTIVE — tenant={tenant_id} cs_spoke={cs_spoke}{keynote}"
                self._log_agent_diag(host_spoke, aid, hostname, decision)

                if not enabled or not cs_spoke:
                    continue
                n_active += 1

                await self._relay_inbox(host_spoke, cs_spoke, aid, hostname)

                if now - self._last_usb_push.get(aid, 0.0) >= self.usb_interval:
                    await self._sync_usb_config(host_spoke, cs_spoke, aid, hostname, now)

        # Cycle heartbeat so "the bridge saw N agents, M active" is visible in the
        # hub log / WebUI Logs even when it does nothing (0 spokes / 0 agents /
        # all skipped) — throttled to changes so a steady fleet doesn't spam.
        cyc = f"spokes={len(agent_spokes)} agents={n_agents} active={n_active}"
        if cyc != self._last_cycle_diag:
            self._last_cycle_diag = cyc
            logger.info("[cs-bridge] cycle: %s", cyc)
        else:
            logger.debug("[cs-bridge] cycle: %s", cyc)

    # ── helpers ────────────────────────────────────────────────────────────

    async def _connected_agents(self, host_spoke: str) -> list:
        resp = await self.hub.request_response(host_spoke, "GET_AGENTS", {}, timeout=30.0)
        data = _unwrap(resp)
        agents = data.get("agents", []) if isinstance(data, dict) else []
        return [a for a in agents if isinstance(a, dict) and a.get("agent_id")]

    def _agent_config_entry(self, agent_id: str, hostname: str = None):
        """Return ``(key, entry)`` for an agent's stored ``agent_config``, tolerant
        of the entry being keyed by the runtime ``agent_id`` OR the ``hostname``.

        Historically the bridge keyed strictly by ``agent_id`` while the WebUI
        count (simulations/routes.py) scans values — so a per-agent enable saved
        under the hostname (or an older id) showed "CS-enabled agents: 1" yet the
        bridge never matched it, so usb_config never reached the agent and
        auto-provision reported "no dongle_vidpids configured". Prefer an exact
        agent_id match; fall back to hostname. Returns ``(agent_id, {})`` on miss."""
        try:
            store = self.hub.state.system_state.get("agent_config", {}) or {}
        except Exception:
            return agent_id, {}
        for key in (agent_id, hostname):
            if key and isinstance(store.get(key), dict):
                return key, store[key]
        return agent_id, {}

    def _client_simulation(self, agent_id: str, hostname: str = None) -> Dict[str, Any]:
        _key, entry = self._agent_config_entry(agent_id, hostname)
        return entry.get("client_simulation") or {}

    def _migrate_agent_config_key(self, old_key: str, new_key: str) -> None:
        """Permanently re-key an ``agent_config`` entry from a hostname (or other
        stale id) to the runtime ``agent_id``, then persist. Load-time can't do
        this — the hostname→agent_id map only exists once a live ``GET_AGENTS``
        returns — so the bridge heals it on the first cycle it sees the mismatch.
        After this the tolerant ``_agent_config_entry`` lookup is belt-and-
        suspenders, not load-bearing. On the rare case both keys exist, the
        stale entry's explicit client_simulation (the operator's enable/tenant)
        wins, but any usb_config already on the agent_id entry is preserved."""
        try:
            store = self.hub.state.system_state.get("agent_config", {}) or {}
            if old_key == new_key or old_key not in store:
                return
            src = store.pop(old_key)
            dst = store.get(new_key) or {}
            merged = {**dst, **src}  # operator-set src wins on collisions
            src_cs = src.get("client_simulation") or {}
            dst_cs = dst.get("client_simulation") or {}
            cs = {**dst_cs, **src_cs}
            if "usb_config" not in src_cs and dst_cs.get("usb_config"):
                cs["usb_config"] = dst_cs["usb_config"]
            if cs:
                merged["client_simulation"] = cs
            store[new_key] = merged
            self.hub.state.save_state()
            logger.info("[cs-bridge] migrated agent_config key %r → %r "
                        "(runtime agent_id) — hostname-keyed enable normalized",
                        old_key, new_key)
        except Exception as exc:  # noqa: BLE001
            logger.warning("[cs-bridge] agent_config re-key %r→%r failed: %s",
                           old_key, new_key, exc)

    def _log_agent_diag(self, host_spoke: str, agent_id: str,
                        hostname: str, decision: str) -> None:
        """Emit the per-agent CS-provisioning decision as a greppable
        ``[cs-bridge]`` line so the WHOLE gate (enabled? tenant? cs spoke? key
        mismatch?) is visible in the hub log / WebUI Logs without SSH+jq.
        INFO on a state change (so a broken agent is loud), DEBUG when steady
        (so a healthy fleet doesn't spam every 60s cycle)."""
        line = f"[cs-bridge] {agent_id} (host {hostname} via {host_spoke}): {decision}"
        if self._last_diag.get(agent_id) != decision:
            self._last_diag[agent_id] = decision
            logger.info(line)
        else:
            logger.debug(line)

    def _spoke_tenant(self, spoke_id: str) -> Optional[str]:
        try:
            return self.hub.state.get_spoke_tenant(spoke_id)
        except Exception:
            return None

    async def _relay_inbox(self, host_spoke: str, cs_spoke: str,
                           agent_id: str, hostname: str) -> None:
        hub = self.hub
        inbox = await hub.request_response(cs_spoke, "CS_POLL_AGENT_INBOX",
                                           {"hostname": hostname}, timeout=5.0)
        data = _unwrap(inbox)
        commands = data.get("commands", []) if isinstance(data, dict) else []
        if not commands:
            return
        for cmd in commands:
            if not isinstance(cmd, dict):
                continue
            await self._relay_one(host_spoke, cs_spoke, agent_id, cmd)

    async def _relay_one(self, host_spoke: str, cs_spoke: str,
                         agent_id: str, cmd: Dict[str, Any]) -> None:
        hub = self.hub
        cmd_id = cmd.get("id")
        action = cmd.get("action")
        if not cmd_id or not action:
            return
        # Carry the cs queue id so the agent's CS_COMMAND dispatch can
        # correlate a later CS_COMMAND_RESULT back to this command (Phase E).
        relay_data: Dict[str, Any] = {"cs_cmd_id": cmd_id, "action": action}
        args = cmd.get("args") or {}
        if isinstance(args, dict):
            relay_data.update(args)

        try:
            raw = await hub.request_response(
                host_spoke, "SPOKE_RELAY",
                {"target_agent_id": agent_id, "command": "CS_COMMAND", "data": relay_data},
                timeout=self.relay_timeout,
            )
        except Exception as exc:  # noqa: BLE001
            await self._ack(cs_spoke, cmd_id, "failed", f"relay error: {exc}")
            return

        data = _unwrap(raw)
        status = str(data.get("status", "") or "").upper()
        message = data.get("message", "")

        # Long ops acknowledge "accepted" and stream progress + a terminal
        # CS_COMMAND_RESULT later (Phase E). Leave delivered; do not ack now.
        if status in ("ACCEPTED", "PENDING", "QUEUED"):
            logger.debug("CS bridge: %s %s accepted by %s (long-op; ack deferred)",
                         cmd_id, action, agent_id)
            return

        if status == "SUCCESS":
            ack_status, ack_msg = "completed", message or ""
        elif status in ("ERROR", "FAILED", "TIMEOUT"):
            ack_status, ack_msg = "failed", message or f"agent returned {status}"
        else:
            # Unknown / empty (e.g. timed-out request_response) → failed.
            ack_status, ack_msg = "failed", message or "agent command did not complete"

        await self._ack(cs_spoke, cmd_id, ack_status, ack_msg)

    async def _ack(self, cs_spoke: str, cmd_id: str, status: str, message: str) -> None:
        try:
            await self.hub.request_response(
                cs_spoke, "CS_ACK_COMMAND",
                {"id": cmd_id, "status": status, "message": message},
                timeout=5.0,
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug("CS bridge: ack %s (%s) failed: %s", cmd_id, status, exc)

    async def _sync_usb_config(self, host_spoke: str, cs_spoke: str,
                               agent_id: str, hostname: str, now: float) -> None:
        hub = self.hub
        try:
            resp = await hub.request_response(cs_spoke, "CS_GET_USB_CONFIG",
                                              {"hostname": hostname}, timeout=5.0)
        except Exception as exc:  # noqa: BLE001
            logger.debug("CS bridge: usb config fetch for %s failed: %s", agent_id, exc)
            self._last_usb_push[agent_id] = now
            return
        data = _unwrap(resp)
        cfg = data.get("usb_config") if isinstance(data, dict) else None
        if not isinstance(cfg, dict):
            self._log_agent_diag(host_spoke, agent_id, hostname,
                                 f"SKIP no-usb-config — CS_GET_USB_CONFIG on {cs_spoke} "
                                 f"returned no usb_config (spoke has no dongle config yet)")
            self._last_usb_push[agent_id] = now
            return

        sig = json.dumps(cfg, sort_keys=True, separators=(",", ":"), default=str)
        # Push when the config changed OR it's been >= repush_interval since we
        # last actually sent it — the periodic re-push re-establishes CS mode on
        # an agent that restarted and lost it (see repush_interval note).
        stale = (now - self._last_actual_push.get(agent_id, 0.0)) >= self.repush_interval
        if self._last_usb_cfg.get(agent_id) == sig and not stale:
            self._last_usb_push[agent_id] = now  # unchanged + recently pushed
            return

        # Build the full agent config (preserve display_name/enabled/tenant_id)
        # and merge the fresh usb_config into client_simulation. The cs spoke is
        # authoritative for USB knobs; the hub store is not modified (the spoke
        # persists the merged config spoke-side for reconnect re-push).
        _key, ac = self._agent_config_entry(agent_id, hostname)
        merged = dict(ac) if isinstance(ac, dict) else {}
        cs_cfg = dict(merged.get("client_simulation") or {})
        cs_cfg["usb_config"] = cfg
        # Keep the guard set in sync if the cs spoke publishes one (optional).
        protected = cfg.get("protected_vmids") if isinstance(cfg, dict) else None
        if protected:
            cs_cfg["protected_vmids"] = protected
        merged["client_simulation"] = cs_cfg

        try:
            # Drain-aware: when the host spoke is mid self-update (draining —
            # about to os._exit + relaunch), a raw request_response would hang
            # to its 5s timeout when the spoke drops its WS mid-reply (the
            # "Request Timeout: [SET_AGENT_CONFIG] ... after 5.0s" flood on
            # Update) and the late ack then lands as "unknown message ID"
            # (the _recent_request_timeouts TTL expires across the spoke's
            # restart). _drain_aware_config_push queues straight to the durable
            # mailbox when draining (tracked in pending_ack → ack recognized,
            # no timeout, no warning), and otherwise does a normal
            # live-attempt + queue-on-unreachable push. Same path CS_CONFIG_UPDATE
            # already uses. Mirrors the push_or_queue_to_spoke semantics.
            outcome = await hub._drain_aware_config_push(
                host_spoke, "SET_AGENT_CONFIG",
                {"agent_id": agent_id, "config": merged}, timeout=5.0)
            if not outcome.get("queued"):
                self._last_usb_cfg[agent_id] = sig
                self._last_actual_push[agent_id] = now
            _nvid = len(cfg.get("vidpids") or []) if isinstance(cfg, dict) else 0
            _qnote = " (queued — spoke draining/unreachable, applies on reconnect)" \
                if outcome.get("queued") else ""
            logger.info("[cs-bridge] %s: PUSHED usb_config from %s (%d dongle vidpid(s), "
                        "auto_provision=%s) — host should flip AUTO-PROV on within ~60s%s",
                        agent_id, cs_spoke, _nvid, cfg.get("auto_provision"), _qnote)
        except Exception as exc:  # noqa: BLE001
            logger.warning("[cs-bridge] %s: usb_config PUSH FAILED to spoke %s: %s",
                           agent_id, host_spoke, exc)
        finally:
            self._last_usb_push[agent_id] = now