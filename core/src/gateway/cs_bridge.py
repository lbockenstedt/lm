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


def _is_timeout_message(message: Any) -> bool:
    """True if a spoke/agent ERROR message reads as a transient relay TIMEOUT
    (retryable) rather than a genuine op rejection (don't retry). Matches the
    hub's ``"Timed out waiting for spoke response"`` and the spoke
    send_to_agent's ``"Agent response timeout"`` plus the common phrasings an
    agent/OS surfaces when a host is too saturated to ACK in time. A genuine
    agent ERROR (``"VM not found"``, ``"already deleted"``, ``"no such vmid"``)
    contains none of these markers and correctly returns False."""
    if not message:
        return False
    msg = str(message).strip().lower()
    if not msg:
        return False
    return any(m in msg for m in (
        "timed out", "timeout", "time-out", "timed-out",
        "did not respond", "didn't respond", "no response",
    ))
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
        # Long ops (delete_vm / reclone_vm / snapshot_vm / clone_lxc /
        # provision_unassigned / reclone_all) get a wider hub relay window: the
        # agent may be mid-op (a prior mass-delete VM, auto-prov cloning) and
        # can't ACCEPT the next CS_COMMAND within the 16s fast window — the
        # relay would time out and the command would be marked dead even though
        # the agent is alive, just busy. This sits slightly above the spoke's
        # ``agent_relay_timeout_long_s`` (60s default) so the spoke's own
        # send_to_agent long-op window can complete before the hub gives up.
        self.relay_timeout_long = _env_int("CS_RELAY_TIMEOUT_LONG_S", 65, 10) + 0.0
        # On a relay timeout (agent too busy to ACCEPT), re-queue the command
        # for the next poll tick up to this many times before marking it
        # failed — "retry 5 then give up" instead of a single timeout killing a
        # mass-delete on a busy agent. 0 = fail-fast (old behavior).
        self.max_retries = _env_int("CS_RELAY_MAX_RETRIES", 5, 0)
        # The spoke→agent relay timeouts (Setup → General → global_config
        # ``agent_relay_timeout_long_s`` / ``_fast_s``) ALSO drive the hub→spoke
        # window: the hub must wait at least as long as the spoke's send_to_agent
        # window or it pre-empts it (user set long=900s but the hub bridge still
        # used the 65s env default → the hub re-queued every tick and the spoke's
        # 900s window never got to complete). _apply_configured_timeouts keeps
        # the hub window = configured + MARGIN (and never below the env default),
        # re-read each tick so a General save takes effect within one cycle
        # without a hub restart. _configured_long/_fast are the spoke's windows
        # surfaced in the Diagnostics panel for display.
        self._configured_long: Optional[float] = None
        self._configured_fast: Optional[float] = None
        self._env_relay_timeout = self.relay_timeout
        self._env_relay_timeout_long = self.relay_timeout_long
        self._apply_configured_timeouts()
        # Long-op actions (mirror cs_spoke._LONG so the bridge picks the long
        # relay window without a round-trip). Keep in sync with the spoke set.
        self._long_actions = {"delete_vm", "reclone_vm", "snapshot_vm", "clone_lxc",
                              "provision_unassigned", "reclone_all", "proxmox_reclone_all"}
        # Per-agent USB-config sync state.
        self._last_usb_cfg: Dict[str, str] = {}   # agent_id -> canonical blob sig
        self._last_usb_push: Dict[str, float] = {}  # agent_id -> ts (last check)
        self._last_actual_push: Dict[str, float] = {}  # agent_id -> ts (last SEND)
        self._last_diag: Dict[str, str] = {}  # agent_id -> last [cs-bridge] decision (throttle)
        self._last_cycle_diag: str = ""  # last [cs-bridge] cycle summary (throttle)
        # Per-agent relay outcome counters (for the WebUI "CS Bridge Status"
        # panel — lets an Azure-hub operator see, per agent, whether commands
        # are being accepted / re-queued / failing, without SSH). agent_id ->
        # {hostname, decision, accepted, requeued, gave_up, completed, failed,
        #  last_outcome, last_ts}. Bumped in _relay_one/_requeue_or_fail/_ack.
        self._relay_counts: Dict[str, Dict[str, Any]] = {}

    # ── main loop ──────────────────────────────────────────────────────────

    async def run(self) -> None:
        # Let spokes/agents connect before the first poll.
        await asyncio.sleep(5)
        logger.info("CS bridge loop started (poll=%ds, usb=%ds)",
                    self.poll_interval, self.usb_interval)
        while True:
            try:
                self._apply_configured_timeouts()
                await self._tick()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                logger.warning("CS bridge tick error: %s", exc)
            await asyncio.sleep(self.poll_interval)

    def _apply_configured_timeouts(self) -> None:
        """Re-read the spoke→agent relay timeouts from the hub's global_config
        (Setup → General) and keep the hub→spoke relay window above them, so a
        configured long-op window of (say) 900s actually lets the spoke's
        send_to_agent 900s window complete instead of the hub pre-empting at the
        65s env default and re-queuing every tick. Idempotent + cheap (one dict
        lookup), called once per poll cycle so a General save takes effect
        within one cycle — no hub restart needed.

        The hub window = configured + MARGIN (5s) so the spoke's reply lands
        before the hub gives up; never below the env default (CS_RELAY_TIMEOUT_S
        / CS_RELAY_TIMEOUT_LONG_S). Unconfigured → env defaults (old behavior).
        """
        margin = 5.0
        try:
            gc = (self.hub.state.get_global_config() or {}) if getattr(
                self.hub, "state", None) else {}
        except Exception:  # noqa: BLE001 — best-effort; fall back to env
            gc = {}
        cl = gc.get("agent_relay_timeout_long_s")
        cf = gc.get("agent_relay_timeout_fast_s")
        self._configured_long = float(cl) if cl is not None else None
        self._configured_fast = float(cf) if cf is not None else None
        if self._configured_long is not None:
            self.relay_timeout_long = max(self._env_relay_timeout_long,
                                          self._configured_long + margin)
        if self._configured_fast is not None:
            self.relay_timeout = max(self._env_relay_timeout,
                                      self._configured_fast + margin)

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
        # Record the latest decision on the per-agent counter row so the WebUI
        # panel can show "ACTIVE / SKIP not-enabled / SKIP no-cs-spoke" alongside
        # the relay counters in one place. Also surface host_spoke (the spoke the
        # agent is actually connected to / commands are delivered through) — the
        # decision's cs_spoke is the tenant-canonical queue broker, so without
        # host_spoke the operator can't see the per-agent delivery path that
        # diagnoses "ACTIVE but 0 commands relayed" (e.g. svr-02 connected to
        # cs-svr-02-spoke while cs_spoke=cs-svr-04-spoke).
        row = self._relay_counts.setdefault(
            agent_id,
            {"hostname": hostname, "host_spoke": "", "decision": "",
             "accepted": 0, "requeued": 0, "gave_up": 0, "completed": 0,
             "failed": 0, "last_outcome": None, "last_ts": 0.0,
             "last_inbox_count": 0},
        )
        row["hostname"] = hostname
        row["host_spoke"] = host_spoke
        row["decision"] = decision

    def _bump(self, agent_id: str, hostname: str, outcome: str) -> None:
        """Increment a per-agent relay-outcome counter and stamp the last
        outcome/ts, for the WebUI "CS Bridge Status" panel."""
        row = self._relay_counts.setdefault(
            agent_id,
            {"hostname": hostname, "host_spoke": "", "decision": "",
             "accepted": 0, "requeued": 0, "gave_up": 0, "completed": 0,
             "failed": 0, "last_outcome": None, "last_ts": 0.0,
             "last_inbox_count": 0},
        )
        row["hostname"] = hostname
        if outcome in row:
            row[outcome] = int(row[outcome]) + 1
        row["last_outcome"] = outcome
        row["last_ts"] = time.time()

    def status_snapshot(self) -> Dict[str, Any]:
        """Snapshot of the bridge's per-agent state for the WebUI "CS Bridge
        Status" panel — the decision (ACTIVE / SKIP reason) plus relay outcome
        counters per agent, so an Azure-hub operator can diagnose "why isn't
        svr-02 deleting" (bridge reaching it? commands re-queued? failing?)
        without SSH. Returns a JSON-serializable dict."""
        # Prune agents we haven't seen in a while (gone offline) so the panel
        # reflects the live fleet — keep the last row for a recent window so a
        # transient drop doesn't erase the counters mid-diagnosis.
        now = time.time()
        agents = []
        for aid, row in self._relay_counts.items():
            r = dict(row)
            r["agent_id"] = aid
            r["last_ts_iso"] = (
                time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r.get("last_ts", 0.0)))
                if r.get("last_ts") else ""
            )
            agents.append(r)
        agents.sort(key=lambda r: (r.get("hostname") or r.get("agent_id") or ""))
        return {
            "agents": agents,
            "cycle": self._last_cycle_diag,
            "max_retries": self.max_retries,
            # Hub→spoke relay windows (what the bridge actually waits). After
            # _apply_configured_timeouts these track the General setting + margin
            # (so a 900s long-op setting → ~905s here), never below the env
            # default. Shown in the Diagnostics panel.
            "relay_timeout_s": self.relay_timeout,
            "relay_timeout_long_s": self.relay_timeout_long,
            # The spoke→agent windows the operator configured in Setup → General
            # (agent_relay_timeout_long_s / _fast_s), surfaced so the panel can
            # show both legs side by side. None when unconfigured (env defaults).
            "configured_long_s": self._configured_long,
            "configured_fast_s": self._configured_fast,
            "now": now,
        }

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
        # Record the inbox count on the per-agent row so the panel can distinguish
        # "bridge reached the agent but its inbox on the cs spoke is EMPTY" (no
        # commands queued / enqueue-side hostname-key mismatch — 0 accepted with
        # 0 in the inbox) from "inbox had commands but the relay failed/timed
        # out" (0 accepted with N in the inbox → relay path issue).
        row = self._relay_counts.get(agent_id)
        if isinstance(row, dict):
            row["last_inbox_count"] = len(commands)
        if not commands:
            return
        for cmd in commands:
            if not isinstance(cmd, dict):
                continue
            await self._relay_one(host_spoke, cs_spoke, agent_id, hostname, cmd)

    async def _relay_one(self, host_spoke: str, cs_spoke: str,
                         agent_id: str, hostname: str, cmd: Dict[str, Any]) -> None:
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

        # Long ops get the wider hub relay window (relay_timeout_long) — a busy
        # agent (mid mass-delete / auto-prov) can take longer than the 16s fast
        # window just to ACCEPT, and a false "Timed out waiting for spoke
        # response" here would mark a perfectly-runnable command dead.
        timeout = (self.relay_timeout_long if action in self._long_actions
                   else self.relay_timeout)

        try:
            raw = await hub.request_response(
                host_spoke, "SPOKE_RELAY",
                {"target_agent_id": agent_id, "command": "CS_COMMAND", "data": relay_data},
                timeout=timeout,
            )
        except Exception as exc:  # noqa: BLE001 — spoke mid-reconnect: retry, don't fail.
            await self._requeue_or_fail(cs_spoke, agent_id, hostname, cmd_id, action,
                                        f"relay error: {exc}")
            return

        data = _unwrap(raw)
        status = str(data.get("status", "") or "").upper()
        message = data.get("message", "")

        # Long ops acknowledge "accepted" and stream progress + a terminal
        # CS_COMMAND_RESULT later (Phase E). Leave delivered; do not ack now.
        if status in ("ACCEPTED", "PENDING", "QUEUED"):
            self._bump(agent_id, hostname, "accepted")
            # Touch the command so its updated_at + last_contact refresh — this
            # SUPPRESSES the cs spoke's 30s stale-delivered re-send (pointless
            # while the op runs) and keeps the delete-verify sweep
            # (DELETE_VERIFY_TIMEOUT_SECS) from firing on a slow-but-alive
            # delete that re-acks every poll. The cs spoke re-probes every 30s
            # even without this, but the touch keeps the verify window honest.
            await self._touch(cs_spoke, cmd_id)
            logger.debug("CS bridge: %s %s accepted by %s (long-op; ack deferred)",
                         cmd_id, action, agent_id)
            return

        if status == "SUCCESS":
            ack_status, ack_msg = "completed", message or ""
        elif status in ("ERROR", "FAILED", "TIMEOUT"):
            # Distinguish a relay TIMEOUT (the agent was too busy to ACCEPT —
            # transient; retry up to max_retries via requeue) from a genuine
            # agent ERROR/FAILED (the op ran and the agent rejected it — don't
            # retry, that just repeats the same rejection forever). Three legs
            # can produce a timeout-shaped ERROR, all retryable:
            #   - the HUB's request_response: "Timed out waiting for spoke response"
            #   - the spoke's send_to_agent: "Agent response timeout" (the agent
            #     was too busy/CPU-pegged to ACK within its relay window — note
            #     the spoke widens long ops to 60s but a saturated host can still
            #     slip past it; without this branch the command FAILED on the
            #     FIRST attempt with no retry even though the op often runs)
            #   - an agent returning TIMEOUT (transient "couldn't complete now")
            # A genuine agent ERROR ("VM not found", "already deleted") does NOT
            # contain a timeout marker, so it correctly falls through to fail.
            is_relay_timeout = status == "TIMEOUT" or _is_timeout_message(message)
            if is_relay_timeout:
                await self._requeue_or_fail(cs_spoke, agent_id, hostname, cmd_id,
                                           action, message or "relay timed out")
                return
            ack_status, ack_msg = "failed", message or f"agent returned {status}"
        else:
            # Unknown / empty (e.g. a timed-out request_response that lost the
            # race before the timeout string was set) → treat as retryable.
            await self._requeue_or_fail(cs_spoke, agent_id, hostname, cmd_id, action,
                                        message or "agent command did not complete")
            return

        await self._ack(cs_spoke, agent_id, hostname, cmd_id, action, ack_status, ack_msg)

    async def _requeue_or_fail(self, cs_spoke: str, agent_id: str, hostname: str,
                               cmd_id: str, action: str, message: str) -> None:
        """Re-queue a command whose relay TIMED OUT (agent too busy to ACCEPT,
        or the owning spoke was mid-reconnect) for the next poll tick, up to
        ``max_retries``. Once exhausted, the cs spoke's ``requeue_command``
        marks it ``failed`` itself — so this never acks a "failed" that would
        short-circuit a later, legitimate retry. ``max_retries <= 0`` (or a
        non-positive env) falls back to the old fail-fast behavior."""
        if self.max_retries <= 0:
            await self._ack(cs_spoke, agent_id, hostname, cmd_id, action, "failed", message)
            return
        try:
            raw = await self.hub.request_response(
                cs_spoke, "CS_REQUEUE_COMMAND",
                {"id": cmd_id, "max_retries": self.max_retries, "message": message},
                timeout=5.0,
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug("CS bridge: requeue %s failed: %s", cmd_id, exc)
            return
        data = _unwrap(raw)
        if data.get("requeued"):
            self._bump(agent_id, hostname, "requeued")
            logger.info("[cs-bridge] %s %s %s relay timed out — re-queued (attempt %s/%s): %s",
                        agent_id, hostname, action, data.get("attempts"),
                        data.get("max_retries"), message)
        else:
            # Exhausted retries → the queue already marked it failed.
            self._bump(agent_id, hostname, "gave_up")
            logger.warning("[cs-bridge] %s %s %s gave up after %s relay attempt(s): %s",
                            agent_id, hostname, action, data.get("attempts"), message)

    async def _touch(self, cs_spoke: str, cmd_id: str) -> None:
        """Refresh a delivered command's updated_at + last_contact (in-memory on
        the cs spoke) on ACCEPTED, so the stale-delivered re-probe and the
        delete-verify sweep don't fire while a long op is alive and re-acking.
        Best-effort — a touch failure just means the spoke re-probes normally."""
        try:
            await self.hub.request_response(
                cs_spoke, "CS_TOUCH_COMMAND", {"id": cmd_id}, timeout=5.0,
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug("CS bridge: touch %s failed: %s", cmd_id, exc)

    async def _ack(self, cs_spoke: str, agent_id: str, hostname: str,
                   cmd_id: str, action: str, status: str, message: str) -> None:
        try:
            await self.hub.request_response(
                cs_spoke, "CS_ACK_COMMAND",
                {"id": cmd_id, "status": status, "message": message},
                timeout=5.0,
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug("CS bridge: ack %s (%s) failed: %s", cmd_id, status, exc)
            return
        # Genuine terminal outcome (completed | failed). A "failed" here is a
        # genuine agent rejection (the op ran), NOT a relay timeout (those
        # requeue above). Log at INFO so an Azure-hub operator can grep the
        # agent hostname in WebUI Logs and see exactly what happened to each
        # command without SSH — the per-agent decision line alone doesn't show
        # outcomes.
        if status == "completed":
            self._bump(agent_id, hostname, "completed")
        else:
            self._bump(agent_id, hostname, "failed")
            logger.info("[cs-bridge] %s %s %s acked failed: %s",
                        agent_id, hostname, action, message)

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