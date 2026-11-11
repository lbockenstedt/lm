"""VNC + interactive-console session registry for the LM Hub (agent-terminates-WSS)."""

# Postpone evaluation of type hints so annotations stay cheap at import time.
from __future__ import annotations

# asyncio provides session frame queues and background refresh tasks.
import asyncio
# json keys the console-sync dedupe.
import json
# logging reports console refresh and sync problems.
import logging
# re validates that a string looks like a real hostname.
import re
# time drives session expiry and last-sync timestamps.
import time
# Type hints for session dicts and optional lookups.
from typing import Any, Dict, Optional

# Device spec lookup used when mapping console-identified models to NetBox types.
from device_specs import get_spec as get_device_spec

# Named logger shared by all console-related messages.
logger = logging.getLogger("Console")

# How long an identical console-probe NetBox push is skipped after a success.
_CONSOLE_RESYNC_S = 3600.0

# Words a console prompt parser can mistake for a hostname.
_NOT_HOSTNAMES = {"hostname", "password", "login", "username", "standby",
                  "localhost", "switch", "unknown", "n/a", "none"}


def _usable_hostname(name: str) -> str:
    """The name if it can be a real device hostname, else "". Rejects prompt
    noise ("Password:", "N/A", "standby"), bare model numbers ("6300") and
    anything with spaces (a USB adapter product string)."""
    # Normalise to a trimmed string.
    name = str(name or "").strip()
    # Reject anything that is not a plain hostname token, is a known prompt word, or is all digits.
    if (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name)
            or name.lower() in _NOT_HOSTNAMES or name.isdigit()):
        return ""
    # Looks like a real hostname.
    return name


class HubVncConsoleMixin:
    """Browser↔Proxmox VNC + interactive-console relay session bookkeeping.

    State (``self.vnc_sessions`` / ``self.console_sessions``) is owned by
    ``LabManagerHub.__init__``; these methods only register/lookup/reap sessions
    and event-drive the console auto-identify → NetBox device sync.
    """

    # ── VNC console sessions (agent-terminates-WSS) ───────────────────────────
    # The browser opens /ws/console/{session_id}; Proxmox→browser frames land on
    # the session queue via _handle_agent_relay_up (VNC_FRAME_UP), and browser→
    # Proxmox frames go out via send_to_spoke_command (VNC_FRAME_DOWN). 60s TTL
    # so an unclaimed session (browser never connects) is reaped.

    # Seconds an unclaimed VNC session lives before it is reaped.
    VNC_SESSION_TTL = 60

    # ── Console → NetBox device sync config/status (System → Sync) ────────────
    # Key under global_config that holds the console-to-NetBox sync settings.
    _CONSOLE_NETBOX_SYNC_CFG_KEY = "console_netbox_device_sync"

    def _console_netbox_sync_cfg(self) -> Dict[str, Any]:
        """Read the console→NetBox sync config fresh from global_config
        (enabled / source_of_truth / defaults{role,device_type,site})."""
        # Read the sync settings dict, tolerating any missing level.
        return ((getattr(self.state, "system_state", {}) or {})
                .get("global_config", {})
                .get(self._CONSOLE_NETBOX_SYNC_CFG_KEY, {})) or {}

    def _console_netbox_sync_enabled(self) -> bool:
        """Whether console auto-identify results are mirrored into NetBox.
        Enabled by default (preserves the original always-on behavior); an
        operator opts out via the System → Sync card."""
        # Default to enabled when the setting is absent.
        return bool(self._console_netbox_sync_cfg().get("enabled", True))

    def _record_console_sync_status(self, tenant_id: str, tenant_name: str,
                                    status: str, name: str, message: str = "") -> None:
        """Track the most recent console→NetBox sync per tenant for the UI
        status card (in-memory; event-driven, so no persistent history)."""
        # Create the status store on first use.
        if not hasattr(self, "_console_sync_status"):
            self._console_sync_status: Dict[str, Dict[str, Any]] = {}
        # Get (or create) this tenant's status row with zeroed counters.
        st = self._console_sync_status.setdefault(
            tenant_id, {"tenant_id": tenant_id, "synced": 0, "errors": 0})
        # Record the latest sync outcome and when it happened.
        st["tenant_name"] = tenant_name
        st["status"] = status
        st["last_device"] = name
        st["message"] = message
        st["last_sync_ts"] = time.time()
        # Bump the success or error counter.
        if status == "success":
            st["synced"] = int(st.get("synced", 0)) + 1
        elif status == "error":
            st["errors"] = int(st.get("errors", 0)) + 1

    def console_netbox_sync_status(self) -> list:
        """Per-tenant console→NetBox sync status rows for the UI."""
        # Return all per-tenant rows (empty if nothing has synced yet).
        return list(getattr(self, "_console_sync_status", {}).values())

    # ── Console ports warm-cache refresh (background) ─────────────────────────
    # /api/console/ports used to live-poll CONSOLE_LIST_PORTS on every request
    # (15s per spoke, so a single wedged console host blocked the whole page).
    # Instead this background loop keeps the warm cache fresh with a generous
    # timeout, and the route serves the last-known list instantly (see
    # routes/console.py::_list_visible_console_ports). Raw (pre tenant-filter)
    # per the warm-cache contract; the route re-applies visibility per reader.
    # How often the background loop re-polls every console spoke.
    CONSOLE_PORTS_REFRESH_INTERVAL = 30.0   # seconds between fleet refresh sweeps
    CONSOLE_PORTS_REFRESH_TIMEOUT = 60.0    # generous per-spoke poll timeout (base;
    # extended by SPOKE_PROGRESS keepalives — CONSOLE_LIST_PORTS is in _KEEPALIVE_CMDS)
    # A healthy spoke is re-polled every REFRESH_INTERVAL, so an entry older than
    # this window means the background poll can't reach it (wedged/offline) — the
    # route then serves it marked ``stale``. ~4× the interval to avoid flagging a
    # spoke that merely missed one sweep.
    CONSOLE_PORTS_STALE_AFTER = 120.0
    # A connected spoke that keeps timing out (websocket up, command loop wedged)
    # is re-polled on an exponential backoff instead of every sweep, capped here.
    CONSOLE_PORTS_MAX_BACKOFF = 600.0

    @staticmethod
    def _console_unwrap_ports(result: Any) -> list:
        """request_response envelope → the spoke's ``ports`` list (mirror of
        routes/console.py::_console_unwrap so the loop and the route agree)."""
        # Unwrap the response envelope and return its ports list (empty when malformed).
        if isinstance(result, dict):
            data = result.get("payload", {}).get("data", result)
            if isinstance(data, dict):
                return data.get("ports") or []
        return []

    async def refresh_console_ports_cache(self, sids=None, timeout: Optional[float] = None) -> set:
        """Poll CONSOLE_LIST_PORTS for the given (or all connected) console
        spokes and store each raw port list in the warm cache under
        ``("console_ports", sid)``. Best-effort: a wedged/offline spoke is
        skipped so its last-known snapshot survives. Returns the refreshed sids.

        Spokes are polled CONCURRENTLY: each poll is an independent per-spoke
        round-trip with a generous timeout, so a serial sweep made one wedged
        console host delay the warm-cache refresh of every other host behind it
        (which in turn let their entries age into cold-start live polls on the
        page). ``asyncio.gather`` bounds the whole sweep to the slowest spoke."""
        # Default to the class timeout and to every connected console spoke.
        if timeout is None:
            timeout = self.CONSOLE_PORTS_REFRESH_TIMEOUT
        # The background sweep (no explicit sids) skips spokes still in backoff;
        # an explicit refresh (route / on demand) always polls.
        backoff = getattr(self, "_console_ports_backoff", None)
        if backoff is None:
            backoff = self._console_ports_backoff = {}
        if sids is None:
            now = time.monotonic()
            sids = [s for s in (self.get_all_spokes_by_type("console") or [])
                    if backoff.get(s, (0, 0.0))[1] <= now]
        # Sids that were refreshed successfully this sweep.
        refreshed: set = set()

        async def _refresh_one(sid):
            """Poll one spoke and store its ports; failures leave the old snapshot in place."""
            try:
                # Ask the spoke for its port list and store it in the warm cache.
                r = await self.request_response(sid, "CONSOLE_LIST_PORTS", {}, timeout=timeout)
                await self.warm_set("console_ports", sid, self._console_unwrap_ports(r))
                refreshed.add(sid)
                backoff.pop(sid, None)
            except Exception as exc:  # noqa: BLE001 - one dead console mustn't stall the sweep
                # An unreachable spoke is skipped so it cannot stall the sweep,
                # and polled less often the longer it keeps failing.
                fails = backoff.get(sid, (0, 0.0))[0] + 1
                delay = min(self.CONSOLE_PORTS_REFRESH_INTERVAL * 2 ** fails,
                            self.CONSOLE_PORTS_MAX_BACKOFF)
                backoff[sid] = (fails, time.monotonic() + delay)
                if fails == 1:
                    logger.warning("console ports refresh: %s not answering (%s); backing off",
                                   sid, exc)
                logger.debug("console ports refresh: %s unreachable (%s)", sid, exc)

        # Poll every spoke concurrently.
        if sids:
            await asyncio.gather(*(_refresh_one(sid) for sid in sids))
        return refreshed

    def schedule_console_ports_refresh(self, sids) -> None:
        """Fire-and-forget warm-cache refresh for ``sids``, deduped so a burst of
        page loads (or an aging entry served on every request) doesn't stack
        duplicate polls. Never blocks the caller (the route)."""
        # Lazily create the set of sids that already have a refresh running.
        inflight = getattr(self, "_console_ports_refresh_inflight", None)
        if inflight is None:
            inflight = self._console_ports_refresh_inflight = set()
        # Only schedule sids not already in flight.
        todo = [s for s in sids if s not in inflight]
        if not todo:
            return
        # Mark them in flight so concurrent callers do not duplicate the poll.
        inflight.update(todo)

        async def _run():
            """Run the refresh, then clear the in-flight markers whatever happens."""
            try:
                await self.refresh_console_ports_cache(todo)
            finally:
                # Release the in-flight markers so later calls can refresh again.
                for s in todo:
                    inflight.discard(s)

        # Start the refresh in the background without awaiting it.
        try:
            asyncio.create_task(_run())
        except RuntimeError:  # pragma: no cover - no running loop
            # No running event loop: undo the in-flight markers since nothing was scheduled.
            for s in todo:
                inflight.discard(s)

    async def run_console_ports_refresh_loop(self):
        """Keep the console-ports warm cache fresh for every connected console
        spoke, so /api/console/ports serves from RAM instead of live-polling."""
        logger.info("Console ports warm-cache refresh loop started.")
        # Refresh forever; errors are logged and the loop continues.
        while True:
            try:
                await self.refresh_console_ports_cache()
            except Exception as exc:  # noqa: BLE001 - loop must never die
                logger.error("console ports refresh loop error: %s", exc)
            # Wait before the next sweep.
            await asyncio.sleep(self.CONSOLE_PORTS_REFRESH_INTERVAL)


    def register_vnc_session(self, session_id: str, meta: Dict[str, Any]) -> None:
        """Create the session's frame queue and store its metadata."""
        # New session: empty frame queue, expiry deadline, not yet connected, plus caller metadata.
        self.vnc_sessions[session_id] = {
            "queue": asyncio.Queue(),
            "expires": time.time() + self.VNC_SESSION_TTL,
            "connected": False,
            **meta,
        }

    def get_vnc_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Return a live session dict (queue + meta) or None if absent/expired.
        The TTL only applies BEFORE the browser connects; a ``connected`` session
        never expires. VNC sessions routinely outlive the 60s reap window (a user
        sits on a console for minutes), and each VNC_FRAME_UP re-reads the session
        by id — reaping a connected session mid-view silently freezes the screen
        (upstream frames get dropped). Mirrors get_console_session / get_shell_session."""
        # Look up the session; unknown ids return None.
        sess = self.vnc_sessions.get(session_id)
        if not sess:
            return None
        # Reap a session that never connected and has passed its deadline.
        if not sess.get("connected") and sess.get("expires", 0) < time.time():
            self.vnc_sessions.pop(session_id, None)
            return None
        return sess

    def _vnc_writer_map(self) -> Dict[str, str]:
        """Lazily-initialized unique_id → writer session_id map. Lazy (like
        ``_console_sync_status``) so hub test fixtures that predate this
        feature don't need to know about a new ``__init__`` attribute."""
        # Create the writer map on first use.
        if not hasattr(self, "_vnc_writers"):
            self._vnc_writers: Dict[str, str] = {}
        return self._vnc_writers

    def unregister_vnc_session(self, session_id: str) -> None:
        """Remove a VNC session and release its write lock if it held one."""
        # Drop the session and read which VM it was viewing.
        sess = self.vnc_sessions.pop(session_id, None)
        unique_id = str((sess or {}).get("unique_id") or "")
        # Release the write lock if the departing session held it — the VM is
        # up for grabs again (the next opener becomes writer, or an explicit
        # takeover claims it). Remaining read-only viewers are NOT auto-
        # promoted, same as the serial console's PortChannel.detach().
        writers = self._vnc_writer_map()
        # Release the lock only if this session was the writer.
        if unique_id and writers.get(unique_id) == session_id:
            writers.pop(unique_id, None)

    def vnc_attach(self, unique_id: str, session_id: str) -> bool:
        """Register ``session_id`` as a viewer of ``unique_id``; the first
        viewer (no current writer) becomes the writer. Returns True if this
        session is (now) the writer."""
        # First viewer of a VM becomes its writer.
        writers = self._vnc_writer_map()
        if unique_id not in writers:
            writers[unique_id] = session_id
            return True
        # Otherwise report whether this session already is the writer.
        return writers.get(unique_id) == session_id

    def vnc_is_writer(self, unique_id: str, session_id: str) -> bool:
        """Return True if ``session_id`` currently holds the write lock for ``unique_id``."""
        return self._vnc_writer_map().get(str(unique_id or "")) == session_id

    def vnc_takeover(self, unique_id: str, session_id: str) -> Optional[str]:
        """Forcibly make ``session_id`` the writer for ``unique_id``, evicting
        whoever currently holds it. Returns the dispossessed session_id (None
        if there was no prior writer, or the caller already held it)."""
        # Read the current writer; nothing to evict if the caller already holds it.
        writers = self._vnc_writer_map()
        prev = writers.get(unique_id)
        if prev == session_id:
            return None
        # Hand the lock to the caller and report who lost it.
        writers[unique_id] = session_id
        return prev

    async def notify_vnc_downgraded(self, session_id: str) -> None:
        """Push a ``("downgraded",)`` control tuple onto a still-open VNC
        session's queue so its live /ws/console relay tells the browser to
        drop to view-only, without closing the connection. No-op if the
        session already closed."""
        # Only signal sessions that are still open.
        sess = self.vnc_sessions.get(session_id)
        if sess is not None:
            await sess["queue"].put(("downgraded",))

    def vnc_viewers(self, unique_id: str) -> list:
        """Presence: the connected VNC viewers currently attached to ``unique_id``.

        Each user opens their OWN VNC session (distinct session_id → its own
        Proxmox vncwebsocket); QEMU's VNC server natively multiplexes the clients
        so every viewer sees/controls the same screen. This lists who is attached
        so the UI can show a live viewer roster. Returns newest-first."""
        out = []
        # Walk every VNC session and collect the connected ones viewing this VM.
        for sid, s in list(self.vnc_sessions.items()):
            if not s.get("connected"):
                continue
            if str(s.get("unique_id") or "") != str(unique_id or ""):
                continue
            # Report who is viewing, whether they hold the write lock, and since when.
            out.append({
                "session_id": sid,
                "username": s.get("username") or "",
                "tenant_id": s.get("tenant_id") or "",
                "is_writer": self._vnc_writer_map().get(str(unique_id or "")) == sid,
                "since": s.get("connected_at") or 0,
            })
        # Newest viewers first.
        out.sort(key=lambda v: v.get("since") or 0, reverse=True)
        return out

    # Seconds an unclaimed interactive console session lives before it is reaped.
    CONSOLE_SESSION_TTL = 60

    def register_console_session(self, session_id: str, meta: Dict[str, Any]) -> None:
        """Create a console session's byte queue + metadata (mirrors VNC)."""
        # New session: empty byte queue, expiry deadline, not yet connected, plus caller metadata.
        self.console_sessions[session_id] = {
            "queue": asyncio.Queue(),
            "expires": time.time() + self.CONSOLE_SESSION_TTL,
            "connected": False,
            **meta,
        }

    def get_console_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Return a live console session (queue + meta) or None. The TTL only
        applies BEFORE the browser connects; a ``connected`` session never
        expires (interactive consoles sit idle at a prompt for long stretches)."""
        # Look up the session; unknown ids return None.
        sess = self.console_sessions.get(session_id)
        if not sess:
            return None
        # Reap a session that never connected and has passed its deadline.
        if not sess.get("connected") and sess.get("expires", 0) < time.time():
            self.console_sessions.pop(session_id, None)
            return None
        return sess

    def unregister_console_session(self, session_id: str) -> None:
        """Forget a console session (no-op if already gone)."""
        self.console_sessions.pop(session_id, None)

    # ── Host-shell (xterm terminal) sessions — agent-terminates-PTY ───────────
    # Same shape as the console session: a byte queue fed by SHELL_OUT frames via
    # _handle_agent_relay_up; browser keystrokes go out as SHELL_IN. TTL applies
    # only until the browser connects (an idle shell sits at a prompt for ages).
    # Seconds an unclaimed host-shell session lives before it is reaped.
    SHELL_SESSION_TTL = 60

    def register_shell_session(self, session_id: str, meta: Dict[str, Any]) -> None:
        """Create a host-shell session's byte queue and store its metadata."""
        self.shell_sessions[session_id] = {
            "queue": asyncio.Queue(),
            "expires": time.time() + self.SHELL_SESSION_TTL,
            "connected": False,
            **meta,
        }

    def get_shell_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Return a live host-shell session or None if absent or expired before connecting."""
        # Look up the session; unknown ids return None.
        sess = self.shell_sessions.get(session_id)
        if not sess:
            return None
        # Reap a session that never connected and has passed its deadline.
        if not sess.get("connected") and sess.get("expires", 0) < time.time():
            self.shell_sessions.pop(session_id, None)
            return None
        return sess

    def unregister_shell_session(self, session_id: str) -> None:
        """Forget a host-shell session (no-op if already gone)."""
        self.shell_sessions.pop(session_id, None)

    async def _auto_llm_console_identify(self, spoke_id: str, data: Dict[str, Any]) -> bool:
        """Auto-escalate an unidentified console port to the LLM AI-identify path
        when it's enabled — the local static fingerprint came back empty. Returns
        True if the LLM orchestration ran (so the caller skips the placeholder
        sync); False if AI-identify is off/unavailable or there's nothing to send.
        Best-effort and rate-limited by the spoke's own probe backoff; the learned
        fingerprint cache keeps repeat prompts from re-hitting the LLM."""
        # The port id and captured banner are what the LLM needs; without them do nothing.
        port_id = str(data.get("port_id") or "").strip()
        banner = str(data.get("banner") or "")
        if not port_id or not banner.strip():
            return False
        # The LLM identify module is optional; missing means the feature is unavailable.
        try:
            from routes import console_llm_identify as llm  # optional feature
        except Exception:  # noqa: BLE001
            return False
        # Respect the operator's on/off switch for AI identify.
        if not llm.hub_llm_identify_enabled(self):
            return False
        # Find an agent able to run the LLM identify; none means we cannot escalate.
        agent = llm.find_ab(self)
        if not agent:
            return False
        # Run the identify flow; any failure is logged and reported as "not run".
        try:
            await llm.orchestrate(self, agent, spoke_id, port_id)
            logger.info("console: auto-escalated %s to AI identify "
                        "(local fingerprint found nothing)", port_id)
            return True
        except Exception as e:  # noqa: BLE001
            logger.warning("console auto AI-identify failed for %s: %s", port_id, e)
            return False

    async def _authorized_probe_tenant(self, spoke_id: str, claimed: Any, device_ip: str) -> str:
        """Resolve the tenant a console probe result may be written under WITHOUT
        trusting the spoke's self-declared ``tenant_id``.

        The sender ``spoke_id`` is authenticated; its *registered* tenant is
        authoritative. A compromised/rogue console spoke must not be able to
        forge a device into another tenant's NetBox inventory by putting that
        tenant's id in the (spoke-controlled) probe payload.

          * Console spoke DEDICATED to a tenant (registered, non-shared) → every
            device it reports is that tenant's; a differing payload ``tenant_id``
            is refused and logged (mirrors ``_console_tenant_ok``: a dedicated
            agent's ports are all its own tenant's).
          * SHARED / unassigned console spoke → a per-port override to a specific
            tenant is honored only when the identified device IP is contained in
            that tenant's NetBox prefixes (hub-side prefix attribution, the same
            containment rule ``attribute_by_prefix`` uses), so it still cannot
            attribute a device to a tenant that doesn't own the address.

        Returns the authorized tenant id, or the spoke's own (possibly empty /
        shared) tenant as the fail-closed fallback — the caller's slug check then
        skips the sync when that resolves to nothing.
        """
        # access provides tenant-sharing checks and prefix-based attribution.
        import access
        # The spoke's registered tenant and the tenant the payload claims.
        base = (self.state.get_spoke_tenant(spoke_id) or "").strip()
        claimed = str(claimed or "").strip()
        # No claim, or a claim matching the registered tenant, is simply the registered tenant.
        if not claimed or claimed == base:
            return base
        # Dedicated spoke: its registered tenant is authoritative, full stop.
        if base and not access.tenant_is_shared(base):
            logger.warning(
                "console probe from %s claimed tenant %s but spoke is dedicated to %s; "
                "forcing %s (cross-tenant attribution refused)", spoke_id, claimed, base, base)
            return base
        # Shared / unassigned spoke with a differing claim: corroborate the claim
        # against the claimed tenant's prefixes before honoring it (the hint
        # lets an address that overlaps another tenant's VRF still count).
        # Ask which tenant's prefixes contain the device IP, hinting at the claimed tenant.
        try:
            buckets, _ = await access.attribute_by_prefix(
                self, [{"ip": device_ip or "", "source_tenant_id": claimed}])
        except Exception:  # noqa: BLE001
            # Attribution failure means the claim cannot be corroborated.
            buckets = {}
        # Honour the claim only when the IP actually falls in that tenant's prefixes.
        if device_ip and claimed in buckets:
            return claimed
        # Otherwise refuse the cross-tenant claim and fall back to the registered tenant.
        logger.warning(
            "console probe from %s claimed tenant %s not corroborated by prefix for ip=%r; "
            "refusing cross-tenant attribution", spoke_id, claimed, device_ip)
        return base

    async def _handle_console_probe(self, spoke_id: str, data: Dict[str, Any]) -> None:
        """A console spoke auto-identified a device — match/create a NetBox device
        from the harvested identity (best-effort, event-driven). Uses the port's
        EFFECTIVE tenant, resolved hub-side by ``_authorized_probe_tenant`` (a
        per-port override in the payload is honored only when the sender spoke is
        actually authorized to attribute to it — never blindly trusted). Uses
        replace=False so we upsert one device, not overwrite the tenant's
        discovered set. Serial is surfaced in the port UI; NetBox gets
        ip/mac/hostname (the sync_devices device shape)."""
        # Pull the harvested identity fields out of the probe payload, trimmed.
        identity = data.get("identity") or {}
        ip = str(identity.get("ip") or "").strip()
        mac = str(identity.get("mac") or "").strip()
        vendor = str(data.get("vendor") or "").strip()
        real_host = str(identity.get("hostname") or "").strip()
        serial = str(identity.get("serial") or "").strip()
        # The local fingerprint didn't recognize the device TYPE (no vendor). If
        # AI-assisted identify is enabled, auto-escalate to the LLM to identify
        # vendor/model — independent of whether we gleaned a hostname from the
        # prompt (a name alone doesn't tell us what the box is). The fingerprint
        # DB (console_learn) then caches the result so repeat prompts stay static.
        # Guard on method != "llm" so the LLM's own result can't re-trigger this.
        if not vendor and str(data.get("method") or "").strip() != "llm":
            if await self._auto_llm_console_identify(spoke_id, data):
                return
        # Console → NetBox device sync toggle (System → Sync). Enabled by
        # default (preserves the original always-on behavior); an operator can
        # opt out in the UI. The LLM auto-identify above still runs regardless —
        # it feeds the Console UI + global search independent of NetBox sync.
        if not self._console_netbox_sync_enabled():
            return
        # Name: the device's real hostname, else its serial. Never the USB
        # adapter product string or the port id — those name the console
        # cable, not the device, and every port sharing an adapter model
        # became one more junk NetBox device ("FT232R USB UART", "uart-ttyS0").
        hostname = _usable_hostname(real_host) or serial
        # Nothing identifying at all: nothing to sync.
        if not (ip or mac or hostname or serial):
            return
        # Find the NetBox (ipam) spoke; without one there is nowhere to sync.
        netbox = self.get_spoke_by_type("ipam")
        if not netbox:
            logger.debug("console probe from %s: no NetBox spoke; device not synced", spoke_id)
            return
        # Resolve the tenant this device may be written under, plus its display name and NetBox
        # slug.
        tenant_id = await self._authorized_probe_tenant(spoke_id, data.get("tenant_id"), ip)
        tenant_cfg = self.state.get_tenant(tenant_id) or {}
        tenant_name = tenant_cfg.get("name") or tenant_id
        slug = str(tenant_cfg.get("netbox_tenant_slug") or "").strip()
        # Without a tenant and NetBox slug the device cannot be placed; record a skip.
        if not tenant_id or not slug:
            logger.info("console probe from %s: tenant/netbox_tenant_slug unset; "
                        "device not synced to NetBox", spoke_id)
            self._record_console_sync_status(
                tenant_id or "(unmapped)", tenant_name, "skipped",
                hostname or serial or mac or ip,
                "tenant / netbox_tenant_slug unset")
            return
        # Load the sync settings (source of truth and defaults).
        cfg = self._console_netbox_sync_cfg()
        # Discovered hardware model (from the LLM/fingerprint identify) +
        # vendor → the sink places the device under its REAL device_type
        # instead of the generic default.
        model = str(identity.get("model") or data.get("model") or "").strip()
        # NetBox gets ip/mac/hostname AND the serial — serial is the strongest
        # match key (the sink matches serial → ip → mac → hostname), so a
        # console-identified device is recognised across DHCP IP moves / renames.
        device_rec = {"ip": ip, "mac": mac, "hostname": hostname, "serial": serial}
        # Add model and vendor only when known.
        if model:
            device_rec["model"] = model
        if vendor:
            device_rec["manufacturer"] = vendor
        # Recorded model spec (asked from the LLM once per model) gives the
        # NetBox type its ports; its role, else the identified device class.
        spec = await get_device_spec(self, model, vendor) if model else None
        # Attach the spec when one was found.
        if spec:
            device_rec["spec"] = spec
        # Role comes from the spec, else a slugified version of the identified device type.
        role = (spec or {}).get("role") or re.sub(
            r"[^a-z0-9]+", "-", str(identity.get("type") or "").lower()).strip("-")
        # "other" is not a useful role, so leave it unset.
        if role and role != "other":
            device_rec["role"] = role
        # Build the NetBox sync request: one device, upserted (not replacing the tenant's set).
        payload = {
            "tenant_id": tenant_id, "tenant_slug": slug,
            "tenant_name": tenant_name,
            "source": "Console", "replace": False,
            "source_of_truth": str(cfg.get("source_of_truth") or "external"),
            "devices": [device_rec],
            "defaults": cfg.get("defaults", {}) or {},
        }
        # Console spokes re-probe the same ports all day. A device already
        # synced with this exact record is skipped for an hour: each push is a
        # paced background feed on the NetBox spoke, and repeats only crowd it.
        key = json.dumps(payload, sort_keys=True, default=str)
        recent = self.__dict__.setdefault("_console_synced", {})
        now = time.monotonic()
        for k in [k for k, at in recent.items() if now - at > _CONSOLE_RESYNC_S]:
            recent.pop(k, None)
        if key in recent:
            return
        # Send it to NetBox and record the outcome for the status card. The
        # NetBox spoke queues background feeds behind live UI reads, so give it
        # the same long wait as the other discovery feeds.
        try:
            await self.request_response(netbox, "NETBOX_SYNC_DEVICES", payload, timeout=600.0)
            recent[key] = now
            logger.info("console probe: synced %s to NetBox (tenant %s)",
                        hostname or serial or mac or ip, tenant_id)
            self._record_console_sync_status(
                tenant_id, tenant_name, "success", hostname or serial or mac or ip)
        except Exception as e:  # noqa: BLE001
            # Sync failure: log and record an error with a truncated message.
            logger.warning("console probe NetBox sync failed: %s", e)
            self._record_console_sync_status(
                tenant_id, tenant_name, "error",
                hostname or serial or mac or ip, str(e)[:200])
