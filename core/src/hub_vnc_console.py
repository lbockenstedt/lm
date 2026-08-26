"""VNC + interactive-console session registry for the LM Hub (agent-terminates-WSS)."""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Dict, Optional

logger = logging.getLogger("Console")


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

    VNC_SESSION_TTL = 60

    # ── Console → NetBox device sync config/status (System → Sync) ────────────
    _CONSOLE_NETBOX_SYNC_CFG_KEY = "console_netbox_device_sync"

    def _console_netbox_sync_cfg(self) -> Dict[str, Any]:
        """Read the console→NetBox sync config fresh from global_config
        (enabled / source_of_truth / defaults{role,device_type,site})."""
        return ((getattr(self.state, "system_state", {}) or {})
                .get("global_config", {})
                .get(self._CONSOLE_NETBOX_SYNC_CFG_KEY, {})) or {}

    def _console_netbox_sync_enabled(self) -> bool:
        """Whether console auto-identify results are mirrored into NetBox.
        Enabled by default (preserves the original always-on behavior); an
        operator opts out via the System → Sync card."""
        return bool(self._console_netbox_sync_cfg().get("enabled", True))

    def _record_console_sync_status(self, tenant_id: str, tenant_name: str,
                                    status: str, name: str, message: str = "") -> None:
        """Track the most recent console→NetBox sync per tenant for the UI
        status card (in-memory; event-driven, so no persistent history)."""
        if not hasattr(self, "_console_sync_status"):
            self._console_sync_status: Dict[str, Dict[str, Any]] = {}
        st = self._console_sync_status.setdefault(
            tenant_id, {"tenant_id": tenant_id, "synced": 0, "errors": 0})
        st["tenant_name"] = tenant_name
        st["status"] = status
        st["last_device"] = name
        st["message"] = message
        st["last_sync_ts"] = time.time()
        if status == "success":
            st["synced"] = int(st.get("synced", 0)) + 1
        elif status == "error":
            st["errors"] = int(st.get("errors", 0)) + 1

    def console_netbox_sync_status(self) -> list:
        """Per-tenant console→NetBox sync status rows for the UI."""
        return list(getattr(self, "_console_sync_status", {}).values())

    # ── Console ports warm-cache refresh (background) ─────────────────────────
    # /api/console/ports used to live-poll CONSOLE_LIST_PORTS on every request
    # (15s per spoke, so a single wedged console host blocked the whole page).
    # Instead this background loop keeps the warm cache fresh with a generous
    # timeout, and the route serves the last-known list instantly (see
    # routes/console.py::_list_visible_console_ports). Raw (pre tenant-filter)
    # per the warm-cache contract; the route re-applies visibility per reader.
    CONSOLE_PORTS_REFRESH_INTERVAL = 30.0   # seconds between fleet refresh sweeps
    CONSOLE_PORTS_REFRESH_TIMEOUT = 60.0    # generous per-spoke poll timeout (base;
    # extended by SPOKE_PROGRESS keepalives — CONSOLE_LIST_PORTS is in _KEEPALIVE_CMDS)
    # A healthy spoke is re-polled every REFRESH_INTERVAL, so an entry older than
    # this window means the background poll can't reach it (wedged/offline) — the
    # route then serves it marked ``stale``. ~4× the interval to avoid flagging a
    # spoke that merely missed one sweep.
    CONSOLE_PORTS_STALE_AFTER = 120.0

    @staticmethod
    def _console_unwrap_ports(result: Any) -> list:
        """request_response envelope → the spoke's ``ports`` list (mirror of
        routes/console.py::_console_unwrap so the loop and the route agree)."""
        if isinstance(result, dict):
            data = result.get("payload", {}).get("data", result)
            if isinstance(data, dict):
                return data.get("ports") or []
        return []

    async def refresh_console_ports_cache(self, sids=None, timeout: Optional[float] = None) -> set:
        """Poll CONSOLE_LIST_PORTS for the given (or all connected) console
        spokes and store each raw port list in the warm cache under
        ``("console_ports", sid)``. Best-effort: a wedged/offline spoke is
        skipped so its last-known snapshot survives. Returns the refreshed sids."""
        if timeout is None:
            timeout = self.CONSOLE_PORTS_REFRESH_TIMEOUT
        if sids is None:
            sids = self.get_all_spokes_by_type("console") or []
        refreshed: set = set()
        for sid in sids:
            try:
                r = await self.request_response(sid, "CONSOLE_LIST_PORTS", {}, timeout=timeout)
                await self.warm_set("console_ports", sid, self._console_unwrap_ports(r))
                refreshed.add(sid)
            except Exception as exc:  # noqa: BLE001 - one dead console mustn't stall the sweep
                logger.debug("console ports refresh: %s unreachable (%s)", sid, exc)
        return refreshed

    def schedule_console_ports_refresh(self, sids) -> None:
        """Fire-and-forget warm-cache refresh for ``sids``, deduped so a burst of
        page loads (or an aging entry served on every request) doesn't stack
        duplicate polls. Never blocks the caller (the route)."""
        inflight = getattr(self, "_console_ports_refresh_inflight", None)
        if inflight is None:
            inflight = self._console_ports_refresh_inflight = set()
        todo = [s for s in sids if s not in inflight]
        if not todo:
            return
        inflight.update(todo)

        async def _run():
            try:
                await self.refresh_console_ports_cache(todo)
            finally:
                for s in todo:
                    inflight.discard(s)

        try:
            asyncio.create_task(_run())
        except RuntimeError:  # pragma: no cover - no running loop
            for s in todo:
                inflight.discard(s)

    async def run_console_ports_refresh_loop(self):
        """Keep the console-ports warm cache fresh for every connected console
        spoke, so /api/console/ports serves from RAM instead of live-polling."""
        logger.info("Console ports warm-cache refresh loop started.")
        while True:
            try:
                await self.refresh_console_ports_cache()
            except Exception as exc:  # noqa: BLE001 - loop must never die
                logger.error("console ports refresh loop error: %s", exc)
            await asyncio.sleep(self.CONSOLE_PORTS_REFRESH_INTERVAL)


    def register_vnc_session(self, session_id: str, meta: Dict[str, Any]) -> None:
        """Create the session's frame queue and store its metadata."""
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
        sess = self.vnc_sessions.get(session_id)
        if not sess:
            return None
        if not sess.get("connected") and sess.get("expires", 0) < time.time():
            self.vnc_sessions.pop(session_id, None)
            return None
        return sess

    def _vnc_writer_map(self) -> Dict[str, str]:
        """Lazily-initialized unique_id → writer session_id map. Lazy (like
        ``_console_sync_status``) so hub test fixtures that predate this
        feature don't need to know about a new ``__init__`` attribute."""
        if not hasattr(self, "_vnc_writers"):
            self._vnc_writers: Dict[str, str] = {}
        return self._vnc_writers

    def unregister_vnc_session(self, session_id: str) -> None:
        sess = self.vnc_sessions.pop(session_id, None)
        unique_id = str((sess or {}).get("unique_id") or "")
        # Release the write lock if the departing session held it — the VM is
        # up for grabs again (the next opener becomes writer, or an explicit
        # takeover claims it). Remaining read-only viewers are NOT auto-
        # promoted, same as the serial console's PortChannel.detach().
        writers = self._vnc_writer_map()
        if unique_id and writers.get(unique_id) == session_id:
            writers.pop(unique_id, None)

    def vnc_attach(self, unique_id: str, session_id: str) -> bool:
        """Register ``session_id`` as a viewer of ``unique_id``; the first
        viewer (no current writer) becomes the writer. Returns True if this
        session is (now) the writer."""
        writers = self._vnc_writer_map()
        if unique_id not in writers:
            writers[unique_id] = session_id
            return True
        return writers.get(unique_id) == session_id

    def vnc_is_writer(self, unique_id: str, session_id: str) -> bool:
        return self._vnc_writer_map().get(str(unique_id or "")) == session_id

    def vnc_takeover(self, unique_id: str, session_id: str) -> Optional[str]:
        """Forcibly make ``session_id`` the writer for ``unique_id``, evicting
        whoever currently holds it. Returns the dispossessed session_id (None
        if there was no prior writer, or the caller already held it)."""
        writers = self._vnc_writer_map()
        prev = writers.get(unique_id)
        if prev == session_id:
            return None
        writers[unique_id] = session_id
        return prev

    async def notify_vnc_downgraded(self, session_id: str) -> None:
        """Push a ``("downgraded",)`` control tuple onto a still-open VNC
        session's queue so its live /ws/console relay tells the browser to
        drop to view-only, without closing the connection. No-op if the
        session already closed."""
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
        for sid, s in list(self.vnc_sessions.items()):
            if not s.get("connected"):
                continue
            if str(s.get("unique_id") or "") != str(unique_id or ""):
                continue
            out.append({
                "session_id": sid,
                "username": s.get("username") or "",
                "tenant_id": s.get("tenant_id") or "",
                "is_writer": self._vnc_writer_map().get(str(unique_id or "")) == sid,
                "since": s.get("connected_at") or 0,
            })
        out.sort(key=lambda v: v.get("since") or 0, reverse=True)
        return out

    CONSOLE_SESSION_TTL = 60

    def register_console_session(self, session_id: str, meta: Dict[str, Any]) -> None:
        """Create a console session's byte queue + metadata (mirrors VNC)."""
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
        sess = self.console_sessions.get(session_id)
        if not sess:
            return None
        if not sess.get("connected") and sess.get("expires", 0) < time.time():
            self.console_sessions.pop(session_id, None)
            return None
        return sess

    def unregister_console_session(self, session_id: str) -> None:
        self.console_sessions.pop(session_id, None)

    # ── Host-shell (xterm terminal) sessions — agent-terminates-PTY ───────────
    # Same shape as the console session: a byte queue fed by SHELL_OUT frames via
    # _handle_agent_relay_up; browser keystrokes go out as SHELL_IN. TTL applies
    # only until the browser connects (an idle shell sits at a prompt for ages).
    SHELL_SESSION_TTL = 60

    def register_shell_session(self, session_id: str, meta: Dict[str, Any]) -> None:
        self.shell_sessions[session_id] = {
            "queue": asyncio.Queue(),
            "expires": time.time() + self.SHELL_SESSION_TTL,
            "connected": False,
            **meta,
        }

    def get_shell_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        sess = self.shell_sessions.get(session_id)
        if not sess:
            return None
        if not sess.get("connected") and sess.get("expires", 0) < time.time():
            self.shell_sessions.pop(session_id, None)
            return None
        return sess

    def unregister_shell_session(self, session_id: str) -> None:
        self.shell_sessions.pop(session_id, None)

    async def _auto_llm_console_identify(self, spoke_id: str, data: Dict[str, Any]) -> bool:
        """Auto-escalate an unidentified console port to the LLM AI-identify path
        when it's enabled — the local static fingerprint came back empty. Returns
        True if the LLM orchestration ran (so the caller skips the placeholder
        sync); False if AI-identify is off/unavailable or there's nothing to send.
        Best-effort and rate-limited by the spoke's own probe backoff; the learned
        fingerprint cache keeps repeat prompts from re-hitting the LLM."""
        port_id = str(data.get("port_id") or "").strip()
        banner = str(data.get("banner") or "")
        if not port_id or not banner.strip():
            return False
        try:
            from routes import console_llm_identify as llm  # optional feature
        except Exception:  # noqa: BLE001
            return False
        if not llm.hub_llm_identify_enabled(self):
            return False
        agent = llm.find_ab(self)
        if not agent:
            return False
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
        import access
        base = (self.state.get_spoke_tenant(spoke_id) or "").strip()
        claimed = str(claimed or "").strip()
        if not claimed or claimed == base:
            return base
        # Dedicated spoke: its registered tenant is authoritative, full stop.
        if base and not access.tenant_is_shared(base):
            logger.warning(
                "console probe from %s claimed tenant %s but spoke is dedicated to %s; "
                "forcing %s (cross-tenant attribution refused)", spoke_id, claimed, base, base)
            return base
        # Shared / unassigned spoke with a differing claim: corroborate the claim
        # against the claimed tenant's prefixes before honoring it.
        try:
            buckets, _ = await access.attribute_by_prefix(self, [{"ip": device_ip or ""}])
        except Exception:  # noqa: BLE001
            buckets = {}
        if device_ip and claimed in buckets:
            return claimed
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
        # Name preference: the device's real hostname (or serial), else the USB
        # adapter product string (e.g. "USB Serial Controller") — a friendlier
        # name than the cryptic port id, which is the last resort.
        product = str(data.get("product") or "").strip()
        hostname = str(real_host or serial or product or data.get("port_id") or "").strip()
        if not (ip or mac or hostname or serial):
            return
        netbox = self.get_spoke_by_type("ipam")
        if not netbox:
            logger.debug("console probe from %s: no NetBox spoke; device not synced", spoke_id)
            return
        tenant_id = await self._authorized_probe_tenant(spoke_id, data.get("tenant_id"), ip)
        tenant_cfg = self.state.get_tenant(tenant_id) or {}
        tenant_name = tenant_cfg.get("name") or tenant_id
        slug = str(tenant_cfg.get("netbox_tenant_slug") or "").strip()
        if not tenant_id or not slug:
            logger.info("console probe from %s: tenant/netbox_tenant_slug unset; "
                        "device not synced to NetBox", spoke_id)
            self._record_console_sync_status(
                tenant_id or "(unmapped)", tenant_name, "skipped",
                hostname or serial or mac or ip,
                "tenant / netbox_tenant_slug unset")
            return
        cfg = self._console_netbox_sync_cfg()
        # Discovered hardware model (from the LLM/fingerprint identify) +
        # vendor → the sink places the device under its REAL device_type
        # instead of the generic default.
        model = str(identity.get("model") or data.get("model") or "").strip()
        # NetBox gets ip/mac/hostname AND the serial — serial is the strongest
        # match key (the sink matches serial → ip → mac → hostname), so a
        # console-identified device is recognised across DHCP IP moves / renames.
        device_rec = {"ip": ip, "mac": mac, "hostname": hostname, "serial": serial}
        if model:
            device_rec["model"] = model
        if vendor:
            device_rec["manufacturer"] = vendor
        payload = {
            "tenant_id": tenant_id, "tenant_slug": slug,
            "tenant_name": tenant_name,
            "source": "Console", "replace": False,
            "source_of_truth": str(cfg.get("source_of_truth") or "external"),
            "devices": [device_rec],
            "defaults": cfg.get("defaults", {}) or {},
        }
        try:
            await self.request_response(netbox, "NETBOX_SYNC_DEVICES", payload, timeout=60.0)
            logger.info("console probe: synced %s to NetBox (tenant %s)",
                        hostname or serial or mac or ip, tenant_id)
            self._record_console_sync_status(
                tenant_id, tenant_name, "success", hostname or serial or mac or ip)
        except Exception as e:  # noqa: BLE001
            logger.warning("console probe NetBox sync failed: %s", e)
            self._record_console_sync_status(
                tenant_id, tenant_name, "error",
                hostname or serial or mac or ip, str(e)[:200])
