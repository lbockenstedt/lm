"""VNC + interactive-console session registry for the LM Hub (agent-terminates-WSS)."""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Dict, Optional

logger = logging.getLogger("Hub")


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


    def register_vnc_session(self, session_id: str, meta: Dict[str, Any]) -> None:
        """Create the session's frame queue and store its metadata."""
        self.vnc_sessions[session_id] = {
            "queue": asyncio.Queue(),
            "expires": time.time() + self.VNC_SESSION_TTL,
            **meta,
        }

    def get_vnc_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Return a live session dict (queue + meta) or None if absent/expired.
        Expired sessions are reaped on read."""
        sess = self.vnc_sessions.get(session_id)
        if not sess:
            return None
        if sess.get("expires", 0) < time.time():
            self.vnc_sessions.pop(session_id, None)
            return None
        return sess

    def unregister_vnc_session(self, session_id: str) -> None:
        self.vnc_sessions.pop(session_id, None)

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
        agent = llm.find_bugfixer(self)
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

    async def _handle_console_probe(self, spoke_id: str, data: Dict[str, Any]) -> None:
        """A console spoke auto-identified a device — match/create a NetBox device
        from the harvested identity (best-effort, event-driven). Uses the port's
        EFFECTIVE tenant (per-port override in the payload, else the console
        agent's tenant). replace=False so we upsert one device, not overwrite the
        tenant's discovered set. Serial is surfaced in the port UI; NetBox gets
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
        tenant_id = str(data.get("tenant_id") or "").strip() or (self.state.get_spoke_tenant(spoke_id) or "")
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
