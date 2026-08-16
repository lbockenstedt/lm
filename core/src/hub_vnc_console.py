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
        # Local fingerprint failed to recognize the device (no vendor and no
        # harvested identity). If AI-assisted identify is enabled, auto-escalate
        # to the LLM instead of syncing a placeholder device — the fingerprint DB
        # (console_learn) then caches the result so repeat prompts stay static.
        # Guard on method != "llm" so the LLM's own result can't re-trigger this.
        if (not vendor and not (ip or mac or real_host or serial)
                and str(data.get("method") or "").strip() != "llm"):
            if await self._auto_llm_console_identify(spoke_id, data):
                return
        hostname = str(real_host or serial or data.get("port_id") or "").strip()
        if not (ip or mac or hostname):
            return
        netbox = self.get_spoke_by_type("ipam")
        if not netbox:
            logger.debug("console probe from %s: no NetBox spoke; device not synced", spoke_id)
            return
        tenant_id = str(data.get("tenant_id") or "").strip() or (self.state.get_spoke_tenant(spoke_id) or "")
        tenant_cfg = self.state.get_tenant(tenant_id) or {}
        slug = str(tenant_cfg.get("netbox_tenant_slug") or "").strip()
        if not tenant_id or not slug:
            logger.info("console probe from %s: tenant/netbox_tenant_slug unset; "
                        "device not synced to NetBox", spoke_id)
            return
        payload = {
            "tenant_id": tenant_id, "tenant_slug": slug,
            "tenant_name": tenant_cfg.get("name") or tenant_id,
            "source": "Console", "replace": False,
            "devices": [{"ip": ip, "mac": mac, "hostname": hostname}], "defaults": {},
        }
        try:
            await self.request_response(netbox, "NETBOX_SYNC_DEVICES", payload, timeout=60.0)
            logger.info("console probe: synced %s to NetBox (tenant %s)",
                        hostname or mac or ip, tenant_id)
        except Exception as e:  # noqa: BLE001
            logger.warning("console probe NetBox sync failed: %s", e)
