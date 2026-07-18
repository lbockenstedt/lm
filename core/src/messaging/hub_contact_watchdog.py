"""Hub-contact watchdog — ``HubContactWatchdogMixin``.

Pure textual extraction from ``control_plane.py``: the opt-in escalating
self-recovery watchdog (restart -> reboot -> sleep ladder when the hub is
unreachable) mixed into ``BaseControlPlane``. The outage clock
(``self._last_hub_contact``) and the task handle (``self._hub_contact_task``)
stay in ``BaseControlPlane`` (set in __init__ / run); these methods only
reference that ``self`` state plus ``self._spoke_state_dir`` and
``self._flush_log_relay_async`` (LogRelayMixin) resolved via the class. No
behavior change.
"""

import asyncio
import json
import os
import time
import logging

logger = logging.getLogger("BaseControlPlane")


class HubContactWatchdogMixin:
    """Escalating hub-contact self-recovery watchdog for BaseControlPlane."""

    # ------------------------------------------------------------------
    # Hub-contact watchdog (escalating self-recovery when the hub is
    # unreachable). OPT-IN (LM_HUB_CONTACT_WATCHDOG=1) — the reboot stage is
    # drastic (on a pxmx agent that runs on the Proxmox HOST, a reboot cycles
    # every VM on that host), so it is off unless a deployment enables it.
    # ------------------------------------------------------------------
    def _hcw_state_path(self) -> str:
        return os.path.join(self._spoke_state_dir(), "hub_contact_watchdog.json")

    def _hcw_config_path(self) -> str:
        return os.path.join(self._spoke_state_dir(), "hub_contact_watchdog_config.json")

    def _hcw_config(self) -> dict:
        """Effective watchdog config, read fresh each tick. Precedence: the
        hub-pushed config file (SPOKE_SET_WATCHDOG, persisted so it survives a
        restart/reboot and applies even when the hub is unreachable) OVER env
        vars OVER defaults. Persisting locally matters: the whole point is to
        recover when the hub can't be reached, so 'enabled' can't depend on a
        live push."""
        def _envf(name, default):
            try:
                return max(1.0, float(os.environ.get(name, "").strip() or default))
            except (TypeError, ValueError):
                return float(default)
        cfg = {
            "enabled": os.environ.get("LM_HUB_CONTACT_WATCHDOG", "0").lower() in ("1", "true", "yes"),
            "service_s": _envf("LM_HUB_WATCHDOG_SERVICE_S", 300),
            "reboot_s": _envf("LM_HUB_WATCHDOG_REBOOT_S", 900),
            "reboot_grace_s": _envf("LM_HUB_WATCHDOG_REBOOT_GRACE_S", 300),
            "sleep_s": _envf("LM_HUB_WATCHDOG_SLEEP_S", 3600),
            "max_runs": int(_envf("LM_HUB_WATCHDOG_MAX_RUNS", 3)),
        }
        try:
            with open(self._hcw_config_path()) as f:
                pushed = json.load(f)
            if isinstance(pushed, dict):
                if "enabled" in pushed:
                    cfg["enabled"] = bool(pushed["enabled"])
                for k, caster in (("service_s", float), ("reboot_s", float),
                                  ("reboot_grace_s", float), ("sleep_s", float),
                                  ("max_runs", int)):
                    if pushed.get(k) is not None:
                        try:
                            cfg[k] = max(1, caster(pushed[k]))
                        except (TypeError, ValueError):
                            pass
        except FileNotFoundError:
            pass
        except Exception as e:  # noqa: BLE001
            logger.debug("hub-contact watchdog: config read failed: %s", e)
        return cfg

    def _hcw_save_config(self, cfg: dict) -> None:
        """Persist the hub-pushed watchdog config so it survives restart/reboot."""
        try:
            os.makedirs(os.path.dirname(self._hcw_config_path()), exist_ok=True)
            tmp = self._hcw_config_path() + ".tmp"
            with open(tmp, "w") as f:
                json.dump(cfg, f)
            os.replace(tmp, self._hcw_config_path())
        except Exception as e:  # noqa: BLE001
            logger.debug("hub-contact watchdog: config save failed: %s", e)

    def _hcw_load(self) -> dict:
        """Load persisted escalation state (survives restart + reboot). A run =
        one escalation attempt (service restart at t1, reboot at t2); after a
        failed run we sleep, then start another. Keys: run, run_start_at, stage,
        sleep_until, last_contact_at, gave_up."""
        try:
            with open(self._hcw_state_path()) as f:
                d = json.load(f)
            return d if isinstance(d, dict) else {}
        except Exception:  # noqa: BLE001
            return {}

    def _hcw_save(self, st: dict) -> None:
        try:
            os.makedirs(os.path.dirname(self._hcw_state_path()), exist_ok=True)
            tmp = self._hcw_state_path() + ".tmp"
            with open(tmp, "w") as f:
                json.dump(st, f)
            os.replace(tmp, self._hcw_state_path())
        except Exception as e:  # noqa: BLE001
            logger.debug("hub-contact watchdog: state save failed: %s", e)

    def _hcw_clear(self) -> None:
        try:
            os.remove(self._hcw_state_path())
        except FileNotFoundError:
            pass
        except Exception as e:  # noqa: BLE001
            logger.debug("hub-contact watchdog: state clear failed: %s", e)

    async def _hcw_reboot(self) -> None:
        """Reboot the host (best-effort; needs sudoers for reboot). Flushes logs
        first so the escalation is visible in the hub relay before we go down."""
        try:
            await self._flush_log_relay_async()
        except Exception:  # noqa: BLE001
            pass
        for cmd in (["sudo", "-n", "/sbin/reboot"], ["sudo", "-n", "reboot"],
                    ["systemctl", "reboot"], ["/sbin/reboot"]):
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd, stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL)
                await asyncio.wait_for(proc.wait(), timeout=15.0)
                if proc.returncode == 0:
                    return
            except Exception:  # noqa: BLE001
                continue
        logger.error("hub-contact watchdog: reboot command failed (no sudoers for "
                     "reboot?); leaving the server up.")

    async def _hub_contact_watchdog(self):
        """Escalating recovery when the hub can't be reached. Per run:
          * outage >= T1 (5m default): restart the service (os._exit(3) →
            systemd Restart=on-failure relaunches).
          * still down at outage >= T2 (15m default): reboot the host.
          * still down after the reboot grace: the run failed → sleep T_SLEEP
            (1h default), then start the next run.
        After max_runs (3 default, ~4h) give up and stay offline. State persists
        across the restart/reboot so the ladder is not reset by its own actions.
        Any successful hub contact clears the state (full recovery). Config is
        read fresh each tick (hub-pushed file → env → defaults) so the WebUI can
        enable/disable + retune it without a restart; the task always runs and
        no-ops while disabled."""
        # Reload the outage clock from disk so a reboot/restart doesn't reset it.
        st = self._hcw_load()
        if st.get("last_contact_at"):
            # Keep the OLDER of (seeded now, persisted) so an ongoing outage keeps
            # counting; a genuine fresh boot after real contact just uses now.
            self._last_hub_contact = min(self._last_hub_contact, float(st["last_contact_at"]))
        logger.info("hub-contact watchdog running (enabled=%s).", self._hcw_config()["enabled"])
        while True:
            try:
                await asyncio.sleep(30)
                cfg = self._hcw_config()
                if not cfg["enabled"]:
                    if self._hcw_load():  # was armed, now disabled → wipe ladder
                        self._hcw_clear()
                    continue
                T1, T2 = cfg["service_s"], cfg["reboot_s"]
                GRACE, SLEEP, MAX_RUNS = cfg["reboot_grace_s"], cfg["sleep_s"], cfg["max_runs"]
                now = time.time()
                connected = self._hub_ws is not None
                outage = now - self._last_hub_contact
                st = self._hcw_load()

                if connected or outage < 1:
                    if st:  # recovered → wipe the ladder
                        logger.info("hub-contact watchdog: hub reachable again — clearing escalation state.")
                        self._hcw_clear()
                    # Persist a periodic contact heartbeat so a later boot inherits it.
                    self._hcw_save({"last_contact_at": self._last_hub_contact})
                    continue

                if st.get("gave_up"):
                    continue
                if now < float(st.get("sleep_until", 0) or 0):
                    continue  # cooling down between runs
                run = int(st.get("run", 0) or 0)
                if run >= MAX_RUNS:
                    logger.error("hub-contact watchdog: hub unreachable after %d runs (~%.1fh) — "
                                 "giving up; leaving this node offline.", run,
                                 (T2 + SLEEP) * MAX_RUNS / 3600.0)
                    st["gave_up"] = True
                    self._hcw_save(st)
                    continue

                # Start a run if none in progress. run_start_at anchors T1/T2.
                if not st.get("run_start_at"):
                    st.update({"run_start_at": now, "stage": "started",
                               "last_contact_at": self._last_hub_contact})
                    self._hcw_save(st)
                run_outage = now - float(st["run_start_at"])
                stage = st.get("stage", "started")

                if stage == "started" and run_outage >= T1:
                    logger.error("hub-contact watchdog: no hub contact for %.0fs (run %d) — "
                                 "restarting the service.", run_outage, run + 1)
                    st["stage"] = "service_restarted"
                    st["last_contact_at"] = self._last_hub_contact
                    self._hcw_save(st)
                    try:
                        await self._flush_log_relay_async()
                    except Exception:  # noqa: BLE001
                        pass
                    os._exit(3)  # systemd Restart=on-failure relaunches us
                elif stage == "service_restarted" and run_outage >= T2:
                    logger.error("hub-contact watchdog: still no hub contact %.0fs into run %d — "
                                 "rebooting the server.", run_outage, run + 1)
                    st["stage"] = "rebooted"
                    st["last_contact_at"] = self._last_hub_contact
                    self._hcw_save(st)
                    await self._hcw_reboot()
                elif stage == "rebooted" and run_outage >= (T2 + GRACE):
                    logger.error("hub-contact watchdog: run %d failed (service restart + reboot "
                                 "did not restore contact) — sleeping %.0fs before the next run.",
                                 run + 1, SLEEP)
                    st.update({"run": run + 1, "sleep_until": now + SLEEP,
                               "run_start_at": 0, "stage": "started",
                               "last_contact_at": self._last_hub_contact})
                    self._hcw_save(st)
            except asyncio.CancelledError:
                raise
            except Exception as e:  # noqa: BLE001 — never fatal
                logger.debug("hub-contact watchdog cycle failed: %s", e)
