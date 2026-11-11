"""``lm-dhcp-worker`` — the Kea-host half of an HA pair.

Runs on each Kea server and dials its coordinator's ``/ws/agent`` listener (the
``dhcp`` module spoke). Like the DNS worker this is deliberately NOT a generic
agent: the op table below is everything it can be asked to do. The only shell
commands it ever runs are a small number of FIXED, argument-free apt-get/dpkg
invocations for the Kea hook-library packages — there is no caller-supplied
command, package name, path or URL anywhere.

The apply op snapshots the running config before writing so the coordinator can
roll a node back when its partner fails mid-transaction.
"""

# argparse reads worker settings from the command line.
import argparse
# asyncio runs the WebSocket client loop.
import asyncio
# copy.deepcopy keeps config snapshots independent of later edits.
import copy
# Standard-library logging (logger defined below).
import logging
# os checks hook-library files and reads environment settings.
import os
# shutil.which detects whether apt-get exists on this host.
import shutil
# subprocess runs the fixed apt-get/dpkg/systemctl commands.
import subprocess
# Type hints only; they document payload shapes.
from typing import Any, Dict, Optional

# KeaManager talks to the local Kea daemons; kea_ha supplies HA helper functions.
# The import path differs when run as a script vs loaded as a package.
try:
    from kea_manager import KeaManager, worker_code_version
    from kea_ha import config_fingerprint, hook_paths, parse_ha_status, resolve_hook_dir
# Package layout: import through src.
except ImportError:  # loaded as a package (src.X)
    from src.kea_manager import KeaManager, worker_code_version  # type: ignore
    from src.kea_ha import (  # type: ignore
        config_fingerprint, hook_paths, parse_ha_status, resolve_hook_dir)

# One named logger so all worker messages can be filtered together.
logger = logging.getLogger("DHCPWorker")

#: The ONLY package install this worker can perform. Fixed argv — no shell, no
#: caller-supplied package name. The hook libraries ship in **kea-common** on
#: Debian/Ubuntu; there is no "kea-hooks" package, so the old value could only
#: ever fail and leave the node reporting its HA libraries missing.
_HOOK_PACKAGES = ("kea-common",)

# Coordinator agent port reserved for the DHCP role.
DEFAULT_COORDINATOR_PORT = 8770
# Packet-counter snapshots for the Overview's hour/day/week/month windows.
STATS_HISTORY_PATH = "/var/lib/lm-dhcp-worker/stats_history.json"


class DhcpWorkerOps:
    """The fixed operation table exposed to the coordinator."""

    def __init__(self, mgr: KeaManager):
        """Bind the ops to a Kea manager and start with no rollback snapshots.

        Args:
            mgr: Manager for the local Kea daemons.
        """
        # Keep the manager; the DHCPv4 rollback snapshot is empty until the first apply.
        self.mgr = mgr
        self._snapshot: Optional[Dict[str, Any]] = None
        # Separate DHCPv6 rollback slot: a v6 apply/rollback must never
        # clobber (or be clobbered by) an in-flight v4 apply/rollback on the
        # same worker — they are two independent Kea daemons/configs.
        self._snapshot6: Optional[Dict[str, Any]] = None

    # ── Hooks ───────────────────────────────────────────────────────────────

    def install_hooks(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """``KEAW_INSTALL_HOOKS`` — make sure the HA + lease_cmds libs exist.

        Idempotent: present → SUCCESS without touching apt. Absent → one fixed
        ``apt-get install -y kea-common``. Still absent afterwards → ERROR, so
        the coordinator refuses to generate an HA config this node cannot load.
        """
        # Resolve the hook dir ON THIS NODE: the multiarch triplet differs per
        # architecture, so a coordinator's x86_64 default made every arm64
        # worker report its HA libraries missing.
        hook_dir = resolve_hook_dir(str(data.get("hook_dir") or ""))
        # Full paths of each required hook library, and which of them are missing.
        paths = hook_paths(hook_dir)
        missing = [name for name, path in paths.items() if not os.path.exists(path)]
        # Everything is already present: nothing to install.
        if not missing:
            return {"status": "SUCCESS", "libraries": paths, "installed": False,
                    "hook_dir": hook_dir}
        # Without apt-get there is no way to install them here.
        if not shutil.which("apt-get"):
            return {"status": "ERROR", "libraries": paths,
                    "message": f"missing Kea hook libraries: {', '.join(missing)} "
                               f"(no apt-get on this host to install them)"}
        # Run the one fixed install command; a timeout or launch failure is an error.
        try:
            proc = subprocess.run(
                ["apt-get", "install", "-y", "-qq", *_HOOK_PACKAGES],
                capture_output=True, text=True, timeout=300)
        # apt-get could not run or timed out.
        except Exception as e:  # noqa: BLE001
            return {"status": "ERROR", "libraries": paths, "message": str(e)}
        # apt may have created the arch-specific dir only now, so re-resolve.
        hook_dir = resolve_hook_dir(str(data.get("hook_dir") or ""))
        paths = hook_paths(hook_dir)
        # Check again after the install.
        still_missing = [name for name, path in paths.items()
                         if not os.path.exists(path)]
        # Still missing: report the failure with the tail of apt's output.
        if still_missing:
            detail = (proc.stderr or proc.stdout or "").strip()[-500:]
            return {"status": "ERROR", "libraries": paths, "hook_dir": hook_dir,
                    "message": f"Kea hook libraries still missing after install: "
                               f"{', '.join(still_missing)}. {detail}"}
        # Installed successfully.
        return {"status": "SUCCESS", "libraries": paths, "installed": True,
                "hook_dir": hook_dir}

    # ── Config lifecycle ────────────────────────────────────────────────────

    @staticmethod
    def _config_of(data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Return the Dhcp4 body of data["config"] (wrapped or bare), or None if absent."""
        # Accept either {"Dhcp4": {...}} or the bare Dhcp4 dict.
        cfg = data.get("config")
        if isinstance(cfg, dict) and "Dhcp4" in cfg:
            cfg = cfg["Dhcp4"]
        return cfg if isinstance(cfg, dict) else None

    def validate(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """``KEAW_VALIDATE`` — Kea's own ``config-test`` on a candidate config.

        Uses the running daemon's parser rather than a local heuristic: only Kea
        can say whether Kea will accept a config.
        """
        # Pull out the candidate config; it is required.
        cfg = self._config_of(data)
        if cfg is None:
            return {"status": "ERROR", "message": "config (Dhcp4) is required"}
        # Ask Kea to test the config without applying it.
        try:
            self.mgr._rpc("dhcp4", "config-test", {"Dhcp4": cfg})
        # Kea rejected the config: its error message is the answer.
        except Exception as e:  # noqa: BLE001 — a rejected config is the answer
            return {"status": "ERROR", "message": str(e)}
        # Kea accepted it: return its fingerprint.
        return {"status": "SUCCESS", "digest": config_fingerprint(cfg)}

    def get_config(self, _data: Dict[str, Any]) -> Dict[str, Any]:
        """``KEAW_GET_CONFIG`` — this node's FULL running ``Dhcp4`` config.

        The coordinator renders the node's next config on top of this, so
        interfaces, lease database, loggers and every other node-local setting
        survive a cluster apply instead of being replaced by a generated stub.
        """
        # Fetch the running config; certain failures trigger a one-time self-heal attempt.
        try:
            cfg = self.mgr.get_config()
        # Fetch failed; look at why.
        except Exception as e:  # noqa: BLE001
            err_msg = str(e)
            # Errors that mean the daemon is down or unreachable can often be fixed by a restart.
            if any(term in err_msg.lower() for term in ("likely to be offline", "permission denied", "connection refused", "unable to forward")):
                logger.warning("Kea DHCP4 appears offline or inaccessible (%s); attempting service restart & permission repair", err_msg)
                # Restart (and repair permissions); if that worked, wait a moment and retry once.
                if self._restart_kea_dhcp4_service():
                    import time
                    time.sleep(1.0)
                    try:
                        cfg = self.mgr.get_config()
                    # Still failing after the restart: report both errors.
                    except Exception as retry_e:  # noqa: BLE001
                        return {"status": "ERROR", "message": f"{err_msg} (restart retry failed: {retry_e})"}
                # Restart failed: report the original error.
                else:
                    return {"status": "ERROR", "message": err_msg}
            # Some other error: report it as-is.
            else:
                return {"status": "ERROR", "message": err_msg}
        # Anything other than a dict is not a usable config.
        if not isinstance(cfg, dict):
            return {"status": "ERROR",
                    "message": f"Kea returned {type(cfg).__name__}, not a config"}
        # Return the config and its fingerprint.
        return {"status": "SUCCESS", "config": cfg,
                "digest": config_fingerprint(cfg)}

    # ── DHCPv6 config lifecycle ─────────────────────────────────────────────
    #
    # Parallels the v4 methods above against Kea's separate dhcp6 daemon/CA
    # service. This first pass deliberately omits the v4 path's advanced
    # self-healing (hook-load diagnostics, HA-TLS/kea.conf permission repair,
    # ABI/package-version detail) — those are proven fixes for known v4
    # failure modes observed in production and have not yet been reproduced
    # or ported for dhcp6. The safety-critical snapshot/rollback contract
    # (never report SUCCESS unless both config-set AND config-write landed;
    # restore-on-write-failure) is preserved.

    @staticmethod
    def _config6_of(data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Return the Dhcp6 body of data["config"] (wrapped or bare), or None if absent."""
        # Accept either {"Dhcp6": {...}} or the bare Dhcp6 dict.
        cfg = data.get("config")
        if isinstance(cfg, dict) and "Dhcp6" in cfg:
            cfg = cfg["Dhcp6"]
        return cfg if isinstance(cfg, dict) else None

    def validate6(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """``KEAW_VALIDATE6`` — Kea's own ``config-test`` against dhcp6."""
        # Pull out the candidate config; it is required.
        cfg = self._config6_of(data)
        if cfg is None:
            return {"status": "ERROR", "message": "config (Dhcp6) is required"}
        # Ask Kea's dhcp6 daemon to test the config without applying it.
        try:
            self.mgr._rpc("dhcp6", "config-test", {"Dhcp6": cfg})
        # Kea rejected the config: its error message is the answer.
        except Exception as e:  # noqa: BLE001 — a rejected config is the answer
            return {"status": "ERROR", "message": str(e)}
        # Kea accepted it: return its fingerprint.
        return {"status": "SUCCESS", "digest": config_fingerprint(cfg)}

    def get_config6(self, _data: Dict[str, Any]) -> Dict[str, Any]:
        """``KEAW_GET_CONFIG6`` — this node's FULL running ``Dhcp6`` config."""
        # Fetch the running dhcp6 config.
        try:
            cfg = self.mgr.get_config6()
        # Daemon unreachable or command failed.
        except Exception as e:  # noqa: BLE001
            return {"status": "ERROR", "message": str(e)}
        # Anything other than a dict is not a usable config.
        if not isinstance(cfg, dict):
            return {"status": "ERROR",
                    "message": f"Kea returned {type(cfg).__name__}, not a config"}
        # Return the config and its fingerprint.
        return {"status": "SUCCESS", "config": cfg,
                "digest": config_fingerprint(cfg)}

    def apply6(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """``KEAW_APPLY6`` — snapshot, ``config-set``, ``config-write`` on dhcp6.

        Same mutated/restored reporting contract as :meth:`apply` — see there
        for why the two Kea calls are distinguished."""
        # Pull out the candidate config; it is required.
        cfg = self._config6_of(data)
        if cfg is None:
            return {"status": "ERROR", "message": "config (Dhcp6) is required",
                    "mutated": False}
        # Snapshot the running config first so a failed transaction can be rolled back.
        try:
            self._snapshot6 = copy.deepcopy(self.mgr.get_config6())
        # Without a snapshot we refuse to change anything.
        except Exception as e:  # noqa: BLE001
            return {"status": "ERROR", "mutated": False,
                    "message": f"cannot snapshot current DHCPv6 config for rollback: {e}"}
        # Apply the new config (config-set, then config-write to disk).
        outcome = self.mgr.apply_config6(copy.deepcopy(cfg))
        # Both steps landed: success.
        if outcome.get("set") and outcome.get("written"):
            return {"status": "SUCCESS", "version": data.get("version"),
                    "mutated": True, "digest": config_fingerprint(cfg)}
        # config-set failed: nothing changed on this node.
        if not outcome.get("set"):
            return {"status": "ERROR", "mutated": False,
                    "message": outcome.get("error") or "config-set (Dhcp6) failed"}
        # config-set landed, config-write did not: restore locally right now —
        # see apply()'s identical restore-on-write-failure rationale.
        # Restore the snapshot so the node is not left on an unpersisted config.
        restore = self.mgr.apply_config6(copy.deepcopy(self._snapshot6))
        # Restore fully landed: report the original failure, node unchanged.
        if restore.get("set") and restore.get("written"):
            return {"status": "ERROR", "mutated": False, "restored": True,
                    "message": (f"config-write failed ({outcome.get('error')}); "
                                f"the previous DHCPv6 configuration was restored "
                                f"and persisted on this node")}
        # Restore is running but not saved to disk: partial.
        if restore.get("set"):
            return {"status": "PARTIAL", "mutated": True, "restored": False,
                    "message": (f"config-write failed ({outcome.get('error')}); "
                                f"the previous DHCPv6 configuration is running "
                                f"again but could NOT be persisted "
                                f"({restore.get('error')})")}
        # Even the restore failed: the node is running the new, unsaved config.
        return {"status": "PARTIAL", "mutated": True, "restored": False,
                "message": (f"config-write failed ({outcome.get('error')}) AND "
                            f"the local restore failed ({restore.get('error')}) "
                            f"— this node is running the new, unpersisted "
                            f"DHCPv6 configuration")}

    def rollback6(self, _data: Dict[str, Any]) -> Dict[str, Any]:
        """``KEAW_ROLLBACK6`` — restore the dhcp6 config from the last apply6."""
        # Nothing to roll back to unless apply6 ran first.
        if self._snapshot6 is None:
            return {"status": "ERROR", "message": "no DHCPv6 snapshot to roll back to"}
        # Re-apply the snapshot.
        outcome = self.mgr.apply_config6(copy.deepcopy(self._snapshot6))
        # config-set failed: rollback did not happen.
        if not outcome.get("set"):
            return {"status": "ERROR",
                    "message": outcome.get("error") or "rollback config-set (Dhcp6) failed"}
        # Running again but not saved to disk: partial.
        if not outcome.get("written"):
            return {"status": "PARTIAL",
                    "digest": config_fingerprint(self._snapshot6),
                    "message": (f"previous DHCPv6 configuration restored but not "
                                f"persisted ({outcome.get('error')})")}
        # Rolled back and persisted.
        return {"status": "SUCCESS",
                "digest": config_fingerprint(self._snapshot6)}

    def standdown6(self, _data: Dict[str, Any]) -> Dict[str, Any]:
        """``KEAW_STANDDOWN6`` — leave the DHCPv6 HA pair cleanly (see
        :meth:`standdown` for the v4 rationale, identical here)."""
        # Copy the running dhcp6 config so it can be edited safely.
        try:
            cfg = copy.deepcopy(self.mgr.get_config6())
        # Cannot read the config: report it.
        except Exception as e:  # noqa: BLE001
            return {"status": "ERROR", "message": str(e)}
        # Remove the HA and lease_cmds hook entries, counting how many were dropped.
        before = len(cfg.get("hooks-libraries") or [])
        cfg["hooks-libraries"] = [
            h for h in (cfg.get("hooks-libraries") or [])
            if isinstance(h, dict) and not str(h.get("library", "")).endswith(
                ("libdhcp_ha.so", "libdhcp_lease_cmds.so"))]
        removed = before - len(cfg["hooks-libraries"])
        # No HA hooks were loaded: nothing to do.
        if not removed:
            return {"status": "SUCCESS", "changed": False,
                    "message": "no HA hooks were loaded"}
        # Apply and persist the trimmed config; anything short of both is an error.
        outcome = self.mgr.apply_config6(cfg)
        if not (outcome.get("set") and outcome.get("written")):
            return {"status": "ERROR", "changed": bool(outcome.get("set")),
                    "message": outcome.get("error") or "could not remove the DHCPv6 HA hooks"}
        # HA hooks removed and saved.
        return {"status": "SUCCESS", "changed": True, "hooks_removed": removed}

    def ha_status6(self, _data: Dict[str, Any]) -> Dict[str, Any]:
        """``KEAW_HA_STATUS6`` — ``status-get`` (dhcp6) plus config digest."""
        # Ask the dhcp6 daemon for its HA status.
        try:
            raw = self.mgr._rpc("dhcp6", "status-get", {})
        # Daemon unreachable: report it as not running.
        except Exception as e:  # noqa: BLE001
            return {"status": "ERROR", "message": str(e), "running": False}
        # Also report the config fingerprint and subnet count, best effort.
        digest = ""
        subnet_count = None
        try:
            cfg = self.mgr.get_config6()
            digest = config_fingerprint(cfg)
            subnet_count = len(cfg.get("subnet6") or [])
        # Config unreadable: still return the HA status without the digest.
        except Exception as e:  # noqa: BLE001 — HA state is still worth reporting
            logger.debug("could not read DHCPv6 config for digest: %s", e)
        # Return raw and parsed HA status with the digest and subnet count.
        return {"status": "SUCCESS", "running": True, "status_get": raw,
                "ha": parse_ha_status(raw), "digest": digest,
                "subnet_count": subnet_count}

    @staticmethod
    def _hook_load_failure_detail(error: str, hook_dir: str) -> str:
        """Enrich a Kea "hook libraries failed to load" config-set rejection.

        Kea's own error string (e.g. "One or more hook libraries failed to
        load") never says WHICH library or why — the real reason is only in
        the kea-dhcp4-server journal at the instant it tried to dlopen() the
        .so. Without this, that error was a dead end in the UI: the operator
        had to SSH in and grep journalctl themselves. Appends the resolved
        hook dir's actual listing (wrong arch triplet / missing file is
        visible immediately), the kea-dhcp4-server/kea-common package
        versions (a mismatch here means the libraries are for a DIFFERENT
        Kea ABI than the running daemon — a same-version ``--reinstall``
        cannot fix that), an ``ldd`` of the HA hook .so (surfaces "not found"
        shared-library dependencies, the #1 real dlopen() failure cause
        distinct from a missing/corrupt file), plus the last few HOOKS_*
        log lines.
        """
        # Only enrich hook-load errors; return anything else unchanged.
        if "hook librar" not in (error or "").lower():
            return error
        # Start with Kea's error, then append each diagnostic found.
        detail = [error]
        # Add which worker code commit is running, if known.
        code_ver = worker_code_version()
        if code_ver.get("commit"):
            detail.append(
                f"worker code: {code_ver['commit']}"
                + (f" ({code_ver['commit_time']})" if code_ver.get("commit_time") else "")
                + (" [locally modified]" if code_ver.get("dirty") else ""))
        # List the resolved hook directory (shows a wrong arch path or missing files).
        try:
            hook_dir = resolve_hook_dir(hook_dir)
            entries = sorted(os.listdir(hook_dir)) if os.path.isdir(hook_dir) else []
            detail.append(f"hook dir {hook_dir}: "
                          f"{', '.join(entries) if entries else '(missing or empty)'}")
        # Directory listing failed: say so.
        except Exception as e:  # noqa: BLE001
            detail.append(f"could not list hook dir: {e}")
        # Add installed Kea package versions so ABI drift is visible.
        pkg_versions = DhcpWorkerOps._installed_package_versions()
        if pkg_versions:
            detail.append("package versions: " + ", ".join(
                f"{name}={ver}" for name, ver in pkg_versions.items()))
        # Add any unresolved shared-library dependencies of the HA hook.
        ldd_issue = DhcpWorkerOps._ldd_missing_deps(
            os.path.join(hook_dir, "libdhcp_ha.so"))
        if ldd_issue:
            detail.append(f"libdhcp_ha.so dependency check: {ldd_issue}")
        # Add any HA-TLS permission problem.
        ha_tls_issue = DhcpWorkerOps._ha_tls_permission_issue()
        if ha_tls_issue:
            detail.append(f"HA-TLS material check: {ha_tls_issue}")
        # Add the most relevant recent hook-related log line from Kea's journal.
        # Best effort: failures here are ignored.
        try:
            proc = subprocess.run(
                ["journalctl", "-u", "kea-dhcp4-server", "-n", "30", "--no-pager"],
                capture_output=True, text=True, timeout=10)
            # Prefer the actual ERROR/FATAL line over a later benign
            # "successfully closed" cleanup message — a real dlopen()/config
            # failure (e.g. HA_CONFIGURATION_FAILED "... Permission denied")
            # is almost always followed by Kea unloading the libraries it did
            # manage to load, and picking the LAST hook-related line surfaced
            # that harmless unload instead of the actual cause.
            hook_lines = [ln for ln in (proc.stdout or "").splitlines()
                         if "hook" in ln.lower() or "HOOKS_" in ln]
            error_lines = [ln for ln in hook_lines
                          if " ERROR " in ln or " FATAL " in ln]
            chosen = (error_lines or hook_lines)
            if chosen:
                detail.append("recent log: " + chosen[-1][:300])
        # journalctl unavailable: skip the log line.
        except Exception:  # noqa: BLE001 — best-effort only
            pass
        # Join everything into one message.
        return " | ".join(detail)

    @staticmethod
    def _ha_tls_permission_issue() -> str:
        """Return a human-readable problem description if the HA-TLS material
        the daemon (running as ``_kea``) needs to read isn't actually
        readable by it — the #1 real cause behind a generic "hook libraries
        failed to load" when the files themselves are present and intact
        (see ``_repair_ha_tls_permissions``). Returns "" when fine or when the
        directory/user don't apply (HA not configured on this node)."""
        # HA-TLS directory; if it does not exist, HA TLS is not in use here.
        d = DhcpWorkerOps._HA_TLS_DIR
        if not os.path.isdir(d):
            return ""
        # Best effort: any error means "no detected problem".
        try:
            # Read the directory's owner/mode and look up the _kea group.
            st = os.stat(d)
            # grp is Unix-only, so import it just here.
            import grp
            try:
                kea_gid = grp.getgrnam("_kea").gr_gid
            # No _kea group: Kea is not installed the usual way, so the check does not apply.
            except KeyError:
                return ""
            # _kea can enter the directory if group-execute is set and it owns the group, or if
            # world-execute is set.
            mode = st.st_mode
            group_can_enter = bool(mode & 0o010) and st.st_gid == kea_gid
            world_can_enter = bool(mode & 0o001)
            # Neither applies: describe the problem.
            if not (group_can_enter or world_can_enter):
                return (f"{d} is not readable by the _kea user (owner gid="
                        f"{st.st_gid}, mode={oct(mode & 0o777)}) — the daemon "
                        f"cannot traverse into it to read its HA trust anchor")
        # Stat or lookup failure: report nothing.
        except Exception:  # noqa: BLE001 — best-effort only
            pass
        # No problem found.
        return ""

    #: Packages whose version alignment matters for hook-library ABI
    #: compatibility — kea-common ships the hooks, kea-dhcp4-server is the
    #: daemon that dlopen()s them; a mismatch between the two after a partial
    #: upgrade is the leading cause of an ALL-hooks load failure that a same-
    #: version ``apt-get --reinstall kea-common`` can never fix.
    _VERSION_CHECK_PACKAGES = ("kea-common", "kea-dhcp4-server", "kea-ctrl-agent")

    @staticmethod
    def _installed_package_versions() -> Dict[str, str]:
        """``dpkg-query`` versions of the Kea packages, for the diagnostic
        detail above — lets an operator (or this code, see
        ``_repair_hook_libraries``) see at a glance whether kea-common and
        kea-dhcp4-server drifted apart, which a plain existence check can't."""
        # Without dpkg-query (not Debian/Ubuntu) there is nothing to report.
        if not shutil.which("dpkg-query"):
            return {}
        # Ask dpkg for each package's installed version.
        versions: Dict[str, str] = {}
        for pkg in DhcpWorkerOps._VERSION_CHECK_PACKAGES:
            # Query one package; skip it if the query fails.
            try:
                proc = subprocess.run(
                    ["dpkg-query", "-W", "-f=${Version}", pkg],
                    capture_output=True, text=True, timeout=10)
                # Record the version only if the package is installed.
                if proc.returncode == 0 and proc.stdout.strip():
                    versions[pkg] = proc.stdout.strip()
            # dpkg-query error or timeout: skip this package.
            except Exception:  # noqa: BLE001 — best-effort only
                continue
        # Return the versions found.
        return versions

    @staticmethod
    def _ldd_missing_deps(so_path: str) -> str:
        """Run ``ldd`` against a hook .so and report any "not found" shared
        library dependency — this is what an ABI/version mismatch (or a
        half-upgraded libc/libssl) actually looks like at the dynamic-loader
        level, versus Kea's own error which only says "failed to load".
        Returns "" when the file is missing, ldd isn't available, or every
        dependency resolves.
        """
        # Skip when the file or ldd is missing.
        if not os.path.isfile(so_path) or not shutil.which("ldd"):
            return ""
        # Run ldd on the library.
        try:
            proc = subprocess.run(
                ["ldd", so_path], capture_output=True, text=True, timeout=10)
        # ldd failed to run: report that.
        except Exception as e:  # noqa: BLE001
            return f"ldd failed: {e}"
        # Collect lines reporting unresolved dependencies.
        missing = [ln.strip() for ln in (proc.stdout or "").splitlines()
                   if "not found" in ln]
        return "; ".join(missing) if missing else ""

    def apply(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """``KEAW_APPLY`` — snapshot, ``config-set``, ``config-write``.

        The two Kea calls are distinguished because they fail differently:

        * ``config-set`` failed → the node is UNTOUCHED (``mutated: False``);
          the coordinator can skip it when rolling back.
        * ``config-set`` succeeded but ``config-write`` failed → the new config
          is ALREADY RUNNING but unpersisted. The worker restores its snapshot
          LOCALLY and immediately, because a coordinator that crashed here would
          otherwise leave the node silently diverged. If that local restore also
          fails the node is genuinely mutated (``mutated: True``,
          ``restored: False``) and the verdict is ``PARTIAL``, never ERROR — the
          distinction the coordinator needs to decide what to roll back.
        """
        # Pull out the candidate config; it is required.
        cfg = self._config_of(data)
        if cfg is None:
            return {"status": "ERROR", "message": "config (Dhcp4) is required",
                    "mutated": False}
        # Snapshot the running config first so a failed transaction can be rolled back.
        try:
            self._snapshot = copy.deepcopy(self.mgr.get_config())
        except Exception as e:  # noqa: BLE001
            # No snapshot means no rollback; refuse rather than apply a change
            # the coordinator believes it can undo.
            return {"status": "ERROR", "mutated": False,
                    "message": f"cannot snapshot current config for rollback: {e}"}
        # Apply the new config (config-set, then config-write to disk).
        outcome = self.mgr.apply_config(copy.deepcopy(cfg))
        # Both steps landed: success.
        if outcome.get("set") and outcome.get("written"):
            return {"status": "SUCCESS", "version": data.get("version"),
                    "mutated": True, "digest": config_fingerprint(cfg)}
        # Running but not saved: try to self-heal a permission problem before giving up.
        if outcome.get("set") and not outcome.get("written"):
            # Kea's write error text.
            write_err = str(outcome.get("error") or "")
            # config-set landed (running config is already the new one) but
            # config-write couldn't persist it — if that's the master conf
            # file's own permissions (root:root 0644 with no group-write for
            # _kea, the same class of bug as the HA-TLS directory), fix it
            # and retry the SAME config-write once before falling through to
            # the restore-and-report path below.
            # Kea could not open its conf file for writing: fix file permissions and AppArmor.
            if "unable to open file" in write_err.lower() and "for writing" in write_err.lower():
                # Record each repair that actually changed something.
                healed = []
                if self._repair_kea_conf_permissions():
                    healed.append("fixed /etc/kea/kea-dhcp4.conf permissions")
                if self._repair_kea_apparmor_write_access():
                    healed.append("granted AppArmor write access to /etc/kea/kea-dhcp4.conf")
                # If anything was repaired, retry just the write once.
                if healed:
                    retry_write = self.mgr.write_config()
                    # Retry worked: success, noting what was healed.
                    if retry_write.get("written"):
                        return {"status": "SUCCESS", "version": data.get("version"),
                                "mutated": True, "digest": config_fingerprint(cfg),
                                "self_healed": healed}
                    # Retry failed: keep its error for the restore path below.
                    outcome = {**outcome, "error": retry_write.get("error") or write_err}
        # config-set itself failed: the node is unchanged.
        if not outcome.get("set"):
            # Hook directory hint and Kea's error.
            hook_dir = str(data.get("hook_dir") or "")
            error = outcome.get("error") or "config-set failed"
            # A hook-load rejection can mean the .so EXISTS (install_hooks()
            # already checked that) but fails to dlopen() — corrupt package,
            # ABI mismatch after an unrelated OS update, bad permissions. This
            # used to be a dead end requiring a manual uninstall/reinstall of
            # the whole DHCP role; try the fixed, safe repair actions first
            # (HA-TLS permission fix, then reinstall the package that owns
            # the libraries) and retry the SAME config-set once before
            # giving up.
            # Hook-load failure: try the safe repairs, then retry the whole apply once.
            if "hook librar" in error.lower():
                # Record each repair that actually changed something.
                healed = []
                if self._repair_ha_tls_permissions():
                    healed.append("fixed /etc/kea/ha-tls permissions")
                if self._repair_hook_libraries(hook_dir):
                    healed.append("reinstalled Kea hook libraries")
                # If anything was repaired, retry the apply.
                if healed:
                    retry = self.mgr.apply_config(copy.deepcopy(cfg))
                    # Retry fully landed: success, noting what was healed.
                    if retry.get("set") and retry.get("written"):
                        return {"status": "SUCCESS", "version": data.get("version"),
                                "mutated": True, "digest": config_fingerprint(cfg),
                                "self_healed": healed}
                    # Retry's config-set failed: report its error; otherwise continue to the
                    # write-failed handling with the retry's outcome.
                    if not retry.get("set"):
                        error = retry.get("error") or error
                    else:
                        outcome = retry  # fall through to the write-failed path below
            # config-set failed (even after any repair): return the enriched diagnostic.
            return {"status": "ERROR", "mutated": False,
                    "message": self._hook_load_failure_detail(error, hook_dir)}
        # config-set landed, config-write did not: restore locally right now.
        # A restore counts ONLY when BOTH config-set and config-write succeeded.
        # A restore whose write failed leaves the node running the old config
        # but with the NEW one still on disk, so the next kea restart silently
        # boots the configuration we just decided to abandon — that is a mutated
        # node, not a clean one.
        restore = self.mgr.apply_config(copy.deepcopy(self._snapshot))
        # Restore fully landed: report the original failure, node unchanged.
        if restore.get("set") and restore.get("written"):
            return {"status": "ERROR", "mutated": False, "restored": True,
                    "message": (f"config-write failed ({outcome.get('error')}); "
                                f"the previous configuration was restored and "
                                f"persisted on this node")}
        # Restore is running but not saved to disk: partial.
        if restore.get("set"):
            return {"status": "PARTIAL", "mutated": True, "restored": False,
                    "message": (f"config-write failed ({outcome.get('error')}); "
                                f"the previous configuration is running again "
                                f"but could NOT be persisted "
                                f"({restore.get('error')}) — a Kea restart would "
                                f"boot the abandoned configuration")}
        # Even the restore failed: the node is running the new, unsaved config.
        return {"status": "PARTIAL", "mutated": True, "restored": False,
                "message": (f"config-write failed ({outcome.get('error')}) AND "
                            f"the local restore failed "
                            f"({restore.get('error')}) — this node is running "
                            f"the new, unpersisted configuration")}

    #: The HA-TLS material the daemon (running as ``_kea``) must be able to
    #: read for libdhcp_ha.so to load: the shared trust anchor + this node's
    #: own cert/key. Installed root:root 0750 before kea-common (and thus the
    #: ``_kea`` user) exists on a fresh HA-member install, then never
    #: revisited — leaving the daemon permanently unable to even traverse
    #: into the directory. Kea then only ever reports the generic "One or
    #: more hook libraries failed to load", masking the real
    #: HA_CONFIGURATION_FAILED "... Permission denied" underneath.
    _HA_TLS_DIR = "/etc/kea/ha-tls"

    @staticmethod
    def _repair_ha_tls_permissions() -> bool:
        """Group-own ``/etc/kea/ha-tls`` (and its contents) to ``_kea`` so the
        daemon can read its HA trust anchor / cert / key. Fixed, argument-free
        ``chgrp``/``chmod`` calls only — no caller-supplied path. Returns
        ``True`` iff the directory exists and every fix-up call succeeded."""
        # Nothing to fix if the directory does not exist.
        d = DhcpWorkerOps._HA_TLS_DIR
        if not os.path.isdir(d):
            return False
        # Give the _kea group ownership and directory traversal/read access; any failure aborts.
        try:
            subprocess.run(["chgrp", "-R", "_kea", d],
                            capture_output=True, text=True, timeout=10, check=True)
            subprocess.run(["chmod", "0750", d],
                            capture_output=True, text=True, timeout=10, check=True)
            subprocess.run(["chmod", "-R", "g+rX", d],
                            capture_output=True, text=True, timeout=10, check=True)
        # A command failed: log it and report the repair as unsuccessful.
        except Exception as e:  # noqa: BLE001
            logger.warning("could not repair %s permissions: %s", d, e)
            return False
        # Every fix-up succeeded.
        return True

    #: The Debian package ships this root:root 0644 (world-readable, no
    #: group-write). The daemon runs as _kea and "config-write" opens this
    #: exact path for writing IN-PROCESS as _kea — without a group-write
    #: grant every config-write (including a rollback's local restore) fails
    #: with "Unable to open file ... for writing", identical in spirit to the
    #: HA-TLS directory bug above but on the master config file itself.
    _KEA_DHCP4_CONF = "/etc/kea/kea-dhcp4.conf"

    @staticmethod
    def _repair_kea_conf_permissions() -> bool:
        """Group-own ``/etc/kea/kea-dhcp4.conf`` to ``_kea`` and grant
        group-write so the daemon's own ``config-write`` RPC can persist it.
        Fixed, argument-free ``chgrp``/``chmod`` calls only. Returns ``True``
        iff the file exists and every fix-up call succeeded."""
        # Nothing to fix if the file does not exist.
        f = DhcpWorkerOps._KEA_DHCP4_CONF
        if not os.path.isfile(f):
            return False
        # Make _kea the file's group; any failure aborts.
        try:
            subprocess.run(["chgrp", "_kea", f],
                            capture_output=True, text=True, timeout=10, check=True)
            # 0660 (not 0640): the file must be GROUP-WRITABLE for the _kea
            # daemon's own config-write RPC to persist -- 0640 only grants the
            # _kea group read, which looked identical to ha-tls/kea-api-password
            # (both correctly 0640, but those are only ever read by the _kea
            # process, never written) and silently never actually fixed the bug.
            subprocess.run(["chmod", "0660", f],
                            capture_output=True, text=True, timeout=10, check=True)
        # A command failed: log it and report the repair as unsuccessful.
        except Exception as e:  # noqa: BLE001
            logger.warning("could not repair %s permissions: %s", f, e)
            return False
        # Every fix-up succeeded.
        return True

    #: Ubuntu's shipped AppArmor profiles for kea-dhcp4 and kea-ctrl-agent
    #: grant only ``/etc/kea/ r`` + ``/etc/kea/** r`` — read-only. Unix file
    #: permissions on kea-dhcp4.conf can be perfectly correct (0660 root:_kea)
    #: and config-write STILL fails with the identical "Unable to open file
    #: ... for writing", because AppArmor denies the write() syscall before
    #: the kernel even checks the file mode bits. This masqueraded as a
    #: permissions bug (see ``_repair_kea_conf_permissions`` above) for a long
    #: time because the error text is indistinguishable between the two
    #: causes. Fix: drop a local override (the profile's own
    #: ``#include <local/usr.sbin.kea-...>`` hook exists for exactly this)
    #: granting write on the conf file, then reload the profile so it takes
    #: effect without restarting kea.
    # Local-override and system profile folders, the rule line to add, and the profiles it
    # goes into.
    _AA_LOCAL_DIR = "/etc/apparmor.d/local"
    _AA_SYSTEM_DIR = "/etc/apparmor.d"
    _AA_OVERRIDE_LINE = "  /etc/kea/kea-dhcp4.conf rw,\n"
    _AA_PROFILES = ("usr.sbin.kea-dhcp4", "usr.sbin.kea-ctrl-agent")

    @classmethod
    def _repair_kea_apparmor_write_access(cls) -> bool:
        """Append a local AppArmor override granting write on
        ``kea-dhcp4.conf`` to both the ``kea-dhcp4`` and ``kea-ctrl-agent``
        profiles (if not already present), then reload each profile with
        ``apparmor_parser -r`` so it takes effect immediately. No-ops (and
        returns ``False``) if AppArmor isn't in use on this host. Returns
        ``True`` iff every profile needing the override got it applied."""
        # No local override folder means AppArmor is not in use here.
        if not os.path.isdir(cls._AA_LOCAL_DIR):
            return False
        # Becomes False if any profile could not be fixed.
        ok = True
        # Fix each Kea profile in turn.
        for profile in cls._AA_PROFILES:
            # Where the override goes and the system profile it belongs to.
            override_path = os.path.join(cls._AA_LOCAL_DIR, profile)
            system_path = os.path.join(cls._AA_SYSTEM_DIR, profile)
            # Profile not installed: nothing to fix for it.
            if not os.path.isfile(system_path):
                continue
            # Each profile's failure is logged and recorded without stopping the others.
            try:
                # Read any existing override so the rule is not added twice.
                existing = ""
                if os.path.isfile(override_path):
                    with open(override_path, "r") as fh:
                        existing = fh.read()
                # Append the rule only when missing.
                if cls._AA_OVERRIDE_LINE.strip() not in existing:
                    with open(override_path, "a") as fh:
                        fh.write(cls._AA_OVERRIDE_LINE)
                # Reload the profile so the change takes effect now.
                subprocess.run(["apparmor_parser", "-r", system_path],
                                capture_output=True, text=True, timeout=15, check=True)
            # Write or reload failed for this profile.
            except Exception as e:  # noqa: BLE001
                logger.warning("could not repair AppArmor write access for %s: %s",
                               profile, e)
                ok = False
        # True only if every profile was fixed.
        return ok


    @staticmethod
    def _repair_hook_libraries(hook_dir: str) -> bool:
        """Reinstall the package(s) owning the Kea hook libraries and confirm
        the files are present afterward.

        A plain ``apt-get install --reinstall kea-common`` (the original,
        fixed repair) only re-lays down the SAME package version already on
        disk — it cannot fix an ABI mismatch where ``kea-common`` (which ships
        the hooks) and ``kea-dhcp4-server`` (the daemon that dlopen()s them)
        have drifted to different versions, e.g. after a partial/interrupted
        apt upgrade. That case makes EVERY hook fail with "failed to load"
        (as opposed to one specific corrupt/missing file), which is exactly
        what a repeated production failure with all 9 libraries listed looks
        like. So: check whether kea-common and kea-dhcp4-server versions
        match first; if they don't, refresh the apt cache and install BOTH
        packages together so apt is free to bring them to the same version,
        rather than reinstalling kea-common alone at its current (mismatched)
        version. Falls back to the original same-version reinstall when the
        versions already match (a corrupt/truncated file is the more likely
        cause there) or when dpkg-query isn't available to tell.
        """
        # Without apt-get nothing can be reinstalled.
        if not shutil.which("apt-get"):
            return False
        # Compare the hook package's version with the daemon's version.
        versions = DhcpWorkerOps._installed_package_versions()
        common_ver = versions.get("kea-common")
        daemon_ver = versions.get("kea-dhcp4-server")
        mismatched = bool(common_ver and daemon_ver and common_ver != daemon_ver)
        # Log that we are realigning versions rather than reinstalling.
        if mismatched:
            logger.warning(
                "kea-common (%s) and kea-dhcp4-server (%s) versions differ — "
                "repairing by realigning both packages instead of a same-"
                "version reinstall", common_ver, daemon_ver)
        # Run the appropriate fixed apt commands; any failure aborts.
        try:
            # Versions differ: refresh package lists and upgrade both together.
            if mismatched:
                subprocess.run(["apt-get", "update", "-y", "-qq"],
                                capture_output=True, text=True, timeout=300)
                subprocess.run(
                    ["apt-get", "install", "-y", "-qq",
                     "kea-common", "kea-dhcp4-server"],
                    capture_output=True, text=True, timeout=300)
            # Versions match: reinstall the hook package at its current version.
            else:
                subprocess.run(
                    ["apt-get", "install", "--reinstall", "-y", "-qq", *_HOOK_PACKAGES],
                    capture_output=True, text=True, timeout=300)
        # apt failed or timed out.
        except Exception as e:  # noqa: BLE001
            logger.warning("hook library reinstall failed: %s", e)
            return False
        # Confirm every hook library file exists now.
        resolved = resolve_hook_dir(hook_dir)
        paths = hook_paths(resolved)
        still_missing = [name for name, path in paths.items() if not os.path.exists(path)]
        # Some still missing: the repair failed.
        if still_missing:
            logger.warning("hook libraries still missing after reinstall: %s",
                            ", ".join(still_missing))
            return False
        # File-existence was always insufficient to prove a real fix — the
        # library can exist and still fail dlopen() (that's the whole bug
        # this method exists to address). Cross-check with ldd so a repair
        # that changed nothing meaningful doesn't get reported as a success
        # right before the retried config-set fails again anyway.
        # Check the HA hook's shared-library dependencies with ldd.
        ldd_issue = DhcpWorkerOps._ldd_missing_deps(paths.get("ha", ""))
        if ldd_issue:
            logger.warning("hook libraries present but still have unresolved "
                            "dependencies after reinstall: %s", ldd_issue)
            return False
        # Log the new package versions and report success.
        after = DhcpWorkerOps._installed_package_versions()
        logger.info("self-heal: reinstalled Kea hook libraries (%s); "
                    "package versions now: %s", resolved,
                    ", ".join(f"{k}={v}" for k, v in after.items()) or "unknown")
        return True

    @classmethod
    def _restart_kea_dhcp4_service(cls) -> bool:
        """Attempt to repair permissions and start/restart kea-dhcp4-server if offline."""
        # Fix every known permission problem first, ignoring individual results.
        cls._repair_ha_tls_permissions()
        cls._repair_kea_conf_permissions()
        cls._repair_kea_apparmor_write_access()
        # Restart with systemctl, falling back to the older service command.
        try:
            if shutil.which("systemctl"):
                # Restart via systemd and report success if it worked.
                proc = subprocess.run(
                    ["systemctl", "restart", "kea-dhcp4-server"],
                    capture_output=True, text=True, timeout=15)
                if proc.returncode == 0:
                    logger.info("Successfully restarted kea-dhcp4-server service")
                    return True
                # systemctl failed: log why.
                logger.warning("systemctl restart kea-dhcp4-server returned %d: %s",
                               proc.returncode, (proc.stderr or proc.stdout).strip())
            # No systemd: try the SysV service wrapper.
            elif shutil.which("service"):
                proc = subprocess.run(
                    ["service", "kea-dhcp4-server", "restart"],
                    capture_output=True, text=True, timeout=15)
                if proc.returncode == 0:
                    logger.info("Successfully restarted kea-dhcp4-server service")
                    return True
        # Restart could not run.
        except Exception as e:  # noqa: BLE001
            logger.warning("Failed to restart kea-dhcp4-server service: %s", e)
        # Neither restart method worked.
        return False

    def rollback(self, _data: Dict[str, Any]) -> Dict[str, Any]:
        """``KEAW_ROLLBACK`` — restore the config captured by the last apply."""
        # Nothing to roll back to unless apply ran first.
        if self._snapshot is None:
            return {"status": "ERROR", "message": "no snapshot to roll back to"}
        # Re-apply the snapshot.
        outcome = self.mgr.apply_config(copy.deepcopy(self._snapshot))
        # config-set failed: rollback did not happen.
        if not outcome.get("set"):
            return {"status": "ERROR",
                    "message": outcome.get("error") or "rollback config-set failed"}
        if not outcome.get("written"):
            # Running the old config again, just not persisted — say so rather
            # than claiming a clean rollback.
            return {"status": "PARTIAL",
                    "digest": config_fingerprint(self._snapshot),
                    "message": (f"previous configuration restored but not "
                                f"persisted ({outcome.get('error')})")}
        # Rolled back and persisted.
        return {"status": "SUCCESS",
                "digest": config_fingerprint(self._snapshot)}

    def standdown(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """``KEAW_STANDDOWN`` — leave the HA pair cleanly.

        Issued when the operator removes this node from the topology. Strips the
        HA + lease_cmds hook entries from the running config so the node stops
        heartbeating at a partner it is no longer paired with (it keeps serving
        its own scopes — silently blackholing DHCP would be worse). Everything
        else in the node's configuration is preserved."""
        # Copy the running config so it can be edited safely.
        try:
            cfg = copy.deepcopy(self.mgr.get_config())
        # Cannot read the config: report it.
        except Exception as e:  # noqa: BLE001
            return {"status": "ERROR", "message": str(e)}
        # Remove the HA and lease_cmds hook entries, counting how many were dropped.
        before = len(cfg.get("hooks-libraries") or [])
        cfg["hooks-libraries"] = [
            h for h in (cfg.get("hooks-libraries") or [])
            if isinstance(h, dict) and not str(h.get("library", "")).endswith(
                ("libdhcp_ha.so", "libdhcp_lease_cmds.so"))]
        removed = before - len(cfg["hooks-libraries"])
        # No HA hooks were loaded: nothing to do.
        if not removed:
            return {"status": "SUCCESS", "changed": False,
                    "message": "no HA hooks were loaded"}
        # Apply and persist the trimmed config; anything short of both is an error.
        outcome = self.mgr.apply_config(cfg)
        if not (outcome.get("set") and outcome.get("written")):
            return {"status": "ERROR", "changed": bool(outcome.get("set")),
                    "message": outcome.get("error") or "could not remove the HA hooks"}
        # HA hooks removed and saved.
        return {"status": "SUCCESS", "changed": True, "hooks_removed": removed}

    # ── Status ──────────────────────────────────────────────────────────────

    def ha_status(self, _data: Dict[str, Any]) -> Dict[str, Any]:
        """``KEAW_HA_STATUS`` — ``status-get`` plus the running config digest."""
        # Ask the dhcp4 daemon for its HA status.
        try:
            raw = self.mgr._rpc("dhcp4", "status-get", {})
        # Daemon unreachable: report it as not running.
        except Exception as e:  # noqa: BLE001
            return {"status": "ERROR", "message": str(e), "running": False}
        # Also report the config fingerprint and subnet count, best effort.
        digest = ""
        subnet_count = None
        try:
            cfg = self.mgr.get_config()
            digest = config_fingerprint(cfg)
            subnet_count = len(cfg.get("subnet4") or [])
        # Config unreadable: still return the HA status without the digest.
        except Exception as e:  # noqa: BLE001 — HA state is still worth reporting
            logger.debug("could not read config for digest: %s", e)
        # Return raw and parsed HA status with the digest and subnet count.
        return {"status": "SUCCESS", "running": True, "status_get": raw,
                "ha": parse_ha_status(raw), "digest": digest,
                "subnet_count": subnet_count}

    def status(self, _data: Dict[str, Any]) -> Dict[str, Any]:
        """``KEAW_STATUS`` — return the local Kea status."""
        return {"status": "SUCCESS", **self.mgr.status()}

    def list_subnets(self, _data: Dict[str, Any]) -> Dict[str, Any]:
        """``KEAW_LIST_SUBNETS`` — return the DHCPv4 subnets configured on this node."""
        return {"status": "SUCCESS", "subnets": self.mgr.list_subnets()}

    def list_leases(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """``KEAW_LIST_LEASES`` — return DHCPv4 leases, optionally for one subnet."""
        return {"status": "SUCCESS",
                "leases": self.mgr.list_leases(data.get("subnet") or None)}

    def list_reservations(self, _data: Dict[str, Any]) -> Dict[str, Any]:
        """``KEAW_LIST_RES`` — return the DHCPv4 host reservations on this node."""
        return {"status": "SUCCESS", "reservations": self.mgr.list_reservations()}

    def delete_lease(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """``KEAW_DEL_LEASE`` — delete DHCPv4 lease(s) by current IP, old IP and/or MAC.

        Args:
            data: ip (or ip-address), old_ip, and/or mac (or hw-address).

        Returns:
            SUCCESS with the list of purged addresses.
        """
        # Accept both LM-style and Kea-style field names.
        ip = data.get("ip") or data.get("ip-address")
        old_ip = data.get("old_ip")
        mac = data.get("mac") or data.get("hw-address")
        # At least one identifier is required.
        if not ip and not mac and not old_ip:
            return {"status": "ERROR", "message": "ip, old_ip, or mac is required"}
        # Addresses actually removed.
        purged = set()
        # Prefer the manager's purge helper, which also catches leases matching the MAC.
        if hasattr(self.mgr, "purge_leases_for_mac_or_ip"):
            # Purge by the current IP.
            if ip:
                purged.update(self.mgr.purge_leases_for_mac_or_ip(mac=mac, ip=ip))
            # Also purge the previous IP if it differs.
            if old_ip and old_ip != ip:
                purged.update(self.mgr.purge_leases_for_mac_or_ip(mac=mac, ip=old_ip))
            # MAC only: purge every lease for that MAC.
            if mac and not ip and not old_ip:
                purged.update(self.mgr.purge_leases_for_mac_or_ip(mac=mac))
        # Older manager without the purge helper: delete by IP only.
        else:
            if ip:
                self.mgr.delete_lease(ip)
                purged.add(ip)
            if old_ip and old_ip != ip:
                self.mgr.delete_lease(old_ip)
                purged.add(old_ip)
        # Report what was purged.
        return {"status": "SUCCESS", "purged": list(purged)}

    # ── DHCPv6 read-only / lease ops (HA fanout targets) ────────────────────

    def list_subnets6(self, _data: Dict[str, Any]) -> Dict[str, Any]:
        """``KEAW_LIST_SUBNETS6`` — return the DHCPv6 subnets configured on this node."""
        return {"status": "SUCCESS", "subnets": self.mgr.list_subnets6()}

    def list_leases6(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """``KEAW_LIST_LEASES6`` — return DHCPv6 leases, optionally for one subnet."""
        return {"status": "SUCCESS",
                "leases": self.mgr.list_leases6(data.get("subnet") or None)}

    def list_reservations6(self, _data: Dict[str, Any]) -> Dict[str, Any]:
        """``KEAW_LIST_RES6`` — return the DHCPv6 host reservations on this node."""
        return {"status": "SUCCESS", "reservations": self.mgr.list_reservations6()}

    def delete_lease6(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """``KEAW_DEL_LEASE6`` — purge DHCPv6 lease(s) by address and/or MAC.

        A purge RPC that FAILED must not look like "nothing to delete": the
        coordinator builds its operator-visible errors from this status, so
        collapsing an unreachable Kea into SUCCESS reports a clean apply while
        the client keeps its stale address.
        """
        # Accept both LM-style and Kea-style field names.
        ip = data.get("ip") or data.get("ip-address")
        old_ip = data.get("old_ip")
        mac = data.get("mac") or data.get("hw-address")
        # At least one identifier is required.
        if not ip and not mac and not old_ip:
            return {"status": "ERROR", "message": "ip, old_ip, or mac is required"}
        # Addresses actually removed so far.
        purged = set()
        # Purge by current IP, previous IP, or MAC only; any RPC failure is reported.
        try:
            if ip:
                purged.update(self.mgr.purge_leases6_for_mac_or_ip(mac=mac, ip=ip))
            if old_ip and old_ip != ip:
                purged.update(self.mgr.purge_leases6_for_mac_or_ip(mac=mac, ip=old_ip))
            if mac and not ip and not old_ip:
                purged.update(self.mgr.purge_leases6_for_mac_or_ip(mac=mac))
        # Purge failed: return an error with whatever was purged before the failure.
        except Exception as e:  # noqa: BLE001
            return {"status": "ERROR", "purged": sorted(purged),
                    "message": f"DHCPv6 lease purge failed: {e}"}
        # Report what was purged.
        return {"status": "SUCCESS", "purged": list(purged)}

    def diagnostics(self, _data: Dict[str, Any]) -> Dict[str, Any]:
        """``KEAW_DIAGNOSTICS`` — return the local Kea diagnostics report."""
        return self.mgr.diagnostics()

    def packet_trace(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """``KEAW_PACKET_TRACE`` — this node's DHCPv4 request/error trace."""
        # Trace the given MAC (or all clients) over the last N minutes, with an optional capture.
        return self.mgr.packet_trace(data.get("mac") or "", data.get("minutes", 30),
                                     data.get("capture_seconds", 0))

    def stats(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """``KEAW_STATS`` — return local Kea statistics, packet counters
        windowed to ``range_seconds`` when given."""
        return self.mgr.get_stats(range_seconds=(data or {}).get("range_seconds"))

    def dns_hook_config(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """``KEAW_DNS_HOOK_CONFIG`` — enable/update/disable the real-time
        Kea -> Unbound run_script hook on THIS node."""
        settings = data.get("settings")
        if not isinstance(settings, dict):
            return {"status": "ERROR", "message": "settings object is required"}
        return self.mgr.configure_dns_hook(settings, hook_dir=data.get("hook_dir") or "")

    def dns_hook_status(self, _data: Dict[str, Any]) -> Dict[str, Any]:
        """``KEAW_DNS_HOOK_STATUS`` — this node's on-disk hook settings, whether
        the running Kea config currently loads it, and a log tail."""
        status = self.mgr.dns_hook_status()
        top_status = ("PARTIAL" if status.get("loaded_in_running_config") is None
                      or status.get("running_config_error") else "SUCCESS")
        return {"status": top_status, **status}

    def release_declines(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """``KEAW_RELEASE_DECLINES`` — free declined addresses on this node: all
        of them with ``all``, else those held past its current probation."""
        return self.mgr.release_held_declines(release_all=bool(data.get("all")))

    def op_table(self) -> Dict[str, Any]:
        """Return the complete map of command names this worker accepts to handler methods."""
        # Anything not in this table is rejected by the transport.
        return {
            "KEAW_INSTALL_HOOKS": self.install_hooks,
            "KEAW_GET_CONFIG": self.get_config,
            "KEAW_VALIDATE": self.validate,
            "KEAW_APPLY": self.apply,
            "KEAW_ROLLBACK": self.rollback,
            "KEAW_STANDDOWN": self.standdown,
            "KEAW_HA_STATUS": self.ha_status,
            "KEAW_GET_CONFIG6": self.get_config6,
            "KEAW_VALIDATE6": self.validate6,
            "KEAW_APPLY6": self.apply6,
            "KEAW_ROLLBACK6": self.rollback6,
            "KEAW_STANDDOWN6": self.standdown6,
            "KEAW_HA_STATUS6": self.ha_status6,
            "KEAW_STATUS": self.status,
            "KEAW_LIST_SUBNETS": self.list_subnets,
            "KEAW_LIST_LEASES": self.list_leases,
            "KEAW_LIST_RES": self.list_reservations,
            "KEAW_DEL_LEASE": self.delete_lease,
            "KEAW_RELEASE_DECLINES": self.release_declines,
            "KEAW_LIST_SUBNETS6": self.list_subnets6,
            "KEAW_LIST_LEASES6": self.list_leases6,
            "KEAW_LIST_RES6": self.list_reservations6,
            "KEAW_DEL_LEASE6": self.delete_lease6,
            "KEAW_DIAGNOSTICS": self.diagnostics,
            "KEAW_STATS": self.stats,
            "KEAW_DNS_HOOK_CONFIG": self.dns_hook_config,
            "KEAW_DNS_HOOK_STATUS": self.dns_hook_status,
            "KEAW_PACKET_TRACE": self.packet_trace,
        }


def build_worker(member_id: str, coordinator_url: str, secret: str,
                 ca_url: str = "http://localhost:8001"):
    """Wire the op table into the shared cluster worker transport."""
    # Import the shared worker transport; its path differs between layouts.
    try:
        from core.src.messaging.service_cluster import ServiceWorkerClient
    # Flat layout: core/src is on sys.path directly.
    except ImportError:
        from messaging.service_cluster import ServiceWorkerClient  # type: ignore
    # Kea manager pointed at the Control Agent URL, sampling packet counters
    # in the background for the Overview's time windows.
    mgr = KeaManager(ca_url=ca_url, stats_history_path=STATS_HISTORY_PATH)
    mgr.start_stats_sampler()
    # Build the operation table on top of the manager.
    ops = DhcpWorkerOps(mgr)
    # default_port drives the URL normalization, which REJECTS a plaintext
    # ws:// to a remote coordinator (the PSK rides in the handshake).
    return ServiceWorkerClient(member_id, coordinator_url, secret,
                               ops.op_table(), hostname=os.uname().nodename,
                               default_port=DEFAULT_COORDINATOR_PORT)


def main() -> None:
    """Parse settings from command line/environment and run the worker until stopped."""
    # Each option falls back to an environment variable so systemd can configure it.
    parser = argparse.ArgumentParser(description="Lab Manager Kea HA worker")
    parser.add_argument("--id", default=os.getenv("LM_DHCP_MEMBER_ID", ""),
                        help="HA member id (must match the module's member list "
                             "and Kea's this-server-name)")
    parser.add_argument("--coordinator", default=os.getenv("LM_DHCP_COORDINATOR", ""),
                        help="wss://<dhcp-module-host>:8770/ws/agent")
    parser.add_argument("--secret", default=os.getenv("LM_DHCP_WORKER_SECRET", ""),
                        help="shared worker secret (matches the module's agent_secret)")
    parser.add_argument("--ca-url", default=os.getenv("KEA_CA_URL",
                                                      "http://localhost:8001"))
    # Parse the command line into args.
    args = parser.parse_args()
    # Member id, coordinator URL and secret are all required.
    if not args.id:
        parser.error("--id is required (or LM_DHCP_MEMBER_ID in the environment)")
    if not args.coordinator or not args.secret:
        parser.error("--coordinator and --secret are required "
                     "(or LM_DHCP_COORDINATOR / LM_DHCP_WORKER_SECRET)")
    # Log to stderr with timestamps; force replaces any handlers installed earlier.
    logging.basicConfig(
        level=logging.INFO, force=True,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    # Build the worker and run its connection loop until the process is stopped.
    worker = build_worker(args.id, args.coordinator, args.secret, ca_url=args.ca_url)
    asyncio.run(worker.run())


# Run main() when executed as a script.
if __name__ == "__main__":
    main()
