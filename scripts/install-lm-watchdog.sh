#!/bin/bash
# install-lm-watchdog.sh — deploy the Lab Manager hub AUTO-HEAL watchdog.
#
# Idempotent. Run as root ON THE HUB BOX:
#     sudo bash install-lm-watchdog.sh
#
# WHY THIS EXISTS — the hub's lm.service can NOT self-heal two failure modes,
# both of which we hit in production (WebUI dead, only a reboot recovered):
#
#   (1) WEDGED EVENT LOOP — the python process is still "active" (systemd sees a
#       live PID) so `Restart=on-failure` never fires, but the asyncio loop is
#       stuck and :443 stops serving. A hung loop also ignores the graceful
#       SIGTERM, so `systemctl restart lm` HANGS. Worse, on the legacy
#       `Type=oneshot` + start_all.sh unit the hub is `nohup … main.py &`
#       DETACHED (MainPID=0) — systemd can't cycle a process it never tracked.
#       Only an external force-restart (SIGKILL + free the port) recovers it.
#
#   (2) LEGACY generic-agent ZOMBIE (lm-bootstrap / lm-generic-agent) — the hub
#       DETECTS it (_detect_legacy_leaf → update-health warning) but runs as the
#       svc_lm user and can't remove a systemd unit. Detection without root =
#       the warning never clears.
#
# This watchdog runs as ROOT from its OWN systemd unit (outside lm.service's
# cgroup), so it can force-restart a wedged hub and purge the zombie. It is the
# runtime safety net; the PERMANENT fix for (1) is re-running install_all.sh,
# which rebuilds lm.service as Type=exec (direct ExecStart=main.py) so a normal
# `systemctl restart` cycles the hub cleanly.
#
# KEEP THE lm-watchdog BODY IN SYNC WITH the copy embedded in install_all.sh.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "ERROR: run as root — sudo bash $0" >&2; exit 1; }

install -d -m 0755 /var/log/lm /var/lib/lm

# ── the watchdog itself ─────────────────────────────────────────────────────
cat > /usr/local/bin/lm-watchdog <<'WD'
#!/bin/bash
# Lab Manager hub auto-heal. Installed by install-lm-watchdog.sh / install_all.sh.
# Runs every 60s as root via lm-watchdog.timer, OUTSIDE lm.service's cgroup.
set -uo pipefail
MAX_FAILS="${LM_WATCHDOG_MAX_FAILS:-3}"   # consecutive bad probes before force-restart
STATE=/var/lib/lm/watchdog-fails
LOG=/var/log/lm/watchdog.log
log(){ printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >> "$LOG" 2>/dev/null; }

# Probe /status across every scheme/port the hub may serve on (mirrors the
# install_all.sh recovery probe). 0 = a 200 was seen somewhere.
hub_healthy(){
  local url code
  for url in "https://127.0.0.1:443/status" "http://127.0.0.1:443/status" "http://127.0.0.1:8000/status"; do
    code=$(curl -sk -m 8 -o /dev/null -w '%{http_code}' "$url" 2>/dev/null || echo 000)
    [ "$code" = 200 ] && return 0
  done
  return 1
}

# ── 1. Hub liveness ─────────────────────────────────────────────────────────
if systemctl is-enabled --quiet lm.service 2>/dev/null; then
  state=$(systemctl is-active lm.service 2>/dev/null || echo unknown)
  case "$state" in
    active)
      if hub_healthy; then
        [ -f "$STATE" ] && { rm -f "$STATE"; log "hub healthy again"; } || true
      else
        fails=$(( $(cat "$STATE" 2>/dev/null || echo 0) + 1 ))
        echo "$fails" > "$STATE"
        log "hub unresponsive: unit active but /status not 200 (strike $fails/$MAX_FAILS)"
        if [ "$fails" -ge "$MAX_FAILS" ]; then
          log "FORCE-RESTART: SIGKILL wedged hub + free :443/:8000, then restart"
          systemctl kill -s KILL lm.service 2>/dev/null || true
          if command -v fuser >/dev/null 2>&1; then
            fuser -k -9 443/tcp 8000/tcp 2>/dev/null || true
          fi
          sleep 2
          # `timeout` guards against a restart that itself hangs on a legacy
          # detached unit; the hub is already dead so stop completes instantly.
          timeout 60 systemctl restart lm.service 2>/dev/null \
            || timeout 30 systemctl start lm.service 2>/dev/null || true
          rm -f "$STATE"
          log "hub restart issued"
        fi
      fi
      ;;
    failed)
      # systemd gave up after hitting the start limit — clear the latch + start.
      log "lm.service FAILED (start-limit) — reset-failed + start"
      systemctl reset-failed lm.service 2>/dev/null || true
      timeout 30 systemctl start lm.service 2>/dev/null || true
      rm -f "$STATE"
      ;;
    *)
      # activating / deactivating / inactive — systemd is already handling it.
      rm -f "$STATE"
      ;;
  esac
fi

# ── 1a. PULL: keep /opt/lm current from GitHub ──────────────────────────────
# The in-process repo_sync loop has proven unreliable (dies after a cycle), so
# the external watchdog is the authoritative PULLER too: fetch origin/main and
# hard-align (also self-heals a conflicted/half-rebased checkout). The pull runs
# ANY time — harmless, the hub keeps serving old code — while the RESTART into it
# stays gated by 1b's window/idle check. Runs as svc_lm to preserve /opt/lm
# ownership; offline fetch failures are non-fatal.
if [ -d /opt/lm/.git ]; then
  runuser -u svc_lm -- git -C /opt/lm fetch --quiet origin main 2>/dev/null || true
  lc=$(runuser -u svc_lm -- git -C /opt/lm rev-parse HEAD 2>/dev/null || true)
  rc=$(runuser -u svc_lm -- git -C /opt/lm rev-parse origin/main 2>/dev/null || true)
  if [ -n "$lc" ] && [ -n "$rc" ] && [ "$lc" != "$rc" ]; then
    log "pull: /opt/lm behind (local ${lc:0:7} -> remote ${rc:0:7}) — hard-align to origin/main"
    runuser -u svc_lm -- git -C /opt/lm reset --hard origin/main 2>/dev/null || true
  fi
fi

# ── 1b. STALE hub: pulled new code but the running process never restarted ──
# The in-process self-restart (lm-update-restart) can silently fail to fire from
# the daemon (child not detached / cgroup teardown), leaving the hub serving OLD
# code after a git pull. The hub is "active" and /status is 200, so section 1
# never triggers. Detect it externally and do a PROVEN `systemctl restart lm`.
# Two independent signals (either one triggers):
#   (a) sentinel  — the hub drops /var/lib/lm/state/stale-restart-requested when
#                   its update-health sees running-version != on-disk VERSION.
#   (b) drift     — running version (last "unified surface" startup log line) vs
#                   on-disk /opt/lm/VERSION. Fully external; bootstraps a stale
#                   hub even before the sentinel code is loaded.
# The fresh process boots current, so neither signal recurs → no restart loop.
# Guarded on hub health + a 2-min cooldown so it can never hot-loop.
STALE_SENTINEL=/var/lib/lm/state/stale-restart-requested
STALE_TS=/var/lib/lm/watchdog-stale-ts          # cooldown between restarts
RESTART_ALLOWED=/var/lib/lm/state/restart-allowed  # hub-computed gate (no longer used to gate STALE-restart — staleness always restarts; kept for a future planned-restart path)
is_force=0; stale_reason=""
if [ -f "$STALE_SENTINEL" ]; then
  body=$(head -c 100 "$STALE_SENTINEL" 2>/dev/null | tr -d '\n')
  case "$body" in "force "*) is_force=1 ;; esac      # footer Update button = force
  stale_reason="sentinel: $body"
elif [ -d /opt/lm/.git ]; then
  disk_ver=$(tr -d '[:space:]' < /opt/lm/VERSION 2>/dev/null || true)
  # Running version: the file the hub publishes at startup (robust). Fall back to
  # the 'unified surface' startup line across hub.log AND the rotated hub.log.1
  # (log-parse alone missed a stale hub whose startup line had rotated out).
  run_ver=$(tr -d '[:space:]' < /var/lib/lm/state/running-version 2>/dev/null || true)
  [ -z "$run_ver" ] && run_ver=$(grep -haoE "Hub [^ ]+ unified surface" /var/log/lm/hub.log /var/log/lm/hub.log.1 2>/dev/null | tail -1 | awk '{print $2}')
  if [ -n "$disk_ver" ] && [ -n "$run_ver" ] && [ "$disk_ver" != "$run_ver" ]; then
    stale_reason="version drift: running $run_ver vs on-disk $disk_ver"
  fi
fi
if [ -n "$stale_reason" ] && systemctl is-active --quiet lm.service 2>/dev/null && hub_healthy; then
  now=$(date +%s); last=$(cat "$STALE_TS" 2>/dev/null || echo 0)
  # Staleness is an ERROR state (the running process is serving old/buggy code),
  # NOT planned maintenance — restart immediately, day or night. The
  # maintenance-window / idle gate (RESTART_ALLOWED, hub-computed) is for
  # PLANNED pull-and-restart only; it does NOT apply here. Before this change a
  # stale hub sat UNLOADED until the 02:00 window — a fixed bug kept running for
  # hours because the restart was gated while users were logged in. The 120s
  # cooldown + the hub_healthy + is-active guards above prevent a hot-loop; the
  # fresh process boots current (run_v == disk_v) so neither signal recurs.
  # $is_force only labels the path (force sentinel from the hub's
  # check_update_health vs the external drift backstop) — both restart now.
  if [ $(( now - last )) -ge 120 ]; then
    echo "$now" > "$STALE_TS"
    [ "$is_force" = 1 ] && fx=" [FORCE]" || fx=""
    log "STALE hub ($stale_reason)$fx — clean restart to load on-disk code"
    rm -f "$STALE_SENTINEL"
    timeout 60 systemctl restart lm.service 2>/dev/null || true
    log "stale restart issued"
  fi
fi

# ── heartbeat: prove the watchdog is alive to the hub → WebUI ────────────────
printf '%s armed\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > /var/lib/lm/watchdog-status 2>/dev/null || true

# ── 2. Retire the legacy generic-agent zombie (root remediation) ────────────
# Mirrors install_all.sh retire_legacy_leaf. The hub detects but can't remove.
names="lm-generic-agent lm-bootstrap"
for f in /etc/systemd/system/*.service /run/systemd/system/*.service \
         /lib/systemd/system/*.service /usr/lib/systemd/system/*.service; do
  [ -e "$f" ] || continue
  grep -qE "/opt/lm/generic-agent" "$f" 2>/dev/null && names="$names $(basename "$f" .service)"
done
purged=0
for svc in $(printf '%s\n' $names | sort -u); do
  [ -n "$svc" ] || continue
  [ "$svc" = lm ] && continue                       # never touch the hub's own unit
  if [ -e "/etc/systemd/system/${svc}.service" ] \
     || systemctl list-unit-files "${svc}.service" 2>/dev/null | grep -qE "^${svc}\.service"; then
    systemctl stop "$svc" 2>/dev/null || true
    systemctl disable "$svc" 2>/dev/null || true
    rm -f "/etc/systemd/system/${svc}.service"
    systemctl reset-failed "$svc" 2>/dev/null || true
    log "purged legacy zombie unit ${svc}.service"
    purged=1
  fi
done
if [ -d /opt/lm/generic-agent ] || [ -d /opt/lm/generic_agent ]; then
  pkill -f "/opt/lm/generic-agent/src/agent.py" 2>/dev/null || true
  rm -rf /opt/lm/generic-agent /opt/lm/generic_agent
  log "removed legacy /opt/lm/generic-agent"
  purged=1
fi
[ "$purged" = 1 ] && systemctl daemon-reload 2>/dev/null || true
exit 0
WD
chmod 0755 /usr/local/bin/lm-watchdog
chown root:root /usr/local/bin/lm-watchdog

# ── systemd units: a oneshot + a 60s timer ──────────────────────────────────
cat > /etc/systemd/system/lm-watchdog.service <<'SVC'
[Unit]
Description=Lab Manager hub auto-heal watchdog (force-restart wedged hub + purge zombie)
After=network.target
[Service]
Type=oneshot
ExecStart=/usr/local/bin/lm-watchdog
SVC

cat > /etc/systemd/system/lm-watchdog.timer <<'TMR'
[Unit]
Description=Run the Lab Manager hub watchdog every 60s
[Timer]
OnBootSec=120
OnUnitActiveSec=60
AccuracySec=10
[Install]
WantedBy=timers.target
TMR

systemctl daemon-reload
systemctl enable --now lm-watchdog.timer

echo "✅ lm-watchdog installed and armed."
systemctl --no-pager status lm-watchdog.timer 2>/dev/null | head -4 || true
echo "   log:      /var/log/lm/watchdog.log"
echo "   run now:  sudo systemctl start lm-watchdog.service"
echo "   tune:     LM_WATCHDOG_MAX_FAILS (default 3 → ~3 min of downtime before force-restart)"
