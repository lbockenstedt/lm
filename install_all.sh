#!/bin/bash
# -u: treat unset vars as errors (catches typos in path/flag refs that would
#   otherwise silently expand to empty and mis-install).
# -o pipefail: a failed stage in a pipeline (e.g. `git ... | jq`) now surfaces
#   as a non-zero exit instead of being masked by the last stage's success, so
#   partial failures are visible in /var/log/lm/install.log instead of silent.
set -euo pipefail

# ------------------------------------------------------------------
# Argument Parsing
# ------------------------------------------------------------------
REINSTALL=false
RESET_SECRETS=false
RESET_USERS=false
EXCLUDE=()
# TLS cert verification is OFF by default (self-signed hub cert → encrypt
# without authenticating; the lab default). Pass --tls-verify to make
# co-located spokes/agents verify the hub cert against a CA. With no
# --tls-ca-cert, the hub's own generated cert ($TLS_CERT) is used as the CA
# (works because co-located clients share the box). Supply --tls-ca-cert
# <path> to verify against a different CA. The env values are resolved below
# (after $TLS_CERT is defined) and written into .env + the unit.
TLS_VERIFY=false
TLS_CA_CERT=""

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --reinstall)     REINSTALL=true ;;
        --reset-secrets) RESET_SECRETS=true ;;
        --reset-users)   RESET_USERS=true ;;
        --exclude)       shift; IFS=',' read -ra EXCLUDE <<< "$1" ;;
        --tls-verify)    TLS_VERIFY=true ;;
        --tls-ca-cert)   shift; TLS_CA_CERT="$1" ;;
        *) echo "Unknown argument: $1"; exit 1 ;;
    esac
    shift
done

# ------------------------------------------------------------------
# Path Configuration & Logging
# ------------------------------------------------------------------
BASE_DIR="/opt/lm"
OLD_BASE_DIR="/opt/lm-manager"
SvcUser="svc_lm"
LOG_DIR="/var/log/lm"
INSTALL_LOG="$LOG_DIR/install.log"

# Create log directory early so logging helpers can work
mkdir -p "$LOG_DIR"
chown -R root:root "$LOG_DIR" # Temporary root ownership for installer
chmod 755 "$LOG_DIR"

# Logging Helpers
log() {
    # Standard info log: only to file
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] INFO: $1" >> "$INSTALL_LOG" 2>/dev/null || true
}

log_c() {
    # Console and file: for high-level progress
    echo "$1"
    log "$1"
}

log_e() {
    # Error log: console and file
    echo "❌ $1" >&2
    log "ERROR: $1"
}

log_w() {
    # Warning: console + file, but NOT logged as ERROR — keeps expected/soft
    # conditions (e.g. a pre-approval that will be done manually) out of the
    # hub's Error Log / BugFixer, which key off the "error" token.
    echo "⚠️  $1" >&2
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1" >> "$INSTALL_LOG" 2>/dev/null || true
}

# Probe the hub /status endpoint across every port/scheme the hub may be on:
#   - https://localhost:443  (unified wss hub, TLS on — the new default)
#   - http://localhost:443   (unified plaintext hub, no cert)
#   - http://localhost:8000  (legacy hub OR the LM_TLS_PORT=8000 boot probe)
# Returns 0 (and sets $? 0) as soon as any one answers 200. Used by the
# boot/rollback health checks so a rolled-back pre-unified hub (8000) AND the
# unified 443 hub are both detected without knowing which is running.
_status_200() {
    local url code
    for url in "https://localhost:443/status" "http://localhost:443/status" "http://localhost:8000/status"; do
        code="$(curl -sk -o /dev/null -w '%{http_code}' --max-time 3 "$url" 2>/dev/null || echo 000)"
        [ "$code" = "200" ] && return 0
    done
    return 1
}

# ------------------------------------------------------------------
# Update recovery helpers (manual path) — THIN WRAPPERS over the Python
# entrypoint core/src/update_recovery.py, which is the SINGLE SOURCE OF TRUTH
# for the on-disk recovery state machine (snapshot cp, pending/bad-version/
# failed JSON writes, prune). Same paths + formats as the auto path; all state
# lives under /var/lib/lm/state (svc_lm-writable).
#
#   update-backup/<ts>/{src,WebUI}   pre-swap code snapshot
#   pending_update.json              {backup_dir,from_version,to_version,ts}
#   bad_versions.json                {"versions": [...]}  (skip re-pull these)
#   update_failed.json               double-failure marker for manual recovery
#
# The Python CLI (``python3 update_recovery.py {snapshot,rollback,markbad,
# clearpending,writefailed,prune}``) is invoked below. The /usr/local/bin/
# lm-update-restart helper (provisioned below) ALSO delegates its state-file
# ops to that CLI; only its poll/curl/systemd-run logic stays in bash (that is
# not state-machine). A behavior change to the snapshot/pending/bad-version
# format MUST be made in core/src/update_recovery.py — the wrappers inherit it.
# ------------------------------------------------------------------
RECOVERY_STATE_DIR="/var/lib/lm/state"
RECOVERY_BACKUP_ROOT="$RECOVERY_STATE_DIR/update-backup"
RECOVERY_PENDING="$RECOVERY_STATE_DIR/pending_update.json"
RECOVERY_BAD="$RECOVERY_STATE_DIR/bad_versions.json"
RECOVERY_FAILED="$RECOVERY_STATE_DIR/update_failed.json"
RECOVERY_HEALTH_TIMEOUT=60
RECOVERY_ROLLBACK_TIMEOUT=30
RECOVERY_KEEP_BACKUPS=3
# Path to the Python recovery CLI (single source of truth for state ops).
# $BASE_DIR is set above; these helpers only run after that.
RECOVERY_PY="$BASE_DIR/core/src/update_recovery.py"

# Exit cleanup — mirrors install_production.sh's `trap 'rm -f "$TMP"' EXIT` but
# also reaps our transient clone dir and a stale pending manifest. Rationale:
#   * lm_tmp/ is recreated fresh every run (line ~495), so a leftover from a
#     killed install only wastes space and can confuse a re-run — always remove.
#   * pending_update.json is written by snapshot_hub_code() *before* the
#     destructive code swap. If the install is killed BEFORE that swap
#     completes, lm_tmp/ is still present (the normal `rm -rf lm_tmp` at
#     ~line 527 never ran) and the hub is NOT mid a real update — the old code
#     is still in place, so the pending marker is stale and would make the next
#     lm-update-restart try to roll back to a snapshot that matches the running
#     code (a no-op at best, harmful at worst). Clear it.
#   * If lm_tmp/ was already removed, the swap completed and the boot/rollback
#     path (rollback_hub_code / recovery_clear_pending) owns pending — leave it
#     alone so a genuine in-flight update can still be rolled back.
# On any non-zero exit, point the operator at the two logs that explain why.
cleanup_on_exit() {
    local rc=$?
    if [ "$rc" -ne 0 ]; then
        log_e "Install aborted (exit $rc). See $INSTALL_LOG and $LOG_DIR/hub.log for details."
    fi
    if [ -d "$BASE_DIR/lm_tmp" ]; then
        rm -rf "$BASE_DIR/lm_tmp" 2>/dev/null || true
        if [ -f "$RECOVERY_PENDING" ]; then
            rm -f "$RECOVERY_PENDING" 2>/dev/null || true
            log "Cleared stale pending_update.json (install aborted before code swap completed)"
        fi
    fi
    return 0
}
trap cleanup_on_exit EXIT

# snapshot_hub_code <from_version> <to_version>
# Snapshot core/src + WebUI *before* the destructive swap and write the
# pending manifest so a failed boot can be rolled back. No-op on a fresh
# reinstall (nothing to roll back to). Delegates the cp + pending write +
# chown to the Python CLI (single source of truth).
snapshot_hub_code() {
    local from_v="$1" to_v="$2" bdir
    [ "$REINSTALL" = true ] && return 0
    [ -d "$BASE_DIR/core/src" ] || return 0
    # Best-effort cp (a missing src/WebUI in the backup only means that
    # component can't be rolled back; rollback_hub_code guards with
    # `[ -d "$bdir/src" ]` before using it). The CLI also chowns the state dir
    # to svc_lm; a chown miss here is corrected by the recursive chown at
    # ~line 966 before the hub boots — safe.
    bdir="$(python3 "$RECOVERY_PY" snapshot \
        --hub-root "$BASE_DIR" --from-version "$from_v" --to-version "$to_v" \
        --chown-user "$SvcUser" 2>/dev/null)" \
        || log_e "Failed to write pre-update snapshot (rollback may be unavailable)"
    if [ -n "$bdir" ]; then
        log "Pre-update snapshot saved to $bdir (from=$from_v to=$to_v)"
    fi
    # Best-effort by design ("rollback may be unavailable"): a snapshot failure
    # must NEVER abort the install. The `&& log` form above returned 1 when the
    # snapshot failed (empty $bdir), which under `set -e` aborted the whole
    # script at the call site — turning a benign "no rollback this update" into
    # a hard install failure. Always return 0 here.
    return 0
}

# recovery_prune_backups <keep>  — keep newest <keep> snapshots, drop the rest.
recovery_prune_backups() {
    local keep="${1:-$RECOVERY_KEEP_BACKUPS}"
    python3 "$RECOVERY_PY" prune --keep "$keep" >/dev/null 2>/dev/null || true
}

recovery_clear_pending() {
    python3 "$RECOVERY_PY" clearpending >/dev/null 2>/dev/null || true
}

# recovery_add_bad_version <v> — mark a version bad so the auto loop skips it.
recovery_add_bad_version() {
    local v="$1"
    [ -n "$v" ] || return 0
    python3 "$RECOVERY_PY" markbad "$v" --chown-user "$SvcUser" >/dev/null 2>/dev/null || true
    # chown is best-effort: a root-owned bad_versions.json is still readable
    # by the auto-update loop (lm-update-restart runs as root via sudo) —
    # safe to ignore.
    log "Marked version $v bad (failed to boot, rolled back)"
}

recovery_write_failed() { # <to_version> <backup_dir> <reason>
    local to_v="$1" bdir="$2" reason="$3"
    python3 "$RECOVERY_PY" writefailed \
        --to-version "$to_v" --backup-dir "$bdir" --reason "$reason" \
        --chown-user "$SvcUser" >/dev/null 2>/dev/null || true
}

# rollback_hub_code <to_version>
# Restore the pre-swap snapshot, realign venv deps, restart, re-poll /status.
# Called when the 60s readiness poll fails — the new code won't boot. The
# pending manifest is read here in bash (a read, not a state-machine write) so
# the "Rolling back..." log line is printed BEFORE the restore, matching the
# original log ordering; the restore cp itself is delegated to the Python CLI.
rollback_hub_code() {
    local to_v="$1" pending bdir from_v res ok
    pending="$(cat "$RECOVERY_PENDING" 2>/dev/null || true)"
    bdir="$(printf '%s' "$pending" | jq -r '.backup_dir // empty' 2>/dev/null)"
    from_v="$(printf '%s' "$pending" | jq -r '.from_version // empty' 2>/dev/null)"

    if [ -z "$bdir" ] || [ ! -d "$bdir/src" ]; then
        log_e "Hub failed to start after ${RECOVERY_HEALTH_TIMEOUT}s and no rollback snapshot exists; leaving hub down. Last log output:"
        tail -30 "$LOG_DIR/hub.log" >&2 || true
        recovery_write_failed "$to_v" "" "no snapshot; new version failed /status within ${RECOVERY_HEALTH_TIMEOUT}s"
        exit 1
    fi

    log_e "Hub failed to start after ${RECOVERY_HEALTH_TIMEOUT}s. Rolling back to pre-update snapshot ($bdir)..."
    # Delegate the snapshot restore (rm + cp + chown of core/src + WebUI) to the
    # Python CLI. venv + data are preserved by the install; only src/WebUI swap.
    res="$(python3 "$RECOVERY_PY" rollback \
        --hub-root "$BASE_DIR" --backup-dir "$bdir" --chown-user "$SvcUser" 2>/dev/null || true)"
    ok="$(printf '%s' "$res" | jq -r '.ok // false' 2>/dev/null)"
    if [ "$ok" != "true" ]; then
        log_e "Snapshot restore failed for $bdir; leaving hub down. Snapshot preserved for manual recovery."
        recovery_write_failed "$to_v" "$bdir" "snapshot restore failed"
        exit 1
    fi

    # Realign venv deps to the restored code (venv was just built for the new code).
    # Meaningful: a failure here means the rolled-back code may run against the
    # new code's deps and crash again. We continue (best-effort — the snapshot is
    # already restored) but log_e so the partial failure is visible to the
    # operator in both the console and /var/log/lm/install.log, not just the file.
    log_c "🛠️  Reinstalling dependencies for rolled-back code..."
    "$BASE_DIR/core/venv/bin/python3" -m pip install -q -r "$BASE_DIR/core/requirements.txt" >> "$INSTALL_LOG" 2>&1 \
        || log_e "pip install on rollback reported failures (continuing — rolled-back code may misbehave)"

    recovery_add_bad_version "$to_v"
    recovery_clear_pending

    log_c "🚀 Restarting Hub with rolled-back code..."
    systemctl restart lm 2>/dev/null || true

    # Re-poll /status for the rolled-back boot.
    local waited=0 code=000
    while [ "$waited" -lt "$RECOVERY_ROLLBACK_TIMEOUT" ]; do
        # Rolled-back code may be pre-unified (hub on 8000) or unified (443) —
        # _status_200 probes both schemes/ports so either is detected.
        if _status_200; then code=200; break; fi
        sleep 2; waited=$((waited + 2))
    done
    if [ "$code" != "200" ]; then
        log_e "Rolled-back code ALSO failed to start after ${RECOVERY_ROLLBACK_TIMEOUT}s. Snapshot preserved at $bdir for manual recovery."
        recovery_write_failed "$to_v" "$bdir" "rollback also failed to boot within ${RECOVERY_ROLLBACK_TIMEOUT}s"
        exit 1
    fi
    log_c "✅ Install failed but rolled back to v${from_v:-previous}; hub is healthy. v${to_v} marked bad (auto-update will skip it until a newer version ships)."
    recovery_prune_backups "$RECOVERY_KEEP_BACKUPS"
    exit 0
}

echo "🚀 Starting Native Lab Manager Installation (LXC-Optimized)..."

# 1. Pre-flight Check (Permissions)
log_c "🔍 Performing pre-flight checks..."
if [ "$(id -u)" -ne 0 ]; then
    log_e "This script must be run as root or with sudo."
    if command -v sudo >/dev/null 2>&1; then
        echo "👉 Please run: sudo bash $0"
        exit 1
    else
        log_e "Sudo not found. Root privileges are required for this installation."
        exit 1
    fi
fi

# 2. System Dependencies
log_c "📦 Installing system dependencies..."
apt-get update >> "$INSTALL_LOG" 2>&1
# Package roles:
#   python3-pip/venv — hub + per-spoke venvs.
#   git/curl          — clone spokes, hit the hub API during install.
#   lsof/net-tools    — port/process cleanup before restart (lm-self-restart).
#   jq                — recovery state JSON (pending_update/bad_versions).
#   sudo              — svc_lm runs the restart/recover helpers via sudoers.
#   psmisc            — provides pkill (ExecStop precision + spoke reap below).
#   hostname          — `hostname -I` used in the final dashboard URL print.
#   systemd-container — provides systemd-run, used by lm-self-restart and
#                       lm-update-restart to schedule restarts from a transient
#                       unit OUTSIDE lm.service's cgroup (without this package
#                       those helpers can't survive the stop phase of restart).
apt-get install -y python3-pip python3-venv git curl lsof net-tools jq sudo psmisc hostname systemd-container >> "$INSTALL_LOG" 2>&1

# Ensure consistent hostname for logging and diagnostics. SIDE EFFECT: changes
# the host's hostname system-wide (persisted across reboots via hostnamectl),
# which also updates the shell prompt and any tool that reads $(hostname). In
# unprivileged LXC containers hostnamectl may be denied by the host's
# systemd policy — the fallback echo keeps the install moving in that case.
log_c "🏷️  Setting system hostname to lm-hub..."
hostnamectl set-hostname lm-hub || echo "Hostname change failed (expected in some LXC environments)"

# Mark all directories under /opt/lm as safe for git to avoid dubious ownership errors
git config --global --add safe.directory /opt/lm
git config --global --add safe.directory '/opt/lm/*'

# ------------------------------------------------------------------
# User & Permission Setup
# ------------------------------------------------------------------
# Create non-root user for the service
if ! id -u "$SvcUser" >/dev/null 2>&1; then
    log_c "👤 Creating system user $SvcUser..."
    # Guarded by the id -u probe above; on a re-run the user already exists
    # (race-free) and useradd would fail — safe to ignore.
    useradd -r -m -d /opt/lm -s /usr/sbin/nologin "$SvcUser" || true
fi

# Ensure global log directory ownership is correct now that user exists
chown -R $SvcUser:$SvcUser "$LOG_DIR"

# Grant svc_lm permission to restart the LM service without a password.
#
# The hub restarts ITSELF after a self-update (core/src/main.py update_hub).
# Doing that with a bare `systemctl restart lm` from inside the hub races the
# stop/start against the hub's own cgroup and can strand lm.service inactive
# for ~16 min (the restart is never handed off, so the stop-phase SIGTERM kills
# the very process that issued it before start runs). Instead the hub calls the
# /usr/local/bin/lm-self-restart helper (via the sudoers rule below), which uses
# `systemd-run --no-block` to schedule the restart from a transient unit OWNED
# BY PID 1 — outside lm.service's cgroup — so the restart command survives the
# hub being stopped and completes cleanly.
log_c "⚙️ Configuring hub self-restart helper + sudoers for $SvcUser..."
cat > /usr/local/bin/lm-self-restart <<'HELPER'
#!/bin/bash
# Schedules an lm.service restart from a transient unit outside lm's cgroup.
# See lm/install_all.sh for rationale. Invoked by the hub as
# `sudo -n /usr/local/bin/lm-self-restart` (sudoers grants only this exact path).
set -euo pipefail
_unit="lm-self-restart-$$-$RANDOM"
exec systemd-run --no-block --quiet --collect \
    --unit="$_unit" --service-type=oneshot \
    /bin/bash -c 'sleep 3; exec systemctl restart lm'
HELPER
chown root:root /usr/local/bin/lm-self-restart
chmod 0755 /usr/local/bin/lm-self-restart

# Post-update restart + health-gated rollback helper for the auto-update path
# (core/src/main.py perform_update → calls this instead of lm-self-restart so
# a broken update is rolled back instead of leaving the hub dark). Runs via
# systemd-run --no-block (re-execs itself into a transient unit owned by PID 1,
# outside lm.service's cgroup) so it survives the hub being stopped and can
# poll /status + restore the snapshot afterward. State-file ops (snapshot
# restore, pending/bad-version/failed writes, prune) delegate to the Python CLI
# core/src/update_recovery.py — the SINGLE SOURCE OF TRUTH. Only poll/curl/
# systemd-run logic stays in bash (that is not state-machine).
#
# KEEP IN SYNC WITH: core/src/update_recovery.py (Python source of truth). The
# recovery_* helpers near the top of this file delegate to the same CLI. A
# behavior change to the snapshot/pending/bad-version format is made in
# update_recovery.py only — the wrappers inherit it.
cat > /usr/local/bin/lm-update-restart <<'HELPER'
#!/bin/bash
# Post-update hub restart with health-gated rollback. Invoked by the hub as
# `sudo -n /usr/local/bin/lm-update-restart` (sudoers grants only this path).
#
# State-file ops (snapshot restore, pending/bad-version/failed writes, prune)
# delegate to the Python CLI core/src/update_recovery.py — the SINGLE SOURCE OF
# TRUTH for the on-disk recovery state machine. Only the poll/curl/systemd-run
# logic lives here (that is not state-machine). Same on-disk state files
# (pending_update.json / bad_versions.json / update_failed.json under
# /var/lib/lm/state); a format change must be made in update_recovery.py.
set -uo pipefail

STATE_DIR="/var/lib/lm/state"
PENDING="$STATE_DIR/pending_update.json"
HEALTH_TIMEOUT=60
ROLLBACK_TIMEOUT=30
KEEP_BACKUPS=3
SVC_USER="svc_lm"
BASE_DIR="/opt/lm"
# After `systemctl restart lm` the hub runs the unified :443 surface (wss with
# a cert, plaintext 443 without). _status_200 (defined above) probes 443 wss,
# 443 plain, and legacy 8000 so the watchdog detects the hub regardless of TLS
# or a rolled-back pre-unified code path.
RECOVERY_PY="$BASE_DIR/core/src/update_recovery.py"

# Re-exec under a transient systemd unit outside lm's cgroup so this process
# survives the `systemctl restart lm` it issues (otherwise the restart kills
# us before we can poll /status or roll back). The guard prevents an infinite
# re-exec loop. Mirrors the lm-self-restart transient-unit trick.
if [ -z "${LM_UPDATE_RESTART_GUARD:-}" ]; then
    export LM_UPDATE_RESTART_GUARD=1
    exec systemd-run --no-block --quiet --collect \
        --unit="lm-update-restart-$$-$RANDOM" --service-type=oneshot \
        --setenv=LM_UPDATE_RESTART_GUARD=1 \
        /usr/local/bin/lm-update-restart
fi

poll_status() {  # $1=timeout  -> 0 if /status returns 200 within timeout
    local timeout="$1" waited=0
    while [ "$waited" -lt "$timeout" ]; do
        _status_200 && return 0
        sleep 2; waited=$((waited + 2))
    done
    return 1
}

# Let the hub return its HTTP response before the restart actually fires.
sleep 3
systemctl restart lm 2>/dev/null || true

# 1) Did the new version boot?
if poll_status "$HEALTH_TIMEOUT"; then
    python3 "$RECOVERY_PY" clearpending >/dev/null 2>&1 || true
    python3 "$RECOVERY_PY" prune --keep "$KEEP_BACKUPS" >/dev/null 2>&1 || true
    exit 0
fi

# 2) New version failed — roll back to the pre-swap snapshot.
# Read the pending manifest here (a read, not a state-machine write) so the
# "rolling back" log line and the to_v/from_v extraction stay in bash; the
# restore cp + chown is delegated to the Python CLI below.
pending="$(cat "$PENDING" 2>/dev/null || true)"
bdir="$(printf '%s' "$pending" | jq -r '.backup_dir // empty' 2>/dev/null)"
to_v="$(printf '%s' "$pending" | jq -r '.to_version // empty' 2>/dev/null)"
from_v="$(printf '%s' "$pending" | jq -r '.from_version // empty' 2>/dev/null)"

if [ -z "$bdir" ] || [ ! -d "$bdir/src" ]; then
    # No snapshot to roll back to — leave the hub down and record for manual recovery.
    python3 "$RECOVERY_PY" writefailed --to-version "$to_v" --backup-dir "$bdir" \
        --reason "no snapshot; new version failed /status within ${HEALTH_TIMEOUT}s" \
        --chown-user "$SVC_USER" >/dev/null 2>&1 || true
    exit 1
fi

echo "lm-update-restart: new version v${to_v} failed to boot; rolling back to v${from_v}" >&2
res="$(python3 "$RECOVERY_PY" rollback --hub-root "$BASE_DIR" --backup-dir "$bdir" --chown-user "$SVC_USER" 2>/dev/null || true)"
ok="$(printf '%s' "$res" | jq -r '.ok // false' 2>/dev/null)"
if [ "$ok" != "true" ]; then
    python3 "$RECOVERY_PY" writefailed --to-version "$to_v" --backup-dir "$bdir" \
        --reason "snapshot restore failed" --chown-user "$SVC_USER" >/dev/null 2>&1 || true
    exit 1
fi
# Realign venv deps to the restored code (best-effort). This runs in the
# rollback branch where the hub is already down; a pip failure leaves the
# rolled-back code running against the new code's deps, which may crash — but
# the alternative (aborting) would leave the hub dark with no recovery path.
# Safe to ignore: the snapshot is already restored and we restart regardless.
[ -f "$BASE_DIR/core/requirements.txt" ] && \
    "$BASE_DIR/core/venv/bin/python3" -m pip install -q -r "$BASE_DIR/core/requirements.txt" 2>/dev/null || true

python3 "$RECOVERY_PY" markbad "$to_v" --chown-user "$SVC_USER" >/dev/null 2>&1 || true
python3 "$RECOVERY_PY" clearpending >/dev/null 2>&1 || true
systemctl restart lm 2>/dev/null || true

# 3) Did the rolled-back code boot?
if poll_status "$ROLLBACK_TIMEOUT"; then
    echo "lm-update-restart: rolled back to v${from_v}; marked v${to_v} bad (auto-update skips it until a newer version ships)" >&2
    python3 "$RECOVERY_PY" prune --keep "$KEEP_BACKUPS" >/dev/null 2>&1 || true
    exit 0
fi

# 4) Rollback also failed — preserve the snapshot for manual recovery.
python3 "$RECOVERY_PY" writefailed --to-version "$to_v" --backup-dir "$bdir" \
    --reason "rollback also failed to boot within ${ROLLBACK_TIMEOUT}s" \
    --chown-user "$SVC_USER" >/dev/null 2>&1 || true
exit 1
HELPER
chown root:root /usr/local/bin/lm-update-restart
chmod 0755 /usr/local/bin/lm-update-restart

# Spoke-recovery helper for the hub watchdog (core/src/main.py
# run_spoke_recovery_loop). A spoke unit that crash-looped into systemd `failed`
# (e.g. cs status=203/EXEC when the venv/interpreter was missing) is NOT revived
# by `systemctl restart` alone — it needs `reset-failed` first, which is NOT in
# the sudoers rule below (only `restart` is). This helper does inspect -> reset-
# failed (if SubState==failed) -> restart atomically and prints one line of JSON
# the hub parses to classify the strand (ActiveState/SubState/Result/
# ExecMainStatus/NRestarts). The hub calls it as:
#   sudo -n /usr/local/bin/lm-spoke-recover --inspect <unit>   (read-only)
#   sudo -n /usr/local/bin/lm-spoke-recover <unit>            (recover)
# Least privilege: sudoers grants svc_lm only this one path (the `*` covers both
# the --inspect and recover argument forms); no raw systemctl introspection.
cat > /usr/local/bin/lm-spoke-recover <<'HELPER'
#!/bin/bash
# See lm/install_all.sh for rationale. Invoked by the hub watchdog as
# `sudo -n /usr/local/bin/lm-spoke-recover [--inspect] <unit>`.
set -euo pipefail

show() {  # $1=unit -> sets A Sub R EMS EMC NR_ from `systemctl show`
    local out
    out=$(systemctl show "$1" --property=ActiveState,SubState,Result,ExecMainStatus,ExecMainCode,NRestarts 2>/dev/null || true)
    A=$(printf '%s\n' "$out" | awk -F= '/^ActiveState=/{print $2; exit}')
    Sub=$(printf '%s\n' "$out" | awk -F= '/^SubState=/{print $2; exit}')
    R=$(printf '%s\n' "$out" | awk -F= '/^Result=/{print $2; exit}')
    EMS=$(printf '%s\n' "$out" | awk -F= '/^ExecMainStatus=/{print $2; exit}')
    EMC=$(printf '%s\n' "$out" | awk -F= '/^ExecMainCode=/{print $2; exit}')
    NR_=$(printf '%s\n' "$out" | awk -F= '/^NRestarts=/{print $2; exit}')
}

mode="recover"
unit=""
for a in "$@"; do
    case "$a" in
        --inspect) mode="inspect" ;;
        --*) ;;
        *) unit="$a" ;;
    esac
done
[ -n "$unit" ] || { echo '{"error":"no unit"}' >&2; exit 2; }

show "$unit"
case "$mode" in
    inspect)
        printf '{"unit":"%s","ActiveState":"%s","SubState":"%s","Result":"%s","ExecMainStatus":"%s","ExecMainCode":"%s","NRestarts":"%s"}\n' \
            "$unit" "${A:-}" "${Sub:-}" "${R:-}" "${EMS:-}" "${EMC:-}" "${NR_:-}"
        ;;
    recover)
        reset=false
        if [ "${Sub:-}" = "failed" ]; then
            systemctl reset-failed "$unit" 2>/dev/null || true
            reset=true
        fi
        systemctl restart "$unit" 2>/dev/null || true
        printf '{"unit":"%s","pre":{"ActiveState":"%s","SubState":"%s","Result":"%s","ExecMainStatus":"%s","ExecMainCode":"%s","NRestarts":"%s"},"reset":%s,"restarted":true}\n' \
            "$unit" "${A:-}" "${Sub:-}" "${R:-}" "${EMS:-}" "${EMC:-}" "${NR_:-}" "$reset"
        ;;
esac
HELPER
chown root:root /usr/local/bin/lm-spoke-recover
chmod 0755 /usr/local/bin/lm-spoke-recover

# Update-path permission-repair helper (self-heal for ownership drift). If a
# person or a faulty install leaves /opt/lm/.git/objects or /var/log/lm root-
# owned, the svc_lm-run Update button / 15-min auto-update git pull fails with
# "insufficient permission for adding an object to repository database .git/
# objects". The hub health check (update_pipeline.check_update_health, run each
# repo-sync cycle) detects it and invokes this via
#   sudo -n /usr/local/bin/lm-fix-perms
# to hand the checkout + logs back to the service user. Idempotent, least-priv
# (fixed paths baked in, no args).
cat > /usr/local/bin/lm-fix-perms <<HELPER
#!/bin/bash
# See lm/install_all.sh. Restores $SvcUser ownership of the hub checkout + log
# dir so the service user's git pull can write .git/objects.
set -e
chown -R $SvcUser:$SvcUser /opt/lm /var/log/lm 2>/dev/null || true
runuser -u $SvcUser -- git config --global --add safe.directory /opt/lm 2>/dev/null || true
echo "lm-fix-perms: restored $SvcUser ownership of /opt/lm + /var/log/lm"
HELPER
chown root:root /usr/local/bin/lm-fix-perms
chmod 0755 /usr/local/bin/lm-fix-perms

cat > /etc/sudoers.d/lm <<SUDOERS
$SvcUser ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart lm
$SvcUser ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart lm-*
$SvcUser ALL=(ALL) NOPASSWD: /usr/local/bin/lm-self-restart
$SvcUser ALL=(ALL) NOPASSWD: /usr/local/bin/lm-update-restart
$SvcUser ALL=(ALL) NOPASSWD: /usr/local/bin/lm-spoke-recover *
$SvcUser ALL=(ALL) NOPASSWD: /usr/local/bin/lm-fix-perms
SUDOERS
chmod 440 /etc/sudoers.d/lm

# ------------------------------------------------------------------
# Reinstall Logic
# ------------------------------------------------------------------
# Stop hub (lm.service) and kill any process still holding hub ports.
# Do NOT pkill -9 python — that would kill lm-ldap/lm-netbox/lm-dns and
# trigger rapid systemd restart loops that can hit StartLimitBurst and leave
# those services in a permanent "failed" state through the rest of the install.
log_c "🧹 Cleaning up existing Hub processes..."
systemctl stop lm || true
# Clear the unified 443 port (real hub), 8000 (boot probe / legacy hub), and
# 8765 (legacy spoke-WS) so nothing stale can hold the hub's bind.
for port in 443 8000 8765; do
    pid=$(lsof -t -i :$port || true)
    if [ -n "$pid" ]; then
        kill -9 $pid || true
    fi
done

if [ "$REINSTALL" = true ]; then
    log_c "⚠️  REINSTALL MODE: Wiping all configuration, state, and installations..."
    # Remove installation directory and secrets
    rm -rf "$BASE_DIR"
    rm -f /etc/systemd/system/lm.service
    log_c "🧹 Clean slate achieved. Proceeding with fresh installation..."
fi

if [ "$RESET_SECRETS" = true ]; then
    log_c "🔑 RESET-SECRETS MODE: Wiping Hub identity and spoke keys..."
    # The secrets are located in $BASE_DIR/core/data
    rm -f "$BASE_DIR/core/data/keys.json"
    rm -f "$BASE_DIR/core/data/hub_secret.json"
    log_c "🧹 Secrets wiped. Hub will regenerate a new identity on start."
fi

# Cleanup legacy installations
if [ -d "$OLD_BASE_DIR" ]; then
    log_c "🗑️  Removing legacy installation at $OLD_BASE_DIR..."
    rm -rf "$OLD_BASE_DIR"
fi

mkdir -p "$BASE_DIR"
chown -R $SvcUser:$SvcUser "$BASE_DIR"
cd "$BASE_DIR"

# ── Retire the legacy Generic Leaf Agent (lm-bootstrap / lm-generic-agent) ──
# A hub VM cloned from an OLD image can carry a crash-looping generic-agent unit
# whose ExecStart is /opt/lm/generic-agent/src/agent.py (removed from the repo).
# It's protocol-incompatible + useless on the hub and spams the journal on a 10s
# restart loop. The AGENT installer purges this (agent/install_agent.sh
# retire_legacy_agent), but a HUB install never ran that — so do it here too.
# Match by unit NAME and by any unit whose ExecStart references the legacy path
# (older builders named it variously, e.g. lm-bootstrap). KEEP IN SYNC WITH
# agent/install_agent.sh retire_legacy_agent. Idempotent + non-fatal.
retire_legacy_leaf() {
    local names="lm-generic-agent lm-bootstrap"
    local f u svc purged=0
    for f in /etc/systemd/system/*.service /etc/systemd/system/*/*.service \
             /run/systemd/system/*.service \
             /lib/systemd/system/*.service /usr/lib/systemd/system/*.service; do
        [ -e "$f" ] || continue
        grep -qE "/opt/lm/generic-agent" "$f" 2>/dev/null && names="$names $(basename "$f" .service)"
    done
    for u in $(systemctl list-units --type=service --state=running,failed --no-legend --plain 2>/dev/null | awk '{print $1}'); do
        systemctl show "$u" -p ExecStart 2>/dev/null | grep -q "/opt/lm/generic-agent" && names="$names ${u%.service}"
    done
    for svc in $(printf '%s\n' $names | sort -u); do
        [ -n "$svc" ] || continue
        [ "$svc" = "lm" ] && continue   # never touch the hub's own unit
        if [ -e "/etc/systemd/system/${svc}.service" ] \
           || systemctl list-unit-files "${svc}.service" 2>/dev/null | grep -qE "^${svc}\.service"; then
            systemctl stop    "$svc" 2>/dev/null || true
            systemctl disable "$svc" 2>/dev/null || true
            rm -f "/etc/systemd/system/${svc}.service"
            systemctl mask    "$svc" 2>/dev/null || true
            systemctl reset-failed "$svc" 2>/dev/null || true
            log_c "🧹 Purged legacy leaf unit ${svc}.service."
            purged=1
        fi
    done
    if [ -d /opt/lm/generic-agent ] || [ -d /opt/lm/generic_agent ]; then
        pkill -f "/opt/lm/generic-agent/src/agent.py" 2>/dev/null || true
        rm -rf /opt/lm/generic-agent /opt/lm/generic_agent
        log_c "🧹 Removed legacy leaf dir /opt/lm/generic-agent."
        purged=1
    fi
    [ "$purged" = 1 ] && systemctl daemon-reload 2>/dev/null || true
}
retire_legacy_leaf

# Clone core components (Hub and WebUI)
log_c "🌐 Cloning Core Repository..."
rm -rf lm_tmp
git clone "https://github.com/lbockenstedt/lm.git" lm_tmp

# Preserve data directory during updates
DATA_BACKUP_DIR="$BASE_DIR/core_data_backup"
if [ "$REINSTALL" = false ] && [ -d "$BASE_DIR/core/data" ]; then
    log "Preserving existing data directory during update..."
    mv "$BASE_DIR/core/data" "$DATA_BACKUP_DIR"
fi

# Snapshot the current code + WebUI *before* the destructive swap so a failed
# boot can be rolled back (manual path — mirrors the auto path's snapshot in
# core/src/main.py perform_update). No-op on a fresh reinstall.
if [ "$REINSTALL" = false ]; then
    _FROM_V="$(cat "$BASE_DIR/VERSION" 2>/dev/null || echo unknown)"
    _TO_V="$(cat lm_tmp/VERSION 2>/dev/null || echo unknown)"
    snapshot_hub_code "$_FROM_V" "$_TO_V"
fi

# Keep $BASE_DIR as a real GIT CHECKOUT (do NOT discard the clone's .git). This
# is what lets the WebUI "Update" button + the 15-min auto-update loop use the
# verified git-pull path (update_pipeline._is_git_repo → _git_update, which
# checks the HEAD actually advanced) instead of the fragile download/tarball
# fallback that reports success even when nothing changed. Relocate the clone's
# .git into $BASE_DIR and let git materialize the whole tracked tree in place
# (core/, WebUI/, dns/, dhcp/, root scripts, VERSION, docs). Untracked paths
# (cs/, pxmx/, venv/, .env, certs/, data/) are left untouched by reset --hard.
rm -rf "$BASE_DIR/core" "$BASE_DIR/WebUI" "$BASE_DIR/dns" "$BASE_DIR/dhcp"
rm -rf "$BASE_DIR/.git"
mv lm_tmp/.git "$BASE_DIR/.git"
rm -rf lm_tmp
git config --global --add safe.directory "$BASE_DIR" 2>/dev/null || true
if ( cd "$BASE_DIR" && git reset --hard HEAD ); then
    log_c "✅ Hub laid down as a git checkout (Update button + auto-update will use git pull)."
else
    log_e "git checkout of the hub tree failed — hub may not be updatable via the button."
fi
# The git ops above ran as root, so .git/objects + the tree are root-owned. The
# hub runs as $SvcUser and the Update button / auto-update do `git pull` as that
# user — root-owned .git/objects → "insufficient permission for adding an object"
# and every update fails silently. Hand the checkout back to $SvcUser and make it
# trust the dir (the safe.directory add above went into ROOT's gitconfig).
chown -R "$SvcUser:$SvcUser" "$BASE_DIR/.git" 2>/dev/null || true
runuser -u "$SvcUser" -- git config --global --add safe.directory "$BASE_DIR" 2>/dev/null || true

# Restore data directory (core/data is not tracked; the rm -rf core above
# removed it, so restore the pre-update copy).
if [ -d "$DATA_BACKUP_DIR" ]; then
    log "Restoring preserved data directory..."
    rm -rf "$BASE_DIR/core/data"
    mv "$DATA_BACKUP_DIR" "$BASE_DIR/core/data"
fi

# Sync other spokes
# NOTE: this loop MUST respect --exclude. The per-module installer that
# *recreates* each spoke's venv (install_cs.sh / install_pxmx.sh / ...) is
# gated by EXCLUDE below, so if we wipe an excluded module's venv here but
# skip its installer, the venv is never restored and the service crash-loops
# with status=203/EXEC ("Unable to locate executable .../venv/bin/python3").
# Excluded modules are left entirely untouched (no venv wipe, no code pull).
REPOS=("cs" "pxmx" "opnsense" "cppm" "netbox" "ldap" "nw" "le")
for repo in "${REPOS[@]}"; do
    _excluded=false
    for ex in "${EXCLUDE[@]}"; do [[ "$repo" == "$ex" ]] && _excluded=true; done
    if $_excluded; then
        log_c "⏭️  Skipping $repo in sync (excluded) — leaving venv/code untouched"
        continue
    fi
    if [ -d "$repo/.git" ]; then
        log_c "📂 $repo already exists. Updating..."
        cd "$repo"
        rm -rf venv
        git checkout .
        # Rebase the local branch onto origin. If the rebase fails (diverged
        # history, a stale local commit, or an autostash conflict), fall back to
        # a hard reset to origin's tip instead of letting `set -e` abort the
        # whole install — a partial install (hub updated, this spoke stranded
        # mid-pull) is worse than a clean force-sync. Spoke secrets live in
        # gitignored untracked files (.env, *.key, keys.json, …) which a
        # `git reset --hard` preserves (it only moves tracked files).
        if ! git pull --rebase --autostash; then
            log_e "git pull --rebase failed for $repo; falling back to hard reset to origin"
            git fetch origin
            _branch="$(git rev-parse --abbrev-ref HEAD)"
            git reset --hard "origin/$_branch"
        fi
        cd ..
    else
        log_c "🌐 Cloning $repo..."
        git clone "https://github.com/lbockenstedt/$repo.git"
    fi
done

# 5. Run Modular Installers
log_c "🛠️ Running modular installations..."

# --- Step A: Hub Backend ---
log_c "Setting up Hub Backend..."
cd "$BASE_DIR/core"

# Hub venv setup
if [ -d "venv" ] && [ ! -f "venv/bin/python3" ]; then rm -rf venv; fi
if [ ! -d "venv" ]; then python3 -m venv venv; fi
./venv/bin/python3 -m pip install --upgrade pip -q
./venv/bin/python3 -m pip install -r requirements.txt -q

# Ensure the data directory exists and is owned by the service user
mkdir -p "$BASE_DIR/core/data"
chown -R $SvcUser:$SvcUser "$BASE_DIR"

# --- Step B: WebUI Assets ---
log_c "Setting up WebUI assets..."
cd "$BASE_DIR/WebUI"
if [ -f "install_ui.sh" ]; then
    bash ./install_ui.sh
else
    log_c "✅ UI assets already in place (install_ui.sh not found in WebUI directory, skipping)."
fi
cd "$BASE_DIR"

# --- Step B2: Ensure Hub credentials (LM_FERNET_KEY) ---
log_c "🔑 Ensuring Hub credentials..."
HUB_ENV="$BASE_DIR/.env"
touch "$HUB_ENV"
chmod 600 "$HUB_ENV"

# Fernet encryption key (preserve existing)
if ! grep -q "^LM_FERNET_KEY=.\+" "$HUB_ENV" 2>/dev/null; then
    FERNET_KEY=$("$BASE_DIR/core/venv/bin/python3" -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
    if grep -q "^LM_FERNET_KEY=" "$HUB_ENV" 2>/dev/null; then
        sed -i "s|^LM_FERNET_KEY=.*|LM_FERNET_KEY=$FERNET_KEY|" "$HUB_ENV"
    else
        echo "LM_FERNET_KEY=$FERNET_KEY" >> "$HUB_ENV"
    fi
    log_c "✅ Generated new LM_FERNET_KEY"
else
    log_c "✅ LM_FERNET_KEY already set — preserving existing key"
fi
export LM_FERNET_KEY=$(grep "^LM_FERNET_KEY=" "$HUB_ENV" | cut -d'=' -f2-)

# --reset-users: wipe user accounts now that the Fernet key is available and
# the hub is still stopped, so it boots with an empty users dict.
if [ "$RESET_USERS" = true ]; then
    log_c "🗑️  Wiping user accounts (--reset-users)..."
    PYTHONPATH="$BASE_DIR/core/src" LM_FERNET_KEY="$LM_FERNET_KEY" \
        "$BASE_DIR/core/venv/bin/python3" - <<'PYEOF'
import sys, json, os
sys.path.insert(0, os.environ.get("PYTHONPATH", "/opt/lm/core/src"))
from security.encryption import hub_encryption

state_paths = [
    "/var/lib/lm/state/system.json",
    os.path.expanduser("~/.local/share/lm/state/system.json"),
]
f = next((p for p in state_paths if os.path.exists(p) and os.path.getsize(p) > 0), None)
if not f:
    print("  No state file yet — users will start empty automatically")
    sys.exit(0)

raw = open(f, "rb").read()
try:
    d = json.loads(hub_encryption.decrypt(raw))
except Exception:
    try:
        d = json.loads(raw)
    except Exception:
        print("  Could not parse state file — skipping")
        sys.exit(1)

d["users"] = {}
open(f, "wb").write(hub_encryption.encrypt(json.dumps(d)))
print(f"  ✅ Users wiped from {f}")
PYEOF
fi

# --- Step C: Create runtime directories and start Hub ---
mkdir -p /var/lib/lm
chown "$SvcUser:$SvcUser" /var/lib/lm
mkdir -p "$BASE_DIR/core/data"
chown -R "$SvcUser:$SvcUser" "$BASE_DIR/core/data"

# Seed default update_sources so a fresh install configures every spoke's
# repo uniformly without the admin hand-entering 7 URLs. Idempotent — only
# missing keys are written, so admin-configured URLs are never overwritten.
# Runs before the Hub boots so it loads the seeded sources at startup (and
# the final `systemctl restart lm` reloads them after an update).
log_c "📦 Seeding default update_sources (missing keys only)..."
mkdir -p /var/lib/lm/state
# Best-effort: on a fresh install the dir was just created by root and the
# recursive chown at ~line 970 re-owns it anyway; on an update it may already
# be svc_lm-owned. Either way a miss here is corrected later — safe to ignore.
chown -R "$SvcUser:$SvcUser" /var/lib/lm/state 2>/dev/null || true
PYTHONPATH="$BASE_DIR/core/src" LM_FERNET_KEY="$LM_FERNET_KEY" \
    "$BASE_DIR/core/venv/bin/python3" - <<'PYEOF'
import sys, json, os
sys.path.insert(0, os.environ.get("PYTHONPATH", "/opt/lm/core/src"))
from security.encryption import hub_encryption

# Canonical repo URLs per module key the Hub reads (main.py update_spokes_only
# / _type_to_source_key). `opn` is the legacy alias for opnsense kept so the
# older reader path still resolves. `agent` is intentionally NOT seeded —
# agents (bugfixer) self-update and skip when their source is unset.
DEFAULTS = {
    "hub": "https://github.com/lbockenstedt/lm.git",
    "pxmx": "https://github.com/lbockenstedt/pxmx.git",
    "opnsense": "https://github.com/lbockenstedt/opnsense.git",
    "opn": "https://github.com/lbockenstedt/opnsense.git",
    "cs": "https://github.com/lbockenstedt/cs.git",
    "cppm": "https://github.com/lbockenstedt/cppm.git",
    "netbox": "https://github.com/lbockenstedt/netbox.git",
    "ldap": "https://github.com/lbockenstedt/ldap.git",
    "nw": "https://github.com/lbockenstedt/nw.git",
}

state_paths = [
    "/var/lib/lm/state/system.json",
    os.path.expanduser("~/.local/share/lm/state/system.json"),
]
f = next((p for p in state_paths if os.path.exists(p) and os.path.getsize(p) > 0), None)

if f:
    raw = open(f, "rb").read()
    try:
        d = json.loads(hub_encryption.decrypt(raw))
    except Exception:
        try:
            d = json.loads(raw)
        except Exception:
            print("  Could not parse state file — skipping seed")
            sys.exit(0)
else:
    # Fresh install: create the state file with a minimal skeleton so the
    # Hub loads the seeded update_sources on first boot.
    f = state_paths[0]
    os.makedirs(os.path.dirname(f), exist_ok=True)
    d = {}

gc = d.setdefault("global_config", {})
sources = gc.setdefault("update_sources", {})
added = []
for key, url in DEFAULTS.items():
    if not sources.get(key):
        sources[key] = url
        added.append(key)

try:
    open(f, "wb").write(hub_encryption.encrypt(json.dumps(d)))
except Exception:
    open(f, "w").write(json.dumps(d, indent=2))

if added:
    print(f"  ✅ Seeded update_sources: {', '.join(added)} -> {f}")
else:
    print(f"  All update_sources already present -> {f}")
PYEOF

log_c "🚀 Starting Hub (boot probe on :8000)..."
# Boot-crash probe: start the hub on an UNPRIVILEGED port (LM_TLS_PORT=8000) so
# svc_lm can bind it without the systemd unit's CAP_NET_BIND_SERVICE. This probe
# only exists to catch a new-version boot crash (import/DB errors) BEFORE we
# commit the unified :443 unit, and to persist pre-approvals into the hub state
# file. The cert + .env + systemd unit are written below (after the module
# installs) and the final `systemctl restart lm` brings up the REAL hub on the
# unified 0.0.0.0:443 wss surface (svc_lm + ambient cap + cert). Spoke units are
# baked with the real wss://localhost:443/ws/spoke URL (HUB_WS below) and
# reconnect-loop (Restart=always) until that restart lands.
export PYTHONPATH="$BASE_DIR/core/src"
if command -v sudo >/dev/null 2>&1; then
    sudo -u $SvcUser env \
        LM_FERNET_KEY="$LM_FERNET_KEY" \
        LM_TLS_PORT=8000 \
        PYTHONPATH="$PYTHONPATH" \
        nohup "$BASE_DIR/core/venv/bin/python3" "$BASE_DIR/core/src/main.py" > "$LOG_DIR/hub.log" 2>&1 &
else
    LM_TLS_PORT=8000 nohup "$BASE_DIR/core/venv/bin/python3" "$BASE_DIR/core/src/main.py" > "$LOG_DIR/hub.log" 2>&1 &
fi

# Give the Hub API a moment to fully start and stabilize
log_c "⏳ Waiting for Hub boot probe to initialize..."
HUB_WAIT=0
HUB_TIMEOUT=60
until curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/status | grep -q "200"; do
    sleep 2
    HUB_WAIT=$((HUB_WAIT + 2))
    if [ "$HUB_WAIT" -ge "$HUB_TIMEOUT" ]; then
        # New code failed to boot — roll back to the pre-update snapshot
        # (restores core/src + WebUI, reinstalls deps, restarts, re-polls).
        # Exits 0 if the rollback boots, 1 if it also fails (snapshot preserved).
        rollback_hub_code "$_TO_V"
    fi
done
sleep 2

# Hub came up on the new version — clear the pending manifest + prune backups.
recovery_clear_pending
recovery_prune_backups "$RECOVERY_KEEP_BACKUPS"

# HUB_API targets the :8000 boot probe (above) for in-install REST calls
# (pre-approval below writes to the shared state file, which the real :443 hub
# inherits at the final restart). HUB_WS is the REAL unified spoke-WS URL baked
# into every spoke unit — spokes reconnect-loop until the :443 hub lands.
HUB_API="http://localhost:8000"
HUB_WS="wss://localhost:443/ws/spoke"

# Anti-lockout: ensure the first admin account always retains admin + protected status.
# Runs on every install/update so manual state edits can never permanently lock out the admin.
log_c "🔒 Enforcing anti-lockout on first admin account..."
PYTHONPATH="$BASE_DIR/core/src" LM_FERNET_KEY="$LM_FERNET_KEY" \
    "$BASE_DIR/core/venv/bin/python3" - <<'PYEOF'
import sys, json, os
sys.path.insert(0, os.environ.get("PYTHONPATH", "/opt/lm/core/src"))
from security.encryption import hub_encryption

state_paths = [
    "/var/lib/lm/state/system.json",
    os.path.expanduser("~/.local/share/lm/state/system.json"),
]
f = next((p for p in state_paths if os.path.exists(p) and os.path.getsize(p) > 0), None)
if not f:
    print("  No state file found — skipping (first install)")
    sys.exit(0)

raw = open(f, "rb").read()
try:
    d = json.loads(hub_encryption.decrypt(raw))
except Exception:
    d = json.loads(raw)

users = d.get("users", {})
if not users:
    print("  No users yet — skipping")
    sys.exit(0)

first_uid = next(iter(users))
u = users[first_uid]
changed = False
p = u.get("permissions", {})
if not (p.get("admin") or p.get("role") == "admin"):
    u["permissions"] = {"role": "admin"}
    changed = True
if not u.get("protected"):
    u["protected"] = True
    changed = True
if u.get("tenants"):
    u["tenants"] = []
    changed = True

if changed:
    try:
        open(f, "wb").write(hub_encryption.encrypt(json.dumps(d)))
    except Exception:
        open(f, "w").write(json.dumps(d, indent=2))
    print(f"  Restored admin + protected + no-tenant on '{first_uid}'")
else:
    print(f"  '{first_uid}' already correct — no changes needed")
PYEOF

# UNIFIED AGENT-SPOKE MODEL: this all-in-one box runs ONE generic agent that
# hosts every module as a ROLE (sub-spoke {agent}-{role}), instead of ten
# dedicated spokes. The hub is co-located here and owns :443, so the agent
# installs with --loopback: the pxmx role's agent-host listener binds
# 127.0.0.1:8443 (hub /ws/agent byte-proxies) and the cs role's :443 listener is
# suppressed. Each module maps to its _ROLE_MAP role; install_agent.sh clones
# each role's repo + deps, and the agent's _role_post_install runs each heavy
# role's `--infra-only` host prep (cs Kea/NIC + cert; pxmx agent-host).
# NOTE (behavioural change): connection config (NetBox URL/token, OPNsense
# host/key, …) now comes from the hub push (configure it in the WebUI), not from
# a per-module .env. The NetBox *application* (Postgres/nginx) remains a separate
# install — the netbox role only talks to it.
AGENT_ID="agent-$(hostname -s)"
declare -A MODULE_ROLE=(
    ["cs"]="simulation" ["pxmx"]="proxmox" ["opnsense"]="opnsense"
    ["cppm"]="cppm" ["netbox"]="netbox" ["ldap"]="ldap"
    ["dns"]="dns" ["dhcp"]="dhcp" ["nw"]="network" ["le"]="le"
)
ROLES=()
for mod in cs pxmx opnsense cppm netbox ldap dns dhcp nw le; do
    skip=false
    for ex in "${EXCLUDE[@]}"; do [[ "$mod" == "$ex" ]] && skip=true && break; done
    if $skip; then
        log_c "⏭️  Skipping ${MODULE_ROLE[$mod]} role (module $mod excluded)"
        continue
    fi
    ROLES+=("${MODULE_ROLE[$mod]}")
done
ROLES_CSV="$(IFS=,; printf '%s' "${ROLES[*]}")"

# Pre-approve the AGENT id so it connects zero-touch; its role sub-spokes
# ({agent}-{role}) auto-approve via the parent — no per-role pre-approval.
log_c "✅ Pre-approving agent '$AGENT_ID'..."
curl -sf -X POST "$HUB_API/setup/approve_spoke" \
    -H "Content-Type: application/json" \
    -d "{\"spoke_id\":\"$AGENT_ID\",\"action\":\"approve\"}" > /dev/null \
    || log_w "Pre-approval failed for $AGENT_ID (agent will need manual approval)"

if [[ -z "$ROLES_CSV" ]]; then
    log_c "No roles to install (all modules excluded)."
else
    log_c "Installing unified agent '$AGENT_ID' with roles: $ROLES_CSV"
    # Reap any stale agent control_plane before (re)install so it can't hold a
    # role's listener port while the new one comes up.
    pkill -f "agent/src/control_plane.*--id ${AGENT_ID}" 2>/dev/null || true
    if ( bash "$BASE_DIR/agent/install_agent.sh" --hub "$HUB_WS" --id "$AGENT_ID" --roles "$ROLES_CSV" --loopback ); then
        log_c "  ✅ agent installed (roles: $ROLES_CSV)"
    else
        log_e "  ⚠️  agent installer exited non-zero — check journalctl -u lm-agent"
    fi
    systemctl restart lm-agent 2>/dev/null \
        || log_e "lm-agent failed to restart after install — check journalctl -u lm-agent"
fi

# 6. Log rotation — cap each log file at 10 MB, keep 5 compressed copies
log_c "🔄 Configuring log rotation..."
cat > /etc/logrotate.d/lm <<'LOGROTATE'
/var/log/lm/*.log {
    size 10M
    rotate 5
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
LOGROTATE

# 7. Persistence & Auto-start
log_c "⚙️ Configuring systemd for auto-start on reboot..."

# Final permission fix: ensure service user owns everything including files created by root during install
chown -R $SvcUser:$SvcUser "$BASE_DIR"

# Utility scripts (sync_secrets.sh, verify_auth.sh) live in the repo root and
# are already copied into $BASE_DIR by the `cp -r lm_tmp/* "$BASE_DIR/"` step
# above (~line 584), and ownership is fixed by the recursive chown at line 964.
# The previous block here was a no-op self-copy (`cp X X` source==dest) — removed.
# If a future change moves these scripts out of the repo root, re-add an explicit
# copy from the clone source here.

# ── Self-signed TLS cert for the hub's unified :443 wss surface ──
# With the cert present the hub serves wss on 0.0.0.0:443 (WebUI + REST +
# /ws/spoke + /ws/console); co-located spokes dial wss://127.0.0.1:443/ws/spoke
# with verify-off. Without a cert the hub serves plaintext 0.0.0.0:443. Skip
# gracefully if openssl is absent — the hub then falls back to plaintext :443.
TLS_CERT_DIR="$BASE_DIR/certs"
TLS_CERT="$TLS_CERT_DIR/hub.crt"
TLS_KEY="$TLS_CERT_DIR/hub.key"
mkdir -p "$TLS_CERT_DIR"
if ! command -v openssl >/dev/null 2>&1; then
    echo "⚠️  openssl not found — skipping hub TLS cert generation (hub stays plaintext)."
elif [ -f "$TLS_CERT" ] && [ -f "$TLS_KEY" ]; then
    echo "🔒 Hub TLS cert already present at $TLS_CERT — preserving."
else
    echo "🔒 Generating self-signed hub TLS cert at $TLS_CERT…"
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "$TLS_KEY" -out "$TLS_CERT" -days 3650 \
        -subj "/CN=lm-hub" \
        -addext "subjectAltName=IP:127.0.0.1,DNS:lm-hub,DNS:lm-hub.local" \
        >/dev/null 2>&1 || echo "⚠️  openssl cert generation failed — hub stays plaintext."
fi
if [ -f "$TLS_KEY" ]; then
    chmod 600 "$TLS_KEY"
    chown "$SvcUser:$SvcUser" "$TLS_KEY" "$TLS_CERT" 2>/dev/null || true
fi
# Resolve the verify flag into env values now that $TLS_CERT is defined.
# Co-located clients can verify against the hub's own generated cert (it doubles
# as the trust anchor); an explicit --tls-ca-cert overrides that.
if $TLS_VERIFY; then
    HUB_TLS_VERIFY_ENV=1
    HUB_TLS_CA_ENV="${TLS_CA_CERT:-$TLS_CERT}"
else
    HUB_TLS_VERIFY_ENV=0
    HUB_TLS_CA_ENV=""
fi

# Also surface the TLS knobs in .env so non-unit launches (start_all.sh) see them.
if ! grep -q "^LM_TLS_CERT=" "$BASE_DIR/.env" 2>/dev/null; then
    {
        echo "LM_TLS_CERT=$TLS_CERT"
        echo "LM_TLS_KEY=$TLS_KEY"
        echo "LM_TLS_PORT=443"
        echo "LM_PXMX_AGENT_PORT=8443"
        echo "LM_HUB_TLS_VERIFY=$HUB_TLS_VERIFY_ENV"
        [ -n "$HUB_TLS_CA_ENV" ] && echo "LM_HUB_CA_CERT=$HUB_TLS_CA_ENV"
    } >> "$BASE_DIR/.env"
fi
# A re-install with --tls-verify (or removing it) should update an existing .env
# rather than leaving a stale verify setting from a prior install.
if [ -f "$BASE_DIR/.env" ]; then
    sed -i "s|^LM_HUB_TLS_VERIFY=.*|LM_HUB_TLS_VERIFY=$HUB_TLS_VERIFY_ENV|" "$BASE_DIR/.env" 2>/dev/null || true
    if [ -n "$HUB_TLS_CA_ENV" ]; then
        grep -q "^LM_HUB_CA_CERT=" "$BASE_DIR/.env" 2>/dev/null \
            && sed -i "s|^LM_HUB_CA_CERT=.*|LM_HUB_CA_CERT=$HUB_TLS_CA_ENV|" "$BASE_DIR/.env" \
            || echo "LM_HUB_CA_CERT=$HUB_TLS_CA_ENV" >> "$BASE_DIR/.env"
    else
        sed -i "/^LM_HUB_CA_CERT=/d" "$BASE_DIR/.env" 2>/dev/null || true
    fi
fi

# Build the verify fragment for the unit Environment line (empty when off).
_TLS_CA_UNIT=""
[ -n "$HUB_TLS_CA_ENV" ] && _TLS_CA_UNIT=" LM_HUB_CA_CERT=$HUB_TLS_CA_ENV"

# Create the systemd service unit
cat <<EOF > /etc/systemd/system/lm.service
[Unit]
Description=Lab Manager Orchestrator
After=network.target

[Service]
# Type=exec + a direct ExecStart so systemd TRACKS the hub as MainPID. The old
# Type=oneshot + `ExecStart=start_all.sh` (which `nohup … main.py &` detached)
# left MainPID=0: no Restart/watchdog, `systemctl status` showed no process, and
# `systemctl restart lm` couldn't cleanly cycle the hub. start_all.sh launched
# only this one process on the hub box, so running main.py directly is
# equivalent (the hub's own self-restart path uses lm-update-restart /
# systemd-run and is unaffected).
Type=exec
User=$SvcUser
WorkingDirectory=$BASE_DIR
EnvironmentFile=-$BASE_DIR/.env
# Unified :443 surface: the hub's single uvicorn serves WebUI + REST + /ws/spoke
# + /ws/agent + /ws/console on 0.0.0.0:443 (wss with a cert, plaintext without).
# /ws/agent byte-proxies to the co-located pxmx spoke's loopback
# LM_PXMX_AGENT_PORT (127.0.0.1:8443 plaintext — TLS terminates here at 443; the
# pxmx spoke runs LM_PXMX_AGENT_LOOPBACK=1 via its own unit). Cert verification
# is OFF by default (self-signed → encrypt without auth); --tls-verify at
# install sets LM_HUB_TLS_VERIFY=1 + LM_HUB_CA_CERT so co-located
# spokes/agents verify. AmbientCapabilities lets svc_lm bind the privileged
# 443 without being root.
Environment=LM_TLS_PORT=443 LM_PXMX_AGENT_PORT=8443 LM_HUB_TLS_VERIFY=$HUB_TLS_VERIFY_ENV$_TLS_CA_UNIT
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
ExecStart=$BASE_DIR/core/venv/bin/python3 $BASE_DIR/core/src/main.py
StandardOutput=append:$LOG_DIR/hub.log
StandardError=append:$LOG_DIR/hub.log
# No ExecStop needed: Type=exec makes systemd SIGTERM MainPID (and reap the
# cgroup) on stop — precise, and it no longer nukes gunicorn/netbox-rq/spokes
# the way the old `pkill` sweep risked.
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Enable and start the service
systemctl daemon-reload
systemctl enable lm
systemctl restart lm

# ── Auto-heal watchdog ──────────────────────────────────────────────────────
# A root-owned supervisor (its OWN unit, outside lm.service's cgroup) that heals
# two failures lm.service can't fix itself: (1) a WEDGED event loop — the process
# stays "active" so Restart= never fires but :443 stops serving (and a hung loop
# ignores SIGTERM, so `systemctl restart` hangs); (2) the legacy generic-agent
# zombie the hub detects but can't remove as svc_lm. Force-restarts the hub
# (SIGKILL + free the port) and purges the zombie, every 60s.
# KEEP THE lm-watchdog BODY IN SYNC WITH scripts/install-lm-watchdog.sh.
log_c "🩺 Installing hub auto-heal watchdog (lm-watchdog.timer)..."
cat > /usr/local/bin/lm-watchdog <<'WD'
#!/bin/bash
# Lab Manager hub auto-heal. Runs every 60s as root via lm-watchdog.timer,
# OUTSIDE lm.service's cgroup. KEEP IN SYNC WITH scripts/install-lm-watchdog.sh.
set -uo pipefail
MAX_FAILS="${LM_WATCHDOG_MAX_FAILS:-3}"
STATE=/var/lib/lm/watchdog-fails
LOG=/var/log/lm/watchdog.log
log(){ printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >> "$LOG" 2>/dev/null; }
hub_healthy(){
  local url code
  for url in "https://127.0.0.1:443/status" "http://127.0.0.1:443/status" "http://127.0.0.1:8000/status"; do
    code=$(curl -sk -m 8 -o /dev/null -w '%{http_code}' "$url" 2>/dev/null || echo 000)
    [ "$code" = 200 ] && return 0
  done
  return 1
}
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
          command -v fuser >/dev/null 2>&1 && fuser -k -9 443/tcp 8000/tcp 2>/dev/null || true
          sleep 2
          timeout 60 systemctl restart lm.service 2>/dev/null \
            || timeout 30 systemctl start lm.service 2>/dev/null || true
          rm -f "$STATE"
          log "hub restart issued"
        fi
      fi
      ;;
    failed)
      log "lm.service FAILED (start-limit) — reset-failed + start"
      systemctl reset-failed lm.service 2>/dev/null || true
      timeout 30 systemctl start lm.service 2>/dev/null || true
      rm -f "$STATE"
      ;;
    *) rm -f "$STATE" ;;
  esac
fi
names="lm-generic-agent lm-bootstrap"
for f in /etc/systemd/system/*.service /run/systemd/system/*.service \
         /lib/systemd/system/*.service /usr/lib/systemd/system/*.service; do
  [ -e "$f" ] || continue
  grep -qE "/opt/lm/generic-agent" "$f" 2>/dev/null && names="$names $(basename "$f" .service)"
done
purged=0
for svc in $(printf '%s\n' $names | sort -u); do
  [ -n "$svc" ] || continue
  [ "$svc" = lm ] && continue
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
systemctl enable --now lm-watchdog.timer 2>/dev/null || true

log_c "🔄 Restarting spoke services to connect with hub..."
# Include the NetBox app units (netbox/netbox-rq) so the installer guarantees
# the app is up at the end of a run, even if something earlier stopped them.
# Guarded by `systemctl is-enabled` so this is a no-op on hosts that use an
# external NetBox (no local app units present).
for svc in netbox netbox-rq lm-netbox lm-ldap lm-dns lm-dhcp lm-nw; do
    if systemctl is-enabled "$svc" >/dev/null 2>&1; then
        systemctl reset-failed "$svc" 2>/dev/null || true
        # Gate the success log on the actual restart exit code so a failed
        # restart is surfaced (log_e) instead of an unconditional ✅ masking it.
        if systemctl restart "$svc"; then
            log_c "  ✅ $svc restarted"
        else
            log_e "  ⚠️  $svc failed to restart — check journalctl -u $svc"
        fi
    fi
done

# ------------------------------------------------------------------
# 7. Post-Installation Auth Verification & Self-Healing
# ------------------------------------------------------------------
log_c "🔍 Running final authentication verification..."
if [ -f "$BASE_DIR/verify_auth.sh" ]; then
    bash "$BASE_DIR/verify_auth.sh"
else
    log_e "Verification script verify_auth.sh not found. Skipping final auth check."
fi

echo ""
log_c "🎉 Native installation complete!"
log_c "📂 All modules are located in: $BASE_DIR"
log_c "⚙️ Service 'lm' is enabled and running."
log_c "🚀 To manage the system: systemctl start|stop|restart lm"
log_c "🌐 Hub API & Dashboard: https://$(hostname -I | awk '{print $1}'):443  (wss; --tls-verify off by default → accept the self-signed cert)"
log_c "📦 Version: $(cat "$BASE_DIR/core/VERSION" 2>/dev/null || echo unknown)"
log_c "📝 Logs: $INSTALL_LOG (install) and $LOG_DIR/hub.log (hub runtime) — check these if the hub later misbehaves."
