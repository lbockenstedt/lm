#!/usr/bin/env bash
# Lab Manager — Unbound DNS Spoke Installer
# Called by install_all.sh; source is already present at $INSTALL_DIR/dns
set -euo pipefail

INSTALL_DIR="/opt/lm"
SERVICE_NAME="lm-dns"
ENV_FILE="$INSTALL_DIR/dns/.env"

HUB_URL=""; SPOKE_ID=""; SPOKE_SECRET=""; INFRA_ONLY=false
# Cluster-worker mode: this host is one of N Unbound resolvers driven by a
# single DNS module. All three must be supplied together.
MEMBER_ID=""; COORDINATOR=""; WORKER_SECRET=""
STAND_DOWN=false
WORKER_SERVICE="lm-dns-worker"
WORKER_ENV="/etc/lm-dns-worker/worker.env"
# Runtime dirs the DNS module (coordinator) owns. Created + chowned so the
# unprivileged service account can actually write its cluster config and the
# durable desired state — the coordinator fails CLOSED on a write error, so an
# unwritable dir would block every record change.
SVC_USER="svc_lm"
COORD_DIRS=("/etc/lm-dns" "/var/lib/lm-dns")
# Coordinator listener TLS. Workers verify this certificate against the CA
# handed to them (--ca-cert), so the listener is never plaintext and never
# unverified. A self-signed pair is generated when none is supplied.
TLS_DIR="/etc/lm-dns/tls"
TLS_CERT="$TLS_DIR/coordinator.crt"
TLS_KEY="$TLS_DIR/coordinator.key"
COORD_CERT=""; COORD_KEY=""; COORD_SAN=""
WORKER_CA=""
LM_REPO="https://github.com/lbockenstedt/lm.git"

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --hub)    HUB_URL="$2";      shift ;;
        --id)     SPOKE_ID="$2";     shift ;;
        --secret) SPOKE_SECRET="$2"; shift ;;
        # Deploy-role mode: install the Unbound SERVER only (no lm-dns spoke unit).
        # The DNS module that manages it is the SEPARATE "dns" role. Mirrors
        # netbox/ldap --infra-only.
        --infra-only) INFRA_ONLY=true ;;
        # Cluster-worker mode (see --member-id below): install Unbound AND the
        # lm-dns-worker unit that dials the managing DNS module's coordinator
        # listener, so this resolver is driven as one member of a cluster
        # instead of standing alone. Implies --infra-only (no lm-dns spoke here
        # — the module lives on the coordinator).
        --member-id)     MEMBER_ID="$2";     INFRA_ONLY=true; shift ;;
        --coordinator)   COORDINATOR="$2";   INFRA_ONLY=true; shift ;;
        --worker-secret) WORKER_SECRET="$2"; INFRA_ONLY=true; shift ;;
        # Worker trust anchor: the coordinator's cert (or its CA). Written to
        # /etc/lm-dns-worker/coordinator-ca.pem and pinned via LM_CLUSTER_CA_CERT.
        --ca-cert)       WORKER_CA="$2";     shift ;;
        # Coordinator listener material. Omitted -> a self-signed pair is minted.
        --tls-cert)      COORD_CERT="$2";    shift ;;
        --tls-key)       COORD_KEY="$2";     shift ;;
        --tls-san)       COORD_SAN="$2";     shift ;;
        # Leave the cluster: stop the worker. Runs before the --hub validation.
        --stand-down)    STAND_DOWN=true ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac; shift
done

# --stand-down: this resolver was removed from the cluster. Runs BEFORE the
# --hub validation, because recovery must not require a hub argument for a node
# that no longer belongs to any coordinator. Unbound and its records are left
# alone — stopping them would blackhole every client still pointed here.
if [[ "$STAND_DOWN" == true ]]; then
    systemctl disable --now lm-dns-worker 2>/dev/null || true
    rm -f /etc/lm-dns-worker/worker.env /var/lib/lm-dns-worker/applied.json
    systemctl daemon-reload 2>/dev/null || true
    echo "DNS cluster worker stopped; this resolver left the cluster."
    echo "Unbound and its records are untouched and still answering."
    exit 0
fi

# Accept a bare hub IP/host for --hub (e.g. `--hub 172.16.1.31` == `--hub
# wss://172.16.1.31:443`). A ws://|wss:// scheme or the "auto" sentinel is left
# as-is; host:port gets a scheme; a bare host defaults to the unified :443.
if [ -n "${HUB_URL:-}" ] && [ "$HUB_URL" != "auto" ]; then
    case "$HUB_URL" in
        ws://*|wss://*) : ;;
        *:[0-9]*)       HUB_URL="wss://${HUB_URL}" ;;
        *)              HUB_URL="wss://${HUB_URL}:443" ;;
    esac
fi

if [[ "$INFRA_ONLY" == false && -z "$HUB_URL" ]]; then
    echo "Usage: $0 --hub <ws://HUB:8765> [--id dns-spoke-1]  |  --infra-only"; exit 1
fi
SPOKE_ID="${SPOKE_ID:-${SERVICE_NAME}-$(hostname -s)}"
mkdir -p /var/log/lm

# Unbound's per-name query-log directory. Owned by the "unbound" system user
# (not $SVC_USER) since unbound itself opens/writes the logfile there; the
# coordinator only tails it. Without this, unbound-managed's self-enabled
# log-queries conf silently writes nothing (permission denied is swallowed by
# unbound's log_init()) and DNS statistics' per-destination breakdown stays
# empty forever. unbound_manager.py also re-chowns this on each poll as a
# self-heal in case the dir gets recreated with the wrong owner.
install -d -m 0755 /var/log/unbound
if id -u unbound >/dev/null 2>&1; then
    chown unbound:unbound /var/log/unbound
fi

# Coordinator state/config dirs, writable by the account the lm-dns unit runs as.
for d in "${COORD_DIRS[@]}"; do
    install -d -m 0750 "$d"
    if id -u "$SVC_USER" >/dev/null 2>&1; then
        chown "$SVC_USER":"$SVC_USER" "$d"
    fi
done

# Coordinator listener certificate. The cluster listener REFUSES to bind
# plaintext on a public interface, so without this a clustered DNS module would
# simply never come up. Self-signed by default; the worker pins this exact
# certificate as its trust anchor.
provision_coordinator_tls() {
    install -d -m 0750 "$TLS_DIR"
    if [[ -n "$COORD_CERT" && -n "$COORD_KEY" ]]; then
        install -m 0644 "$COORD_CERT" "$TLS_CERT"
        install -m 0640 "$COORD_KEY"  "$TLS_KEY"
    elif [[ ! -s "$TLS_CERT" || ! -s "$TLS_KEY" ]]; then
        local san="${COORD_SAN:-$(hostname -f 2>/dev/null || hostname -s)}"
        local ips
        ips=$(hostname -I 2>/dev/null || true)
        local altnames="DNS:${san}"
        for ip in $ips; do altnames="${altnames},IP:${ip}"; done
        openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
            -keyout "$TLS_KEY" -out "$TLS_CERT" \
            -subj "/CN=${san}" -addext "subjectAltName=${altnames}" >/dev/null 2>&1
        chmod 0644 "$TLS_CERT"; chmod 0640 "$TLS_KEY"
        echo "Minted a self-signed coordinator certificate (${altnames})."
    fi
    if id -u "$SVC_USER" >/dev/null 2>&1; then
        chown "$SVC_USER":"$SVC_USER" "$TLS_DIR" "$TLS_CERT" "$TLS_KEY" 2>/dev/null || true
    fi
}

# Circular logging: cap /var/log/lm/*.log so it can't fill the disk (copytruncate
# keeps the inode → the running spoke's O_APPEND FileHandler + systemd stderr
# keep appending). Belt-and-suspenders alongside logging_setup's RotatingFileHandler.
cat > /etc/logrotate.d/lm <<'LOGROTATE'
/var/log/lm/*.log /var/log/client-sim-*.log {
    su root root
    size 50M
    rotate 5
    missingok
    notifempty
    compress
    delaycompress
    copytruncate
}
LOGROTATE

# Unbound. -o DPkg::Lock::Timeout makes apt WAIT for the dpkg lock rather than
# dying with rc=100 when this deploy collides with another apt user (a sibling
# role deploy, an LM OS update, unattended-upgrades). Set explicitly as well as
# via /etc/apt/apt.conf.d/99lm-lock-timeout so the deploy is safe even on a node
# whose agent has not yet dropped that file.
apt-get -o DPkg::Lock::Timeout=600 install -y -qq unbound
grep -q "control-enable: yes" /etc/unbound/unbound.conf 2>/dev/null || cat >> /etc/unbound/unbound.conf <<'UNBOUNDCFG'

remote-control:
    control-enable: yes
    control-interface: 127.0.0.1
    control-port: 8953
UNBOUNDCFG

# Listen on all interfaces + allow LAN clients. Unbound defaults to 127.0.0.1
# ONLY and REFUSES non-local queries, so the DNS role would never answer a query
# sent to its LAN IP — it looks like "no response / firewall" even with the
# firewall off. Idempotent: guarded on the interface line.
grep -q "interface: 0.0.0.0" /etc/unbound/unbound.conf 2>/dev/null || cat >> /etc/unbound/unbound.conf <<'UNBOUNDSRV'

server:
    interface: 0.0.0.0
    access-control: 127.0.0.0/8 allow
    access-control: 10.0.0.0/8 allow
    access-control: 172.16.0.0/12 allow
    access-control: 192.168.0.0/16 allow
    access-control: 169.254.0.0/16 allow
UNBOUNDSRV
# Per-query-type counters (num.query.type.A, AAAA, PTR, ...) are omitted from
# stats_noreset unless extended statistics are enabled. Keep this independent
# of the listener block above so an existing install self-heals on re-run.
grep -qE '^[[:space:]]*extended-statistics:[[:space:]]*yes' /etc/unbound/unbound.conf 2>/dev/null || cat >> /etc/unbound/unbound.conf <<'UNBOUNDSTATS'

server:
    extended-statistics: yes
UNBOUNDSTATS
mkdir -p /etc/unbound/conf.d
grep -q "conf\.d" /etc/unbound/unbound.conf 2>/dev/null \
    || echo 'include-toplevel: "/etc/unbound/conf.d/*.conf"' >> /etc/unbound/unbound.conf
unbound-control-setup 2>/dev/null || true
# Non-fatal: if unbound refuses to start (e.g. a config it rejects on some
# version), still install/start the lm-dns spoke below instead of aborting the
# whole install under `set -e` — the spoke must reach --hub regardless.
systemctl enable --now unbound || echo "⚠️  unbound failed to start — DNS spoke will still install; check 'unbound-checkconf'"
if systemctl is-active --quiet unbound; then
    unbound-control reload >/dev/null 2>&1 || systemctl restart unbound
fi

# Cluster worker: this resolver is one member of a DNS cluster. Lay down the
# lm-dns-worker unit that dials the coordinator's /ws/agent listener. The worker
# executes a FIXED op table (apply record set / report state / status /
# diagnostics / stats) — it is not a general-purpose agent.
if [[ -n "$MEMBER_ID" || -n "$COORDINATOR" || -n "$WORKER_SECRET" ]]; then
    if [[ -z "$MEMBER_ID" || -z "$COORDINATOR" || -z "$WORKER_SECRET" ]]; then
        echo "--member-id, --coordinator and --worker-secret must be given together"; exit 1
    fi
    # Accept a bare coordinator host (`--coordinator 10.0.1.9`); 8769 is the DNS
    # module's cluster listener port (pxmx 8766 / cs 8767 / hub-self 8768).
    # Default to wss:// — the worker sends its PSK in the first handshake frame,
    # so a plaintext hop off-box would publish the cluster credential. A ws://
    # URL to a NON-loopback host is rejected outright rather than upgraded, so
    # the operator finds out instead of silently getting what they asked for.
    case "$COORDINATOR" in
        ws://*|wss://*) : ;;
        *:[0-9]*)       COORDINATOR="wss://${COORDINATOR}" ;;
        *)              COORDINATOR="wss://${COORDINATOR}:8769" ;;
    esac
    case "$COORDINATOR" in
        ws://localhost*|ws://127.*|ws://[::1]*) : ;;
        ws://*)
            echo "Refusing plaintext ws:// to a remote coordinator: the worker"
            echo "secret is sent in the handshake. Use wss:// (or a loopback"
            echo "address when TLS terminates upstream)."; exit 1 ;;
    esac
    case "$COORDINATOR" in
        */ws/agent) : ;;
        *)          COORDINATOR="${COORDINATOR%/}/ws/agent" ;;
    esac

    # The worker runs from the lm checkout (dns/src + core/src). A resolver host
    # deployed via the curl-piped installer has no source yet — clone it. If
    # it already exists (re-running this installer on an already-provisioned
    # host), pull latest instead of silently no-op'ing: this worker has no
    # other self-update mechanism, so "re-run the installer to pick up a fix"
    # must actually update the code or every such instruction is a no-op.
    if [[ ! -f "$INSTALL_DIR/dns/src/dns_worker.py" ]]; then
        apt-get install -y -qq git
        rm -rf "$INSTALL_DIR.tmp-clone"
        git clone --depth 1 "$LM_REPO" "$INSTALL_DIR.tmp-clone"
        mkdir -p "$INSTALL_DIR"
        cp -a "$INSTALL_DIR.tmp-clone/." "$INSTALL_DIR/"
        rm -rf "$INSTALL_DIR.tmp-clone"
    elif [[ -d "$INSTALL_DIR/.git" ]]; then
        echo "Existing checkout at $INSTALL_DIR — pulling latest before (re)install."
        git -C "$INSTALL_DIR" fetch --depth 1 origin HEAD
        git -C "$INSTALL_DIR" reset --hard FETCH_HEAD
    fi
    if [[ ! -x "$INSTALL_DIR/dns/venv/bin/python3" ]]; then
        apt-get install -y -qq python3-venv
        python3 -m venv "$INSTALL_DIR/dns/venv"
    fi
    "$INSTALL_DIR/dns/venv/bin/pip" install --upgrade pip -q
    [[ -f "$INSTALL_DIR/dns/requirements.txt" ]] && \
        "$INSTALL_DIR/dns/venv/bin/pip" install -r "$INSTALL_DIR/dns/requirements.txt" -q

    mkdir -p "$(dirname "$WORKER_ENV")" /var/lib/lm-dns-worker
    # Trust anchor for the coordinator's cert. Verification is MANDATORY on this
    # leg (the PSK rides in the handshake), so refuse to install a worker that
    # has nothing to verify against.
    WORKER_CA_PATH="/etc/lm-dns-worker/coordinator-ca.pem"
    if [[ -n "$WORKER_CA" ]]; then
        if [[ "$(readlink -f "$WORKER_CA")" != "$(readlink -f "$WORKER_CA_PATH")" ]]; then
            install -m 0644 "$WORKER_CA" "$WORKER_CA_PATH"
        else
            chmod 0644 "$WORKER_CA_PATH"
        fi
    elif [[ ! -s "$WORKER_CA_PATH" ]]; then
        echo "--ca-cert is required: the worker verifies the coordinator's"
        echo "certificate before sending its secret. Copy the coordinator's"
        echo "$TLS_CERT to this host and pass it as --ca-cert."; exit 1
    fi
    cat > "$WORKER_ENV" <<EOF
LM_DNS_MEMBER_ID=$MEMBER_ID
LM_DNS_COORDINATOR=$COORDINATOR
LM_DNS_WORKER_SECRET=$WORKER_SECRET
LM_CLUSTER_CA_CERT=$WORKER_CA_PATH
LM_CLUSTER_TLS_CHECK_HOSTNAME=0
EOF
    chmod 600 "$WORKER_ENV"

    cat > /etc/systemd/system/${WORKER_SERVICE}.service <<EOF
[Unit]
Description=Lab Manager DNS Cluster Worker (Unbound)
After=network-online.target unbound.service
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=$WORKER_ENV
Environment="PYTHONPATH=$INSTALL_DIR:$INSTALL_DIR/core/src:$INSTALL_DIR/dns/src"
WorkingDirectory=$INSTALL_DIR/dns/src
ExecStart=$INSTALL_DIR/dns/venv/bin/python3 dns_worker.py --id \$LM_DNS_MEMBER_ID
StandardOutput=append:/var/log/lm/lm-dns-worker.log
StandardError=append:/var/log/lm/lm-dns-worker.log
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now "$WORKER_SERVICE"
    echo "DNS cluster worker installed (member: $MEMBER_ID → $COORDINATOR)"
    exit 0
fi

# Deploy-role: server-only. The lm-dns spoke that manages this Unbound is loaded
# SEPARATELY as the "dns" role (module_type dns), exactly like netbox-server /
# ldap-server + their client modules. Skip the spoke venv/.env/unit below.
if [[ "$INFRA_ONLY" == true ]]; then
    echo "DNS server (Unbound) installed (infra-only) — load the 'dns' role to manage it."
    exit 0
fi

# Python venv
cd "$INSTALL_DIR/dns"
python3 -m venv venv
./venv/bin/pip install --upgrade pip -q
[[ -f requirements.txt ]] && ./venv/bin/pip install -r requirements.txt -q

# Preserve existing secret across re-installs; otherwise start without one (zero-touch).
if [[ -f "$ENV_FILE" ]] && grep -q "^SPOKE_SECRET=.\+" "$ENV_FILE"; then
    SPOKE_SECRET=$(grep "^SPOKE_SECRET=" "$ENV_FILE" | cut -d= -f2-)
    echo "Preserving existing SPOKE_SECRET."
elif [[ -z "$SPOKE_SECRET" ]]; then
    echo "ℹ️  No pre-shared secret — spoke will connect unauthenticated and await admin approval."
fi

# Preserve the minted INSTALL_UUID so a re-install keeps the same hub-side
# fingerprint (install_uuid). Without this the cat > below wipes the line and
# the spoke mints a fresh UUID on next start → hub records a `reimaged`
# (fingerprint-changed) event for a box that was only updated.
# _ensure_install_uuid mints on first start only when this line is absent.
INSTALL_UUID_LINE=""
if [[ -f "$ENV_FILE" ]] && grep -q "^INSTALL_UUID=.\+" "$ENV_FILE"; then
    EXISTING_UUID=$(grep "^INSTALL_UUID=" "$ENV_FILE" | cut -d= -f2-)
    [[ -n "$EXISTING_UUID" ]] && INSTALL_UUID_LINE="INSTALL_UUID=$EXISTING_UUID" \
        && echo "Preserving existing install UUID (hub fingerprint)."
fi

cat > "$ENV_FILE" <<EOF
SPOKE_ID=$SPOKE_ID
SPOKE_SECRET=$SPOKE_SECRET
HUB_URL=$HUB_URL
${INSTALL_UUID_LINE}
EOF
chmod 600 "$ENV_FILE"

provision_coordinator_tls

cat > /etc/systemd/system/${SERVICE_NAME}.service <<EOF
[Unit]
Description=Lab Manager DNS Spoke (Unbound)
After=network-online.target unbound.service
Wants=network-online.target

[Service]
Type=simple
User=svc_lm
EnvironmentFile=$ENV_FILE
Environment="PYTHONPATH=$INSTALL_DIR/core/src:$INSTALL_DIR/dns/src"
Environment="LM_TLS_CERT=$TLS_CERT"
Environment="LM_TLS_KEY=$TLS_KEY"
WorkingDirectory=$INSTALL_DIR/dns/src
ExecStart=$INSTALL_DIR/dns/venv/bin/python3 control_plane.py --id \$SPOKE_ID --hub \$HUB_URL
StandardOutput=append:/var/log/lm/lm-dns.log
StandardError=append:/var/log/lm/lm-dns.log
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now "$SERVICE_NAME"
echo "DNS spoke installed (ID: $SPOKE_ID)"
