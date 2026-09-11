#!/usr/bin/env bash
# Lab Manager — Kea DHCP Spoke Installer
# Called by install_all.sh; source is already present at $INSTALL_DIR/dhcp
set -euo pipefail

INSTALL_DIR="/opt/lm"
SERVICE_NAME="lm-dhcp"
ENV_FILE="$INSTALL_DIR/dhcp/.env"

HUB_URL=""; SPOKE_ID=""; SPOKE_SECRET=""; INFRA_ONLY=false
# HA-worker mode: this host is one node of a Kea HA pair driven by a single
# DHCP module. All three must be supplied together.
MEMBER_ID=""; COORDINATOR=""; WORKER_SECRET=""
# HA peer traffic gets its OWN authenticated control agent on its own port. The
# node-local agent on 8001 stays loopback-only and unauthenticated (only the
# co-located worker may drive Kea); publishing that one would hand unauthenticated
# config-set rights to anyone who can reach the box.
HA_PORT="8002"; HA_USER="kea-ha"; HA_PASSWORD=""; HA_PEERS=()
# HA peer channel TLS. Both ends present a cert and verify the other against the
# shared HA trust anchor; the basic-auth credentials ride INSIDE that session.
HA_TLS_DIR="/etc/kea/ha-tls"
HA_CA="$HA_TLS_DIR/ha-ca.pem"
HA_CERT="$HA_TLS_DIR/node.crt"
HA_KEY="$HA_TLS_DIR/node.key"
HA_CA_IN=""; HA_CERT_IN=""; HA_KEY_IN=""
STAND_DOWN=false
WORKER_SERVICE="lm-dhcp-worker"
HA_AGENT_SERVICE="kea-ha-agent"
HA_AGENT_CONF="/etc/kea/kea-ha-agent.conf"
WORKER_ENV="/etc/lm-dhcp-worker/worker.env"
# Runtime dirs the DHCP module (coordinator) owns. Created + chowned so the
# unprivileged service account can actually write its HA topology and durable
# desired state instead of failing closed on every save.
SVC_USER="svc_lm"
COORD_DIRS=("/etc/lm-dhcp" "/var/lib/lm-dhcp")
TLS_DIR="/etc/lm-dhcp/tls"
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
        # Deploy-role mode: install the Kea SERVER only (no lm-dhcp spoke unit).
        # The DHCP module that manages it is the SEPARATE "dhcp" role. Mirrors
        # netbox/ldap --infra-only.
        --infra-only) INFRA_ONLY=true ;;
        # HA-worker mode: install Kea AND the lm-dhcp-worker unit that dials the
        # managing DHCP module's coordinator listener, so this node is driven as
        # one half of an HA pair instead of standing alone. Implies --infra-only
        # (no lm-dhcp spoke here — the module lives on the coordinator).
        --member-id)     MEMBER_ID="$2";     INFRA_ONLY=true; shift ;;
        --coordinator)   COORDINATOR="$2";   INFRA_ONLY=true; shift ;;
        --worker-secret) WORKER_SECRET="$2"; INFRA_ONLY=true; shift ;;
        # HA peer channel: a SECOND control agent, basic-auth protected and
        # firewalled to the partner. Never the loopback-only 8001 agent.
        --ha-port)       HA_PORT="$2";       shift ;;
        --ha-user)       HA_USER="$2";       shift ;;
        --ha-password)   HA_PASSWORD="$2";   shift ;;
        --ha-peer)       HA_PEERS+=("$2");   shift ;;
        # HA channel TLS material (mutual verification between the two nodes).
        --ha-ca)         HA_CA_IN="$2";      shift ;;
        --ha-cert)       HA_CERT_IN="$2";    shift ;;
        --ha-key)        HA_KEY_IN="$2";     shift ;;
        # Cluster-worker trust anchor + coordinator listener material.
        --ca-cert)       WORKER_CA="$2";     shift ;;
        --tls-cert)      COORD_CERT="$2";    shift ;;
        --tls-key)       COORD_KEY="$2";     shift ;;
        --tls-san)       COORD_SAN="$2";     shift ;;
        # Leave the pair: stop the worker + HA agent and drop the HA hooks.
        --stand-down)    STAND_DOWN=true ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac; shift
done

# --stand-down: this node was removed from the HA topology. Runs BEFORE the
# --hub validation below, because recovery must not require the hub argument:
# the whole point of this flag is to clean up a node that no longer belongs to
# any coordinator, and demanding --hub made the documented recovery command exit
# with a usage error.
if [[ "$STAND_DOWN" == true ]]; then
    systemctl disable --now lm-dhcp-worker 2>/dev/null || true
    systemctl disable --now kea-ha-agent 2>/dev/null || true
    rm -f /etc/nftables.d/lm-kea-ha.nft /etc/systemd/system/kea-ha-agent.service
    rm -f /etc/lm-dhcp-worker/worker.env
    if command -v nft >/dev/null 2>&1; then
        nft delete table inet lm_kea_ha 2>/dev/null || true
    fi
    if command -v iptables >/dev/null 2>&1; then
        iptables -D INPUT -p tcp --dport "$HA_PORT" -j LM_KEA_HA 2>/dev/null || true
        iptables -F LM_KEA_HA 2>/dev/null || true
        iptables -X LM_KEA_HA 2>/dev/null || true
        netfilter-persistent save 2>/dev/null || true
    fi
    systemctl daemon-reload 2>/dev/null || true
    echo "Kea HA worker + HA control agent stopped; this node left the pair."
    echo "Kea itself is still serving its own scopes."
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
    echo "Usage: $0 --hub <ws://HUB:8765> [--id dhcp-spoke-1]  |  --infra-only"; exit 1
fi
SPOKE_ID="${SPOKE_ID:-${SERVICE_NAME}-$(hostname -s)}"
mkdir -p /var/log/lm

# Coordinator state/config dirs. The lm-dhcp unit runs as svc_lm, so these must
# exist AND be writable by it — otherwise the HA topology save and the durable
# desired-state write both fail closed on a freshly installed box.
for d in "${COORD_DIRS[@]}"; do
    install -d -m 0750 "$d"
    if id -u "$SVC_USER" >/dev/null 2>&1; then
        chown "$SVC_USER":"$SVC_USER" "$d"
    fi
done

# Coordinator listener certificate — the cluster listener refuses to bind
# plaintext on a public interface, so a clustered DHCP module cannot come up
# without one. Workers pin this exact certificate.
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

# Kea DHCP4 + Control Agent — noninteractive prevents credential prompts.
# -o DPkg::Lock::Timeout makes apt WAIT for the dpkg lock rather than dying with
# rc=100 when this deploy collides with another apt user (a sibling role deploy,
# an LM OS update, unattended-upgrades). Set explicitly as well as via
# /etc/apt/apt.conf.d/99lm-lock-timeout so the deploy is safe even on a node
# whose agent has not yet dropped that file.
DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 install -y -qq kea-dhcp4-server kea-ctrl-agent

# The Debian kea-dhcp4-server package creates /etc/kea at mode 0750, but its
# own systemd unit's ConfigurationDirectory=kea expects 0755 — the mismatch
# doesn't stop the service, but systemd logs
# "ConfigurationDirectory 'kea' already exists but the mode is different"
# on every start/reload. Realign it unconditionally (not just in the HA
# branch below, which only runs for HA-worker installs) so plain/non-HA
# installs don't carry this warning either.
chmod 0755 /etc/kea 2>/dev/null || true

# Write a clean kea-ctrl-agent config: loopback-only, port 8001, no auth.
# The default Debian package config may prompt for HTTP auth credentials;
# this replaces it unconditionally so the install is fully non-interactive.
KEA_CA_CONF="/etc/kea/kea-ctrl-agent.conf"
cat > "$KEA_CA_CONF" <<'KEACONF'
{
    "Control-agent": {
        "http-host": "127.0.0.1",
        "http-port": 8001,
        "control-sockets": {
            "dhcp4": {
                "socket-type": "unix",
                "socket-name": "/run/kea/kea4-ctrl-socket"
            }
        },
        "loggers": [{
            "name": "kea-ctrl-agent",
            "output_options": [{"output": "syslog"}],
            "severity": "WARN"
        }]
    }
}
KEACONF

# The packaged kea-ctrl-agent.service unit gates startup on
# ConditionFileNotEmpty=/etc/kea/kea-api-password — even though the config
# above uses no HTTP basic-auth at all. Without this file present and
# non-empty, systemd silently SKIPS starting the unit on every boot/enable
# (no error, ActiveState stays inactive, "systemctl status" just shows
# "skipped, unmet condition check"), which is exactly what made the Kea
# CA unreachable at http://localhost:8001 while kea-dhcp4-server itself was
# fine. The content is never read/validated by kea-ctrl-agent (auth is off
# in the JSON config), it only has to exist and be non-empty, so a random
# placeholder satisfies the condition without weakening anything.
if [[ ! -s /etc/kea/kea-api-password ]]; then
    head -c 32 /dev/urandom | base64 > /etc/kea/kea-api-password
    chmod 640 /etc/kea/kea-api-password
    chgrp _kea /etc/kea/kea-api-password 2>/dev/null || true
fi

# The Debian kea-dhcp4-server package ships /etc/kea/kea-dhcp4.conf with a
# built-in demo "subnet4": [{"subnet": "192.0.2.0/24", ...}] entry. The LM
# worker's sync() always fully replaces subnet4 once a real NetBox sync has
# run, but on a fresh install — before that first sync — this stock demo
# subnet is visible in diagnostics/UI and looks like a real (broken) config.
# Strip it here so a freshly-installed node starts with an empty subnet4
# instead of the packaged placeholder.
KEA_DHCP4_CONF="/etc/kea/kea-dhcp4.conf"
if [[ -f "$KEA_DHCP4_CONF" ]]; then
    python3 - "$KEA_DHCP4_CONF" <<'PYEOF'
import json, sys
path = sys.argv[1]
with open(path) as f:
    cfg = json.load(f)
dhcp4 = cfg.get("Dhcp4", cfg)
if dhcp4.get("subnet4"):
    dhcp4["subnet4"] = []
    with open(path, "w") as f:
        json.dump(cfg, f, indent=2)
PYEOF
fi

# Non-fatal: the distro Kea often fails to start on a fresh box (no subnets/
# interfaces yet), but the lm-dhcp spoke talks to the ctrl-agent at RUNTIME and
# doesn't need Kea already up at install time — don't abort under `set -e`.
systemctl enable --now kea-ctrl-agent kea-dhcp4-server || echo "⚠️  Kea failed to start — DHCP spoke will still install; configure Kea via the module"

# HA worker: this node is one half of a Kea HA pair. Install the HA hook
# libraries (the HA hook cannot synchronise leases without lease_cmds) and the
# lm-dhcp-worker unit that dials the coordinator's /ws/agent listener. The
# worker executes a FIXED op table (install-hooks / validate / apply / rollback
# / ha-status / lists / diagnostics) — it is not a general-purpose agent.
if [[ -n "$MEMBER_ID" || -n "$COORDINATOR" || -n "$WORKER_SECRET" ]]; then
    if [[ -z "$MEMBER_ID" || -z "$COORDINATOR" || -z "$WORKER_SECRET" ]]; then
        echo "--member-id, --coordinator and --worker-secret must be given together"; exit 1
    fi
    if [[ -z "$HA_PASSWORD" ]]; then
        echo "--ha-password is required for an HA member: the HA control agent"
        echo "must never accept an unauthenticated peer."; exit 1
    fi

    # The node-local control agent (8001, written above) stays LOOPBACK-ONLY and
    # is left untouched. HA peer traffic gets a DEDICATED agent on $HA_PORT with
    # HTTP basic auth, so the partner can run ha-heartbeat + lease sync without
    # exposing unauthenticated config-set to the network.
    install -d -m 0755 /etc/kea
    install -d -m 0750 "$HA_TLS_DIR"

    # HA channel TLS. Both nodes present a certificate and verify the partner
    # against the shared trust anchor; basic-auth credentials travel INSIDE that
    # session and are never exposed on the wire. Supplying the material is
    # required — there is no plaintext HTTP fallback for peer traffic.
    # The agent may pre-stage HA PEM material directly at the destination
    # path (e.g. $HA_CA already IS $HA_CA_IN when config was written straight
    # into /etc/kea/ha-tls by the deploy-role handler). `install` refuses to
    # copy a file onto itself, so skip the copy in that case instead of
    # failing the whole deploy.
    if [[ -n "$HA_CA_IN" && "$(readlink -f "$HA_CA_IN" 2>/dev/null)" != "$(readlink -f "$HA_CA" 2>/dev/null)" ]]; then install -m 0644 "$HA_CA_IN" "$HA_CA"; fi
    if [[ -n "$HA_CERT_IN" && "$(readlink -f "$HA_CERT_IN" 2>/dev/null)" != "$(readlink -f "$HA_CERT" 2>/dev/null)" ]]; then install -m 0644 "$HA_CERT_IN" "$HA_CERT"; fi
    if [[ -n "$HA_KEY_IN" && "$(readlink -f "$HA_KEY_IN" 2>/dev/null)" != "$(readlink -f "$HA_KEY" 2>/dev/null)" ]]; then install -m 0640 "$HA_KEY_IN" "$HA_KEY"; fi
    if [[ ! -s "$HA_CA" || ! -s "$HA_CERT" || ! -s "$HA_KEY" ]]; then
        echo "--ha-ca, --ha-cert and --ha-key are required: HA peer traffic is"
        echo "HTTPS with mutual certificate verification. Generate one CA, issue"
        echo "a cert to each node from it, and pass them on both nodes."; exit 1
    fi
    chgrp _kea "$HA_KEY" 2>/dev/null || true

    cat > "$HA_AGENT_CONF" <<EOF
{
    "Control-agent": {
        "http-host": "0.0.0.0",
        "http-port": ${HA_PORT},
        "trust-anchor": "${HA_CA}",
        "cert-file": "${HA_CERT}",
        "key-file": "${HA_KEY}",
        "cert-required": true,
        "authentication": {
            "type": "basic",
            "realm": "kea-ha",
            "clients": [ { "user": "${HA_USER}", "password": "${HA_PASSWORD}" } ]
        },
        "control-sockets": {
            "dhcp4": {
                "socket-type": "unix",
                "socket-name": "/run/kea/kea4-ctrl-socket"
            }
        },
        "loggers": [{
            "name": "kea-ctrl-agent",
            "output_options": [{"output": "syslog"}],
            "severity": "WARN"
        }]
    }
}
EOF
    chmod 640 "$HA_AGENT_CONF"
    chgrp _kea "$HA_AGENT_CONF" 2>/dev/null || true

    cat > /etc/systemd/system/${HA_AGENT_SERVICE}.service <<EOF
[Unit]
Description=Kea Control Agent (authenticated HA peer channel)
After=network-online.target kea-dhcp4-server.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/sbin/kea-ctrl-agent -c ${HA_AGENT_CONF}
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    # Firewall scope, PERSISTENT: only the declared partner address(es) may reach
    # the HA port. Runtime-only rules were lost on the first reboot, which is
    # exactly when nobody is watching — so the ruleset is written to
    # /etc/nftables.d (loaded by nftables.service) or saved via
    # netfilter-persistent, and re-applied immediately.
    if [[ ${#HA_PEERS[@]} -gt 0 ]]; then
        if command -v nft >/dev/null 2>&1; then
            install -d -m 0755 /etc/nftables.d
            {
                echo "table inet lm_kea_ha {"
                echo "    chain input {"
                echo "        type filter hook input priority 0; policy accept;"
                for peer in "${HA_PEERS[@]}"; do
                    echo "        ip saddr ${peer} tcp dport ${HA_PORT} accept"
                done
                echo "        tcp dport ${HA_PORT} drop"
                echo "    }"
                echo "}"
            } > /etc/nftables.d/lm-kea-ha.nft
            grep -q 'include "/etc/nftables.d/\*.nft"' /etc/nftables.conf 2>/dev/null \
                || echo 'include "/etc/nftables.d/*.nft"' >> /etc/nftables.conf
            nft delete table inet lm_kea_ha 2>/dev/null || true
            nft -f /etc/nftables.d/lm-kea-ha.nft 2>/dev/null || true
            systemctl enable nftables 2>/dev/null || true
        elif command -v iptables >/dev/null 2>&1; then
            iptables -N LM_KEA_HA 2>/dev/null || iptables -F LM_KEA_HA
            iptables -C INPUT -p tcp --dport "$HA_PORT" -j LM_KEA_HA 2>/dev/null \
                || iptables -I INPUT -p tcp --dport "$HA_PORT" -j LM_KEA_HA
            for peer in "${HA_PEERS[@]}"; do
                iptables -A LM_KEA_HA -s "$peer" -j ACCEPT
            done
            iptables -A LM_KEA_HA -j DROP
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq iptables-persistent 2>/dev/null || true
            netfilter-persistent save 2>/dev/null \
                || echo "⚠️  could not persist the iptables rules — they will be lost on reboot."
        else
            echo "⚠️  no nft/iptables found — HA port ${HA_PORT} is protected by mutual"
            echo "    TLS + basic auth only; restrict it at the network layer."
        fi
    else
        echo "⚠️  no --ha-peer given — HA port ${HA_PORT} is reachable from anywhere"
        echo "    that can present a valid HA client certificate; pass --ha-peer."
    fi

    # Hook libraries. On Debian/Ubuntu they ship in **kea-common** (there is no
    # "kea-hooks" package — installing it always failed and the pair then
    # reported its HA libraries missing). Resolve the multiarch hook dir instead
    # of assuming the x86_64 triplet.
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq kea-common \
        || echo "⚠️  kea-common not available from apt — the DHCP module will report the missing HA libraries"
    # kea-common's postinst creates the _kea user/group the daemon runs as.
    # $HA_TLS_DIR was created root:root above (before this package existed),
    # so kea-dhcp4 (running as _kea) could never traverse into it to read
    # ha-ca.pem/node.crt/node.key — libdhcp_ha.so's load() then fails with
    # "Permission denied" reading the CA file, which Kea only ever surfaces
    # as the generic "One or more hook libraries failed to load". Group-own
    # the directory now that _kea exists so the daemon can actually enter it;
    # 0750 root:_kea keeps it closed to everyone else.
    chgrp _kea "$HA_TLS_DIR" 2>/dev/null || true
    HOOK_DIR=""
    for cand in /usr/lib/*/kea/hooks /usr/lib/kea/hooks /usr/local/lib/kea/hooks; do
        if [[ -f "$cand/libdhcp_ha.so" ]]; then HOOK_DIR="$cand"; break; fi
    done
    if [[ -z "$HOOK_DIR" ]]; then
        echo "⚠️  libdhcp_ha.so not found under /usr/lib/*/kea/hooks — the DHCP"
        echo "    module will report the missing HA libraries for this node."
    else
        echo "Kea hook libraries: $HOOK_DIR"
    fi

    systemctl daemon-reload
    systemctl enable --now "$HA_AGENT_SERVICE" \
        || echo "⚠️  ${HA_AGENT_SERVICE} failed to start — the pair cannot heartbeat until it does"

    # Accept a bare coordinator host (`--coordinator 10.0.1.9`); 8770 is the
    # DHCP module's cluster listener port (dns uses 8769). Default to wss:// —
    # the worker sends its PSK in the first handshake frame. A ws:// URL to a
    # NON-loopback host is rejected rather than upgraded.
    case "$COORDINATOR" in
        ws://*|wss://*) : ;;
        *:[0-9]*)       COORDINATOR="wss://${COORDINATOR}" ;;
        *)              COORDINATOR="wss://${COORDINATOR}:8770" ;;
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

    # The worker runs from the lm checkout (dhcp/src + core/src). A Kea host
    # deployed via the curl-piped installer has no source yet — clone it. If
    # it already exists (re-running this installer on an already-provisioned
    # host), pull latest instead of silently no-op'ing: this worker has no
    # other self-update mechanism, so "re-run the installer to pick up a fix"
    # must actually update the code or every such instruction is a no-op.
    if [[ ! -f "$INSTALL_DIR/dhcp/src/dhcp_worker.py" ]]; then
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
    if [[ ! -x "$INSTALL_DIR/dhcp/venv/bin/python3" ]]; then
        apt-get install -y -qq python3-venv
        python3 -m venv "$INSTALL_DIR/dhcp/venv"
    fi
    "$INSTALL_DIR/dhcp/venv/bin/pip" install --upgrade pip -q
    [[ -f "$INSTALL_DIR/dhcp/requirements.txt" ]] && \
        "$INSTALL_DIR/dhcp/venv/bin/pip" install -r "$INSTALL_DIR/dhcp/requirements.txt" -q

    mkdir -p "$(dirname "$WORKER_ENV")"
    WORKER_CA_PATH="/etc/lm-dhcp-worker/coordinator-ca.pem"
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
LM_DHCP_MEMBER_ID=$MEMBER_ID
LM_DHCP_COORDINATOR=$COORDINATOR
LM_DHCP_WORKER_SECRET=$WORKER_SECRET
LM_CLUSTER_CA_CERT=$WORKER_CA_PATH
LM_CLUSTER_TLS_CHECK_HOSTNAME=0
EOF
    chmod 600 "$WORKER_ENV"

    cat > /etc/systemd/system/${WORKER_SERVICE}.service <<EOF
[Unit]
Description=Lab Manager Kea HA Worker
After=network-online.target kea-ctrl-agent.service
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=$WORKER_ENV
Environment="PYTHONPATH=$INSTALL_DIR:$INSTALL_DIR/core/src:$INSTALL_DIR/dhcp/src"
WorkingDirectory=$INSTALL_DIR/dhcp/src
ExecStart=$INSTALL_DIR/dhcp/venv/bin/python3 dhcp_worker.py --id \$LM_DHCP_MEMBER_ID
StandardOutput=append:/var/log/lm/lm-dhcp-worker.log
StandardError=append:/var/log/lm/lm-dhcp-worker.log
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now "$WORKER_SERVICE"
    echo "Kea HA worker installed (member: $MEMBER_ID → $COORDINATOR)"
    exit 0
fi

# Deploy-role: server-only. The lm-dhcp spoke that manages this Kea is loaded
# SEPARATELY as the "dhcp" role (module_type dhcp), exactly like netbox-server /
# ldap-server + their client modules. Skip the spoke venv/.env/unit below.
if [[ "$INFRA_ONLY" == true ]]; then
    echo "DHCP server (Kea) installed (infra-only) — load the 'dhcp' role to manage it."
    exit 0
fi

# Python venv
cd "$INSTALL_DIR/dhcp"
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
KEA_CA_URL=http://localhost:8001
${INSTALL_UUID_LINE}
EOF
chmod 600 "$ENV_FILE"

provision_coordinator_tls

cat > /etc/systemd/system/${SERVICE_NAME}.service <<EOF
[Unit]
Description=Lab Manager DHCP Spoke (Kea)
After=network-online.target kea-dhcp4-server.service kea-ctrl-agent.service
Wants=network-online.target

[Service]
Type=simple
User=svc_lm
EnvironmentFile=$ENV_FILE
Environment="PYTHONPATH=$INSTALL_DIR/core/src:$INSTALL_DIR/dhcp/src"
Environment="LM_TLS_CERT=$TLS_CERT"
Environment="LM_TLS_KEY=$TLS_KEY"
WorkingDirectory=$INSTALL_DIR/dhcp/src
ExecStart=$INSTALL_DIR/dhcp/venv/bin/python3 control_plane.py --id \$SPOKE_ID --hub \$HUB_URL
StandardOutput=append:/var/log/lm/lm-dhcp.log
StandardError=append:/var/log/lm/lm-dhcp.log
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now "$SERVICE_NAME"
echo "DHCP spoke installed (ID: $SPOKE_ID)"
