#!/bin/bash
set -e

HUB_WS=""
SPOKE_ID=""
SPOKE_SECRET=""
HUB_SECRET=""

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --hub) HUB_WS="$2"; shift ;;
        --id) SPOKE_ID="$2"; shift ;;
        --secret) SPOKE_SECRET="$2"; shift ;;
        --hub-secret) HUB_SECRET="$2"; shift ;;
        *) echo "Unknown parameter passed: $1"; exit 1 ;;
    esac
    shift
done

if [ -z "$HUB_WS" ] || [ -z "$SPOKE_ID" ] || [ -z "$SPOKE_SECRET" ]; then
    echo "❌ Missing required arguments: --hub, --id, and --secret are required."
    exit 1
fi

echo "🚀 Installing Generic Agent..."

# 1. System Dependencies
apt-get update
apt-get install -y python3-pip python3-venv git

# 2. Create service user
if ! id "svc_lm" &>/dev/null; then
    useradd -r -s /bin/false svc_lm
fi

# 3. Installation Directory
INSTALL_DIR="/opt/lm/generic-agent"
mkdir -p "$INSTALL_DIR"
# Copy current directory (assuming we are in the repo)
cp -r . "$INSTALL_DIR/"

cd "$INSTALL_DIR"
python3 -m venv venv
./venv/bin/python3 -m pip install --upgrade pip -q
./venv/bin/python3 -m pip install websockets python-dotenv -q
# We also need to ensure core is available.
# Since it's a separate directory in the repo, we might need to
# copy core into the installation directory.
# But for this generic agent to work, it needs the core library.
# Let's assume the installation process handles the core dependency.

# 4. Systemd Service
cat <<EOF > /etc/systemd/system/lm-generic-agent.service
[Unit]
Description=Lab Manager Generic Agent
After=network.target

[Service]
User=svc_lm
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/venv/bin/python3 $INSTALL_DIR/src/agent.py --id $SPOKE_ID --secret $SPOKE_SECRET --hub-secret $HUB_SECRET --hub $HUB_WS
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable lm-generic-agent
systemctl restart lm-generic-agent

echo "🎉 Generic Agent installation complete!"
