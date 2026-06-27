#!/usr/bin/env bash
# setup_oracle.sh — one-shot installer. Run ON the Oracle (or any Linux) VM after:
#     git clone https://github.com/Anjurjaved/bd-hack-scan
#     cd bd-hack-scan && cp deploy/scanner.env.example deploy/scanner.env
#     nano deploy/scanner.env      # fill SHARED_TOKEN + GROQ_API_KEY
#     bash deploy/setup_oracle.sh
# Installs Python + deps, then registers two systemd units:
#   bdscan.service          — the always-on parallel scan engine (Restart=always)
#   bdscan-harvest.timer    — runs the BD harvesters every 2h
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
USER_NAME="$(whoami)"
echo ">> repo=$REPO user=$USER_NAME"

if [ ! -f "$REPO/deploy/scanner.env" ]; then
  echo "!! deploy/scanner.env missing. Run: cp deploy/scanner.env.example deploy/scanner.env && nano deploy/scanner.env"
  exit 1
fi
if grep -q "PUT_YOUR_SHARED_TOKEN_HERE" "$REPO/deploy/scanner.env"; then
  echo "!! Edit deploy/scanner.env first — SHARED_TOKEN is still the placeholder."
  exit 1
fi

# 1) system deps
if command -v apt-get >/dev/null 2>&1; then
  sudo apt-get update -y
  sudo apt-get install -y python3 python3-venv python3-pip git curl
elif command -v dnf >/dev/null 2>&1; then
  sudo dnf install -y python3 python3-pip git curl
elif command -v yum >/dev/null 2>&1; then
  sudo yum install -y python3 python3-pip git curl
fi

# 2) python venv + deps
python3 -m venv "$REPO/venv"
"$REPO/venv/bin/pip" install -q --upgrade pip
"$REPO/venv/bin/pip" install -q -r "$REPO/scanner/requirements.txt"
"$REPO/venv/bin/pip" install -q -r "$REPO/harvester/requirements.txt"

chmod +x "$REPO/deploy/run_workers.sh" "$REPO/deploy/run_harvest.sh"

# 3) systemd: always-on scanner
sudo tee /etc/systemd/system/bdscan.service >/dev/null <<EOF
[Unit]
Description=BD Hack-Audit scanner (parallel workers)
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=$USER_NAME
WorkingDirectory=$REPO
ExecStart=/usr/bin/env bash $REPO/deploy/run_workers.sh
Restart=always
RestartSec=30
[Install]
WantedBy=multi-user.target
EOF

# 4) systemd: harvest timer (every 2h)
sudo tee /etc/systemd/system/bdscan-harvest.service >/dev/null <<EOF
[Unit]
Description=BD Hack-Audit harvest cycle
After=network-online.target
[Service]
Type=oneshot
User=$USER_NAME
WorkingDirectory=$REPO
ExecStart=/usr/bin/env bash $REPO/deploy/run_harvest.sh
EOF

sudo tee /etc/systemd/system/bdscan-harvest.timer >/dev/null <<EOF
[Unit]
Description=Run BD harvest every 2 hours
[Timer]
OnBootSec=3min
OnUnitActiveSec=2h
Persistent=true
[Install]
WantedBy=timers.target
EOF

# 5) enable + start
sudo systemctl daemon-reload
sudo systemctl enable --now bdscan.service
sudo systemctl enable --now bdscan-harvest.timer
sudo systemctl start bdscan-harvest.service || true   # first harvest now

echo
echo "==================================================================="
echo " ✅ DONE — scanner running 24/7, harvest every 2h."
echo "   live logs:   journalctl -u bdscan -f"
echo "   harvest log: journalctl -u bdscan-harvest -f"
echo "   status:      systemctl status bdscan bdscan-harvest.timer"
echo "   dashboard:   https://bd-hack-audit-api.javed-it.workers.dev/"
echo "==================================================================="
