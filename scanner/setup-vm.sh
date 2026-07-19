#!/usr/bin/env bash
# Run ON the Oracle VM (Ubuntu 22.04/24.04 or Oracle Linux 8/9). Installs Node 20 and registers the scanner as a
# systemd service with Restart=always, so it self-heals across crashes/OOM/reboots — the "must never stop"
# guarantee the Cloudflare cron could not give. Expects run.mjs, scan.js, signatures.js, package.json,
# bd-scanner.service, scanner.env in the CURRENT directory (deploy-to-vm.sh scp's them to ~/).
set -euo pipefail
DIR=/opt/bd-scanner
echo "[setup] installing Node 20 if needed…"
if ! command -v node >/dev/null 2>&1 || [ "$(node -v | sed 's/v//;s/\..*//')" -lt 20 ]; then
  if command -v apt-get >/dev/null 2>&1; then
    curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
    sudo apt-get install -y nodejs
  else
    curl -fsSL https://rpm.nodesource.com/setup_20.x | sudo -E bash -
    sudo dnf install -y nodejs || sudo yum install -y nodejs
  fi
fi
echo "[setup] node $(node -v)"
echo "[setup] installing files to $DIR…"
sudo mkdir -p "$DIR"
sudo cp run.mjs scan.js signatures.js package.json scanner.env "$DIR"/
sudo chmod 600 "$DIR"/scanner.env
echo "[setup] installing systemd service…"
sudo cp bd-scanner.service /etc/systemd/system/bd-scanner.service
sudo systemctl daemon-reload
sudo systemctl enable --now bd-scanner
sleep 2
echo "[setup] status:"
sudo systemctl --no-pager status bd-scanner | head -8 || true
echo ""
echo "[setup] DONE.  Follow live logs with:  sudo journalctl -u bd-scanner -f"
echo "[setup] tune concurrency later in $DIR/scanner.env then: sudo systemctl restart bd-scanner"
