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
    # DELIBERATELY NOT dnf/yum. On the 946MB E2.1.Micro the dnf dependency solve alone OOM-kills the box and
    # takes the running scanner down with it — that happened, and recovering it cost a reboot. The official
    # prebuilt tarball is a plain extract: no solver, no compilation, a few hundred MB of disk and ~0 RAM.
    ARCH="$(uname -m)"; case "$ARCH" in aarch64) NARCH=arm64 ;; x86_64) NARCH=x64 ;; *) echo "unsupported arch $ARCH"; exit 1 ;; esac
    NVER=v20.20.2
    curl -fsSL "https://nodejs.org/dist/$NVER/node-$NVER-linux-$NARCH.tar.xz" -o /tmp/node.tar.xz
    sudo mkdir -p /opt/node && sudo tar -xJf /tmp/node.tar.xz -C /opt/node --strip-components=1
    sudo ln -sf /opt/node/bin/node /usr/bin/node && sudo ln -sf /opt/node/bin/npm /usr/bin/npm
    rm -f /tmp/node.tar.xz
  fi
fi
echo "[setup] node $(node -v)"
echo "[setup] installing files to $DIR…"
sudo mkdir -p "$DIR" "$DIR/layers"
sudo cp run.mjs scan.js signatures.js package.json scanner.env "$DIR"/
# detector v2 layer modules — scan.js imports ./layers/*, so a scan.js copied without them will not start
[ -d layers ] && sudo cp layers/*.js "$DIR/layers"/
# VM-side harvesters (crt.sh, CrUX, CT tailing, …) — driven by their own systemd timers, not by run.mjs
for h in harvest-*.mjs bdgate.mjs oci-a1-catcher.mjs; do [ -f "$h" ] && sudo cp "$h" "$DIR"/; done
sudo chmod 600 "$DIR"/scanner.env
echo "[setup] installing systemd service…"
sudo cp bd-scanner.service /etc/systemd/system/bd-scanner.service
sudo systemctl daemon-reload
sudo systemctl enable bd-scanner
# `enable --now` does NOT restart a service that is already running, so a deploy would copy the new files and
# leave the old process serving them — which has silently happened here before. Restart explicitly.
sudo systemctl restart bd-scanner
sleep 3
echo "[setup] status:"
sudo systemctl --no-pager status bd-scanner | head -8 || true
echo ""
echo "[setup] DONE.  Follow live logs with:  sudo journalctl -u bd-scanner -f"
echo "[setup] tune concurrency later in $DIR/scanner.env then: sudo systemctl restart bd-scanner"
