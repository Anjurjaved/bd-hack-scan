#!/usr/bin/env bash
# Run on the Mac (or wherever the repo + ~/.secrets live). Bundles the scanner + the SHARED detector
# (workers/src/scan.js + signatures.js — the single source of truth) + a scanner.env built from ~/.secrets,
# copies them to the Oracle VM, and runs setup-vm.sh remotely to bring the service up.
#
#   Usage:  ./deploy-to-vm.sh  opc@<VM_PUBLIC_IP>   [ssh-key.pem]
#   (Oracle Linux login user is 'opc'; Ubuntu images use 'ubuntu'.)
set -euo pipefail
HOST="${1:?usage: ./deploy-to-vm.sh user@vm-ip [ssh-key.pem]}"
KEY="${2:-}"
SSH_OPTS=(-o StrictHostKeyChecking=accept-new)
[ -n "$KEY" ] && SSH_OPTS+=(-i "$KEY")

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

cp "$ROOT/scanner/run.mjs" "$ROOT/scanner/package.json" "$ROOT/scanner/bd-scanner.service" "$ROOT/scanner/setup-vm.sh" "$TMP/"
# the shared detector — copied fresh so the VM always runs the CURRENT scan.js (repo working tree = live code)
cp "$ROOT/workers/src/scan.js" "$ROOT/workers/src/signatures.js" "$TMP/"

# build scanner.env from ~/.secrets (never committed)
GEMINI="$(sed -n '1,17p' "$HOME/.secrets/gemini_api_keys" | paste -sd, -)"
GROQ="$(grep -oE 'gsk_[A-Za-z0-9_]+' "$HOME/.secrets/groq_keys.env" | paste -sd, -)"
TOKEN="$(grep -oE 'SHARED_TOKEN=.*' "$HOME/.secrets/bd_hack_audit.env" | cut -d= -f2 | tr -d '"'"'"' ')"
cat > "$TMP/scanner.env" <<EOF
API_BASE=https://bd-hack-audit-api.javed-it.workers.dev
SHARED_TOKEN=$TOKEN
GEMINI_API_KEYS=$GEMINI
GROQ_API_KEY=$GROQ
GROQ_MODEL=llama-3.1-8b-instant
GEMINI_MODEL=gemini-2.5-flash
CONCURRENCY=${CONCURRENCY:-400}
BATCH=${BATCH:-500}
DOMAIN_MS=30000
EOF

echo "[deploy] copying to $HOST …"
scp "${SSH_OPTS[@]}" "$TMP"/* "$HOST":~/
echo "[deploy] running remote setup …"
ssh "${SSH_OPTS[@]}" "$HOST" 'bash ~/setup-vm.sh'
echo "[deploy] DONE — scanner is live on the VM.  Logs: ssh $HOST 'sudo journalctl -u bd-scanner -f'"
