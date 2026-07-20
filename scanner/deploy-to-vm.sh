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
# detector v2 layer modules. scan.js imports these, so shipping scan.js without them is a hard startup failure —
# they travel together or not at all.
mkdir -p "$TMP/layers" && cp "$ROOT"/workers/src/layers/*.js "$TMP/layers"/ 2>/dev/null || true
# VM-side harvesters + the A1 catcher (each has its own systemd timer/service; run.mjs does not call them)
cp "$ROOT"/scanner/harvest-*.mjs "$ROOT"/scanner/bdgate.mjs "$ROOT"/scanner/oci-a1-catcher.mjs "$TMP/" 2>/dev/null || true
cp "$ROOT"/scanner/*.service "$ROOT"/scanner/*.timer "$TMP/" 2>/dev/null || true

# build scanner.env from ~/.secrets (never committed).
#
# THIS FILE IS REGENERATED ON EVERY DEPLOY, which silently discarded live tuning once already: a redeploy reset
# CONCURRENCY back to the default and wiped the CRUX_*/CF_API_* harvest knobs, and the box was running the
# dangerous setting again within seconds. Anything tuned on the VM must therefore be carried forward, so the
# deploy preserves every key it does not itself own.
PRESERVE_KEYS='CRUX_|CF_API_|TLSSAN_|CC_|PDNS_|EIIN_|BDGATE_|SCAN_PROFILE|DOMAIN_MS|CONCURRENCY|BATCH'
EXISTING=""
if EXISTING="$(ssh "${SSH_OPTS[@]}" "$HOST" 'sudo cat /opt/bd-scanner/scanner.env 2>/dev/null' 2>/dev/null)"; then
  KEEP="$(printf '%s\n' "$EXISTING" | grep -E "^($PRESERVE_KEYS)" || true)"
  [ -n "$KEEP" ] && echo "[deploy] preserving $(printf '%s\n' "$KEEP" | wc -l | tr -d ' ') tuned setting(s) from the VM"
fi

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
# 400/500 was the old two-fetch detector's setting and it is DANGEROUS under detector v2, which issues 16-26
# requests per domain. 260 wedged this 1-OCPU / 946MB box hard enough that sshd stopped answering and only an
# OCI reset recovered it. 120/240 is the measured-stable point and is the default here, not a suggestion.
CONCURRENCY=${CONCURRENCY:-120}
BATCH=${BATCH:-240}
# 30s was sized for the two-fetch detector. Measured under detector v2: a clean site finishes in 8-10s, but a
# genuinely hacked one takes ~44s because it earns the deep tier — doorway enumeration, per-URL cloak checks,
# web-shell probes. Cutting exactly those scans off at 30s would truncate the evidence on the only domains that
# matter. Hacked sites are a small fraction of the queue, so the throughput cost is negligible.
DOMAIN_MS=70000
# full = every detector v2 layer, including the extra fetches (reachability ladder, ungated doorway discovery,
# referer/mobile cloak probes, feed + search probes). The Cloudflare shards deliberately stay on "light":
# they run under the free-plan CPU wall that produced error 1102 and froze the engine for 3.3 hours, and a
# shard that 1102s mid-scan used to pin a poison domain at the head of its queue forever.
SCAN_PROFILE=full
EOF

# Re-apply anything that was tuned on the VM. It goes LAST so it wins over the defaults written above — the
# running box is the source of truth for its own limits, not this script's constants.
if [ -n "${KEEP:-}" ]; then
  printf '\n# ---- preserved from the running VM ----\n%s\n' "$KEEP" >> "$TMP/scanner.env"
fi

echo "[deploy] copying to $HOST …"
scp -r "${SSH_OPTS[@]}" "$TMP"/* "$HOST":~/      # -r: the bundle now carries a layers/ subdirectory
echo "[deploy] running remote setup …"
ssh "${SSH_OPTS[@]}" "$HOST" 'bash ~/setup-vm.sh'
echo "[deploy] DONE — scanner is live on the VM.  Logs: ssh $HOST 'sudo journalctl -u bd-scanner -f'"
