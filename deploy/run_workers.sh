#!/usr/bin/env bash
# run_workers.sh — launch N parallel scanner workers, each in a restart loop.
# scan.py claims batches until the queue empties, exits cleanly, then we restart
# it after a short pause. This IS the always-on scan engine (systemd keeps THIS
# script alive; this script keeps the N workers alive).
set -u
REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"
set -a; . "$REPO/deploy/scanner.env"; set +a
VENV="$REPO/venv"
N="${SCAN_WORKERS:-6}"

export API_BASE SHARED_TOKEN GROQ_API_KEY
export VERIFY_PROVIDER="${VERIFY_PROVIDER:-groq}"
export SCAN_CONC="${SCAN_CONC:-50}" VERIFY_CONC="${VERIFY_CONC:-8}"
export DOMAIN_TIMEOUT="${DOMAIN_TIMEOUT:-90}" JOB_MINUTES="${JOB_MINUTES:-25}"

echo "[run_workers] starting $N workers (conc=$SCAN_CONC, groq=$VERIFY_PROVIDER)"
pids=()
for i in $(seq 1 "$N"); do
  (
    while true; do
      WORKER_ID="vm-w$i" "$VENV/bin/python" "$REPO/scanner/scan.py" || true
      sleep 20   # queue was empty / job ended — wait, then claim again
    done
  ) &
  pids+=($!)
done
trap 'echo "[run_workers] stopping"; kill "${pids[@]}" 2>/dev/null' TERM INT
wait
