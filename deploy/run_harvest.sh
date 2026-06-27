#!/usr/bin/env bash
# run_harvest.sh — one harvest cycle (called by the systemd timer every ~2h).
# Runs the BD-focused domain sources, then asks the Worker to build scan batches
# from the freshly-harvested domains. Each harvester is bounded + idempotent.
set -u
REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"
set -a; . "$REPO/deploy/scanner.env"; set +a
VENV="$REPO/venv"
export API_BASE SHARED_TOKEN
UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"

# BD-first sources (global_feeder intentionally omitted — it feeds non-BD junk).
for h in crtsh directories reverse_ip osm; do
  echo "=== harvest: $h ($(date -u +%H:%M:%S)) ==="
  "$VENV/bin/python" "$REPO/harvester/$h.py" || echo "  $h exited non-zero (handled)"
done

# turn freshly-harvested domains into ready scan batches
curl -s -X POST -H "authorization: Bearer $SHARED_TOKEN" -H "user-agent: $UA" "$API_BASE/build" >/dev/null && echo "build triggered"
