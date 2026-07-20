#!/usr/bin/env bash
# run_booster.sh — residential-IP booster for the sources the Cloudflare Worker CANNOT fetch.
# bdtradeinfo / bdbusinessdirectory / kagoz are Cloudflare-fronted and block the Worker egress IP,
# and the r.jina.ai reader-proxy throttles Worker traffic too — so they can only be harvested from a
# normal (residential) IP. This script runs harvester/directories.py (covers all of them) + osm.py
# from the user's Mac and POSTs the results to the Worker /harvest, then triggers /build. The Worker
# firehose (reverse-IP / lead-coip / Wikidata / 2 directories) keeps the queue full 24/7 regardless;
# this just adds the blocked directories whenever the Mac is on. Idempotent — the Worker dedups.
# Scheduled by ~/Library/LaunchAgents/com.javed.bdhackaudit.booster.plist (every 3h).
set -u
REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO" || exit 1
set -a; . "$REPO/deploy/scanner.env"; set +a
PY="$REPO/.venv/bin/python"
export API_BASE SHARED_TOKEN
export DIRECTORIES_MAX_LISTINGS="${DIRECTORIES_MAX_LISTINGS:-800}" DIRECTORIES_WORKERS="${DIRECTORIES_WORKERS:-16}"

echo "=== booster start $(date -u +%FT%TZ) ==="
for h in directories osm; do
  echo "--- harvest: $h ($(date -u +%H:%M:%S)) ---"
  "$PY" "$REPO/harvester/$h.py" 2>&1 || echo "  $h exited non-zero (handled)"
done
# turn freshly-harvested domains into ready scan batches
curl -s -m 30 -X POST -H "authorization: Bearer $SHARED_TOKEN" "$API_BASE/build" >/dev/null && echo "build triggered"
echo "=== booster done $(date -u +%FT%TZ) ==="
