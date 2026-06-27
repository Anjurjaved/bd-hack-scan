#!/usr/bin/env bash
# deploy_scanners.sh — deploy N-1 parallel scanner-shard Workers (free, same Cloudflare
# account, NO card). Main Worker is shard 0; this deploys bd-scan-1 .. bd-scan-(N-1).
# Each scans rowid % N == shard, so the N shards partition the queue with zero overlap.
#
#   GROQ_API_KEY="gsk_a,gsk_b,gsk_c" bash deploy/deploy_scanners.sh 8
#
# After this, set SCAN_SHARDS="<N>" in workers/wrangler.toml [vars] and redeploy the main
# Worker so it scans as shard 0 of N.
set -u
cd "$(dirname "$0")/../workers"
N="${1:-8}"
: "${GROQ_API_KEY:?set GROQ_API_KEY=gsk_a,gsk_b,gsk_c}"

: "${SHARED_TOKEN:?set SHARED_TOKEN (the bearer the main Worker fans out with)}"
for i in $(seq 1 $((N - 1))); do
  echo "=== bd-scan-$i  (shard $i of $N) ==="
  npx --yes wrangler deploy -c scanner.wrangler.toml --name "bd-scan-$i" \
    --var "SCAN_SHARD:$i" --var "SCAN_SHARDS:$N" 2>&1 | grep -Ei 'Deployed|workers.dev|error' | head -2
  printf '%s' "$GROQ_API_KEY"  | npx --yes wrangler secret put GROQ_API_KEY  --name "bd-scan-$i" 2>&1 | grep -Ei 'Success|error' | head -1
  printf '%s' "$SHARED_TOKEN" | npx --yes wrangler secret put SHARED_TOKEN --name "bd-scan-$i" 2>&1 | grep -Ei 'Success|error' | head -1
done
echo "done — $((N - 1)) cron-less shard Workers (the main cron fans out to /run)."
