// scan-worker.js — a parallel scanner SHARD Worker. NO cron of its own (Cloudflare free
// caps cron triggers per ACCOUNT, ~5, all used by the main Worker). Instead the main Worker's
// every-minute cron HTTP-fans-out to each shard's /run, so every shard runs in its OWN
// invocation (own 10ms CPU + 50 subrequests) — true free parallelism with zero cron cost.
// Scans its slice rowid % SCAN_SHARDS == SCAN_SHARD. State + ingest live in the shared D1.
import { scanTick } from "./scan.js";

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.replace(/\/+$/, "") === "/run") {
      const tok = (request.headers.get("authorization") || "").replace(/^Bearer\s+/i, "").trim();
      if (!env.SHARED_TOKEN || tok !== env.SHARED_TOKEN) return new Response("unauthorized", { status: 401 });
      const r = await scanTick(env).catch((e) => ({ error: String(e).slice(0, 80) }));
      return new Response(JSON.stringify({ shard: env.SCAN_SHARD || 0, ...r }), { headers: { "content-type": "application/json" } });
    }
    return new Response(`bd scanner shard ${env.SCAN_SHARD || 0}/${env.SCAN_SHARDS || 1}`, { status: 200 });
  },
};
