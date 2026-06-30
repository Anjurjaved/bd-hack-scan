import { scanTick, scanDomain, scanSlice, ingestResults, scanOneVerified, fetchContact } from "./scan.js";
import { harvestReverseIp, harvestCrtsh, harvestDirectories, harvestCommonCrawl, harvestLeadCoip, harvestBdIpSweep } from "./harvest.js";

/**
 * BD Hack-Audit — Cloudflare Worker API
 * --------------------------------------------------------------------------
 * The single brain that sits between the GitHub-Actions scan engine + harvester
 * and the live dashboard. All state lives in Cloudflare D1 (binding: DB).
 *
 * WRITE endpoints (require Bearer SHARED_TOKEN):
 *   POST /harvest   harvester pushes newly-found domains    -> domains + batches
 *   POST /claim     a scanner job claims the next ready batch -> returns its domains
 *   POST /ingest    a scanner job returns results            -> findings + counters
 *   POST /heartbeat a scanner job reports it is alive        -> workers_heartbeat
 *   POST /keyusage  scanner reports Gemini key usage         -> key_usage
 *
 * READ endpoints (public, for the dashboard):
 *   GET  /api/stats   everything: counters, daily/hourly series, categories,
 *                     queue depth, workers, keys, per-source harvest
 *   GET  /api/leads   confirmed/flagged findings (filter + paginate)
 *   GET  /api/feed    recent live events
 *   GET  /health      liveness
 *
 * Cron (every 2 min): roll hourly/daily aggregates, trim the events feed,
 * recompute headline counters, refresh the /api/stats cache.
 *
 * Free-tier discipline: we NEVER write a row per clean domain. Scan progress is
 * tracked at BATCH granularity; only findings + small aggregates are written.
 */

const DHAKA_OFFSET = 6 * 3600; // UTC+6
const BATCH_TARGET = 1000;
const CATEGORIES = ["gambling", "pharma", "adult", "deface", "cloak", "foreign_lang", "malware", "redirect"];

const nowSec = () => Math.floor(Date.now() / 1000);
const dhakaDay = (ts) => new Date((ts + DHAKA_OFFSET) * 1000).toISOString().slice(0, 10);
const dhakaHour = (ts) => new Date((ts + DHAKA_OFFSET) * 1000).toISOString().slice(0, 13).replace("T", "-");

const JSON_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "access-control-allow-origin": "*",
  "access-control-allow-headers": "authorization, content-type",
  "access-control-allow-methods": "GET, POST, OPTIONS",
};
const json = (obj, status = 200) => new Response(JSON.stringify(obj), { status, headers: JSON_HEADERS });
const bad = (msg, status = 400) => json({ ok: false, error: msg }, status);

function authed(request, env) {
  const h = request.headers.get("authorization") || "";
  const tok = h.replace(/^Bearer\s+/i, "").trim();
  return env.SHARED_TOKEN && tok && tok === env.SHARED_TOKEN;
}

// Normalize to a registrable-ish host: lowercase, strip scheme/path/port, drop leading www.
function normalizeDomain(raw) {
  if (!raw) return null;
  let s = String(raw).trim().toLowerCase();
  s = s.replace(/^[a-z]+:\/\//, "").replace(/\/.*$/, "").replace(/:.*$/, "").replace(/^www\./, "");
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(s)) return null;
  return s;
}

export default {
  async fetch(request, env, ctx) {
    if (request.method === "OPTIONS") return new Response(null, { headers: JSON_HEADERS });
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";
    try {
      // ---- public reads ----
      if (request.method === "GET" && path === "/health") return json({ ok: true, ts: nowSec() });
      if (request.method === "GET" && path === "/api/stats") return await apiStats(env, ctx);
      if (request.method === "GET" && path === "/api/leads") return await apiLeads(env, url);
      if (request.method === "GET" && path === "/api/feed") return await apiFeed(env, url);
      if (request.method === "GET" && path === "/api/seed") return await apiSeed(env, url);
      if (request.method === "GET" && path === "/") return json({ ok: true, service: "bd-hack-audit-api", endpoints: ["/api/stats", "/api/leads", "/api/feed", "/health"] });

      // public write: dashboard "not a lead" toggle (low-stakes, reversible)
      if (request.method === "POST" && path === "/reject") {
        return await rejectLead(env, await request.json().catch(() => ({})));
      }
      // public write: dashboard manual on-demand scan (capped 4/call, not destructive)
      if (request.method === "POST" && path === "/scan_manual") {
        return await scanManual(env, await request.json().catch(() => ({})));
      }

      // ---- authed writes ----
      if (request.method === "POST") {
        if (!authed(request, env)) return bad("unauthorized", 401);
        const body = await request.json().catch(() => ({}));
        if (path === "/harvest") return await harvest(env, body);
        if (path === "/lead-ips") return await storeLeadIps(env, body);
        if (path === "/build") return json({ ok: true, built: await buildBatches(env, 200) });
        if (path === "/cursor") return await cursorEndpoint(env, body);
        if (path === "/claim") return await claim(env, body);
        if (path === "/ingest") return await ingest(env, body);
        if (path === "/scan_tick") {
          if (body.domain) return json({ ok: true, result: await scanDomain(env, { domain: body.domain }) });
          return json({ ok: true, ...(await scanTick(env, body.n)) });
        }
        if (path === "/harvest_now") {
          if (body.source === "crtsh") return json({ ok: true, ...(await harvestCrtsh(env)) });
          if (body.source === "reverse") return json({ ok: true, ...(await harvestReverseIp(env)) });
          if (body.source === "directories") return json({ ok: true, ...(await harvestDirectories(env)) });
          if (body.source === "leadcoip") return json({ ok: true, ...(await harvestLeadCoip(env)) });
          if (body.source === "bdipsweep") return json({ ok: true, ...(await harvestBdIpSweep(env)) });
          if (body.source === "addr") return json({ ok: true, ...(await backfillAddresses(env)) });
          return json({ ok: true, ...(await harvestCommonCrawl(env)) });
        }
        if (path === "/heartbeat") return await heartbeat(env, body);
        if (path === "/keyusage") return await keyusage(env, body);
      }
      return bad("not found", 404);
    } catch (e) {
      return bad("server error: " + (e && e.message ? e.message : String(e)), 500);
    }
  },

  async scheduled(event, env, ctx) {
    const c = event.cron;
    if (c === "*/15 * * * *") ctx.waitUntil(housekeeping(env).then(() => harvestLeadCoip(env)).then(() => backfillAddresses(env)).catch(() => {}));  // housekeeping + shared-IP multiplier + address back-fill
    else if (c === "*/20 * * * *") ctx.waitUntil(Promise.allSettled([harvestCommonCrawl(env), harvestReverseIp(env)]));  // Common Crawl + reverse-IP snowball (co-hosted BD businesses)
    else if (c === "37 */2 * * *") ctx.waitUntil(harvestDirectories(env).catch(() => {}));   // BD business directories (.com sites)
    else if (c === "13 */6 * * *") ctx.waitUntil(Promise.allSettled([harvestCrtsh(env), harvestBdIpSweep(env)]));        // crt.sh .bd identities + BD IP-space sweep
    else ctx.waitUntil(scanFanout(env).catch(() => {}));                                       // every minute: scan (shard 0 + fan-out to shards 1..N)
  },
};

// ===========================================================================
// HARVEST — insert new domains, assign to fillable batches, roll over at 1000
// body: { source, domains: [{domain, business?, phone?, bd_score?}] }
// ===========================================================================
async function harvest(env, body) {
  const source = (body.source || "unknown").slice(0, 64);
  let list = Array.isArray(body.domains) ? body.domains : [];
  if (list.length === 0) return json({ ok: true, inserted: 0, found: 0 });
  if (list.length > 2000) list = list.slice(0, 2000); // cap per call

  const now = nowSec();
  // de-dup within the payload + normalize
  const seen = new Set();
  const rows = [];
  for (const d of list) {
    const norm = normalizeDomain(d.domain || d.host || d.url);
    if (!norm || seen.has(norm)) continue;
    seen.add(norm);
    rows.push({ domain: norm, business: (d.business || "").slice(0, 200), phone: (d.phone || "").slice(0, 40), bd: Number(d.bd_score) || 0 });
  }
  const found = rows.length;
  if (found === 0) return json({ ok: true, inserted: 0, found: 0 });

  let inserted = 0;

  // RACE-FREE: just insert domains (batch_id stays NULL). Batches are built
  // separately by buildBatches() in the single-threaded cron, so concurrent
  // harvesters never corrupt batch accounting. D1 caps bound params at 100/query
  // (14 rows * 6 cols = 84).
  const ROWS_PER_STMT = 14;
  for (let i = 0; i < rows.length; i += ROWS_PER_STMT) {
    const chunk = rows.slice(i, i + ROWS_PER_STMT);
    const ph = chunk.map(() => "(?,?,?,?,?,?)").join(",");
    const binds = [];
    for (const r of chunk) binds.push(r.domain, source, r.bd, r.business, r.phone, now);
    const res = await env.DB.prepare(
      "INSERT OR IGNORE INTO domains (domain,source,bd_score,business,phone,added_ts) VALUES " + ph
    ).bind(...binds).run();
    inserted += res.meta.changes || 0;
  }

  const day = dhakaDay(now);
  await env.DB.batch([
    env.DB.prepare("INSERT INTO harvest_log (source,found,new_domains,dups,ts) VALUES (?,?,?,?,?)").bind(source, found, inserted, found - inserted, now),
    env.DB.prepare("INSERT INTO source_state (source,last_run,total_harvested,enabled) VALUES (?,?,?,1) ON CONFLICT(source) DO UPDATE SET last_run=excluded.last_run, total_harvested=total_harvested+?").bind(source, now, inserted, inserted),
    env.DB.prepare("INSERT INTO daily_stats (day,harvested) VALUES (?,?) ON CONFLICT(day) DO UPDATE SET harvested=harvested+?").bind(day, inserted, inserted),
    env.DB.prepare("UPDATE counters SET value=value+? WHERE metric='total_harvested'").bind(inserted),
    env.DB.prepare("UPDATE counters SET value=value+? WHERE metric='total_domains'").bind(inserted),
  ]);
  return json({ ok: true, found, inserted, dups: found - inserted });
}

// Build scannable batches from unassigned domains. Single-threaded (cron / /build),
// so it is race-free. Full 1000-domain batches; a settled remainder (>10 min old) is flushed.
async function buildBatches(env, maxBatches = 80) {
  const now = nowSec();
  const nbRow = await env.DB.prepare("SELECT value FROM counters WHERE metric='next_batch_id'").first();
  let nextId = (nbRow && nbRow.value) ? nbRow.value : 1;
  const cntRow = await env.DB.prepare("SELECT COUNT(*) c, MIN(added_ts) m FROM domains WHERE batch_id IS NULL").first();
  let pending = cntRow ? cntRow.c : 0;
  let built = 0;
  const full = Math.min(Math.floor(pending / 1000), maxBatches);
  for (let k = 0; k < full; k++) {
    await env.DB.batch([
      env.DB.prepare("UPDATE domains SET batch_id=? WHERE rowid IN (SELECT rowid FROM domains WHERE batch_id IS NULL ORDER BY rowid LIMIT 1000)").bind(nextId),
      env.DB.prepare("INSERT OR REPLACE INTO batches (batch_id,pass_no,domain_count,status,created_ts) VALUES (?,1,1000,'ready',?)").bind(nextId, now),
    ]);
    nextId++; built++; pending -= 1000;
  }
  // flush a settled remainder so the tail of a finished harvest still gets scanned
  if (pending > 0 && built < maxBatches && cntRow && cntRow.m && (now - cntRow.m) > 600) {
    await env.DB.batch([
      env.DB.prepare("UPDATE domains SET batch_id=? WHERE batch_id IS NULL").bind(nextId),
      env.DB.prepare("INSERT OR REPLACE INTO batches (batch_id,pass_no,domain_count,status,created_ts) VALUES (?,1,?,'ready',?)").bind(nextId, pending, now),
    ]);
    nextId++; built++;
  }
  if (built) {
    await env.DB.prepare("INSERT INTO counters (metric,value) VALUES ('next_batch_id',?) ON CONFLICT(metric) DO UPDATE SET value=?").bind(nextId, nextId).run();
  }
  return built;
}

// Per-source cursor (used by the paced global-ranked feeder). POST {source} reads;
// POST {source, cursor} sets and reads back.
async function cursorEndpoint(env, body) {
  const source = (body.source || "").slice(0, 64);
  if (!source) return bad("source required");
  if (body.cursor != null) {
    await env.DB.prepare(
      "INSERT INTO source_state (source, cursor, last_run) VALUES (?,?,?) ON CONFLICT(source) DO UPDATE SET cursor=excluded.cursor, last_run=excluded.last_run"
    ).bind(source, String(body.cursor), nowSec()).run();
  }
  const r = await env.DB.prepare("SELECT cursor FROM source_state WHERE source=?").bind(source).first();
  return json({ ok: true, source, cursor: r ? r.cursor : null });
}

// ===========================================================================
// CLAIM — give a scanner job the next ready batch + its domains
// body: { worker_id, max?  }
// ===========================================================================
async function claim(env, body) {
  const worker = (body.worker_id || "anon").slice(0, 64);
  const now = nowSec();
  // pick the oldest ready batch, or a claimed-but-stale one (>30 min, job died)
  const stale = now - 1800;
  let b = await env.DB.prepare(
    "SELECT batch_id FROM batches WHERE status='ready' ORDER BY batch_id LIMIT 1"
  ).first();
  if (!b) {
    b = await env.DB.prepare(
      "SELECT batch_id FROM batches WHERE status='claimed' AND claimed_ts < ? ORDER BY claimed_ts LIMIT 1"
    ).bind(stale).first();
  }
  if (!b) return json({ ok: true, batch_id: null, domains: [] }); // queue empty

  await env.DB.prepare("UPDATE batches SET status='claimed', claimed_by=?, claimed_ts=? WHERE batch_id=?")
    .bind(worker, now, b.batch_id).run();
  const rs = await env.DB.prepare("SELECT domain, business, phone FROM domains WHERE batch_id=?").bind(b.batch_id).all();
  return json({ ok: true, batch_id: b.batch_id, domains: rs.results || [] });
}

// ===========================================================================
// INGEST — scanner returns a finished batch's results
// body: { batch_id, worker_id, scanned, errors, findings: [ {domain,business,phone,
//         category,layers,proof_snippet,proof_url,http_status,stage1_score,
//         stage2_verdict,stage2_reason,stage2_category,confirmed} ] }
// ===========================================================================
async function ingest(env, body) {
  const batchId = body.batch_id;
  const scanned = Number(body.scanned) || 0;
  const errors = Number(body.errors) || 0;
  const findings = Array.isArray(body.findings) ? body.findings : [];
  const now = nowSec();
  const day = dhakaDay(now), hour = dhakaHour(now);

  const stmts = [];
  const catCount = Object.fromEntries(CATEGORIES.map((c) => [c, 0]));
  let flagged = 0, confirmed = 0;

  for (const f of findings.slice(0, 1500)) {
    const dom = normalizeDomain(f.domain);
    if (!dom) continue;
    flagged++;
    const conf = f.confirmed ? 1 : 0;
    if (conf) confirmed++;
    const cat = (f.category || "").toLowerCase();
    if (catCount[cat] !== undefined && conf) catCount[cat]++;
    stmts.push(
      env.DB.prepare(
        "INSERT INTO findings (domain,business,phone,category,layers,proof_snippet,proof_url,http_status,stage1_score,stage2_verdict,stage2_reason,stage2_category,confirmed,pass_no,first_ts,ts,evidence,is_bd,biz_type,status) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
      ).bind(
        dom, (f.business || "").slice(0, 200), (f.phone || "").slice(0, 40), cat,
        (f.layers || "").slice(0, 200), (f.proof_snippet || "").slice(0, 600), (f.proof_url || "").slice(0, 300),
        Number(f.http_status) || 0, Number(f.stage1_score) || 0,
        (f.stage2_verdict || "").slice(0, 20), (f.stage2_reason || "").slice(0, 400), (f.stage2_category || "").slice(0, 30),
        conf, Number(body.pass_no) || 1, now, now, (f.evidence || "").slice(0, 4000),
        f.is_bd ? 1 : 0, (f.biz_type || "").slice(0, 30), (f.status || "lead").slice(0, 16)
      )
    );
    // live feed: only confirmed (keeps the feed signal-rich + small)
    if (conf) {
      stmts.push(env.DB.prepare("INSERT INTO events (kind,domain,detail,ts) VALUES ('confirmed',?,?,?)")
        .bind(dom, (cat + " | " + (f.proof_snippet || "")).slice(0, 200), now));
    }
  }

  // mark the batch done
  if (batchId != null) {
    stmts.push(env.DB.prepare(
      "UPDATE batches SET status='done', done_ts=?, scanned=?, flagged=?, confirmed=?, errors=? WHERE batch_id=?"
    ).bind(now, scanned, flagged, confirmed, errors, batchId));
  }

  // aggregate counters (a handful of writes for a whole 1000-domain batch)
  const catSet = CATEGORIES.map((c) => `${c}=${c}+${catCount[c]}`).join(",");
  stmts.push(env.DB.prepare(
    `INSERT INTO daily_stats (day,scanned,flagged,confirmed,errors,${CATEGORIES.join(",")}) VALUES (?,?,?,?,?,${CATEGORIES.map(() => "?").join(",")}) ` +
    `ON CONFLICT(day) DO UPDATE SET scanned=scanned+?, flagged=flagged+?, confirmed=confirmed+?, errors=errors+?, ${catSet}`
  ).bind(day, scanned, flagged, confirmed, errors, ...CATEGORIES.map((c) => catCount[c]), scanned, flagged, confirmed, errors));
  stmts.push(env.DB.prepare(
    "INSERT INTO hourly_stats (hour,scanned,flagged,confirmed,errors) VALUES (?,?,?,?,?) ON CONFLICT(hour) DO UPDATE SET scanned=scanned+?, flagged=flagged+?, confirmed=confirmed+?, errors=errors+?"
  ).bind(hour, scanned, flagged, confirmed, errors, scanned, flagged, confirmed, errors));
  stmts.push(env.DB.prepare("UPDATE counters SET value=value+? WHERE metric='total_scanned'").bind(scanned));
  stmts.push(env.DB.prepare("UPDATE counters SET value=value+? WHERE metric='total_flagged'").bind(flagged));
  stmts.push(env.DB.prepare("UPDATE counters SET value=value+? WHERE metric='total_confirmed'").bind(confirmed));
  stmts.push(env.DB.prepare("UPDATE counters SET value=value+? WHERE metric='total_errors'").bind(errors));

  await env.DB.batch(stmts);
  return json({ ok: true, batch_id: batchId, scanned, flagged, confirmed });
}

async function heartbeat(env, body) {
  const now = nowSec();
  await env.DB.prepare(
    "INSERT INTO workers_heartbeat (worker_id,last_seen,scanned_total,current_batch,state) VALUES (?,?,?,?,?) ON CONFLICT(worker_id) DO UPDATE SET last_seen=excluded.last_seen, scanned_total=excluded.scanned_total, current_batch=excluded.current_batch, state=excluded.state"
  ).bind((body.worker_id || "anon").slice(0, 64), now, Number(body.scanned_total) || 0, body.current_batch ?? null, (body.state || "running").slice(0, 30)).run();
  return json({ ok: true });
}

async function keyusage(env, body) {
  const now = nowSec(), day = dhakaDay(now);
  const items = Array.isArray(body.keys) ? body.keys : [];
  const stmts = items.slice(0, 50).map((k) =>
    env.DB.prepare(
      "INSERT INTO key_usage (key_id,day,requests,successes,rate_limited,last_used) VALUES (?,?,?,?,?,?) ON CONFLICT(key_id) DO UPDATE SET day=excluded.day, requests=requests+?, successes=successes+?, rate_limited=rate_limited+?, last_used=excluded.last_used"
    ).bind(String(k.key_id).slice(0, 40), day, Number(k.requests) || 0, Number(k.successes) || 0, Number(k.rate_limited) || 0, now, Number(k.requests) || 0, Number(k.successes) || 0, Number(k.rate_limited) || 0)
  );
  if (stmts.length) await env.DB.batch(stmts);
  return json({ ok: true });
}

// ===========================================================================
// DASHBOARD READS
// ===========================================================================
let STATS_CACHE = { ts: 0, body: null };

async function apiStats(env, ctx) {
  const now = nowSec();
  if (STATS_CACHE.body && now - STATS_CACHE.ts < 15) return json(STATS_CACHE.body);

  const counters = {};
  for (const r of (await env.DB.prepare("SELECT metric,value FROM counters").all()).results || []) counters[r.metric] = r.value;

  const daily = (await env.DB.prepare("SELECT * FROM daily_stats ORDER BY day DESC LIMIT 21").all()).results || [];
  const hourly = (await env.DB.prepare("SELECT * FROM hourly_stats ORDER BY hour DESC LIMIT 48").all()).results || [];

  const q = {};
  for (const r of (await env.DB.prepare("SELECT status, COUNT(*) c, COALESCE(SUM(domain_count),0) d FROM batches GROUP BY status").all()).results || [])
    q[r.status] = { batches: r.c, domains: r.d };

  const cats = (await env.DB.prepare("SELECT category, COUNT(*) c FROM findings WHERE confirmed=1 GROUP BY category ORDER BY c DESC").all()).results || [];
  const sources = (await env.DB.prepare("SELECT source, total_harvested, last_run FROM source_state ORDER BY total_harvested DESC LIMIT 60").all()).results || [];
  const workers = (await env.DB.prepare("SELECT * FROM workers_heartbeat WHERE last_seen > ? ORDER BY last_seen DESC").bind(now - 900).all()).results || [];
  const keys = (await env.DB.prepare("SELECT * FROM key_usage WHERE day=? ORDER BY requests DESC").bind(dhakaDay(now)).all()).results || [];
  const recentRate = (await env.DB.prepare("SELECT COALESCE(SUM(scanned),0) s FROM hourly_stats WHERE hour=?").bind(dhakaHour(now)).first()) || { s: 0 };
  // BD vs global split of the registry (the .bd subset is the monetizable core)
  const bdRow = (await env.DB.prepare("SELECT COUNT(*) c FROM domains WHERE domain LIKE '%.bd'").first()) || { c: 0 };
  const unscRow = (await env.DB.prepare("SELECT COUNT(*) c FROM domains WHERE pass_no=0").first()) || { c: 0 };
  const leadGeo = { bd: 0, intl: 0 };
  for (const r of (await env.DB.prepare("SELECT is_bd, COUNT(*) c FROM findings WHERE confirmed=1 AND status!='rejected' GROUP BY is_bd").all()).results || [])
    leadGeo[r.is_bd ? "bd" : "intl"] = r.c;

  const body = {
    ok: true,
    now,
    counters,
    queue: q,
    rate_this_hour: recentRate.s,
    bd_domains: bdRow.c,
    unscanned: unscRow.c,
    lead_geo: leadGeo,
    categories: cats,
    daily: daily.reverse(),
    hourly: hourly.reverse(),
    sources,
    workers,
    keys,
  };
  STATS_CACHE = { ts: now, body };
  return json(body);
}

async function apiLeads(env, url) {
  const cat = url.searchParams.get("category");
  const region = url.searchParams.get("region");   // bd | intl
  const biz = url.searchParams.get("biz");
  const onlyConfirmed = url.searchParams.get("confirmed") !== "0";
  const limit = Math.min(parseInt(url.searchParams.get("limit") || "200", 10) || 200, 5000);
  const offset = Math.max(parseInt(url.searchParams.get("offset") || "0", 10) || 0, 0);
  const manual = url.searchParams.get("manual") === "1";
  let sql = "SELECT id,domain,business,phone,category,layers,proof_snippet,proof_url,http_status,stage2_verdict,stage2_reason,confirmed,ts,evidence,is_bd,biz_type,status,ip,is_manual,mbatch,address,district FROM findings WHERE status != 'rejected'";
  const binds = [];
  if (manual) {
    sql += " AND is_manual=1";
  } else {
    sql += " AND (is_manual IS NULL OR is_manual=0)";
    if (onlyConfirmed) sql += " AND confirmed=1";
    if (region === "bd") sql += " AND is_bd=1";
    else if (region === "intl") sql += " AND is_bd=0";
  }
  if (cat) { sql += " AND category=?"; binds.push(cat); }
  if (biz) { sql += " AND biz_type=?"; binds.push(biz); }
  sql += " ORDER BY ts DESC LIMIT ? OFFSET ?";
  binds.push(limit, offset);
  const rs = await env.DB.prepare(sql).bind(...binds).all();
  return json({ ok: true, leads: rs.results || [], limit, offset });
}

// Manual on-demand scan — the user pastes domain(s); we run the FULL deep scan + the same
// Gemini/Groq verify (no steps skipped), store results under a named batch (is_manual=1), and
// return them instantly. Bulk lists are chunked by the dashboard (cap per call = worker subreq
// budget). body: { domains: "a.com,b.com" | [..], name?: "<batch label>" }
async function scanManual(env, body) {
  const name = String(body.name || "").slice(0, 60);
  let domains = Array.isArray(body.domains) ? body.domains : String(body.domains || "").split(",");
  domains = [...new Set(domains.map(normalizeDomain).filter(Boolean))].slice(0, 4); // cap/call: scanDomain is subreq-heavy
  if (!domains.length) return json({ ok: true, scanned: 0, results: [] });
  const now = nowSec();
  const out = [], stmts = [];
  for (const dom of domains) {
    let r;
    try { r = await scanOneVerified(env, dom); } catch (e) { r = { domain: dom, error: "scan failed" }; }
    if (r.error) { out.push({ domain: dom, error: r.error }); continue; }
    out.push({ domain: dom, hacked: r.confirmed, flagged: r.flagged, category: r.category, verdict: r.verdict, reason: r.reason, proofUrl: r.proofUrl, proof: r.proof, status: r.status, isBd: r.isBd });
    stmts.push(env.DB.prepare("DELETE FROM findings WHERE domain=? AND is_manual=1").bind(dom));
    stmts.push(env.DB.prepare(
      "INSERT INTO findings (domain,business,phone,category,layers,proof_snippet,proof_url,http_status,stage2_verdict,stage2_reason,confirmed,pass_no,first_ts,ts,evidence,is_bd,biz_type,status,is_manual,mbatch,address,district) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
    ).bind(dom, "", (r.phone || "").slice(0, 40), r.category, (r.layers || "").slice(0, 200), (r.proof || "").slice(0, 600), (r.proofUrl || "").slice(0, 300), r.httpStatus || 0, (r.verdict || "").slice(0, 20), (r.reason || "").slice(0, 400), r.confirmed ? 1 : 0, 1, now, now, JSON.stringify(r.evidence || []).slice(0, 4000), r.isBd ? 1 : 0, (r.bizType || "").slice(0, 30), (r.status || "manual").slice(0, 16), 1, name, (r.address || "").slice(0, 200), (r.district || "").slice(0, 40)));
  }
  if (stmts.length) await env.DB.batch(stmts);
  return json({ ok: true, scanned: out.length, results: out });
}

// Back-fill address/district on already-confirmed leads (one cheap homepage fetch + regex, ZERO
// Gemini). Bounded per run + '-' sentinel so each lead is tried once; runs on the */15 cron.
async function backfillAddresses(env) {
  const N = Number(env.ADDR_BACKFILL || 8);
  const rows = (await env.DB.prepare(
    "SELECT domain FROM findings WHERE confirmed=1 AND status!='rejected' AND (address IS NULL OR address='') AND (district IS NULL OR district='') ORDER BY id LIMIT ?"
  ).bind(N).all()).results || [];
  if (!rows.length) return { tried: 0, backfilled: 0 };
  const stmts = [];
  let got = 0;
  for (const r of rows) {
    let c; try { c = await fetchContact(r.domain); } catch (e) { c = null; }
    const addr = (c && c.address) || "", dist = (c && c.district) || "", ph = (c && c.phone) || "";
    if (addr || dist) got++;
    stmts.push(env.DB.prepare(
      "UPDATE findings SET address=?, district=?, phone=CASE WHEN (phone IS NULL OR phone='') THEN ? ELSE phone END WHERE domain=? AND confirmed=1"
    ).bind(addr || "-", dist || "-", ph, r.domain));
  }
  if (stmts.length) await env.DB.batch(stmts);
  return { tried: rows.length, backfilled: got };
}

// Bulk-store the hosting IP of confirmed leads (from the lead-coip harvester / worker cron).
// Powers the dashboard's shared-server ("area") clustering. body: { pairs: [{domain, ip}] }
async function storeLeadIps(env, body) {
  const pairs = Array.isArray(body.pairs) ? body.pairs : [];
  if (!pairs.length) return json({ ok: true, updated: 0 });
  const stmts = [];
  for (const p of pairs.slice(0, 3000)) {
    const dom = normalizeDomain(p.domain);
    const ip = String(p.ip || "").trim().slice(0, 45);
    if (!dom || !ip || !/^[0-9a-fA-F:.]+$/.test(ip)) continue;
    stmts.push(env.DB.prepare("UPDATE findings SET ip=? WHERE domain=?").bind(ip, dom));
  }
  let updated = 0;
  for (let i = 0; i < stmts.length; i += 50) {
    const res = await env.DB.batch(stmts.slice(i, i + 50));
    for (const r of res) updated += (r.meta && r.meta.changes) || 0;
  }
  return json({ ok: true, updated });
}

// Public (the dashboard's "not a lead" button) — toggles a finding's status.
async function rejectLead(env, body) {
  const id = Number(body.id);
  if (!id) return bad("id required");
  const status = body.status === "lead" ? "lead" : "rejected";
  await env.DB.prepare("UPDATE findings SET status=? WHERE id=?").bind(status, id).run();
  return json({ ok: true, id, status });
}

async function apiFeed(env, url) {
  const limit = Math.min(parseInt(url.searchParams.get("limit") || "60", 10) || 60, 200);
  const rs = await env.DB.prepare("SELECT kind,domain,detail,ts FROM events ORDER BY id DESC LIMIT ?").bind(limit).all();
  return json({ ok: true, feed: rs.results || [] });
}

// Rotating slice of known .bd domains — seeds for the reverse-IP harvester
// (resolve these to their shared hosting IPs, then reverse-IP to find co-hosted
// BD businesses we don't have yet). Public read; domains are not secret.
async function apiSeed(env, url) {
  const limit = Math.min(parseInt(url.searchParams.get("limit") || "200", 10) || 200, 500);
  const offset = Math.max(parseInt(url.searchParams.get("offset") || "0", 10) || 0, 0);
  const rs = await env.DB.prepare(
    "SELECT domain FROM domains WHERE domain LIKE '%.bd' ORDER BY rowid LIMIT ? OFFSET ?"
  ).bind(limit, offset).all();
  const domains = (rs.results || []).map((r) => r.domain);
  // wrap the offset when we run off the end so the harvester keeps cycling
  const totalRow = await env.DB.prepare("SELECT COUNT(*) c FROM domains WHERE domain LIKE '%.bd'").first();
  return json({ ok: true, domains, offset, limit, total: totalRow ? totalRow.c : 0 });
}

// ===========================================================================
// HOUSEKEEPING (cron) — trim events, requeue stale claims, recompute totals
// ===========================================================================
// Every-minute scan: main does shard 0 itself, then HTTP-fans-out to sibling shard Workers
// (bd-scan-1..N-1) so each runs scanTick in its own invocation (own CPU + subrequest budget).
// This gives free N-way parallelism without needing N cron triggers (Cloudflare caps those).
async function scanFanout(env) {
  const shards = Math.max(1, Number(env.SCAN_SHARDS || 1));
  const sub = env.SCAN_SUBDOMAIN || "javed-it";
  const hdr = { headers: { authorization: "Bearer " + (env.SHARED_TOKEN || "") } };
  // every shard SCANS in its own invocation (own CPU/subrequests); results come back here.
  const tasks = [scanSlice(env)];   // main = shard 0
  for (let i = 1; i < shards; i++) {
    const svc = env["SHARD" + i];
    const p = svc ? svc.fetch("https://shard/run", hdr) : fetch(`https://bd-scan-${i}.${sub}.workers.dev/run`, hdr);
    tasks.push(p.then((r) => r.json()).catch(() => null));
  }
  const results = await Promise.all(tasks);
  // aggregate, then write ONCE (single writer = zero D1 write-contention across shards)
  const agg = { rowids: [], findings: [], scanned: 0, errors: 0 };
  for (const r of results) {
    if (!r) continue;
    if (Array.isArray(r.rowids)) agg.rowids.push(...r.rowids);
    if (Array.isArray(r.findings)) agg.findings.push(...r.findings);
    agg.scanned += r.scanned || 0;
    agg.errors += r.errors || 0;
  }
  if (agg.rowids.length) await ingestResults(env, agg);
  // one lightweight engine heartbeat per tick so the dashboard shows the live shard fleet
  const live = results.filter(Boolean).length;
  await env.DB.prepare(
    "INSERT INTO workers_heartbeat (worker_id,last_seen,scanned_total,current_batch,state) VALUES ('cf-engine',?,?,?,'running') ON CONFLICT(worker_id) DO UPDATE SET last_seen=excluded.last_seen, scanned_total=workers_heartbeat.scanned_total+excluded.scanned_total, current_batch=excluded.current_batch, state='running'"
  ).bind(Math.floor(Date.now() / 1000), agg.scanned, live).run();
}

async function housekeeping(env) {
  const now = nowSec();
  // build scannable batches from freshly-harvested domains (race-free, single-threaded here)
  await buildBatches(env);
  // keep events feed small (last ~2000 by id)
  await env.DB.prepare("DELETE FROM events WHERE id < (SELECT COALESCE(MAX(id),0)-2000 FROM events)").run();
  // requeue claimed batches whose worker went silent > 30 min
  await env.DB.prepare("UPDATE batches SET status='ready', claimed_by=NULL WHERE status='claimed' AND claimed_ts < ?").bind(now - 1800).run();
  // refresh stats cache opportunistically
  STATS_CACHE = { ts: 0, body: null };
}
