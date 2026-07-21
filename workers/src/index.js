import { scanTick, scanDomain, scanSlice, ingestResults, scanOneVerified, fetchContact, DETECTOR_GEN } from "./scan.js";
import { harvestReverseIp, harvestCrtsh, harvestDirectories, harvestCommonCrawl, harvestLeadCoip, harvestBdIpSweep, harvestWikidata, harvestIpTree, harvestCrux, harvestRipeBd, harvestWikiEdu, harvestOverpass } from "./harvest.js";
import { bizType, registrableOf } from "./signatures.js";
import { buildSpamHosts } from "./layers/links.js";

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

// ---- session auth (login cookie, HMAC-signed). SHARED_TOKEN still bypasses for cron/shards/tooling. ----
function timingSafeEq(a, b) { if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false; let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i); return r === 0; }
async function hmacHex(msg, secret) {
  const k = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret || "x"), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const s = await crypto.subtle.sign("HMAC", k, new TextEncoder().encode(msg));
  return [...new Uint8Array(s)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function signSession(env, ttl = 2592000) { const exp = nowSec() + ttl; return exp + "." + (await hmacHex(String(exp), env.SESSION_SECRET)); }
async function verifySession(token, env) {
  const i = String(token || "").lastIndexOf("."); if (i < 1) return false;
  const exp = token.slice(0, i), sig = token.slice(i + 1);
  if (!/^\d+$/.test(exp) || Number(exp) < nowSec()) return false;
  return timingSafeEq(sig, await hmacHex(exp, env.SESSION_SECRET));
}
async function sessionOk(request, env) {
  if (authed(request, env)) return true;        // SHARED_TOKEN bypass (cron/shards/owner tooling)
  if (!env.SITE_USER) return true;              // auth not configured yet → stay open (prevents lockout before secrets are set)
  const c = request.headers.get("cookie") || "";
  const m = c.match(/(?:^|;\s*)bdsess=([^;]+)/);
  return m ? await verifySession(decodeURIComponent(m[1]), env) : false;
}
async function doLogin(env, request) {
  const ip = request.headers.get("cf-connecting-ip") || "0";
  const now = nowSec();
  let f = null; try { f = await env.DB.prepare("SELECT fails,blocked_until FROM auth_fails WHERE ip=?").bind(ip).first(); } catch (e) {}
  if (f && f.blocked_until > now) return bad("অনেকবার ভুল চেষ্টা — " + Math.ceil((f.blocked_until - now) / 60) + " মিনিট পর আবার চেষ্টা করুন", 429);
  const body = await request.json().catch(() => ({}));
  const u = String(body.user || "").trim(), p = String(body.pass || "");
  if (env.SITE_USER && u === env.SITE_USER && p === env.SITE_PASS) {
    try { await env.DB.prepare("DELETE FROM auth_fails WHERE ip=?").bind(ip).run(); } catch (e) {}
    const tok = await signSession(env);
    return new Response(JSON.stringify({ ok: true }), { status: 200, headers: { "content-type": "application/json", "set-cookie": "bdsess=" + tok + "; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=2592000" } });
  }
  const fails = (f ? f.fails : 0) + 1;
  const blk = fails >= 5 ? now + 900 : 0;       // 5 wrong tries → 15-min IP lockout (brute-force safe even for a 4-char password)
  try { await env.DB.prepare("INSERT INTO auth_fails (ip,fails,blocked_until) VALUES (?,?,?) ON CONFLICT(ip) DO UPDATE SET fails=?,blocked_until=?").bind(ip, fails, blk, fails, blk).run(); } catch (e) {}
  return bad(blk ? "৫ বার ভুল — ১৫ মিনিট বন্ধ" : "ID বা password ভুল — আর " + (5 - fails) + " বার বাকি", 401);
}
function logoutResp() { return new Response(JSON.stringify({ ok: true }), { status: 200, headers: { "content-type": "application/json", "set-cookie": "bdsess=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0" } }); }

// Normalize to a registrable-ish host: lowercase, strip scheme/path/port, drop leading www.
function normalizeDomain(raw) {
  if (!raw) return null;
  let s = String(raw).trim().toLowerCase();
  s = s.replace(/^[a-z]+:\/\//, "").replace(/\/.*$/, "").replace(/:.*$/, "").replace(/^www\./, "");
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(s)) return null;
  return s;
}

// Read failover: try the primary D1; on any DB error, transparently retry the same read against the
// DB2 hot-standby mirror so the dashboard never goes dark during a primary-D1 blip. Zero cost on the
// healthy path (no probe — it only retries when the primary actually throws).
async function failover(env, fn) {
  try { return await fn(env); }
  catch (e) {
    if (env.DB2) { try { return await fn({ ...env, DB: env.DB2 }); } catch (e2) { /* fall through */ } }
    throw e;
  }
}

export default {
  async fetch(request, env, ctx) {
    if (request.method === "OPTIONS") return new Response(null, { headers: JSON_HEADERS });
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";
    try {
      // ---- auth: login / logout (public) ----
      if (request.method === "POST" && path === "/login") return await doLogin(env, request);
      if (request.method === "POST" && path === "/logout") return logoutResp();
      if (request.method === "GET" && path === "/health") return json({ ok: true, ts: nowSec() });
      // ---- AUTH GATE: all data reads + dashboard writes require a logged-in session.
      // SHARED_TOKEN (Bearer) bypasses for cron/shards/owner-tooling. /health + write endpoints below keep their own auth.
      if ((request.method === "GET" && path.startsWith("/api/")) || (request.method === "POST" && (path === "/reject" || path === "/scan_manual"))) {
        if (!(await sessionOk(request, env))) return bad("unauthorized — login required", 401);
      }
      // ---- public reads ----
      if (request.method === "GET" && path === "/api/stats") return await failover(env, (e) => apiStats(e, ctx));
      if (request.method === "GET" && path === "/api/leads") return await failover(env, (e) => apiLeads(e, url));
      if (request.method === "GET" && path === "/api/lead") return await failover(env, (e) => apiLead(e, url));
      if (request.method === "GET" && path === "/api/feed") return await failover(env, (e) => apiFeed(e, url));
      if (request.method === "GET" && path === "/api/spamhosts") return await failover(env, (e) => apiSpamHosts(e));
      if (request.method === "GET" && path === "/api/domains") return await failover(env, (e) => apiDomains(e, url));
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
        if (path === "/vm-pull") return await vmPull(env, body);      // Oracle VM scanner pulls a batch (pre-marked)
        if (path === "/vm-push") return await vmPush(env, body);      // Oracle VM scanner pushes findings back
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
          if (body.source === "wikidata") return json({ ok: true, ...(await harvestWikidata(env)) });
          if (body.source === "crux") return json({ ok: true, ...(await harvestCrux(env)) });
          if (body.source === "ripebd") return json({ ok: true, ...(await harvestRipeBd(env)) });
          if (body.source === "wikiedu") return json({ ok: true, ...(await harvestWikiEdu(env)) });
          if (body.source === "overpass") return json({ ok: true, ...(await harvestOverpass(env)) });
          if (body.source === "iptree") return json({ ok: true, ...(await harvestIpTree(env)) });
          if (body.source === "addr") return json({ ok: true, ...(await backfillAddresses(env)) });
          if (body.source === "cleanip") return json({ ok: true, ...(await enrichCleanIps(env)) });
          return json({ ok: true, ...(await harvestCommonCrawl(env)) });
        }
        if (path === "/heartbeat") return await heartbeat(env, body);
        if (path === "/keyusage") return await keyusage(env, body);
        if (path === "/sync_d2") return json({ ok: true, ...(await syncToD2(env)) });
      }
      return bad("not found", 404);
    } catch (e) {
      return bad("server error: " + (e && e.message ? e.message : String(e)), 500);
    }
  },

  async scheduled(event, env, ctx) {
    const c = event.cron;
    if (c === "*/15 * * * *") ctx.waitUntil(housekeeping(env).then(() => harvestLeadCoip(env)).then(() => backfillAddresses(env)).then(() => enrichCleanIps(env)).catch(() => {}));  // housekeeping + shared-IP multiplier + address back-fill + clean-site IP enrichment
    else if (c === "*/20 * * * *") {
      // ip-tree = the #1 all-TLD BD engine, rapiddns-heavy. Sharing ONE invocation with commonCrawl+reverseIp
      // starved it (0 'ip-tree' events, 624 ASN /24 blocks never swept). Give it a CLEAN, uncontended run on
      // alternate */20 ticks (full subrequest budget); reverseIp(productive)+commonCrawl run the other tick.
      const slot = Math.floor(Date.now() / 1200000) % 2;
      if (slot === 0) ctx.waitUntil(harvestIpTree(env).catch(() => {}));
      else ctx.waitUntil(Promise.allSettled([harvestReverseIp(env), harvestCommonCrawl(env)]));
    }
    else if (c === "37 */2 * * *") ctx.waitUntil(harvestCrux(env).then(() => harvestWikidata(env)).then(() => harvestWikiEdu(env)).catch(() => {}));   // CrUX BD top-list (238k all-TLD) + Wikidata BD-org sites + Wikipedia BD university/college sites (directories dropped — weak; still via /harvest_now)
    else if (c === "13 */6 * * *") ctx.waitUntil(Promise.allSettled([harvestCrtsh(env), harvestBdIpSweep(env), harvestRipeBd(env)]));        // crt.sh .bd identities + BD IP-space sweep (ipdeny) + RIPEstat authoritative BD prefixes. (OSM Overpass = scanner/harvest-overpass.mjs on the VM — its ~150s query exceeds Worker limits.)
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

// ===========================================================================
// ORACLE-VM SCANNER BRIDGE — the heavy fetch+detect runs on an always-free Oracle A1 VM (no Cloudflare CPU
// wall, no 50-subrequest cap, thousands of concurrent fetches). The Worker stays the SINGLE D1 writer: the VM
// only PULLS a batch of unscanned domains and PUSHES findings back. Same optimistic pre-mark deadlock-safety
// as scanSlice, so a VM crash never pins a poison domain. Runs alongside the CF shard engine (both feed D1).
// ===========================================================================
async function vmPull(env, body) {
  const n = Math.min(Math.max(Number(body.n) || 200, 1), 1000);
  // `fp` and `base` complete the cross-scan loop: fp is last pass's fingerprint (outbound hosts, script srcs,
  // title hash, sitemap size) which dnsfp diffs to spot a newly-appeared spam host on a previously-clean site —
  // near-proof of a fresh compromise at zero extra HTTP cost. `base` is the origin the reachability ladder
  // settled on last time, so a re-scan skips straight to the rung that worked.
  const COLS = "SELECT rowid,domain,business,phone,bd_score,source,fp,base FROM domains";
  // The VM is the only scanner running the full detector, so it is the only one served the re-qualification
  // tiers. Priority, highest first:
  //   1. never scanned                  — new harvest always goes first, it is the freshest lead surface
  //   2. dead=1 and not yet v2-qualified — the resurrection pass. These were marked dead by a detector that
  //      only ever tried https://, so an http-only site or one with an expired certificate was written off
  //      without being scanned once. Neglected and already-compromised sites are exactly the population with
  //      broken TLS, which makes this the single most hack-dense tier in the database.
  //   3. everything else not yet v2-qualified — the ordinary re-scan of the corpus under the new layers
  //   4. CONFIRMED leads not yet v2-qualified — re-adjudication. A confirmed lead is normally excluded from
  //      re-scanning (it is already caught, and re-scanning republishes duplicate "confirmed" events), but that
  //      exclusion also means a lead confirmed by a BUGGY detector can never be corrected and stays in the sales
  //      list forever. It is why banglachotigolpo1.com and potnhub.org are still confirmed leads today, months
  //      after the gate that would have parked them was written. Every lead must survive the current gate.
  //   5. least-recently-scanned          — the pre-existing continuity rotation, so scanners are never idle
  const tiers = [
    { sql: `${COLS} WHERE pass_no=0 ORDER BY bd_score DESC, rowid LIMIT ?`, args: [] },
    // HIGH-VALUE FIRST (2026-07-21): the .gov.bd/.edu.bd/.ac.bd sites are registrar-locked (can't be a spam brand),
    // so a hack on one is always a real, sellable victim — and they are exactly where cloaked gambling injection
    // (amrgc.edu.bd) hides. There are ~20k live + ~10.5k dead institutional rows still un-deep-scanned; pulling them
    // BEFORE the 76k foreign live-shallow rows deep-audits every BD government/school site in ~11h instead of week-3.
    // Live first, then the dead-resurrection of the same class. `pass_no ASC` keeps the queue moving (same rule as
    // the generic tiers); once all institutional are gen>=DETECTOR_GEN these return empty and fall through.
    { sql: `${COLS} WHERE gen<? AND dead=0 AND pass_no<9000 AND (domain LIKE '%.gov.bd' OR domain LIKE '%.edu.bd' OR domain LIKE '%.ac.bd') AND domain NOT IN (SELECT domain FROM findings WHERE confirmed=1) ORDER BY pass_no ASC, bd_score DESC LIMIT ?`, args: [DETECTOR_GEN] },
    { sql: `${COLS} WHERE gen<? AND dead=1 AND pass_no<9000 AND (domain LIKE '%.gov.bd' OR domain LIKE '%.edu.bd' OR domain LIKE '%.ac.bd') ORDER BY pass_no ASC, bd_score DESC LIMIT ?`, args: [DETECTOR_GEN] },
    // The re-qualification tiers order by pass_no ASC, not by bd_score. pass_no is advanced by the pre-mark below
    // on every single pull, so the queue keeps moving even if gen never advances — which is exactly what happens
    // whenever the VM is running older code than this Worker. Ordering by a static column instead would hand the
    // same top-N rows back on every pull forever, and a mid-upgrade window would livelock the whole scanner.
    { sql: `${COLS} WHERE dead=1 AND gen<? AND pass_no<9000 ORDER BY pass_no ASC, bd_score DESC LIMIT ?`, args: [DETECTOR_GEN] },
    { sql: `${COLS} WHERE gen<? AND pass_no>0 AND pass_no<9000 AND dead=0 AND domain NOT IN (SELECT domain FROM findings WHERE confirmed=1) ORDER BY pass_no ASC, bd_score DESC LIMIT ?`, args: [DETECTOR_GEN] },
    { sql: `${COLS} WHERE gen<? AND pass_no<9000 AND domain IN (SELECT domain FROM findings WHERE confirmed=1) ORDER BY pass_no ASC, rowid LIMIT ?`, args: [DETECTOR_GEN] },
    { sql: `${COLS} WHERE pass_no>0 AND pass_no<9000 AND domain NOT IN (SELECT domain FROM findings WHERE confirmed=1) ORDER BY pass_no ASC, rowid LIMIT ?`, args: [] },
  ];
  let rows = [];
  for (const t of tiers) {
    if (rows.length >= n) break;
    const got = (await env.DB.prepare(t.sql).bind(...t.args, n - rows.length).all()).results || [];
    rows = rows.concat(got);
  }
  // OPTIMISTIC PRE-MARK (deadlock-breaker): claim the whole batch before handing it out, so a VM crash mid-batch
  // can't leave rows pinned at pass_no=0 forever. ingestResults (via /vm-push) sets the dead flag, not pass_no.
  for (let i = 0; i < rows.length; i += 90) {
    const c = rows.slice(i, i + 90).map((r) => r.rowid);
    if (c.length) { try { await env.DB.prepare(`UPDATE domains SET pass_no=pass_no+1 WHERE rowid IN (${c.map(() => "?").join(",")})`).bind(...c).run(); } catch (e) {} }
  }
  return json({ ok: true, domains: rows });
}
async function vmPush(env, body) {
  // gen: the detector generation the VM actually ran. Only a scanner that ran the full detector may claim it,
  // and it can never claim a generation newer than this Worker knows about (a stale VM must not stamp rows
  // v2-qualified after the Worker has moved to v3).
  const agg = { rowids: Array.isArray(body.rowids) ? body.rowids : [], findings: Array.isArray(body.findings) ? body.findings : [], scanned: Number(body.scanned) || 0, errors: Number(body.errors) || 0, dead: Array.isArray(body.dead) ? body.dead : [], parked: Array.isArray(body.parked) ? body.parked : [], cleared: Array.isArray(body.cleared) ? body.cleared : [], fps: Array.isArray(body.fps) ? body.fps : [], gen: Math.min(Number(body.gen) || 0, DETECTOR_GEN) };
  // NEVER swallow this again. The old version caught the throw, said nothing, and still answered ok:true — so a
  // total ingestion outage looked exactly like a healthy engine from every angle the VM and the dashboard had.
  // It hid one for long enough to be found only by querying D1 by hand. Report it, and let the VM decide.
  let ingestError = "";
  try { await ingestResults(env, agg); } catch (e) { ingestError = (e && e.message ? e.message : String(e)).slice(0, 300); }
  const t = nowSec();
  // register the VM as a live worker + advance the engine tick so the dashboard reflects VM throughput
  try {
    await env.DB.prepare("INSERT INTO workers_heartbeat (worker_id,last_seen,scanned_total,current_batch,state) VALUES ('oracle-vm',?,?,?,'running') ON CONFLICT(worker_id) DO UPDATE SET last_seen=excluded.last_seen, scanned_total=workers_heartbeat.scanned_total+excluded.scanned_total, current_batch=excluded.current_batch, state='running'").bind(t, agg.scanned, Number(body.workers) || 1).run();
    await env.DB.prepare("INSERT INTO counters (metric,value) VALUES ('last_tick_ts',?) ON CONFLICT(metric) DO UPDATE SET value=?").bind(t, t).run();
  } catch (e) {}
  if (ingestError) {
    try { await env.DB.prepare("INSERT INTO events (kind,domain,detail,ts) VALUES ('error','vm-push',?,?)").bind(("ingest failed: " + ingestError).slice(0, 200), t).run(); } catch (e) {}
    return json({ ok: false, error: "ingest failed: " + ingestError, scanned: agg.scanned }, 500);
  }
  return json({ ok: true, ingested: agg.findings.length, scanned: agg.scanned });
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
        // apex must be written on EVERY insert path, not just ingestResults — a finding that reaches D1
        // without an organisation shows up as its own lead card and undoes the rollup.
        "INSERT INTO findings (domain,business,phone,category,layers,proof_snippet,proof_url,http_status,stage1_score,stage2_verdict,stage2_reason,stage2_category,confirmed,pass_no,first_ts,ts,evidence,is_bd,biz_type,status,apex) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
      ).bind(
        dom, (f.business || "").slice(0, 200), (f.phone || "").slice(0, 40), cat,
        (f.layers || "").slice(0, 200), (f.proof_snippet || "").slice(0, 600), (f.proof_url || "").slice(0, 300),
        Number(f.http_status) || 0, Number(f.stage1_score) || 0,
        (f.stage2_verdict || "").slice(0, 20), (f.stage2_reason || "").slice(0, 400), (f.stage2_category || "").slice(0, 30),
        conf, Number(body.pass_no) || 1, now, now, (f.evidence || "").slice(0, 4000),
        f.is_bd ? 1 : 0, (f.biz_type || "").slice(0, 30), (f.status || "lead").slice(0, 16),
        registrableOf(dom)
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

  // CANONICAL "currently hacked" definition (one source of truth for every view): a DISTINCT
  // domain that is confirmed=1, not rejected, and not a manual scan. Category breakdown uses the
  // same basis so headline = BD+Intl badges = category-sum all agree (fixes the 1153-vs-898 drift,
  // which came from `total_confirmed` being a lifetime cumulative event counter that double-counts
  // re-scan passes + historically-deleted rows — nothing was lost, the counter just over-counted).
  // Counted per ORGANISATION (apex), not per host — the dashboard's badges/table/gallery all group on apex
  // via dedupeLeads(), so counting hosts here would put two different numbers for the same thing on the same
  // screen. Rows written before the apex column existed have apex NULL and COALESCE back to their own host,
  // so this can only ever shrink towards the truth as the re-scan fills them in.
  const cats = (await env.DB.prepare("SELECT category, COUNT(DISTINCT COALESCE(NULLIF(apex,''),domain)) c FROM findings WHERE confirmed=1 AND status!='rejected' AND (is_manual IS NULL OR is_manual=0) AND category IS NOT NULL AND category!='' GROUP BY category ORDER BY c DESC").all()).results || [];
  const sources = (await env.DB.prepare("SELECT source, total_harvested, last_run FROM source_state ORDER BY total_harvested DESC LIMIT 60").all()).results || [];
  // ALWAYS include the cf-engine row (never time-filter it) so the dashboard shows the REAL last-tick age
  // instead of dropping it and falling back to the 99999 "restarting / all idle" sentinel. The 900s window
  // still hides the legacy per-shard w* rows.
  const workers = (await env.DB.prepare("SELECT * FROM workers_heartbeat WHERE worker_id='cf-engine' OR last_seen > ? ORDER BY last_seen DESC").bind(now - 900).all()).results || [];
  const keys = (await env.DB.prepare("SELECT * FROM key_usage WHERE day=? ORDER BY requests DESC").bind(dhakaDay(now)).all()).results || [];
  const recentRate = (await env.DB.prepare("SELECT COALESCE(SUM(scanned),0) s FROM hourly_stats WHERE hour=?").bind(dhakaHour(now)).first()) || { s: 0 };
  // BD vs global split of the registry (the .bd subset is the monetizable core). These were the
  // hot-path bottleneck (full scans of the 58k domains table — ~3.5s per cache-miss + a LIKE '%.bd'
  // leading-wildcard that can't use an index). Now precomputed in housekeeping (*/15) and read from
  // counters → instant. Live-scan fallback only if the precomputed value is missing.
  const bdRow = (counters.bd_domains != null) ? { c: counters.bd_domains } : ((await env.DB.prepare("SELECT COUNT(*) c FROM domains WHERE domain LIKE '%.bd'").first()) || { c: 0 });
  const unscRow = (counters.unscanned != null) ? { c: counters.unscanned } : ((await env.DB.prepare("SELECT COUNT(*) c FROM domains WHERE pass_no=0").first()) || { c: 0 });
  // "queue বাকি" used to render `unscanned` (pass_no=0), which drains to ~0 almost immediately and then sits
  // next to "১,৯২,৪২৩ domain" telling the owner the work is finished. The honest number is how much of the
  // corpus the DEEP detector has still never seen: only the VM stamps gen=DETECTOR_GEN, and 82% of the corpus
  // has still only met the light shards, which skip the reachability ladder and all 61 v2 layers.
  const deepRow = (await env.DB.prepare("SELECT COUNT(*) c FROM domains WHERE gen < ? AND dead=0").bind(DETECTOR_GEN).first()) || { c: 0 };
  const leadGeo = { bd: 0, intl: 0 };
  for (const r of (await env.DB.prepare("SELECT is_bd, COUNT(DISTINCT COALESCE(NULLIF(apex,''),domain)) c FROM findings WHERE confirmed=1 AND status!='rejected' AND (is_manual IS NULL OR is_manual=0) GROUP BY is_bd").all()).results || [])
    leadGeo[r.is_bd ? "bd" : "intl"] = r.c;
  const confirmedSites = leadGeo.bd + leadGeo.intl; // distinct hacked sites — THE headline number

  const body = {
    ok: true,
    now,
    counters,
    queue: q,
    rate_this_hour: recentRate.s,
    bd_domains: bdRow.c,
    unscanned: unscRow.c,
    deep_pending: deepRow.c,          // live domains the FULL detector has not adjudicated yet
    lead_geo: leadGeo,
    confirmed_sites: confirmedSites,                 // distinct hacked sites (live truth) — use this for the headline
    confirmed_lifetime: counters.total_confirmed || 0, // cumulative confirmation events (historical stat, not the live count)
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

// Short-lived cache for the leads list (the dashboard's heaviest poll). Keyed by the full query
// string so each distinct filter caches independently; trimmed on housekeeping. Cuts repeated
// full-table D1 reads to near-zero when several viewers (or one viewer's 30s poll) overlap.
let LEADS_CACHE = {};
// /api/domains — the harvested-domain registry = the user's "all BD sites" asset (63k+). type=clean
// (scanned & NOT confirmed-hacked → sellable SAFE BD businesses), all, or unscanned. region bd|intl by
// bd_score. count=1 → just the count (tab badge). Paginated; the dashboard export pulls successive pages.
async function apiDomains(env, url) {
  const type = url.searchParams.get("type") || "clean";
  const region = url.searchParams.get("region");
  const q = (url.searchParams.get("q") || "").trim().toLowerCase();
  const wantCount = url.searchParams.get("count") === "1";
  const limit = Math.min(parseInt(url.searchParams.get("limit") || "500", 10) || 500, 5000);
  const offset = Math.max(parseInt(url.searchParams.get("offset") || "0", 10) || 0, 0);
  const biz = url.searchParams.get("biz");         // filter clean sites by (name-derived) business category
  const source = url.searchParams.get("source");   // filter/organize by the harvest source it came from
  let where = "1=1"; const binds = [];
  // clean = scanned, reachable (NOT dead), and NOT confirmed-hacked → the sellable SAFE-site asset.
  if (type === "clean") where += " AND pass_no>0 AND pass_no<9000 AND (dead IS NULL OR dead=0) AND domain NOT IN (SELECT domain FROM findings WHERE confirmed=1)";
  else if (type === "dead") where += " AND dead=1";     // scanned but unreachable / no-longer-exists → kept separate
  // running = alive & NOT confirmed-hacked = the whole "chalu/nirapod" corpus (includes not-yet-scanned live sites)
  else if (type === "running") where += " AND (dead IS NULL OR dead=0) AND domain NOT IN (SELECT domain FROM findings WHERE confirmed=1)";
  else if (type === "unscanned") where += " AND pass_no=0";
  // type=all → whole registry. BD region = the same hosting-based definition as leads (bd_score>=25 OR .bd).
  if (region === "bd") where += " AND (bd_score>=25 OR domain LIKE '%.bd')";
  else if (region === "intl") where += " AND bd_score<25 AND domain NOT LIKE '%.bd'";
  if (source) { where += " AND source=?"; binds.push(source); }
  if (q) { where += " AND (lower(domain) LIKE ? OR lower(business) LIKE ?)"; binds.push("%" + q + "%", "%" + q + "%"); }
  // `biz` is derived in JS from the domain+business text, so it cannot be a SQL predicate. It was previously
  // applied AFTER LIMIT/OFFSET, which broke two things at once: the count branch ignored it entirely
  // (?biz=education&count=1 answered 118,314 — the UNFILTERED total — while the list returned 446 rows), and
  // paging advanced the offset by the FILTERED length against an UNFILTERED query, so rows were both repeated
  // and skipped. Now we over-fetch in windows and filter before slicing, so count and paging agree.
  if (biz) {
    const CAP = 20000;                 // bounded work per request; `truncated` tells the caller we stopped early
    const rows = (await env.DB.prepare(
      "SELECT domain,business,bd_score,source,pass_no,ip,gen,dead,(EXISTS(SELECT 1 FROM findings f WHERE f.domain=domains.domain AND f.confirmed=1)) AS hacked FROM domains WHERE " + where + " ORDER BY bd_score DESC, domain LIMIT ?"
    ).bind(...binds, CAP).all()).results || [];
    for (const r of rows) r.category = bizType(r.domain, "", r.business || "");
    const all = rows.filter((r) => r.category === biz);
    if (wantCount) return json({ ok: true, type, region: region || "all", count: all.length, truncated: rows.length >= CAP });
    const page = all.slice(offset, offset + limit);
    return json({ ok: true, type, region: region || "all", count: all.length, offset, returned: page.length, truncated: rows.length >= CAP, domains: page });
  }
  if (wantCount) {
    const c = await env.DB.prepare("SELECT COUNT(*) n FROM domains WHERE " + where).bind(...binds).first();
    return json({ ok: true, type, region: region || "all", count: c ? c.n : 0 });
  }
  const rows = (await env.DB.prepare(
    "SELECT domain,business,bd_score,source,pass_no,ip,gen,dead,(EXISTS(SELECT 1 FROM findings f WHERE f.domain=domains.domain AND f.confirmed=1)) AS hacked FROM domains WHERE " + where + " ORDER BY bd_score DESC, domain LIMIT ? OFFSET ?"
  ).bind(...binds, limit, offset).all()).results || [];
  // enrich each row with a name-derived business category (zero DB cost — regex on domain+business).
  // powers the "organize clean sites by category" view without a write-per-clean-domain.
  for (const r of rows) r.category = bizType(r.domain, "", r.business || "");
  return json({ ok: true, type, region: region || "all", count: rows.length, offset, returned: rows.length, domains: rows });
}
// apiSpamHosts — the self-learned spam-host blocklist (detector layer L45KNOWNHOST).
// Injection campaigns reuse the same delivery hosts across hundreds of victims, so a host already seen on
// confirmed victims is strong, free corroboration on the next one. Mined here rather than on the scanner
// because the Oracle VM — where the full detector runs — has no D1 of its own; it pulls this on startup.
// buildSpamHosts requires a host to appear on 3+ DISTINCT victims and excludes the victim's own domain,
// shared CDN/platform infrastructure, and per-customer-subdomain hosts, so one lead's CDN cannot become a signal.
let SPAMHOSTS_CACHE = null, SPAMHOSTS_TS = 0;
async function apiSpamHosts(env) {
  const now = nowSec();
  if (SPAMHOSTS_CACHE && now - SPAMHOSTS_TS < 3600) return json(SPAMHOSTS_CACHE);
  const rows = (await env.DB.prepare(
    "SELECT domain, proof_url, proof_snippet, evidence FROM findings WHERE confirmed=1 ORDER BY ts DESC LIMIT 3000"
  ).all()).results || [];
  // 5 distinct victims, not 3. At 3 the current 2,713-lead corpus mines exactly three hosts, and inspecting
  // them is the whole argument: one is a Kenyan business, one an unrelated .com, and only xhamster.com is
  // plausibly campaign infrastructure. That is not evidence, it is coincidence — and this layer has a feedback
  // loop (confirmed leads mint hosts that confirm the next leads), so a wrong host propagates. At 5 the list is
  // EMPTY today, which leaves L45KNOWNHOST inert exactly as it is now; it will arm itself as the corpus grows
  // and a real campaign shows up on enough victims to be undeniable.
  const mined = buildSpamHosts(rows.map((r) => ({ domain: r.domain, evidence: r.evidence, proof_url: r.proof_url, proof: r.proof_snippet })), 5);
  SPAMHOSTS_CACHE = { ok: true, ts: now, victimsScanned: rows.length, hosts: mined.slice(0, 1500) };
  SPAMHOSTS_TS = now;
  return json(SPAMHOSTS_CACHE);
}

async function apiLeads(env, url) {
  const cat = url.searchParams.get("category");
  const region = url.searchParams.get("region");   // bd | intl
  const biz = url.searchParams.get("biz");
  const onlyConfirmed = url.searchParams.get("confirmed") !== "0";
  const limit = Math.min(parseInt(url.searchParams.get("limit") || "200", 10) || 200, 5000);
  const offset = Math.max(parseInt(url.searchParams.get("offset") || "0", 10) || 0, 0);
  const manual = url.searchParams.get("manual") === "1";
  // slim=1 (dashboard default): omit the heavy per-row `evidence` JSON blob (≤4000 chars each) and
  // send only ev_count — shrinks the ~889-row payload ~5-10×. Full evidence loads lazily per lead
  // via /api/lead?id= when a modal opens. Zero behaviour change, far less bytes over the wire.
  const slim = url.searchParams.get("slim") === "1";
  const ck = url.search;
  const cached = LEADS_CACHE[ck];
  if (cached && nowSec() - cached.ts < 20) return json(cached.body);

  const evCol = slim
    ? "CASE WHEN json_valid(evidence) THEN json_array_length(evidence) ELSE (CASE WHEN proof_url IS NOT NULL AND proof_url!='' THEN 1 ELSE 0 END) END AS ev_count"
    : "evidence";
  // apex = the organisation behind the host. The dashboard groups on it so six compromised hosts under
  // buet.ac.bd render as ONE lead card for BUET with its six hosts listed, instead of filling the gallery.
  let sql = "SELECT id,domain,COALESCE(NULLIF(apex,''),domain) AS apex,business,phone,category,layers,proof_snippet,proof_url,http_status,stage2_verdict,stage2_reason,confirmed,ts," + evCol + ",is_bd,biz_type,status,ip,is_manual,mbatch,address,district,area FROM findings WHERE status != 'rejected'";
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
  // Server-side `status` predicate. Without it the review tab could only filter client-side inside whatever
  // `ts DESC LIMIT 500` happened to return — a ~10-hour window that contained ZERO adult rows, so the tab
  // rendered nothing while 10,259 findings waited and 1,117 gambling findings had no approval path at all.
  // A bigger limit could never fix that; it needed to be a WHERE clause.
  const status = url.searchParams.get("status");
  if (status) { sql += " AND status=?"; binds.push(status); }
  // `total` lets the client page instead of guessing. The old dashboard asked for limit=3000 every 30s and
  // silently truncated everything downstream — list, badges, gallery AND exports — once the corpus passed it.
  const countSql = "SELECT COUNT(*) n FROM (" + sql + ")";
  sql += " ORDER BY ts DESC LIMIT ? OFFSET ?";
  const totalRow = await env.DB.prepare(countSql).bind(...binds).first();
  binds.push(limit, offset);
  const rs = await env.DB.prepare(sql).bind(...binds).all();
  const rows = rs.results || [];
  const total = totalRow ? totalRow.n : rows.length;
  const body = { ok: true, leads: rows, limit, offset, slim, total, returned: rows.length, hasMore: offset + rows.length < total };
  LEADS_CACHE[ck] = { ts: nowSec(), body };
  return json(body);
}

// One full finding (with evidence) — lazy-loaded by the modal when the slim list omitted evidence.
async function apiLead(env, url) {
  const id = Number(url.searchParams.get("id"));
  if (!id) return bad("id required");
  const r = await env.DB.prepare("SELECT id,domain,evidence,proof_snippet,proof_url,layers,stage2_reason FROM findings WHERE id=?").bind(id).first();
  return json({ ok: true, lead: r || null });
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
      "INSERT INTO findings (domain,business,phone,category,layers,proof_snippet,proof_url,http_status,stage2_verdict,stage2_reason,confirmed,pass_no,first_ts,ts,evidence,is_bd,biz_type,status,is_manual,mbatch,address,district,area,ip,apex) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
    ).bind(dom, "", (r.phone || "").slice(0, 40), r.category, (r.layers || "").slice(0, 200), (r.proof || "").slice(0, 600), (r.proofUrl || "").slice(0, 300), r.httpStatus || 0, (r.verdict || "").slice(0, 20), (r.reason || "").slice(0, 400), r.confirmed ? 1 : 0, 1, now, now, JSON.stringify(r.evidence || []).slice(0, 4000), r.isBd ? 1 : 0, (r.bizType || "").slice(0, 30), (r.status || "manual").slice(0, 16), 1, name, (r.address || "").slice(0, 200), (r.district || "").slice(0, 40), (r.area || "").slice(0, 40), (r.ip || "").slice(0, 45), registrableOf(dom)));
  }
  if (stmts.length) await env.DB.batch(stmts);
  return json({ ok: true, scanned: out.length, results: out });
}

// Back-fill address/district on already-confirmed leads (one cheap homepage fetch + regex, ZERO
// Gemini). Bounded per run + '-' sentinel so each lead is tried once; runs on the */15 cron.
async function backfillAddresses(env) {
  const N = Number(env.ADDR_BACKFILL || 8);
  const rows = (await env.DB.prepare(
    "SELECT domain FROM findings WHERE confirmed=1 AND status!='rejected' AND COALESCE(address,'')!='-' AND (COALESCE(address,'')='' OR COALESCE(area,'')='') ORDER BY id LIMIT ?"
  ).bind(N).all()).results || [];
  if (!rows.length) return { tried: 0, backfilled: 0 };
  const stmts = [];
  let got = 0;
  for (const r of rows) {
    let c; try { c = await fetchContact(r.domain); } catch (e) { c = null; }
    const addr = (c && c.address) || "", dist = (c && c.district) || "", ar = (c && c.area) || "", ph = (c && c.phone) || "";
    if (addr || dist || ar) got++;
    // area always set; address/district set only when currently empty so a re-fetch can't wipe a real address
    stmts.push(env.DB.prepare(
      "UPDATE findings SET address=CASE WHEN COALESCE(address,'') IN ('','-') THEN ? ELSE address END, district=CASE WHEN COALESCE(district,'') IN ('','-') THEN ? ELSE district END, area=?, phone=CASE WHEN (phone IS NULL OR phone='') THEN ? ELSE phone END WHERE domain=? AND confirmed=1"
    ).bind(addr || "-", dist || "-", ar || "-", ph, r.domain));
  }
  if (stmts.length) await env.DB.batch(stmts);
  return { tried: rows.length, backfilled: got };
}

async function dohResolve(name) {
  try {
    const r = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=A`, { headers: { accept: "application/dns-json" }, signal: AbortSignal.timeout(5000) });
    const j = await r.json();
    const a = (j.Answer || []).find((x) => x.type === 1);
    return a ? a.data : null;
  } catch (e) { return null; }
}
// Resolve + store the hosting IP of a bounded slice of CLEAN (scanned, not-hacked) BD domains so the
// safe-site list can be clustered by shared server (same as the leads view). Bounded/run, '-' sentinel
// so each is tried once, on the */15 cron. ZERO LLM. Fills the 58k registry's IPs gradually.
async function enrichCleanIps(env) {
  const N = Number(env.CLEANIP_N || 25);
  const rows = (await env.DB.prepare(
    "SELECT domain FROM domains WHERE pass_no>0 AND pass_no<9000 AND (dead IS NULL OR dead=0) AND (ip IS NULL OR ip='') AND (bd_score>=25 OR domain LIKE '%.bd') AND domain NOT IN (SELECT domain FROM findings WHERE confirmed=1) ORDER BY bd_score DESC LIMIT ?"
  ).bind(N).all()).results || [];
  if (!rows.length) return { tried: 0 };
  const stmts = [];
  for (const r of rows) {
    let ip = "-";
    try { const a = await dohResolve(r.domain); if (a) ip = a; } catch (e) {}
    stmts.push(env.DB.prepare("UPDATE domains SET ip=? WHERE domain=?").bind(ip, r.domain));
  }
  if (stmts.length) await env.DB.batch(stmts);
  return { tried: rows.length };
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
  // `confirmed` is what the lead list, the badges and every export actually filter on, so status alone was a
  // no-op in both directions: approving a review row left it invisible, and rejecting left it counted. The
  // adult-review queue depends on this working — a human approving a genuine victim has to actually publish it.
  await env.DB.prepare("UPDATE findings SET status=?, confirmed=? WHERE id=?").bind(status, status === "lead" ? 1 : 0, id).run();
  return json({ ok: true, id, status, confirmed: status === "lead" ? 1 : 0 });
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
  // TWO-PHASE, STALL-PROOF DESIGN. The old design fanned out to ALL shards + the main slice in ONE awaited
  // Promise.all, then wrote last_tick_ts at the very END. When every shard started returning 1102 ("Worker
  // exceeded resource limits") the whole invocation burned its budget on the dead-shard fan-out and was
  // KILLED before the end-write ran → last_tick_ts froze for hours while the START heartbeat kept refreshing
  // (engine "looked alive" but scanned nothing). Fix: do the MAIN slice FIRST and advance the tick immediately,
  // THEN best-effort fan-out. Now even if EVERY shard 1102s, PHASE 1 has already scanned + advanced the tick,
  // so the engine can never stall or look dead — the shards can only ADD throughput.
  const nowT = () => Math.floor(Date.now() / 1000);
  const stampAlive = async () => { try { await env.DB.prepare("INSERT INTO workers_heartbeat (worker_id,last_seen,state) VALUES ('cf-engine',?,'running') ON CONFLICT(worker_id) DO UPDATE SET last_seen=excluded.last_seen, state='running'").bind(nowT()).run(); } catch (e) {} };
  // advance last_tick_ts + refine the heartbeat (scanned_total += n, live shard count). Called after EACH
  // phase so a later-phase death can never rewind the "engine alive" signal.
  const writeTick = async (addScanned, live) => {
    const t = nowT();
    try {
      await env.DB.prepare(
        "INSERT INTO workers_heartbeat (worker_id,last_seen,scanned_total,current_batch,state) VALUES ('cf-engine',?,?,?,'running') ON CONFLICT(worker_id) DO UPDATE SET last_seen=excluded.last_seen, scanned_total=workers_heartbeat.scanned_total+excluded.scanned_total, current_batch=excluded.current_batch, state='running'"
      ).bind(t, addScanned, live).run();
      await env.DB.prepare("INSERT INTO counters (metric,value) VALUES ('last_tick_ts',?) ON CONFLICT(metric) DO UPDATE SET value=?").bind(t, t).run();
    } catch (e) { /* heartbeat write blip — next minute's tick retries */ }
  };
  await stampAlive();
  const TMO = Number(env.SHARD_TIMEOUT_MS || 28000);
  const withTimeout = (p, ms) => Promise.race([Promise.resolve(p).catch(() => null), new Promise((res) => setTimeout(() => res(null), ms))]);

  // ---- PHASE 1: main slice (shard 0). Small (MAIN_SCAN_N) so it ALWAYS finishes inside the budget and
  // advances the tick. This alone keeps the engine alive + draining the queue even with every shard dead. ----
  // PHASE 1 runs on the MAIN worker's CRON invocation, whose CPU budget is STRICTER than a shard's fetch invocation.
  // Once the fresh queue drains, PHASE 1 re-scans heavy .gov.bd/.edu.bd WordPress sites; at n=3 that can exceed the
  // cron CPU wall and get hard-killed BEFORE writeTick → last_tick_ts freezes (engine looks stalled though shards
  // still drain via PHASE 2). Keep PHASE 1 to ONE light domain so the tick always advances; the shards carry volume.
  const mainN = Number(env.MAIN_SCAN_N || 1);
  const mainRes = await withTimeout(scanSlice(env, mainN), TMO);
  let mainScanned = 0;
  if (mainRes && Array.isArray(mainRes.rowids) && mainRes.rowids.length) {
    try { await ingestResults(env, mainRes); } catch (e) { /* ingest blip — rowids retry next tick */ }
    mainScanned = mainRes.scanned || 0;
  }
  await writeTick(mainScanned, 1);   // <-- engine is now provably alive + advancing, whatever the shards do

  // ---- PHASE 2: best-effort fan-out to sibling shards. Bounded; if all 1102/time-out it costs a little
  // wall-time and adds nothing, but PHASE 1 already succeeded, so the engine never stalls. ----
  const shards = Math.max(1, Number(env.SCAN_SHARDS || 1));
  const sub = env.SCAN_SUBDOMAIN || "javed-it";
  const hdr = { headers: { authorization: "Bearer " + (env.SHARED_TOKEN || "") } };
  const tasks = [];
  for (let i = 1; i < shards; i++) {
    const svc = env["SHARD" + i];
    const p = svc ? svc.fetch("https://shard/run", hdr) : fetch(`https://bd-scan-${i}.${sub}.workers.dev/run`, hdr);
    tasks.push(withTimeout(p.then((r) => r.json()), TMO));
  }
  if (tasks.length) {
    const results = await Promise.all(tasks);
    const agg = { rowids: [], findings: [], scanned: 0, errors: 0, dead: [], parked: [] };
    let live = 0;
    for (const r of results) {
      if (!r || typeof r !== "object" || r.error) continue;   // 1102 → r.json() rejected → null; scanSlice error → r.error
      live++;
      if (Array.isArray(r.rowids)) agg.rowids.push(...r.rowids);
      if (Array.isArray(r.findings)) agg.findings.push(...r.findings);
      if (Array.isArray(r.dead)) agg.dead.push(...r.dead);
      if (Array.isArray(r.parked)) agg.parked.push(...r.parked);   // forward shard-detected genuine-spam parks to the single writer
      agg.scanned += r.scanned || 0;
      agg.errors += r.errors || 0;
    }
    if (agg.rowids.length) { try { await ingestResults(env, agg); } catch (e) { /* rowids retry next tick */ } }
    await writeTick(agg.scanned, 1 + live);   // add ONLY the shard scanned (main already counted in PHASE 1)
  }
}

async function housekeeping(env) {
  const now = nowSec();
  // build scannable batches from freshly-harvested domains (race-free, single-threaded here)
  await buildBatches(env);
  // keep events feed small (last ~2000 by id)
  await env.DB.prepare("DELETE FROM events WHERE id < (SELECT COALESCE(MAX(id),0)-2000 FROM events)").run();
  // requeue claimed batches whose worker went silent > 30 min
  await env.DB.prepare("UPDATE batches SET status='ready', claimed_by=NULL WHERE status='claimed' AND claimed_ts < ?").bind(now - 1800).run();
  // precompute the expensive registry counts so /api/stats never full-scans the 58k domains table
  // on the hot path (this was the ~3.5s cache-miss cost). Read back from counters in apiStats.
  const bd = await env.DB.prepare("SELECT COUNT(*) c FROM domains WHERE domain LIKE '%.bd'").first();
  const un = await env.DB.prepare("SELECT COUNT(*) c FROM domains WHERE pass_no=0").first();
  await env.DB.batch([
    env.DB.prepare("INSERT INTO counters (metric,value) VALUES ('bd_domains',?) ON CONFLICT(metric) DO UPDATE SET value=?").bind(bd ? bd.c : 0, bd ? bd.c : 0),
    env.DB.prepare("INSERT INTO counters (metric,value) VALUES ('unscanned',?) ON CONFLICT(metric) DO UPDATE SET value=?").bind(un ? un.c : 0, un ? un.c : 0),
  ]);
  // reconcile the headline counter to the LIVE distinct truth — kills the cumulative-counter drift
  // (total_confirmed had accumulated re-scan + historically-deleted confirmation events, so it read
  // 1153 while the real distinct hacked-site count was ~889). Now the raw counter can't lie either.
  await env.DB.prepare(
    "UPDATE counters SET value=(SELECT COUNT(DISTINCT domain) FROM findings WHERE confirmed=1 AND status!='rejected' AND (is_manual IS NULL OR is_manual=0)) WHERE metric='total_confirmed'"
  ).run();
  // mirror primary → DB2 hot-standby (incremental, single-writer, well under free-tier budget)
  await syncToD2(env).catch(() => {});
  // refresh caches opportunistically
  STATS_CACHE = { ts: 0, body: null };
  LEADS_CACHE = {};
}

// Mirror the primary D1 into the DB2 hot-standby (single writer = no write-conflict, no data loss).
// Runs on the */15 housekeeping cron via waitUntil → never adds latency to live requests, never
// pressures Cloudflare on the hot path. Tiny aggregate tables are full-copied; findings + events are
// copied incrementally (only rows newer than the last sync, small overlap) so it stays far under the
// D1 free-tier write budget. The dashboard already dedupes leads by domain + counts via
// COUNT(DISTINCT domain), so any stale duplicate rows in the mirror never skew the numbers.
async function syncToD2(env) {
  const m = env.DB2;
  if (!m) return { ok: false, skipped: "no DB2" };
  const now = nowSec();
  const copyFull = async (table, cols) => {
    const rows = (await env.DB.prepare(`SELECT ${cols.join(",")} FROM ${table}`).all()).results || [];
    if (!rows.length) return 0;
    const per = Math.max(1, Math.floor(95 / cols.length)); // D1 caps ~100 bound params per statement
    const ph = "(" + cols.map(() => "?").join(",") + ")";
    const stmts = [];
    for (let i = 0; i < rows.length; i += per) {
      const chunk = rows.slice(i, i + per);
      const binds = [];
      for (const r of chunk) for (const c of cols) binds.push(r[c]);
      stmts.push(m.prepare(`INSERT OR REPLACE INTO ${table} (${cols.join(",")}) VALUES ` + chunk.map(() => ph).join(",")).bind(...binds));
    }
    for (let i = 0; i < stmts.length; i += 50) await m.batch(stmts.slice(i, i + 50));
    return rows.length;
  };
  // 1) tiny full-copy tables (~100 rows) — headline counters, charts, sources, system
  await copyFull("counters", ["metric", "value"]);
  await copyFull("daily_stats", ["day", "harvested", "scanned", "flagged", "confirmed", "errors", "gambling", "pharma", "adult", "deface", "cloak", "foreign_lang", "malware", "redirect"]);
  await copyFull("hourly_stats", ["hour", "scanned", "flagged", "confirmed", "errors"]);
  await copyFull("source_state", ["source", "cursor", "last_run", "total_harvested", "enabled"]);
  await copyFull("workers_heartbeat", ["worker_id", "last_seen", "scanned_total", "current_batch", "state"]);
  // 2) incremental findings (the lead data) — only rows touched since the last sync
  const lastRow = await env.DB.prepare("SELECT value FROM counters WHERE metric='d2_sync_ts'").first();
  const since = (lastRow && lastRow.value) ? lastRow.value - 180 : 0;
  const FC = ["id", "domain", "business", "phone", "category", "layers", "proof_snippet", "proof_url", "http_status", "stage1_score", "stage2_verdict", "stage2_reason", "stage2_category", "confirmed", "pass_no", "first_ts", "ts", "evidence", "is_bd", "biz_type", "status", "ip", "is_manual", "mbatch", "address", "district", "area", "apex"];
  const fr = (await env.DB.prepare(`SELECT ${FC.join(",")} FROM findings WHERE ts >= ? ORDER BY id`).bind(since).all()).results || [];
  const upsert = async (table, cols, rows) => {
    if (!rows.length) return;
    const per = Math.max(1, Math.floor(95 / cols.length));
    const ph = "(" + cols.map(() => "?").join(",") + ")";
    const stmts = [];
    for (let i = 0; i < rows.length; i += per) {
      const chunk = rows.slice(i, i + per);
      const binds = [];
      for (const r of chunk) for (const c of cols) binds.push(r[c]);
      stmts.push(m.prepare(`INSERT OR REPLACE INTO ${table} (${cols.join(",")}) VALUES ` + chunk.map(() => ph).join(",")).bind(...binds));
    }
    for (let i = 0; i < stmts.length; i += 50) await m.batch(stmts.slice(i, i + 50));
  };
  await upsert("findings", FC, fr);
  // 3) incremental recent events for the live feed on failover, then trim the mirror
  const ev = (await env.DB.prepare("SELECT id,kind,domain,detail,ts FROM events WHERE ts >= ? ORDER BY id LIMIT 500").bind(since).all()).results || [];
  await upsert("events", ["id", "kind", "domain", "detail", "ts"], ev);
  await m.prepare("DELETE FROM events WHERE id < (SELECT COALESCE(MAX(id),0)-2000 FROM events)").run();
  await env.DB.prepare("INSERT INTO counters (metric,value) VALUES ('d2_sync_ts',?) ON CONFLICT(metric) DO UPDATE SET value=?").bind(now, now).run();
  return { ok: true, findings: fr.length, events: ev.length, ts: now };
}
