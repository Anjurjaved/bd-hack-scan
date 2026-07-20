// harvest-crux-full.mjs — the FULL Chrome-UX-Report "country = Bangladesh" harvest, run ON THE ORACLE VM.
//
// Supersedes harvest-crux-bd.mjs, which took only the `.bd` slice of whatever months it had not seen.
// MEASURED 2026-07-19 on 202606: that meant it ingested 15,630 hosts and threw away 235,727 — including
// 144,340 `.com` origins. Those .com origins ARE the point. The owner's market is Bangladeshi schools,
// colleges, madrasas and businesses, and real BD businesses overwhelmingly live on .com, not .bd.
//
//   API_BASE=… SHARED_TOKEN=… node scanner/harvest-crux-full.mjs
//
// ── THREE SOURCES, ONE PIPELINE ─────────────────────────────────────────────────────────────────────
//   RANK 1  zakird/crux-top-lists mirror — 18 monthly BD files (202501…202606), verified live.
//   RANK 17 BigQuery chrome-ux-report.country_bd.YYYYMM — 103 monthly tables (201712…202606), i.e. 85
//           months the mirror does NOT have. VERIFIED REACHABLE (see the BigQuery section below).
//   RANK 39 Cloudflare Radar ranking/top?location=BD — a differently-derived (resolver-traffic) ranking.
//           VERIFIED WORKING BUT NEARLY WORTHLESS FOR DISCOVERY — see the honest measurement below.
//
// ── THE TRAP THIS SCRIPT EXISTS TO NOT FALL INTO ────────────────────────────────────────────────────
// "country = BD" in CrUX means "visited BY people in Bangladesh", NOT "is a Bangladeshi website". The
// list is full of Google/Facebook/CDN origins and, far worse, foreign gambling brands that stuff
// "bd"/"bangladesh" into their domain to rank for Bangladeshi searches. MEASURED on 202606: 5,944 of the
// 235,727 non-.bd hosts trip a BD name token and 1,969 trip a casino/adult brand token. Admitting hosts
// by NAME is exactly the mistake that forced a 24,000-row purge on 2026-07-04.
//
// So there are two tiers and only two:
//   TIER A  `.bd`      → admitted on the TLD alone. BTCL controls it; it cannot be self-asserted.
//   TIER B  everything → admitted ONLY by bdgate.isBdHost() (hosting IP inside APNIC-delegated BD space,
//                        or a registry-gated .bd nameserver). Never by the string.
//
// eduLexicon() IS used here, but ONLY to decide WHICH non-.bd host spends a DNS lookup FIRST — the
// education phase runs before the bulk phase because schools are the owner's stated first priority.
// Every non-.bd host still faces isBdHost() and nothing is ever admitted because its name looked BD.
//
// ── ENV (all optional; defaults tuned for the 946MB / 1 OCPU Always-Free VM) ────────────────────────
//   API_BASE               https://bd-hack-audit-api.javed-it.workers.dev
//   SHARED_TOKEN           —      required; bdgate.submit() throws without it
//   CRUX_SOURCES           mirror,radar,bq   comma list; drop one to disable it
//   CRUX_STATE             /opt/bd-scanner/.crux-full-state.json   resumable cursor (phase + line offset)
//   CRUX_GATE_CACHE        <BDGATE_DIR>/crux-gate.tsv  host<TAB>0|1 verdicts, so a DoH lookup is never repeated
//   CRUX_MONTHS_PER_RUN    2      mirror months touched per run
//   CRUX_GATE_BUDGET       6000   max isBdHost() calls per run (~3 min at 33 DoH/s)
//   CRUX_GATE_CONC         24     in-flight gate checks (bdgate's global token bucket is the real limiter)
//   CRUX_PHASES            bd,edu,nonbd
//   CRUX_SKIP_SPAMMY       1      1 = do not spend DNS on 1xbet-bd/mostbet-style brand names
//   CRUX_BD_ALIVE          0      1 = DoH-liveness-check the .bd tier too (rank 58; costs ~15k lookups/month)
//   CRUX_LIMIT_HOSTS       0      0 = unlimited; >0 caps hosts read per month (testing only)
//   CRUX_SEEN_MAX_AGE_H    12     how stale the bdgate seen-set may be before re-seeding from D1
//   RADAR_DATES_PER_RUN    8      Radar dates walked backwards per run
//   RADAR_STEP_DAYS        7
//   CF_API_EMAIL/CF_API_KEY        global-key auth (X-Auth-Email + X-Auth-Key) — verified working
//   CF_API_TOKEN                   bearer-token auth, used instead if present
//   BQ_PROJECT             jit-seo   billing project for the query job (the DATA is public)
//   BQ_ACCESS_TOKEN        —      OAuth token; if absent BQ_TOKEN_CMD is run to mint one
//   BQ_TOKEN_CMD           gcloud auth application-default print-access-token
//   BQ_MONTHS_PER_RUN      2

import { execFile } from "node:child_process";
import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import readline from "node:readline";
import { promisify } from "node:util";

import {
  CACHE_DIR, API_BASE_DEFAULT,
  loadBdRanges, isBdHostDetail, eduLexicon, alive,
  loadSeen, seen, markSeen, seenSize, normHost, submit, bdRangeStats,
} from "./bdgate.mjs";

const execFileP = promisify(execFile);
const env = process.env;
const num = (v, d) => (Number.isFinite(Number(v)) ? Number(v) : d);
const flag = (v, d) => (v === undefined ? d : v === "1" || v === "true");

const API_BASE = (env.API_BASE || API_BASE_DEFAULT).replace(/\/+$/, "");
const TOKEN = env.SHARED_TOKEN || "";
const SOURCES = new Set((env.CRUX_SOURCES || "mirror,radar,bq").split(",").map((s) => s.trim()).filter(Boolean));
const STATE_FILE = env.CRUX_STATE || "/opt/bd-scanner/.crux-full-state.json";
const GATE_CACHE_FILE = env.CRUX_GATE_CACHE || path.join(CACHE_DIR, "crux-gate.tsv");
const MONTHS_PER_RUN = num(env.CRUX_MONTHS_PER_RUN, 2);
const GATE_BUDGET = num(env.CRUX_GATE_BUDGET, 6000);
const GATE_CONC = Math.max(1, num(env.CRUX_GATE_CONC, 24));
const PHASES = (env.CRUX_PHASES || "bd,edu,nonbd").split(",").map((s) => s.trim()).filter(Boolean);
const SKIP_SPAMMY = flag(env.CRUX_SKIP_SPAMMY, true);
const BD_ALIVE = flag(env.CRUX_BD_ALIVE, false);
const LIMIT_HOSTS = num(env.CRUX_LIMIT_HOSTS, 0);
const SEEN_MAX_AGE_H = num(env.CRUX_SEEN_MAX_AGE_H, 12);
const SEEN_PAGE = num(env.CRUX_SEEN_PAGE, 1000);   // 5000 → HTTP 503 from the live Worker; see loadSeen call

const LIST_API = "https://api.github.com/repos/zakird/crux-top-lists/contents/data/country/bd";
const RAW_BASE = "https://raw.githubusercontent.com/zakird/crux-top-lists/main/data/country/bd/";
const UA = "bd-hack-audit/1.0 (+javeditsolution.com)";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const log = (...a) => console.log("[crux-full]", ...a);
const warn = (...a) => console.error("[crux-full]", ...a);
const rssMB = () => Math.round(process.memoryUsage().rss / 1048576);

// ═══════════════════════════════════════════════════════════════════════════════════════════════════
// STATE — a resumable {phase, offset} cursor per month.
//
// A month file holds ~252k hosts and the non-.bd tier costs a DNS lookup each; that is hours of polite
// DoH, far longer than one cron slot. So a run does bounded work and writes down exactly where it
// stopped. Nothing is ever re-fetched, and nothing is ever skipped because a run was cut short.
// ═══════════════════════════════════════════════════════════════════════════════════════════════════

const S_DEFAULT = { v: 2, mirror: {}, bq: {}, radarCursorDays: 0, updated: 0 };
let STATE = { ...S_DEFAULT };

async function loadState() {
  try {
    const j = JSON.parse(await fsp.readFile(STATE_FILE, "utf8"));
    STATE = { ...S_DEFAULT, ...j, mirror: j.mirror || {}, bq: j.bq || {} };
  } catch { STATE = { ...S_DEFAULT }; }
}
async function saveState() {
  STATE.updated = Date.now();
  try {
    await fsp.mkdir(path.dirname(STATE_FILE), { recursive: true }).catch(() => {});
    await fsp.writeFile(STATE_FILE, JSON.stringify(STATE));
  } catch (e) { warn("state save failed:", String(e).slice(0, 90)); }
}
// A month's cursor: phase = which tier we are on, off = data lines already consumed in that phase.
function monthCursor(bucket, key) {
  const b = STATE[bucket];
  if (!b[key]) b[key] = { phase: PHASES[0], off: 0 };
  return b[key];
}
function advancePhase(cur) {
  const i = PHASES.indexOf(cur.phase);
  if (i < 0 || i === PHASES.length - 1) { cur.phase = "done"; cur.off = 0; return; }
  cur.phase = PHASES[i + 1];
  cur.off = 0;
}

// ═══════════════════════════════════════════════════════════════════════════════════════════════════
// GATE VERDICT CACHE — the reason this harvester gets cheaper every run.
//
// isBdHost() on a non-.bd host is 1-4 DoH lookups. The CrUX BD corpus is ~250k non-.bd hosts and the
// 18 monthly files overlap enormously, so without a persistent verdict cache the same foreign CDN would
// be re-resolved 18 times. Stored as `host<TAB>0|1`, appended, stream-loaded.
// MEASURED memory: 100k cached verdicts ≈ 14MB. The corpus bounds it at a few hundred thousand.
// ═══════════════════════════════════════════════════════════════════════════════════════════════════

const GATE = new Map();
let gateStream = null;

async function loadGateCache() {
  try {
    const rl = readline.createInterface({ input: fs.createReadStream(GATE_CACHE_FILE, { encoding: "utf8" }), crlfDelay: Infinity });
    for await (const line of rl) {
      const t = line.indexOf("\t");
      if (t > 0) GATE.set(line.slice(0, t), line.charCodeAt(t + 1) === 49);
    }
  } catch {}
  return GATE.size;
}
function gateRemember(host, bd) {
  if (GATE.has(host)) return;
  GATE.set(host, bd);
  try {
    if (!gateStream) gateStream = fs.createWriteStream(GATE_CACHE_FILE, { flags: "a" });
    gateStream.write(host + "\t" + (bd ? "1" : "0") + "\n");
  } catch {}
}

// ═══════════════════════════════════════════════════════════════════════════════════════════════════
// STREAMING READERS — nothing here ever holds a whole dataset.
//
// The month file is 1.9MB gzipped / ~11MB of text. It is decompressed with the platform's
// DecompressionStream (zero npm deps, exactly as harvest-crux-bd.mjs did) and read a line at a time.
// The ONLY per-month structure retained is the bounded submit batch; there is deliberately no
// per-month Set of hosts. MEASURED justification: a full 251,357-host Set cost 130MB RSS, and it buys
// almost nothing — the same file contains only 794 duplicate origins in 252,151 rows (0.3%, the
// http:// and https:// forms of one site). markSeen() and the gate cache already dedupe across runs.
// ═══════════════════════════════════════════════════════════════════════════════════════════════════

async function* streamLines(webBody) {
  const reader = webBody.getReader();
  const dec = new TextDecoder();
  let buf = "";
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    buf += dec.decode(value, { stream: true });
    let nl;
    while ((nl = buf.indexOf("\n")) >= 0) { yield buf.slice(0, nl); buf = buf.slice(nl + 1); }
    if (buf.length > 1 << 20) { yield buf; buf = ""; }
  }
  if (buf) yield buf;
}

async function fetchRetry(url, opts = {}, tries = 4, label = "") {
  for (let a = 1; a <= tries; a++) {
    try {
      const r = await fetch(url, { headers: { "user-agent": UA, ...(opts.headers || {}) }, ...opts });
      // 502/429/5xx from a free public service is the rank-2 trap: back off, never hammer.
      if (r.status === 429 || r.status >= 500) { warn(`${label} http ${r.status}, backoff ${a}`); await sleep(a * 5000); continue; }
      return r;
    } catch (e) { warn(`${label} fetch error ${String(e).slice(0, 60)}, backoff ${a}`); await sleep(a * 5000); }
  }
  return null;
}

async function* monthHostLines(file) {
  const r = await fetchRetry(RAW_BASE + file, { signal: AbortSignal.timeout(180000) }, 4, file);
  if (!r || !r.ok) return;
  let first = true;
  for await (const line of streamLines(r.body.pipeThrough(new DecompressionStream("gzip")))) {
    if (first) { first = false; continue; }                 // "origin,rank" header
    if (!line) continue;
    const c = line.indexOf(",");
    const origin = c < 0 ? line : line.slice(0, c);
    const host = normHost(origin);
    if (host) yield host;
  }
}

// ═══════════════════════════════════════════════════════════════════════════════════════════════════
// THE TIER LOGIC
// ═══════════════════════════════════════════════════════════════════════════════════════════════════

const BD_INST = /\.(edu|ac|gov|mil)\.bd$/;

/** TIER A score. Institutional .bd is the highest-value lead type in the system. */
function bdTierRow(host) {
  return { domain: host, bd_score: BD_INST.test(host) ? 60 : 50 };
}

/** TIER B score, derived from WHY the gate admitted it — never from the name. */
function gatedRow(host, detail, isEdu) {
  let s = detail.reason === "ip-in-bd" ? 55 : detail.reason === "ns-bd-tld" ? 52 : 48;
  if (isEdu) s += 5;
  return { domain: host, bd_score: s };
}

// A bounded, self-flushing submit batch — the counterpart of "never buffer a whole dataset".
//
// TWO THINGS HERE ARE LOAD-BEARING, both found by running this against production rather than reasoning:
//
// 1. BATCH SIZE. A 500-row POST to /harvest MEASURED 11.3 seconds against the live Worker, and under
//    concurrent cron load whole 500-row chunks came back non-2xx and were dropped after 4 retries.
//    CRUX_BATCH defaults to 250 so each flush is one comfortably-sized sub-chunk inside submit().
//
// 2. markSeen() HAPPENS AFTER A SUCCESSFUL FLUSH, NEVER BEFORE. The seen-set is written to disk and
//    survives the process. Marking a host seen and then failing to POST it means that host is silently
//    never harvested again — a permanent hole, invisible in the logs. So hosts are held in `queued`
//    (in-run dedup only), and promoted to the durable seen-set only once the Worker has acknowledged
//    them. A failed flush releases them, and the next run picks them up.
const BATCH_SIZE = num(env.CRUX_BATCH, 250);

function makeBatch(source, size = BATCH_SIZE) {
  let rows = [];
  const queued = new Set();
  const tot = { posted: 0, found: 0, inserted: 0, dups: 0, failed: 0, lost: 0 };
  return {
    has(host) { return queued.has(host); },
    async add(host, row) {
      if (queued.has(host)) return;
      queued.add(host);
      rows.push(row);
      if (rows.length >= size) await this.flush();
    },
    async flush() {
      if (!rows.length) return;
      const batch = rows; rows = [];
      const hosts = batch.map((r) => r.domain);
      let r;
      try { r = await submit(API_BASE, TOKEN, source, batch); }
      catch (e) {
        warn(`submit(${source}) threw: ${String(e).slice(0, 120)}`);
        tot.lost += batch.length;
        for (const h of hosts) queued.delete(h);
        return;
      }
      tot.posted += r.posted; tot.found += r.found; tot.inserted += r.inserted; tot.dups += r.dups; tot.failed += r.failed;

      if (r.failed) {
        // Some chunk(s) never landed. Release every host in this flush rather than guess which —
        // re-POSTing a row the Worker already has is free (INSERT OR IGNORE); losing one is not.
        tot.lost += r.failed;
        for (const h of hosts) queued.delete(h);
        warn(`${source}: ${r.failed} rows failed to POST — released, will retry on a later run`);
        return;
      }
      // Acknowledged by the Worker → now it is safe to make "seen" durable.
      for (const h of hosts) markSeen(h);

      // The brief's hard rule, applied ONLY when the POST itself succeeded: chunks went through and the
      // Worker still counted found=0 means every row VANISHED into the d.domain===undefined bug.
      if (r.chunks > 0 && r.posted > 0 && r.found === 0) {
        warn(`FAILURE: ${source} posted ${r.posted} rows over ${r.chunks} successful chunks and the Worker found 0 — the payload shape is wrong, not the network`);
      }
    },
    tot,
  };
}

/**
 * Run the non-.bd tier through the ONLY admission function, with bounded concurrency.
 * `budget` is consumed per actual gate call; cache hits are free.
 */
async function gateAndSubmit(hosts, batch, counters, isEduPhase) {
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(GATE_CONC, hosts.length) }, async () => {
    for (;;) {
      const k = i++;
      if (k >= hosts.length) return;
      const host = hosts[k];
      let bd = GATE.get(host);
      if (bd === undefined) {
        let d;
        try { d = await isBdHostDetail(host); } catch (e) { warn("gate error", host, String(e).slice(0, 60)); continue; }
        bd = d.bd;
        counters.gateCalls++;
        gateRemember(host, bd);
        if (bd) {
          counters.admitted++;
          counters.reasons[d.reason] = (counters.reasons[d.reason] || 0) + 1;
          if (counters.samples.length < 40) counters.samples.push(`${host} (${d.reason})`);
          await batch.add(host, gatedRow(host, d, isEduPhase));
        }
      } else if (bd) {
        // A cached admit that has not reached the registry yet (e.g. an earlier run's POST failed).
        counters.cacheAdmits++;
        await batch.add(host, gatedRow(host, { reason: "cached" }, isEduPhase));
      }
    }
  }));
}

// ═══════════════════════════════════════════════════════════════════════════════════════════════════
// ONE MONTH, ONE PHASE — the unit of work.
//
// phase "bd"    : zero network beyond the POST. Every `.bd` host straight in.
// phase "edu"   : only non-.bd hosts whose NAME suggests a school/college/madrasa/institute. MEASURED
//                 on 202606: 6,538 of 235,727 non-.bd hosts (2.8%) — roughly 3 minutes of polite DoH
//                 for the owner's single highest-priority segment. The lexicon picks the ORDER; the
//                 gate still makes the decision.
// phase "nonbd" : every remaining non-.bd host, in CrUX rank order (the files are sorted most-popular
//                 first, which is a good proxy for "a real site worth scanning").
// ═══════════════════════════════════════════════════════════════════════════════════════════════════

async function runMonth(bucket, key, lineSource, label, counters) {
  const cur = monthCursor(bucket, key);
  if (cur.phase === "done") return;

  const batch = makeBatch(bucket === "bq" ? "crux-bq" : "crux-full");
  let read = 0, consumed = 0, pending = [];
  const t0 = Date.now();

  const flushPending = async () => {
    if (!pending.length) return;
    const hosts = pending; pending = [];
    await gateAndSubmit(hosts, batch, counters, cur.phase === "edu");
  };

  for await (const host of lineSource) {
    read++;
    if (LIMIT_HOSTS && read > LIMIT_HOSTS) break;
    if (read <= cur.off) continue;                          // resume: skip what a previous run consumed
    consumed++;

    const isBd = host.endsWith(".bd");

    if (cur.phase === "bd") {
      if (!isBd) continue;
      if (seen(host)) continue;
      if (BD_ALIVE) { counters.aliveCalls++; if (!(await alive(host))) { counters.dead++; continue; } }
      if (!batch.has(host)) { counters.bdAdmitted++; await batch.add(host, bdTierRow(host)); }
      continue;
    }

    // Both non-.bd phases from here on.
    if (isBd) continue;                                     // already handled in the bd phase
    if (seen(host)) continue;                               // already in the registry
    const cached = GATE.get(host);
    if (cached === false) { counters.cacheRejects++; continue; }   // known-foreign, costs nothing

    const lex = eduLexicon(host);
    if (cur.phase === "edu" && !lex.isEdu) continue;
    if (cur.phase === "nonbd" && lex.isEdu && PHASES.includes("edu")) continue;  // the edu phase had it
    if (SKIP_SPAMMY && lex.isSpammy) { counters.spamSkipped++; continue; }

    pending.push(host);
    if (pending.length >= GATE_CONC * 4) {
      await flushPending();
      // Budget is checked AFTER a flush so the cursor never lands mid-batch.
      if (counters.gateCalls >= GATE_BUDGET) { cur.off = read; break; }
    }
    if (read % 25000 === 0) log(`  ${label}/${cur.phase} … ${read} read, ${counters.gateCalls} gated, ${counters.admitted} admitted, rss ${rssMB()}MB`);
  }
  // Loop ran to completion without breaking → this phase has consumed the whole file.
  if (pending.length) await flushPending();
  await batch.flush();

  const finished = counters.gateCalls < GATE_BUDGET && !(LIMIT_HOSTS && read > LIMIT_HOSTS);
  if (finished) advancePhase(cur);
  await saveState();

  counters.lost += batch.tot.lost;
  log(`${label}/${finished ? "completed" : "partial"} phase=${cur.phase} — read ${read} (${consumed} new to cursor), ` +
      `bd+${counters.bdAdmitted}, gated ${counters.gateCalls}, admitted ${counters.admitted}, ` +
      `found ${batch.tot.found}, inserted ${batch.tot.inserted}, dups ${batch.tot.dups}` +
      (batch.tot.lost ? `, LOST ${batch.tot.lost} (released for retry)` : "") +
      ` (${((Date.now() - t0) / 1000).toFixed(0)}s, rss ${rssMB()}MB)`);
}

// ═══════════════════════════════════════════════════════════════════════════════════════════════════
// SOURCE 1 (RANK 1) — the zakird GitHub mirror. VERIFIED LIVE 2026-07-19:
//   18 files, 202501.csv.gz … 202606.csv.gz, ~1.9MB each, 3.5s to download.
//   202606 → 252,151 rows, 251,357 unique hosts, 15,630 .bd, 144,340 .com.
// ═══════════════════════════════════════════════════════════════════════════════════════════════════

async function listMirrorMonths() {
  const r = await fetchRetry(LIST_API, { headers: { accept: "application/vnd.github+json" }, signal: AbortSignal.timeout(60000) }, 3, "github-list");
  if (!r || !r.ok) { warn("github contents API unavailable" + (r ? " http " + r.status : "")); return []; }
  const a = await r.json().catch(() => []);
  return (Array.isArray(a) ? a : []).map((x) => x.name).filter((n) => /^\d{6}\.csv\.gz$/.test(n)).sort();
}

async function runMirror(counters) {
  const months = await listMirrorMonths();
  if (!months.length) return;
  // Newest first: the freshest month has the most live sites. Months already "done" are skipped free.
  const todo = months.slice().reverse().filter((m) => monthCursor("mirror", m).phase !== "done");
  log(`mirror: ${months.length} BD month files, ${months.length - todo.length} complete, ${todo.length} outstanding`);
  let touched = 0;
  for (const file of todo) {
    if (touched >= MONTHS_PER_RUN) break;
    if (counters.gateCalls >= GATE_BUDGET) { log("mirror: gate budget spent, stopping"); break; }
    touched++;
    // Each phase re-streams the file. That is deliberate: the download is 1.9MB / ~4s, which is far
    // cheaper than holding 250k hosts in RAM to avoid it.
    for (let guard = 0; guard < PHASES.length + 1; guard++) {
      const cur = monthCursor("mirror", file);
      if (cur.phase === "done") break;
      const before = cur.phase;
      await runMonth("mirror", file, monthHostLines(file), file, counters);
      if (counters.gateCalls >= GATE_BUDGET) break;
      if (monthCursor("mirror", file).phase === before) break;  // partial, budget or limit hit
    }
    await sleep(1500);
  }
}

// ═══════════════════════════════════════════════════════════════════════════════════════════════════
// SOURCE 2 (RANK 17) — BigQuery chrome-ux-report.country_bd. ASSESSED HONESTLY, AND IT WORKS.
//
// The brief asked whether this is reachable without a card. MEASURED 2026-07-19 from this machine:
//   • chrome-ux-report.country_bd holds 103 monthly tables, 201712 … 202606. The GitHub mirror has 18
//     (202501+), so 85 months exist ONLY here.
//   • The DATA is a public dataset; what needs credentials is the query JOB's billing project.
//   • This project already has usable Google credentials: gcloud ADC for mdanjurjaved@gmail.com and
//     project `jit-seo` (see ~/.claude/reference/credentials-and-access.md §7). No new card, no signup.
//   • `SELECT DISTINCT origin FROM country_bd.201712` → jobComplete, totalRows 6,851, scanned 586,044
//     BYTES in 2.5s. BigQuery is columnar, so a one-column DISTINCT reads ~0.6MB of a 67MB table.
//     A recent month (202606) dry-runs at 8.2MB. All 103 months ≈ 0.5GB, i.e. 0.05% of the 1TB/month
//     free query allowance. Cost is effectively zero and no card is required for the sandbox tier.
//
// THE ONE REAL CAVEAT, stated plainly: the credential is a user OAuth token on the developer laptop.
// The Oracle VM has no gcloud. So `bq` is a source you run from the laptop, or after copying ADC to the
// VM. If no token can be minted this phase logs and skips — it never fails the run.
// ═══════════════════════════════════════════════════════════════════════════════════════════════════

const BQ_PROJECT = env.BQ_PROJECT || "jit-seo";
const BQ_MONTHS_PER_RUN = num(env.BQ_MONTHS_PER_RUN, 2);
const BQ_TOKEN_CMD = env.BQ_TOKEN_CMD || "gcloud auth application-default print-access-token";
let BQ_TOKEN = null;

async function bqToken() {
  if (BQ_TOKEN !== null) return BQ_TOKEN;
  if (env.BQ_ACCESS_TOKEN) return (BQ_TOKEN = env.BQ_ACCESS_TOKEN);
  const parts = BQ_TOKEN_CMD.split(/\s+/);
  // gcloud is commonly outside PATH under systemd; try the standard install location too.
  for (const bin of [parts[0], path.join(env.HOME || "", "google-cloud-sdk/bin", parts[0])]) {
    try {
      const { stdout } = await execFileP(bin, parts.slice(1), { timeout: 60000 });
      const t = stdout.trim();
      if (t.length > 50) return (BQ_TOKEN = t);
    } catch {}
  }
  return (BQ_TOKEN = "");
}

async function bqListMonths(token) {
  const r = await fetchRetry(
    `https://bigquery.googleapis.com/bigquery/v2/projects/chrome-ux-report/datasets/country_bd/tables?maxResults=500`,
    { headers: { authorization: "Bearer " + token }, signal: AbortSignal.timeout(60000) }, 3, "bq-list");
  if (!r || !r.ok) return [];
  const j = await r.json().catch(() => ({}));
  return (j.tables || []).map((t) => t.tableReference.tableId).filter((t) => /^\d{6}$/.test(t)).sort();
}

/** Page a month's DISTINCT origins out of BigQuery as an async iterator of hostnames. */
async function* bqMonthHosts(token, month) {
  const body = {
    useLegacySql: false, timeoutMs: 120000, maxResults: 20000,
    query: "SELECT DISTINCT origin FROM `chrome-ux-report.country_bd." + month + "` ORDER BY origin",
  };
  let r = await fetchRetry(`https://bigquery.googleapis.com/bigquery/v2/projects/${BQ_PROJECT}/queries`, {
    method: "POST",
    headers: { authorization: "Bearer " + token, "content-type": "application/json" },
    body: JSON.stringify(body), signal: AbortSignal.timeout(180000),
  }, 3, "bq-query");
  if (!r || !r.ok) { warn(`bq ${month}: query failed` + (r ? " http " + r.status : "")); return; }
  let j = await r.json().catch(() => null);
  if (!j || j.error) { warn(`bq ${month}:`, JSON.stringify(j?.error || {}).slice(0, 200)); return; }

  const jobId = j.jobReference?.jobId;
  const loc = j.jobReference?.location;
  for (;;) {
    for (const row of j.rows || []) {
      const h = normHost(row.f?.[0]?.v);
      if (h) yield h;
    }
    if (!j.pageToken || !jobId) return;
    const u = `https://bigquery.googleapis.com/bigquery/v2/projects/${BQ_PROJECT}/queries/${jobId}` +
      `?maxResults=20000&pageToken=${encodeURIComponent(j.pageToken)}` + (loc ? `&location=${loc}` : "");
    const n = await fetchRetry(u, { headers: { authorization: "Bearer " + token }, signal: AbortSignal.timeout(180000) }, 3, "bq-page");
    if (!n || !n.ok) return;
    j = await n.json().catch(() => null);
    if (!j) return;
  }
}

async function runBigQuery(counters) {
  const token = await bqToken();
  if (!token) {
    log("bq: SKIPPED — no OAuth token. Set BQ_ACCESS_TOKEN, or install gcloud and run " +
        "`gcloud auth application-default login`. The dataset is public; only the query job needs a billing project.");
    return;
  }
  const months = await bqListMonths(token);
  if (!months.length) { warn("bq: could not list country_bd tables — token may lack bigquery scope"); return; }
  // Only the months the free GitHub mirror does NOT carry. Fetching 202501+ twice would be pure waste.
  const mirrorHas = new Set((await listMirrorMonths()).map((f) => f.slice(0, 6)));
  const todo = months.filter((m) => !mirrorHas.has(m) && monthCursor("bq", m).phase !== "done").reverse();
  log(`bq: ${months.length} country_bd tables (${months[0]}…${months[months.length - 1]}), ` +
      `${months.length - mirrorHas.size} beyond the mirror, ${todo.length} outstanding`);
  let touched = 0;
  for (const m of todo) {
    if (touched >= BQ_MONTHS_PER_RUN || counters.gateCalls >= GATE_BUDGET) break;
    touched++;
    for (let guard = 0; guard < PHASES.length + 1; guard++) {
      const cur = monthCursor("bq", m);
      if (cur.phase === "done") break;
      const before = cur.phase;
      await runMonth("bq", m, bqMonthHosts(token, m), "bq:" + m, counters);
      if (counters.gateCalls >= GATE_BUDGET) break;
      if (monthCursor("bq", m).phase === before) break;
    }
    await sleep(1500);
  }
}

// ═══════════════════════════════════════════════════════════════════════════════════════════════════
// SOURCE 3 (RANK 39) — Cloudflare Radar. IT WORKS, AND IT IS ESSENTIALLY WORTHLESS. Measured, not guessed.
//
// TOP60 #39 predicted "1e4-3e4 across a year of dates" from `limit=1000`. That is wrong:
//   • limit=1000 → HTTP 400 `{"code":2001,"message":"Number must be less than or equal to 100"}`.
//     The endpoint caps at 100 rows. There is no paging parameter.
//   • Walking 12 monthly dates (2025-06 … 2026-07) returned 1,200 rows containing 159 UNIQUE domains,
//     of which exactly ONE was .bd — google.com.bd, which is Google. The rest are the global CDN/social
//     top-100 that every country's list shares.
//   • The downloadable RANKING_BUCKET datasets (top_1000000 etc.) are tagged GLOBAL and take no
//     location parameter, so they cannot substitute.
//   • rankingType=TRENDING_RISE ignores `location` entirely — it returned gamersky.com, sfr.fr, jumia.ma.
//   • Anonymous access is 9106 "Missing X-Auth-Key…". The account's global key works via
//     X-Auth-Email + X-Auth-Key (Bearer on the global key does NOT).
// It is kept because it is 8 cheap requests and a genuinely different (resolver-traffic) basis, so it
// can surface a popular BD site CrUX missed. It must never be counted on for volume.
// ═══════════════════════════════════════════════════════════════════════════════════════════════════

const RADAR_DATES_PER_RUN = num(env.RADAR_DATES_PER_RUN, 8);
const RADAR_STEP_DAYS = num(env.RADAR_STEP_DAYS, 7);

function radarAuth() {
  if (env.CF_API_TOKEN) return { authorization: "Bearer " + env.CF_API_TOKEN };
  if (env.CF_API_EMAIL && env.CF_API_KEY) return { "x-auth-email": env.CF_API_EMAIL, "x-auth-key": env.CF_API_KEY };
  return null;
}

async function runRadar(counters) {
  const auth = radarAuth();
  if (!auth) { log("radar: SKIPPED — set CF_API_TOKEN, or CF_API_EMAIL + CF_API_KEY"); return; }
  const batch = makeBatch("crux-radar");
  const start = STATE.radarCursorDays || 0;
  const hosts = new Set();
  let reqs = 0;
  for (let k = 0; k < RADAR_DATES_PER_RUN; k++) {
    const daysBack = start + k * RADAR_STEP_DAYS;
    const d = new Date(Date.now() - daysBack * 86400000).toISOString().slice(0, 10);
    const r = await fetchRetry(`https://api.cloudflare.com/client/v4/radar/ranking/top?location=BD&limit=100&date=${d}`,
      { headers: auth, signal: AbortSignal.timeout(45000) }, 3, "radar");
    reqs++;
    if (!r || !r.ok) { warn(`radar ${d}: http ${r ? r.status : "fail"}`); continue; }
    const j = await r.json().catch(() => ({}));
    if (!j.success) { warn(`radar ${d}:`, JSON.stringify(j.errors || []).slice(0, 160)); continue; }
    for (const rows of Object.values(j.result || {})) {
      for (const row of Array.isArray(rows) ? rows : []) {
        const h = normHost(row.domain);
        if (h) hosts.add(h);
      }
    }
    await sleep(600);
  }
  STATE.radarCursorDays = start + RADAR_DATES_PER_RUN * RADAR_STEP_DAYS;
  counters.radarRequests = reqs;
  counters.radarUnique = hosts.size;

  const need = [];
  for (const h of hosts) {
    if (seen(h)) continue;
    if (h.endsWith(".bd")) { await batch.add(h, bdTierRow(h)); continue; }
    if (GATE.get(h) === false) continue;
    if (SKIP_SPAMMY && eduLexicon(h).isSpammy) continue;
    need.push(h);
  }
  // Same gate as everything else. A Radar top-100 domain gets no special treatment for being popular.
  await gateAndSubmit(need, batch, counters, false);
  await batch.flush();
  await saveState();
  log(`radar: ${reqs} requests, ${hosts.size} unique domains, ${need.length} needed gating, ` +
      `${batch.tot.inserted} inserted (cursor now ${STATE.radarCursorDays}d back)`);
}

// ═══════════════════════════════════════════════════════════════════════════════════════════════════

async function main() {
  if (!TOKEN) { warn("SHARED_TOKEN missing — bdgate.submit() would throw on the first POST"); process.exit(1); }

  const counters = {
    gateCalls: 0, admitted: 0, bdAdmitted: 0, cacheRejects: 0, cacheAdmits: 0, spamSkipped: 0,
    aliveCalls: 0, dead: 0, radarRequests: 0, radarUnique: 0, lost: 0, reasons: {}, samples: [],
  };

  await loadState();
  const ranges = await loadBdRanges();
  log(`APNIC BD space: ${ranges.records} records → ${ranges.blocks} disjoint blocks, ${ranges.addresses} addresses (${ranges.source})`);
  const g = await loadGateCache();
  // pageSize MUST be well under bdgate's 5000 default. MEASURED against the live Worker:
  //   /api/domains?type=all&limit=5000 → HTTP 503 in 0.85s (every time)
  //   /api/domains?type=all&limit=1000 → HTTP 200, 122KB
  // With the default, page 0 fails all 3 retries and the seen-set silently seeds ZERO hosts — which
  // makes every already-known domain look new and re-POSTs the entire registry. maxPages is raised to
  // match, since 1000-row pages need ~165 of them to cover a 165k-row registry.
  const s = await loadSeen(API_BASE, TOKEN, { maxAgeH: SEEN_MAX_AGE_H, pageSize: SEEN_PAGE, maxPages: 400 });
  log(`seen-set ${s.total} hosts (disk ${s.fromDisk}, api ${s.fromApi}/${s.pages}p) · gate cache ${g} verdicts · rss ${rssMB()}MB`);
  log(`sources=[${[...SOURCES]}] phases=[${PHASES}] budget=${GATE_BUDGET} conc=${GATE_CONC} skipSpammy=${SKIP_SPAMMY}`);

  const t0 = Date.now();
  if (SOURCES.has("mirror")) await runMirror(counters);
  if (SOURCES.has("bq") && counters.gateCalls < GATE_BUDGET) await runBigQuery(counters);
  if (SOURCES.has("radar")) await runRadar(counters);
  await saveState();

  log(`DONE in ${((Date.now() - t0) / 1000).toFixed(0)}s — bd-tier +${counters.bdAdmitted}, ` +
      `gate calls ${counters.gateCalls}, ADMITTED ${counters.admitted}, ` +
      `free cache rejects ${counters.cacheRejects}, cached admits ${counters.cacheAdmits}, ` +
      `spam skipped ${counters.spamSkipped}, seen-set ${seenSize()}, rss ${rssMB()}MB`);
  if (counters.lost) warn(`${counters.lost} rows could not be POSTed and were released — they are NOT marked seen and will be retried.`);
  if (Object.keys(counters.reasons).length) log("admit reasons:", JSON.stringify(counters.reasons));
  if (counters.samples.length) log("sample admits:", counters.samples.slice(0, 12).join(", "));
  if (counters.gateCalls > 0 && counters.admitted === 0) {
    warn(`${counters.gateCalls} hosts gated and ZERO admitted — verify APNIC ranges loaded (${bdRangeStats().source}) before trusting this.`);
  }
}

main().catch((e) => { console.error("[crux-full] fatal:", e); process.exit(1); });
