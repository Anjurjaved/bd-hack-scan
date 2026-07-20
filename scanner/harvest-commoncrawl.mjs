// harvest-commoncrawl.mjs — Common Crawl harvester for Bangladeshi hostnames, run ON THE ORACLE VM.
//
// Ranks 2 (cluster.idx byte-range slice), 38 (webgraph domain-vertices bd. prefix), 53 (backwards
// crawl walk). Zero npm dependencies, plain node ESM, streaming throughout, ~60MB resident.
//
//   API_BASE=… SHARED_TOKEN=… node scanner/harvest-commoncrawl.mjs
//
// ─────────────────────────────────────────────────────────────────────────────────────────────────
// WHY THE OLD HARVESTER PRODUCED 14 DOMAINS IN ITS LIFETIME
//
// workers/src/harvest.js:harvestCommonCrawl() pages the CDX *query* API:
//     https://index.commoncrawl.org/CC-MAIN-…-index?url=*.bd&output=json&page=N
// with a 320KB read cap. Measured behaviour: that endpoint returns capture records for ONE host at a
// time, so a page is ~10,000 captures of the same domain and a whole run yields a handful of new
// names. It is not tunable — it is the wrong endpoint. It is deleted here, not adjusted.
//
// THE REPLACEMENT (rank 2), verified live 2026-07-19/20 against CC-MAIN-2026-25:
//   1. cluster.idx is the crawl's 101,131,403-byte sparse index, SORTED by SURT key, and the server
//      honours Range (`accept-ranges: bytes`). So the `bd,` region is found by BINARY SEARCH over
//      byte offsets — 56 tiny reads, ~48s, instead of downloading 101MB.
//   2. MEASURED: the bd, keys occupy cluster.idx bytes 2,372,075-2,404,653, which is 210 index
//      blocks, and every one of them lives in cdx-00007.gz at bytes 62,107,596-106,657,210 — one
//      contiguous 42.5MB run. (211 blocks are fetched: the block immediately BEFORE the first bd,
//      key must be included, because a sparse index entry is the FIRST key in its block, so the
//      earliest bd, captures live at the tail of the preceding block.)
//   3. Each block is an independent gzip member, so the concatenated range decompresses as one
//      multi-member gzip stream and is parsed line-by-line without ever being buffered.
//   FULL-SLICE RESULT: 1 range request, 42.5MB, 232s, 34.5MB RSS → 629,875 bd, capture keys →
//   10,855 unique hostnames / 6,980 registrable apexes. 6,111 of those hosts are institutional
//   (3,340 .gov.bd · 2,138 .edu.bd · 618 .ac.bd · 15 .mil.bd) — 56% of the slice, which is exactly
//   the owner's stated priority target.
//
//   ⚠ THE BYTE OFFSETS ARE PER-CRAWL AND MUST NEVER BE HARDCODED. Measured on the very next crawl,
//   CC-MAIN-2026-21: 222 blocks, still all in cdx-00007.gz, but at bytes 131,962,955-178,548,033.
//   Same file name, completely different offsets. That is why every crawl gets its own binary search
//   (57 requests, ~11s) whose result is then cached in the state file forever.
//
// RANK 38 — webgraph domain-vertices. Also sorted, also a superset of the CDX .bd set (it includes
// domains that were only ever LINKED TO, never crawled). It is a single ~900MB gzip member so Range
// is useless, but sorting means we can stop the moment we pass the bd. prefix.
//   MEASURED on cc-main-2026-apr-may-jun (858.6MB, auto-discovered): 13,789 bd. vertices out of
//   2,644,183 lines, after reading 19.3MB compressed = 2.25% of the file, in 165s at 40.5MB RSS.
//
// RANK 53 — the backwards walk. collinfo.json lists 125 collections (measured), and cluster.idx was
// verified present on all of them — HTTP 200 at CC-MAIN-2026-21, 2025-33, 2023-23, 2019-39, 2017-13,
// 2015-11, 2013-48 and the oldest, CC-MAIN-2008-2009. So the technique runs the entire archive. One
// crawl per run, cursor persisted. Dead/rotated hosts are fine: the scanner re-validates liveness.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────────
// ON TRAP 1 (never admit a domain because its NAME says "bd")
//
// Both sources here are keyed on the .bd TLD itself — `bd,` in SURT space, `bd.` in reversed-domain
// space — which is BTCL registry-gated and cannot be self-asserted. So 1xbet-bd.org / 22bet-bd.com
// style casino spam is structurally unreachable from this file: it is a .org and a .com and neither
// sorts anywhere near the bd region. Every host is still passed through bdgate's isBdHost(), which
// admits it on rung 1 (.bd TLD) with ZERO DNS lookups — correctness for free.
//
// ON TRAP 2 (free public services 502 under load)
// data.commoncrawl.org is a CloudFront-fronted static bucket and is far more tolerant than crt.sh,
// but it is still free infrastructure. ccGet() retries 429/5xx with exponential backoff, sleeps
// between range reads, and a failed range is split in half and retried rather than abandoned.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────────
// ENV (all optional)
//
//   API_BASE            https://bd-hack-audit-api.javed-it.workers.dev
//   SHARED_TOKEN        —          required; without it the Worker 401s every write
//   CC_MODE             auto       auto | cdx | webgraph | both
//                                  auto = one CDX crawl per run, plus the webgraph once per release
//   CC_CRAWL            —          pin a single collection id (e.g. CC-MAIN-2026-25); disables the walk
//   CC_STATE            <bdgate cache dir>/commoncrawl-state.json
//   CC_RANGE_MB         48         max MB per Range request. 48 = the whole bd slice in ONE request
//                                  (the rank-2 design). Lower it to make a flaky link resumable.
//   CC_MAX_HOSTS        0          stop after N hosts found (0 = no limit). Testing knob.
//   CC_FLUSH            500        submit every N new hosts, so RAM and progress stay bounded.
//                                  500 = exactly one bdgate submit chunk. MEASURED: a 500-row POST to
//                                  /harvest takes ~12s (D1 write), and a 2000-row flush (4 back-to-back
//                                  chunks) lost 1,500 rows to timeouts while other harvesters were also
//                                  writing. One chunk per flush was reliable across every later run.
//   CC_LIVENESS         1          1 = DoH A-record prefilter (bdgate alive()) before submitting
//   CC_LIVENESS_MAX     25000      hosts liveness-checked per run; beyond this they pass unchecked
//                                  (a first run sees ~30k new names and DoH is capped at 33/s)
//   CC_SLEEP_MS         1500       polite gap between range reads
//   CC_WEBGRAPH_RELEASE —          pin a release id; otherwise discovered and cached
//   CC_COLLINFO_TTL_H   72         re-fetch collinfo.json at most this often
//
// Cadence: systemd timer every 6h. One crawl per run walks all 125 collections in ~31 days, then
// the cursor wraps to the newest crawl, which by then has been replaced with a fresh one.

import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import zlib from "node:zlib";
import { Readable } from "node:stream";

import {
  loadBdRanges, isBdHost, eduLexicon, alive,
  loadSeen, seen, markSeen, submit, normHost, mapLimit,
  CACHE_DIR, API_BASE_DEFAULT,
} from "./bdgate.mjs";

const env = process.env;
const numEnv = (v, d) => (Number.isFinite(Number(v)) && Number(v) >= 0 && v !== undefined && v !== "" ? Number(v) : d);

const API_BASE = (env.API_BASE || API_BASE_DEFAULT).replace(/\/+$/, "");
const TOKEN = env.SHARED_TOKEN || "";
const SOURCE = "commoncrawl";
const MODE = (env.CC_MODE || "auto").toLowerCase();
const PIN_CRAWL = env.CC_CRAWL || "";
const STATE_FILE = env.CC_STATE || path.join(CACHE_DIR, "commoncrawl-state.json");
const RANGE_BYTES = Math.max(1, numEnv(env.CC_RANGE_MB, 48)) * 1024 * 1024;
const MAX_HOSTS = numEnv(env.CC_MAX_HOSTS, 0);
const FLUSH = Math.max(50, numEnv(env.CC_FLUSH, 500));
const LIVENESS = env.CC_LIVENESS !== "0";
const LIVENESS_MAX = numEnv(env.CC_LIVENESS_MAX, 25000);
const SLEEP_MS = numEnv(env.CC_SLEEP_MS, 1500);
const COLLINFO_TTL = numEnv(env.CC_COLLINFO_TTL_H, 72) * 3600 * 1000;
const PIN_RELEASE = env.CC_WEBGRAPH_RELEASE || "";

const CC = "https://data.commoncrawl.org";
const COLLINFO = "https://index.commoncrawl.org/collinfo.json";
const UA = "bd-hack-audit/1.0 (+javeditsolution.com; security research)";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const log = (...a) => console.log("[cc]", ...a);
const mb = (n) => (n / 1048576).toFixed(1) + "MB";

// ── run-wide counters, printed at the end so a cron log line is self-explanatory ──────────────────
const stats = {
  requests: 0, bytesDown: 0, found: 0, dup: 0, dead: 0, notBd: 0, queued: 0,
  posted: 0, inserted: 0, edu: 0, spammy: 0, failures: [],
};

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// HTTP with backoff. Common Crawl is free infrastructure — behave like it.
// ═════════════════════════════════════════════════════════════════════════════════════════════════

// PROBED 2026-07-20: the full 42.5MB bd slice took 232s for the author and streams here at ~360KB/s
// (117s) — both uncomfortably inside a 300s TOTAL-duration deadline. A total deadline that sits within
// 2x of the measured runtime is the crt.sh-30s mistake exactly: it converts "slow today" into "failed
// today". So streams get a STALL deadline instead — rearmed by the caller on every data chunk via
// bump(). A hung socket still dies in `stall` ms; a slow-but-progressing transfer never does.
async function ccGet(url, { range = null, stream = false, timeout = 300000, stall = 120000 } = {}) {
  const headers = { "user-agent": UA };
  if (range) headers.range = `bytes=${range[0]}-${range[1]}`;
  for (let attempt = 1; attempt <= 5; attempt++) {
    const ctl = new AbortController();
    let timer = setTimeout(() => ctl.abort(), timeout);
    try {
      stats.requests++;
      const r = await fetch(url, { headers, signal: ctl.signal });
      if (r.status === 429 || r.status >= 500) {
        clearTimeout(timer);
        try { await r.body?.cancel(); } catch {}
        await sleep(Math.min(60000, attempt * attempt * 3000));
        continue;
      }
      if (r.status === 404) { clearTimeout(timer); try { await r.body?.cancel(); } catch {} return { notFound: true, res: r }; }
      if (!r.ok && r.status !== 206) { clearTimeout(timer); try { await r.body?.cancel(); } catch {} throw new Error("http " + r.status); }
      if (stream) {
        const bump = () => { clearTimeout(timer); timer = setTimeout(() => ctl.abort(), stall); };
        bump();                                  // `timeout` was the connect deadline; now go stall-based
        return { res: r, bump, release: () => { clearTimeout(timer); try { ctl.abort(); } catch {} } };
      }
      const buf = Buffer.from(await r.arrayBuffer());
      clearTimeout(timer);
      stats.bytesDown += buf.length;
      return { buf, res: r };
    } catch (e) {
      clearTimeout(timer);
      if (attempt === 5) throw e;
      await sleep(Math.min(60000, attempt * attempt * 3000));
    }
  }
  throw new Error("unreachable");
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// State — the rotating cursor (rank 53) plus the cached per-crawl block map, so re-running a crawl
// costs 0 requests instead of repeating the 56-read binary search.
// ═════════════════════════════════════════════════════════════════════════════════════════════════

async function readState() {
  try { return JSON.parse(await fsp.readFile(STATE_FILE, "utf8")); } catch { return {}; }
}
async function writeState(s) {
  try { await fsp.writeFile(STATE_FILE, JSON.stringify(s, null, 1)); }
  catch (e) { console.error("[cc] state write failed:", String(e).slice(0, 100)); }
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// SURT key → hostname.  "bd,ac,du)/path" → "du.ac.bd"   ·   "bd,com,x,www:8080)/" → "www.x.com.bd"
// Parsing the key beats parsing the per-line JSON: no allocation, no JSON.parse over ~5M lines.
// ═════════════════════════════════════════════════════════════════════════════════════════════════

function surtToHost(key) {
  const paren = key.indexOf(")");
  let auth = paren >= 0 ? key.slice(0, paren) : key;
  const colon = auth.indexOf(":");
  if (colon >= 0) auth = auth.slice(0, colon);          // drop :port
  if (!auth) return null;
  return auth.split(",").reverse().join(".");
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// The submit pipeline. Hosts stream in one at a time; nothing accumulates beyond FLUSH.
// ═════════════════════════════════════════════════════════════════════════════════════════════════

const BD_INST = /\.(edu|ac|gov|mil)\.bd$/i;
const queued = new Set();      // in-flight this run; promoted into bdgate's SEEN only after a
let pending = [];              // successful POST, so a failed flush is retried next run
let hitLimit = false;
let livenessSpent = 0;

// Same rule harvest-crtsh.mjs uses and for the same reason: a deep host like admission.aub.ac.bd is a
// real lead in its own right, AND its 3-label apex keeps the existing IP/cluster logic working. .bd
// registrations are second-level under com./edu./ac./gov./net./org.bd, so the apex is the last three
// labels; on a host that already has three labels the slice is a no-op.
async function offerWithApex(rawHost) {
  await offer(rawHost);
  const p = String(rawHost || "").split(".");
  if (p.length > 3) await offer(p.slice(-3).join("."));
}

async function offer(rawHost) {
  if (hitLimit) return;
  const h = normHost(rawHost);
  if (!h) return;
  // Structural, not a name test: both sources are keyed on the .bd TLD, so anything else is a
  // parse artefact (a neighbouring block's tail) and is dropped rather than trusted.
  if (!h.endsWith(".bd")) { stats.notBd++; return; }
  stats.found++;
  if (MAX_HOSTS && stats.found >= MAX_HOSTS) hitLimit = true;
  if (seen(h) || queued.has(h)) { stats.dup++; return; }
  queued.add(h);
  pending.push(h);
  if (pending.length >= FLUSH) await flush();
}

async function flush() {
  if (!pending.length) return;
  let batch = pending;
  pending = [];

  // rank 58, opt-out: a DoH A-record gate. Measured elsewhere in this project: only 39 of 200
  // sampled .edu.bd names resolve at all, and every corpse costs the scanner a full HTTP timeout.
  if (LIVENESS && livenessSpent < LIVENESS_MAX) {
    const budget = Math.max(0, LIVENESS_MAX - livenessSpent);
    const check = batch.slice(0, budget);
    const passthrough = batch.slice(budget);
    livenessSpent += check.length;
    const ok = await mapLimit(check, 24, async (h) => ((await alive(h)) ? h : null));
    const live = ok.filter(Boolean);
    stats.dead += check.length - live.length;
    batch = live.concat(passthrough);
  }
  if (!batch.length) return;

  const rows = [];
  for (const h of batch) {
    const lex = eduLexicon(h);
    if (lex.isEdu) stats.edu++;
    if (lex.isSpammy) stats.spammy++;
    // Zero-DNS for these sources: rung 1 of the ladder is the .bd TLD. Kept anyway so this file has
    // exactly one admission authority and never grows a private one.
    if (!(await isBdHost(h))) continue;
    rows.push({ domain: h, bd_score: BD_INST.test(h) ? 60 : (lex.isEdu ? 45 : 40) });
  }
  if (!rows.length) return;

  const r = await submit(API_BASE, TOKEN, SOURCE, rows);
  stats.posted += r.posted;
  stats.inserted += r.inserted;
  if (r.ok) for (const row of rows) markSeen(row.domain);
  else stats.failures.push(`submit failed: posted=${r.posted} found=${r.found} failed=${r.failed}`);
  log(`submitted ${r.posted} → found=${r.found} inserted=${r.inserted} dups=${r.dups}${r.ok ? "" : "  ⚠ NOT OK"}`);
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// RANK 2 — locate the bd, blocks in cluster.idx by binary search over byte offsets.
// ═════════════════════════════════════════════════════════════════════════════════════════════════

// Read the first COMPLETE line at/after `pos`. `pos>0` means we land mid-line, so the partial head
// is discarded and the next line returned along with its true starting offset.
async function lineAt(url, pos, total) {
  const CH = 8192;
  const from = Math.min(Math.max(0, pos), Math.max(0, total - 1));
  const { buf } = await ccGet(url, { range: [from, Math.min(total - 1, from + CH)], timeout: 60000 });
  const s = buf.toString("utf8");
  let off = 0;
  if (from > 0) {
    const nl = s.indexOf("\n");
    if (nl < 0) return null;
    off = nl + 1;
  }
  const nl2 = s.indexOf("\n", off);
  if (nl2 < 0) return null;
  return { line: s.slice(off, nl2), start: from + off };
}

// Lowest byte offset whose line's SURT key is >= `prefix`.
async function lowerBound(url, total, prefix, loInit = 0) {
  let lo = loInit, hi = total, best = total;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    const r = await lineAt(url, mid, total);
    if (!r) { hi = mid; continue; }
    if (r.line.split(" ")[0] >= prefix) { best = r.start; hi = mid; } else lo = mid + 1;
  }
  return best;
}

async function findBdBlocks(crawl, state) {
  state.blocks ||= {};
  if (state.blocks[crawl]) { log(`${crawl}: block map from cache (${state.blocks[crawl].length} blocks, 0 requests)`); return state.blocks[crawl]; }

  const url = `${CC}/cc-index/collections/${crawl}/indexes/cluster.idx`;
  const head = await fetch(url, { method: "HEAD", headers: { "user-agent": UA }, signal: AbortSignal.timeout(60000) });
  stats.requests++;
  if (!head.ok) throw new Error(`cluster.idx HEAD ${head.status} for ${crawl}`);
  const total = Number(head.headers.get("content-length"));
  if (!Number.isFinite(total) || total < 1000) throw new Error(`cluster.idx has no usable length for ${crawl}`);

  // "bd," … "bd-".  ',' is 0x2c and '-' is 0x2d, so "bd-" is the immediate successor of the "bd,"
  // prefix in byte order and bounds the region exactly. Seeding the second search with the first
  // result saves ~half the reads.
  const startOff = await lowerBound(url, total, "bd,");
  const endOff = await lowerBound(url, total, "bd-", startOff);

  // Reach back one line so the block PRECEDING the first bd, key is included — see the header note.
  const from = Math.max(0, startOff - 8192);
  const { buf } = await ccGet(url, { range: [from, Math.min(total - 1, endOff + 8192)], timeout: 120000 });
  const rows = [];
  for (const ln of buf.toString("utf8").split("\n")) {
    const f = ln.split("\t");
    if (f.length < 5) continue;
    const key = f[0].split(" ")[0];
    const off = Number(f[2]), len = Number(f[3]);
    if (!f[1] || !Number.isFinite(off) || !Number.isFinite(len)) continue;
    rows.push({ key, file: f[1], off, len });
  }
  const first = rows.findIndex((r) => r.key.startsWith("bd,"));
  if (first < 0) throw new Error(`no bd, keys found in ${crawl} cluster.idx`);
  let last = first;
  for (let i = rows.length - 1; i >= first; i--) if (rows[i].key.startsWith("bd,")) { last = i; break; }
  const blocks = rows.slice(Math.max(0, first - 1), last + 1).map(({ file, off, len }) => ({ file, off, len }));

  const files = [...new Set(blocks.map((b) => b.file))];
  const span = blocks.reduce((a, b) => a + b.len, 0);
  log(`${crawl}: cluster.idx ${mb(total)} → bd, region bytes ${startOff}-${endOff}; ${blocks.length} blocks in ${files.join(",")} = ${mb(span)}`);
  state.blocks[crawl] = blocks;
  await writeState(state);
  return blocks;
}

// Group blocks into contiguous same-file runs of at most RANGE_BYTES. At the default 48MB the whole
// measured 42.5MB bd slice is a single Range request; a smaller value trades requests for resumability.
function planRanges(blocks) {
  const out = [];
  let cur = null;
  for (const b of blocks) {
    const end = b.off + b.len - 1;
    if (cur && cur.file === b.file && b.off === cur.to + 1 && end - cur.from + 1 <= RANGE_BYTES) { cur.to = end; cur.n++; continue; }
    if (cur) out.push(cur);
    cur = { file: b.file, from: b.off, to: end, n: 1 };
  }
  if (cur) out.push(cur);
  return out;
}

// Stream one Range through gunzip, line by line. On a decompression failure the range is halved and
// each half retried, so one bad block cannot cost the whole 42.5MB.
async function pullRange(crawl, r, depth = 0) {
  const url = `${CC}/cc-index/collections/${crawl}/indexes/${r.file}`;
  let got = 0;
  try {
    const { res, bump, release } = await ccGet(url, { range: [r.from, r.to], stream: true });
    const src = Readable.fromWeb(res.body);
    const gz = zlib.createGunzip();
    src.on("error", () => {});     // an intentional early destroy must not become an unhandled event
    gz.on("error", () => {});
    // bump() on every chunk is what makes `stall` a STALL deadline instead of a hard wall-clock one. Without
    // this call the timer armed in ccGet fires 120s into any transfer, ctl.abort() kills the socket, the two
    // error handlers below swallow it, pipe() does not forward it, and the `for await` loop then waits on a
    // promise that never settles — Node drains the event loop and exits 0 with no output at all. That is what
    // a silent truncation looks like: a harvester that reports success and did half the work. This Mac streams
    // the 44MB slice in ~100s, surviving by 20%; the header records 232s for the same slice, and the Oracle VM
    // has the slower link — so on the VM it would have truncated essentially every run.
    src.on("data", (c) => { stats.bytesDown += c.length; bump(); });
    src.pipe(gz);
    let buf = "";
    try {
      for await (const chunk of gz) {
        buf += chunk.toString("latin1");
        let nl;
        while ((nl = buf.indexOf("\n")) >= 0) {
          const line = buf.slice(0, nl);
          buf = buf.slice(nl + 1);
          const sp = line.indexOf(" ");
          if (sp <= 0) continue;
          const key = line.slice(0, sp);
          if (!key.startsWith("bd,")) continue;   // tail of the preceding block / head of the next
          const h = surtToHost(key);
          if (h) { got++; await offerWithApex(h); }
        }
        if (buf.length > 1 << 20) buf = "";       // pathological unterminated line — cannot happen in CDX
        if (hitLimit) break;
      }
    } finally { try { gz.destroy(); } catch {} try { src.destroy(); } catch {} release(); }
  } catch (e) {
    const size = r.to - r.from + 1;
    if (depth >= 4 || size < 1 << 20) { stats.failures.push(`${r.file} ${r.from}-${r.to}: ${String(e).slice(0, 80)}`); return got; }
    const mid = r.from + Math.floor(size / 2);
    log(`range ${r.from}-${r.to} failed (${String(e).slice(0, 60)}) — splitting`);
    got += await pullRange(crawl, { ...r, to: mid }, depth + 1);
    got += await pullRange(crawl, { ...r, from: mid + 1 }, depth + 1);
  }
  return got;
}

async function runCdx(crawl, state) {
  const t0 = Date.now();
  const blocks = await findBdBlocks(crawl, state);
  const ranges = planRanges(blocks);
  log(`${crawl}: ${blocks.length} blocks → ${ranges.length} range request(s)`);
  let got = 0;
  for (const r of ranges) {
    if (hitLimit) break;
    got += await pullRange(crawl, r);
    log(`${crawl}: ${r.file} ${r.from}-${r.to} (${mb(r.to - r.from + 1)}, ${r.n} blocks) — ${got} bd captures so far, ${stats.found} hosts`);
    await sleep(SLEEP_MS);
  }
  log(`${crawl}: CDX done in ${((Date.now() - t0) / 1000).toFixed(0)}s — ${got} bd, capture keys`);
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// RANK 38 — webgraph domain-vertices. Sorted reversed domains, so exit at the end of the bd. prefix.
// ═════════════════════════════════════════════════════════════════════════════════════════════════

const M = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"];
const wgUrl = (rel) => `${CC}/projects/hyperlinkgraph/${rel}/domain/${rel}-domain-vertices.txt.gz`;

// There is no listing endpoint for hyperlinkgraph/, so releases are probed. Names are
// cc-main-<year>-<m1>-<m2>-<m3> over a rolling 3-month window; HEAD is cheap and the answer is
// cached in the state file. VERIFIED live 2026-07-19: 2026-feb-mar-apr 200 (922,163,725 bytes),
// 2025-oct-nov-dec 200, 2025-sep-oct-nov 200, 2025-aug-sep-oct 200, 2025-may-jun-jul 200,
// 2025-feb-mar-apr 200 — while 2025-nov-dec-jan and 2024-nov-dec-jan both 404. The windows are
// irregular, which is exactly why they must be probed and never hardcoded.
function candidateReleases(now = new Date()) {
  const out = [];
  for (let back = 0; back < 30; back++) {
    const d = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - back, 1));
    const y = d.getUTCFullYear(), m = d.getUTCMonth();
    const trio = [0, 1, 2].map((k) => M[(m + k) % 12]);
    out.push(`cc-main-${y}-${trio.join("-")}`);
  }
  return [...new Set(out)];
}

async function discoverRelease(state) {
  if (PIN_RELEASE) return PIN_RELEASE;
  state.wgProbe ||= {};
  for (const rel of candidateReleases()) {
    if (state.wgProbe[rel] === false) continue;
    if (state.wgProbe[rel] === true) return rel;
    try {
      stats.requests++;
      const r = await fetch(wgUrl(rel), { method: "HEAD", headers: { "user-agent": UA }, signal: AbortSignal.timeout(45000) });
      state.wgProbe[rel] = r.ok;
      if (r.ok) { log(`webgraph release ${rel} (${mb(Number(r.headers.get("content-length")))})`); await writeState(state); return rel; }
    } catch {}
    await sleep(400);
  }
  await writeState(state);
  return null;
}

async function runWebgraph(rel) {
  const t0 = Date.now();
  const { res, bump, release } = await ccGet(wgUrl(rel), { stream: true, timeout: 900000 });
  const src = Readable.fromWeb(res.body);
  const gz = zlib.createGunzip();
  src.on("error", () => {});
  gz.on("error", () => {});
  let compressed = 0;
  src.on("data", (c) => { compressed += c.length; stats.bytesDown += c.length; bump(); });  // see pullRange: without bump() this is a hard wall, not a stall deadline
  src.pipe(gz);
  let buf = "", lines = 0, got = 0, stop = false;
  try {
    outer:
    for await (const chunk of gz) {
      buf += chunk.toString("latin1");
      let nl;
      while ((nl = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 1);
        lines++;
        // format: "<id>\t<reversed-domain>\t<hostcount>"  e.g. "0\taaa.10\t1"  (verified live)
        const tab = line.indexOf("\t");
        if (tab < 0) continue;
        const tab2 = line.indexOf("\t", tab + 1);
        const rev = tab2 < 0 ? line.slice(tab + 1) : line.slice(tab + 1, tab2);
        if (rev.startsWith("bd.")) {
          got++;
          await offerWithApex(rev.split(".").reverse().join("."));
        } else if (got > 0 && rev > "bd.") { stop = true; break outer; }   // sorted → nothing left
      }
      if (hitLimit) { stop = true; break; }
    }
  } finally { try { gz.destroy(); } catch {} try { src.destroy(); } catch {} release(); }
  log(`webgraph ${rel}: ${got} bd. vertices from ${lines} lines, read ${mb(compressed)} compressed (early-exit=${stop}) in ${((Date.now() - t0) / 1000).toFixed(0)}s`);
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════

async function collections(state) {
  if (state.collinfo && Date.now() - (state.collinfoAt || 0) < COLLINFO_TTL) return state.collinfo;
  const { buf } = await ccGet(COLLINFO, { timeout: 90000 });
  const ids = JSON.parse(buf.toString("utf8")).map((c) => c.id).filter(Boolean);
  if (!ids.length) throw new Error("collinfo.json parsed 0 collections");
  state.collinfo = ids;                     // newest first, as served
  state.collinfoAt = Date.now();
  await writeState(state);
  log(`collinfo: ${ids.length} collections, newest ${ids[0]}`);
  return ids;
}

async function main() {
  if (!TOKEN) { console.error("[cc] SHARED_TOKEN missing — every write would 401. Refusing to burn bandwidth."); process.exit(1); }
  const t0 = Date.now();
  const state = await readState();

  await loadBdRanges();
  const s = await loadSeen(API_BASE, TOKEN);
  log(`seen-set: ${s.total} hosts (${s.fromDisk} disk, ${s.fromApi} api, ${s.pages} pages)`);

  const doCdx = MODE === "cdx" || MODE === "auto" || MODE === "both";
  const doWg = MODE === "webgraph" || MODE === "both" || MODE === "auto";

  if (doCdx) {
    let crawl = PIN_CRAWL;
    if (!crawl) {
      const ids = await collections(state);
      const cursor = numEnv(state.cdxCursor, 0) % ids.length;      // rank 53: backwards walk
      crawl = ids[cursor];
      state.cdxCursor = (cursor + 1) % ids.length;
      await writeState(state);
      log(`crawl ${crawl} (cursor ${cursor} → ${state.cdxCursor} of ${ids.length})`);
    }
    try { await runCdx(crawl, state); }
    catch (e) { stats.failures.push(`cdx ${crawl}: ${String(e).slice(0, 140)}`); console.error("[cc] cdx failed:", e); }
  }

  if (doWg && !hitLimit) {
    state.wgDone ||= {};
    const rel = await discoverRelease(state);
    if (!rel) stats.failures.push("webgraph: no release responded to HEAD");
    else if (MODE === "auto" && state.wgDone[rel]) log(`webgraph ${rel} already harvested — skipping (CC_MODE=webgraph forces it)`);
    else {
      try { await runWebgraph(rel); state.wgDone[rel] = Date.now(); await writeState(state); }
      catch (e) { stats.failures.push(`webgraph ${rel}: ${String(e).slice(0, 140)}`); console.error("[cc] webgraph failed:", e); }
    }
  }

  await flush();

  log("─".repeat(78));
  log(`DONE in ${((Date.now() - t0) / 1000).toFixed(0)}s · ${stats.requests} requests · ${mb(stats.bytesDown)} downloaded · rss ${mb(process.memoryUsage().rss)}`);
  log(`hosts: ${stats.found} found · ${stats.dup} already known · ${stats.dead} dead (no A record) · ${stats.notBd} non-.bd dropped`);
  log(`submitted ${stats.posted} → ${stats.inserted} NEW in the queue · ${stats.edu} education-lexicon hits · ${stats.spammy} spam-brand names`);
  if (stats.failures.length) { console.error(`[cc] ${stats.failures.length} FAILURE(S):`); for (const f of stats.failures.slice(0, 20)) console.error("   ·", f); }
  await writeState(state);
}

main().catch((e) => { console.error("[cc] fatal:", e); process.exit(1); });
