// harvest-eiin.mjs — the BANGLADESHI EDUCATION IDENTITY SPINE, run ON THE ORACLE VM.
//
// Zero npm dependencies, plain node ESM, streaming, sized for the 946MB / 1 OCPU Oracle VM.
// Imports the shared gate (./bdgate.mjs) for BD-ness, liveness, dedupe and the /harvest POST — none of
// that is reimplemented here.
//
//   node scanner/harvest-eiin.mjs --mode=registry     # rank 23 — pull the BANBEIS institution table
//   node scanner/harvest-eiin.mjs --mode=dpe          # rank 54 — pull the DPE primary-school table
//   node scanner/harvest-eiin.mjs --mode=candidates   # rank 24 — name→domain generation + DoH resolve
//   node scanner/harvest-eiin.mjs --mode=verify       # rank 25 — self-test the EIIN-on-page extractor
//   node scanner/harvest-eiin.mjs --mode=all          # registry → dpe → candidates  (the cron default)
//
// It is also a LIBRARY. The scanner imports the rank-25 extractor from here:
//
//   import { loadEiinIndex, eiinProof, isKnownEiin } from "./harvest-eiin.mjs";
//   await loadEiinIndex();                       // once at startup, ~160KB + ~5MB of records
//   const proof = eiinProof(html);               // sync, zero network, ~µs
//   if (proof?.known) { /* decisive BD-education proof; survives Cloudflare */ }
//
// main() only runs when the file is EXECUTED, never when imported (see the guard at the bottom).
//
// ─────────────────────────────────────────────────────────────────────────────────────────────────
// WHAT WAS ACTUALLY MEASURED (2026-07-19/20, live probes — the brief's endpoints were wrong)
//
// The brief gave `http://182.252.85.85/eiin/institute_tracking` for rank 23. That URL is a LOGIN WALL
// (title "EIIN :: institute Login", Tracking ID + password). The whole 182.252.85.85/eiin/ app is an
// EIIN *application* portal — apply / track your application / admin login. It contains no institution
// listing of any kind. Anyone building against the brief verbatim harvests exactly nothing.
//
// The real public registry was found by walking the BANBEIS nav to "ইন্সটিটিউট সার্চ" →
// http://182.252.85.84:3080 (a React SPA) → its bundle's API base → the one unauthenticated route:
//
//     GET http://182.252.85.81:8000/api/v1/institute/public/list?page=<1..N>&size=50
//
//   • /institute/list, /institute/all, /institute/find/<id> all return 401. ONLY the
//     `/institute/public/list` path is open. That single word is the difference between 401 and 40k rows.
//   • meta.total = 40,162 — NOT the 130k-160k the brief claimed. See the honesty note below.
//   • `size` is silently capped at 50 server-side (size=5000 still returns 50 rows), so a full pull is
//     804 pages. `page` is 1-indexed; page 805 returns an empty array.
//   • rows are ordered by eiinNo ascending and are stable across pages (page 1 ends 100052, page 2
//     starts 100053) — so a page cursor is safe here, unlike an OFFSET over a table being written to.
//   • `?eiinNo=<6 digits>` is an exact-match filter returning 1 row. That is the rank-25 online oracle.
//   • `?search=` is accepted and IGNORED (total stays 40,162). Do not rely on it.
//
// WHY 40,162 AND NOT 130,000 — the brief's number is wrong, and the portal itself says why. BANBEIS
// prints on its own EIIN homepage: "স্বতন্ত্র এবতেদায়ী মাদ্রাসা ও ইংলিশ মিডিয়াম স্কুলের EIIN প্রদান করা হয় না"
// (standalone ebtedayee madrasas and English-medium schools are not issued an EIIN). The 130k+ figure
// in circulation counts all institutions in the country including the ~65,500 government primary
// schools, which are administered by DPE and carry a *school code*, not an EIIN. Those are a separate
// table — rank 54 below. 40,162 EIIN + 65,569 DPE = ~105.7k, which is where the "130k-160k" came from.
//
// RANK 54 (DPE/IPEMIS) — the brief said "treat it as a cross-reference not a domain source". Correct,
// and I am keeping that framing, but the brief undersold the access: the public dashboard exposes only
// aggregates (https://api.ipemis.dpe.gov.bd/api/school-stat-public → 65,569 schools, 374,568 teachers),
// and every /api/school-*-public list route 404s. The full per-school table is nonetheless public via
// the DataTables backend the /search-school page drives:
//
//     GET https://ipemis.dpe.gov.bd/load-lite-school-list?draw=1&start=<n>&length=<250>
//     → { recordsTotal: 65569, aaData: [ { schoolCode, schoolName, schoolNameLocal,
//                                          division/district/upazila/geoUnion (EN+BN), schoolTypeName,
//                                          totalTeacher, totalStudent } ] }
//
//   length=100 → 2.7s, length=1000 → 50s, length=5000 → 0 rows. Throughput peaks near length=250.
//   This yields ZERO domains and is not submitted to /harvest. It is a name+geography cross-reference,
//   exactly as the brief instructed. Government primary schools genuinely do not have websites.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────────
// THE TRAP THIS FILE IS MOST EXPOSED TO
//
// Rank 24 GENERATES domain names from institution names. That is, structurally, the exact shape of the
// mistake that cost this project 24,000 purged rows: inventing a string that "looks Bangladeshi" and
// admitting it. The name is not evidence. So every generated non-.bd candidate must clear
// bdgate.isBdHost() — routed APNIC BD address space, or a .bd nameserver — before it is submitted, and
// three extra guards run on top (see CANDIDATE SAFETY below): a per-TLD wildcard control probe, a
// parking-IP frequency cap, and a generic-apex blocklist. A candidate that merely resolves is NOT a
// find; nabinagar.com resolving proves nothing about a school in Nabinagar.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────────
// ENV (all optional; defaults tuned for the Oracle VM)
//
//   API_BASE               https://bd-hack-audit-api.javed-it.workers.dev   (read by bdgate)
//   SHARED_TOKEN           —                     bearer token for /harvest and /api/domains
//   EIIN_DIR               /opt/bd-scanner/.eiin  data dir; falls back to os.tmpdir() if unwritable
//   EIIN_MODE              all                   registry | dpe | candidates | verify | all
//   EIIN_API               http://182.252.85.81:8000/api/v1   BANBEIS public API base
//   EIIN_PAGE_SIZE         50                    server caps at 50; larger is silently ignored
//   EIIN_CONCURRENCY       4                     parallel registry pages (a govt box — stay gentle)
//   EIIN_MAX_PAGES         0                     0 = all 804
//   EIIN_REFRESH_H         168                   re-pull the registry at most weekly
//   DPE_URL                https://ipemis.dpe.gov.bd/load-lite-school-list
//   DPE_PAGE               250                   rows per request (peak throughput)
//   DPE_MAX_ROWS           0                     0 = all 65,569
//   DPE_REFRESH_H          720                   monthly; this table barely moves
//   EIIN_TLDS              .edu.bd,.com,.org,.net,.info
//   EIIN_CAND_INSTITUTES   1500                  institutions per candidates run (cursored, resumable)
//   EIIN_MAX_CAND          8                     max name-forms per institution (× TLDs = lookups)
//   EIIN_PARK_MAX          25                    an IP seen on more than this many candidates = parking
//   EIIN_DRY_RUN           0                     1 = generate + resolve + gate, but never POST
//   EIIN_DEBUG             0                     1 = log every candidate decision

import fs from "node:fs";
import fsp from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import readline from "node:readline";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  loadBdRanges, isBdHost, isBdHostDetail, eduLexicon, resolveA,
  loadSeen, seen, markSeen, submit, normHost, mapLimit, API_BASE_DEFAULT,
} from "./bdgate.mjs";

const env = process.env;
const num = (v, d) => (Number.isFinite(Number(v)) && Number(v) >= 0 ? Number(v) : d);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const DEBUG = env.EIIN_DEBUG === "1";
const dbg = (...a) => { if (DEBUG) console.error("[eiin]", ...a); };
const log = (...a) => console.log("[eiin]", ...a);

const EIIN_API = (env.EIIN_API || "http://182.252.85.81:8000/api/v1").replace(/\/+$/, "");
const PAGE_SIZE = Math.min(num(env.EIIN_PAGE_SIZE, 50), 50);   // hard server cap; larger is a no-op
const CONCURRENCY = Math.max(1, num(env.EIIN_CONCURRENCY, 4));
const MAX_PAGES = num(env.EIIN_MAX_PAGES, 0);
const REFRESH_MS = num(env.EIIN_REFRESH_H, 168) * 3600 * 1000;

const DPE_URL = env.DPE_URL || "https://ipemis.dpe.gov.bd/load-lite-school-list";
const DPE_PAGE = Math.max(10, num(env.DPE_PAGE, 250));
const DPE_MAX_ROWS = num(env.DPE_MAX_ROWS, 0);
const DPE_REFRESH_MS = num(env.DPE_REFRESH_H, 720) * 3600 * 1000;

const TLDS = String(env.EIIN_TLDS || ".edu.bd,.com,.org,.net,.info")
  .split(",").map((s) => s.trim().toLowerCase().replace(/^\.?/, ".")).filter((s) => s.length > 1);
const CAND_INSTITUTES = num(env.EIIN_CAND_INSTITUTES, 1500);
const MAX_CAND = Math.max(1, num(env.EIIN_MAX_CAND, 8));
const PARK_MAX = Math.max(2, num(env.EIIN_PARK_MAX, 25));
const DRY_RUN = env.EIIN_DRY_RUN === "1";

const UA = "Mozilla/5.0 (compatible; bd-hack-audit/1.0; +javeditsolution.com)";

function resolveDir() {
  const want = env.EIIN_DIR || "/opt/bd-scanner/.eiin";
  for (const d of [want, path.join(os.tmpdir(), "bd-eiin")]) {
    try { fs.mkdirSync(d, { recursive: true }); fs.accessSync(d, fs.constants.W_OK); return d; } catch {}
  }
  return os.tmpdir();
}
export const DATA_DIR = resolveDir();
const REGISTRY_FILE = path.join(DATA_DIR, "banbeis-institutes.ndjson");
const DPE_FILE = path.join(DATA_DIR, "dpe-primary-schools.ndjson");
const CAND_CURSOR = path.join(DATA_DIR, "candidates.cursor");
const PARK_FILE = path.join(DATA_DIR, "parking-ips.json");

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// RANK 23 — the BANBEIS EIIN registry.
//
// 804 pages × 50 rows. Written to disk as NDJSON as each page lands; nothing accumulates in RAM, so
// the pull costs the same whether the table has 40k rows or 400k. A partial pull is written to a
// .part file and only renamed over the good copy on success — a network failure at page 700 must not
// destroy last week's complete table.
// ═════════════════════════════════════════════════════════════════════════════════════════════════

async function getJson(url, { tries = 4, timeout = 60000, headers = {} } = {}) {
  for (let attempt = 1; attempt <= tries; attempt++) {
    try {
      const r = await fetch(url, {
        headers: { "user-agent": UA, accept: "application/json", ...headers },
        signal: AbortSignal.timeout(timeout),
      });
      // 429/5xx on a government box = back off hard, it is not a fast machine.
      if (r.status === 429 || r.status >= 500) { await sleep(attempt * 4000); continue; }
      if (!r.ok) return { httpError: r.status };
      const txt = await r.text();
      try { return JSON.parse(txt); } catch { await sleep(attempt * 2000); continue; }
    } catch { await sleep(attempt * 3000); }
  }
  return null;
}

/** One page of the BANBEIS public institute list. page is 1-indexed. */
async function fetchRegistryPage(page) {
  const j = await getJson(`${EIIN_API}/institute/public/list?page=${page}&size=${PAGE_SIZE}`);
  if (!j || j.httpError) return { rows: null, total: 0, http: j?.httpError || 0 };
  return { rows: Array.isArray(j.data) ? j.data : [], total: Number(j?.meta?.total) || 0 };
}

function cleanName(s) { return String(s || "").replace(/\s+/g, " ").trim(); }

function registryRow(r) {
  const eiin = String(r?.eiinNo || "").trim();
  if (!/^\d{6}$/.test(eiin)) return null;
  return {
    eiin,
    name: cleanName(r.instituteName),
    nameBn: cleanName(r.instituteNameBn),
    type: cleanName(r.instituteTypeName),
    division: cleanName(r.divisionName),
    district: cleanName(r.districtName),
    thana: cleanName(r.thanaName),
  };
}

/**
 * Pull the whole BANBEIS registry to disk as NDJSON. Skips the network entirely if the on-disk copy
 * is younger than EIIN_REFRESH_H. @returns {Promise<{rows:number, pages:number, total:number, cached:boolean}>}
 */
export async function pullRegistry({ force = false } = {}) {
  if (!force) {
    try {
      const st = await fsp.stat(REGISTRY_FILE);
      if (Date.now() - st.mtimeMs < REFRESH_MS && st.size > 1000) {
        const rows = await countLines(REGISTRY_FILE);
        log(`registry: on-disk copy is fresh (${rows} rows, ${((Date.now() - st.mtimeMs) / 3600000).toFixed(1)}h old) — skipping pull`);
        return { rows, pages: 0, total: rows, cached: true };
      }
    } catch {}
  }

  const first = await fetchRegistryPage(1);
  if (!first.rows) throw new Error(`BANBEIS registry unreachable (http ${first.http}) — ${EIIN_API}/institute/public/list`);
  const total = first.total;
  const lastPage = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const pages = MAX_PAGES > 0 ? Math.min(MAX_PAGES, lastPage) : lastPage;
  log(`registry: total=${total} institutions, size=${PAGE_SIZE}/page → ${lastPage} pages, pulling ${pages} at concurrency ${CONCURRENCY}`);

  const part = REGISTRY_FILE + ".part";
  const out = fs.createWriteStream(part, { flags: "w" });
  const write = (rows) => new Promise((res) => {
    let buf = "";
    for (const r of rows) { const row = registryRow(r); if (row) buf += JSON.stringify(row) + "\n"; }
    if (!buf) return res(0);
    const n = buf.split("\n").length - 1;
    out.write(buf) ? res(n) : out.once("drain", () => res(n));
  });

  let written = await write(first.rows);
  let failed = 0;
  const t0 = Date.now();
  const todo = [];
  for (let p = 2; p <= pages; p++) todo.push(p);

  // Pages are fetched with bounded concurrency but each result is written as it arrives; the order in
  // the file does not matter because every consumer keys on eiin.
  let done = 0;
  await mapLimit(todo, CONCURRENCY, async (p) => {
    const { rows } = await fetchRegistryPage(p);
    if (!rows) { failed++; return; }
    written += await write(rows);
    if (++done % 100 === 0) {
      const rate = written / ((Date.now() - t0) / 1000);
      log(`registry: ${done}/${todo.length} pages, ${written} rows (${rate.toFixed(0)} rows/s)`);
    }
  });

  await new Promise((res) => out.end(res));
  if (written < 1) { await fsp.unlink(part).catch(() => {}); throw new Error("registry: 0 rows written"); }
  // Only replace the good copy once we have a complete-enough pull.
  await fsp.rename(part, REGISTRY_FILE);
  log(`registry: DONE — ${written} institutions on disk (${failed} pages failed) in ${((Date.now() - t0) / 1000).toFixed(0)}s → ${REGISTRY_FILE}`);
  return { rows: written, pages: pages, total, cached: false, failedPages: failed };
}

async function countLines(file) {
  let n = 0;
  const rl = readline.createInterface({ input: fs.createReadStream(file, { encoding: "utf8" }), crlfDelay: Infinity });
  for await (const line of rl) if (line.trim()) n++;
  return n;
}

/** Stream the on-disk registry, one parsed record at a time. Never loads the file into memory. */
export async function* streamRegistry(file = REGISTRY_FILE) {
  let rl;
  try { rl = readline.createInterface({ input: fs.createReadStream(file, { encoding: "utf8" }), crlfDelay: Infinity }); }
  catch { return; }
  for await (const line of rl) {
    if (!line.trim()) continue;
    try { yield JSON.parse(line); } catch {}
  }
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// RANK 54 — DPE / IPEMIS primary schools. A CROSS-REFERENCE TABLE, NOT A DOMAIN SOURCE.
//
// Stated plainly because the brief asked for honesty and because someone will eventually look at this
// file and wonder why 65,569 rows produce zero leads: Bangladeshi *government primary* schools do not
// have websites. They are administered centrally through IPEMIS itself; there is no budget line, no
// procurement path and no reason for one to exist. This table therefore submits NOTHING to /harvest.
//
// What it is genuinely for:
//   • cross-referencing a name/district scraped off a page against a real institution,
//   • disambiguating the many schools that share a name across districts,
//   • and giving rank 24 a second name corpus IF a future run ever wants to test primary-school names.
// ═════════════════════════════════════════════════════════════════════════════════════════════════

function dpeRow(r) {
  const code = String(r?.schoolCode || "").trim();
  if (!code) return null;
  return {
    schoolCode: code,
    name: cleanName(r.schoolName),
    nameBn: cleanName(r.schoolNameLocal),
    type: cleanName(r.schoolTypeName),
    division: cleanName(r.divisionName),
    district: cleanName(r.districtName),
    upazila: cleanName(r.upazilaName),
    union: cleanName(r.geoUnionName),
    teachers: Number(r.totalTeacher) || 0,
    students: Number(r.totalStudent) || 0,
  };
}

/** Pull the DPE primary-school table to disk. Returns 0 domains, by design. */
export async function pullDpe({ force = false } = {}) {
  if (!force) {
    try {
      const st = await fsp.stat(DPE_FILE);
      if (Date.now() - st.mtimeMs < DPE_REFRESH_MS && st.size > 1000) {
        const rows = await countLines(DPE_FILE);
        log(`dpe: on-disk copy is fresh (${rows} rows) — skipping pull`);
        return { rows, cached: true, domains: 0 };
      }
    } catch {}
  }

  const headers = { "x-requested-with": "XMLHttpRequest" };
  const first = await getJson(`${DPE_URL}?draw=1&start=0&length=${DPE_PAGE}`, { headers, timeout: 120000 });
  if (!first || first.httpError || !Array.isArray(first.aaData)) {
    log(`dpe: UNAVAILABLE (http ${first?.httpError || "?"}) — skipping; this source yields 0 domains anyway`);
    return { rows: 0, cached: false, domains: 0, failed: true };
  }
  const total = Number(first.recordsTotal) || first.aaData.length;
  const want = DPE_MAX_ROWS > 0 ? Math.min(DPE_MAX_ROWS, total) : total;
  log(`dpe: recordsTotal=${total}, pulling ${want} rows at length=${DPE_PAGE}`);

  const part = DPE_FILE + ".part";
  const out = fs.createWriteStream(part, { flags: "w" });
  const write = (rows) => new Promise((res) => {
    let buf = "", n = 0;
    for (const r of rows) { const row = dpeRow(r); if (row) { buf += JSON.stringify(row) + "\n"; n++; } }
    if (!buf) return res(0);
    out.write(buf) ? res(n) : out.once("drain", () => res(n));
  });

  let written = await write(first.aaData);
  const t0 = Date.now();
  // Strictly sequential: this endpoint took 50s for 1000 rows, so it is plainly not a fast box and
  // parallel requests would be antisocial for no gain.
  for (let start = DPE_PAGE; start < want; start += DPE_PAGE) {
    const j = await getJson(`${DPE_URL}?draw=1&start=${start}&length=${DPE_PAGE}`, { headers, timeout: 120000 });
    if (!j || j.httpError || !Array.isArray(j.aaData) || !j.aaData.length) { log(`dpe: stopped at start=${start}`); break; }
    written += await write(j.aaData);
    if ((start / DPE_PAGE) % 20 === 0) log(`dpe: ${written}/${want} rows (${(written / ((Date.now() - t0) / 1000)).toFixed(0)}/s)`);
  }

  await new Promise((res) => out.end(res));
  if (written < 1) { await fsp.unlink(part).catch(() => {}); return { rows: 0, domains: 0, failed: true }; }
  await fsp.rename(part, DPE_FILE);
  log(`dpe: DONE — ${written} primary schools on disk → ${DPE_FILE} (0 domains submitted, by design)`);
  return { rows: written, cached: false, domains: 0 };
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// RANK 25 — the EIIN-on-page extractor. THE STRONGEST FREE BD-EDUCATION PROOF THERE IS.
//
// Why it beats hosting IP: an EIIN is issued by BANBEIS to a specific physical institution. A number
// that (a) appears on the page next to the literal token EIIN / ইআইআইএন and (b) exists in the 40,162-row
// registry cannot be forged by a foreign casino operator, is unaffected by Cloudflare proxying (which
// destroys IP-based detection), and simultaneously proves the site is a GENUINE VICTIM rather than a
// spam brand — which is exactly the distinction that the 2026-07-16 genuine-vs-hacked incident needed.
//
// Membership in the registry is the whole point. A bare six-digit number near the word EIIN proves
// nothing; ~900k of the 6-digit space is not a valid EIIN. `known:false` is reported, never trusted.
//
// Bengali digits are handled: many school sites print ইআইআইএন: ১০৮০৬৬.
//
// ⚠ WHAT A KNOWN EIIN DOES AND DOES NOT PROVE — measured live, not assumed.
//
// PROVES: the page belongs to a Bangladeshi educational institution. That is what the system needs it
// for (BD-ness that survives Cloudflare, plus genuine-victim classification), and on that it is solid.
//
// DOES NOT PROVE: *which* institution. Measured counter-example from a live run over 60 real .edu.bd
// hosts — anarkaliss.edu.bd (Anarkali Secondary School) renders the literal string
//
//     "Institute Code: 0000  EIIN: 0000  EIIN No: 107906"
//
// and 107906 is DARUNNAZAT SIDDIKIA KAMIL MADRASAH in Dhaka. It is leftover boilerplate from a
// school-management SaaS template (the "EIIN: 0000" placeholder next to it gives the game away). So:
//   • treat eiinProof().known as a BD/education BOOLEAN — trustworthy;
//   • treat eiinProof().name as a HINT for outreach copy — corroborate against the page <title> or the
//     scanner's own address/district extraction before putting it in a message to a business owner;
//   • the same EIIN appearing on several unrelated domains is itself a useful signal: it fingerprints
//     a school-SaaS vendor cluster (TOP60 rank 14), whose other tenants are prime victims.
//
// The extractor deliberately skips the "EIIN: 0000" placeholder — it requires exactly six digits — and
// returns every candidate it saw in `all` so a caller can spot the duplicate-template case.
// ═════════════════════════════════════════════════════════════════════════════════════════════════

let EIIN_SET = null;          // sorted Uint32Array — binary search, 160KB for 40k entries
let EIIN_RECORDS = null;      // Map<number, {name,type,division,district,thana}> — ~5MB, optional

const BN_DIGITS = { "০": "0", "১": "1", "২": "2", "৩": "3", "৪": "4", "৫": "5", "৬": "6", "৭": "7", "৮": "8", "৯": "9" };
/** Convert Bengali numerals to ASCII. Exported — the scanner needs this for phone/address too. */
export function bnToAsciiDigits(s) { return String(s || "").replace(/[০-৯]/g, (c) => BN_DIGITS[c] || c); }

// The label, in every spelling seen on real BD school sites, plus the Bengali form.
const EIIN_LABEL = /(?:\bE\s*[-.]?\s*I\s*[-.]?\s*I\s*[-.]?\s*N\b|ই\s*আই\s*আই\s*এন|ইআইআইএন)/gi;

function stripHtml(html) {
  return String(html || "")
    .replace(/<(script|style|noscript)\b[^>]*>[\s\S]*?<\/\1>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;?/gi, " ")
    .replace(/&#(\d+);/g, (_, d) => (Number(d) < 0x10000 ? String.fromCharCode(Number(d)) : " "))
    .replace(/\s+/g, " ");
}

/**
 * Every 6-digit number that appears within `window` chars AFTER an EIIN label. Zero network.
 * @returns {number[]} candidate EIINs, deduped, in page order
 */
export function extractEiinCandidates(html, { window: win = 40 } = {}) {
  const text = bnToAsciiDigits(stripHtml(html));
  const out = [];
  const seenN = new Set();
  EIIN_LABEL.lastIndex = 0;
  let m;
  while ((m = EIIN_LABEL.exec(text)) !== null) {
    const tail = text.slice(m.index + m[0].length, m.index + m[0].length + win);
    // Skip separators/words like "No.", ":" , "নম্বর" then take the first 6-digit run.
    const d = tail.match(/(?<![\d])(\d{6})(?![\d])/);
    if (d) {
      const n = Number(d[1]);
      if (n >= 100000 && n <= 999999 && !seenN.has(n)) { seenN.add(n); out.push(n); }
    }
  }
  return out;
}

/** Load the EIIN index from the on-disk registry. Call once; idempotent. */
export async function loadEiinIndex({ withRecords = true, force = false } = {}) {
  if (EIIN_SET && !force) return { size: EIIN_SET.length, records: EIIN_RECORDS ? EIIN_RECORDS.size : 0 };
  const nums = [];
  const recs = withRecords ? new Map() : null;
  for await (const r of streamRegistry()) {
    const n = Number(r.eiin);
    if (!Number.isFinite(n)) continue;
    nums.push(n);
    if (recs) recs.set(n, { name: r.name, type: r.type, division: r.division, district: r.district, thana: r.thana });
  }
  if (!nums.length) {
    throw new Error(`eiin: no registry on disk at ${REGISTRY_FILE} — run --mode=registry first`);
  }
  nums.sort((a, b) => a - b);
  EIIN_SET = Uint32Array.from(nums);
  EIIN_RECORDS = recs;
  dbg("index loaded", EIIN_SET.length);
  return { size: EIIN_SET.length, records: recs ? recs.size : 0 };
}

/** Sync membership test. THROWS if the index was never loaded — a silent false here would quietly
 *  discard the best BD proof the system has, exactly the failure mode bdgate.ipInBd() guards against. */
export function isKnownEiin(n) {
  if (!EIIN_SET) throw new Error("eiin: call `await loadEiinIndex()` before isKnownEiin()");
  const v = Number(n);
  if (!Number.isFinite(v)) return false;
  let lo = 0, hi = EIIN_SET.length - 1;
  while (lo <= hi) {
    const m = (lo + hi) >> 1;
    if (v < EIIN_SET[m]) hi = m - 1;
    else if (v > EIIN_SET[m]) lo = m + 1;
    else return true;
  }
  return false;
}

/** The record behind a known EIIN (official name, type, district) — or null. */
export function eiinRecord(n) { return EIIN_RECORDS ? EIIN_RECORDS.get(Number(n)) || null : null; }

/**
 * THE SCANNER'S ENTRY POINT. Sync, zero network.
 * @returns {null | {eiin:number, known:boolean, all:number[], name?:string, district?:string, type?:string}}
 *   known===true is decisive proof of a Bangladeshi educational institution.
 */
export function eiinProof(html) {
  const cands = extractEiinCandidates(html);
  if (!cands.length) return null;
  for (const n of cands) {
    if (isKnownEiin(n)) {
      const rec = eiinRecord(n) || {};
      return { eiin: n, known: true, all: cands, name: rec.name, district: rec.district, type: rec.type, division: rec.division, thana: rec.thana };
    }
  }
  return { eiin: cands[0], known: false, all: cands };
}

/** Online single-EIIN oracle against BANBEIS (`?eiinNo=`). Use sparingly; the local index is free. */
export async function verifyEiinOnline(n) {
  const j = await getJson(`${EIIN_API}/institute/public/list?page=1&size=50&eiinNo=${encodeURIComponent(n)}`, { tries: 2, timeout: 30000 });
  const row = j && !j.httpError && Array.isArray(j.data) ? j.data[0] : null;
  return row ? registryRow(row) : null;
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// RANK 24 — name → candidate domain generation.
//
// The pattern is real and was re-verified live while writing this file:
//     nabinagarghs.edu.bd → 65.60.45.202     (and 65.60.45.202 is the eduman/shikkhaloy school-SaaS
//                                             box from TOP60 rank 14 — so one hit lands on a whole
//                                             cluster of other schools)
// The brief's second example, hcmshs.edu.bd, returned SERVFAIL at probe time. Reported as-is: one of
// the two cited examples is currently dead. The generator is not tuned to make it pass.
//
// GENERATORS, derived from how BD institutions actually name their domains:
//   core = name words minus type words ("HIGH","SCHOOL","GOVT","AND",…) — the place/person part
//   type = the type words, mapped to their conventional abbreviation
//
//   1. core + typeAbbrev            NABINAGAR GOVT HIGH SCHOOL   → nabinagarghs      ← the verified one
//   2. acronym(all words)           HAJEE CHAND MIA SHAHEEN H S  → hcmshs
//   3. acronym(core) + typeAbbrev
//   4. core + typeWordSpelledOut    → nabinagarhighschool / nabinagarschool
//   5. concat(all words)            → ummulqurahighschool
//   6. core alone                   → only when it is specific enough (see the blocklist)
//
// Each base is tried across EIIN_TLDS, .edu.bd first (highest hit rate, and admitted by bdgate rung 1).
// ═════════════════════════════════════════════════════════════════════════════════════════════════

// Words that describe the KIND of institution rather than which one it is.
const TYPE_WORDS = new Set([
  "high", "school", "schools", "college", "collegiate", "madrasah", "madrasa", "madrasha", "madrassa",
  "dakhil", "alim", "fazil", "kamil", "ebtedayee", "ebtedaee", "hafizia", "qawmi",
  "primary", "secondary", "junior", "senior", "academy", "institute", "institution", "university",
  "polytechnic", "technical", "vocational", "commerce", "textile", "nursing", "medical", "cadet",
  "kindergarten", "residential", "model", "pilot", "multilateral", "mohila", "girls", "boys", "balika",
  "bidyalaya", "biddaloy", "bidyaloy", "vidyalaya", "uccha", "ucha", "maddhyamik", "nimno",
]);
// Words that are pure noise in a domain name.
const STOP_WORDS = new Set([
  "the", "and", "of", "for", "at", "in", "a", "an", "no", "nos",
  "govt", "government", "sarkari", "sarkary", "national", "public", "memorial", "smriti",
  "ltd", "limited", "campus", "branch", "unit", "shakha",
]);
// Type → the abbreviation BD schools actually register.
const TYPE_ABBREV = [
  [["high", "school", "college"], "hsc"],
  [["school", "college"], "sc"],
  [["girls", "high", "school"], "ghs"],
  [["govt", "high", "school"], "ghs"],
  [["high", "school"], "hs"],
  [["dakhil", "madrasah"], "dm"],
  [["alim", "madrasah"], "am"],
  [["fazil", "madrasah"], "fm"],
  [["kamil", "madrasah"], "km"],
  [["madrasah"], "madrasah"],
  [["degree", "college"], "dc"],
  [["college"], "college"],
  [["primary", "school"], "ps"],
  [["technical", "college"], "tc"],
  [["polytechnic"], "polytechnic"],
  [["school"], "school"],
];

// Bases that are far too generic to attribute to any one institution. Generating "dhaka.com" and
// admitting whatever answers is precisely the class of mistake this project already paid for once.
const GENERIC_BASES = new Set([
  "school", "college", "madrasah", "madrasa", "highschool", "govtschool", "highschoolandcollege",
  "university", "institute", "academy", "polytechnic", "primaryschool", "girlsschool", "boysschool",
  "education", "bangladesh", "bangla", "dhaka", "chittagong", "chattogram", "sylhet", "khulna",
  "rajshahi", "barisal", "barishal", "rangpur", "mymensingh", "comilla", "cumilla", "gov", "govt",
  "model", "national", "public", "central", "city", "town", "union", "upazila", "district",
]);

// A name whose distinctive part is ONLY a place ("2 NO. DHAKA GOVT PRIMARY SCHOOL" → core = ["dhaka"])
// must not spawn dhakaschool/dhakacollege/dhakahighschool. Hundreds of institutions share a district
// name, so such a base identifies no one — and dhakacollege.com resolving in BD would be admitted by
// the gate while being an entirely unrelated business. Measured: this rule alone removes ~4 junk
// candidates per bare-place institution.
const PLACE_ONLY = new Set([
  "bagerhat", "bandarban", "barguna", "barisal", "barishal", "bhola", "bogra", "bogura",
  "brahmanbaria", "chandpur", "chapainawabganj", "nawabganj", "chittagong", "chattogram", "chuadanga",
  "comilla", "cumilla", "coxsbazar", "coxbazar", "dhaka", "dinajpur", "faridpur", "feni", "gaibandha",
  "gazipur", "gopalganj", "habiganj", "jamalpur", "jessore", "jashore", "jhalokati", "jhenaidah",
  "joypurhat", "khagrachhari", "khagrachari", "khulna", "kishoreganj", "kurigram", "kushtia",
  "lakshmipur", "laxmipur", "lalmonirhat", "madaripur", "magura", "manikganj", "meherpur",
  "moulvibazar", "maulvibazar", "munshiganj", "mymensingh", "naogaon", "narail", "narayanganj",
  "narsingdi", "natore", "netrokona", "netrakona", "nilphamari", "noakhali", "pabna", "panchagarh",
  "patuakhali", "pirojpur", "rajbari", "rajshahi", "rangamati", "rangpur", "satkhira", "shariatpur",
  "sherpur", "sirajganj", "sunamganj", "sylhet", "tangail", "thakurgaon",
]);

// The spelled-out suffix worth trying, chosen from the type words the name ACTUALLY contains. Blindly
// appending school+college+highschool to every name generated nonsense like
// "alipurdarussunnatdakhilmadrashaschool" and burned three DoH lookups per institution to prove it.
function spelledTypes(ws) {
  const set = new Set(ws);
  const out = [];
  if (set.has("high") && set.has("school")) out.push("highschool");
  if (set.has("school")) out.push("school");
  if (set.has("college")) out.push("college");
  if (set.has("madrasah") || set.has("madrasa") || set.has("madrasha") || set.has("madrassa")) out.push("madrasah");
  if (set.has("university")) out.push("university");
  if (set.has("academy")) out.push("academy");
  if (set.has("polytechnic")) out.push("polytechnic");
  if (!out.length) out.push("school");        // untyped name — "school" is the safest single guess
  return out.slice(0, 2);
}

function words(name) {
  return String(name || "").toLowerCase()
    .replace(/[^a-z0-9\s]/g, " ")
    .split(/\s+/).filter(Boolean)
    .filter((w) => !/^\d+$/.test(w));       // "2 NO. ..." ward numbers add nothing
}

function typeAbbrevOf(ws) {
  const set = new Set(ws);
  for (const [need, abbr] of TYPE_ABBREV) if (need.every((w) => set.has(w))) return abbr;
  return "";
}

const acronym = (ws) => ws.map((w) => w[0]).join("");

/**
 * Candidate domain BASES (no TLD) for one institution name. Deterministic and capped.
 * @returns {string[]}
 */
export function candidateBases(name, max = MAX_CAND) {
  const ws = words(name);
  if (ws.length < 1) return [];
  const meaningful = ws.filter((w) => !STOP_WORDS.has(w));
  const core = meaningful.filter((w) => !TYPE_WORDS.has(w));
  const abbr = typeAbbrevOf(ws);

  const coreCat = core.join("");
  const allCat = meaningful.join("");
  const out = [];
  const push = (s) => {
    const b = String(s || "").replace(/[^a-z0-9]/g, "");
    // <4 chars collides with everything; >40 is never registered by a school.
    if (b.length < 4 || b.length > 40) return;
    if (GENERIC_BASES.has(b)) return;
    if (!out.includes(b)) out.push(b);
  };

  // Is the distinctive part nothing but a place name? Then most forms identify no one.
  const barePlace = core.length === 0 || core.every((w) => PLACE_ONLY.has(w));

  if (coreCat && abbr) push(coreCat + abbr);                    // nabinagar + ghs  ← the verified form
  if (meaningful.length >= 3) push(acronym(meaningful));         // hcmshs
  if (core.length >= 2 && abbr) push(acronym(core) + abbr);
  if (coreCat && !barePlace) for (const t of spelledTypes(ws)) push(coreCat + t);
  push(allCat);                                                  // ummulqurahighschool
  // core alone only when it is specific: multi-word, or one long distinctive word — never a bare place.
  if (!barePlace && (core.length >= 2 || (core.length === 1 && core[0].length >= 7))) push(coreCat);

  return out.slice(0, max);
}

// ── CANDIDATE SAFETY ────────────────────────────────────────────────────────────────────────────
// Three guards on top of bdgate.isBdHost(), each aimed at a specific way generated names go wrong.

/**
 * GUARD 1 — per-TLD wildcard control probe. Some registries/resolvers answer every name under a
 * suffix. If a random 20-char nonsense label resolves, EVERY candidate under that TLD would look
 * like a hit, so the TLD is disabled for the run. Costs one lookup per TLD.
 */
async function wildcardProbe(tlds) {
  const usable = [];
  for (const tld of tlds) {
    const nonce = "zzq" + Math.random().toString(36).slice(2, 12) + "x9k";
    const ips = await resolveA(nonce + tld);
    if (ips.length) log(`guard: ${tld} answers a nonsense name (${ips[0]}) — WILDCARD, disabled this run`);
    else usable.push(tld);
  }
  return usable;
}

/** GUARD 2 — parking/wildcard IP frequency. One IP behind many unrelated generated names is a parking
 *  page or a catch-all, not N schools. Counts persist across runs. */
async function loadParkCounts() {
  try { return new Map(Object.entries(JSON.parse(await fsp.readFile(PARK_FILE, "utf8")))); } catch { return new Map(); }
}
async function saveParkCounts(m) {
  // Keep the file bounded — only IPs that actually look like parking are worth remembering.
  const obj = {};
  for (const [k, v] of m) if (v >= 3) obj[k] = v;
  try { await fsp.writeFile(PARK_FILE, JSON.stringify(obj)); } catch {}
}

async function readCursor() { try { return Number(await fsp.readFile(CAND_CURSOR, "utf8")) || 0; } catch { return 0; } }
async function writeCursor(n) { try { await fsp.writeFile(CAND_CURSOR, String(n)); } catch {} }

/**
 * Generate, resolve and gate candidate domains for the next slice of institutions.
 * Cursored and resumable: each run advances through the registry by EIIN_CAND_INSTITUTES and wraps.
 */
export async function runCandidates({ apiBase = API_BASE_DEFAULT, token = env.SHARED_TOKEN || "" } = {}) {
  await loadBdRanges();
  const totalRows = await countLines(REGISTRY_FILE).catch(() => 0);
  if (!totalRows) throw new Error("candidates: no registry on disk — run --mode=registry first");

  const start = await readCursor();
  const end = start + CAND_INSTITUTES;
  log(`candidates: institutions [${start}, ${Math.min(end, totalRows)}) of ${totalRows}; tlds=${TLDS.join(",")}; max ${MAX_CAND} bases each`);

  const tlds = await wildcardProbe(TLDS);
  if (!tlds.length) { log("candidates: every TLD wildcards — aborting run"); return { hosts: 0 }; }

  const park = await loadParkCounts();

  // Build the candidate list for this slice, streaming — the registry is never held in RAM.
  const cands = [];                      // {host, eiin, name, district}
  let idx = 0, institutions = 0, generated = 0, skippedSeen = 0;
  for await (const r of streamRegistry()) {
    const i = idx++;
    if (i < start) continue;
    if (i >= end) break;
    institutions++;
    for (const base of candidateBases(r.name)) {
      for (const tld of tlds) {
        const host = normHost(base + tld);
        if (!host) continue;
        generated++;
        if (seen(host)) { skippedSeen++; continue; }     // already in D1 — do not spend a lookup
        const lex = eduLexicon(host);
        if (lex.isSpammy) { dbg("spam-name reject", host); continue; }
        cands.push({ host, eiin: r.eiin, name: r.name, district: r.district, type: r.type });
      }
    }
  }
  log(`candidates: ${institutions} institutions → ${generated} names generated, ${skippedSeen} already known, ${cands.length} to resolve`);

  // Resolve. bdgate globally rate-limits DoH to BDGATE_DNS_RPS regardless of the concurrency here, so
  // this number only controls how many are in flight, never the request rate.
  let resolved = 0, checked = 0;
  const hits = [];
  const t0 = Date.now();
  await mapLimit(cands, 24, async (c) => {
    if (++checked % 2000 === 0) {
      log(`candidates: ${checked}/${cands.length} resolved, ${hits.length} live+BD (${(checked / ((Date.now() - t0) / 1000)).toFixed(0)}/s)`);
    }
    const ips = await resolveA(c.host);
    if (!ips.length) return;
    resolved++;
    // GUARD 2 — parking frequency.
    for (const ip of ips) park.set(ip, (park.get(ip) || 0) + 1);
    if (ips.every((ip) => (park.get(ip) || 0) > PARK_MAX)) { dbg("parking reject", c.host, ips[0]); return; }
    // THE ADMISSION DECISION — never the name.
    const d = await isBdHostDetail(c.host);
    if (!d.bd) { dbg("not-bd reject", c.host, d.reason, d.ip || ""); return; }
    hits.push({ ...c, ip: ips[0], reason: d.reason });
  });

  await saveParkCounts(park);
  await writeCursor(end >= totalRows ? 0 : end);

  log(`candidates: ${resolved}/${cands.length} resolved to an A record, ${hits.length} passed the BD gate`);
  for (const h of hits.slice(0, 20)) log(`  HIT ${h.host}  ${h.ip}  [${h.reason}]  EIIN ${h.eiin} — ${h.name} (${h.district})`);

  if (!hits.length) return { hosts: 0, generated, resolved, institutions };

  const rows = hits.map((h) => ({
    domain: h.host,
    // .edu.bd/.ac.bd are registry-gated institutional TLDs — the highest-confidence rows in the system.
    bd_score: /\.(edu|ac|gov)\.bd$/.test(h.host) ? 75 : 60,
    business: h.name ? `${h.name}${h.district ? " · " + h.district : ""}` : undefined,
  }));
  hits.forEach((h) => markSeen(h.host));

  if (DRY_RUN) { log(`candidates: DRY RUN — ${rows.length} rows NOT submitted`); return { hosts: rows.length, dryRun: true, generated, resolved, institutions }; }
  const res = await submit(apiBase, token, "eiin-candidates", rows);
  log(`candidates: submit → found=${res.found} inserted=${res.inserted} dups=${res.dups} ok=${res.ok}`);
  if (res.posted > 0 && res.found === 0) throw new Error("candidates: every row was dropped by the Worker — payload shape is wrong");
  return { hosts: rows.length, inserted: res.inserted, found: res.found, generated, resolved, institutions };
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// verify mode — a self-test for the rank-25 extractor against the live registry.
// ═════════════════════════════════════════════════════════════════════════════════════════════════

async function runVerify() {
  const idx = await loadEiinIndex();
  log(`verify: index = ${idx.size} EIINs, ${idx.records} records`);

  const samples = [];
  let n = 0;
  for await (const r of streamRegistry()) { if (n++ % 4000 === 0) samples.push(r); if (samples.length >= 6) break; }

  let pass = 0, fail = 0;
  const check = (label, html, expect) => {
    const p = eiinProof(html);
    const got = p ? `${p.eiin}/${p.known}` : "null";
    const ok = got === expect;
    ok ? pass++ : fail++;
    log(`  ${ok ? "PASS" : "FAIL"} ${label} → ${got}${ok ? "" : " (expected " + expect + ")"}${p?.name ? "  [" + p.name + "]" : ""}`);
  };

  for (const s of samples) {
    check(`plain "EIIN: ${s.eiin}"`, `<p>EIIN: ${s.eiin}</p>`, `${s.eiin}/true`);
    const bn = String(s.eiin).replace(/\d/g, (d) => "০১২৩৪৫৬৭৮৯"[Number(d)]);
    check(`bengali "ইআইআইএন: ${bn}"`, `<div>ইআইআইএন : ${bn}</div>`, `${s.eiin}/true`);
    check(`table row`, `<table><tr><td>EIIN No.</td><td>${s.eiin}</td></tr></table>`, `${s.eiin}/true`);
  }
  // Negative cases — the ones that matter.
  check("no EIIN on page", "<p>Welcome to our school. Call 01711223344.</p>", "null");
  check("6 digits, no label", "<p>Estd 1985, roll 123456</p>", "null");
  check("label + unknown number", "<p>EIIN: 999998</p>", "999998/false");
  check("script content ignored", `<script>var eiin=100001;</script><p>hello</p>`, "null");

  // Cross-check the local index against the live BANBEIS oracle for one real and one fake EIIN.
  const real = samples[0];
  const online = await verifyEiinOnline(real.eiin);
  const onlineOk = online && online.eiin === real.eiin;
  onlineOk ? pass++ : fail++;
  log(`  ${onlineOk ? "PASS" : "FAIL"} online oracle ?eiinNo=${real.eiin} → ${online ? online.name : "null"}`);
  const fake = await verifyEiinOnline("999998");
  const fakeOk = fake === null;
  fakeOk ? pass++ : fail++;
  log(`  ${fakeOk ? "PASS" : "FAIL"} online oracle ?eiinNo=999998 → ${fake ? fake.name : "null"} (expected null)`);

  log(`verify: ${pass} passed, ${fail} failed`);
  return { pass, fail };
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════

function argOf(name, dflt) {
  const hit = process.argv.find((a) => a.startsWith(`--${name}=`));
  return hit ? hit.slice(name.length + 3) : dflt;
}

async function main() {
  const mode = String(argOf("mode", env.EIIN_MODE || "all")).toLowerCase();
  const token = env.SHARED_TOKEN || "";
  const force = process.argv.includes("--force");
  const t0 = Date.now();
  log(`start mode=${mode} dir=${DATA_DIR}${DRY_RUN ? " DRY-RUN" : ""}`);

  if (mode === "registry" || mode === "all") await pullRegistry({ force });
  if (mode === "dpe" || mode === "all") await pullDpe({ force });
  if (mode === "verify") { const r = await runVerify(); process.exitCode = r.fail ? 1 : 0; }
  if (mode === "candidates" || mode === "all") {
    if (!token) { log("candidates: SHARED_TOKEN missing — skipping (nothing could be submitted)"); }
    else {
      // The seen-set is what stops us spending a DNS lookup on 161k domains D1 already has.
      const s = await loadSeen(API_BASE_DEFAULT, token);
      log(`candidates: seen-set = ${s.total} hosts (${s.fromDisk} disk, ${s.fromApi} api)`);
      await runCandidates({ token });
    }
  }
  log(`done in ${((Date.now() - t0) / 1000).toFixed(0)}s`);
}

// Only run when EXECUTED. The scanner imports eiinProof() from this file and must not trigger a
// 804-page government API crawl by doing so.
const isMain = (() => {
  try { return process.argv[1] && fileURLToPath(import.meta.url) === fs.realpathSync(process.argv[1]); }
  catch { return import.meta.url === pathToFileURL(process.argv[1] || "").href; }
})();
if (isMain) main().catch((e) => { console.error("[eiin] fatal:", e); process.exit(1); });
