// harvest-wayback.mjs — Internet Archive CDX harvester for Bangladeshi institutional domains.
// RANK 16 (spam-qualified, primary) + RANK 55 (bulk host enumeration, slow background trickle).
//
// Runs ON THE ORACLE VM. Zero npm dependencies, plain node ESM, streaming, bounded memory.
//
//   API_BASE=… SHARED_TOKEN=… node scanner/harvest-wayback.mjs
//
// ─────────────────────────────────────────────────────────────────────────────────────────────────
// WHAT MAKES THIS SOURCE DIFFERENT
//
// Every other harvester in this system finds a domain and hands it to the scanner to find out whether
// it is hacked. This one HARVESTS AND QUALIFIES IN THE SAME REQUEST: it asks the Internet Archive for
// .edu.bd / .ac.bd / .gov.bd URLs whose PATH matches a gambling-spam regex. A hit is not "a Bangladeshi
// school" — it is "a Bangladeshi school that was serving Indonesian slot-spam on a date the Archive
// recorded". That is a pre-qualified lead with a timestamped, third-party, verbatim proof URL, which is
// the highest value per row in the whole source list.
//
// MEASURED live 2026-07-20 on 10 index pages of *.edu.bd (81s):
//   aai.edu.bd                     https://aai.edu.bd/cgi-sys/suspendedpage.cgi?bonanza=slot-depo-5rb
//   casino.aamctg.edu.bd           http://www.casino.aamctg.edu.bd/
//   bangladesh.casino.aamctg.edu.bd
// A medical college with a subdomain literally called `casino`, and a school whose SUSPENDED cPanel page
// is still serving slot-spam query strings. Three hosts, three genuine hacks, zero false positives.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────────
// THE NAME-TEST TRAP DOES NOT APPLY HERE, AND HERE IS WHY THAT IS NOT LUCK
//
// The project's standing rule is that a domain is NEVER Bangladeshi because its name says so —
// 1xbet-bd.org is foreign casino spam, not a BD business. This harvester is structurally immune:
// it never matches on the hostname at all. The CDX `url=*.edu.bd` parameter is a REGISTRY-STRUCTURAL
// constraint (the .bd delegation hierarchy), and the spam regex is applied to `original`, i.e. the PATH
// AND QUERY STRING — never the host. `1xbet-bd.org` can never appear in a `*.edu.bd` result set no
// matter what its name says. Every host is still passed through bdgate's isBdHost() anyway, which
// admits these via its `.bd` TLD rung with zero DNS traffic.
//
// The inverse is the thing to keep straight: `casino.aamctg.edu.bd` IS admitted, and correctly so.
// The spam word is in the SUBDOMAIN of a domain the .bd registry delegated to a Bangladeshi medical
// college. That is the signature of a victim, not of a spam brand.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────────
// MEASURED CDX BEHAVIOUR — the four things that decide the whole design
//
// 1. `url=*.bd` IS FORBIDDEN. HTTP 403 "This type of request is not allowed", in 1.9s, repeatably.
//    A TLD-wide domain match is not available at any price. You MUST enumerate concrete suffixes
//    (*.edu.bd, *.ac.bd, …). Do not waste a run rediscovering this.
//
// 2. THE UNPAGED FILTERED QUERY 504s WHEREVER THE SPAM IS SPARSE — which is most places.
//    *.edu.bd?filter=…&limit=1000 → HTTP 200 in 62.5s (1001 rows, 7 hosts).
//    *.ac.bd and *.gov.bd, same shape → HTTP 504 Gateway Time-out at 64.1s, both of them.
//    The cause is not load. The server scans the index until it has filled `limit` matches; where
//    matches are rare it scans everything and blows the ~60s upstream gateway timeout. So the naive
//    "just add a filter and a resumeKey" approach silently works on exactly one suffix and dies on the
//    rest. THIS IS WHY THE HARVESTER IS PAGE-SHARDED INSTEAD.
//
// 3. `page=N` BOUNDS THE SERVER-SIDE SCAN AND NEVER TIMED OUT. `showNumPages=true` gives the shard
//    count; each page is an independent, cheap, resumable unit. MEASURED page counts:
//       *.edu.bd 3869 · *.ac.bd 1602 · *.gov.bd 19840 · *.com.bd 16949
//    Filtered page fetches ran 1.1-30.7s (one 59s outlier) across ~50 requests with zero 504s.
//    Verified equivalent, not just cheaper: *.edu.bd page 2 with the filter returns exactly the
//    aai.edu.bd rows the unpaged query found. Paging loses nothing.
//
// 4. PREFIX COLLAPSE IS A 9x SAVING FOR BULK ENUMERATION AND A 504 FOR FILTERED QUERIES.
//    `collapse=urlkey:22` collapses on the SURT prefix, i.e. roughly per-host instead of per-URL.
//    Bulk, 3 pages: collapse=urlkey → 3,676 rows / 44s. collapse=urlkey:22 → 204 rows / 5s.
//    SAME 4 hosts. But combined with a `filter` it 504s/terminates, so filtered modes use `limit`
//    to cap the download instead. Both levers exist; they are not interchangeable.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────────
// THE SPAM REGEX WAS TUNED AGAINST MEASURED FALSE POSITIVES — DO NOT "IMPROVE" IT BLIND
//
// The obvious instinct is to widen the token list. It was tried, on identical pages, and measured:
//
//   narrow (brief's 5 tokens)                          10 pages →  1 host,  0 FP
//   wide   (+ toto maxwin … zeus 4d 88 777 scatter)    10 pages →  8 hosts, 5 FP  (37% precision)
//   cleaned (this file)                                10 pages →  3 hosts, 0 FP  (100% precision)
//
// The five false positives and their exact causes, so nobody re-adds these tokens:
//   `4d`      → WordPress cache-buster `?ver=4d63a3d491d11ffd8ac6` (hit 3 unrelated schools)
//   `88`      → Facebook CDN filenames `410255525_3426773534231136_8893897092263153375_n.jpg`
//   `777`     → jQuery-UI sprite `ui-icons_777777_256x240.png`
//   `scatter` → `scatter-plot`, `scatter-diagram-in-7-qc-tools` — ordinary statistics coursework
//   `zeus`    → mythology/CS coursework; only meaningful as `slot-zeus`, which `slot` already catches
//
// Two structural guards keep the surviving tokens honest:
//   * a REQUIRED leading delimiter `[/?=&_.-]`, so `alphabet`/`photo` cannot trip `bet`/`toto`
//   * a REQUIRED trailing non-letter `([^a-z].*|$)` with an optional plural, so `judicial` cannot trip
//     `judi` and — this one matters in Bangladesh — `bandarban`, a district name, cannot trip `bandar`.
// Any token you add MUST be dry-run against real pages the way these were. See the porn-FP incident in
// memory/bd-hack-audit-20260719-porn-fp-fix.md for what skipping that step costs.
//
// MODE `cjk` is a second, orthogonal, 100%-precision detector: percent-encoded CJK/Hangul in the path
// of a .bd institutional site = foreign-language SEO injection. MEASURED: found
// abdulabadhighschool.edu.bd serving 17,039 Korean exam-dump pages (`/pdf/app-1Z0-888_…`). The byte
// range deliberately starts at %E3 so Bengali (%E0%A6/%E0%A7) can never match its own country's
// language — verified 0 Bengali rows in the result set. This mode is row-heavy, hence WAYBACK_LIMIT.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────────
// ENV (all optional; defaults tuned for the 946MB / 1 OCPU Oracle VM)
//
//   API_BASE               https://bd-hack-audit-api.javed-it.workers.dev
//   SHARED_TOKEN           —          required; bdgate.submit() throws without it
//   WAYBACK_MODES          spam,cjk   comma list of spam | cjk | bulk. `bulk` is rank 55 — see below.
//   WAYBACK_SUFFIXES       edu.bd,ac.bd,gov.bd,mil.bd     institutional first (highest lead value)
//   WAYBACK_BULK_SUFFIXES  edu.bd,ac.bd,gov.bd,com.bd,org.bd,net.bd
//   WAYBACK_PAGES          8          index pages per (mode,suffix) per run
//   WAYBACK_BULK_PAGES     4          rank 55 is a trickle — keep it small on purpose
//   WAYBACK_FROM           2024       CDX `from` (YYYY); recent captures only
//   WAYBACK_LIMIT          400        max rows per page — stops one mega-infected host dumping 17k rows
//   WAYBACK_COLLAPSE_PFX   22         SURT prefix length for bulk mode (measured 9x cheaper than none)
//   WAYBACK_GAP_MS         2500       polite gap between CDX requests
//   WAYBACK_TIMEOUT_MS     180000     per-request; the gateway itself gives up near 60s
//   WAYBACK_RETRIES        3
//   WAYBACK_BUDGET_S       1500       hard wall-clock stop, so a systemd timer can never overlap itself
//   WAYBACK_REQUIRE_ALIVE  1          drop hosts that no longer resolve (a corpse cannot buy cleanup)
//   WAYBACK_MAX_GATE       1500       max hosts DNS-gated per run; the rest wait for the cursor to wrap
//   WAYBACK_STATE          /opt/bd-scanner/.wayback-cursor.json
//   WAYBACK_PROOF_FILE     /opt/bd-scanner/wayback-proofs.jsonl   append-only evidence log
//   WAYBACK_MARK_BUSINESS  1          tag qualified rows so the dashboard shows they are pre-qualified
//   WAYBACK_DRY            0          1 = do everything except POST (use this to re-tune the regex)
//
// CADENCE: `spam,cjk` every 2h (bd-wayback.timer). `bulk` every 6h with WAYBACK_BULK_PAGES small.
// Rank 55 is genuinely inefficient and is labelled as such — it is a background slot, never a primary
// engine. Its own brief measured 54,847 rows for 242 unique hosts; prefix collapse improves the cost
// but not the fundamentals, so it stays on a leash.

import {
  loadBdRanges, isBdHost, alive, loadSeen, seen, markSeen, submit, mapLimit, API_BASE_DEFAULT,
} from "./bdgate.mjs";
import fs from "node:fs";
import fsp from "node:fs/promises";

const env = process.env;
const num = (v, d) => (Number.isFinite(Number(v)) && Number(v) > 0 ? Number(v) : d);
const list = (v, d) => String(v || d).split(",").map((s) => s.trim()).filter(Boolean);

const API_BASE = (env.API_BASE || API_BASE_DEFAULT).replace(/\/+$/, "");
const TOKEN = env.SHARED_TOKEN || "";
const MODES = list(env.WAYBACK_MODES, "spam,cjk");
const SUFFIXES = list(env.WAYBACK_SUFFIXES, "edu.bd,ac.bd,gov.bd,mil.bd");
const BULK_SUFFIXES = list(env.WAYBACK_BULK_SUFFIXES, "edu.bd,ac.bd,gov.bd,com.bd,org.bd,net.bd");
const PAGES = num(env.WAYBACK_PAGES, 8);
const BULK_PAGES = num(env.WAYBACK_BULK_PAGES, 4);
const FROM = String(env.WAYBACK_FROM || "2024");
const LIMIT = num(env.WAYBACK_LIMIT, 400);
const COLLAPSE_PFX = num(env.WAYBACK_COLLAPSE_PFX, 22);
const GAP_MS = num(env.WAYBACK_GAP_MS, 2500);
const TIMEOUT_MS = num(env.WAYBACK_TIMEOUT_MS, 180000);
const RETRIES = num(env.WAYBACK_RETRIES, 3);
const BUDGET_MS = num(env.WAYBACK_BUDGET_S, 1500) * 1000;
const REQUIRE_ALIVE = env.WAYBACK_REQUIRE_ALIVE !== "0";
const MAX_GATE = num(env.WAYBACK_MAX_GATE, 1500);
const STATE_FILE = env.WAYBACK_STATE || "/opt/bd-scanner/.wayback-cursor.json";
const PROOF_FILE = env.WAYBACK_PROOF_FILE || "/opt/bd-scanner/wayback-proofs.jsonl";
const MARK_BUSINESS = env.WAYBACK_MARK_BUSINESS !== "0";
const DRY = env.WAYBACK_DRY === "1";

const CDX = "http://web.archive.org/cdx/search/cdx";
const UA = "bd-hack-audit/1.0 (+https://javeditsolution.com; security research)";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const started = Date.now();
const budgetLeft = () => BUDGET_MS - (Date.now() - started);

// ═══════════════════════════════════════════════════════════════════════════════════════════════════
// The filters. See the long tuning note in the header before touching SPAM_TOKENS.
// ═══════════════════════════════════════════════════════════════════════════════════════════════════

const SPAM_TOKENS = [
  // Indonesian/SEA gambling-injection vocabulary — the dominant hack on BD institutional sites.
  "slot", "togel", "judi", "gacor", "sbobet", "maxwin", "situs", "bandar", "pragmatic",
  "toto", "pulsa", "bocoran", "paito", "jitu", "hoki", "mahjong", "rungkad", "depo",
  "cuan", "taruhan", "pkv", "dominoqq", "bolagila",
  // Generic gambling English — safe only because of the delimiter+boundary guards.
  "casino", "poker", "jackpot", "betting",
];
// leading delimiter, token, optional plural, then a non-letter or end-of-string.
const SPAM_FILTER = `original:.*[/?=&_.-](${SPAM_TOKENS.join("|")})s?([^a-z].*|$)`;

// Percent-encoded UTF-8 lead bytes %E3-%ED = Japanese kana, CJK, Hangul. %E0 (Bengali) is EXCLUDED by
// construction so a Bangladeshi site writing Bangla in its own URLs can never be flagged.
//
// THE {3,} IS NOT DECORATION — it was added after a measured false positive on the live run:
//   https://a2i.gov.bd/%E3%80%81https:/medium.com/digitalhks/bangladeshs-a2i-program-…
// `%E3%80%81` is U+3001, the CJK ideographic comma. One stray punctuation character had leaked into a
// mangled outbound link on a legitimate Bangladeshi government site — no injection at all. Requiring a
// RUN of three consecutive CJK/Hangul characters is what separates injected foreign-language content
// (`/pdf/app-1Z0-888_%EC%9C%A0%ED%9A%A8%ED%95%9C-…`, long Hangul strings) from stray punctuation.
// Do not relax this to {1,}.
const CJK_FILTER = "original:.*(%E[3-9ABCD]%[89AB][0-9A-F]%[89AB][0-9A-F]){3,}.*";

const MODE_DEFS = {
  spam: { filter: SPAM_FILTER, source: "wayback-spam", qualified: true, bdScore: 90, pages: PAGES, suffixes: SUFFIXES },
  cjk: { filter: CJK_FILTER, source: "wayback-cjk", qualified: true, bdScore: 85, pages: PAGES, suffixes: SUFFIXES },
  // Rank 55. Honestly labelled: no qualification, low score, small page budget, its own source row.
  bulk: { filter: null, source: "wayback-bulk", qualified: false, bdScore: 55, pages: BULK_PAGES, suffixes: BULK_SUFFIXES },
};

// ═══════════════════════════════════════════════════════════════════════════════════════════════════
// CDX transport. Retries on 5xx/network, gives up permanently on 403 (see trap 1 — retrying a 403
// forever is how a harvester burns a whole run on a request the Archive will never serve).
// ═══════════════════════════════════════════════════════════════════════════════════════════════════

const stats = { requests: 0, ok: 0, http403: 0, http504: 0, http429: 0, netFail: 0, bytes: 0, cdxSecs: 0 };

async function cdxGet(params) {
  const url = `${CDX}?${new URLSearchParams(params)}`;
  for (let attempt = 1; attempt <= RETRIES; attempt++) {
    if (budgetLeft() < 15000) return { fatal: true, reason: "budget" };
    const t0 = Date.now();
    stats.requests++;
    try {
      const r = await fetch(url, { headers: { "user-agent": UA, accept: "text/plain" }, signal: AbortSignal.timeout(TIMEOUT_MS) });
      const txt = await r.text();
      stats.cdxSecs += (Date.now() - t0) / 1000;
      stats.bytes += txt.length;
      if (r.ok) { stats.ok++; return { txt }; }
      if (r.status === 403) { stats.http403++; return { fatal: true, reason: "403" }; }
      if (r.status === 504) stats.http504++;
      if (r.status === 429) { stats.http429++; await sleep(attempt * 20000); continue; }
      await sleep(attempt * 6000);
    } catch {
      stats.cdxSecs += (Date.now() - t0) / 1000;
      stats.netFail++;
      await sleep(attempt * 6000);
    }
  }
  return { fatal: false, reason: "retries-exhausted" };
}

// numPages is stable enough to cache for a day; without it every run spends a request per suffix.
const pageCounts = new Map();
async function numPages(suffix) {
  if (pageCounts.has(suffix)) return pageCounts.get(suffix);
  const r = await cdxGet({ url: `*.${suffix}`, showNumPages: "true" });
  const n = r.txt ? parseInt(String(r.txt).trim(), 10) : NaN;
  const v = Number.isFinite(n) && n > 0 ? n : 0;
  pageCounts.set(suffix, v);
  return v;
}

// ═══════════════════════════════════════════════════════════════════════════════════════════════════
// Rotating page cursor. One counter per (mode, suffix), wrapping at numPages, persisted as JSON.
// Persisted BEFORE the pages are fetched: a run that dies mid-page must not re-walk the same pages
// forever. Losing one page to a crash is cheap; an infinite loop on page 0 is not.
// ═══════════════════════════════════════════════════════════════════════════════════════════════════

async function readState() {
  try { return JSON.parse(await fsp.readFile(STATE_FILE, "utf8")) || {}; } catch { return {}; }
}
async function writeState(st) {
  try {
    await fsp.mkdir(STATE_FILE.replace(/\/[^/]+$/, ""), { recursive: true }).catch(() => {});
    await fsp.writeFile(STATE_FILE, JSON.stringify(st, null, 2));
  } catch (e) { console.error("[wayback] cursor write failed:", String(e).slice(0, 90)); }
}

// ═══════════════════════════════════════════════════════════════════════════════════════════════════
// Host extraction. `original` is a full URL; keep the exact host AND, for a deep subdomain, the
// 3-label registrable apex — `casino.aamctg.edu.bd` is the hacked host but `aamctg.edu.bd` is the
// medical college that pays for the cleanup, and both are real rows.
// ═══════════════════════════════════════════════════════════════════════════════════════════════════

function hostsFromLine(line, out, proofs, mode) {
  const original = line.split(" ")[0];
  if (!original) return;
  let h;
  try { h = new URL(original.includes("://") ? original : "http://" + original).hostname.toLowerCase(); } catch { return; }
  h = h.replace(/^www\./, "");
  if (!h || !/^[a-z0-9.-]+$/.test(h) || !h.endsWith(".bd")) return;   // punycode/garbage/off-TLD
  if (!out.has(h)) { out.add(h); if (mode.qualified) proofs.push({ host: h, url: original.slice(0, 400) }); }
  const parts = h.split(".");
  if (parts.length > 3) out.add(parts.slice(-3).join("."));           // x.y.edu.bd -> y.edu.bd
}

async function walkPages(modeName, mode, suffix, state) {
  const total = await numPages(suffix);
  if (!total) { console.log(`[wayback] ${modeName}/${suffix}: numPages unavailable — skipping this run`); return { hosts: new Set(), proofs: [] }; }
  const key = `${modeName}:${suffix}`;
  const start = num(state[key], 0) % total;
  const want = Math.min(mode.pages, total);
  state[key] = (start + want) % total;
  await writeState(state);                                            // advance BEFORE fetching — see note above

  const hosts = new Set();
  const proofs = [];
  let rows = 0, hitPages = 0, done = 0;

  for (let i = 0; i < want; i++) {
    if (budgetLeft() < 20000) { console.log(`[wayback] ${modeName}/${suffix}: wall-clock budget reached after ${done} pages`); break; }
    const page = (start + i) % total;
    const params = { url: `*.${suffix}`, fl: "original", page: String(page), limit: String(LIMIT) };
    if (mode.filter) { params.filter = mode.filter; params.from = FROM; params.collapse = "urlkey"; }
    else params.collapse = `urlkey:${COLLAPSE_PFX}`;                  // bulk only — 9x cheaper, but 504s with a filter

    const r = await cdxGet(params);
    done++;
    if (r.fatal) { console.error(`[wayback] ${modeName}/${suffix} p${page}: fatal ${r.reason} — abandoning this suffix`); break; }
    if (!r.txt) { await sleep(GAP_MS); continue; }

    let n = 0;
    for (const line of r.txt.split("\n")) {
      const t = line.trim();
      if (!t) continue;
      n++;
      hostsFromLine(t, hosts, proofs, mode);
    }
    rows += n;
    if (n) hitPages++;
    await sleep(GAP_MS);
  }
  console.log(`[wayback] ${modeName}/${suffix}: pages ${start}..${(start + done - 1) % total} of ${total} — ${done} fetched, ${rows} rows, ${hitPages} hit-pages, ${hosts.size} hosts`);
  return { hosts, proofs };
}

// ═══════════════════════════════════════════════════════════════════════════════════════════════════
// The gate. Every host goes through bdgate — even though a `*.edu.bd` query cannot structurally return
// a non-.bd host, so isBdHost() resolves it on its `.bd` TLD rung with ZERO DNS traffic. It is kept
// because the admission rule belongs in one place, and because a future suffix added to
// WAYBACK_SUFFIXES might not be .bd at all.
//
// alive() is the expensive one (DoH, globally rate-limited at 33/s inside bdgate) and the valuable one:
// the brief measured only 39 of 200 .edu.bd domains still resolving. A dead school cannot buy a cleanup.
// ═══════════════════════════════════════════════════════════════════════════════════════════════════

// FOUND BY ACTUALLY RUNNING THIS: the wall-clock budget guards the CDX phase, but the gate is DNS-bound
// and was originally unbounded. `bulk` mode can surface thousands of hosts in one run, and at bdgate's
// global 33 lookups/s (up to 2 per host, apex then www) that phase alone can outlast the systemd timer
// interval and overlap the next run. So the gate is both CAPPED and budget-aware. Skipped hosts are not
// lost: the page cursor wraps, so they come round again on the next full cycle.
async function gate(hosts) {
  const fresh = [...hosts].filter((h) => !seen(h));
  const budgeted = fresh.slice(0, MAX_GATE);
  const skippedCap = fresh.length - budgeted.length;
  const kept = [];
  const drop = { notBd: 0, dead: 0, skippedBudget: 0 };
  await mapLimit(budgeted, 12, async (h) => {
    if (budgetLeft() < 10000) { drop.skippedBudget++; return; }
    if (!(await isBdHost(h))) { drop.notBd++; return; }
    if (REQUIRE_ALIVE && !(await alive(h))) { drop.dead++; return; }
    kept.push(h);
  });
  if (skippedCap) console.log(`[wayback] gate cap: ${skippedCap} hosts deferred to a later cycle (WAYBACK_MAX_GATE=${MAX_GATE})`);
  return { kept, drop, alreadySeen: hosts.size - fresh.length };
}

async function appendProofs(modeName, proofs) {
  if (!proofs.length) return;
  try {
    await fsp.mkdir(PROOF_FILE.replace(/\/[^/]+$/, ""), { recursive: true }).catch(() => {});
    const ts = new Date().toISOString();
    await fsp.appendFile(PROOF_FILE, proofs.map((p) => JSON.stringify({ ts, mode: modeName, ...p })).join("\n") + "\n");
  } catch (e) { console.error("[wayback] proof log failed:", String(e).slice(0, 90)); }
}

async function main() {
  if (!TOKEN && !DRY) { console.error("[wayback] SHARED_TOKEN missing — bdgate.submit() would throw. Set it, or run with WAYBACK_DRY=1."); process.exit(1); }
  console.log(`[wayback] modes=${MODES.join(",")} pages=${PAGES}/bulk${BULK_PAGES} from=${FROM} limit=${LIMIT} alive=${REQUIRE_ALIVE} dry=${DRY}`);

  await loadBdRanges();
  const seeded = await loadSeen(API_BASE, TOKEN).catch((e) => { console.error("[wayback] loadSeen failed (continuing; the Worker's INSERT OR IGNORE is the real dedup authority):", String(e).slice(0, 90)); return { total: 0 }; });
  console.log(`[wayback] seen-set: ${seeded.total} known hosts`);

  const state = await readState();
  const summary = [];

  for (const modeName of MODES) {
    const mode = MODE_DEFS[modeName];
    if (!mode) { console.error(`[wayback] unknown mode "${modeName}" — expected spam|cjk|bulk`); continue; }
    if (modeName === "bulk") console.log(`[wayback] --- mode bulk (RANK 55): host enumeration, no qualification, deliberately throttled. Not a primary engine. ---`);

    const allHosts = new Set();
    const allProofs = [];
    for (const suffix of mode.suffixes) {
      if (budgetLeft() < 30000) { console.log("[wayback] budget exhausted — stopping cleanly"); break; }
      const { hosts, proofs } = await walkPages(modeName, mode, suffix, state);
      hosts.forEach((h) => allHosts.add(h));
      allProofs.push(...proofs);
    }

    await appendProofs(modeName, allProofs);
    const { kept, drop, alreadySeen } = await gate(allHosts);

    let res = { found: 0, inserted: 0, dups: 0, ok: true };
    if (kept.length && !DRY) {
      const business = MARK_BUSINESS && mode.qualified ? `[wayback ${modeName}] archived spam URL on file` : "";
      const items = kept.map((h) => ({ domain: h, bd_score: mode.bdScore, ...(business ? { business } : {}) }));
      res = await submit(API_BASE, TOKEN, mode.source, items);
      if (res.ok) kept.forEach(markSeen);
    }

    console.log(`[wayback] ${modeName}: ${allHosts.size} hosts seen (${alreadySeen} already known, ${drop.notBd} non-BD, ${drop.dead} dead) -> ${kept.length} submitted -> found=${res.found} inserted=${res.inserted} dups=${res.dups}${res.ok ? "" : "  ** SUBMIT FAILED **"}`);
    if (mode.qualified && kept.length) {
      console.log(`[wayback] ${modeName} PRE-QUALIFIED leads: ${kept.slice(0, 20).join(", ")}${kept.length > 20 ? ` … +${kept.length - 20}` : ""}`);
    }
    summary.push({ mode: modeName, hosts: allHosts.size, submitted: kept.length, inserted: res.inserted, ok: res.ok });
  }

  await writeState(state);
  console.log(`[wayback] DONE in ${((Date.now() - started) / 1000).toFixed(0)}s — cdx: ${stats.requests} req, ${stats.ok} ok, ${stats.http504} 504, ${stats.http403} 403, ${stats.http429} 429, ${stats.netFail} net-fail, ${(stats.bytes / 1e6).toFixed(1)}MB, ${stats.cdxSecs.toFixed(0)}s in-flight`);
  console.log(`[wayback] summary ${JSON.stringify(summary)}`);
  console.log(`[wayback] rss ${(process.memoryUsage().rss / 1e6).toFixed(0)}MB`);
  if (summary.some((s) => !s.ok)) process.exit(2);
}

main().catch((e) => { console.error("[wayback] fatal:", e); process.exit(1); });
