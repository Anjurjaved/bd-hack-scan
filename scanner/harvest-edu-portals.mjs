// harvest-edu-portals.mjs — Bangladeshi EDUCATION-institution domain harvester, run ON THE ORACLE VM.
//
// Covers TOP60 ranks 21, 22, 35, 42, 43, 44, 47. Education is the owner's PRIMARY target: schools, colleges,
// madrasas, universities and technical institutes first. Most real ones sit on .com, which is exactly what
// generic .bd harvesting cannot see — so every task here starts from an authoritative Bangladeshi government
// or regulator surface and walks outward to whatever TLD the institution actually uses.
//
//   API_BASE=… SHARED_TOKEN=… node scanner/harvest-edu-portals.mjs
//   API_BASE=… SHARED_TOKEN=… EDU_TASKS=ugc,natportal EDU_DRY=1 node scanner/harvest-edu-portals.mjs
//
// ─────────────────────────────────────────────────────────────────────────────────────────────────
// THE FIVE TASKS (rotated by a cursor file so one run is short and polite; see EDU_TASKS_PER_RUN)
//
//   ugc        RANK 35  ugc-universities.gov.bd public/private/international university lists.
//                       ⚠ The websites are in PLAIN TABLE TEXT, not in href=. Regex the TEXT.
//                       ⚠ Its HTTPS certificate is EXPIRED (measured 2026-07-20) — this task uses http://.
//
//   natportal  RANK 22  The Bangladesh National Portal AJAX API — the clean way to enumerate the whole
//                       upazila/district portal estate with ZERO hardcoded hostnames:
//                         /ajax/get/division/list                     → 8 divisions
//                         /ajax/get/district/{divId}/list             → 64 districts
//                         /ajax/get/office-type/{typeId}/levels       → the level ids for an office type
//                         /ajax/get/office-level/{lvlId}/offices?office_type_id=…&loc_id=…&loc_type=…
//                       Each office object carries .domain / .subdomain / .domains[].subdomain.
//                       The office-type ids are NOT hardcoded — they are read live out of the
//                       <select name="officeType"> on any portal page, whose <option data-allow-levels>
//                       attribute also carries the level ids. Two types are used:
//                         "উপজেলা পোর্টাল"     → 499 upazila portals   (measured 2026-07-20)
//                         "শিক্ষা প্রতিষ্ঠান"  → 502 institution portals across school/college/university/
//                                                madrasha/nursing/polytechnic levels (measured)
//                       Then each upazila portal's /pages/education-institutes is scraped for outbound
//                       non-government links. MEASURED HONESTLY: that scrape yields ~0.3 usable domains
//                       per upazila (12 upazilas sampled → 0 emails, 44 URLs, nearly all boilerplate).
//                       The 1,001 portal hostnames are the real prize of this task; the scrape is a bonus
//                       and is capped by EDU_UPZ_PER_RUN so it can never dominate a run.
//
//   boards     RANKS 42/43/44  DSHE (EMIS/MPO), BTEB (polytechnics), BMEB (alia madrasas), BANBEIS, and the
//                       education boards. Hostnames are NOT hardcoded as live: a seed set is PROBED and the
//                       dead ones are reported, and further board hosts are discovered from cross-links on
//                       the ones that answer. Collects portal pages + every PDF URL they publish.
//
//   pdf        RANK 21  The cleverest source: MPO / recognition / circular PDFs print each institution's
//                       EMAIL, and the email domain IS the school's website domain — the best available
//                       trick for catching schools that sit on .com. pdftotext is used when present,
//                       otherwise a minimal inline FlateDecode+Tj/TJ extractor (node:zlib only, no npm).
//                       ⚠ MEASURED: a large fraction of BD government circulars are SCANNED IMAGES with no
//                       text layer at all (1 of 8 BMEB PDFs, 4 of 10 DSHE PDFs had zero extractable text).
//                       There is no free OCR on this box, so those are skipped, not "handled".
//
//   teachers   RANK 47  teachers.gov.bd (Shikkha Batayon) — teacher-authored blog/ambassador pages where
//                       authors link their own institutions.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────────
// THE TWO TRAPS, AND HOW THIS FILE STAYS OUT OF THEM
//
//  1. A DOMAIN IS NEVER BANGLADESHI BECAUSE ITS NAME SAYS SO. "bd"/"bangladesh" in a hostname is the
//     signature of foreign casino spam (1xbet-bd.org, 1win-bangladesh.net). This file NEVER decides
//     BD-ness itself — it calls bdgate.isBdHost(), which uses hosting IP inside APNIC BD space, a
//     registry-gated .bd nameserver, or the .bd TLD, and nothing else.
//
//     ONE narrowly-scoped addition, applied ONLY to email domains lifted out of a government PDF
//     (EDU_PROVENANCE_ADMIT, default on): a domain printed as an institution's contact address inside an
//     official ministry circular has AUTHORITATIVE-REGISTRY provenance, which the brief explicitly allows
//     alongside hosting-IP and CA-validated-organisation evidence. It is the only way to recover the real
//     target — a school on a Cloudflare-proxied .com, which bdgate documents as a known false negative.
//     It is still gated: eduLexicon().isSpammy is a hard reject, the host must resolve, free-mail and
//     infrastructure domains are dropped, and provenance-only rows are submitted at a LOWER bd_score (55)
//     than IP/NS-proven rows (70) so the scanner's own gate stays the final authority.
//     Links scraped out of HTML get NO such shortcut — a hacked government page can be link-injected, so
//     HTML-sourced candidates must pass isBdHost() outright.
//
//  2. FREE PUBLIC SERVICES 502 IF YOU HAMMER THEM. Every fetch here is retried with backoff, bounded by a
//     small global concurrency, spaced by a per-host politeness delay, and given a long timeout. Work is
//     cursored: each run does EDU_TASKS_PER_RUN tasks and a bounded slice of the long lists, and picks up
//     where it left off next time, so nothing is ever permanently lost to one bad afternoon.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────────
// ⚠ TLS: BANGLADESHI GOVERNMENT PORTALS SERVE BROKEN CERTIFICATE CHAINS.
// Measured 2026-07-20 with node 24: dhaka.gov.bd → UNABLE_TO_VERIFY_LEAF_SIGNATURE (incomplete chain),
// ugc-universities.gov.bd → CERT_HAS_EXPIRED. `node --use-system-ca` does NOT fix an incomplete chain.
// So fetchText() tries strictly first and, ONLY for a *.gov.bd host and ONLY on a certificate error,
// retries with verification relaxed. These are public, read-only government pages and nothing is ever
// sent to them, so this is an availability decision, not a security one. Set EDU_TLS_STRICT=1 to disable
// the fallback (and expect most of this harvester to go dark).
//
// ─────────────────────────────────────────────────────────────────────────────────────────────────
// MEMORY: designed for the 946MB / 1 OCPU box. Nothing is buffered whole: HTML bodies are capped at
// EDU_MAX_HTML bytes, PDFs are streamed to a temp file and capped at EDU_MAX_PDF bytes and deleted
// immediately, candidates live in a plain Set of hostnames, and results are submitted in chunks as each
// task finishes rather than accumulated to the end.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────────
// ENV (all optional except SHARED_TOKEN; defaults tuned for the Oracle VM)
//
//   API_BASE               https://bd-hack-audit-api.javed-it.workers.dev
//   SHARED_TOKEN           —           REQUIRED; Bearer token for POST /harvest
//   EDU_TASKS              —           comma list to force specific tasks (ugc,natportal,boards,pdf,teachers)
//   EDU_TASKS_PER_RUN      2           how many tasks one cron run covers (cursor rotates through them)
//   EDU_STATE              /opt/bd-scanner/.edu-portals-state.json    cursor + per-task offsets
//   EDU_PDF_SEEN           /opt/bd-scanner/.edu-portals-pdfs.txt      PDF URLs already extracted
//   EDU_CONCURRENCY        4           global in-flight HTTP requests (kept low on purpose)
//   EDU_GATE_CONCURRENCY   24          in-flight bdgate checks; DNS-bound, and bdgate caps DoH at 33/s
//                                      anyway, so this only controls how much we idle on NXDOMAIN latency
//   EDU_HOST_DELAY_MS      400         minimum gap between two requests to the SAME host
//   EDU_TIMEOUT_MS         60000       per-request timeout (BD gov portals are slow; 8s+ is normal)
//   EDU_MAX_HTML           3000000     hard cap on a single HTML body (bytes)
//   EDU_MAX_PDF            8000000     hard cap on a single PDF (bytes); larger ones are skipped
//   EDU_UPZ_PER_RUN        60          upazila portals whose institute page is scraped per run
//   EDU_PDFS_PER_RUN       40          PDFs downloaded + text-extracted per run
//   EDU_PDF_PAGES_PER_RUN  6           board listing pages crawled for PDF links per run
//   EDU_PROVENANCE_ADMIT   1           1 = admit PDF-email domains on government provenance (see above)
//   EDU_DRY                0           1 = do everything but the POST (prints what it would submit)
//   EDU_DRY_SAMPLE         25          how many rows EDU_DRY prints
//   EDU_TEACHER_SUBPAGES   40          teachers.gov.bd blog/profile pages followed per listing page
//   EDU_DEBUG              0           1 = verbose per-candidate logging

import fs from "node:fs";
import fsp from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import http from "node:http";
import https from "node:https";
import zlib from "node:zlib";
import { spawnSync } from "node:child_process";
import {
  loadBdRanges, isBdHostDetail, eduLexicon, alive,
  loadSeen, seen, markSeen, seenSize, submit, normHost, mapLimit,
  API_BASE_DEFAULT, CACHE_DIR,
} from "./bdgate.mjs";

const env = process.env;
const num = (v, d) => (Number.isFinite(Number(v)) && Number(v) >= 0 ? Number(v) : d);

const API_BASE = (env.API_BASE || API_BASE_DEFAULT).replace(/\/+$/, "");
const TOKEN = env.SHARED_TOKEN || "";
const TASKS_PER_RUN = num(env.EDU_TASKS_PER_RUN, 2);
const CONCURRENCY = Math.max(1, num(env.EDU_CONCURRENCY, 4));
const HOST_DELAY = num(env.EDU_HOST_DELAY_MS, 400);
const TIMEOUT = num(env.EDU_TIMEOUT_MS, 60000);
const MAX_HTML = num(env.EDU_MAX_HTML, 3_000_000);
const MAX_PDF = num(env.EDU_MAX_PDF, 8_000_000);
// The gate is DNS-bound, not CPU- or bandwidth-bound, and a host that does not exist is the SLOW case:
// MEASURED bau.portal.gov.bd (NXDOMAIN on both apex and www) = 10.4s, versus 0.1-0.5s for a live host.
// bdgate already caps the whole process at 33 DoH queries/second, so this number only controls how much
// we idle on latency. At 8 it took >20 minutes to gate the 1,001 National-Portal hosts; 24 makes it ~7.
const GATE_CONCURRENCY = Math.max(1, num(env.EDU_GATE_CONCURRENCY, 24));
const UPZ_PER_RUN = num(env.EDU_UPZ_PER_RUN, 60);
const PDFS_PER_RUN = num(env.EDU_PDFS_PER_RUN, 40);
const PDF_PAGES_PER_RUN = num(env.EDU_PDF_PAGES_PER_RUN, 6);
const PROVENANCE_ADMIT = env.EDU_PROVENANCE_ADMIT !== "0";
const TLS_STRICT = env.EDU_TLS_STRICT === "1";
const DRY = env.EDU_DRY === "1";
const DEBUG = env.EDU_DEBUG === "1";

const STATE_FILE = env.EDU_STATE || path.join(CACHE_DIR, ".edu-portals-state.json");
const PDF_SEEN_FILE = env.EDU_PDF_SEEN || path.join(CACHE_DIR, ".edu-portals-pdfs.txt");

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const log = (...a) => console.log("[edu]", ...a);
const dbg = (...a) => { if (DEBUG) console.error("[edu:dbg]", ...a); };

const STATS = { requests: 0, bytes: 0, tlsRelaxed: 0, failures: 0, pdfsFetched: 0, pdfsNoText: 0 };

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// HTTP — node:https/node:http directly, because global fetch() cannot relax an incomplete BD gov chain.
// Bounded concurrency + per-host spacing + capped body + retry with backoff.
// ═════════════════════════════════════════════════════════════════════════════════════════════════

let inFlight = 0;
const waiters = [];
async function acquire() {
  if (inFlight < CONCURRENCY) { inFlight++; return; }
  await new Promise((r) => waiters.push(r));
  inFlight++;
}
function release() { inFlight--; const w = waiters.shift(); if (w) w(); }

const lastHit = new Map();                       // host → ts, bounded below
async function politeness(host) {
  if (lastHit.size > 5000) lastHit.clear();
  const prev = lastHit.get(host) || 0;
  const wait = prev + HOST_DELAY - Date.now();
  if (wait > 0) await sleep(wait);
  lastHit.set(host, Date.now());
}

const CERT_ERR = /CERT|SIGNATURE|SELF_SIGNED|ALT_NAME|UNABLE_TO_VERIFY/i;

/** One raw request. `sink` (optional) receives chunks as Buffers instead of building a string. */
function rawRequest(url, { relax = false, maxBytes = MAX_HTML, sink = null, redirects = 0 } = {}) {
  return new Promise((resolve) => {
    let u;
    try { u = new URL(url); } catch { return resolve({ err: "bad-url" }); }
    const mod = u.protocol === "http:" ? http : https;
    const req = mod.get(url, {
      headers: {
        "user-agent": "Mozilla/5.0 (compatible; bd-hack-audit/1.0; +https://javeditsolution.com)",
        accept: "text/html,application/json,application/pdf,*/*",
        "accept-language": "bn,en;q=0.8",
      },
      rejectUnauthorized: !relax,
      timeout: TIMEOUT,
    }, (res) => {
      const code = res.statusCode || 0;
      if ([301, 302, 303, 307, 308].includes(code) && res.headers.location && redirects < 5) {
        res.resume();
        let next;
        try { next = new URL(res.headers.location, url).href; } catch { return resolve({ err: "bad-redirect" }); }
        return resolve(rawRequest(next, { relax, maxBytes, sink, redirects: redirects + 1 }));
      }
      if (code !== 200) { res.resume(); return resolve({ code, err: "http-" + code }); }

      let n = 0, truncated = false;
      const parts = [];
      res.on("data", (chunk) => {
        n += chunk.length;
        if (n > maxBytes) { truncated = true; res.destroy(); return; }
        if (sink) sink.write(chunk); else parts.push(chunk);
      });
      res.on("close", () => {
        STATS.bytes += n;
        if (truncated && sink) return resolve({ err: "too-large", bytes: n });
        resolve({ code: 200, bytes: n, truncated, body: sink ? null : Buffer.concat(parts).toString("utf8") });
      });
      res.on("error", (e) => resolve({ err: e.code || String(e) }));
    });
    req.on("error", (e) => resolve({ err: e.code || String(e) }));
    req.on("timeout", () => { req.destroy(); resolve({ err: "timeout" }); });
  });
}

/**
 * Fetch a URL as text. Retries with backoff; on a certificate error against a *.gov.bd host, retries once
 * with verification relaxed (see the TLS note at the top of this file).
 * @returns {Promise<string|null>}
 */
async function fetchText(url, { attempts = 3, maxBytes = MAX_HTML } = {}) {
  let host;
  try { host = new URL(url).host; } catch { return null; }
  for (let a = 1; a <= attempts; a++) {
    await acquire();
    let r;
    try {
      await politeness(host);
      STATS.requests++;
      r = await rawRequest(url, { maxBytes });
      if (r.err && CERT_ERR.test(r.err) && !TLS_STRICT && /\.gov\.bd$/i.test(host)) {
        STATS.tlsRelaxed++;
        STATS.requests++;
        r = await rawRequest(url, { relax: true, maxBytes });
      }
    } finally { release(); }
    if (r && r.code === 200) return r.body;
    dbg("fetch fail", url, r && r.err, "attempt", a);
    if (r && /^http-4/.test(String(r.err))) break;      // a 4xx is a real answer; do not retry
    await sleep(a * 1500);
  }
  STATS.failures++;
  return null;
}

async function fetchJson(url) {
  const t = await fetchText(url);
  if (!t) return null;
  try { return JSON.parse(t); } catch { return null; }
}

/** Stream a PDF to a temp file. Returns the path, or null. Caller MUST unlink it. */
async function fetchPdfToFile(url) {
  let host;
  try { host = new URL(url).host; } catch { return null; }
  const tmp = path.join(os.tmpdir(), "edu-" + Date.now() + "-" + Math.random().toString(36).slice(2) + ".pdf");
  for (let a = 1; a <= 2; a++) {
    const sink = fs.createWriteStream(tmp);
    await acquire();
    let r;
    try {
      await politeness(host);
      STATS.requests++;
      r = await rawRequest(url, { maxBytes: MAX_PDF, sink });
      if (r.err && CERT_ERR.test(r.err) && !TLS_STRICT && /\.gov\.bd$/i.test(host)) {
        STATS.tlsRelaxed++; STATS.requests++;
        r = await rawRequest(url, { relax: true, maxBytes: MAX_PDF, sink });
      }
    } finally { release(); }
    await new Promise((res) => sink.end(res));
    if (r && r.code === 200 && r.bytes > 100) { STATS.pdfsFetched++; return tmp; }
    await fsp.unlink(tmp).catch(() => {});
    if (r && (r.err === "too-large" || /^http-4/.test(String(r.err)))) break;
    await sleep(a * 2000);
  }
  return null;
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// PDF TEXT — RANK 21. pdftotext when it exists, otherwise an inline zero-dependency extractor.
// ═════════════════════════════════════════════════════════════════════════════════════════════════

const HAS_PDFTOTEXT = (() => {
  try { return spawnSync("pdftotext", ["-v"], { timeout: 8000 }).status !== null; } catch { return false; }
})();

/**
 * Minimal inline PDF text extraction: inflate every FlateDecode stream with node:zlib, then pull the
 * literal strings out of Tj / TJ / ' / " text operators. Emails and web addresses are plain ASCII in the
 * PDF's own encoding, so this is more than good enough for what rank 21 needs, and it does not pretend to
 * be a real PDF renderer. Bengali text comes out as mojibake — irrelevant, we only want the ASCII.
 */
function pdfTextInline(buf) {
  const out = [];
  // Uncompressed literals first (many BD circulars have a plain-text metadata block).
  const push = (s) => { if (s) out.push(s); };
  const scanOps = (s) => {
    for (const m of s.matchAll(/\(((?:\\.|[^\\()])*)\)\s*(?:Tj|TJ|'|")/g)) {
      push(m[1].replace(/\\([nrtbf()\\])/g, " ").replace(/\\[0-7]{1,3}/g, " "));
    }
    for (const m of s.matchAll(/\[((?:[^\][]|\\.)*)\]\s*TJ/g)) {
      for (const p of m[1].matchAll(/\(((?:\\.|[^\\()])*)\)/g)) {
        push(p[1].replace(/\\([nrtbf()\\])/g, " ").replace(/\\[0-7]{1,3}/g, " "));
      }
    }
  };
  const latin = buf.toString("latin1");
  scanOps(latin);
  // Then every deflate stream.
  let idx = 0;
  for (;;) {
    const s = latin.indexOf("stream", idx);
    if (s < 0) break;
    let b = s + 6;
    if (latin[b] === "\r") b++;
    if (latin[b] === "\n") b++;
    const e = latin.indexOf("endstream", b);
    if (e < 0) break;
    idx = e + 9;
    const raw = buf.subarray(b, e);
    if (raw.length < 8 || raw.length > 12_000_000) continue;
    let inf = null;
    try { inf = zlib.inflateSync(raw); } catch { try { inf = zlib.inflateRawSync(raw); } catch { inf = null; } }
    if (!inf) continue;
    scanOps(inf.toString("latin1"));
  }
  return out.join(" ");
}

async function pdfText(file) {
  if (HAS_PDFTOTEXT) {
    const r = spawnSync("pdftotext", ["-q", "-layout", "-enc", "UTF-8", file, "-"], {
      timeout: 60000, maxBuffer: 64 * 1024 * 1024,
    });
    const t = r.stdout ? r.stdout.toString("utf8") : "";
    if (t.replace(/\s+/g, "").length > 40) return t;
    // fall through — a scanned PDF gives pdftotext nothing either, but try the inline path once
  }
  try {
    const buf = await fsp.readFile(file);
    return pdfTextInline(buf);
  } catch { return ""; }
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// CANDIDATE EXTRACTION
// ═════════════════════════════════════════════════════════════════════════════════════════════════

// Never submit these. Infrastructure, social, CDNs, wikis, government-portal furniture, and — critically —
// free mail providers, whose presence in a circular says nothing at all about a school's website.
const JUNK = new RegExp([
  "(^|\\.)(google|gstatic|googleapis|googleusercontent|youtube|youtu\\.be|facebook|fb|instagram|twitter",
  "|x\\.com|linkedin|whatsapp|telegram|pinterest|tiktok|vimeo|flickr|blogspot|wordpress\\.com|wix",
  "|w3\\.org|schema\\.org|jquery|bootstrapcdn|cdnjs|cloudflare|jsdelivr|unpkg|fontawesome|ckeditor",
  "|wikipedia|wikimedia|wikidata|archive\\.org|oraclecloud|oraclecloud15|apple\\.com|itunes\\.apple\\.com",
  "|microsoft|office\\.com|adobe\\.com|nvaccess|mozilla|opera|example\\.(com|org)|localhost",
  "|gmail|googlemail|yahoo|ymail|rocketmail|hotmail|outlook|live\\.com|msn\\.com|aol\\.com|icloud",
  "|protonmail|proton\\.me|zoho|mail\\.ru|yandex|rediffmail|nothi\\.gov\\.bd|doptor\\.gov\\.bd",
  "|bangla\\.gov\\.bd|portal\\.gov\\.bd|plausible|matomo|sentry|gravatar)$",
].join(""), "i");

const RE_EMAIL = /[A-Za-z0-9._%+-]+@([A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+)/g;
const RE_URLHOST = /https?:\/\/([A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+)/g;
// Bare "www.x.edu.bd" / "abc.edu.bd" as it appears in UGC table TEXT and in circular body text.
const RE_BARE = /\b((?:www\.)?[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.(?:edu\.bd|ac\.bd|gov\.bd|com\.bd|net\.bd|org\.bd|info\.bd|mil\.bd|edu|ac|com|net|org|info|xyz|online|site|institute|academy))\b/gi;

const decodeEntities = (s) => {
  let out = String(s);
  for (let i = 0; i < 2; i++) {
    out = out
      .replace(/&#x([0-9a-f]+);/gi, (_, h) => { try { return String.fromCodePoint(parseInt(h, 16)); } catch { return " "; } })
      .replace(/&#(\d+);/g, (_, d) => { try { return String.fromCodePoint(Number(d)); } catch { return " "; } })
      .replace(/&quot;/gi, '"').replace(/&apos;/gi, "'").replace(/&lt;/gi, "<")
      .replace(/&gt;/gi, ">").replace(/&nbsp;/gi, " ").replace(/&amp;/gi, "&");
  }
  return out;
};

/** Strip tags so RE_BARE can see table TEXT (rank 35: UGC websites are text, not hrefs). */
const htmlToText = (html) => decodeEntities(
  String(html).replace(/<script[\s\S]*?<\/script>/gi, " ").replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ")
).replace(/\s+/g, " ");

/**
 * Pull hostname candidates out of a blob.
 * @param {string} blob
 * @param {"html"|"text"|"pdf"} kind
 * @returns {Map<string,{via:Set<string>}>}
 */
function extractCandidates(blob, kind) {
  const found = new Map();
  const add = (raw, via) => {
    const h = normHost(raw);
    if (!h) return;
    if (h.split(".").length < 2 || h.length > 200) return;
    if (JUNK.test(h) || JUNK.test(h.replace(/^www\./, ""))) return;
    if (!/\.[a-z]{2,}$/i.test(h)) return;
    if (/^\d+\.\d+\.\d+\.\d+$/.test(h)) return;
    const e = found.get(h) || { via: new Set() };
    e.via.add(via);
    found.set(h, e);
  };
  const text = kind === "html" ? htmlToText(blob) : decodeEntities(blob);
  const linky = kind === "html" ? decodeEntities(blob) : text;

  for (const m of linky.matchAll(RE_EMAIL)) add(m[1], kind === "pdf" ? "pdf-email" : "email");
  for (const m of linky.matchAll(RE_URLHOST)) add(m[1], "url");
  for (const m of text.matchAll(RE_BARE)) add(m[1], kind === "pdf" ? "pdf-text" : "text");
  return found;
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// THE GATE — bdgate decides BD-ness; this file only decides what evidence is allowed to reach it.
// ═════════════════════════════════════════════════════════════════════════════════════════════════

const admitted = new Map();                       // host → row (deduped across tasks in one run)
let statsAdmit = { checked: 0, spamRejected: 0, dead: 0, foreign: 0, provenance: 0, proven: 0, alreadySeen: 0 };

/**
 * @param {string} host
 * @param {Set<string>} via       how the host was found; "pdf-email" carries government provenance
 * @param {string} source         which task found it, for logging
 * @param {string} [business]     optional institution name
 * @param {boolean} [registry]    true when the host came off an AUTHORITATIVE Bangladeshi registry
 *                                surface (UGC accreditation roster, National Portal office API,
 *                                ministry circular email) rather than an ordinary HTML link
 */
async function consider(host, via, source, business, registry = false) {
  const h = normHost(host);
  if (!h || admitted.has(h)) return;
  statsAdmit.checked++;

  const lex = eduLexicon(h);
  if (lex.isSpammy) { statsAdmit.spamRejected++; dbg("REJECT spam-brand", h, lex.hits.join(",")); return; }

  if (!(await alive(h))) { statsAdmit.dead++; dbg("REJECT dead", h); return; }

  const d = await isBdHostDetail(h);
  if (d.bd) {
    statsAdmit.proven++;
    admitted.set(h, { domain: h, bd_score: /\.(edu|ac|gov|mil)\.bd$/i.test(h) ? 75 : 70, business, _why: d.reason, _src: source });
    return;
  }

  // Provenance path. Only reachable for a host named BY a Bangladeshi authority — the UGC accreditation
  // roster, the National Portal's own office records, or a contact address printed in a ministry
  // circular. Those are registry evidence, which the brief allows next to hosting-IP and CA-validated
  // organisation. It exists to recover the documented bdgate false negative: a real BD university or
  // school on a Cloudflare-proxied .edu/.com, e.g. UGC-listed aust.edu / ewubd.edu, which no free signal
  // can otherwise separate from a foreign host. It is NEVER reachable from a name token.
  if (PROVENANCE_ADMIT && (registry || via.has("pdf-email"))) {
    statsAdmit.provenance++;
    admitted.set(h, { domain: h, bd_score: 55, business, _why: "bd-registry-provenance", _src: source });
    return;
  }

  statsAdmit.foreign++;
  dbg("REJECT not-bd", h, d.reason, [...via].join("/"));
}

/** Run consider() over a candidate map with bounded DNS concurrency. */
async function considerAll(map, source, business, registry = false) {
  const entries = [...map.entries()].filter(([h]) => !admitted.has(h));
  await mapLimit(entries, GATE_CONCURRENCY, ([h, v]) => consider(h, v.via, source, business, registry));
}

/** www.foo.edu.bd also implies foo.edu.bd — the apex is what the IP/cluster logic keys on. */
function withApexes(rows) {
  const out = new Map(rows.map((r) => [r.domain, r]));
  for (const r of rows) {
    if (!r.domain.startsWith("www.")) continue;
    const apex = r.domain.slice(4);
    if (apex.split(".").length >= 2 && !out.has(apex)) out.set(apex, { ...r, domain: apex });
  }
  return [...out.values()];
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// STATE — cursor over tasks and over the long per-task lists.
// ═════════════════════════════════════════════════════════════════════════════════════════════════

const DEFAULT_STATE = { taskCursor: 0, upzOffset: 0, boardPageOffset: 0, pdfQueue: [] };
async function readState() {
  try { return { ...DEFAULT_STATE, ...JSON.parse(await fsp.readFile(STATE_FILE, "utf8")) }; }
  catch { return { ...DEFAULT_STATE }; }
}
async function writeState(s) {
  // pdfQueue is the only unbounded field — keep it small so the state file never becomes a data store.
  const trimmed = { ...s, pdfQueue: (s.pdfQueue || []).slice(0, 4000) };
  try { await fsp.writeFile(STATE_FILE, JSON.stringify(trimmed)); } catch (e) { log("state write failed:", String(e).slice(0, 90)); }
}

const pdfSeen = new Set();
async function loadPdfSeen() {
  try {
    const rl = (await import("node:readline")).createInterface({
      input: fs.createReadStream(PDF_SEEN_FILE, { encoding: "utf8" }), crlfDelay: Infinity,
    });
    for await (const line of rl) { const t = line.trim(); if (t) pdfSeen.add(t); }
  } catch {}
}
let pdfSeenStream = null;
function markPdfSeen(u) {
  if (pdfSeen.has(u)) return false;
  pdfSeen.add(u);
  try {
    if (!pdfSeenStream) pdfSeenStream = fs.createWriteStream(PDF_SEEN_FILE, { flags: "a" });
    pdfSeenStream.write(u + "\n");
  } catch {}
  return true;
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// TASK: ugc — RANK 35
// ═════════════════════════════════════════════════════════════════════════════════════════════════

// http:// on purpose — the HTTPS cert is expired (measured). ~180 accredited universities, the highest
// per-lead value in the system, and many sit on .edu / .ac / .com rather than .edu.bd.
const UGC_PAGES = [
  "http://www.ugc-universities.gov.bd/public-universities",
  "http://www.ugc-universities.gov.bd/private-universities",
  "http://www.ugc-universities.gov.bd/international-universities",
];

async function taskUgc() {
  let pages = 0;
  const cands = new Map();
  for (const u of UGC_PAGES) {
    const html = await fetchText(u);
    if (!html) { log("ugc: DEAD", u); continue; }
    pages++;
    // The websites live in plain TABLE TEXT, not in href=. htmlToText + RE_BARE is the whole trick.
    for (const [h, v] of extractCandidates(html, "html")) {
      const e = cands.get(h) || { via: new Set() };
      v.via.forEach((x) => e.via.add(x));
      cands.set(h, e);
    }
    log(`ugc: ${u.split("/").pop()} — ${html.length} bytes, ${cands.size} cumulative candidates`);
  }
  // registry=true: ugc-universities.gov.bd IS the accreditation roster. A domain on it is a UGC-accredited
  // Bangladeshi university by definition, which is exactly the registry evidence bdgate's IP/NS rungs
  // cannot see once the university sits behind Cloudflare.
  await considerAll(cands, "ugc", null, true);
  return { pages, candidates: cands.size };
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// TASK: natportal — RANK 22 (+ the education-institution office type it also exposes)
// ═════════════════════════════════════════════════════════════════════════════════════════════════

// Every National-Portal site serves the same header widget and the same /ajax API, so any of these works
// as the entry point. MEASURED GOTCHA 2026-07-20: www.bangladesh.gov.bd renders the <select> but 301s
// every /ajax path to its own homepage, so the API is NOT available on that origin. A base is therefore
// only accepted after /ajax/get/division/list is probed and actually returns a non-empty array — a
// hardcoded base would otherwise "succeed" with HTTP 200 and harvest exactly nothing.
const NAT_SEEDS = ["https://bangladesh.gov.bd/", "https://dhaka.gov.bd/", "https://chittagong.gov.bd/"];

/**
 * Read the office-type ids + their level ids LIVE out of the <select name="officeType"> on a portal page.
 * Nothing here is hardcoded: portals get rebuilt and these ids change, and a hardcoded id would fail
 * silently with an empty 200 rather than loudly.
 * @returns {Promise<Array<{id:string,title:string,levels:Object,base:string}>>}
 */
async function natOfficeTypes() {
  for (const seed of NAT_SEEDS) {
    const html = await fetchText(seed);
    if (!html) { dbg("natportal seed unreachable", seed); continue; }
    const i = html.indexOf('name="officeType"');
    if (i < 0) { dbg("natportal seed has no officeType select", seed); continue; }
    const base = new URL(seed).origin;
    const probe = await fetchJson(`${base}/ajax/get/division/list`);
    if (!Array.isArray(probe) || !probe.length) { log(`natportal: ${base} serves the widget but not the /ajax API — trying next seed`); continue; }
    const seg = html.slice(i, html.indexOf("</select>", i) + 9);
    const out = [];
    for (const m of seg.matchAll(/<option value="([a-f0-9]{12,})"\s+title="([^"]*)"[^>]*data-allow-levels='([^']*)'/g)) {
      let levels = {};
      try { levels = JSON.parse(decodeEntities(m[3])); } catch {}
      out.push({ id: m[1], title: m[2], levels, base, divisions: probe });
    }
    if (out.length) return out;
  }
  return [];
}

async function taskNatportal(state) {
  const types = await natOfficeTypes();
  if (!types.length) { log("natportal: could not read officeType select — API shape changed, ABORTING task"); return { dead: true }; }
  const base = types[0].base;
  log(`natportal: ${types.length} office types resolved live from ${base}`);

  const byTitle = (needle) => types.find((t) => t.title.includes(needle));
  const upzType = byTitle("উপজেলা পোর্টাল");
  const eduType = byTitle("শিক্ষা প্রতিষ্ঠান");

  const divisions = types[0].divisions || [];
  const districts = [];
  for (const d of divisions) {
    districts.push(...(await fetchJson(`${base}/ajax/get/district/${d._id}/list`) || []));
  }
  log(`natportal: ${divisions.length} divisions, ${districts.length} districts`);

  const officeHosts = new Map();                  // host → business name
  const grab = (arr, label) => {
    for (const o of arr || []) {
      const h = normHost(o.domain || o.subdomain || (o.domains && o.domains[0] && o.domains[0].subdomain));
      if (h) officeHosts.set(h, (o.title_en || o.title_bn || label || "").trim().slice(0, 200));
    }
  };

  // (a) Upazila portals — the ~560 hosts rank 22 is about, enumerated exactly.
  const upazilaPortals = [];
  if (upzType) {
    const lvl = upzType.levels?.upazila_level?.id;
    if (lvl) {
      await mapLimit(districts, 3, async (dd) => {
        const o = await fetchJson(`${base}/ajax/get/office-level/${lvl}/offices?office_type_id=${upzType.id}&loc_id=${dd._id}&loc_type=loc_district_id`);
        grab(o, dd.title_en);
        for (const x of o || []) {
          const h = normHost(x.domain || x.subdomain);
          if (h) upazilaPortals.push({ host: h, district: dd.title_en, name: x.title_en || x.title_bn });
        }
      });
    }
  }
  log(`natportal: ${upazilaPortals.length} upazila portals`);

  // (b) The education-institution office type — school / college / university / madrasha / nursing /
  //     polytechnic levels, i.e. ranks 42/43/44's target population as the government itself lists it.
  let eduOffices = 0;
  if (eduType) {
    for (const [code, lv] of Object.entries(eduType.levels || {})) {
      const o = await fetchJson(`${base}/ajax/get/office-level/${lv.id}/offices?office_type_id=${eduType.id}`);
      grab(o, code);
      eduOffices += (o || []).length;
      log(`natportal: education level ${code} — ${(o || []).length} offices`);
    }
  }

  // Submit every portal hostname the API named. These are .gov.bd, so bdgate admits them on rung 1.
  // Bounded-parallel, not sequential: this is ~1,000 hosts and each costs 1-2 DoH lookups. See GATE_CONCURRENCY.
  await mapLimit([...officeHosts.entries()], GATE_CONCURRENCY, async ([h, name]) => {
    if (seen(h)) { statsAdmit.alreadySeen++; return; }
    await consider(h, new Set(["registry"]), "natportal", name, true);
  });

  // (c) Bounded scrape of upazila education-institute pages for outbound institution links.
  //     Measured yield is low (~0.3/upazila) — capped so it can never eat the run.
  let off = state.upzOffset || 0;
  const slice = [];
  for (let k = 0; k < Math.min(UPZ_PER_RUN, upazilaPortals.length); k++) {
    slice.push(upazilaPortals[(off + k) % upazilaPortals.length]);
  }
  state.upzOffset = upazilaPortals.length ? (off + slice.length) % upazilaPortals.length : 0;

  let scraped = 0, outbound = 0;
  await mapLimit(slice, CONCURRENCY, async (u) => {
    const html = await fetchText(`https://${u.host}/pages/education-institutes?per_page=100`);
    if (!html) return;
    scraped++;
    const c = extractCandidates(html, "html");
    outbound += c.size;
    await considerAll(c, "natportal-upazila", null);
  });
  log(`natportal: scraped ${scraped}/${slice.length} upazila institute pages (cursor now ${state.upzOffset}/${upazilaPortals.length}), ${outbound} raw candidates`);

  return { divisions: divisions.length, districts: districts.length, upazilaPortals: upazilaPortals.length, eduOffices, portalHosts: officeHosts.size, scraped };
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// TASK: boards — RANKS 42 / 43 / 44
//
// The TOP60 probe found six education-board hostnames returning connection failure. They are therefore
// treated as CANDIDATES TO PROBE, never as known-good: each is probed, the result is reported, and the
// live ones are crawled for further board hosts. Nothing downstream depends on any single host.
// ═════════════════════════════════════════════════════════════════════════════════════════════════

const BOARD_SEEDS = [
  "https://dshe.gov.bd/",                 // rank 42 — DSHE (enter here; mpo.dshe.gov.bd was dead at probe)
  "https://emis.gov.bd/emis/",            // rank 42 — EMIS
  "https://bteb.gov.bd/",                 // rank 43 — technical board (www.bteb.gov.bd does NOT answer)
  "https://bmeb.gov.bd/",                 // rank 44 — madrasah board
  "https://banbeis.gov.bd/",
  "https://educationboard.gov.bd/",
  "https://dhakaeducationboard.gov.bd/",
  "https://rajshahieducationboard.gov.bd/",
  "https://jessoreboard.gov.bd/",
  "https://comillaboard.gov.bd/",
  "https://barisalboard.gov.bd/",
  "https://sylhetboard.gov.bd/",
  "https://dinajpureducationboard.gov.bd/",
  "https://mymensingheducationboard.gov.bd/",
  "https://bise-ctg.gov.bd/",
  "https://khulnaeducationboard.gov.bd/",
];

// Listing pages that these portals expose. Not every portal has every one; a 404 is normal and cheap.
const BOARD_SUBPAGES = [
  "pages/notices?per_page=100",
  "pages/news?per_page=100",
  "pages/common-documents?per_page=100",
  "pages/files?per_page=100",
  "pages/annual-reports?per_page=100",
  "pages/external-links",
];

async function taskBoards(state) {
  const alive_ = [], dead = [];
  const pdfUrls = new Set();
  const cands = new Map();
  const merge = (m) => { for (const [h, v] of m) { const e = cands.get(h) || { via: new Set() }; v.via.forEach((x) => e.via.add(x)); cands.set(h, e); } };

  // attempts:1 on the liveness probe. A board host that is down does not refuse the connection, it
  // ACCEPTS and hangs (measured: educationboard.gov.bd resolves to 103.230.107.233 and never answers), so
  // the default 3 attempts × EDU_TIMEOUT_MS turns each corpse into three minutes of dead air. One try is
  // all a probe needs; the host is retried on the next run anyway.
  await mapLimit(BOARD_SEEDS, CONCURRENCY, async (u) => {
    const html = await fetchText(u, { attempts: 1 });
    if (!html) { dead.push(u); return; }
    alive_.push(u);
    merge(extractCandidates(html, "html"));
    for (const m of decodeEntities(html).matchAll(/https?:\/\/[^\s"'<>]+\.pdf\b/gi)) pdfUrls.add(m[0]);
  });
  log(`boards: LIVE ${alive_.length}/${BOARD_SEEDS.length} — dead today: ${dead.length ? dead.join(" ") : "none"}`);

  // Crawl a rotating slice of listing sub-pages on the live hosts for more PDFs.
  const targets = [];
  for (const base of alive_) for (const sub of BOARD_SUBPAGES) targets.push(new URL(sub, base).href);
  let off = state.boardPageOffset || 0;
  const slice = [];
  for (let k = 0; k < Math.min(PDF_PAGES_PER_RUN, targets.length); k++) slice.push(targets[(off + k) % targets.length]);
  state.boardPageOffset = targets.length ? (off + slice.length) % targets.length : 0;

  await mapLimit(slice, CONCURRENCY, async (u) => {
    const html = await fetchText(u);
    if (!html) return;
    merge(extractCandidates(html, "html"));
    for (const m of decodeEntities(html).matchAll(/https?:\/\/[^\s"'<>]+\.pdf\b/gi)) pdfUrls.add(m[0]);
  });

  const fresh = [...pdfUrls].filter((u) => !pdfSeen.has(u));
  state.pdfQueue = [...new Set([...(state.pdfQueue || []), ...fresh])];
  log(`boards: crawled ${slice.length} listing pages (cursor ${state.boardPageOffset}/${targets.length}); ${pdfUrls.size} PDF links seen, ${fresh.length} new → queue now ${state.pdfQueue.length}`);

  await considerAll(cands, "boards");
  return { live: alive_.length, dead, pdfQueued: state.pdfQueue.length };
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// TASK: pdf — RANK 21. Circular PDFs → institution EMAIL → the school's own domain.
// ═════════════════════════════════════════════════════════════════════════════════════════════════

async function taskPdf(state) {
  let queue = state.pdfQueue || [];
  if (!queue.length) {
    log("pdf: queue empty — running the boards task first to fill it");
    await taskBoards(state);
    queue = state.pdfQueue || [];
  }
  const batch = queue.slice(0, PDFS_PER_RUN);
  state.pdfQueue = queue.slice(batch.length);

  let withText = 0, noText = 0, emails = 0;
  const cands = new Map();
  for (const u of batch) {
    markPdfSeen(u);
    const f = await fetchPdfToFile(u);
    if (!f) continue;
    let txt = "";
    try { txt = await pdfText(f); } finally { await fsp.unlink(f).catch(() => {}); }
    const dense = txt.replace(/\s+/g, "").length;
    if (dense < 40) { noText++; STATS.pdfsNoText++; dbg("pdf no text layer (scanned image):", u); continue; }
    withText++;
    const c = extractCandidates(txt, "pdf");
    for (const [h, v] of c) {
      if (v.via.has("pdf-email")) emails++;
      const e = cands.get(h) || { via: new Set() };
      v.via.forEach((x) => e.via.add(x));
      cands.set(h, e);
    }
  }
  log(`pdf: ${batch.length} queued, ${withText} had a text layer, ${noText} were scanned images (no free OCR — skipped), ${cands.size} host candidates, ${emails} from email addresses; ${state.pdfQueue.length} left in queue`);
  await considerAll(cands, "pdf-circular");
  return { attempted: batch.length, withText, noText, candidates: cands.size };
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// TASK: teachers — RANK 47. teachers.gov.bd authors link their own institutions.
// ═════════════════════════════════════════════════════════════════════════════════════════════════

const TEACHER_PAGES = [
  "https://teachers.gov.bd/",
  "https://teachers.gov.bd/blogs",
  "https://teachers.gov.bd/ambassadors",
];

async function taskTeachers() {
  const cands = new Map();
  let pages = 0;
  for (const u of TEACHER_PAGES) {
    const html = await fetchText(u);
    if (!html) { log("teachers: DEAD", u); continue; }
    pages++;
    for (const [h, v] of extractCandidates(html, "html")) {
      const e = cands.get(h) || { via: new Set() };
      v.via.forEach((x) => e.via.add(x));
      cands.set(h, e);
    }
    // Follow the post/profile links one level — that is where an author's own school URL actually appears.
    // MEASURED 2026-07-20: teachers.gov.bd emits ABSOLUTE hrefs (href="https://teachers.gov.bd/blog/details/844587"),
    // so a relative-only pattern matched 0 of 36 real links and this whole task silently harvested nothing.
    // The origin prefix is therefore optional, and it is pinned to teachers.gov.bd so a link-injected page
    // can never make this follow an attacker's host. /profile/ is included: an author's profile page is
    // where the institution is actually named.
    const links = [...new Set(
      [...decodeEntities(html).matchAll(/href="(?:https?:\/\/teachers\.gov\.bd)?(\/(?:blogs?|contents?|profile)\/[^"#?]+)"/gi)].map((m) => m[1]),
    )].slice(0, num(env.EDU_TEACHER_SUBPAGES, 40));
    await mapLimit(links, CONCURRENCY, async (p) => {
      const h2 = await fetchText(new URL(p, u).href);
      if (!h2) return;
      pages++;
      for (const [h, v] of extractCandidates(h2, "html")) {
        const e = cands.get(h) || { via: new Set() };
        v.via.forEach((x) => e.via.add(x));
        cands.set(h, e);
      }
    });
    log(`teachers: ${u} — ${links.length} sub-pages followed, ${cands.size} cumulative candidates`);
  }
  await considerAll(cands, "teachers");
  return { pages, candidates: cands.size };
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// MAIN
// ═════════════════════════════════════════════════════════════════════════════════════════════════

const ALL_TASKS = ["ugc", "natportal", "boards", "pdf", "teachers"];

async function main() {
  const t0 = Date.now();
  if (!TOKEN && !DRY) { console.error("SHARED_TOKEN missing (set EDU_DRY=1 to run without submitting)"); process.exit(1); }

  await loadBdRanges();
  const seedInfo = await loadSeen(API_BASE, TOKEN);
  log(`seen-set ${seenSize()} hosts (disk ${seedInfo.fromDisk}, api ${seedInfo.fromApi}); pdftotext=${HAS_PDFTOTEXT ? "yes" : "no (inline extractor)"}`);
  await loadPdfSeen();

  const state = await readState();
  let todo;
  if (env.EDU_TASKS) {
    todo = env.EDU_TASKS.split(",").map((s) => s.trim()).filter((s) => ALL_TASKS.includes(s));
  } else {
    const start = state.taskCursor % ALL_TASKS.length;
    todo = Array.from({ length: Math.min(TASKS_PER_RUN, ALL_TASKS.length) }, (_, k) => ALL_TASKS[(start + k) % ALL_TASKS.length]);
    state.taskCursor = (start + todo.length) % ALL_TASKS.length;
  }
  log(`run covers: ${todo.join(" ")} (next cursor ${state.taskCursor})`);

  const results = {};
  for (const t of todo) {
    const s = Date.now();
    try {
      if (t === "ugc") results.ugc = await taskUgc();
      else if (t === "natportal") results.natportal = await taskNatportal(state);
      else if (t === "boards") results.boards = await taskBoards(state);
      else if (t === "pdf") results.pdf = await taskPdf(state);
      else if (t === "teachers") results.teachers = await taskTeachers();
    } catch (e) {
      results[t] = { error: String(e).slice(0, 200) };
      log(`task ${t} FAILED: ${String(e).slice(0, 200)}`);
    }
    log(`task ${t} done in ${((Date.now() - s) / 1000).toFixed(0)}s — ${admitted.size} admitted so far`);
    await writeState(state);
  }

  const rows = withApexes([...admitted.values()].map(({ domain, bd_score, business }) => (business ? { domain, bd_score, business } : { domain, bd_score })));
  log(`gate: checked ${statsAdmit.checked} | admitted ${admitted.size} (+${rows.length - admitted.size} derived apexes) | ip/ns/tld-proven ${statsAdmit.proven}, bd-registry-provenance ${statsAdmit.provenance} | rejected: not-BD ${statsAdmit.foreign}, dead ${statsAdmit.dead}, spam-brand ${statsAdmit.spamRejected}`);

  let res = { found: 0, inserted: 0, dups: 0, posted: rows.length, ok: true };
  if (DRY) {
    log("EDU_DRY=1 — not submitting. Sample of what would be posted:");
    for (const r of rows.slice(0, num(env.EDU_DRY_SAMPLE, 25))) log("   ", JSON.stringify(r));
  } else if (rows.length) {
    res = await submit(API_BASE, TOKEN, "edu-portals", rows);
    for (const r of rows) markSeen(r.domain);
  }

  log(`DONE in ${((Date.now() - t0) / 1000).toFixed(0)}s — requests ${STATS.requests} (${(STATS.bytes / 1e6).toFixed(1)}MB, ${STATS.tlsRelaxed} needed relaxed TLS, ${STATS.failures} gave up), pdfs ${STATS.pdfsFetched} (${STATS.pdfsNoText} scanned/no-text)`);
  log(`SUBMIT posted=${res.posted} found=${res.found} inserted=${res.inserted} dups=${res.dups} ok=${res.ok}`);
  log("RESULTS " + JSON.stringify(results));
  if (!res.ok && !DRY) process.exitCode = 2;
}

main().catch((e) => { console.error("[edu] fatal:", e); process.exit(1); });
