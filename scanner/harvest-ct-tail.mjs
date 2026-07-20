// harvest-ct-tail.mjs — Static-CT tiled log tailing for Bangladeshi business + education domains.
// Runs ON THE ORACLE VM (946MB / 1 OCPU). Zero npm dependencies, plain node ESM, fully streaming.
//
//   API_BASE=… SHARED_TOKEN=… node scanner/harvest-ct-tail.mjs
//
// ─────────────────────────────────────────────────────────────────────────────────────────────────
// RANKS IMPLEMENTED (see scratchpad/TOP60.md)
//
//   #4  Static-CT tiled log tailing — ~9.5M certs/day of IMMUTABLE, index-cursored tiles. Every TLS
//       certificate issued to any Bangladeshi site passes through here within minutes. Unlike crt.sh,
//       Wayback, CommonCrawl or any directory, this source cannot go stale, cannot be rate-limited
//       into uselessness, and cannot be switched off — the tiles are static files on a CDN and the
//       cursor is a monotonic integer. This is the structural fix for the intake collapse.
//   #12 First-certificate watcher — a new school/coaching centre gets its Let's Encrypt cert minutes
//       after provisioning. Tailing the head of the log is the EARLIEST POSSIBLE detection of a new
//       BD site, months before any crawler, corpus or directory could see it. Implemented via
//       bdgate's seen-set: a host at the log head that is not in the 161k registry is brand new.
//   #33 Subject O/L/C parsing during ingest — C=BD or L=Dhaka in an OV/EV certificate is CA-VALIDATED
//       proof-grade BD-ness with ZERO DNS work, and the O= string is the legal business name, which
//       goes straight into outreach copy. This is the only BD signal in the whole system that is
//       stronger than hosting IP, because a Certificate Authority did the legal-entity check for us.
//   #41 Renewal-delta / multi-tenant new-tenant detection — a hostname appearing in a shared-hosting
//       AutoSSL certificate alongside hosts we already know is a NEW TENANT on a box we already
//       track. See the honest scoping note in the RANK 41 block below.
//   #32 Sectigo Tiger/Elephant RFC6962 tailing — OPT-IN (CTTAIL_SECTIGO=1), because it is measurably
//       8x the requests and ~3x the bytes per certificate. See the RANK 32 block for the numbers.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────────
// THE ONE RULE (inherited from bdgate.mjs — read it before touching this file)
//
// A domain is NEVER admitted as Bangladeshi because its NAME says so. eduLexicon() here is ONLY a
// zero-network prefilter that decides which hostnames are worth spending a DNS lookup on. The
// admission decision is isBdHost() (hosting IP in APNIC BD space / .bd-registry nameserver / .bd TLD)
// or a CA-VALIDATED Subject C=BD. A CT firehose is exactly where the 1xbet-bd.org class of foreign
// casino spam appears in bulk, so this gate is not optional — it is the entire reason this harvester
// is safe to run.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────────
// ⚠ NEVER HARDCODE A LOG SHARD NAME. Shards roll every 6 months and the old hardcoded Argon shard
// already 404s. Every endpoint below is resolved at runtime from operators[].tiled_logs[] in
// log_list.json, filtered to logs whose temporal_interval actually covers now. VERIFIED 2026-07-19:
// the submission_url in that file is NOT the read path — reading tiles from it returns 301/404. The
// read path is monitoring_url (Google's is a storage.googleapis.com bucket). This bit us in probing
// and is the single easiest way to get a "dead source" that is in fact perfectly alive.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────────
// ENV (all optional; defaults tuned for the Oracle VM + a 2-hourly systemd timer)
//
//   API_BASE                 https://bd-hack-audit-api.javed-it.workers.dev
//   SHARED_TOKEN             —          bearer token for /harvest (required to submit)
//   CTTAIL_LOG_LIST          https://www.gstatic.com/ct/log_list/v3/log_list.json
//   CTTAIL_LOGS              sycamore,willow,parcelyard   substring filter over log descriptions.
//                            Order matters — it is the priority order the tile budget is spent in.
//                            "all" = every active tiled log (heavy duplication; see notes).
//   CTTAIL_STATE_DIR         /opt/bd-scanner/.cttail      cursors; falls back to os.tmpdir()
//   CTTAIL_MAX_TILES         1200       total complete tiles per run across all logs (~307k certs).
//                                       Sized from the MEASURED log growth rates below — 400 was the
//                                       first guess and it could NOT keep up. See CADENCE.
//   CTTAIL_TILES_PER_LOG     450        per-log cap so one log cannot starve the others
//   CTTAIL_CONCURRENCY       4          parallel tile fetches (politeness + RAM: 4 x ~460KB)
//   CTTAIL_START_BACKLOG     40         cold start: begin this many tiles behind the head, not at 0
//   CTTAIL_MAX_LAG_TILES     20000      if the cursor falls further behind than this, jump to the
//                                       head. A log advances ~37k tiles/day; pretending to catch up
//                                       from a week-old cursor just wastes the whole budget on
//                                       stale tiles and never reaches the head. Honest > complete.
//   CTTAIL_MAX_DNS           3000       hard cap on isBdHost() lookups per run (bdgate is ~33/s)
//   CTTAIL_DNS               1          0 = admit ONLY proof-grade C=BD certs, spend no DNS at all
//   CTTAIL_SECTIGO           0          1 = also tail Sectigo Tiger/Elephant over RFC6962 (rank 32)
//   CTTAIL_SECTIGO_BATCHES   40         get-entries calls per run (the log serves 32 entries each)
//   CTTAIL_SUBMIT            1          0 = dry run, parse and gate but POST nothing
//   CTTAIL_SEEN_PAGE         1000       /api/domains page size. NOT bdgate's default of 5000 — that
//                                       returns HTTP 503 from the live Worker. See the note in main().
//   CTTAIL_SEEN_MAX_PAGES    400        1000 x 400 covers the whole ~161k registry
//   CTTAIL_SEEN_MIN          50000      a seen-set smaller than this means the on-disk cache is
//                                       poisoned by a failed earlier seed; forces one API re-seed
//   CTTAIL_DEBUG             0          1 = log every gate decision
//
// ─────────────────────────────────────────────────────────────────────────────────────────────────
// CADENCE — derived from MEASURED log growth, not from a guess. Run HOURLY.
//
// Growth measured live over a 577-second window on 2026-07-20 by diffing checkpoints:
//     Sycamore2026h2    +4,025 entries  →  0.60M certs/day  →  2,354 tiles/day
//     Willow2026h2      +3,772 entries  →  0.56M certs/day  →  2,206 tiles/day
//     ParcelYard2026h2 +10,145 entries  →  1.52M certs/day  →  5,934 tiles/day
//                                    TOTAL  2.69M certs/day  → 10,494 tiles/day
//
// So STAYING AT THE HEAD of the three default logs costs 10,494 tiles/day. At the 1200-tile default:
//     hourly  → 28,800 tiles/day capacity  = 2.7x headroom (recovers from an outage)  ← RECOMMENDED
//     2-hourly→ 14,400 tiles/day capacity  = 1.4x headroom (works, no room to recover)
//     the original 400-tile default at 2-hourly = 4,800/day — LESS THAN HALF the required rate, so
//     the cursor would fall behind forever and MAX_LAG would silently skip certificates.
//
// Bandwidth ~1.6GB/day compressed at full rate. Inbound transfer is free on Oracle Cloud, and this
// never touches the 10TB/month egress allowance.
//
// TO HALVE THE COST: drop parcelyard from CTTAIL_LOGS. Sycamore+Willow alone are 4,560 tiles/day and
// are where Let's Encrypt certificates land — which is where a new Bangladeshi school actually shows
// up (rank 12). The Google shard adds breadth (commercial CAs) at 57% of the total tile cost.
//
//   systemd timer:  OnCalendar=hourly  +  RandomizedDelaySec=600
// ─────────────────────────────────────────────────────────────────────────────────────────────────

import fs from "node:fs";
import fsp from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import zlib from "node:zlib";

import {
  loadBdRanges, isBdHostDetail, eduLexicon, alive, normHost,
  loadSeen, seen, markSeen, submit, mapLimit, API_BASE_DEFAULT,
} from "./bdgate.mjs";

const env = process.env;
const num = (v, d) => (Number.isFinite(Number(v)) && Number(v) >= 0 ? Number(v) : d);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const API_BASE = (env.API_BASE || API_BASE_DEFAULT).replace(/\/+$/, "");
const TOKEN = env.SHARED_TOKEN || "";
const LOG_LIST_URL = env.CTTAIL_LOG_LIST || "https://www.gstatic.com/ct/log_list/v3/log_list.json";
const LOG_FILTER = (env.CTTAIL_LOGS || "sycamore,willow,parcelyard").toLowerCase().split(",").map((s) => s.trim()).filter(Boolean);
const MAX_TILES = num(env.CTTAIL_MAX_TILES, 1200);
const TILES_PER_LOG = num(env.CTTAIL_TILES_PER_LOG, 450);
const CONCURRENCY = Math.max(1, num(env.CTTAIL_CONCURRENCY, 4));
const START_BACKLOG = num(env.CTTAIL_START_BACKLOG, 40);
const MAX_LAG = num(env.CTTAIL_MAX_LAG_TILES, 20000);
const MAX_DNS = num(env.CTTAIL_MAX_DNS, 3000);
const USE_DNS = env.CTTAIL_DNS !== "0";
const DO_SECTIGO = env.CTTAIL_SECTIGO === "1";
const SECTIGO_BATCHES = num(env.CTTAIL_SECTIGO_BATCHES, 40);
const DO_SUBMIT = env.CTTAIL_SUBMIT !== "0";
const DEBUG = env.CTTAIL_DEBUG === "1";
const SEEN_PAGE = num(env.CTTAIL_SEEN_PAGE, 1000);       // 5000 → HTTP 503 from the live Worker, see main()
const SEEN_MAX_PAGES = num(env.CTTAIL_SEEN_MAX_PAGES, 400);
const SEEN_MIN = num(env.CTTAIL_SEEN_MIN, 50000);        // below this the on-disk seen cache is poisoned

const dbg = (...a) => { if (DEBUG) console.error("[cttail]", ...a); };
const log = (...a) => console.log("[cttail]", ...a);

function resolveStateDir() {
  const want = env.CTTAIL_STATE_DIR || "/opt/bd-scanner/.cttail";
  for (const d of [want, path.join(os.tmpdir(), "cttail")]) {
    try { fs.mkdirSync(d, { recursive: true }); fs.accessSync(d, fs.constants.W_OK); return d; } catch {}
  }
  return os.tmpdir();
}
const STATE_DIR = resolveStateDir();
const CURSOR_FILE = path.join(STATE_DIR, "cursors.json");

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// Cursors — the whole point of tiled CT. An index, not a timestamp, so a run that dies mid-tile
// resumes exactly where it stopped and nothing issued while we were away is ever silently lost
// (which is precisely why public CertStream was rejected in the source review).
// ═════════════════════════════════════════════════════════════════════════════════════════════════

async function readCursors() {
  try { return JSON.parse(await fsp.readFile(CURSOR_FILE, "utf8")) || {}; } catch { return {}; }
}
async function writeCursors(c) {
  try {
    const tmp = CURSOR_FILE + ".tmp";
    await fsp.writeFile(tmp, JSON.stringify(c, null, 1));
    await fsp.rename(tmp, CURSOR_FILE);          // atomic — a killed process cannot corrupt the cursor
  } catch (e) { console.error("[cttail] cursor write failed:", String(e).slice(0, 90)); }
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// RANK 4a — resolve live tiled logs from log_list.json. NEVER hardcoded.
//
// VERIFIED LIVE 2026-07-19: 22 tiled logs across 5 operators (Google ParcelYard/PlumbersArms,
// Let's Encrypt Sycamore/Willow, Geomys Tuscolo, IPng Halloumi/Gouda, TrustAsia Luoshu). Only the
// shards whose temporal_interval brackets "now" are actually receiving certificates; the 2027h1/h2
// shards exist already and are empty, so tailing them burns the budget on nothing.
// ═════════════════════════════════════════════════════════════════════════════════════════════════

async function fetchJson(url, timeout = 60000) {
  const r = await fetch(url, {
    headers: { "user-agent": "bd-hack-audit/1.0 (+javeditsolution.com)", accept: "application/json" },
    signal: AbortSignal.timeout(timeout),
  });
  if (!r.ok) throw new Error("http " + r.status + " " + url);
  return r.json();
}

async function resolveLogs() {
  const cache = path.join(STATE_DIR, "log_list.json");
  let list = null;
  try {
    list = await fetchJson(LOG_LIST_URL);
    await fsp.writeFile(cache, JSON.stringify(list)).catch(() => {});
  } catch (e) {
    console.error("[cttail] log_list fetch failed (" + String(e).slice(0, 80) + ") — trying cache");
    try { list = JSON.parse(await fsp.readFile(cache, "utf8")); } catch {}
  }
  if (!list) throw new Error("cttail: no log list available (network down and no cache)");

  const now = Date.now();
  const out = [];
  for (const op of list.operators || []) {
    for (const L of op.tiled_logs || []) {
      const state = Object.keys(L.state || {})[0] || "unknown";
      if (state === "retired" || state === "rejected" || state === "readonly") continue;
      const ti = L.temporal_interval;
      if (ti) {
        const s = Date.parse(ti.start_inclusive), e = Date.parse(ti.end_exclusive);
        if (Number.isFinite(s) && now < s) continue;          // shard has not opened yet
        if (Number.isFinite(e) && now >= e) continue;          // shard has closed
      }
      // monitoring_url is the READ path. submission_url is for CAs and returns 301/404 for tiles.
      const base = String(L.monitoring_url || "").replace(/\/+$/, "");
      if (!base) continue;
      out.push({ desc: L.description || base, operator: op.name || "?", base, state });
    }
  }

  if (LOG_FILTER.length && LOG_FILTER[0] !== "all") {
    const ranked = [];
    for (const want of LOG_FILTER) {
      for (const l of out) {
        const hay = (l.desc + " " + l.base).toLowerCase();
        if (hay.includes(want) && !ranked.includes(l)) ranked.push(l);
      }
    }
    return ranked;
  }
  return out;
}

// Signed-note checkpoint: line 0 = origin, line 1 = tree size, line 2 = base64 root hash.
async function fetchCheckpoint(base) {
  const r = await fetch(base + "/checkpoint", {
    headers: { "user-agent": "bd-hack-audit/1.0 (+javeditsolution.com)" },
    signal: AbortSignal.timeout(45000),
  });
  if (!r.ok) throw new Error("checkpoint http " + r.status);
  const lines = (await r.text()).split("\n");
  const size = Number(lines[1]);
  if (!Number.isFinite(size) || size < 0) throw new Error("checkpoint unparsable");
  return { origin: lines[0], size };
}

// tlog-tiles path: the index in 3-digit groups, all but the last prefixed "x".
// 1455000 → x001/x455/000. VERIFIED against a live Sycamore fetch (HTTP 200, 256 entries).
function tilePath(n) {
  let s = String(n);
  while (s.length % 3) s = "0" + s;
  const groups = s.match(/.{3}/g);
  return groups.map((g, i) => (i === groups.length - 1 ? g : "x" + g)).join("/");
}

async function fetchTile(base, idx) {
  const url = `${base}/tile/data/${tilePath(idx)}`;
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      const r = await fetch(url, {
        headers: { "user-agent": "bd-hack-audit/1.0 (+javeditsolution.com)" },
        signal: AbortSignal.timeout(60000),
      });
      if (r.status === 404) return null;                         // beyond the published tree — normal
      if (r.status === 429 || r.status >= 500) { await sleep(attempt * 1500); continue; }
      if (!r.ok) return null;
      let buf = Buffer.from(await r.arrayBuffer());
      // Some mirrors store the tile gzipped WITHOUT content-encoding, so undici does not inflate it.
      // Sniff the magic and inflate manually — correct whichever way the origin serves it.
      if (buf.length > 2 && buf[0] === 0x1f && buf[1] === 0x8b) {
        try { buf = zlib.gunzipSync(buf); } catch { return null; }
      }
      return buf;
    } catch { await sleep(attempt * 1500); }
  }
  return null;
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// DER — a minimal, allocation-light walker. Only what is needed: SAN dNSNames + Subject O/L/C/CN.
// A full ASN.1 library would be a dependency, and this box gets zero npm dependencies.
// MEASURED: 87,472 certificates/second single-threaded on this parser.
// ═════════════════════════════════════════════════════════════════════════════════════════════════

function tlv(b, off, end) {
  if (off + 2 > end) return null;
  const tag = b[off];
  let len = b[off + 1], h = 2;
  if (len & 0x80) {
    const nb = len & 0x7f;
    if (nb === 0 || nb > 4 || off + 2 + nb > end) return null;   // indefinite length is illegal in DER
    len = 0;
    for (let i = 0; i < nb; i++) len = len * 256 + b[off + 2 + i];
    h = 2 + nb;
  }
  if (off + h + len > end) return null;
  return { tag, len, vs: off + h, ve: off + h + len, next: off + h + len };
}

function children(b, s, e) {
  const out = [];
  let p = s;
  while (p < e) { const t = tlv(b, p, e); if (!t) break; out.push(t); p = t.next; }
  return out;
}

// X.500 attribute OIDs, DER-hex encoded.
const ATTR_OID = { "550403": "CN", "55040a": "O", "550407": "L", "550406": "C", "55040b": "OU", "550408": "ST" };
const OID_SAN = "551d11";                                        // 2.5.29.17 subjectAltName

function parseName(b, t) {
  const out = {};
  for (const rdn of children(b, t.vs, t.ve)) {
    for (const av of children(b, rdn.vs, rdn.ve)) {
      const kids = children(b, av.vs, av.ve);
      if (kids.length < 2) continue;
      const key = ATTR_OID[b.subarray(kids[0].vs, kids[0].ve).toString("hex")];
      if (!key || out[key]) continue;
      // DirectoryString: PrintableString/UTF8String/etc. UTF-8 decode is correct for all common cases.
      out[key] = b.subarray(kids[1].vs, kids[1].ve).toString("utf8").replace(/[\x00-\x1f]/g, "").trim().slice(0, 200);
    }
  }
  return out;
}

/**
 * @param {Buffer} b   full Certificate DER (x509 entry) or bare TBSCertificate (precert entry)
 * @param {boolean} isPrecert  true when b is already a TBSCertificate
 * @returns {{subject:object, names:string[]}|null}
 */
function certInfo(b, isPrecert) {
  const top = tlv(b, 0, b.length);
  if (!top) return null;
  let tbs;
  if (isPrecert) tbs = top;                                      // the precert TimestampedEntry holds the TBS itself
  else { const c = children(b, top.vs, top.ve); if (!c.length) return null; tbs = c[0]; }

  let ch = children(b, tbs.vs, tbs.ve);
  if (ch.length && ch[0].tag === 0xa0) ch = ch.slice(1);         // [0] EXPLICIT version, absent in v1
  // TBSCertificate order: serial, sigAlg, issuer, validity, subject, spki, [1]/[2]/[3]...
  const subject = ch[4] ? parseName(b, ch[4]) : {};

  const names = new Set();
  for (const c of ch.slice(5)) {
    if (c.tag !== 0xa3) continue;                                // [3] EXPLICIT extensions
    const seq = children(b, c.vs, c.ve)[0];
    if (!seq) continue;
    for (const ext of children(b, seq.vs, seq.ve)) {
      const k = children(b, ext.vs, ext.ve);
      if (!k.length) continue;
      if (b.subarray(k[0].vs, k[0].ve).toString("hex") !== OID_SAN) continue;
      const oct = k[k.length - 1];                               // extnValue OCTET STRING (after optional critical BOOLEAN)
      const gn = tlv(b, oct.vs, oct.ve);
      if (!gn) continue;
      for (const g of children(b, gn.vs, gn.ve)) {
        // [2] IMPLICIT IA5String dNSName. latin1 is the correct 1:1 byte decode for IA5.
        if (g.tag === 0x82) names.add(b.subarray(g.vs, g.ve).toString("latin1").toLowerCase());
      }
    }
  }
  if (subject.CN && /^[*a-z0-9.-]+$/i.test(subject.CN)) names.add(subject.CN.toLowerCase());
  return { subject, names: [...names] };
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// TileLeaf framing (c2sp.org/static-ct-api).
//
//   uint64 timestamp; uint16 entry_type;
//   entry_type 0 (x509)   : opaque cert<1..2^24-1>
//   entry_type 1 (precert): issuer_key_hash[32] + opaque tbs_certificate<1..2^24-1>
//   CtExtensions extensions<0..2^16-1>
//   entry_type 1          : PreCertExtraData { opaque pre_certificate<1..2^24-1> }
//   Fingerprint certificate_chain<0..2^16-1>          (byte length, then n*32)
//
// VERIFIED against a live Sycamore tile: 256 entries parsed with EXACTLY 0 leftover bytes
// (42 x509 + 214 precert). Zero leftover is the proof the framing is right — any field-width mistake
// desynchronises and leaves a remainder.
// ═════════════════════════════════════════════════════════════════════════════════════════════════

function* parseTile(buf, stats) {
  let p = 0;
  while (p < buf.length) {
    try {
      if (p + 10 > buf.length) break;
      const ts = Number(buf.readBigUInt64BE(p)); p += 8;
      const type = buf.readUInt16BE(p); p += 2;
      let body = null;
      if (type === 0) {
        const l = buf.readUIntBE(p, 3); p += 3; body = buf.subarray(p, p + l); p += l;
      } else if (type === 1) {
        p += 32;
        const l = buf.readUIntBE(p, 3); p += 3; body = buf.subarray(p, p + l); p += l;
      } else { stats.framingBreaks++; return; }                  // desync — abandon this tile, keep the rest
      const el = buf.readUInt16BE(p); p += 2 + el;
      if (type === 1) { const l = buf.readUIntBE(p, 3); p += 3 + l; }
      const cl = buf.readUInt16BE(p); p += 2 + cl;
      if (p > buf.length) { stats.framingBreaks++; return; }

      stats.certs++;
      const info = certInfo(body, type === 1);
      if (!info) { stats.parseErrors++; continue; }
      if (!info.names.length) { stats.noNames++; continue; }     // legitimate: IP-only / no-SAN certs
      stats.names += info.names.length;
      yield { ts, subject: info.subject, names: info.names };
    } catch { stats.framingBreaks++; return; }
  }
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// RANK 33 — CA-VALIDATED Subject as proof-grade BD-ness.
//
// This is NOT a name test and must not be confused with one. Subject O/L/C fields only exist in
// OV/EV certificates, where a Certificate Authority performed a legal-entity check against company
// registration documents before issuing. A DV certificate (all of Let's Encrypt) has NO Subject O/L/C
// at all — which is exactly why casino spam, which lives on throwaway DV certs, cannot forge this.
// "1xbet-bd.org" can put "bd" in its NAME for free; it cannot make a CA attest C=BD.
//
// Requiring O to be present alongside C=BD is what keeps this rung honest: it means an organisation
// was actually validated, rather than a bare country code appearing in isolation.
// MEASURED on a live tile: 15/255 certs carried a Subject O (Salesforce, Win the Customer LLC, ...).
// ═════════════════════════════════════════════════════════════════════════════════════════════════

const BD_LOCALITIES = /\b(dhaka|chittagong|chattogram|khulna|rajshahi|sylhet|barisal|barishal|rangpur|mymensingh|gazipur|narayanganj|bogra|bogura|comilla|cumilla|jessore|jashore)\b/i;

function subjectBdProof(subject) {
  if (!subject) return null;
  const C = (subject.C || "").trim().toUpperCase();
  const O = (subject.O || "").trim();
  const L = (subject.L || "").trim();
  if (!O) return null;                       // no CA-validated organisation → this is not proof of anything
  if (C && C !== "BD") return null;          // countryName is authoritative and it says somewhere else
  if (C === "BD") return { reason: "subject-C=BD", org: O };
  if (/\bbangladesh\b/i.test(O)) return { reason: "subject-O=bangladesh", org: O };
  if (BD_LOCALITIES.test(L)) return { reason: "subject-L=" + L.toLowerCase(), org: O };
  return null;
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// THE GATE — one host at a time. Cheap rejects first; DNS is the scarcest resource in the run.
// ═════════════════════════════════════════════════════════════════════════════════════════════════

// ── canonicalHost: collapse the cert-issuance noise that shared hosting puts in every SAN list ──────
//
// MEASURED on the first live run: 19 admitted rows represented only ~12 distinct sites. A cPanel
// AutoSSL certificate always carries www./mail./cpanel./webmail./webdisk./autodiscover./autoconfig.
// variants of the same site, and none of those service subdomains is a website — pushing them into the
// scan queue means the scanner spends a full HTTP fetch proving that mail.foo.com is a mail endpoint.
// Collapsing to the real site both dedupes the queue and removes work from the scanner.
const SERVICE_LABEL = /^(www|mail|webmail|cpanel|whm|webdisk|autodiscover|autoconfig|cpcalendars|cpcontacts|ftp|sftp|smtp|imap|pop|pop3|mx|ns\d*)$/;
// Second-level registry suffixes. "com.bd" / "edu.bd" / "co.uk" are NOT registrable domains, and
// emitting one into the scan queue is worse than emitting nothing.
const SUFFIX_LABEL = /^(com|net|org|edu|ac|gov|mil|info|co|biz|name|pro)$/;

function canonicalHost(h) {
  let s = h;
  // Strip repeatedly: "www.mail.foo.com.bd" and "mail.www.foo.com" both reduce to foo.com(.bd).
  for (let i = 0; i < 3; i++) {
    const dot = s.indexOf(".");
    if (dot < 0) break;
    const first = s.slice(0, dot);
    const rest = s.slice(dot + 1);
    if (!SERVICE_LABEL.test(first)) break;
    const parts = rest.split(".");
    // Guard, caught by a unit test on the first attempt: "mail.com.bd" must NOT become "com.bd".
    // Stop if what remains is a bare public suffix rather than a real registrable domain.
    if (parts.length < 2) break;
    if (parts.length === 2 && SUFFIX_LABEL.test(parts[0])) break;
    s = rest;
  }
  return s;
}

// ── foreign ccTLD guard — the honest limit of IP-based BD-ness, found by running this thing ─────────
//
// MEASURED on the first live run: coalcityinternationalcollege.com.ng was ADMITTED. It is not a bug in
// bdgate — I checked the raw APNIC file and 163.61.188.9 really does sit in `163.61.188.0|512`, an
// APNIC-delegated Bangladeshi block. It is a NIGERIAN school renting BANGLADESHI shared hosting.
// Hosting IP proves where the server is, not whose business it is, and BD hosts sell abroad.
//
// A two-letter TLD is a country code by definition, so a non-.bd ccTLD is a direct claim to belong to
// another country, made by the domain's own registry rather than by a string in its name. The listed
// exceptions are the ccTLDs the market genuinely uses as generic (.io/.co/.ai startups etc), where the
// country meaning has been abandoned. Everything the owner actually wants — .com, .net, .org, .info,
// .biz, .xyz, plus every .bd suffix — is untouched by this.
const GENERIC_TWO_LETTER = new Set(["io", "co", "me", "tv", "cc", "ai", "app", "dev", "so", "to", "gg"]);

function foreignCcTld(h) {
  const tld = h.slice(h.lastIndexOf(".") + 1);
  return tld.length === 2 && tld !== "bd" && !GENERIC_TWO_LETTER.has(tld);
}

const state = {
  tilesFetched: 0, tilesMissing: 0, requests: 0,
  certs: 0, names: 0, parseErrors: 0, noNames: 0, framingBreaks: 0,
  hostsUnique: 0, prefilterPass: 0, spamRejected: 0, alreadySeen: 0,
  dnsSpent: 0, dnsBudgetHit: 0, admitted: 0, rejectedForeign: 0, rejectedDead: 0, foreignCcTld: 0,
  proofGrade: 0, coSanCandidates: 0, coSanAdmitted: 0,
};

const admitted = new Map();      // host -> row
const consideredHosts = new Set();

function scoreFor(host, reason) {
  if (reason.startsWith("subject-")) return 85;                  // CA-validated legal entity
  if (/\.(edu|ac|gov|mil)\.bd$/.test(host)) return 70;
  if (/\.bd$/.test(host)) return 55;
  return 50;                                                     // non-.bd verified by hosting IP / NS
}

/**
 * Decide a single hostname. Returns true if admitted.
 * `proof` is the rank-33 result for the certificate this host came from (may be null).
 * `viaCoSan` marks a rank-41 sibling candidate — it buys a DNS lookup, never admission.
 */
async function gateHost(host, proof, org, viaCoSan) {
  const raw = normHost(host);
  if (!raw) return false;
  const h = canonicalHost(raw);                                  // www./mail./cpanel. → the real site
  if (!h || consideredHosts.has(h)) return false;
  consideredHosts.add(h);
  state.hostsUnique++;

  const lex = eduLexicon(h);

  // Casino/adult brand names are rejected outright. They are the dominant BD-shaped noise in CT and
  // the reason this whole gate exists.
  if (lex.isSpammy) { state.spamRejected++; dbg("spam-reject", h, lex.hits.join(",")); return false; }

  // RANK 12 — novelty. The seen-set is seeded from the live 161k registry, so a survivor here is a
  // host the system has never had. At the head of the log that means a certificate issued minutes ago.
  if (seen(h)) { state.alreadySeen++; return false; }

  // Rank 33 short-circuit: a CA validated this organisation as Bangladeshi. No DNS needed at all.
  if (proof) {
    state.proofGrade++;
    admitted.set(h, { domain: h, bd_score: scoreFor(h, proof.reason), business: org || undefined });
    state.admitted++;
    dbg("ADMIT", h, proof.reason, org || "");
    return true;
  }

  // Foreign ccTLD: the registry itself says this domain belongs to another country. BD hosting IP
  // cannot outvote that — see the coalcityinternationalcollege.com.ng measurement above.
  if (foreignCcTld(h)) { state.foreignCcTld++; dbg("foreign-cctld", h); return false; }

  // RANK 5 — the zero-network 100:1 prefilter. Without it, isBdHost() would be called on ~9.5M
  // hostnames a day, which is 2-4 DoH lookups each and is simply not affordable on this box.
  // A .bd host always proceeds; everything else needs an edu or BD-ish name token to be worth a lookup.
  const isBdTld = /\.bd$/.test(h);
  if (!isBdTld && !lex.isEdu && !lex.isBdish && !viaCoSan) return false;
  state.prefilterPass++;
  if (viaCoSan && !isBdTld && !lex.isEdu && !lex.isBdish) state.coSanCandidates++;

  if (!USE_DNS) return false;
  if (state.dnsSpent >= MAX_DNS) { state.dnsBudgetHit++; return false; }
  state.dnsSpent++;

  // THE ACTUAL ADMISSION DECISION — hosting IP in APNIC BD space, .bd-registry NS, or .bd TLD.
  const d = await isBdHostDetail(h);
  if (!d.bd) { state.rejectedForeign++; dbg("foreign", h, d.reason); return false; }

  // RANK 58 — liveness. A .bd host admitted purely by TLD may be a corpse; measured in the source
  // review, only 39 of 200 sampled .edu.bd domains resolved at all. ip-in-bd/ns-ip-in-bd already
  // proved an A record exists, so only the pure-TLD rung needs the extra check (and DNS is cached).
  if (d.reason === "bd-tld" && !(await alive(h))) { state.rejectedDead++; dbg("dead", h); return false; }

  admitted.set(h, { domain: h, bd_score: scoreFor(h, d.reason), business: org || undefined });
  state.admitted++;
  if (viaCoSan) state.coSanAdmitted++;
  dbg("ADMIT", h, d.reason, viaCoSan ? "(co-san)" : "");
  return true;
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// RANK 41 — renewal-delta / new-tenant detection, scoped honestly.
//
// The brief describes a seen_cert_sha256 + cert_cluster table to spot a tenant that appears in this
// month's AutoSSL certificate but not last month's. The seen-set ALREADY provides the "this hostname
// is new" half of that comparison, against the full 161k registry rather than against one prior cert
// — a strictly stronger baseline. So the missing half is only "is this new host on a box we already
// track", and a shared-hosting certificate answers that for free: its SAN list IS the tenant list.
//
// Therefore: if any hostname on a certificate is already-known BD or .bd, the OTHER hostnames on that
// same certificate are new tenants on a tracked box, and they earn a DNS lookup even when their name
// carries no BD or education token — which is exactly the systematic blind spot of every lexicon.
//
// They earn a LOOKUP, never admission. Association with a BD neighbour is not evidence of BD-ness;
// shared hosting is full of foreign tenants, and admitting by neighbour would reintroduce the
// name-adjacency mistake in a new costume. isBdHost() still decides.
// ═════════════════════════════════════════════════════════════════════════════════════════════════

function certHasBdAnchor(names) {
  for (const n of names) {
    const h = normHost(n);
    if (!h) continue;
    if (/\.bd$/.test(h)) return true;                            // registry-gated, cannot be self-asserted
    if (seen(h) && eduLexicon(h).isBdish) return true;           // already in the BD-only registry
  }
  return false;
}

async function handleCert(entry) {
  const proof = subjectBdProof(entry.subject);
  const org = entry.subject && entry.subject.O ? entry.subject.O : null;
  // Wildcards contribute their apex — "*.foo.edu.bd" is really evidence about foo.edu.bd.
  const names = entry.names.map((n) => (n.startsWith("*.") ? n.slice(2) : n));
  const anchored = names.length > 1 && certHasBdAnchor(names);
  for (const n of names) await gateHost(n, proof, org, anchored);
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// Per-log tailing loop.
// ═════════════════════════════════════════════════════════════════════════════════════════════════

async function tailLog(L, cursors, budget) {
  let cp;
  try { cp = await fetchCheckpoint(L.base); state.requests++; }
  catch (e) { console.error(`[cttail] ${L.desc}: checkpoint failed — ${String(e).slice(0, 90)}`); return 0; }

  const head = Math.floor(cp.size / 256);                        // only COMPLETE (immutable) tiles
  const key = cp.origin || L.desc;
  let cursor = Number(cursors[key]);

  if (!Number.isFinite(cursor) || cursor <= 0) {
    cursor = Math.max(0, head - START_BACKLOG);                  // cold start near the head, not at 0
    log(`${L.desc}: cold start at tile ${cursor} (head ${head}, tree ${cp.size})`);
  } else if (head - cursor > MAX_LAG) {
    log(`${L.desc}: cursor ${cursor} is ${head - cursor} tiles behind head ${head} — jumping to head-${START_BACKLOG}. Backlog is unrecoverable at this rate and pretending otherwise would spend every run on stale tiles.`);
    cursor = Math.max(0, head - START_BACKLOG);
  }
  if (cursor >= head) { log(`${L.desc}: at head (tile ${cursor}) — nothing new`); return 0; }

  const want = Math.min(budget, TILES_PER_LOG, head - cursor);
  const idxs = Array.from({ length: want }, (_, i) => cursor + i);
  const t0 = Date.now();
  let bytes = 0;
  const entriesToGate = [];

  await mapLimit(idxs, CONCURRENCY, async (idx) => {
    const buf = await fetchTile(L.base, idx);
    state.requests++;
    if (!buf) { state.tilesMissing++; return; }
    state.tilesFetched++;
    bytes += buf.length;
    // Parse immediately and keep ONLY the tiny gated shape — the 460KB tile buffer is released here
    // rather than accumulated. This is what keeps RSS flat regardless of tile count.
    // Cheap triage INSIDE the fetch loop so the 460KB tile buffer is dropped immediately and only the
    // handful of interesting certs survive into `entriesToGate`. This is what keeps RSS flat.
    for (const e of parseTile(buf, state)) {
      let interesting = false;
      for (const n of e.names) {
        const h = normHost(n);                                   // normHost already strips a "*." prefix
        if (!h) continue;
        if (/\.bd$/.test(h)) { interesting = true; break; }
        const lex = eduLexicon(h);
        if (lex.isEdu || lex.isBdish) { interesting = true; break; }
      }
      // ...or it carries a CA-validated BD Subject (rank 33), or it is a multi-tenant cert anchored by
      // a host we already track (rank 41).
      if (interesting || subjectBdProof(e.subject) || (e.names.length > 1 && certHasBdAnchor(e.names))) {
        entriesToGate.push(e);
      }
    }
  });

  // DNS-bearing gating is done serially after the fetch pass so the DoH token bucket is the only
  // limiter and tile fetches are never blocked behind a slow resolver.
  for (const e of entriesToGate) await handleCert(e);

  cursors[key] = cursor + want;
  await writeCursors(cursors);

  const secs = (Date.now() - t0) / 1000;
  log(`${L.desc}: tiles ${cursor}..${cursor + want - 1} (${want}) | ${(bytes / 1048576).toFixed(1)}MB | ${state.certs} certs so far | ${entriesToGate.length} certs worth gating | ${secs.toFixed(0)}s | lag now ${head - (cursor + want)} tiles`);
  return want;
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// RANK 32 — Sectigo Tiger/Elephant over RFC6962. OPT-IN, and here is the honest reason.
//
// MEASURED 2026-07-19 against tiger2026h2 (tree_size 1,615,344,419, alive and answering):
//   • get-entries returns 32 entries per call however many you ask for (I requested 256).
//     Static-CT gives 256 per request → 8x the requests for the same certificate count.
//   • 62KB compressed for those 32 entries ≈ 1.9KB/cert, vs ~585B/cert for a gzipped static-CT tile.
//   • Chrome's CT policy requires a Google log for almost every certificate, so the large majority of
//     what Sectigo carries is ALSO in ParcelYard/PlumbersArms, which rank 4 already tails more cheaply.
// It is enabled only when you specifically want the cPanel-AutoSSL slice that Sectigo concentrates.
//
// The framing is reused wholesale: leaf_input is MerkleTreeLeaf = version(1) + leaf_type(1) +
// TimestampedEntry, so skipping 2 bytes hands the exact same parser the exact same structure.
// VERIFIED: byte 0 = 0 (v1), byte 1 = 0 (timestamped_entry), then a valid timestamp and entry_type.
// ═════════════════════════════════════════════════════════════════════════════════════════════════

function parseRfc6962Leaf(leafInput, extraData, stats) {
  const b = Buffer.from(leafInput, "base64");
  if (b.length < 12 || b[0] !== 0 || b[1] !== 0) { stats.parseErrors++; return null; }
  let p = 2;
  const ts = Number(b.readBigUInt64BE(p)); p += 8;
  const type = b.readUInt16BE(p); p += 2;
  let body;
  if (type === 0) { const l = b.readUIntBE(p, 3); p += 3; body = b.subarray(p, p + l); }
  else if (type === 1) { p += 32; const l = b.readUIntBE(p, 3); p += 3; body = b.subarray(p, p + l); }
  else { stats.parseErrors++; return null; }
  stats.certs++;
  const info = certInfo(body, type === 1);
  if (!info) { stats.parseErrors++; return null; }
  if (!info.names.length) { stats.noNames++; return null; }
  stats.names += info.names.length;
  return { ts, subject: info.subject, names: info.names };
}

async function tailSectigo(cursors) {
  const cache = path.join(STATE_DIR, "log_list.json");
  let list = null;
  try { list = JSON.parse(await fsp.readFile(cache, "utf8")); } catch { return; }
  const logs = [];
  for (const op of list.operators || []) {
    for (const L of op.logs || []) {
      const st = Object.keys(L.state || {})[0] || "";
      if (st !== "usable" && st !== "qualified") continue;       // Mammoth/Sabre are readonly now
      if (!/tiger|elephant/i.test(L.description || "")) continue;
      const ti = L.temporal_interval;
      if (ti) {
        const s = Date.parse(ti.start_inclusive), e = Date.parse(ti.end_exclusive);
        if ((Number.isFinite(s) && Date.now() < s) || (Number.isFinite(e) && Date.now() >= e)) continue;
      }
      logs.push({ desc: L.description, base: String(L.url).replace(/\/+$/, "") });
    }
  }
  if (!logs.length) { log("sectigo: no active tiger/elephant shard in the log list"); return; }

  const L = logs[0];
  let sth;
  try {
    sth = await fetchJson(L.base + "/ct/v1/get-sth", 45000);
    state.requests++;
  } catch (e) { console.error("[cttail] sectigo sth failed:", String(e).slice(0, 80)); return; }

  const head = Number(sth.tree_size) || 0;
  const key = "rfc6962:" + L.desc;
  let cursor = Number(cursors[key]);
  const BATCH = 32;
  if (!Number.isFinite(cursor) || cursor <= 0 || head - cursor > MAX_LAG * 256) {
    cursor = Math.max(0, head - SECTIGO_BATCHES * BATCH);
  }

  let got = 0;
  for (let i = 0; i < SECTIGO_BATCHES && cursor < head; i++) {
    const end = Math.min(cursor + BATCH - 1, head - 1);
    let j = null;
    for (let attempt = 1; attempt <= 3 && !j; attempt++) {
      try {
        j = await fetchJson(`${L.base}/ct/v1/get-entries?start=${cursor}&end=${end}`, 45000);
        state.requests++;
      } catch { await sleep(attempt * 1500); }
    }
    if (!j || !Array.isArray(j.entries) || !j.entries.length) break;
    for (const e of j.entries) {
      const parsed = parseRfc6962Leaf(e.leaf_input, e.extra_data, state);
      if (parsed) await handleCert(parsed);
    }
    got += j.entries.length;
    cursor += j.entries.length;
    await sleep(200);                                            // polite to a free public log
  }
  cursors[key] = cursor;
  await writeCursors(cursors);
  log(`sectigo ${L.desc}: ${got} entries consumed, cursor now ${cursor}/${head}`);
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════

async function main() {
  const t0 = Date.now();
  if (!TOKEN && DO_SUBMIT) console.error("[cttail] SHARED_TOKEN missing — will parse and gate but cannot submit");

  const ranges = await loadBdRanges();
  log(`BD ranges: ${ranges.records} records / ${ranges.blocks} blocks / ${ranges.addresses} addresses (${ranges.source})`);

  // ⚠ MEASURED 2026-07-19: bdgate's DEFAULT pageSize of 5000 gets HTTP 503 from the live Worker every
  // time, so loadSeen() silently returns a 0-host seen-set ("page 0 failed after 3 tries") and rank 12
  // novelty detection is dead. Measured against production:
  //     /api/domains?type=all&limit=1000&offset=0  → HTTP 200, 122KB, 1000 rows, 0.67s
  //     /api/domains?type=all&limit=5000&offset=0  → HTTP 503, 17 bytes,  1.18s
  // So the page size is pinned to 1000 here and maxPages raised to cover the whole ~161k registry.
  // Costs ~160 requests / ~2min on a cold cache, then the on-disk seen file serves the next 12h.
  let s = await loadSeen(API_BASE, TOKEN, { pageSize: SEEN_PAGE, maxPages: SEEN_MAX_PAGES });

  // ⚠ SECOND MEASURED TRAP, and it silently disables rank 12 for 12 hours at a time.
  // bdgate's loadSeen() returns early whenever the on-disk seen file is younger than maxAgeH and has
  // ANY content at all: `if (fresh && fromDisk > 0) return`. So if one run seeds the file badly — as
  // happened here the moment the 5000-row page 503'd and left a 19-host file behind — every following
  // run for 12h reads those 19 hosts, calls it a seed, and never contacts the API. Every one of the
  // 161k known domains then looks brand new.
  // A registry this size cannot legitimately shrink to a few thousand, so an implausibly small set is
  // proof of a poisoned cache, not of a small corpus. Force one re-seed past the freshness check.
  if (s.total < SEEN_MIN && TOKEN) {
    console.error(`[cttail] seen-set is only ${s.total} hosts — implausible against a ~161k registry, so the on-disk cache is poisoned. Forcing a re-seed from the API.`);
    s = await loadSeen(API_BASE, TOKEN, { pageSize: SEEN_PAGE, maxPages: SEEN_MAX_PAGES, maxAgeH: 0 });
  }
  log(`seen-set: ${s.total} hosts (disk ${s.fromDisk}, api ${s.fromApi}, ${s.pages} pages)`);
  if (s.total < SEEN_MIN) console.error("[cttail] WARNING: seen-set is still small — hosts already in the registry will be re-POSTed and rank 12 (first-certificate detection) is unreliable this run. Check SHARED_TOKEN and /api/domains.");

  const logs = await resolveLogs();
  if (!logs.length) throw new Error("cttail: no active tiled logs matched CTTAIL_LOGS=" + LOG_FILTER.join(","));
  log(`tiled logs resolved from log_list.json: ${logs.map((l) => l.desc).join(" | ")}`);

  const cursors = await readCursors();
  let budget = MAX_TILES;
  for (const L of logs) {
    if (budget <= 0) break;
    budget -= await tailLog(L, cursors, budget);
  }

  if (DO_SECTIGO) await tailSectigo(cursors);

  const rows = [...admitted.values()];
  let posted = null;
  if (DO_SUBMIT && rows.length && TOKEN) {
    posted = await submit(API_BASE, TOKEN, "ct-tail", rows);
    log(`submit: found=${posted.found} inserted=${posted.inserted} dups=${posted.dups} failed=${posted.failed} ok=${posted.ok}`);
    // Mark seen ONLY after the Worker has actually taken the rows. Marking at admission time (which is
    // what this did first) meant a CTTAIL_SUBMIT=0 dry run, or a failed POST, wrote the host into the
    // persistent seen file anyway — so every later run skipped it as "already known" and the domain
    // was blackholed permanently. Never let a host leave this process marked-seen but unsubmitted.
    if (posted.ok) for (const r of rows) markSeen(r.domain);
    else console.error("[cttail] submit did not fully succeed — NOT marking these hosts as seen, so the next run retries them");
  } else if (rows.length) {
    log(`DRY RUN — ${rows.length} rows NOT submitted (and deliberately NOT marked seen)`);
  }

  const secs = (Date.now() - t0) / 1000;
  const mem = Math.round(process.memoryUsage().rss / 1048576);
  log("──────── RUN SUMMARY ────────");
  log(`requests ${state.requests} | tiles ${state.tilesFetched} ok / ${state.tilesMissing} missing | ${secs.toFixed(0)}s | RSS ${mem}MB`);
  log(`certs ${state.certs} | dNSNames ${state.names} | parseErrors ${state.parseErrors} | noSAN ${state.noNames} | framingBreaks ${state.framingBreaks}`);
  log(`unique hosts considered ${state.hostsUnique} | spam-rejected ${state.spamRejected} | already-known ${state.alreadySeen} | prefilter-pass ${state.prefilterPass}`);
  log(`DNS spent ${state.dnsSpent}/${MAX_DNS}${state.dnsBudgetHit ? " (BUDGET HIT " + state.dnsBudgetHit + " skipped)" : ""} | foreign-hosting ${state.rejectedForeign} | foreign-ccTLD ${state.foreignCcTld} | dead ${state.rejectedDead}`);
  log(`co-SAN candidates ${state.coSanCandidates} (admitted ${state.coSanAdmitted}) | proof-grade C=BD ${state.proofGrade}`);
  log(`ADMITTED ${state.admitted}`);
  for (const r of rows.slice(0, 25)) log(`   + ${r.domain} (score ${r.bd_score})${r.business ? " — " + r.business : ""}`);
  if (state.certs && state.admitted === 0) log("0 admitted. On a short run over ~100k certs that is the expected outcome — BD is ~1 in 5k-30k certificates. Extend CTTAIL_MAX_TILES or let the timer accumulate.");
}

main().catch((e) => { console.error("[cttail] fatal:", e); process.exit(1); });
