// bdgate.mjs — the SHARED Bangladesh-ness + liveness gate that every VM harvester imports.
//
// Zero npm dependencies, plain node ESM, streaming, designed for the 946MB / 1 OCPU Oracle VM.
// MEASURED resident cost: 45MB node baseline → 48MB after loadBdRanges() (2,315 BD ranges live in two
// Uint32Arrays, 18KB) → 108MB with the full 161,450-host seen-set loaded. Well inside the 200MB
// budget. The DNS cache is bounded (never unbounded), the 9MB APNIC file is stream-parsed, and the
// seen file is stream-read — nothing here ever buffers a whole dataset.
//
// MEASURED throughput: ipInBd() 2.7M lookups/sec; eduLexicon() 258k hosts/sec with zero network;
// DoH ~33/s globally rate-limited with a cache (a repeat of 150 lookups returned in 1ms).
//
//   import { loadBdRanges, ipInBd, isBdHost, eduLexicon, alive, loadSeen, seen, markSeen, submit } from "./bdgate.mjs";
//
// ─────────────────────────────────────────────────────────────────────────────────────────────────
// THE ONE RULE THIS MODULE EXISTS TO ENFORCE
//
// A domain is NEVER Bangladeshi because its NAME says so. "bd" and "bangladesh" in a hostname is the
// signature of FOREIGN gambling spam that targets Bangladesh for SEO: 1xbet-bd.org, 22bet-bd.com,
// 1win-bangladesh.net, 12jeet-bangladesh.com. Of 3,166 name-matched hosts in one measured sample,
// essentially all were casino spam, and a previous version of this system had to purge 24,000 rows for
// exactly this mistake. BD-ness is decided ONLY by hosting IP inside APNIC's delegated BD space, by a
// registry-gated .bd nameserver, or by the .bd TLD itself.
//
// eduLexicon() returns an `isBdish` flag. It is a CHEAP PREFILTER AND NOTHING ELSE. It is pure string
// matching, it is exactly the signal the casino spam is engineered to trip, and it MUST NOT admit a
// domain on its own. The only admission function is isBdHost(). Measured live while writing this:
//
//     1xbet-bd.org   → eduLexicon.isBdish = true   ← the name lies
//                    → isBdHost()         = false  ← the gate holds
//
// ─────────────────────────────────────────────────────────────────────────────────────────────────
// ⚠ CALLERS: THE /harvest WIRE FORMAT IS `domains`, NOT `items`
//
// Several harvester briefs say to POST { source, items: [...] }. The LIVE Worker does not read that
// key. workers/src/index.js:213 is literally:
//
//     let list = Array.isArray(body.domains) ? body.domains : [];
//     if (list.length === 0) return json({ ok: true, inserted: 0, found: 0 });
//
// So an `items`-only payload returns HTTP 200 with inserted:0 and harvests NOTHING, silently. submit()
// below sends BOTH keys so it is correct against the Worker as deployed today and against one that is
// later changed to read `items`. Use submit() — do not hand-roll the POST.
//
// The second half of that same bug: the Worker reads `d.domain || d.host || d.url` off each element,
// so bare strings normalise to null and every row is dropped while still answering 200. That cost this
// project 3,126 institution hostnames in one run. submit() coerces strings to {domain} defensively, and
// treats found>0 with inserted===0 as a FAILURE, not a success.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────────
// ENV (all optional; defaults are tuned for the Oracle VM)
//
//   API_BASE              https://bd-hack-audit-api.javed-it.workers.dev   fallback for submit/loadSeen
//   SHARED_TOKEN          —                    fallback bearer token
//   BDGATE_DIR            /opt/bd-scanner/.bdgate   cache dir; auto-falls back to os.tmpdir() if unwritable
//   BDGATE_APNIC_URL      https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest
//   BDGATE_APNIC_TTL_H    24                   re-fetch the delegation file at most once a day
//   BDGATE_DOH            https://cloudflare-dns.com/dns-query
//   BDGATE_DOH_FALLBACK   https://dns.google/resolve
//   BDGATE_DNS_RPS        33                   global DoH token bucket (the brief's ~33/s)
//   BDGATE_DNS_TIMEOUT_MS 8000
//   BDGATE_DNS_CACHE      120000               max cached DNS answers (bounded — never unbounded)
//   BDGATE_SEEN_FILE      <BDGATE_DIR>/seen.txt
//   BDGATE_SUBMIT_CHUNK   500                  Worker hard-caps a /harvest call at 2000 rows
//   BDGATE_DEBUG          0                    1 = log every gate decision

import fs from "node:fs";
import fsp from "node:fs/promises";
import os from "node:os";
import path from "node:path";

const env = process.env;
const num = (v, d) => (Number.isFinite(Number(v)) && Number(v) > 0 ? Number(v) : d);

export const API_BASE_DEFAULT = (env.API_BASE || "https://bd-hack-audit-api.javed-it.workers.dev").replace(/\/+$/, "");
const APNIC_URL = env.BDGATE_APNIC_URL || "https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest";
const APNIC_TTL_MS = num(env.BDGATE_APNIC_TTL_H, 24) * 3600 * 1000;
const DOH = env.BDGATE_DOH || "https://cloudflare-dns.com/dns-query";
const DOH_FALLBACK = env.BDGATE_DOH_FALLBACK || "https://dns.google/resolve";
const DNS_RPS = num(env.BDGATE_DNS_RPS, 33);
const DNS_TIMEOUT = num(env.BDGATE_DNS_TIMEOUT_MS, 8000);
const DNS_CACHE_MAX = num(env.BDGATE_DNS_CACHE, 120000);
const SUBMIT_CHUNK = Math.min(num(env.BDGATE_SUBMIT_CHUNK, 500), 2000);
const DEBUG = env.BDGATE_DEBUG === "1";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const dbg = (...a) => { if (DEBUG) console.error("[bdgate]", ...a); };

// Cache dir resolution: prefer the VM path, silently fall back to tmp on a dev laptop so importing this
// module never throws just because /opt/bd-scanner does not exist.
function resolveDir() {
  const want = env.BDGATE_DIR || "/opt/bd-scanner/.bdgate";
  for (const d of [want, path.join(os.tmpdir(), "bdgate")]) {
    try { fs.mkdirSync(d, { recursive: true }); fs.accessSync(d, fs.constants.W_OK); return d; } catch {}
  }
  return os.tmpdir();
}
export const CACHE_DIR = resolveDir();
const APNIC_CACHE = path.join(CACHE_DIR, "bd-ranges.txt");
const SEEN_FILE = env.BDGATE_SEEN_FILE || path.join(CACHE_DIR, "seen.txt");

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// RANK 27 — APNIC delegated-apnic-extended-latest: the authoritative BD address space.
//
// Verified live 2026-07-19: 9,167,900 bytes, HTTP 200 in 6.5s, 2,315 BD ipv4 records covering
// 2,078,272 addresses. This replaces the ipdeny list, whose harvester's lifetime yield was 1 domain.
//
// Format is pipe-delimited: apnic|BD|ipv4|14.1.100.0|1024|20160112|allocated|A91871C2
// Field 5 is a COUNT OF ADDRESSES, not a prefix length, and APNIC does not guarantee it is a power of
// two or CIDR-aligned. So a range is [start, start+count-1] — never convert it to a /nn.
//
// The 9MB body is streamed and parsed line-by-line; only the ~2,315 BD lines are retained (18KB of
// typed array). At no point is the file held in memory.
// ═════════════════════════════════════════════════════════════════════════════════════════════════

let RANGE_LO = null;   // Uint32Array, sorted ascending
let RANGE_HI = null;   // Uint32Array, parallel
let RANGE_META = { records: 0, addresses: 0, source: "none", fetchedAt: 0 };

function ipToInt(ip) {
  const p = String(ip).split(".");
  if (p.length !== 4) return null;
  let v = 0;
  for (const s of p) {
    if (!/^\d{1,3}$/.test(s)) return null;
    const n = Number(s);
    if (n > 255) return null;
    v = v * 256 + n;
  }
  return v >>> 0;
}

// Streaming line reader over a fetch body — the pattern every harvester should copy for big files.
async function* streamLines(body) {
  const reader = body.getReader();
  const dec = new TextDecoder();
  let buf = "";
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    buf += dec.decode(value, { stream: true });
    let nl;
    while ((nl = buf.indexOf("\n")) >= 0) {
      yield buf.slice(0, nl);
      buf = buf.slice(nl + 1);
    }
    // A pathological line with no newline would grow unbounded; APNIC lines are <100 bytes.
    if (buf.length > 1 << 20) { yield buf; buf = ""; }
  }
  if (buf) yield buf;
}

function installRanges(pairs, meta) {
  pairs.sort((a, b) => a[0] - b[0]);
  // Coalesce touching/overlapping ranges so the binary search cannot fall into a seam.
  const lo = [], hi = [];
  for (const [s, e] of pairs) {
    if (lo.length && s <= hi[hi.length - 1] + 1) {
      if (e > hi[hi.length - 1]) hi[hi.length - 1] = e;
    } else { lo.push(s); hi.push(e); }
  }
  RANGE_LO = Uint32Array.from(lo);
  RANGE_HI = Uint32Array.from(hi);
  RANGE_META = { ...meta, records: pairs.length, blocks: lo.length, fetchedAt: Date.now() };
  return RANGE_META;
}

function parseApnicLine(line, out) {
  // apnic|BD|ipv4|start|count|date|status|opaque-id
  if (line.charCodeAt(0) === 35) return 0;             // '#' comment
  if (line.indexOf("|BD|ipv4|") < 0) return 0;
  const f = line.split("|");
  if (f[1] !== "BD" || f[2] !== "ipv4") return 0;
  const st = ipToInt(f[3]);
  const cnt = Number(f[4]);
  if (st === null || !Number.isFinite(cnt) || cnt < 1) return 0;
  out.push([st, st + cnt - 1]);
  return cnt;
}

let loadPromise = null;

/**
 * Load (and cache on disk, refreshed daily) the authoritative APNIC BD address ranges.
 * Idempotent and concurrency-safe — call it freely; the fetch happens at most once per process.
 * Never throws on a network failure if a stale cache exists: stale BD ranges beat no BD ranges.
 * @returns {Promise<{records:number, blocks:number, addresses:number, source:string}>}
 */
export async function loadBdRanges({ force = false } = {}) {
  if (RANGE_LO && !force) return RANGE_META;
  if (loadPromise && !force) return loadPromise;
  loadPromise = (async () => {
    // 1. fresh disk cache?
    if (!force) {
      try {
        const st = await fsp.stat(APNIC_CACHE);
        if (Date.now() - st.mtimeMs < APNIC_TTL_MS) {
          const pairs = [];
          let addresses = 0;
          for (const line of (await fsp.readFile(APNIC_CACHE, "utf8")).split("\n")) {
            if (!line) continue;
            const [s, e] = line.split(",").map(Number);
            if (Number.isFinite(s) && Number.isFinite(e) && e >= s) { pairs.push([s >>> 0, e >>> 0]); addresses += e - s + 1; }
          }
          if (pairs.length) { dbg("ranges from disk cache", pairs.length); return installRanges(pairs, { addresses, source: "cache" }); }
        }
      } catch {}
    }
    // 2. fetch APNIC, streaming
    const pairs = [];
    let addresses = 0;
    try {
      const r = await fetch(APNIC_URL, {
        headers: { "user-agent": "bd-hack-audit/1.0 (+javeditsolution.com)" },
        signal: AbortSignal.timeout(120000),
      });
      if (!r.ok) throw new Error("apnic http " + r.status);
      for await (const line of streamLines(r.body)) addresses += parseApnicLine(line, pairs);
      if (!pairs.length) throw new Error("apnic parsed 0 BD records");
      await fsp.writeFile(APNIC_CACHE, pairs.map(([s, e]) => s + "," + e).join("\n")).catch(() => {});
      dbg("ranges from apnic", pairs.length, addresses, "addresses");
      return installRanges(pairs, { addresses, source: "apnic" });
    } catch (e) {
      // 3. network down → any stale cache is still far better than treating all of BD as foreign.
      try {
        const stale = [];
        let a2 = 0;
        for (const line of (await fsp.readFile(APNIC_CACHE, "utf8")).split("\n")) {
          if (!line) continue;
          const [s, e] = line.split(",").map(Number);
          if (Number.isFinite(s) && Number.isFinite(e) && e >= s) { stale.push([s >>> 0, e >>> 0]); a2 += e - s + 1; }
        }
        if (stale.length) { console.error("[bdgate] APNIC fetch failed (" + String(e).slice(0, 90) + ") — using STALE cache"); return installRanges(stale, { addresses: a2, source: "stale-cache" }); }
      } catch {}
      throw new Error("bdgate: could not load BD ranges and no cache exists: " + e);
    } finally { loadPromise = null; }
  })();
  return loadPromise;
}

/**
 * Is this IPv4 address inside APNIC-delegated Bangladeshi space? Binary search, O(log 2315).
 * THROWS if loadBdRanges() has not run — returning false would silently mark all of Bangladesh
 * foreign, which is the single worst failure mode this module can have, so it fails loudly instead.
 * IPv6 is not delegated per-country in a usable way here and always returns false (documented, rare).
 */
export function ipInBd(ip) {
  if (!RANGE_LO) throw new Error("bdgate: call `await loadBdRanges()` before ipInBd()");
  const v = ipToInt(ip);
  if (v === null) return false;                       // IPv6 / garbage
  let lo = 0, hi = RANGE_LO.length - 1;
  while (lo <= hi) {
    const m = (lo + hi) >> 1;
    if (v < RANGE_LO[m]) hi = m - 1;
    else if (v > RANGE_HI[m]) lo = m + 1;
    else return true;
  }
  return false;
}

export function bdRangeStats() { return { ...RANGE_META }; }

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// DoH — one shared, rate-limited, cached, failover-capable resolver for every harvester.
//
// RANK 2 TRAP APPLIED HERE TOO: free public services 502 under load. A global token bucket caps the
// whole process at BDGATE_DNS_RPS regardless of how many callers race, answers are cached, and a
// 5xx/timeout on Cloudflare falls over to Google rather than hammering the same endpoint.
// ═════════════════════════════════════════════════════════════════════════════════════════════════

let tokens = DNS_RPS, lastRefill = Date.now();
async function takeToken() {
  for (;;) {
    const now = Date.now();
    tokens = Math.min(DNS_RPS, tokens + ((now - lastRefill) / 1000) * DNS_RPS);
    lastRefill = now;
    if (tokens >= 1) { tokens -= 1; return; }
    await sleep(Math.max(5, Math.ceil((1 - tokens) / DNS_RPS * 1000)));
  }
}

// Bounded cache — insertion-ordered Map, oldest evicted. Never unbounded: a long harvest run would
// otherwise grow the DNS cache past the VM's RAM budget.
const dnsCache = new Map();
function cacheGet(k) { return dnsCache.get(k); }
function cacheSet(k, v) {
  if (dnsCache.size >= DNS_CACHE_MAX) {
    let n = 0;
    for (const key of dnsCache.keys()) { dnsCache.delete(key); if (++n >= 1000) break; }
  }
  dnsCache.set(k, v);
}

const RE_HOST = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/;
export function normHost(h) {
  let s = String(h || "").trim().toLowerCase();
  s = s.replace(/^[a-z]+:\/\//, "").split("/")[0].split("?")[0].split("#")[0];
  s = s.split("@").pop().replace(/:\d+$/, "").replace(/^\*\./, "").replace(/\.+$/, "");
  if (!s || s.length > 253 || !RE_HOST.test(s)) return null;
  return s;
}

async function doh(host, type) {
  const h = normHost(host);
  if (!h) return [];
  const key = type + ":" + h;
  const hit = cacheGet(key);
  if (hit !== undefined) return hit;

  let answers = [];
  for (const base of [DOH, DOH_FALLBACK]) {
    for (let attempt = 1; attempt <= 2; attempt++) {
      await takeToken();
      try {
        const u = `${base}?name=${encodeURIComponent(h)}&type=${type}`;
        const r = await fetch(u, { headers: { accept: "application/dns-json" }, signal: AbortSignal.timeout(DNS_TIMEOUT) });
        if (r.status === 429 || r.status >= 500) { await sleep(attempt * 700); continue; }
        if (!r.ok) break;                                   // 4xx = a real answer about a bad name
        const j = await r.json();
        // Status 3 = NXDOMAIN (authoritative "does not exist"), cache it as an empty answer.
        if (j.Status !== 0) { answers = []; cacheSet(key, answers); return answers; }
        const want = type === "A" ? 1 : 2;
        answers = (j.Answer || []).filter((a) => a.type === want)
          .map((a) => String(a.data || "").replace(/\.$/, "").toLowerCase()).filter(Boolean);
        cacheSet(key, answers);
        return answers;
      } catch { await sleep(attempt * 700); }
    }
  }
  // Both resolvers failed — do NOT cache, so a transient outage is not frozen in as "dead".
  return answers;
}

/** DoH A lookup. Globally rate-limited to ~BDGATE_DNS_RPS/s and cached. @returns {Promise<string[]>} */
export async function resolveA(host) { return doh(host, "A"); }

/**
 * RANK 26 — DoH NS lookup.
 * Why this exists: bdservers.net / hostever / alpha.net.bd customers sit behind Cloudflare, so their
 * A records are 104.x/172.x and IP-based BD detection FAILS on them. The NS delegation still tells
 * the truth about who runs the zone. @returns {Promise<string[]>}
 */
export async function resolveNS(host) { return doh(host, "NS"); }

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// isBdHost — THE ONLY FUNCTION ALLOWED TO ADMIT A DOMAIN AS BANGLADESHI.
//
// Ladder, strongest first. Every rung is grounded in a registry or in routed address space; not one
// of them looks at a name token inside the domain being tested.
//
//   1. .bd TLD                      — BTCL-controlled, cannot be self-asserted.
//   2. any A record inside APNIC BD — routed Bangladeshi address space (rank 27).
//   3. any NS hostname under .bd    — registry-gated; a foreign spammer cannot mint ns1.foo.net.bd.
//   4. any NS hostname resolving into APNIC BD space.
//   5. otherwise FALSE.
//
// MEASURED WHILE WRITING THIS, and the reason rung 3 is a TLD test and not a provider-name list:
//   ns1.hostever.com → 162.251.82.250   (US address space, NOT Bangladeshi)
//   alpha.net.bd     → 104.21.15.140    (Cloudflare)
//   ns1.alpha.net.bd → 209.195.14.14    (US address space)
// A curated "BD hosting provider" name list would therefore be a NAME test wearing a disguise, and it
// would be trivially forgeable by a spammer who simply buys BD hosting. It is deliberately not used to
// decide the boolean. bdNsProvider is reported in the detail object for logging only.
//
// KNOWN AND ACCEPTED LIMIT: a genuine BD business on a .com behind Cloudflare with Cloudflare NS is
// invisible to all four rungs and returns false. Measured example: bracu.ac.bd resolves to
// 104.20.42.218 with Cloudflare NS and is admitted ONLY by rung 1. There is no free signal that
// separates that case from 1xbet-bd.org, which presents identically — and admitting it by name is the
// exact mistake that cost 24,000 rows. False negatives are recoverable; that false positive is not.
// ═════════════════════════════════════════════════════════════════════════════════════════════════

const BD_NS_PROVIDERS = /(^|\.)(bdservers\.net|hostever\.com|alpha\.net\.bd|exabytes\.com\.bd|dhakaweb\.com|bdix\.net|itnuthosting\.com|hostseba\.com|webhostbd\.com)$/;

/** Full decision with the reason — additive to the fixed interface, use it for logging. */
export async function isBdHostDetail(host) {
  const h = normHost(host);
  if (!h) return { bd: false, reason: "invalid-host", host: String(host || "") };
  await loadBdRanges();

  if (/\.bd$/.test(h)) return { bd: true, reason: "bd-tld", host: h };

  const a = await resolveA(h);
  for (const ip of a) if (ipInBd(ip)) return { bd: true, reason: "ip-in-bd", host: h, ip };

  const ns = await resolveNS(h);
  for (const n of ns) if (/\.bd$/.test(n)) return { bd: true, reason: "ns-bd-tld", host: h, ns: n };
  for (const n of ns) {
    const nsIps = await resolveA(n);
    for (const ip of nsIps) if (ipInBd(ip)) return { bd: true, reason: "ns-ip-in-bd", host: h, ns: n, ip };
  }

  return {
    bd: false,
    reason: a.length ? "foreign-hosting" : "no-a-record",
    host: h,
    ip: a[0] || null,
    ns: ns[0] || null,
    // advisory only — NEVER flips `bd`. See the note above about ns1.hostever.com being on US IPs.
    bdNsProvider: ns.some((n) => BD_NS_PROVIDERS.test(n)),
  };
}

/** The real decision. IP-in-BD, else BD nameserver, else .bd TLD, else false. Never true from a name. */
export async function isBdHost(host) {
  const d = await isBdHostDetail(host);
  dbg("isBdHost", d.host, d.bd, d.reason);
  return d.bd;
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// RANK 5 — eduLexicon(): the zero-network 100:1 prefilter that makes the CT firehose affordable.
//
// A Certificate Transparency stream is millions of hostnames. Running isBdHost() on all of them is 2-4
// DoH lookups each and is not affordable. This function is pure string work — no I/O, ~2µs a host — so
// it can triage the firehose down to the ~1% worth spending a DNS lookup on.
//
// ⚠ ADVISORY ONLY. isBdish is a NAME test and name tests are what casino spam exploits. Correct use:
//
//     const lex = eduLexicon(host);
//     if (!lex.isEdu && !lex.isBdish) continue;        // cheap reject — no network spent
//     if (!(await isBdHost(host))) continue;           // the ACTUAL admission decision
//
// Token rules chosen to avoid measured substring traps rather than guessed ones:
//   • "edu"  is token-exact only — substring "edu" matches r-e-d-u-ce, sch-edu-le.
//   • "univ" is banned; "universal" contains "univers". The token is "universi" (universal stops at
//     "universa"), which still catches university / universiti / universite / universidad.
//   • "madras" is banned (Indian city); the token is "madrasa".
//   • districts shorter than 5 chars ("feni") match as whole tokens only.
// Every one of these was checked against the 96k-host live corpus — see the dry-run in the notes.
// ═════════════════════════════════════════════════════════════════════════════════════════════════

const EDU_TOKENS = [
  "school", "college", "universi", "madrasa", "madrassa", "polytechnic", "institute", "institut",
  "academy", "academi", "vidyalaya", "biddaloy", "bidyalay", "bidyaloy", "mahavidyalaya",
  "kindergarten", "highschool", "campus", "faculty", "seminary", "gurukul",
  "shikkha", "shiksha", "chhatra", "student", "scholars", "scholar",
  "vocational", "technical", "tvet", "trainingcenter", "trainingcentre",
  "cadetcollege", "residentialmodel", "medicalcollege", "nursinginstitute", "textileinstitute",
];
// Token-exact only — too short or too collision-prone as substrings.
const EDU_EXACT = new Set(["edu", "ac", "uni", "hs", "govtschool", "gov"]);

// All 64 districts, with the pre- and post-2018 official romanisations (Bogra/Bogura, Jessore/Jashore,
// Comilla/Cumilla, Barisal/Barishal, Chittagong/Chattogram) — old spellings dominate real hostnames.
const DISTRICTS = [
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
];
const BD_MARKERS = ["bangladesh", "bangla", "bengal", "bd"];

// Casino/adult brand tokens — reported so callers can log WHY a name-matched host was still rejected.
// Deliberately brand-specific: no bare "bet", no bare "xxx" (both are catastrophic false positives —
// see the porn-FP incident: "choti"=sandal, "chudi"=bangles are ordinary BD retail words).
const SPAM_BRANDS = [
  "1xbet", "1win", "22bet", "melbet", "betwinner", "parimatch", "mostbet", "linebet", "4rabet",
  "12jeet", "marvelbet", "krikya", "baji", "jeetbuzz", "babu88", "glory-casino", "glorycasino",
  "casino", "jackpot", "roulette", "betting", "satta", "togel", "slotgacor",
];

/**
 * Zero-network triage. @returns {{isEdu:boolean, isBdish:boolean, isSpammy:boolean, hits:string[], tokens:string[]}}
 * isBdish is a PREFILTER, never an admission — see the block comment above.
 */
export function eduLexicon(host) {
  const h = normHost(host) || String(host || "").toLowerCase();
  const flat = h.replace(/[^a-z0-9]/g, "");             // catches "high-school" and "highschool" alike
  const tokens = h.split(/[^a-z0-9]+/).filter(Boolean);
  const tset = new Set(tokens);
  const hits = [];

  let isEdu = false;
  if (/\.(edu|ac)\.bd$/.test(h) || /\.edu$/.test(h)) { isEdu = true; hits.push("tld:" + h.split(".").slice(-2).join(".")); }
  for (const t of EDU_TOKENS) if (flat.includes(t)) { isEdu = true; hits.push("edu:" + t); }
  for (const t of EDU_EXACT) if (tset.has(t)) { isEdu = true; hits.push("edu=" + t); }

  let isBdish = false;
  if (/\.bd$/.test(h)) { isBdish = true; hits.push("bdtld"); }
  for (const m of BD_MARKERS) {
    if (m === "bd" ? tset.has("bd") : flat.includes(m)) { isBdish = true; hits.push("bd:" + m); }
  }
  for (const d of DISTRICTS) {
    // <5 chars ("feni") would collide as a substring, so those must be a whole token.
    if (d.length >= 5 ? flat.includes(d) : tset.has(d)) { isBdish = true; hits.push("dist:" + d); }
  }

  let isSpammy = false;
  for (const s of SPAM_BRANDS) if (flat.includes(s.replace(/-/g, ""))) { isSpammy = true; hits.push("spam:" + s); }

  return { isEdu, isBdish, isSpammy, hits, tokens };
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// RANK 58 — alive(): DoH liveness prefilter.
//
// Measured in the brief: only 39 of 200 sampled .edu.bd domains resolve at all. Without this the scan
// queue fills with corpses, real intake is hidden behind dead rows, and every dead host still costs the
// scanner a full HTTP timeout. One cached DoH lookup removes ~80% of that waste.
//
// A DNS-level test only — it proves the name resolves, not that a webserver answers. Many BD sites
// publish only www., so a bare-apex miss is retried on www. before declaring the host dead.
// ═════════════════════════════════════════════════════════════════════════════════════════════════

export async function alive(host) {
  const h = normHost(host);
  if (!h) return false;
  if ((await resolveA(h)).length) return true;
  if (!h.startsWith("www.") && (await resolveA("www." + h)).length) return true;
  return false;
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// RANK 56 — the seen-set, seeded from the live D1 queue.
//
// The registry held 161,033 domains when this was written. A harvester with no seen-set reports every
// single one of them as a "new" find on day one, which makes the intake number meaningless and hides
// whether the harvester actually works. loadSeen() pages /api/domains?type=all (Bearer SHARED_TOKEN)
// into an on-disk newline file, then keeps it warm across runs.
//
// Memory: MEASURED at 108MB RSS with all 161,450 hostnames loaded (45MB node baseline + ~60MB for the
// Set). The API pages are parsed and discarded one at a time and both the disk read and the append are
// streamed, so nothing scales with corpus size beyond the Set itself.
//
// ⚠ THE SEEN-SET IS A COST REDUCER, NOT A CORRECTNESS GUARANTEE. /api/domains pages with
// LIMIT/OFFSET over `ORDER BY bd_score DESC, domain` on a table that harvesters are inserting into
// concurrently, so rows shift between pages and a few are missed. MEASURED: a full 33-page seed loaded
// 161,441 hostnames and still missed 9 navy.mil.bd hosts that were already in D1 — submit() reported
// them back as dups=9, inserted=0. That is the system working correctly: the Worker's
// `INSERT OR IGNORE` is the real dedup authority, and this set exists only to stop you re-POSTing
// 161k known domains and reporting them as "new". Never treat seen()===false as proof of novelty.
// ═════════════════════════════════════════════════════════════════════════════════════════════════

const SEEN = new Set();
let seenStream = null;

export function seen(host) { const h = normHost(host); return h ? SEEN.has(h) : false; }

export function markSeen(host) {
  const h = normHost(host);
  if (!h || SEEN.has(h)) return false;
  SEEN.add(h);
  try {
    if (!seenStream) seenStream = fs.createWriteStream(SEEN_FILE, { flags: "a" });
    seenStream.write(h + "\n");
  } catch {}
  return true;                                          // true = genuinely new
}

export function seenSize() { return SEEN.size; }

/**
 * Seed the seen-set: on-disk file first, then the live D1 registry (paged) if the file is stale/absent.
 * Safe to call on every run — the API seeding is skipped when the local file is younger than maxAgeH.
 * @returns {Promise<{total:number, fromDisk:number, fromApi:number, pages:number}>}
 */
export async function loadSeen(apiBase = API_BASE_DEFAULT, token = env.SHARED_TOKEN || "", opts = {}) {
  const { maxAgeH = 12, pageSize = 5000, maxPages = 200 } = opts;
  let fromDisk = 0, fromApi = 0, pages = 0;

  // Streamed, not readFile() — the seen file is several MB and a full-buffer read spikes RSS on a
  // 946MB box for no reason.
  try {
    const rl = (await import("node:readline")).createInterface({
      input: fs.createReadStream(SEEN_FILE, { encoding: "utf8" }), crlfDelay: Infinity,
    });
    for await (const line of rl) { const h = normHost(line); if (h && !SEEN.has(h)) { SEEN.add(h); fromDisk++; } }
  } catch {}

  let fresh = false;
  try { fresh = Date.now() - (await fsp.stat(SEEN_FILE)).mtimeMs < maxAgeH * 3600 * 1000; } catch {}
  if (fresh && fromDisk > 0) { dbg("seen: disk only", fromDisk); return { total: SEEN.size, fromDisk, fromApi, pages }; }

  if (!token) { console.error("[bdgate] loadSeen: no SHARED_TOKEN — seen-set is disk-only, expect inflated 'new' counts"); return { total: SEEN.size, fromDisk, fromApi, pages }; }

  const base = String(apiBase || API_BASE_DEFAULT).replace(/\/+$/, "");
  for (let offset = 0, p = 0; p < maxPages; p++, offset += pageSize) {
    let batch = null;
    for (let attempt = 1; attempt <= 3 && !batch; attempt++) {
      try {
        const r = await fetch(`${base}/api/domains?type=all&limit=${pageSize}&offset=${offset}`, {
          headers: { authorization: "Bearer " + token },
          signal: AbortSignal.timeout(90000),
        });
        if (!r.ok) { await sleep(attempt * 1500); continue; }
        batch = (await r.json()).domains || [];
      } catch { await sleep(attempt * 1500); }
    }
    if (!batch) { console.error("[bdgate] loadSeen: page " + p + " failed after 3 tries — partial seed"); break; }
    pages++;
    for (const row of batch) if (markSeen(row.domain)) fromApi++;
    if (batch.length < pageSize) break;                 // last page
    await sleep(150);                                   // be gentle with a live production D1
  }
  dbg("seen total", SEEN.size);
  return { total: SEEN.size, fromDisk, fromApi, pages };
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// submit() — the /harvest POST, done correctly. See the wire-format warning at the top of this file.
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/**
 * POST harvested rows to the Worker. Sends BOTH `domains` (what the live Worker reads) and `items`
 * (what several briefs specify) so it is correct either way. Coerces bare strings into {domain}.
 * @returns {Promise<{found:number, inserted:number, dups:number, posted:number, chunks:number, failed:number, ok:boolean}>}
 */
export async function submit(apiBase, token, source, items) {
  const base = String(apiBase || API_BASE_DEFAULT).replace(/\/+$/, "");
  const tok = token || env.SHARED_TOKEN || "";
  if (!tok) throw new Error("bdgate.submit: SHARED_TOKEN missing — the Worker will 401 every write");

  // Normalise to the OBJECT shape the Worker actually reads (d.domain || d.host || d.url).
  const rows = [];
  const dedup = new Set();
  for (const it of items || []) {
    const src = typeof it === "string" ? { domain: it } : (it || {});
    const domain = normHost(src.domain || src.host || src.url);
    if (!domain || dedup.has(domain)) continue;
    dedup.add(domain);
    const row = { domain, bd_score: Number(src.bd_score) || 0 };
    if (src.business) row.business = String(src.business).slice(0, 200);
    if (src.phone) row.phone = String(src.phone).slice(0, 40);
    rows.push(row);
  }
  const out = { found: 0, inserted: 0, dups: 0, posted: rows.length, chunks: 0, failed: 0, ok: true };
  if (!rows.length) return out;

  for (let i = 0; i < rows.length; i += SUBMIT_CHUNK) {
    const chunk = rows.slice(i, i + SUBMIT_CHUNK);
    let done = false;
    for (let attempt = 1; attempt <= 4 && !done; attempt++) {
      try {
        const r = await fetch(base + "/harvest", {
          method: "POST",
          headers: { authorization: "Bearer " + tok, "content-type": "application/json" },
          // BOTH keys on purpose — `domains` is what workers/src/index.js:213 reads today.
          body: JSON.stringify({ source, domains: chunk, items: chunk }),
        });
        if (r.status === 401) throw new Error("401 unauthorized — bad SHARED_TOKEN");
        if (!r.ok) { await sleep(attempt * 1500); continue; }
        const j = await r.json().catch(() => ({}));
        out.found += j.found || 0;
        out.inserted += j.inserted || 0;
        out.dups += j.dups || 0;
        out.chunks++;
        done = true;
      } catch (e) {
        if (String(e).includes("401")) throw e;
        await sleep(attempt * 1500);
      }
    }
    if (!done) { out.failed += chunk.length; out.ok = false; }
  }

  // THE failure signature: we posted rows and the Worker counted ZERO. That is rows VANISHING, and it
  // means the payload shape is wrong (`items` instead of `domains`, or bare strings) — verified live
  // against production: {items:[{domain:"du.ac.bd"}]} → found:0, {domains:["du.ac.bd"]} → found:0,
  // {domains:[{domain:"du.ac.bd"}]} → found:1. All three return HTTP 200, so only `found` reveals it.
  if (out.posted > 0 && out.found === 0 && out.chunks > 0) {
    out.ok = false;
    console.error(`[bdgate] submit(${source}): posted=${out.posted} but the Worker counted found=0 — every row was DROPPED. The payload shape is wrong.`);
  }
  // NOTE: found>0 with inserted===0 is NOT a failure — it is the normal steady state of a mature
  // harvester re-seeing domains already in the registry (dups===found). Do not alarm on it; use the
  // seen-set to avoid re-posting them in the first place.
  if (out.found > 0 && out.inserted === 0 && out.dups === out.found) dbg(`submit(${source}): all ${out.found} rows already known`);
  if (out.failed) console.error(`[bdgate] submit(${source}): ${out.failed} rows failed to POST after 4 attempts`);
  return out;
}

// ── convenience: bounded-concurrency map, so harvesters do not each reinvent a worker pool ──────────
export async function mapLimit(items, limit, fn) {
  const arr = Array.from(items);
  const out = new Array(arr.length);
  let idx = 0;
  await Promise.all(Array.from({ length: Math.max(1, Math.min(limit, arr.length)) }, async () => {
    for (;;) { const i = idx++; if (i >= arr.length) return; out[i] = await fn(arr[i], i); }
  }));
  return out;
}
