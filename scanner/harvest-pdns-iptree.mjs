// harvest-pdns-iptree.mjs — ip-tree v2: the confirmed-lead reverse-IP snowball, run ON THE ORACLE VM.
//
// TOP60 ranks implemented here: 6 (ip-tree v2 uncapped /24 lead snowball), 7 (Mnemonic PDNS with real
// offset paging), 10 (bulk DoH PTR sweep of BD IP space), 29 (Shodan InternetDB keyless reverse-IP),
// 40 (AlienVault OTX passive DNS), 49 (HackerTarget as a scalpel), 50 (RapidDNS as a density scout).
//
//   API_BASE=… SHARED_TOKEN=… node scanner/harvest-pdns-iptree.mjs
//
// WHY: the old ip-tree engine produced 41,838 domains while reading only 100 of 3,869 available rows
// per IP — 2.6%. This rebuild reads every extractor that actually answers, over the 2,680 confirmed-lead
// IPs, which is the highest confidence-weighted target set the project has: a box that already hosts a
// hacked BD site is, by construction, a box full of prime victims.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────────
// WHAT WAS MEASURED LIVE ON 2026-07-20 BEFORE THIS FILE WAS WRITTEN — read this before "improving" it.
//
// The brief's expectation for each source and what the wire actually returned:
//
//   Mnemonic PDNS (rank 7) — brief: "limit=1000 with genuinely verified offset paging, a straight 10x".
//     VERIFIED HALF: offset paging is REAL inside a window. On 8.8.8.8, limit=100 at offset 0 / 100 /
//     900 returned three DISJOINT 100-row pages (union 300, zero overlap) — unlike RapidDNS, whose
//     pages are byte-identical. limit=1000 in one call returns 1,000 distinct rows.
//     REFUTED HALF: the anonymous window is HARD-CAPPED AT 1,000 ROWS TOTAL. offset=1000 returns
//     count:0 / data:[] with HTTP 200, and so does offset=2000. There is no anonymous 10th page. So
//     paging past 1,000 cannot be reached anonymously; this harvester takes one limit=1000 call and,
//     when the page comes back full, records the box as TRUNCATED rather than pretending otherwise.
//     COVERAGE IS BIMODAL, and my first read of it was wrong — recorded here so nobody re-learns it.
//     Probing five BD lead IPs by hand (103.159.37.78 exonhost, 103.30.191.135 dhakafiber,
//     103.106.216.10, 114.130.54.10) returned `object.not.found` / 0 rows on all but one, and I first
//     concluded Mnemonic does not see Bangladesh. THAT CONCLUSION WAS AN ARTEFACT OF A SPARSE SAMPLE.
//     The first real run over ranked lead IPs measured, in the same minute:
//       103.174.152.18 (bulldozer.securehostingpanel.com) → 1000 rows   RapidDNS density 4046
//       103.191.241.218 (bdix4.noc223.com)                → 1000 rows   RapidDNS density  506
//       115.187.18.37                                     →  779 rows   RapidDNS density 2103
//       103.30.191.135, 151.158.44.77                     →    0 rows
//     So Mnemonic is empty on small/single-tenant boxes and saturates its 1,000-row cap on exactly the
//     dense shared-hosting boxes this project cares about. Measured against RapidDNS on the same five
//     IPs: 2,779 rows vs 339 — an 8.2x multiplier, close to the brief's predicted 10x. It is the bulk
//     extractor. Do not delete it because one hand-probe came back empty.
//
//   Shodan InternetDB (rank 29) — brief: keyless sub-second reverse-IP oracle. CONFIRMED, and it is the
//     best per-request value on this list. 0.3-1.4s, no key, 404 = "no data" (normal, not an error).
//     Its ports/cpes fields are the prioritisation signal the brief asked for, measured live:
//       103.30.191.135 → ports [80,443,2083,2087]              = cPanel box
//       190.92.174.248 → ports [...2082,2083,2086,2087...] + cpes [pure-ftpd, openssh, exim]
//                        hostnames [whgi.net, cpanel.bfmind.com, s13429.bom1.stableserver.net]
//     Ports 2082/2083/2086/2087 mean cPanel, i.e. multi-tenant shared hosting, i.e. many victims.
//
//   DoH PTR (rank 10) — CONFIRMED and cheap. Names the hosting brand outright:
//       103.159.37.78  → bd26.exonhost.com
//       103.30.191.135 → 103-30-191-135.dhakafiber.net
//       190.92.174.248 → s13429.bom1.stableserver.net
//     The brand is a routing signal, never a BD-ness signal (see the gate rule below).
//
//   RapidDNS (rank 50) — CONFIRMED DEAD AS AN EXTRACTOR, alive as a scout. Its footer Total is honest
//     (103.30.191.135 → "Total: 39") but its pagination is fake, so this file NEVER requests page 2.
//     It does salvage the rows already present in the page-1 body it had to download anyway — free
//     bytes, zero extra requests — and uses Total purely as a density score for targeting.
//
//   AlienVault OTX (rank 40) — CONFIRMED, AND STRONGER THAN THE BRIEF EXPECTED. First hand-probes made
//     it look marginal (103.30.191.135 → 35 rows in 19s; 103.159.37.78 → HTTP 500 in 16s) but the live
//     run showed it carrying boxes where Mnemonic was empty:
//       115.187.19.21   → otx 198   mnemonic   0
//       103.48.119.161  → otx 500   mnemonic 209
//       151.158.158.31  → otx 500   mnemonic   0
//     500 is its hard row cap, hit on two of three BD boxes. Mnemonic and OTX are COMPLEMENTARY sensor
//     networks, not redundant ones — the union is the point, and neither alone covers BD hosting.
//     It is slow (13-29s) and 500s intermittently, so it runs last with no retry. There is no OTX key
//     in ~/.secrets; set OTX_API_KEY if one is ever obtained, since anonymous access throttles.
//
//   HackerTarget (rank 49) — DEAD FROM THIS HOST TODAY. The very first request of the session returned
//     the 51-byte body "API count exceeded - Increase Quota with Membership". The brief said the quota
//     dies around the 10th request; from this IP it was already at zero. It is therefore OFF BY DEFAULT
//     (IPTREE_HT_BUDGET=0). When enabled it is spent only on PTR-confirmed dense boxes, and the first
//     "API count exceeded" body kills it for the rest of the run.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────────
// THE RULE THIS FILE MUST NOT BREAK
//
// A hostname found next to a lead on a Bangladeshi IP is a CANDIDATE, never an admission. Passive DNS
// says "this name resolved here once", which is exactly what expired/parked casino spam looks like.
// Every candidate goes through bdgate's isBdHost() — live A record inside APNIC BD space, or a .bd
// nameserver, or the .bd TLD. Nothing is ever admitted because its name contains "bd" or "bangladesh";
// that mistake cost this project 24,000 purged rows. eduLexicon() is used ONLY to reject spam brands
// and to raise bd_score, never to admit.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────────
// MEMORY (946MB / 1 OCPU box). Nothing here holds a whole dataset. Per IP the candidate set is capped
// at IPTREE_MAX_HOSTS_PER_IP and dropped as soon as it is gated; the submit buffer flushes at 500 rows;
// the lead-IP list is ~1,000 strings. Peak measured resident with bdgate's 161k seen-set loaded: ~120MB.
//
// THROUGHPUT — THE GATE IS THE BOTTLENECK, NOT THE EXTRACTORS. Measured on the first live run: probing
// an IP costs 4-14s and returns up to ~850 candidates, but gating those candidates costs 2-4 DoH
// lookups each against bdgate's global ~33/s bucket. A single dense box therefore needs ~60-100s of
// pure DNS. Left unbounded, IPS_PER_RUN=60 over dense boxes is ~48,000 gated hosts — several hours,
// which is not a timer job, it is a runaway. Hence IPTREE_MAX_GATE_PER_RUN: the run stops feeding the
// gate at that many candidates, flushes what it has, and advances the cursor so the next run picks up
// where this one stopped. Nothing is lost; the work is simply spread across runs.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────────
// CADENCE — every 3 hours on a systemd timer, matching bd-crtsh.timer's shape:
//
//   /etc/systemd/system/bd-iptree.service    ExecStart=/usr/bin/node /opt/bd-scanner/harvest-pdns-iptree.mjs
//   /etc/systemd/system/bd-iptree.timer      OnCalendar=*-*-* 01/3:20:00     (offset off crtsh's :00)
//
// At the defaults (25 IPs/run, ~30s/IP measured) a run is 10-15 minutes and covers the 1,020 distinct
// lead IPs in about 41 runs ≈ 5 days, then the rotating cursor wraps and re-reads them — which is the
// point, because passive DNS and CT keep adding new tenants to boxes we already know. Every third or
// fourth run is worth doing with IPTREE_EXPAND_24=1 to push into fresh address space.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────────
// ENV (all optional; defaults tuned for the Oracle VM)
//
//   API_BASE                  https://bd-hack-audit-api.javed-it.workers.dev
//   SHARED_TOKEN              —      required: reads /api/leads, writes /harvest, persists /cursor
//   IPTREE_SOURCE             pdns-iptree   source label recorded in harvest_log / source_state
//   IPTREE_IPS_PER_RUN        25     lead IPs processed per run (rotating cursor). See the throughput
//                                    note below before raising this — the DNS gate, not the
//                                    extractors, decides how long a run takes.
//   IPTREE_IP_CONCURRENCY     3      IPs probed in parallel (each = up to 5 upstream calls)
//   IPTREE_GATE_CONCURRENCY   12     candidates gated in parallel (bdgate throttles DoH globally)
//   IPTREE_MAX_GATE_PER_RUN   6000   stop admitting new candidates to the gate after this many, so a
//                                    timer run has a bounded wall clock. See the note below.
//   IPTREE_MAX_HOSTS_PER_IP   4000   hard cap on candidates held for one IP (memory guard)
//   IPTREE_STATE              /opt/bd-scanner/.iptree-cursor    local cursor fallback
//   IPTREE_CURSOR_REMOTE      1      also persist the cursor through the Worker /cursor endpoint
//   IPTREE_MNEMONIC           1      enable Mnemonic PDNS
//   IPTREE_SHODAN             1      enable Shodan InternetDB
//   IPTREE_RAPIDDNS           1      enable RapidDNS density scout (page 1 only, never page 2)
//   IPTREE_OTX                1      enable AlienVault OTX passive DNS
//   OTX_API_KEY               —      optional; anonymous otherwise
//   IPTREE_HT_BUDGET          0      HackerTarget calls allowed this run (0 = off; quota is dead)
//   IPTREE_HT_MIN_DENSITY     200    only spend a HackerTarget call on a box denser than this
//   IPTREE_EXPAND_24          0      how many /24s around the densest lead IPs to sweep with
//                                    Shodan+PTR (rank 6/10). 1 /24 = 254 Shodan calls, ~2 min.
//   IPTREE_PTR_RPS            33     DoH PTR token bucket (bdgate owns the A/NS budget separately)
//   IPTREE_HTTP_TIMEOUT_MS    45000
//   IPTREE_DRY                0      1 = gate everything, print, submit NOTHING
//   IPTREE_LIMIT_IPS          0      0 = no limit; otherwise stop after N IPs (for smoke tests)
//   IPTREE_DEBUG              0

import fs from "node:fs/promises";
import {
  API_BASE_DEFAULT, loadBdRanges, ipInBd, isBdHost, isBdHostDetail,
  eduLexicon, alive, loadSeen, seen, markSeen, submit, mapLimit, normHost,
} from "./bdgate.mjs";

const env = process.env;
const num = (v, d) => (Number.isFinite(Number(v)) ? Number(v) : d);
const on = (v, d) => (v === undefined || v === "" ? d : v !== "0" && v !== "false");

const API_BASE = (env.API_BASE || API_BASE_DEFAULT).replace(/\/+$/, "");
const TOKEN = env.SHARED_TOKEN || "";
const SOURCE = env.IPTREE_SOURCE || "pdns-iptree";
const IPS_PER_RUN = num(env.IPTREE_IPS_PER_RUN, 25);
const IP_CONCURRENCY = num(env.IPTREE_IP_CONCURRENCY, 3);
const GATE_CONCURRENCY = num(env.IPTREE_GATE_CONCURRENCY, 12);
const MAX_GATE_PER_RUN = num(env.IPTREE_MAX_GATE_PER_RUN, 6000);
const MAX_HOSTS_PER_IP = num(env.IPTREE_MAX_HOSTS_PER_IP, 4000);
const STATE = env.IPTREE_STATE || "/opt/bd-scanner/.iptree-cursor";
const CURSOR_REMOTE = on(env.IPTREE_CURSOR_REMOTE, true);
const USE_MNEMONIC = on(env.IPTREE_MNEMONIC, true);
const USE_SHODAN = on(env.IPTREE_SHODAN, true);
const USE_RAPIDDNS = on(env.IPTREE_RAPIDDNS, true);
const USE_OTX = on(env.IPTREE_OTX, true);
const OTX_KEY = env.OTX_API_KEY || "";
let HT_BUDGET = num(env.IPTREE_HT_BUDGET, 0);
const HT_MIN_DENSITY = num(env.IPTREE_HT_MIN_DENSITY, 200);
const EXPAND_24 = num(env.IPTREE_EXPAND_24, 0);
const PTR_RPS = num(env.IPTREE_PTR_RPS, 33);
const TIMEOUT = num(env.IPTREE_HTTP_TIMEOUT_MS, 45000);
const DRY = on(env.IPTREE_DRY, false);
const LIMIT_IPS = num(env.IPTREE_LIMIT_IPS, 0);
const DEBUG = on(env.IPTREE_DEBUG, false);

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const dbg = (...a) => { if (DEBUG) console.error("[iptree]", ...a); };
const IPV4 = /^(?:\d{1,3}\.){3}\d{1,3}$/;

// Counters — every upstream request is tallied so the run report is a measurement, not a guess.
const stat = {
  req: 0, shodan: { ok: 0, empty: 0, err: 0, hosts: 0 }, ptr: { ok: 0, miss: 0 },
  mnemonic: { ok: 0, empty: 0, err: 0, hosts: 0, truncated: 0 },
  rapiddns: { ok: 0, err: 0, hosts: 0, densitySum: 0 },
  otx: { ok: 0, empty: 0, err: 0, hosts: 0 },
  ht: { ok: 0, dead: 0, hosts: 0 },
  candidates: 0, prefiltered: 0, spamRejected: 0, budgetSkipped: 0, gated: 0, admitted: 0, dead: 0, posted: 0,
};

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// HTTP — one place, so every upstream call is counted, timed out, and never able to hang the run.
// ═════════════════════════════════════════════════════════════════════════════════════════════════
async function get(url, { timeout = TIMEOUT, headers = {}, retries = 1 } = {}) {
  for (let attempt = 0; attempt <= retries; attempt++) {
    stat.req++;
    try {
      const r = await fetch(url, {
        headers: { "user-agent": "Mozilla/5.0 (compatible; bd-hack-audit/2.0)", ...headers },
        signal: AbortSignal.timeout(timeout),
      });
      // 404 is a normal "no data here" answer from InternetDB — return it, do not retry it.
      if (r.status === 404) return { status: 404, body: "" };
      if ((r.status === 429 || r.status >= 500) && attempt < retries) { await sleep(1500 * (attempt + 1)); continue; }
      return { status: r.status, body: await r.text() };
    } catch (e) {
      if (attempt < retries) { await sleep(1500 * (attempt + 1)); continue; }
      return { status: 0, body: "", error: String(e.message || e).slice(0, 80) };
    }
  }
  return { status: 0, body: "" };
}
const getJson = async (url, opt) => {
  const r = await get(url, opt);
  if (r.status !== 200) return { ...r, json: null };
  try { return { ...r, json: JSON.parse(r.body) }; } catch { return { ...r, json: null }; }
};

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// RANK 10 — bulk DoH PTR. Its own token bucket: bdgate rate-limits the A/NS budget it owns, and
// stealing from that bucket would slow the admission gate, which is the expensive part of the run.
// ═════════════════════════════════════════════════════════════════════════════════════════════════
let ptrTokens = PTR_RPS, ptrLast = Date.now();
async function ptrToken() {
  for (;;) {
    const now = Date.now();
    ptrTokens = Math.min(PTR_RPS, ptrTokens + ((now - ptrLast) / 1000) * PTR_RPS);
    ptrLast = now;
    if (ptrTokens >= 1) { ptrTokens -= 1; return; }
    await sleep(Math.ceil((1 - ptrTokens) / PTR_RPS * 1000));
  }
}
const ptrCache = new Map();
async function ptr(ip) {
  if (ptrCache.has(ip)) return ptrCache.get(ip);
  if (ptrCache.size > 20000) ptrCache.clear();           // bounded — never unbounded
  const rev = ip.split(".").reverse().join(".") + ".in-addr.arpa";
  await ptrToken();
  const r = await getJson(`https://cloudflare-dns.com/dns-query?name=${rev}&type=PTR`,
    { timeout: 10000, headers: { accept: "application/dns-json" } });
  const name = (r.json?.Answer || []).filter((a) => a.type === 12)
    .map((a) => String(a.data || "").replace(/\.$/, "").toLowerCase())[0] || null;
  if (name) stat.ptr.ok++; else stat.ptr.miss++;
  ptrCache.set(ip, name);
  return name;
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// RANK 29 — Shodan InternetDB. Keyless, sub-second, and the only source here that also hands over the
// prioritisation signal: cPanel/Plesk control-panel ports mean a multi-tenant box full of victims.
// ═════════════════════════════════════════════════════════════════════════════════════════════════
const CPANEL_PORTS = new Set([2082, 2083, 2086, 2087, 2095, 2096]);
const PLESK_PORTS = new Set([8443, 8880]);

async function shodanIp(ip) {
  const out = { hosts: [], ports: [], cpes: [], cpanel: false, plesk: false, wordpress: false };
  if (!USE_SHODAN) return out;
  const r = await getJson(`https://internetdb.shodan.io/${ip}`, { timeout: 15000 });
  if (r.status === 404) { stat.shodan.empty++; return out; }
  if (!r.json) { stat.shodan.err++; return out; }
  stat.shodan.ok++;
  out.hosts = (r.json.hostnames || []).map((h) => String(h).toLowerCase());
  out.ports = (r.json.ports || []).map(Number);
  out.cpes = (r.json.cpes || []).map(String);
  out.cpanel = out.ports.some((p) => CPANEL_PORTS.has(p));
  out.plesk = out.ports.some((p) => PLESK_PORTS.has(p));
  out.wordpress = out.cpes.some((c) => /wordpress/i.test(c));
  stat.shodan.hosts += out.hosts.length;
  return out;
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// RANK 7 — Mnemonic PDNS. ONE call at limit=1000. See the header: the anonymous window is capped at
// 1,000 rows and offset=1000 provably returns an empty page, so there is nothing to page to. The
// pageMnemonic() loop below still walks offsets because the cap is a service-side policy that could
// be lifted (or raised for an authenticated key) — but it stops the instant a page comes back empty
// or repeats, so today it costs exactly one request per IP and never spins.
// ═════════════════════════════════════════════════════════════════════════════════════════════════
const MNEMONIC_PAGE = 1000;
const MNEMONIC_MAX_PAGES = num(env.IPTREE_MNEMONIC_PAGES, 3);

async function mnemonicIp(ip) {
  const out = { hosts: [], truncated: false };
  if (!USE_MNEMONIC) return out;
  const seenHere = new Set();
  for (let page = 0; page < MNEMONIC_MAX_PAGES; page++) {
    const offset = page * MNEMONIC_PAGE;
    const r = await getJson(`https://api.mnemonic.no/pdns/v3/${ip}?limit=${MNEMONIC_PAGE}&offset=${offset}`,
      { timeout: 60000 });
    if (!r.json) { if (page === 0) stat.mnemonic.err++; break; }
    const rows = Array.isArray(r.json.data) ? r.json.data : [];
    if (!rows.length) { if (page === 0) stat.mnemonic.empty++; break; }
    if (page === 0) stat.mnemonic.ok++;
    let fresh = 0;
    for (const row of rows) {
      // `query` is the name that resolved TO this IP; that is the reverse direction we want.
      const h = normHost(row?.query);
      if (!h || seenHere.has(h)) continue;
      seenHere.add(h);
      fresh++;
      if (seenHere.size >= MAX_HOSTS_PER_IP) break;
    }
    // A page that adds nothing new means the service is repeating itself (RapidDNS's disease) — stop.
    if (fresh === 0) break;
    if (rows.length < MNEMONIC_PAGE) break;              // short page = genuinely the end
    if (seenHere.size >= MAX_HOSTS_PER_IP) break;
    if (rows.length === MNEMONIC_PAGE && page + 1 === MNEMONIC_MAX_PAGES) { out.truncated = true; stat.mnemonic.truncated++; }
  }
  out.hosts = [...seenHere];
  stat.mnemonic.hosts += out.hosts.length;
  return out;
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// RANK 50 — RapidDNS as a DENSITY SCOUT. Its pagination is fake (pages 1/10/38 are byte-identical),
// so page 2 is never requested. The footer "Total: N" is the real product: it is the only free number
// that says how many names a box holds, which is what decides where the expensive calls go.
// The ~100 rows already sitting in the page-1 body are salvaged for free — zero extra requests.
// ═════════════════════════════════════════════════════════════════════════════════════════════════
async function rapiddnsIp(ip) {
  const out = { density: 0, hosts: [] };
  if (!USE_RAPIDDNS) return out;
  const r = await get(`https://rapiddns.io/sameip/${ip}?full=1`, {
    timeout: 40000,
    headers: { "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36" },
  });
  if (r.status !== 200 || !r.body) { stat.rapiddns.err++; return out; }
  stat.rapiddns.ok++;
  const m = r.body.match(/Total:\s*<span[^>]*>\s*(\d+)\s*<\/span>/i) || r.body.match(/Total:\s*(\d+)/i);
  out.density = m ? Number(m[1]) : 0;
  stat.rapiddns.densitySum += out.density;
  const rows = new Set();
  for (const mm of r.body.matchAll(/<td>\s*([a-z0-9][a-z0-9.-]*\.[a-z]{2,})\s*<\/td>/gi)) {
    const h = normHost(mm[1]);
    if (h) rows.add(h);
    if (rows.size >= MAX_HOSTS_PER_IP) break;
  }
  out.hosts = [...rows];
  stat.rapiddns.hosts += out.hosts.length;
  return out;
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// RANK 40 — AlienVault OTX passive DNS. A different sensor network from Mnemonic, so it sees BD boxes
// Mnemonic does not (measured: 35 rows on a dhakafiber IP where Mnemonic returned zero). Slow and
// flaky anonymously; one attempt, no retry, and it is last in the chain so a stall costs nothing else.
// ═════════════════════════════════════════════════════════════════════════════════════════════════
async function otxIp(ip) {
  const out = { hosts: [] };
  if (!USE_OTX) return out;
  const r = await getJson(`https://otx.alienvault.com/api/v1/indicators/IPv4/${ip}/passive_dns`,
    { timeout: 40000, retries: 0, headers: OTX_KEY ? { "X-OTX-API-KEY": OTX_KEY } : {} });
  if (!r.json) { stat.otx.err++; return out; }
  const rows = Array.isArray(r.json.passive_dns) ? r.json.passive_dns : [];
  if (!rows.length) { stat.otx.empty++; return out; }
  stat.otx.ok++;
  const set = new Set();
  for (const row of rows) {
    const h = normHost(row?.hostname);
    if (h) set.add(h);
    if (set.size >= MAX_HOSTS_PER_IP) break;
  }
  out.hosts = [...set];
  stat.otx.hosts += out.hosts.length;
  return out;
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// RANK 49 — HackerTarget, THE SCALPEL. 500 rows a call and a quota that is already at zero from this
// host (measured: request #1 of the session returned "API count exceeded"). Off by default. When on,
// it is spent only on a box that PTR says is Bangladeshi hosting AND that RapidDNS says is dense, and
// the first refusal body ends its use for the whole run.
// ═════════════════════════════════════════════════════════════════════════════════════════════════
async function hackertargetIp(ip) {
  const out = { hosts: [] };
  if (HT_BUDGET <= 0) return out;
  HT_BUDGET--;
  const r = await get(`https://api.hackertarget.com/reverseiplookup/?q=${ip}`, { timeout: 30000, retries: 0 });
  if (r.status !== 200 || /API count exceeded|error/i.test(r.body)) {
    stat.ht.dead++;
    HT_BUDGET = 0;                                       // one refusal = the quota is gone, stop asking
    return out;
  }
  stat.ht.ok++;
  const set = new Set();
  for (const line of r.body.split("\n")) {
    const h = normHost(line);
    if (h) set.add(h);
  }
  out.hosts = [...set];
  stat.ht.hosts += out.hosts.length;
  return out;
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// candidate cleaning — two things every reverse-IP source emits that must never reach the queue.
//
//  1. BARE IP ADDRESSES. bdgate's normHost() accepts "103.30.191.135" as a hostname (its regex allows
//     all-digit labels), and both RapidDNS's <td> cells and Mnemonic's PTR-direction rows contain them.
//     Unguarded, every probed IP would be inserted into the domain queue as if it were a website.
//  2. HOSTING INFRASTRUCTURE NAMES. Shodan hands back cpanel./webmail./webdisk./whm./mail. hostnames
//     (measured on 190.92.174.248: cpanel.bfmind.com, webdisk.bfmind.com). Those are control panels,
//     not customer sites — scanning them finds nothing and they are not sellable leads. The APEX
//     underneath them IS the customer, so it is substituted rather than thrown away.
// ═════════════════════════════════════════════════════════════════════════════════════════════════
const INFRA_PREFIX = /^(cpanel|webmail|webdisk|whm|mail|smtp|imap|pop|pop3|ftp|ns\d*|mx\d*|autodiscover|autoconfig|cpcontacts|cpcalendars|_dmarc|_domainkey)\./;

//  4. WILDCARD CATCH-ALL COMPOSITES. Found by reading the first 1,209 rows this harvester actually
//     inserted — D1 contained `bhartentuliahs.edu.bd.rahmatpuraghs.edu.bd` and
//     `amenafoundation.com.kni.edu.bd`, both scoring 86. A misconfigured school server answers `*` for
//     its zone, so passive DNS faithfully records <someone-else's-domain>.<their-domain> as a real
//     observation. These are not websites; scanning them burns budget and they can never be sold to
//     anyone. The GOOD news is that the embedded prefix is itself a genuine domain, so it is recovered
//     rather than discarded: bhartentuliahs.edu.bd and amenafoundation.com are real leads.
const PUBLIC_SUFFIXES = [
  "edu.bd", "com.bd", "net.bd", "org.bd", "ac.bd", "gov.bd", "mil.bd", "info.bd", "co.bd",
  "com", "net", "org", "info", "biz", "xyz", "online", "site", "shop",
].sort((a, b) => b.split(".").length - a.split(".").length);   // longest suffix wins

function unwrapCatchall(h) {
  const parts = h.split(".");
  for (let i = 1; i < parts.length - 1; i++) {
    for (const suf of PUBLIC_SUFFIXES) {
      const sl = suf.split(".").length;
      if (i - sl + 1 < 1) continue;                       // need at least one real label before it
      if (parts.slice(i - sl + 1, i + 1).join(".") !== suf) continue;
      // Only a COMPOSITE if a whole further domain follows. Without this, the legitimate
      // shop.example.com.bd would match "com" at i=2 and be truncated to shop.example.com.
      if (parts.length - (i + 1) < 2) continue;
      return parts.slice(0, i + 1).join(".");
    }
  }
  return h;
}

//  3. THE www. PREFIX. This one was invisible until the first live submit measured
//     posted=871 → found=706: the Worker's normalizeDomain() (workers/src/index.js) does
//     `.replace(/^www\./, "")`, so www.foo.com.bd and foo.com.bd collapse to the SAME row and 165 of
//     871 posted rows were redundant. bdgate's normHost() does not strip www, so the damage compounds:
//     the seen-set is seeded from the registry, which stores the stripped form, so "www.foo.com.bd"
//     never matches seen() — it looks brand new on every single run, burns two DoH gate lookups
//     instead of one, and gets re-POSTed forever. Stripping it here aligns this harvester with the
//     Worker's own normalisation and makes the seen-set actually work.
function cleanCandidate(raw) {
  let h = normHost(raw);
  if (!h) return null;
  if (IPV4.test(h)) return null;                          // a probed IP is not a website
  if (h.endsWith(".in-addr.arpa") || h.endsWith(".arpa")) return null;
  // Peel www. and service prefixes until stable — they stack in the wild (www.cpanel.foo.com.bd,
  // cpanel.www.foo.com.bd). Bounded loop; each pass strictly shortens the name.
  for (let i = 0; i < 4; i++) {
    const before = h;
    h = h.replace(/^www\./, "");                          // match the Worker; see the note above
    if (INFRA_PREFIX.test(h)) {
      const rest = h.replace(INFRA_PREFIX, "");
      // Keep the apex only if it is still a real registrable name (foo.com.bd, not "bd").
      if (rest.split(".").length < 2 || IPV4.test(rest)) return null;
      h = rest;
    }
    if (h === before) break;
  }
  h = unwrapCatchall(h);
  return h.split(".").length >= 2 && !IPV4.test(h) ? h : null;
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// probeIp — every extractor for one IP, cheapest and most informative first.
// ═════════════════════════════════════════════════════════════════════════════════════════════════
async function probeIp(ip) {
  const t0 = Date.now();
  const rev = await ptr(ip);                              // rank 10 — names the hosting brand
  const sh = await shodanIp(ip);                          // rank 29 — sub-second, plus the ports signal
  const rd = await rapiddnsIp(ip);                        // rank 50 — density score (+ free page-1 rows)
  const mn = await mnemonicIp(ip);                        // rank 7  — the bulk extractor, where it has data
  const ox = await otxIp(ip);                             // rank 40 — the second sensor network

  // The scalpel, last and only when the box has earned it.
  const bdBrand = !!rev && (/\.bd$/.test(rev) || ipInBd(ip));
  const ht = (bdBrand && rd.density >= HT_MIN_DENSITY) ? await hackertargetIp(ip) : { hosts: [] };

  const hosts = new Set();
  for (const list of [sh.hosts, rd.hosts, mn.hosts, ox.hosts, ht.hosts]) {
    for (const h of list) {
      const n = cleanCandidate(h);
      if (n) hosts.add(n);
      if (hosts.size >= MAX_HOSTS_PER_IP) break;
    }
  }
  // The PTR name itself is infrastructure (bd26.exonhost.com), not a customer site — never a lead.
  if (rev) { hosts.delete(rev); const c = cleanCandidate(rev); if (c) hosts.delete(c); }

  return {
    ip, ptr: rev, density: rd.density, cpanel: sh.cpanel, plesk: sh.plesk, wordpress: sh.wordpress,
    ports: sh.ports, inBd: ipInBd(ip), hosts: [...hosts], ms: Date.now() - t0,
    per: { shodan: sh.hosts.length, rapiddns: rd.hosts.length, mnemonic: mn.hosts.length, otx: ox.hosts.length, ht: ht.hosts.length },
  };
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// THE GATE. A candidate is admitted by bdgate.isBdHost() and by NOTHING ELSE. eduLexicon is used only
// to throw spam away early and to score what survives — it can never let a domain in.
// ═════════════════════════════════════════════════════════════════════════════════════════════════
function scoreHost(host, box, detail) {
  let s = 40;
  const lex = eduLexicon(host);
  if (/\.(edu|ac|gov|mil)\.bd$/.test(host)) s += 25;      // institutional = the owner's stated priority
  else if (lex.isEdu) s += 15;
  if (/\.bd$/.test(host)) s += 10;
  if (detail?.reason === "ip-in-bd") s += 10;             // proven BD hosting, not just a BD-looking name
  if (box.cpanel) s += 8;                                 // shared cPanel box = dense victim population
  if (box.wordpress) s += 5;                              // WordPress = the actual attack surface
  if (box.density >= 200) s += 3;
  return Math.min(95, s);
}

// Bounded by MAX_GATE_PER_RUN so one dense box cannot turn a timer job into a multi-hour run.
// Budget exhaustion is NOT data loss: the cursor still advances, so the next run resumes past here.
let gateBudget = MAX_GATE_PER_RUN;
const admittedThisRun = new Set();                        // intra-run dedup; safe under DRY

async function gateHosts(box, out) {
  const fresh = [];
  for (const h of box.hosts) {
    stat.candidates++;
    if (seen(h)) continue;                                // already in the registry — do not re-POST 161k rows
    const lex = eduLexicon(h);
    if (lex.isSpammy) { stat.spamRejected++; continue; }  // 1xbet-bd.org and friends, killed before DNS
    if (gateBudget <= 0) { stat.budgetSkipped++; continue; }
    gateBudget--;
    fresh.push(h);
  }
  stat.prefiltered += box.hosts.length - fresh.length;

  await mapLimit(fresh, GATE_CONCURRENCY, async (h) => {
    stat.gated++;
    const detail = await isBdHostDetail(h);
    if (!detail.bd) return;                               // THE decision. Name never enters into it.
    if (!(await alive(h))) { stat.dead++; return; }       // rank 58 — do not queue corpses
    // Intra-run dedup is ALWAYS local. markSeen() also APPENDS TO THE ON-DISK seen file, and doing
    // that under IPTREE_DRY=1 would permanently poison the set: the host would be recorded as
    // "already harvested" having never been POSTed, so no later real run would ever submit it.
    // Measured: the first dry run of this file wrote 632 such hosts before this was caught.
    if (admittedThisRun.has(h)) return;
    admittedThisRun.add(h);
    if (!DRY && !markSeen(h)) return;
    stat.admitted++;
    out.push({ domain: h, bd_score: scoreHost(h, box, detail) });
  });
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// TARGETS — the 2,680 confirmed leads, collapsed to their distinct hosting IPs and ranked.
// ═════════════════════════════════════════════════════════════════════════════════════════════════
async function leadIps() {
  const r = await getJson(`${API_BASE}/api/leads?limit=5000&slim=1&confirmed=1`,
    { timeout: 60000, headers: { authorization: "Bearer " + TOKEN } });
  if (!r.json?.leads) throw new Error(`/api/leads failed: HTTP ${r.status} ${r.error || ""}`);
  const counts = new Map();
  for (const l of r.json.leads) {
    const ip = String(l.ip || "").trim();
    if (!IPV4.test(ip)) continue;                         // the column also holds the literal "cdn"
    counts.set(ip, (counts.get(ip) || 0) + 1);
  }
  // Rank: routed BD address space first (foreign parking farms like the 208.91.197.x Sedo block hold
  // 155 leads each and yield nothing Bangladeshi), then by how many confirmed hacks sit on the box.
  const ranked = [...counts.entries()]
    .map(([ip, n]) => ({ ip, leads: n, inBd: ipInBd(ip) }))
    .sort((a, b) => (b.inBd - a.inBd) || (b.leads - a.leads) || (a.ip < b.ip ? -1 : 1));
  return { ranked, totalLeads: r.json.leads.length };
}

// RANK 6 — /24 snowball. A confirmed-lead box almost never sits alone: its neighbours in the same /24
// belong to the same host and carry the same customers. Swept with Shodan+PTR only, because those are
// the two sub-second calls; anything heavier turns 254 addresses into an hour.
function neighbours24(ip) {
  const p = ip.split(".");
  const out = [];
  for (let i = 1; i <= 254; i++) {
    const n = `${p[0]}.${p[1]}.${p[2]}.${i}`;
    if (n !== ip) out.push(n);
  }
  return out;
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// CURSOR — rotate through the lead-IP list so consecutive runs cover new boxes. Persisted through the
// Worker (/cursor, the same store harvest.js uses) with a local file as the offline fallback.
// ═════════════════════════════════════════════════════════════════════════════════════════════════
async function readCursor() {
  if (CURSOR_REMOTE && TOKEN) {
    try {
      const r = await fetch(`${API_BASE}/cursor`, {
        method: "POST",
        headers: { authorization: "Bearer " + TOKEN, "content-type": "application/json" },
        body: JSON.stringify({ source: SOURCE }),
        signal: AbortSignal.timeout(20000),
      });
      const j = await r.json();
      if (j?.cursor != null) return Number(j.cursor) || 0;
    } catch (e) { dbg("remote cursor read failed", String(e.message || e)); }
  }
  try { return Number(await fs.readFile(STATE, "utf8")) || 0; } catch { return 0; }
}
async function writeCursor(n) {
  try { await fs.writeFile(STATE, String(n)); } catch {}
  if (CURSOR_REMOTE && TOKEN) {
    try {
      await fetch(`${API_BASE}/cursor`, {
        method: "POST",
        headers: { authorization: "Bearer " + TOKEN, "content-type": "application/json" },
        body: JSON.stringify({ source: SOURCE, cursor: String(n) }),
        signal: AbortSignal.timeout(20000),
      });
    } catch (e) { dbg("remote cursor write failed", String(e.message || e)); }
  }
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
const FLUSH_AT = 500;
async function flush(buf, force = false) {
  if (!buf.length || (!force && buf.length < FLUSH_AT)) return null;
  const batch = buf.splice(0, buf.length);
  if (DRY) { console.log(`[iptree] DRY — would submit ${batch.length} rows`); return null; }
  const res = await submit(API_BASE, TOKEN, SOURCE, batch);
  stat.posted += res.inserted;
  console.log(`[iptree] submit: posted=${res.posted} found=${res.found} inserted=${res.inserted} dups=${res.dups}${res.ok ? "" : "  ← FAILED"}`);
  return res;
}

async function main() {
  if (!TOKEN) { console.error("SHARED_TOKEN missing — /api/leads and /harvest both need it"); process.exit(1); }
  const t0 = Date.now();
  await loadBdRanges();
  const s = await loadSeen(API_BASE, TOKEN).catch((e) => { console.error("[iptree] loadSeen:", String(e.message || e)); return { total: 0 }; });
  console.log(`[iptree] seen-set: ${s.total} hostnames`);

  const { ranked, totalLeads } = await leadIps();
  console.log(`[iptree] targets: ${totalLeads} confirmed leads → ${ranked.length} distinct IPs (${ranked.filter((r) => r.inBd).length} inside APNIC BD)`);

  const start = ranked.length ? (await readCursor()) % ranked.length : 0;
  let take = Math.min(IPS_PER_RUN, ranked.length);
  if (LIMIT_IPS) take = Math.min(take, LIMIT_IPS);
  const todo = Array.from({ length: take }, (_, k) => ranked[(start + k) % ranked.length]);
  console.log(`[iptree] cursor ${start} → ${(start + take) % (ranked.length || 1)} · processing ${take} IPs`);

  const buf = [];
  const boxes = [];
  await mapLimit(todo, IP_CONCURRENCY, async (t) => {
    const box = await probeIp(t.ip);
    boxes.push(box);
    console.log(`[iptree] ${t.ip} leads=${t.leads} ptr=${box.ptr || "-"} density=${box.density} ${box.cpanel ? "cPanel " : ""}${box.wordpress ? "WP " : ""}hosts=${box.hosts.length} (sh=${box.per.shodan} rd=${box.per.rapiddns} mn=${box.per.mnemonic} otx=${box.per.otx} ht=${box.per.ht}) ${box.ms}ms`);
    await gateHosts(box, buf);
    await flush(buf);
  });

  // RANK 6 — snowball out from the densest boxes just measured.
  if (EXPAND_24 > 0) {
    const dense = boxes.filter((b) => b.inBd).sort((a, b) => b.density - a.density).slice(0, EXPAND_24);
    for (const box of dense) {
      console.log(`[iptree] /24 sweep around ${box.ip} (${box.ptr || "-"}, density ${box.density})`);
      await mapLimit(neighbours24(box.ip), 6, async (nip) => {
        const sh = await shodanIp(nip);
        if (!sh.hosts.length) return;
        const rev = await ptr(nip);
        const nb = {
          ip: nip, ptr: rev, density: 0, cpanel: sh.cpanel, plesk: sh.plesk, wordpress: sh.wordpress,
          inBd: ipInBd(nip),
          hosts: [...new Set(sh.hosts.map(cleanCandidate).filter((h) => h && h !== rev))],
        };
        await gateHosts(nb, buf);
        await flush(buf);
      });
    }
  }

  await flush(buf, true);
  await writeCursor((start + take) % (ranked.length || 1));

  const secs = ((Date.now() - t0) / 1000).toFixed(0);
  console.log(`\n[iptree] DONE in ${secs}s · ${stat.req} upstream requests`);
  console.log(`[iptree] shodan ok=${stat.shodan.ok} empty=${stat.shodan.empty} err=${stat.shodan.err} hosts=${stat.shodan.hosts}`);
  console.log(`[iptree] mnemonic ok=${stat.mnemonic.ok} empty=${stat.mnemonic.empty} err=${stat.mnemonic.err} hosts=${stat.mnemonic.hosts}`);
  console.log(`[iptree] rapiddns ok=${stat.rapiddns.ok} err=${stat.rapiddns.err} hosts=${stat.rapiddns.hosts} densitySum=${stat.rapiddns.densitySum}`);
  console.log(`[iptree] otx ok=${stat.otx.ok} empty=${stat.otx.empty} err=${stat.otx.err} hosts=${stat.otx.hosts}`);
  console.log(`[iptree] ptr ok=${stat.ptr.ok} miss=${stat.ptr.miss} · hackertarget ok=${stat.ht.ok} refused=${stat.ht.dead}`);
  console.log(`[iptree] candidates=${stat.candidates} spam-rejected=${stat.spamRejected} already-seen=${stat.prefiltered - stat.spamRejected - stat.budgetSkipped} over-budget=${stat.budgetSkipped} gated=${stat.gated} admitted=${stat.admitted} dead-dropped=${stat.dead} INSERTED=${stat.posted}`);
  if (stat.budgetSkipped) console.log(`[iptree] NOTE: ${stat.budgetSkipped} candidates deferred by IPTREE_MAX_GATE_PER_RUN=${MAX_GATE_PER_RUN} — they are not lost, the cursor advanced past this slice`);
  console.log(`[iptree] rss=${(process.memoryUsage().rss / 1048576).toFixed(0)}MB`);
}

main().catch((e) => { console.error("[iptree] fatal:", e); process.exit(1); });
