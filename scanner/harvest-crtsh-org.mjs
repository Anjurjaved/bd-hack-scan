// harvest-crtsh-org.mjs — CA-VALIDATED Bangladesh discovery via Certificate Transparency metadata.
// Runs ON THE ORACLE VM (946MB / 1 OCPU). Plain node ESM, ZERO npm dependencies.
//
//   API_BASE=… SHARED_TOKEN=… node scanner/harvest-crtsh-org.mjs
//
// ─────────────────────────────────────────────────────────────────────────────────────────────────
// WHY THIS FILE EXISTS
//
// Every other BD-ness signal this project has is an inference: hosting IP (breaks behind Cloudflare),
// nameserver TLD (breaks on .com NS), or the domain string itself (which is the exact thing casino spam
// forges — see bdgate.mjs). An OV/EV certificate's Subject Organisation field is different in kind: a CA
// checked the applicant against a government business registry before issuing it. Domain-Validated certs
// (Let's Encrypt, the whole free tier) carry NO organisation field at all, so an O= query CANNOT return
// spam that merely bought a free cert. That makes O=%Bangladesh% the closest thing to a legal-entity
// oracle available for free, and it is the only source here that confirms a .com/.org/.net as
// Bangladeshi — which is precisely the owner's target, since most real BD businesses are not on .bd.
//
// VERIFIED LIVE 2026-07-19 (crt.sh, HTTP 200 in 10.4s, 455,429 bytes):
//   O=%Bangladesh%  → 1,156 certs → 152 unique hosts: brac.net, icddrb.org, aiub.edu, bergerbd.com,
//                     dsebd.org, bdfare.com, communitybankbd.com — .net/.org/.edu/.com, zero geo-IP guessing.
//   O=%Dhaka%       →   258 certs →  42 unique hosts: diu.ac, isdbd.org, aisdhaka.org, dhakacom.com.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────────
// THE FIELD TRAP — crt.sh REVERSES ITS TWO NAME FIELDS DEPENDING ON THE QUERY PARAMETER
//
// This is the single easiest way to get zero rows out of this source, so it is handled explicitly by two
// separate extractors below. Measured, not assumed:
//
//   ?O=%Bangladesh%   → common_name = "*.brac.net"      ← the DOMAIN
//                       name_value  = "BRAC Bangladesh"  ← the ORGANISATION
//   ?q=%25.brac.net   → common_name = "brac.net"
//                       name_value  = "brac.net\nwww.brac.net\n…"  ← newline-separated HOSTNAMES
//
// Feeding an O= response through a q=-shaped parser harvests organisation names as if they were domains.
// That is where the stray row `'ananda kumar sarkar'` came from in the probe — 14 of 854 rows in one
// response had a human name in common_name. Hosts containing spaces are rejected outright.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────────
// ⚠ MEASURED POISON — DO NOT ADD "Bengal" TO ORG_PATTERNS, AND DO NOT RE-LITIGATE IT
//
// O=%Bengal% returns 854 certs of which 731 (86%) are .in — the government of WEST BENGAL, INDIA:
//   "School Education Department, West Bengal"      → banglarshiksha.gov.in
//   "Panchayat and Rural Development Dept, W.B."    → bangla.gov.in
//   "West Bengal Police"                            → bengalathon.wb.gov.in
// "Bengal" is a region spanning two countries and the Indian half is far more certificated than the
// Bangladeshi half. Adding it would import an Indian state government as Bangladeshi businesses — the
// same class of error as the 24,000-row name-match purge, just wearing a geography costume.
//
// The narrower sibling trap, also measured: O=%Bangladesh% itself returns "Nepal Bangladesh Bank Ltd."
// → mbanking.nbbl.com.np. The org name is CA-validated AND contains "Bangladesh" AND the company is
// genuinely foreign. So a validated org string is strong evidence, not proof, and it is gated below.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────────
// STAGES (rotated by an on-disk cursor; select with STAGES=org,provider,vendor,expand)
//
//   org      RANK 11 — crt.sh ?O=<pattern>: CA-validated legal-entity → domain. The headline source.
//   provider RANK 31 — CertSpotter %.<hosting apex> → serverNN hostnames → resolve → BD hosting IPs.
//                      VERIFIED: exonhost.com yielded bd01…bd20.exonhost.com, and 20/20 resolved INSIDE
//                      APNIC-delegated BD space (103.159.36.x, 103.159.37.x, 138.252.82.68, 103.138.150.2).
//                      Writes an IP list for ip-tree / lead-coip to expand into tenants.
//   vendor   RANK 48 — crt.sh ?q=%25.<vendor apex>: every school tenant a school-SaaS vendor certificated.
//   expand   RANK 30 — CertSpotter ?domain=&include_subdomains: forgotten old./portal./staging. siblings
//                      that crawlers miss and attackers love. Cursor doubles as a renewal monitor.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────────
// ADMISSION LADDER — an org string NEVER admits on its own
//
//   0. reject IP literals. bdgate.normHost("119.148.19.67") returns the IP UNCHANGED (its host regex
//      allows all-digit labels), and crt.sh really does serve IP common_names — "International Hope
//      School Bangladesh" certificated 119.148.19.67. Without this check that IP enters the queue as a
//      domain. Checked here because the shared gate does not check it.
//   1. reject hosts with spaces / invalid / punycode garbage.
//   2. reject a foreign ccTLD (.in .np .pk .lk …) — outranks any org string.
//   3. reject eduLexicon().isSpammy.
//   4. ADMIT if bdgate.isBdHost() is true — real proof (BD IP / BD nameserver / .bd TLD). bd_score 85.
//   5. else ADMIT on the CA-validated org ONLY if the org string does not name a foreign polity. bd_score 60.
//   6. liveness (rank 58) via bdgate.alive() unless CRTORG_REQUIRE_ALIVE=0.
//
// Step 4 is tried BEFORE step 5 on purpose: "Bangladesh-India Friendship Power Company" (bifpcl.online)
// is a genuine BD entity whose name contains "India", so a blanket org-string filter would drop it. Real
// hosting evidence gets to speak first, and the string test only decides the cases evidence cannot.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────────
// ENV (all optional; defaults tuned for the Oracle VM)
//
//   API_BASE                https://bd-hack-audit-api.javed-it.workers.dev
//   SHARED_TOKEN            —      required to POST; without it the run is a dry run
//   STAGES                  org,provider,vendor,expand   comma list, in run order
//   CRTORG_STATE            <BDGATE_DIR>/.crtsh-org-cursor.json    rotating cursors
//   CRTORG_ORG_PER_RUN      3      org patterns per run (politeness — crt.sh 502s under load)
//   CRTORG_PROVIDER_PER_RUN 2      hosting apexes per run (CertSpotter anon quota is ~5-6 queries/hour)
//   CRTORG_VENDOR_PER_RUN   2      vendor apexes per run
//   CRTORG_EXPAND_PER_RUN   6      CertSpotter sibling queries per run
//   CRTORG_CS_TOKEN         —      free api.certspotter.com key; raises the anon quota substantially
//   CRTORG_MAX_BACKOFF_MS   60000  a Retry-After longer than this = upstream quota-exhausted, skip it
//   CRTORG_CRTSH_GAP_MS     12000  min gap between crt.sh calls
//   CRTORG_CS_GAP_MS        3000   min gap between CertSpotter calls
//   CRTORG_TIMEOUT_MS       150000 crt.sh genuinely needs 60s+; the old 30s is why it looked "dead"
//   CRTORG_MAX_BYTES        33554432  abort a response past 32MB (RAM guard; largest seen is 455KB)
//   CRTORG_DNS_CONC         12     concurrent verifications (bdgate caps globally at 33/s anyway)
//   CRTORG_IP_FILE          <BDGATE_DIR>/bd-hosting-ips.txt   rank-31 output for ip-tree
//   CRTORG_REQUIRE_ALIVE    1      set 0 to keep non-resolving domains
//   CRTORG_EXCLUDE_EXPIRED  0      1 = &exclude=expired (smaller/faster, loses dormant orgs)
//   CRTORG_DRY_RUN          0      1 = do everything except POST
//   CRTORG_DEBUG            0

import fsp from "node:fs/promises";
import path from "node:path";
import {
  CACHE_DIR, API_BASE_DEFAULT, loadBdRanges, ipInBd, isBdHostDetail, eduLexicon,
  alive, loadSeen, seen, markSeen, submit, normHost, resolveA, mapLimit, bdRangeStats,
} from "./bdgate.mjs";

const env = process.env;
const num = (v, d) => (Number.isFinite(Number(v)) && Number(v) >= 0 ? Number(v) : d);
const API_BASE = (env.API_BASE || API_BASE_DEFAULT).replace(/\/+$/, "");
const TOKEN = env.SHARED_TOKEN || "";

const STATE_FILE = env.CRTORG_STATE || path.join(CACHE_DIR, ".crtsh-org-cursor.json");
const IP_FILE = env.CRTORG_IP_FILE || path.join(CACHE_DIR, "bd-hosting-ips.txt");
const ORG_PER_RUN = num(env.CRTORG_ORG_PER_RUN, 3);
const PROVIDER_PER_RUN = num(env.CRTORG_PROVIDER_PER_RUN, 2);
const VENDOR_PER_RUN = num(env.CRTORG_VENDOR_PER_RUN, 2);
const EXPAND_PER_RUN = num(env.CRTORG_EXPAND_PER_RUN, 6);
const CRTSH_GAP = num(env.CRTORG_CRTSH_GAP_MS, 12000);
const CS_GAP = num(env.CRTORG_CS_GAP_MS, 3000);
const TIMEOUT = num(env.CRTORG_TIMEOUT_MS, 150000);
// 32MB, not 64: readCapped() holds the decoded string AND the in-flight chunk, so the cap is roughly
// doubled in practice. The largest response MEASURED from any of these endpoints is 455KB (O=%Bangladesh%),
// so 32MB is ~70x headroom while still leaving the 200MB RSS budget intact if something goes pathological.
const MAX_BYTES = num(env.CRTORG_MAX_BYTES, 32 * 1024 * 1024);
const DNS_CONC = num(env.CRTORG_DNS_CONC, 12);
const REQUIRE_ALIVE = env.CRTORG_REQUIRE_ALIVE !== "0";
const EXCLUDE_EXPIRED = env.CRTORG_EXCLUDE_EXPIRED === "1";
const DRY_RUN = env.CRTORG_DRY_RUN === "1";
const DEBUG = env.CRTORG_DEBUG === "1";
const STAGES = (env.STAGES || "org,provider,vendor,expand").split(",").map((s) => s.trim()).filter(Boolean);

const UA = "Mozilla/5.0 (compatible; bd-hack-audit/1.0; +https://javeditsolution.com)";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const dbg = (...a) => { if (DEBUG) console.error("[crtsh-org]", ...a); };
const log = (...a) => console.log("[crtsh-org]", ...a);

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// SOURCE LISTS
// ═════════════════════════════════════════════════════════════════════════════════════════════════

// Ordered by MEASURED yield, best first, so a short run still gets the good ones.
//   %Bangladesh% 1156 certs/152 hosts · %Dhaka% 258/42 · %Chittagong% 36/5 · %Rajshahi% 17/2
//   %Sylhet% 0 · %Chattogram% 0 (kept: cheap, and the post-2018 spelling will accrue certs over time)
// "Bengal" is DELIBERATELY ABSENT — 86% Indian. See the poison note in the header.
const ORG_PATTERNS = [
  "%Bangladesh%", "%Dhaka%", "%Chittagong%", "%Rajshahi%", "%Khulna%",
  "%Barisal%", "%Rangpur%", "%Mymensingh%", "%Sylhet%", "%Chattogram%",
  "%Bangladeshi%", "%Bogura%", "%Narayanganj%", "%Gazipur%", "%Cumilla%",
];

// RANK 31. Apexes of BD shared-hosting companies. Their serverNN.<apex> certificates enumerate the
// physical boxes; resolving those gives a dense BD hosting IP list, and each IP holds tens-to-hundreds
// of tenant sites for lead-coip / ip-tree to expand. exonhost verified: 20 servers → 20 BD IPs.
const PROVIDER_APEXES = [
  "exonhost.com", "dianahost.com", "itnuthosting.com", "hostever.com", "xeonbd.com",
  "alphanet.com.bd", "hostseba.com", "bdservers.net", "webhostbd.com", "dhakaweb.com",
  "bdwebservices.com", "hostingbangladesh.net", "cloudbd.net", "bdix.net",
];

// RANK 48. School-management SaaS vendors — one vendor apex enumerates every school tenant it ever
// certificated. The footer "Developed by" loop on confirmed education leads grows this list over time.
const VENDOR_APEXES = [
  "eduman.com.bd", "shikkhaloy.com", "edusoftbd.com", "schoolsoftbd.com", "onnorokom.com",
];

// A domain on a foreign ccTLD is not a BD business, whatever its certificate's organisation says.
// .np is here because it was MEASURED: "Nepal Bangladesh Bank Ltd." → mbanking.nbbl.com.np.
// .in is here because O=%Bengal% is 86% West Bengal, India.
const FOREIGN_CCTLD = /\.(in|np|pk|lk|bt|mm|cn|my|sg|th|id|ph|vn|ae|sa|qa|om|kw|bh|ru|ua|tr|ir|iq|eg|ng|ke|za|br|ar|mx|au|nz|jp|kr|tw|hk|gb|uk|ie|fr|de|it|es|pt|nl|be|ch|at|se|no|dk|fi|pl|cz|ro|gr|il)$/i;

// Applied ONLY when there is no hosting/NS proof (ladder step 5). Phrases, not bare country words, so a
// genuine BD entity like "Bangladesh-India Friendship Power Company" is not destroyed by the word "India".
const FOREIGN_ORG = [
  "west bengal", "nepal bangladesh", "government of india", "govt of india", "govt. of india",
  "republic of india", "state of west", "kolkata", "calcutta", "assam", "tripura", "meghalaya",
  "pvt ltd, india", "pakistan", "sri lanka", "myanmar",
];

// Multi-label public suffixes we must not mistake for an apex. BD-focused plus the few foreign ones that
// realistically appear; anything unknown falls back to the last two labels.
const MULTI_SUFFIX = new Set([
  "com.bd", "net.bd", "org.bd", "edu.bd", "gov.bd", "ac.bd", "mil.bd", "info.bd", "co.bd",
  "co.uk", "org.uk", "ac.uk", "com.np", "co.in", "com.pk", "com.au", "co.jp",
]);

function apexOf(host) {
  const parts = String(host).split(".");
  if (parts.length <= 2) return host;
  const last2 = parts.slice(-2).join(".");
  return MULTI_SUFFIX.has(last2) ? parts.slice(-3).join(".") : last2;
}

// bdgate.normHost() accepts all-digit labels, so "119.148.19.67" survives it unchanged. crt.sh genuinely
// serves IP common_names, so this guard is mandatory, not defensive.
const IPV4_LITERAL = /^\d{1,3}(\.\d{1,3}){3}$/;
function cleanHost(raw) {
  let h = String(raw || "").trim().toLowerCase();
  if (!h || h.includes(" ")) return null;         // "ananda kumar sarkar" — a person, not a host
  if (h.startsWith("*.")) h = h.slice(2);
  if (h.includes("@")) return null;               // e-mail SAN
  if (IPV4_LITERAL.test(h)) return null;          // ← the 119.148.19.67 case
  if (!/^[a-z0-9.-]+$/.test(h)) return null;      // punycode / garbage
  const n = normHost(h);
  if (!n || !n.includes(".")) return null;
  if (IPV4_LITERAL.test(n)) return null;
  return n;
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// POLITE HTTP — rank-2 trap: free public services 502 when hammered.
// Per-host minimum gap, exponential backoff on 429/5xx, Retry-After honoured, and a streamed byte cap
// so a pathological response can never blow the 946MB box's RAM budget.
// ═════════════════════════════════════════════════════════════════════════════════════════════════

const lastCall = new Map();
async function paced(hostKey, gap) {
  const prev = lastCall.get(hostKey) || 0;
  const wait = prev + gap - Date.now();
  if (wait > 0) await sleep(wait);
  lastCall.set(hostKey, Date.now());
}

// MEASURED 2026-07-19: CertSpotter's ANONYMOUS quota is far tighter than the docs suggest — roughly 5-6
// issuance queries per hour, after which every call returns HTTP 429 with `Retry-After: ~356`. Obeying
// that literally made one 6-provider run take 1,719s (28 min), almost all of it asleep. A cron job that
// sleeps 28 minutes is indistinguishable from a hung one, and on a 1-OCPU box it blocks the next timer.
//
// So: honour ONE short Retry-After, but if the wait exceeds CRTORG_MAX_BACKOFF_MS treat that upstream as
// quota-exhausted FOR THE REST OF THIS RUN and return null immediately for every later call to it. The
// cursor still advances, so the skipped slices are simply picked up by the next run. Set CRTORG_CS_TOKEN
// (a free api.certspotter.com key) to raise the ceiling substantially.
const MAX_BACKOFF = num(env.CRTORG_MAX_BACKOFF_MS, 60000);
const exhausted = new Set();
function isExhausted(hostKey) { return exhausted.has(hostKey); }

async function readCapped(res) {
  const reader = res.body.getReader();
  const dec = new TextDecoder();
  let out = "", total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > MAX_BYTES) { try { await reader.cancel(); } catch {} throw new Error("response exceeded CRTORG_MAX_BYTES"); }
    out += dec.decode(value, { stream: true });
  }
  return out + dec.decode();
}

// Returns { json, headers } or null. null means "give up on this slice for this run".
//
// The cursor DOES still advance past a failed slice, on purpose. The alternative — retrying the same
// slice until it succeeds — is precisely the starvation shape that once left 624 ASN blocks unswept: one
// permanently-failing slice at the head of the list would block every slice behind it forever. Because
// every list is walked modulo its length, an advanced cursor means a failed slice is simply retried one
// full rotation later, and no slice can ever monopolise the run.
async function getJson(url, { hostKey, gap, attempts = 4 } = {}) {
  if (isExhausted(hostKey)) { dbg(`skip (${hostKey} quota-exhausted this run): ${url.slice(0, 70)}`); return null; }
  const headers = { "user-agent": UA, accept: "application/json" };
  if (hostKey === "certspotter" && env.CRTORG_CS_TOKEN) headers.authorization = "Bearer " + env.CRTORG_CS_TOKEN;

  for (let i = 1; i <= attempts; i++) {
    await paced(hostKey, gap);
    try {
      const r = await fetch(url, { headers, signal: AbortSignal.timeout(TIMEOUT) });
      if (r.status === 429 || r.status >= 500) {
        const ra = Number(r.headers.get("retry-after")) || 0;
        const back = Math.max(ra * 1000, i * 8000);
        if (back > MAX_BACKOFF) {
          exhausted.add(hostKey);
          log(`${hostKey} asked for a ${Math.round(back / 1000)}s wait (HTTP ${r.status}) — treating as quota-exhausted, skipping its remaining slices this run`);
          return null;
        }
        dbg(`HTTP ${r.status} on ${url.slice(0, 80)} — backing off ${back}ms`);
        await sleep(back);
        continue;
      }
      if (!r.ok) { dbg(`HTTP ${r.status} (client error) on ${url.slice(0, 80)}`); return null; }
      const txt = await readCapped(r);
      // crt.sh answers non-JSON for unsupported params — `?L=Dhaka&output=json` literally returns
      // "Unsupported output type: json" as HTML. Measured. So never assume a 200 body is JSON.
      try { return { json: JSON.parse(txt), headers: r.headers }; }
      catch { dbg("non-JSON body (truncated/HTML) from " + url.slice(0, 80)); return null; }
    } catch (e) {
      dbg("fetch error " + String(e).slice(0, 90));
      await sleep(i * 8000);
    }
  }
  return null;
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// THE TWO EXTRACTORS — see the field-trap note in the header.
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/** ?O=… responses: common_name is the DOMAIN, name_value is the ORGANISATION. @returns Map<host, org> */
function extractOrgMode(rows) {
  const out = new Map();
  for (const row of Array.isArray(rows) ? rows : []) {
    const h = cleanHost(row?.common_name);
    if (!h) continue;
    const org = String(row?.name_value || "").trim().replace(/\s+/g, " ").slice(0, 200);
    if (!out.has(h) || (org && !out.get(h))) out.set(h, org);
  }
  return out;
}

/** ?q=… responses: name_value is newline-separated HOSTNAMES. @returns Set<host> */
function extractQueryMode(rows) {
  const out = new Set();
  for (const row of Array.isArray(rows) ? rows : []) {
    const cn = cleanHost(row?.common_name);
    if (cn) out.add(cn);
    for (const raw of String(row?.name_value || "").split("\n")) {
      const h = cleanHost(raw);
      if (h) out.add(h);
    }
  }
  return out;
}

/** CertSpotter issuances: dns_names[] is already an array. @returns Set<host> */
function extractCertSpotter(rows) {
  const out = new Set();
  for (const row of Array.isArray(rows) ? rows : []) {
    for (const raw of row?.dns_names || []) {
      const h = cleanHost(raw);
      if (h) out.add(h);
    }
  }
  return out;
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// THE GATE — ladder steps 0-6 from the header.
// ═════════════════════════════════════════════════════════════════════════════════════════════════

const stats = { rejIp: 0, rejForeignTld: 0, rejSpam: 0, rejForeignOrg: 0, rejDead: 0, admitProof: 0, admitOrg: 0, alreadySeen: 0 };

function orgLooksForeign(org) {
  const s = String(org || "").toLowerCase();
  return FOREIGN_ORG.some((p) => s.includes(p));
}

/** @returns {Promise<null | {domain, bd_score, business}>} */
async function admit(host, org, { sourceTag }) {
  const h = cleanHost(host);
  if (!h) { stats.rejIp++; return null; }
  if (FOREIGN_CCTLD.test(h)) { stats.rejForeignTld++; dbg("reject foreign-cctld", h, "|", org); return null; }

  const lex = eduLexicon(h);
  if (lex.isSpammy) { stats.rejSpam++; dbg("reject spam-brand", h, lex.hits.join(",")); return null; }

  const det = await isBdHostDetail(h);
  let bd_score = 0, why = "";
  if (det.bd) { bd_score = 85; why = det.reason; stats.admitProof++; }
  else if (org && !orgLooksForeign(org)) { bd_score = 60; why = "ca-validated-org"; stats.admitOrg++; }
  else if (org) { stats.rejForeignOrg++; dbg("reject foreign-org", h, "|", org); return null; }
  else { stats.rejForeignOrg++; dbg("reject no-proof-no-org", h, det.reason); return null; }

  if (REQUIRE_ALIVE && !(await alive(h))) { stats.rejDead++; dbg("reject dead", h); return null; }

  if (lex.isEdu) bd_score = Math.min(99, bd_score + 10);   // owner's stated first priority
  dbg("ADMIT", h, bd_score, why, sourceTag);
  return { domain: h, bd_score, business: org || "" };
}

// Every domain this run PROVED Bangladeshi. These are the seeds the expand stage works from, so the
// CertSpotter quota is only ever spent on confirmed BD ground rather than on guesses.
const ADMITTED = new Set();

/** Gate a batch concurrently, drop already-seen, and POST. @returns {Promise<number>} newly inserted */
async function gateAndSubmit(candidates, source) {
  const pending = [];
  for (const [host, org] of candidates) {
    const h = cleanHost(host);
    if (!h) { stats.rejIp++; continue; }
    if (seen(h)) { stats.alreadySeen++; continue; }
    pending.push([h, org]);
  }
  if (!pending.length) return 0;

  const rows = (await mapLimit(pending, DNS_CONC, ([h, org]) => admit(h, org, { sourceTag: source })))
    .filter(Boolean);
  if (!rows.length) return 0;
  for (const r of rows) ADMITTED.add(r.domain);

  if (DRY_RUN) { log(`DRY RUN — would submit ${rows.length} rows to ${source}`); rows.forEach((r) => markSeen(r.domain)); return 0; }

  const res = await submit(API_BASE, TOKEN, source, rows);
  rows.forEach((r) => markSeen(r.domain));
  if (!res.ok) console.error(`[crtsh-org] submit(${source}) FAILED: ${JSON.stringify(res)}`);
  log(`submit(${source}) → posted=${res.posted} found=${res.found} inserted=${res.inserted} dups=${res.dups}`);
  return res.inserted;
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// CURSORS — rotate every list so no slice is ever starved (the ip-tree starvation bug, again).
// ═════════════════════════════════════════════════════════════════════════════════════════════════

async function readState() {
  try { return JSON.parse(await fsp.readFile(STATE_FILE, "utf8")) || {}; } catch { return {}; }
}
async function writeState(s) {
  try { await fsp.writeFile(STATE_FILE, JSON.stringify(s, null, 2)); }
  catch (e) { console.error("[crtsh-org] could not persist cursor: " + String(e).slice(0, 80)); }
}
function slice(list, start, n) {
  const k = Math.min(n, list.length);
  return Array.from({ length: k }, (_, i) => list[(start + i) % list.length]);
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// STAGE org — RANK 11
// ═════════════════════════════════════════════════════════════════════════════════════════════════

async function stageOrg(state) {
  const start = num(state.org, 0);
  const todo = slice(ORG_PATTERNS, start, ORG_PER_RUN);
  state.org = (start + todo.length) % ORG_PATTERNS.length;
  log(`stage org — patterns ${todo.join(" ")} (cursor ${start} → ${state.org})`);

  let inserted = 0, hosts = 0, reqs = 0;
  for (const pattern of todo) {
    const url = `https://crt.sh/?O=${encodeURIComponent(pattern)}&output=json${EXCLUDE_EXPIRED ? "&exclude=expired" : ""}`;
    const t0 = Date.now();
    const res = await getJson(url, { hostKey: "crt.sh", gap: CRTSH_GAP });
    reqs++;
    if (!res) { log(`  ${pattern} — no data (502/timeout), retried next run`); continue; }
    const map = extractOrgMode(res.json);
    hosts += map.size;
    inserted += await gateAndSubmit(map, "crtsh-org");
    log(`  ${pattern} — ${res.json.length} certs, ${map.size} hosts (${((Date.now() - t0) / 1000).toFixed(0)}s)`);
  }
  return { inserted, hosts, reqs };
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// STAGE provider — RANK 31
//
// The deliverable here is the IP LIST, not the hostnames: bd07.exonhost.com is the hosting company's own
// infrastructure, never a sales lead. Its VALUE is that it resolves to 103.159.36.250, a BD shared box
// whose tenants are exactly the SMB victims this project sells cleanup to. Tenant hostnames that happen
// to appear in the same certificates ARE submitted.
// ═════════════════════════════════════════════════════════════════════════════════════════════════

// Returns ok:false when the FIRST page never got a usable answer, so callers can distinguish "this apex
// genuinely has no certificates" from "the upstream refused to talk to us". Conflating those two is how a
// dashboard ends up unable to tell an exhausted source from a broken one (TOP60 rank 57).
async function certspotterAll(domain, { maxPages = 3 } = {}) {
  const out = new Set();
  let after = null, reqs = 0, ok = false;
  for (let p = 0; p < maxPages; p++) {
    const u = new URL("https://api.certspotter.com/v1/issuances");
    u.searchParams.set("domain", domain);
    u.searchParams.set("include_subdomains", "true");
    u.searchParams.set("expand", "dns_names");
    if (after) u.searchParams.set("after", after);
    const res = await getJson(u.toString(), { hostKey: "certspotter", gap: CS_GAP, attempts: 3 });
    reqs++;
    if (!res || !Array.isArray(res.json)) break;          // upstream failure — ok stays false on page 0
    ok = true;                                            // we got a real answer, even if it is []
    if (!res.json.length) break;
    for (const h of extractCertSpotter(res.json)) out.add(h);
    // Link: </v1/issuances?after=15644623487&…>; rel="next"  — verified live.
    const link = res.headers.get("link") || "";
    const m = link.match(/[?&]after=(\d+)/);
    if (!m || res.json.length < 100) break;
    after = m[1];
  }
  return { hosts: out, reqs, ok };
}

async function stageProvider(state) {
  const start = num(state.provider, 0);
  const todo = slice(PROVIDER_APEXES, start, PROVIDER_PER_RUN);
  state.provider = (start + todo.length) % PROVIDER_APEXES.length;
  log(`stage provider — ${todo.join(" ")} (cursor ${start} → ${state.provider})`);

  const bdIps = new Set();
  let inserted = 0, hosts = 0, reqs = 0;

  for (const apex of todo) {
    const { hosts: names, reqs: r, ok } = await certspotterAll(apex);
    reqs += r;
    hosts += names.size;
    if (!ok) { log(`  ${apex} — UPSTREAM REFUSED (rate limit / error), not retried this run`); continue; }
    if (!names.size) { log(`  ${apex} — 0 hostnames (genuinely no certificates)`); continue; }

    // Split: the provider's own infrastructure (resolve → BD IP list) vs third-party tenants (submit).
    const infra = [], tenants = new Map();
    for (const h of names) {
      if (h === apex || h.endsWith("." + apex)) infra.push(h);
      else tenants.set(h, "");
    }

    let inBd = 0;
    await mapLimit(infra, DNS_CONC, async (h) => {
      for (const ip of await resolveA(h)) if (ipInBd(ip)) { bdIps.add(ip); inBd++; }
    });
    if (tenants.size) inserted += await gateAndSubmit(tenants, "crtsh-provider");
    log(`  ${apex} — ${names.size} hostnames, ${infra.length} infra → ${inBd} BD A-records, ${tenants.size} tenants`);
  }

  if (bdIps.size) {
    // Append-and-dedupe so ip-tree / lead-coip can consume a stable growing list.
    const existing = new Set();
    try { for (const l of (await fsp.readFile(IP_FILE, "utf8")).split("\n")) if (l.trim()) existing.add(l.trim()); } catch {}
    const before = existing.size;
    for (const ip of bdIps) existing.add(ip);
    await fsp.writeFile(IP_FILE, [...existing].join("\n") + "\n").catch((e) => console.error("[crtsh-org] IP file write failed: " + e));
    log(`stage provider — ${bdIps.size} BD hosting IPs this run; ${IP_FILE} now holds ${existing.size} (+${existing.size - before})`);
  }
  return { inserted, hosts, reqs, bdIps: bdIps.size };
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// STAGE vendor — RANK 48 (crt.sh ?q= — QUERY mode, so name_value holds the HOSTNAMES)
// ═════════════════════════════════════════════════════════════════════════════════════════════════

async function stageVendor(state) {
  const start = num(state.vendor, 0);
  const todo = slice(VENDOR_APEXES, start, VENDOR_PER_RUN);
  state.vendor = (start + todo.length) % VENDOR_APEXES.length;
  log(`stage vendor — ${todo.join(" ")} (cursor ${start} → ${state.vendor})`);

  let inserted = 0, hosts = 0, reqs = 0;
  for (const apex of todo) {
    const url = `https://crt.sh/?q=${encodeURIComponent("%." + apex)}&output=json&deduplicate=Y`;
    const res = await getJson(url, { hostKey: "crt.sh", gap: CRTSH_GAP });
    reqs++;
    if (!res) { log(`  ${apex} — no data`); continue; }
    const set = extractQueryMode(res.json);
    hosts += set.size;
    inserted += await gateAndSubmit([...set].map((h) => [h, ""]), "crtsh-vendor");
    log(`  ${apex} — ${res.json.length} certs, ${set.size} hostnames`);
  }
  return { inserted, hosts, reqs };
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// STAGE expand — RANK 30
//
// Seeds are the apexes this run already proved Bangladeshi, so the expander always works on confirmed BD
// ground rather than burning CertSpotter quota on guesses. Seeds persist in the cursor file, so a later
// run continues where this one stopped instead of re-querying the same apexes forever.
// ═════════════════════════════════════════════════════════════════════════════════════════════════

async function stageExpand(state, discovered) {
  const queue = Array.from(new Set([...(state.expandQueue || []), ...discovered.map(apexOf)]));
  const todo = queue.slice(0, EXPAND_PER_RUN);
  state.expandQueue = queue.slice(EXPAND_PER_RUN).slice(0, 5000);   // bounded — never an unbounded backlog
  if (!todo.length) { log("stage expand — queue empty, nothing to do"); return { inserted: 0, hosts: 0, reqs: 0 }; }
  log(`stage expand — ${todo.length} seeds (${state.expandQueue.length} still queued)`);

  let inserted = 0, hosts = 0, reqs = 0;
  const all = new Map();
  for (const d of todo) {
    const { hosts: names, reqs: r } = await certspotterAll(d, { maxPages: 2 });
    reqs += r;
    hosts += names.size;
    for (const h of names) if (!all.has(h)) all.set(h, "");
    dbg(`  ${d} — ${names.size} hostnames`);
  }
  inserted += await gateAndSubmit(all, "crtsh-expand");
  return { inserted, hosts, reqs };
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════

async function main() {
  const t0 = Date.now();
  if (!TOKEN && !DRY_RUN) {
    console.error("[crtsh-org] SHARED_TOKEN missing — refusing to run. Set CRTORG_DRY_RUN=1 to test without it.");
    process.exit(1);
  }

  const ranges = await loadBdRanges();
  log(`APNIC BD space: ${ranges.records} records / ${ranges.addresses} addresses / ${ranges.blocks} blocks (${ranges.source})`);

  const s = await loadSeen(API_BASE, TOKEN);
  log(`seen-set: ${s.total} hostnames (disk ${s.fromDisk}, api ${s.fromApi}, ${s.pages} pages)`);

  const state = await readState();
  const totals = { inserted: 0, hosts: 0, reqs: 0 };

  const roll = (r) => { totals.inserted += r.inserted; totals.hosts += r.hosts; totals.reqs += r.reqs; };

  try {
    for (const stage of STAGES) {
      try {
        if (stage === "org") { const r = await stageOrg(state); roll(r); }
        else if (stage === "provider") { const r = await stageProvider(state); roll(r); }
        else if (stage === "vendor") { const r = await stageVendor(state); roll(r); }
        else if (stage === "expand") { const r = await stageExpand(state, [...ADMITTED]); roll(r); }
        else console.error(`[crtsh-org] unknown stage "${stage}" — skipped`);
      } catch (e) {
        // One stage failing must never cost the other stages or the cursor.
        console.error(`[crtsh-org] stage ${stage} threw: ${String(e).slice(0, 200)}`);
      }
    }
  } finally {
    await writeState(state);
  }

  log("─".repeat(78));
  log(`gate: admitted ${stats.admitProof} on hosting/NS proof + ${stats.admitOrg} on CA-validated org`);
  log(`gate: rejected ${stats.rejForeignTld} foreign-ccTLD, ${stats.rejForeignOrg} foreign/absent org, ` +
      `${stats.rejSpam} spam-brand, ${stats.rejIp} IP-literal/invalid, ${stats.rejDead} not-resolving; ` +
      `${stats.alreadySeen} already known`);
  log(`DONE — ${totals.hosts} hostnames seen, ${totals.reqs} upstream requests, ` +
      `${totals.inserted} NEW inserted (${((Date.now() - t0) / 1000).toFixed(0)}s)`);
}

main().catch((e) => { console.error("[crtsh-org] fatal:", e); process.exit(1); });
