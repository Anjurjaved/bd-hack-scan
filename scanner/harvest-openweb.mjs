// harvest-openweb.mjs — the OPEN-KNOWLEDGE harvesters: Wikidata (rank 36) + OSM Overpass (rank 37).
//
// Runs on the Oracle VM (946MB / 1 OCPU). Zero npm dependencies, plain node ESM, streaming end to end.
// Both sources are human-curated public knowledge bases, so they arrive with something no other
// harvester in this system produces: a real BUSINESS NAME, and for OSM a street ADDRESS and DISTRICT.
// That metadata is worth as much as the domain — it is what makes outreach copy specific.
//
//   API_BASE=… SHARED_TOKEN=… node scanner/harvest-openweb.mjs
//
// ─────────────────────────────────────────────────────────────────────────────────────────────────
// WHY THIS FILE EXISTS — both sources were live-measured on 2026-07-19/20, not guessed.
//
// RANK 36 — Wikidata SPARQL, P17=Q902 (country = Bangladesh) + P856 (official website).
//   MEASURED: 7,097 distinct BD entities carry an official website (7,175 website statements),
//   yielding 6,831 unique hostnames. The Worker-side harvestWikidata() in workers/src/harvest.js:280
//   has a LIFETIME yield of 606 because it pages `LIMIT 200 OFFSET n` behind a 28s AbortSignal — one
//   cron tick moves the cursor 200 rows, so a full pass needs 36 ticks and any 502 resets progress.
//   MEASURED HERE: the whole 7,097-entity result set, WITH labels, instance-of and the administrative
//   parent, returns in 16.8s / 1.18MB as text/tab-separated-values. There is no reason to paginate it.
//   The endpoint refuses a default/absent User-Agent — WDQS requires a real, contactable UA string.
//
// RANK 37 — OSM Overpass. The repo's scanner/harvest-overpass.mjs has a LIFETIME yield of 6.
//   Its query is [out:json] + `out tags;` over all of Bangladesh, and it JSON.parse()s the entire
//   body. MEASURED HERE, the corrected form — `[out:csv(...)]` with an explicit field list — returns
//   1,985 data rows / 206KB in 63s, including rajukcollege.net (a BD college on .NET, exactly the
//   long tail that IP and CT harvesting miss), and it streams instead of buffering. 1,112 of those
//   rows carry an address and 930 carry a city/district.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────────
// THE TRAP THIS FILE IS MOST EXPOSED TO
//
// Both sources assert "this thing is in Bangladesh". That assertion is about the ENTITY, not about
// the WEBSITE. Measured in the live OSM pull: goethe.de, sc.com (Standard Chartered global),
// bankalfalah.com and bd.ambafrance.org are all genuinely mapped inside Bangladesh — embassies and
// foreign bank branches — and none of them is a Bangladeshi business we can sell a cleanup to.
//
// So a geographic assertion is NEVER a NAME test, but it is also not as strong as hosting. Every
// non-.bd host is first put through bdgate's isBdHost() (hosting IP inside APNIC BD space, or a .bd
// nameserver). What is left over is the GEO-ONLY TIER, and it was measured rather than assumed:
//
//   1,137 non-.bd hosts are geo-asserted but foreign-hosted. 1,120 of them carry a curated entity
//   label, and inspection shows they are overwhelmingly real Bangladeshi organisations sitting behind
//   Cloudflare — Dhaka Post, Channel i, Proshika, Ain O Salish Kendra, Emerald International School
//   Dhaka, Matrix International School, Sea Pearl Cox's Bazar. This is precisely the accepted false
//   negative documented in bdgate.mjs (bracu.ac.bd presents identically to 1xbet-bd.org to the DNS
//   ladder), and dropping all 1,137 would discard the exact population the owner ranked first:
//   BD schools and businesses on .com, not only .bd.
//
//   Exactly ONE of the 7,081 was a betting brand — 8mbets.co, a Wikidata item claiming P17=Q902 with
//   P31=business. So curation is NOT immune to self-insertion, and the geo-only tier gets its own
//   tighter gambling check (GEO_SPAM below) which is corpus-verified to reject that one row and
//   nothing else. See OPENWEB_STRICT for the three levels, and the gate block for the reasoning.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────────
// WHERE THE ADDRESS AND DISTRICT GO
//
// They are NOT lost, but they cannot be POSTed. workers/src/index.js:222 (harvest()) persists exactly
// five columns — domain, source, bd_score, business, phone — and `address`/`district` live on the
// FINDINGS table, written at scan time. So this harvester submits business+phone through /harvest and
// writes the full geo record to a sidecar TSV (OPENWEB_GEO_FILE, default <BDGATE_DIR>/openweb-geo.tsv)
// keyed by domain, ready for the moment a /harvest that accepts them (or a findings backfill) exists.
// Silently dropping them would have been the easy lie; a 1,100-row sidecar is the honest option.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────────
// ENV (all optional; defaults are tuned for the Oracle VM and for a once-daily systemd timer)
//
//   API_BASE            https://bd-hack-audit-api.javed-it.workers.dev
//   SHARED_TOKEN        —      required; without it /harvest 401s every write
//   OPENWEB_SOURCES     wikidata,osm     comma list; also accepts `wikidata` or `osm` alone
//   OPENWEB_ROTATE      0      1 = run ONE source per invocation, rotating via the Worker cursor
//   OPENWEB_STRICT      1      admission level for a non-.bd host that FAILS bdgate.isBdHost():
//                              2 = reject it (IP/NS evidence only; measured 5,944 admitted)
//                              1 = DEFAULT — admit at bd_score 25 if the source gave it a curated
//                                  entity label AND it passes the geo-tier gambling check (5,944+1,120)
//                              0 = admit every geo-asserted host, label or not (5,944+1,137)
//   OPENWEB_ALIVE       1      1 = drop hosts with no A record (rank 58 — the queue fills with corpses)
//   OPENWEB_SEEN        1      1 = seed bdgate's seen-set from D1 so "new" means new
//   OPENWEB_LIMIT       0      >0 = stop after N candidate hosts per source (for test runs)
//   OPENWEB_CONC        16     concurrent gate checks (bdgate globally caps DoH at BDGATE_DNS_RPS)
//   OPENWEB_DRY         0      1 = do everything except POST /harvest
//   OPENWEB_GEO_FILE    <BDGATE_DIR>/openweb-geo.tsv
//   OPENWEB_UA_MAIL     mdanjurjaved@gmail.com   contact address inside the User-Agent
//   WD_TIMEOUT_MS       200000   WDQS answers the full query in ~17s; the headroom is for a bad day
//   OSM_TIMEOUT_MS      400000   Overpass answers in ~63s; its own [timeout:250] fires first
//   OSM_ENDPOINTS       comma list of Overpass mirrors (default: de, kumi, private.coffee, mail.ru)
//   BDGATE_*            see bdgate.mjs — cache dir, DoH rate, APNIC URL, seen file
//
// CADENCE: daily. Both sources are slow-moving curated databases; Wikidata gains a few BD entities a
// week and OSM a few edits a day. Running hourly would be abuse of two free services for ~zero delta.
// Overpass in particular publishes a 2-slot rate limit per client (verified at /api/status).

import fs from "node:fs";
import path from "node:path";
import {
  loadBdRanges, isBdHostDetail, eduLexicon, alive,
  loadSeen, seen, markSeen, submit, normHost, mapLimit,
  CACHE_DIR, API_BASE_DEFAULT, bdRangeStats,
} from "./bdgate.mjs";

const env = process.env;
const int = (v, d) => (Number.isFinite(Number(v)) ? Number(v) : d);
const flag = (v, d) => (v === undefined || v === "" ? d : v === "1" || v === "true");

const API_BASE = (env.API_BASE || API_BASE_DEFAULT).replace(/\/+$/, "");
const TOKEN = env.SHARED_TOKEN || "";
const STRICT = Math.max(0, Math.min(2, int(env.OPENWEB_STRICT, 1)));
const CHECK_ALIVE = flag(env.OPENWEB_ALIVE, true);
const USE_SEEN = flag(env.OPENWEB_SEEN, true);
const LIMIT = int(env.OPENWEB_LIMIT, 0);
const CONC = Math.max(1, int(env.OPENWEB_CONC, 16));
const DRY = flag(env.OPENWEB_DRY, false);
const ROTATE = flag(env.OPENWEB_ROTATE, false);
const GEO_FILE = env.OPENWEB_GEO_FILE || path.join(CACHE_DIR, "openweb-geo.tsv");
const UA = `bd-hack-audit/1.0 (+https://javeditsolution.com; ${env.OPENWEB_UA_MAIL || "mdanjurjaved@gmail.com"})`;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const log = (...a) => console.log("[openweb]", ...a);

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// CURSOR — persisted in the Worker (source_state.cursor via POST /cursor), local file as fallback.
//
// Neither source paginates, so this cursor is not an offset: it is the ROTATION index plus the last
// success timestamp per source. That is what makes "exhausted" distinguishable from "broken" on the
// dashboard (rank 57's complaint), and it survives a VM rebuild because it lives in D1.
// ═════════════════════════════════════════════════════════════════════════════════════════════════

const CURSOR_SOURCE = "openweb";
const CURSOR_FILE = path.join(CACHE_DIR, "openweb-cursor.json");

async function readCursor() {
  if (TOKEN) {
    try {
      const r = await fetch(API_BASE + "/cursor", {
        method: "POST",
        headers: { authorization: "Bearer " + TOKEN, "content-type": "application/json" },
        body: JSON.stringify({ source: CURSOR_SOURCE }),
        signal: AbortSignal.timeout(30000),
      });
      if (r.ok) {
        const j = await r.json();
        if (j.cursor) return JSON.parse(j.cursor);
      }
    } catch (e) { log("cursor: Worker read failed, using local file —", String(e).slice(0, 70)); }
  }
  try { return JSON.parse(fs.readFileSync(CURSOR_FILE, "utf8")); } catch {}
  return { i: 0, runs: 0, last: {} };
}

async function writeCursor(c) {
  const s = JSON.stringify(c);
  try { fs.writeFileSync(CURSOR_FILE, s); } catch {}
  if (!TOKEN) return;
  try {
    await fetch(API_BASE + "/cursor", {
      method: "POST",
      headers: { authorization: "Bearer " + TOKEN, "content-type": "application/json" },
      body: JSON.stringify({ source: CURSOR_SOURCE, cursor: s }),
      signal: AbortSignal.timeout(30000),
    });
  } catch (e) { log("cursor: Worker write failed —", String(e).slice(0, 70)); }
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// STREAMING DELIMITED PARSER
//
// Both sources hand back tab-separated text. Neither may be JSON.parse()d as one blob: the OSM body
// is 206KB today but grows with every OSM edit, and the whole point of the 946MB budget is that no
// harvester's memory scales with its source. This is a character state machine over the fetch body
// stream, so peak resident cost is one chunk plus one row.
//
// `quoted` MUST match the dialect, and getting it wrong is a silent data-corruption bug rather than a
// crash — it cost a full live run here before it was caught:
//
//   OVERPASS (quoted: true)  — genuinely RFC4180-quotes. Measured output contains
//       "Sector 6, Uttara Model Town"  and  "+88028912780, +88028924301, +88028954676"
//     and an OSM value may legally contain a newline, so a naive split on \t plus \n truncates rows.
//
//   WIKIDATA SPARQL TSV (quoted: false) — NOT CSV. A field is an RDF term: <uri> or "label"@en, and
//     tabs/newlines inside a literal are backslash-escaped, so a row can never straddle a line. Run
//     the CSV state machine over it and the opening quote of "Bangladesh Water Development Board"@en
//     is eaten as a CSV quote, the closing quote ends the "field", and the language tag is then
//     appended to the value — yielding the business name `Bangladesh Water Development Board@en`.
//     That is not a crash, it just quietly poisons every outreach name. Terms are unwrapped by
//     unwrapTerm() instead, which strips <> and "…"@lang properly.
// ═════════════════════════════════════════════════════════════════════════════════════════════════

async function* parseDelimited(body, sep = "\t", quoted = true) {
  const reader = body.getReader();
  const dec = new TextDecoder();
  let field = "", row = [], inQ = false, pendingQ = false, sawCR = false;
  const flushField = () => { row.push(field); field = ""; };

  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    const chunk = dec.decode(value, { stream: true });
    for (let k = 0; k < chunk.length; k++) {
      const ch = chunk[k];
      if (quoted) {
        if (pendingQ) {                     // previous char was a `"` while inside a quoted field
          pendingQ = false;
          if (ch === '"') { field += '"'; continue; } // "" → literal quote
          inQ = false;                                // closing quote; fall through to handle `ch`
        }
        if (inQ) {
          if (ch === '"') pendingQ = true; else field += ch;
          continue;
        }
        if (ch === '"' && field === "") { inQ = true; continue; } // opening quote only at field start
      }
      if (ch === sep) { flushField(); continue; }
      if (ch === "\r") { sawCR = true; continue; }
      if (ch === "\n") { flushField(); yield row; row = []; sawCR = false; continue; }
      if (sawCR) { field += "\r"; sawCR = false; }
      field += ch;
    }
  }
  if (pendingQ) pendingQ = false;
  if (field !== "" || row.length) { flushField(); yield row; }
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// RANK 36 — WIKIDATA
//
// Asking for `format=json` and then JSON.parse()ing is the wrong shape: the JSON serialisation of
// this result is ~5x the TSV and cannot be consumed incrementally. SPARQL 1.1 TSV escapes tabs and
// newlines INSIDE literals (\t, \n), so a row can never straddle a line — combined with the streaming
// parser above, memory is flat regardless of how big Wikidata's BD coverage grows.
//
// Values arrive RDF-typed: <http://…> for a URI, "label"@en for a literal. unwrapTerm() undoes that.
//
// Two queries, both measured:
//   Q_MAIN  P17=Q902 + P856          → 7,834 rows / 7,097 entities / 1.18MB in 16.8s
//   Q_ADMIN entities whose P131+ parent is in BD but which lack P17 themselves (schools, thanas —
//           a real gap: idc.edu.bd, Ishwarganj Degree College, is only reachable this way)
//                                    → 53 rows in 5.1s. Small, but free and it is exactly the
//                                      institution class the owner ranked first.
// ═════════════════════════════════════════════════════════════════════════════════════════════════

const WD_ENDPOINT = env.WD_ENDPOINT || "https://query.wikidata.org/sparql";
const WD_TIMEOUT = int(env.WD_TIMEOUT_MS, 200000);

const Q_MAIN = `SELECT ?item ?site ?name ?typeLabel ?admLabel WHERE {
  ?item wdt:P17 wd:Q902 ; wdt:P856 ?site .
  OPTIONAL { ?item wdt:P31 ?type . }
  OPTIONAL { ?item wdt:P131 ?adm . }
  SERVICE wikibase:label { bd:serviceParam wikibase:language "en,bn". ?item rdfs:label ?name . ?type rdfs:label ?typeLabel . ?adm rdfs:label ?admLabel . }
}`;

const Q_ADMIN = `SELECT ?item ?site ?name ?admLabel WHERE {
  ?item wdt:P131+ ?adm . ?adm wdt:P17 wd:Q902 .
  ?item wdt:P856 ?site .
  FILTER NOT EXISTS { ?item wdt:P17 wd:Q902 }
  SERVICE wikibase:label { bd:serviceParam wikibase:language "en,bn". ?item rdfs:label ?name . ?adm rdfs:label ?admLabel . }
}`;

function unwrapTerm(v) {
  const s = String(v || "").trim();
  if (!s) return "";
  if (s.startsWith("<") && s.endsWith(">")) return s.slice(1, -1);
  if (s.startsWith('"')) {
    const end = s.lastIndexOf('"');
    if (end > 0) return s.slice(1, end).replace(/\\n/g, " ").replace(/\\t/g, " ").replace(/\\"/g, '"');
  }
  return s;
}

// A Wikidata label falls back to the Q-id when no label exists in en/bn. "Q61363612" is not a business
// name and putting it in the outreach copy would be worse than leaving the field empty.
const isQid = (s) => /^Q\d+$/.test(s);

async function wdQuery(query, label, stats) {
  for (let attempt = 1; attempt <= 3; attempt++) {
    stats.requests++;
    const t0 = Date.now();
    try {
      const r = await fetch(WD_ENDPOINT, {
        method: "POST",
        headers: {
          // WDQS refuses a generic/absent agent outright. This one is contactable, as their policy asks.
          "user-agent": UA,
          "content-type": "application/sparql-query",
          accept: "text/tab-separated-values",
        },
        body: query,
        signal: AbortSignal.timeout(WD_TIMEOUT),
      });
      if (r.status === 429) {
        const wait = int(r.headers.get("retry-after"), 60) * 1000;
        log(`wikidata ${label}: 429, honouring Retry-After ${wait / 1000}s`);
        await sleep(Math.min(wait, 180000));
        continue;
      }
      if (!r.ok) { log(`wikidata ${label}: HTTP ${r.status}, retry ${attempt}/3`); await sleep(attempt * 15000); continue; }
      log(`wikidata ${label}: HTTP 200 in ${((Date.now() - t0) / 1000).toFixed(1)}s, streaming`);
      return r;
    } catch (e) {
      log(`wikidata ${label}: ${String(e).slice(0, 80)}, retry ${attempt}/3`);
      await sleep(attempt * 15000);
    }
  }
  return null;
}

async function* harvestWikidata(stats) {
  for (const [query, label, cols] of [[Q_MAIN, "P17=Q902", 5], [Q_ADMIN, "P131→BD", 4]]) {
    const r = await wdQuery(query, label, stats);
    if (!r) { stats.failures.push(`wikidata:${label} unreachable after 3 attempts`); continue; }
    let head = true, rows = 0;
    // quoted:false — SPARQL TSV terms are RDF, not CSV. See the parser block comment.
    for await (const f of parseDelimited(r.body, "\t", false)) {
      if (head) { head = false; continue; }                 // ?item ?site ?name …
      if (f.length < 2) continue;
      rows++;
      const site = unwrapTerm(f[1]);
      if (!site) continue;
      const name = unwrapTerm(f[2]);
      // Q_MAIN: [item, site, name, typeLabel, admLabel]   Q_ADMIN: [item, site, name, admLabel]
      const type = cols === 5 ? unwrapTerm(f[3]) : "";
      const adm = cols === 5 ? unwrapTerm(f[4]) : unwrapTerm(f[3]);
      yield {
        url: site,
        business: isQid(name) ? "" : name,
        district: adm,
        address: "",
        phone: "",
        kind: type,
        src: "wikidata",
        wikidata: unwrapTerm(f[0]).split("/").pop(),
      };
    }
    stats.rows[`wikidata:${label}`] = rows;
    log(`wikidata ${label}: ${rows} result rows`);
  }
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// RANK 37 — OSM OVERPASS, THE CORRECTED QUERY
//
// What was wrong with scanner/harvest-overpass.mjs (lifetime yield: 6):
//   • [out:json] + `out tags;` returns EVERY tag of every matched feature as JSON — vastly more bytes
//     than needed — and the file then does JSON.parse(text) on the whole thing.
//   • Its AbortSignal is 240s while the query declares [timeout:180]; under mirror load the fetch is
//     killed mid-body and the run yields nothing, with no partial credit.
// The fix is `[out:csv(<explicit field list>)]`: Overpass does the projection server-side, so the
// body is 206KB instead of megabytes, and the address/district/phone columns arrive for free.
//
// The union of ["website"] and ["contact:website"] matters — OSM has been migrating to the contact:*
// namespace for years and both forms are in active use across Bangladesh.
//
// MEASURED, and the reason for the fallback ladder below: the very first probe of the full-field
// query returned HTTP 504 in 12s from overpass-api.de (server-side load shedding, NOT our timeout),
// while a lighter single-tag query on the same mirror returned 200/1,958 rows in 60s. So: rotate
// mirrors, back off, and if the rich query keeps failing, degrade to the lean one and still get the
// domains — losing the addresses is much better than losing the run.
// ═════════════════════════════════════════════════════════════════════════════════════════════════

const OSM_ENDPOINTS = (env.OSM_ENDPOINTS ||
  "https://overpass-api.de/api/interpreter,https://overpass.kumi.systems/api/interpreter,https://overpass.private.coffee/api/interpreter,https://maps.mail.ru/osm/tools/overpass/api/interpreter"
).split(",").map((s) => s.trim()).filter(Boolean);
const OSM_TIMEOUT = int(env.OSM_TIMEOUT_MS, 400000);

// Field order is load-bearing — the reader below indexes these positions.
const OSM_FIELDS = [
  "website", "contact:website", "name", "name:en",
  "addr:full", "addr:street", "addr:city", "addr:district", "addr:state",
  "phone", "contact:phone", "amenity", "office", "shop", "tourism", "healthcare",
];
const F = Object.fromEntries(OSM_FIELDS.map((n, i) => [n, i]));

const osmQuery = (rich) => rich
  ? `[out:csv(${OSM_FIELDS.map((f) => JSON.stringify(f)).join(",")};false;"\t")][timeout:250];
area["ISO3166-1"="BD"][admin_level=2]->.bd;
(nwr["website"](area.bd);nwr["contact:website"](area.bd););
out tags;`
  : `[out:csv("website","name";false;"\t")][timeout:180];
area["ISO3166-1"="BD"][admin_level=2]->.bd;
nwr["website"](area.bd);
out tags;`;

// Overpass publishes its own rate limit. Asking before knocking is the difference between a good
// citizen and the reason a free service starts 429ing this project. Verified live: overpass-api.de
// answers /api/status with "Rate limit: 2" and "2 slots available now."
async function osmSlotsFree(endpoint) {
  try {
    const r = await fetch(endpoint.replace(/interpreter$/, "status"), {
      headers: { "user-agent": UA }, signal: AbortSignal.timeout(30000),
    });
    if (!r.ok) return null;
    const t = await r.text();
    const m = /(\d+)\s+slots available now/.exec(t);
    if (m) return Number(m[1]);
    if (/Slot available after/.test(t)) return 0;
    return null;
  } catch { return null; }
}

async function osmFetch(rich, stats, mirrorStart) {
  for (let pass = 0; pass < OSM_ENDPOINTS.length; pass++) {
    const ep = OSM_ENDPOINTS[(mirrorStart + pass) % OSM_ENDPOINTS.length];
    const free = await osmSlotsFree(ep);
    if (free === 0) { log(`osm ${ep}: 0 slots free, skipping mirror`); continue; }
    for (let attempt = 1; attempt <= 2; attempt++) {
      stats.requests++;
      const t0 = Date.now();
      try {
        const r = await fetch(ep, {
          method: "POST",
          headers: { "content-type": "application/x-www-form-urlencoded", "user-agent": UA },
          body: "data=" + encodeURIComponent(osmQuery(rich)),
          signal: AbortSignal.timeout(OSM_TIMEOUT),
        });
        // 429 = rate limited, 504 = the gateway shed our query. Both mean "come back later", not "dead".
        if (r.status === 429 || r.status === 504 || r.status === 503) {
          log(`osm ${ep}: HTTP ${r.status} after ${((Date.now() - t0) / 1000).toFixed(0)}s — backing off`);
          await sleep(attempt * 30000);
          continue;
        }
        if (!r.ok) { log(`osm ${ep}: HTTP ${r.status}`); await sleep(attempt * 15000); continue; }
        const ct = r.headers.get("content-type") || "";
        // Overpass reports query errors as 200 text/html. Streaming that as CSV would yield garbage rows.
        if (ct.includes("text/html")) { log(`osm ${ep}: 200 but text/html — query rejected`); await sleep(15000); continue; }
        log(`osm ${ep}: HTTP 200 in ${((Date.now() - t0) / 1000).toFixed(1)}s (${rich ? "rich" : "lean"}), streaming`);
        return r;
      } catch (e) {
        log(`osm ${ep}: ${String(e).slice(0, 80)}`);
        await sleep(attempt * 15000);
      }
    }
  }
  return null;
}

// "Dhaka District" / "Rajshahi Division" → "Dhaka" / "Rajshahi". Cosmetic only; no BD-ness is decided
// here and the raw string is what gets written to the sidecar if it does not match this shape.
const tidyDistrict = (s) => String(s || "").replace(/\s+(district|division|upazila|thana|zila)$/i, "").trim();

async function* harvestOsm(stats, mirrorStart) {
  let rich = true;
  let r = await osmFetch(true, stats, mirrorStart);
  if (!r) { log("osm: rich query failed on every mirror — degrading to the lean query"); rich = false; r = await osmFetch(false, stats, mirrorStart + 1); }
  if (!r) { stats.failures.push("osm: every mirror failed for both the rich and the lean query"); return; }

  let rows = 0, withAddr = 0, withDistrict = 0;
  for await (const f of parseDelimited(r.body, "\t")) {
    if (rows === 0 && (f[0] === "website" || f[0] === "@website")) { rows++; continue; }  // header
    rows++;
    if (!rich) {
      if (f[0]) yield { url: f[0], business: f[1] || "", address: "", district: "", phone: "", kind: "", src: "osm" };
      continue;
    }
    const url = f[F["website"]] || f[F["contact:website"]] || "";
    if (!url) continue;
    // name:en first for outreach that must be typed into an email client; the Bengali name is kept as
    // the fallback because for many BD schools it is the ONLY name recorded in OSM.
    const business = (f[F["name:en"]] || f[F["name"]] || "").trim();
    const address = (f[F["addr:full"]] || [f[F["addr:street"]], f[F["addr:city"]]].filter(Boolean).join(", ")).trim();
    const district = tidyDistrict(f[F["addr:district"]] || f[F["addr:city"]] || f[F["addr:state"]] || "");
    const phone = (f[F["phone"]] || f[F["contact:phone"]] || "").split(",")[0].trim();
    const kind = (f[F["amenity"]] || f[F["office"]] || f[F["shop"]] || f[F["tourism"]] || f[F["healthcare"]] || "").trim();
    if (address) withAddr++;
    if (district) withDistrict++;
    yield { url, business, address, district, phone, kind, src: "osm" };
  }
  stats.rows["osm"] = rows;
  stats.osmGeo = { withAddr, withDistrict, rich };
  log(`osm: ${rows} CSV rows, ${withAddr} with an address, ${withDistrict} with a district`);
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// THE GATE — the only place a domain is admitted.
//
// Order is chosen so the CHEAP rejections happen before any network is spent:
//   1. normHost          — pure string
//   2. asset/junk reject — pure string
//   3. eduLexicon spam   — pure string, ~2µs (rank 5)
//   4. seen()            — in-memory Set (rank 56); already in D1, do not re-POST it
//   5. alive()           — 1 cached DoH lookup (rank 58); ~80% of dead .edu.bd never reach the queue
//   6. isBdHostDetail()  — the actual admission (ranks 26/27); .bd short-circuits with zero network
//
// bd_score reflects HOW the host was admitted, not how loudly the source asserted Bangladesh:
//   60  institutional .bd (.edu/.ac/.gov/.mil.bd) — always a victim, never a spam brand
//   50  any other .bd
//   45  non-.bd whose A record is inside APNIC BD space, or whose NS is .bd
//   25  non-.bd admitted on a curated geographic assertion alone (the geo-only tier)
//
// ── TWO MEASURED CORRECTIONS TO THE SHARED LEXICON, BOTH MADE HERE AND NOT IN bdgate.mjs ─────────
//
// (a) A .bd HOST IS NEVER SPAM-REJECTED. bdgate's SPAM_BRANDS contains "baji" (a real betting brand),
//     and on this source it produced four false positives that are all genuine government sites:
//         bajitpur.kishoreganj.gov.bd · bajitpurup.madaripur.gov.bd
//         bajitkhilaup.sherpur.gov.bd · police.bajitpur.kishoreganj.gov.bd
//     Bajitpur and Bajitkhila are real upazilas. This is the same family as the recorded FP incident
//     where "choti"=sandal and "chudi"=bangles nearly poisoned the porn filter. The .bd TLD is
//     registry-gated and .gov/.edu/.ac/.mil.bd are restricted further, so a foreign casino brand
//     cannot hold one — which is already this project's rule elsewhere. Reported upstream; guarded
//     here so this harvester cannot drop government sites while that is decided.
//
// (b) THE GEO-ONLY TIER GETS A TIGHTER GAMBLING CHECK. It is the weakest evidence in the file, and
//     one Wikidata item (8mbets.co, "8MBets", P17=Q902, P31=business) proved that a betting brand can
//     curate itself into the source. GEO_SPAM below cannot be applied globally — bdgate deliberately
//     has no bare "bet" token because Betagi, Bethuria, Betbunia and Bangladesh Betar are real, and
//     this run admitted 15 such .gov.bd hosts. It is safe HERE only because .bd never reaches this
//     tier (it short-circuits at rung 1). CORPUS DRY-RUN, the method this project requires before any
//     name rule ships: 1 hit in the 7,081 admitted rows (8mbets.co, correct) and 0 hits in the
//     16,124-host live registry seen-set. Accepted cost: a BD .com legitimately named "…bets…" would
//     be lost at score 25.
// ═════════════════════════════════════════════════════════════════════════════════════════════════

const ASSET = /\.(png|jpe?g|gif|svg|css|js|ico|woff2?|ttf|pdf|zip|xml|json|mp4)$/i;
const INST_BD = /\.(edu|ac|gov|mil)\.bd$/i;

// Applied ONLY to the geo-only tier — see note (b) above. Brand-specific or digit-anchored on purpose:
// "bets?\d" / "\d+bets?" catch 8mbets/bet365-style names without touching ordinary Bengali place names.
const GEO_SPAM = /(^|[^a-z])(casino|jackpot|roulette|gacor|togel|satta|rummy|teenpatti|sportsbook|bookmaker|betting|bets?\d|\d+bets?|xbet|bet365|melbet|mostbet|linebet|marvelbet|jeetbuzz|jeetwin|babu\d|krikya|baji\d|nagad88|glorycasino)/;
const GEO_SPAM_SUFFIX = /(^|[^a-z])[a-z0-9]{0,6}bets?($|[^a-z])/;

function scoreFor(host, reason) {
  if (INST_BD.test(host)) return 60;
  if (host.endsWith(".bd")) return 50;
  if (reason === "geo-only") return 25;
  return 45;
}

async function gate(cand, stats) {
  const host = normHost(cand.url);
  if (!host) { stats.rejected.badhost++; return null; }
  if (ASSET.test(host)) { stats.rejected.asset++; return null; }

  const isBdTld = host.endsWith(".bd");
  const lex = eduLexicon(host);
  // note (a): the .bd TLD is registry-gated, so a name-based spam token there is a false positive.
  if (lex.isSpammy && !isBdTld) {
    stats.rejected.spam++;
    stats.spamSamples.length < 12 && stats.spamSamples.push(host + " " + lex.hits.filter((h) => h.startsWith("spam:")).join(","));
    return null;
  }
  if (lex.isSpammy && isBdTld) {
    stats.spamOnBdTld++;
    stats.spamBdSamples.length < 8 && stats.spamBdSamples.push(host + " " + lex.hits.filter((h) => h.startsWith("spam:")).join(","));
  }
  if (USE_SEEN && seen(host)) { stats.rejected.known++; return null; }

  if (CHECK_ALIVE && !(await alive(host))) { stats.rejected.dead++; return null; }

  const d = await isBdHostDetail(host);
  let reason = d.reason;
  if (!d.bd) {
    const note = (x) => stats.foreignSamples.length < 12 && stats.foreignSamples.push(`${host} (${x}${d.ip ? " " + d.ip : ""})`);
    if (STRICT >= 2) { stats.rejected.foreign++; note(d.reason); return null; }
    // note (b): weakest evidence in the file, so it carries the tightest gambling check.
    if (GEO_SPAM.test(host) || GEO_SPAM_SUFFIX.test(host)) {
      stats.rejected.geoSpam++;
      stats.spamSamples.length < 12 && stats.spamSamples.push(host + " geo-tier-gambling");
      return null;
    }
    if (STRICT >= 1 && !cand.business) { stats.rejected.unlabelled++; note("geo-asserted but unlabelled"); return null; }
    reason = "geo-only";
    stats.geoOnly++;
  } else stats.bdHosted++;

  // Counted here, AFTER every rejection, so "education-lexicon" can never exceed "admitted".
  if (lex.isEdu) stats.edu++;
  return { ...cand, host, bd_score: scoreFor(host, reason), reason, isEdu: lex.isEdu };
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════

const tsv = (s) => String(s || "").replace(/[\t\r\n]+/g, " ").slice(0, 300);

async function runSource(name, iter, stats) {
  // Dedupe by URL first (Wikidata emits one row per P31/P131 combination — 7,834 rows for 7,097
  // entities — and OSM maps a chain's every branch to the same website), keeping the record with the
  // most metadata. This is the only structure held in memory and it is bounded by the source size.
  const cands = new Map();
  for await (const c of iter) {
    const key = normHost(c.url);
    if (!key) continue;
    const prev = cands.get(key);
    if (!prev) { cands.set(key, c); }
    else {
      // merge: never overwrite a filled field with an empty one
      for (const k of ["business", "address", "district", "phone", "kind"]) if (!prev[k] && c[k]) prev[k] = c[k];
    }
    if (LIMIT && cands.size >= LIMIT) { log(`${name}: OPENWEB_LIMIT=${LIMIT} reached, stopping the read`); break; }
  }
  const list = [...cands.values()];
  stats.candidates[name] = list.length;
  log(`${name}: ${list.length} unique candidate hosts → gating (concurrency ${CONC})`);

  const gated = (await mapLimit(list, CONC, (c) => gate(c, stats))).filter(Boolean);
  log(`${name}: ${gated.length} admitted`);
  return gated;
}

async function main() {
  const t0 = Date.now();
  if (!TOKEN && !DRY) { console.error("[openweb] SHARED_TOKEN missing — set it, or run with OPENWEB_DRY=1"); process.exit(1); }

  const stats = {
    requests: 0, rows: {}, candidates: {}, edu: 0, geoOnly: 0, bdHosted: 0, spamOnBdTld: 0,
    rejected: { badhost: 0, asset: 0, spam: 0, geoSpam: 0, known: 0, dead: 0, foreign: 0, unlabelled: 0 },
    spamSamples: [], spamBdSamples: [], foreignSamples: [], failures: [],
  };

  const r = await loadBdRanges();
  log(`APNIC BD space: ${r.records} records → ${r.blocks} disjoint blocks, ${r.addresses.toLocaleString()} addresses (${r.source})`);

  if (USE_SEEN) {
    const s = await loadSeen(API_BASE, TOKEN);
    log(`seen-set: ${s.total} hosts (${s.fromDisk} disk, ${s.fromApi} API over ${s.pages} pages)`);
  }

  const cursor = await readCursor();
  let want = (env.OPENWEB_SOURCES || "wikidata,osm").split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
  if (ROTATE && want.length > 1) {
    const pick = want[cursor.i % want.length];
    log(`rotate: run ${cursor.runs} picks "${pick}" of [${want.join(", ")}]`);
    want = [pick];
  }

  const admitted = [];
  for (const s of want) {
    if (s === "wikidata") admitted.push(...await runSource("wikidata", harvestWikidata(stats), stats));
    else if (s === "osm") admitted.push(...await runSource("osm", harvestOsm(stats, cursor.i || 0), stats));
    else log(`unknown source "${s}" — expected wikidata|osm`);
    cursor.last[s] = Math.floor(Date.now() / 1000);
  }

  // One host can legitimately come from both sources; the last write wins on metadata.
  const byHost = new Map();
  for (const a of admitted) {
    const prev = byHost.get(a.host);
    if (!prev) byHost.set(a.host, a);
    else for (const k of ["business", "address", "district", "phone", "kind"]) if (!prev[k] && a[k]) prev[k] = a[k];
  }
  const rows = [...byHost.values()];

  // ── the geo sidecar: address + district have nowhere to go over the wire (see the header note) ──
  if (rows.length) {
    try {
      const exists = fs.existsSync(GEO_FILE);
      const out = fs.createWriteStream(GEO_FILE, { flags: "a" });
      if (!exists) out.write("domain\tsource\tbusiness\tphone\taddress\tdistrict\tkind\tbd_score\tts\n");
      const ts = new Date().toISOString();
      for (const x of rows) {
        out.write([x.host, x.src, tsv(x.business), tsv(x.phone), tsv(x.address), tsv(x.district), tsv(x.kind), x.bd_score, ts].join("\t") + "\n");
      }
      await new Promise((res) => out.end(res));
      const withGeo = rows.filter((x) => x.address || x.district).length;
      log(`geo sidecar: ${rows.length} rows appended to ${GEO_FILE} (${withGeo} carry an address or district)`);
    } catch (e) { log("geo sidecar write failed:", String(e).slice(0, 90)); }
  }

  let res = { found: 0, inserted: 0, dups: 0, posted: 0, ok: true };
  if (DRY) log(`DRY RUN — would POST ${rows.length} rows to ${API_BASE}/harvest`);
  else if (rows.length) {
    // submit() sends BOTH `domains` and `items` as OBJECTS, and flags found>0/inserted=0 correctly.
    // Do not hand-roll this POST: bare strings return HTTP 200 with every row silently dropped.
    res = await submit(API_BASE, TOKEN, "openweb", rows.map((x) => ({
      domain: x.host, bd_score: x.bd_score, business: x.business, phone: x.phone,
    })));
    if (res.posted > 0 && res.found === 0) stats.failures.push("submit: posted>0 but the Worker counted found=0 — payload shape wrong");
    for (const x of rows) markSeen(x.host);
  }

  cursor.i = (cursor.i || 0) + 1;
  cursor.runs = (cursor.runs || 0) + 1;
  await writeCursor(cursor);

  const rej = stats.rejected;
  log("──────────────────────────────────────────────────────────────");
  log(`requests           ${stats.requests}`);
  log(`source rows        ${JSON.stringify(stats.rows)}`);
  log(`unique candidates  ${JSON.stringify(stats.candidates)}`);
  log(`strict level       ${STRICT} (2=IP/NS only · 1=+curated geo-only · 0=+unlabelled geo)`);
  log(`rejected           spam ${rej.spam} · geo-tier gambling ${rej.geoSpam} · unlabelled-geo ${rej.unlabelled} · already-known ${rej.known} · dead ${rej.dead} · foreign-hosted ${rej.foreign} · bad ${rej.badhost + rej.asset}`);
  if (stats.spamSamples.length) log(`  spam rejects     ${stats.spamSamples.join(" | ")}`);
  if (stats.foreignSamples.length) log(`  foreign rejects  ${stats.foreignSamples.slice(0, 6).join(" | ")}`);
  // Loud on purpose: these are the bdgate "baji"→Bajitpur false positives this file is shielding.
  if (stats.spamOnBdTld) log(`  ⚠ ${stats.spamOnBdTld} .bd host(s) tripped bdgate SPAM_BRANDS and were KEPT (registry-gated TLD): ${stats.spamBdSamples.join(" | ")}`);
  log(`admitted           ${rows.length} (${stats.edu} education-lexicon · ${stats.bdHosted} BD-hosted/NS · ${stats.geoOnly} geo-only@25)`);
  log(`POST /harvest      found ${res.found} · inserted ${res.inserted} · dups ${res.dups}${res.ok ? "" : "  ⚠ FAILED"}`);
  log(`rss                ${(process.memoryUsage().rss / 1048576).toFixed(0)}MB · elapsed ${((Date.now() - t0) / 1000).toFixed(0)}s`);
  if (stats.failures.length) { log("FAILURES:"); for (const f of stats.failures) log("  ✗", f); }
  log("──────────────────────────────────────────────────────────────");

  // Exit non-zero ONLY on a real failure, so a systemd timer's status is meaningful. A mature run
  // that finds everything already known (inserted 0, dups = found) is a SUCCESS, not a fault.
  if (!res.ok || (stats.failures.length && rows.length === 0)) process.exit(1);
}

main().catch((e) => { console.error("[openweb] fatal:", e); process.exit(1); });
