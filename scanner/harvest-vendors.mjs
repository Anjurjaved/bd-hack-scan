// harvest-vendors.mjs — TOP60 rank 14 (school-management SaaS vendor tenant enumeration)
//                     + TOP60 rank 15 (education outbound-link snowball).
//
// Runs on the Oracle VM. Zero npm dependencies. Plain node ESM.
//
//   API_BASE=… SHARED_TOKEN=… node scanner/harvest-vendors.mjs
//
// ─────────────────────────────────────────────────────────────────────────────────────────────────
// WHY THIS EXISTS
//
// Bangladeshi schools almost never build their own website. They buy a tenant on a school-management
// SaaS, and that vendor puts hundreds of schools on one box under one apex. VERIFIED LIVE while
// writing this file: eduman.com.bd and shikkhaloy.com both resolve to 65.60.45.202, and one
// rapiddns reverse-IP call on that address returned `nabinagarghs.edu.bd` — a real Bangladeshi
// school — sitting next to them. One vendor box is worth hundreds of ordinary harvest requests.
//
// The compounding part is the DISCOVERY LOOP. Every one of those tenant sites carries a
// "Developed by <vendor>" footer. So each confirmed education lead names its vendor, and each named
// vendor exposes a fresh box full of schools. The vendor list therefore grows on its own, forever,
// without anyone maintaining it. Three passes feed each other:
//
//   pass A  footer loop   confirmed education leads   → NEW vendor apexes      (grows the vendor list)
//   pass B  reverse-IP    vendor apex → hosting IP    → co-tenant schools      (harvests the box)
//   pass C  crt.sh        %.<vendor_apex>             → tenant subdomains      (harvests the zone)
//
// Rank 15 rides along for free: pass A already downloads the HTML of every confirmed education lead,
// so extracting its outbound links costs ZERO extra requests. Education sites link each other
// densely (board → college → feeder school), so that link graph is itself a harvest source.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────────
// ⚠ THE TWO TRAPS, AND HOW THIS FILE AVOIDS THEM
//
// 1. NEVER admit a domain because its NAME looks Bangladeshi. "bd"/"bangladesh" in a hostname is the
//    signature of FOREIGN casino spam (1xbet-bd.org, 1win-bangladesh.net). This project already had
//    to purge 24,000 rows for that mistake. Admission here is decided by exactly two things:
//
//      (a) bdgate.isBdHost() — hosting IP inside APNIC's BD space, BD nameserver, or the .bd registry.
//      (b) being a strict SUBDOMAIN of a known vendor apex (school.eduman.com.bd).
//
//    Rung (b) is not a name test. It is registry-level proof: the vendor controls that zone, and a
//    spammer cannot create a record inside someone else's DNS zone. `eduman-bd.com` would look like a
//    tenant to a name test and is correctly rejected by this one.
//
//    That rung matters because a vendor box is a SHARED reseller box. The same live rapiddns dump
//    that gave us nabinagarghs.edu.bd also contained francusketajne.com, printnsignusa.com and
//    colonypark.com. Co-tenancy alone proves NOTHING — every co-tenant still faces the full gate.
//
// 2. A HACKED SITE'S FOOTER IS ATTACKER-CONTROLLED. Pass A reads footers off sites this system has
//    already confirmed as COMPROMISED. Injected SEO-spam lives in exactly that footer. So a single
//    footer can never promote a vendor. A new vendor apex is admitted only if it is either itself
//    BD-hosted, or named by VENDORS_MIN_FOOTER (default 2) DISTINCT education sites — and never if
//    eduLexicon flags it as a casino/adult brand. One hacked site cannot inject a vendor.
//
// 3. crt.sh 502s and 429s when hammered (it 429'd during this file's own probing, with several
//    harvesters running in parallel). One apex per run by default, 150s timeout, exponential backoff,
//    rotating cursor — never a retry storm.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────────
// MEMORY — target is a 946MB / 1 OCPU VM.
//
// Nothing is ever fully buffered. HTML bodies are read through a streaming reader and hard-capped at
// VENDORS_HTML_CAP bytes (default 512KB) with the rest discarded; only extracted hostnames survive a
// page. Every accumulator is a Set with an explicit cap. Peak RSS measured below.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────────
// ENV (all optional — defaults are tuned for the VM)
//
//   API_BASE                 https://bd-hack-audit-api.javed-it.workers.dev  (bdgate default)
//   SHARED_TOKEN             —          bearer token for /harvest, /cursor, /api/leads
//   VENDORS_STATE            <bdgate cache dir>/vendors-state.json   local mirror of the vendor list
//   VENDORS_CURSOR_SOURCE    vendors    key under which state is persisted via the Worker /cursor
//   VENDORS_LEADS            80         confirmed education leads to read footers from, per run
//   VENDORS_REVIP            8          vendor IPs to reverse-lookup per run (rotating)
//   VENDORS_REVIP_MAX        400        discard a reverse-IP result bigger than this — it is a CDN edge,
//                                       not a vendor box (measured: Cloudflare returned 1087 co-tenants)
//   VENDORS_CRTSH            1          vendor apexes to run %.<apex> against per run (rotating)
//   VENDORS_MIN_FOOTER       2          distinct edu sites that must name a non-BD-hosted vendor
//   VENDORS_PRUNE_TRIES      3          drop a vendor after this many reverse-IPs yielding zero BD hosts
//   VENDORS_CONCURRENCY      6          parallel HTML fetches (polite — these are small BD servers)
//   VENDORS_TIMEOUT_MS       15000      per-page HTTP timeout
//   VENDORS_HTML_CAP         524288     max bytes read per page (rest of the body is discarded)
//   VENDORS_SNOWBALL         1          0 disables the rank-15 outbound-link pass
//   VENDORS_MAX_CANDIDATES   20000      hard cap on the candidate Set (memory guard)
//   VENDORS_GOV_PORTALS      moedu.gov.bd,banbeis.gov.bd,dpe.gov.bd,nctb.gov.bd,bteb.gov.bd
//   VENDORS_BLOCKLIST_TTL_H  168        re-derive the gov-boilerplate blocklist weekly
//   VENDORS_DRY_RUN          0          1 = do everything except POST /harvest
//   VENDORS_DEBUG            0          1 = log every gate decision
//
// CADENCE: systemd timer every 6h. Pass A is the slow one (~80 page fetches); B and C rotate a small
// slice per run so crt.sh and rapiddns are never hammered, and cover the whole vendor list over a day.
// ─────────────────────────────────────────────────────────────────────────────────────────────────

import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";

import {
  API_BASE_DEFAULT, CACHE_DIR,
  loadBdRanges, isBdHost, isBdHostDetail, resolveA,
  eduLexicon, alive, normHost,
  seen, markSeen, loadSeen,
  submit, mapLimit,
} from "./bdgate.mjs";

const env = process.env;
const num = (v, d) => (Number.isFinite(Number(v)) && Number(v) > 0 ? Number(v) : d);

const API_BASE = (env.API_BASE || API_BASE_DEFAULT).replace(/\/+$/, "");
const TOKEN = env.SHARED_TOKEN || "";
const STATE_FILE = env.VENDORS_STATE || path.join(CACHE_DIR, "vendors-state.json");
const BLOCK_FILE = path.join(CACHE_DIR, "vendors-blocklist.json");
const CURSOR_SOURCE = env.VENDORS_CURSOR_SOURCE || "vendors";
const MAX_LEADS = num(env.VENDORS_LEADS, 80);
const MAX_REVIP = num(env.VENDORS_REVIP, 8);
const MAX_CRTSH = Number(env.VENDORS_CRTSH ?? 1);
const MIN_FOOTER = num(env.VENDORS_MIN_FOOTER, 2);
const CONCURRENCY = num(env.VENDORS_CONCURRENCY, 6);
const TIMEOUT_MS = num(env.VENDORS_TIMEOUT_MS, 15000);
const HTML_CAP = num(env.VENDORS_HTML_CAP, 512 * 1024);
const SNOWBALL = env.VENDORS_SNOWBALL !== "0";
const MAX_CANDIDATES = num(env.VENDORS_MAX_CANDIDATES, 20000);
const REVIP_MAX = num(env.VENDORS_REVIP_MAX, 400);
const PRUNE_TRIES = num(env.VENDORS_PRUNE_TRIES, 3);
const GOV_PORTALS = (env.VENDORS_GOV_PORTALS || "moedu.gov.bd,banbeis.gov.bd,dpe.gov.bd,nctb.gov.bd,bteb.gov.bd")
  .split(",").map((s) => s.trim()).filter(Boolean);
const BLOCK_TTL_MS = num(env.VENDORS_BLOCKLIST_TTL_H, 168) * 3600 * 1000;
const DRY_RUN = env.VENDORS_DRY_RUN === "1";
const DEBUG = env.VENDORS_DEBUG === "1";

const UA = "Mozilla/5.0 (compatible; bd-hack-audit/1.0; +https://javeditsolution.com)";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const dbg = (...a) => { if (DEBUG) console.error("[vendors]", ...a); };
const log = (...a) => console.log("[vendors]", ...a);

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// SEED VENDORS
//
// eduman.com.bd and shikkhaloy.com are VERIFIED (both on 65.60.45.202, hosting real .edu.bd schools).
// The rest are seeds only — an entry here buys nothing on its own. A seed that does not resolve, or
// resolves somewhere with no BD tenants, simply produces zero and costs one DNS lookup. The list is
// meant to be OUTGROWN by the footer loop, not maintained by hand.
// ═════════════════════════════════════════════════════════════════════════════════════════════════
const SEED_VENDORS = [
  "eduman.com.bd",        // verified 65.60.45.202
  "shikkhaloy.com",       // verified 65.60.45.202
  "shikkhaloy.com.bd",
  "edusoftbd.com",
  "onnorokom.com",
  "amarschool.com.bd",
  "schoolzonebd.com",
  "edutechbd.com",
  "banglaschool.com.bd",
  "eshikkha.net",
];

// Hosts that are never a vendor and never a lead: CDNs, social, analytics, platforms. This is a
// STATIC floor under the derived gov-boilerplate blocklist, not a substitute for it.
const NEVER = new RegExp(
  "(^|\\.)(" + [
    "google", "googleapis", "gstatic", "googletagmanager", "google-analytics", "doubleclick",
    "facebook", "fb", "fbcdn", "instagram", "twitter", "x", "linkedin", "youtube", "youtu",
    "whatsapp", "telegram", "tiktok", "pinterest", "vimeo",
    "cloudflare", "cloudflareinsights", "jsdelivr", "unpkg", "cdnjs", "bootstrapcdn", "fontawesome",
    "jquery", "wordpress", "wp", "w3", "mozilla", "apple", "microsoft", "office", "bing",
    "adobe", "gravatar", "wixstatic", "wix", "squarespace", "shopify", "godaddy", "namecheap",
    "github", "githubusercontent", "gitlab", "sourceforge", "archive", "wikipedia", "wikimedia",
    "paypal", "visa", "mastercard", "amazon", "amazonaws", "akamai", "akamaihd", "fastly",
    "sectigo", "digicert", "letsencrypt", "comodoca", "geotrust", "verisign", "entrust",
    "schema", "ogp", "purl", "creativecommons", "example", "localhost",
  ].join("|") + ")\\.[a-z.]+$"
);

// ── tiny helpers ────────────────────────────────────────────────────────────────────────────────
const isBdTld = (h) => /\.bd$/.test(h);
/** Registrable apex. .bd is a 3-label registry (x.edu.bd), everything else is 2 (x.com). */
function apexOf(h) {
  const p = String(h || "").split(".").filter(Boolean);
  if (p.length < 2) return "";
  return isBdTld(h) && p.length >= 3 ? p.slice(-3).join(".") : p.slice(-2).join(".");
}
/** True when `h` sits strictly INSIDE the DNS zone of `apex` — registry proof, not a name test. */
const inZoneOf = (h, apex) => h !== apex && h.endsWith("." + apex);

const VALID_HOST = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$/;
function cleanHost(raw) {
  let h = normHost(raw) || "";
  // MEASURED: the first live run admitted dhakaeducationboard.gov.bd AND www.dhakaeducationboard.gov.bd
  // as two separate leads. `www` is never a distinct site — unlike a real subdomain such as
  // result.xyz.edu.bd, which harvest-crtsh.mjs deliberately keeps because it can be hacked on its own.
  if (h.startsWith("www.")) h = h.slice(4);
  if (!h || !VALID_HOST.test(h)) return "";
  if (NEVER.test(h)) return "";
  if (/^\d+\.\d+\.\d+\.\d+$/.test(h)) return "";
  return h;
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// Capped streaming HTML fetch. Never buffers a whole response: reads chunks until HTML_CAP, then
// aborts. A BD school site on a shared host can serve a 40MB page of injected spam — that is exactly
// the kind of site this system targets, so the cap is load-bearing, not a nicety.
// ═════════════════════════════════════════════════════════════════════════════════════════════════
async function fetchHtml(host) {
  for (const scheme of ["https", "http"]) {
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), TIMEOUT_MS);
    try {
      const r = await fetch(`${scheme}://${host}/`, {
        redirect: "follow",
        signal: ac.signal,
        headers: { "user-agent": UA, accept: "text/html,*/*" },
      });
      if (!r.ok || !r.body) { clearTimeout(timer); continue; }
      const ct = r.headers.get("content-type") || "";
      if (ct && !/html|xml|text/i.test(ct)) { clearTimeout(timer); try { ac.abort(); } catch {} continue; }
      const dec = new TextDecoder("utf-8", { fatal: false });
      let out = "", got = 0;
      for await (const chunk of r.body) {
        got += chunk.length;
        out += dec.decode(chunk, { stream: true });
        if (got >= HTML_CAP) { try { ac.abort(); } catch {} break; }
      }
      clearTimeout(timer);
      // final URL matters: many BD schools redirect the apex to www or to the vendor's tenant host
      return { html: out, finalHost: cleanHost(new URL(r.url).hostname) || host, bytes: got };
    } catch { clearTimeout(timer); }
  }
  return null;
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// RANK 14a — the footer regex. "Developed by / Powered by / Designed by / Maintained by".
//
// Deliberately anchored on the ANCHOR TAG rather than on free text: a vendor credit is almost always
// a link, and the href is an exact hostname while the visible text is a brand name we would have to
// guess a domain from. Two shapes are matched:
//   <a href="https://vendor.com">…Developed by…</a>      credit inside the link text
//   Developed by <a href="https://vendor.com">Vendor</a>  credit before the link
// A window of 220 chars keeps a footer credit from binding to an unrelated link elsewhere on the page.
// ═════════════════════════════════════════════════════════════════════════════════════════════════
const CREDIT = "(?:develop|design|maintain|power|creat|built|made)(?:ed|ped|ned)?\\s*(?:&amp;|&|and)?\\s*(?:by|:)";
const RE_CREDIT_THEN_LINK = new RegExp(CREDIT + "[^<]{0,60}(?:<[^>]+>\\s*){0,4}<a[^>]+href\\s*=\\s*[\"']([^\"'>]+)", "gi");
const RE_LINK_THEN_CREDIT = new RegExp("<a[^>]+href\\s*=\\s*[\"']([^\"'>]+)[\"'][^>]*>(?:[^<]|<(?!/a)[^>]*>){0,220}?" + CREDIT, "gi");

/**
 * Vendor hostnames credited in a page's footer.
 * @param {string} html @param {string} selfHost @returns {Set<string>}
 */
export function footerVendors(html, selfHost) {
  const out = new Set();
  const selfApex = apexOf(selfHost);
  // The credit lives in the footer; scanning only the tail also bounds the regex cost on a huge page.
  const tail = html.length > 60000 ? html.slice(-60000) : html;
  for (const re of [RE_CREDIT_THEN_LINK, RE_LINK_THEN_CREDIT]) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(tail)) && out.size < 12) {
      let href = m[1];
      if (!/^https?:\/\//i.test(href)) continue;          // relative link = self-credit, not a vendor
      let h = "";
      try { h = cleanHost(new URL(href).hostname); } catch {}
      if (!h) continue;
      const a = apexOf(h);
      if (!a || a === selfApex) continue;                 // a site crediting itself is not a vendor
      out.add(a);
    }
  }
  return out;
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// RANK 15 — outbound-link snowball. Exported so the SCANNER can call it over HTML it has ALREADY
// fetched, at zero marginal request cost. That is the whole point of rank 15: the scanner downloads
// every queued site's homepage anyway, and the link graph in that HTML is free intake.
//
//   import { snowballHosts } from "./harvest-vendors.mjs";
//   const hosts = snowballHosts(html, host, blocklist);   // pure string work, no I/O
//
// The caller still owes every returned host the full bdgate admission — this returns CANDIDATES.
// ═════════════════════════════════════════════════════════════════════════════════════════════════
const RE_HREF = /<a[^>]+href\s*=\s*["']((?:https?:)?\/\/[^"'>\s]+)/gi;

/**
 * @param {string} html @param {string} selfHost @param {Set<string>} blocklist @returns {Set<string>}
 */
export function snowballHosts(html, selfHost, blocklist = new Set()) {
  const out = new Set();
  const selfApex = apexOf(selfHost);
  RE_HREF.lastIndex = 0;
  let m;
  while ((m = RE_HREF.exec(html)) && out.size < 400) {
    let h = "";
    try { h = cleanHost(new URL(m[1].startsWith("//") ? "https:" + m[1] : m[1]).hostname); } catch {}
    if (!h) continue;
    const a = apexOf(h);
    if (!a || a === selfApex) continue;
    if (blocklist.has(a) || blocklist.has(h)) continue;
    const lex = eduLexicon(h);
    if (lex.isSpammy) continue;                            // never snowball into casino spam
    out.add(h);
  }
  return out;
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// RANK 15b — the gov-boilerplate blocklist, derived from the INTERSECTION of government portals.
//
// Every BD education site links moedu.gov.bd, mygov.bd, forms.gov.bd, bangladesh.gov.bd and the
// national-portal furniture. Left alone, the snowball converges on that boilerplate and drowns the
// real signal. An intersection is the right derivation because it is SELF-MAINTAINING: a host is
// boilerplate precisely when two independent government portals both link it. No hand-curated list to
// go stale, and a genuinely interesting school is never on two ministry portals.
// ═════════════════════════════════════════════════════════════════════════════════════════════════
async function govBlocklist() {
  try {
    const st = JSON.parse(await fsp.readFile(BLOCK_FILE, "utf8"));
    if (Date.now() - (st.ts || 0) < BLOCK_TTL_MS && Array.isArray(st.hosts) && st.hosts.length) {
      log(`blocklist: ${st.hosts.length} hosts from cache (age ${((Date.now() - st.ts) / 3600000).toFixed(1)}h)`);
      return new Set(st.hosts);
    }
  } catch {}

  const counts = new Map();
  let portalsOk = 0;
  for (const p of GOV_PORTALS) {
    const res = await fetchHtml(p);
    if (!res) { log(`blocklist: ${p} — unreachable, skipped`); continue; }
    portalsOk++;
    const hosts = new Set();
    RE_HREF.lastIndex = 0;
    let m;
    while ((m = RE_HREF.exec(res.html))) {
      let h = "";
      try { h = cleanHost(new URL(m[1].startsWith("//") ? "https:" + m[1] : m[1]).hostname); } catch {}
      if (h) { hosts.add(h); hosts.add(apexOf(h)); }
    }
    for (const h of hosts) counts.set(h, (counts.get(h) || 0) + 1);
    log(`blocklist: ${p} — ${hosts.size} outbound hosts`);
  }

  // INTERSECTION: seen on 2+ independent portals. With <2 portals reachable there is no intersection
  // to take, so fall back to cache/empty rather than blocklisting one portal's entire link list.
  if (portalsOk < 2) {
    log("blocklist: fewer than 2 portals reachable — no intersection, using empty blocklist");
    return new Set();
  }
  const hosts = [...counts.entries()].filter(([, c]) => c >= 2).map(([h]) => h);
  // The portals themselves are boilerplate by definition.
  for (const p of GOV_PORTALS) { hosts.push(p, apexOf(p)); }
  const set = new Set(hosts.filter(Boolean));
  try { await fsp.writeFile(BLOCK_FILE, JSON.stringify({ ts: Date.now(), hosts: [...set] })); } catch {}
  log(`blocklist: ${set.size} gov-boilerplate hosts from the intersection of ${portalsOk} portals`);
  return set;
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// STATE — the vendor list, persisted BOTH in D1 (via the Worker /cursor endpoint, so it survives the
// VM being rebuilt) and on local disk (so a Worker outage cannot lose a run's discoveries).
// ═════════════════════════════════════════════════════════════════════════════════════════════════
const MAX_VENDORS = 200;

async function loadState() {
  let st = { vendors: [], pending: {}, tries: {}, wins: {}, ipIdx: 0, ctIdx: 0 };
  try {
    const disk = JSON.parse(await fsp.readFile(STATE_FILE, "utf8"));
    if (disk && typeof disk === "object") st = { ...st, ...disk };
  } catch {}
  if (TOKEN) {
    try {
      const r = await fetch(API_BASE + "/cursor", {
        method: "POST",
        headers: { authorization: "Bearer " + TOKEN, "content-type": "application/json" },
        body: JSON.stringify({ source: CURSOR_SOURCE }),
        signal: AbortSignal.timeout(20000),
      });
      const j = await r.json().catch(() => ({}));
      if (j && j.cursor) {
        const remote = JSON.parse(j.cursor);
        if (Array.isArray(remote.vendors)) st.vendors = [...new Set([...st.vendors, ...remote.vendors])];
        st.ipIdx = Math.max(st.ipIdx || 0, remote.ipIdx || 0);
        st.ctIdx = Math.max(st.ctIdx || 0, remote.ctIdx || 0);
        // `pending` = vendor candidates still short of MIN_FOOTER corroborations. Merge by max count.
        for (const [k, v] of Object.entries(remote.pending || {})) {
          st.pending[k] = Math.max(st.pending[k] || 0, Number(v) || 0);
        }
        for (const key of ["tries", "wins"]) {
          for (const [k, v] of Object.entries(remote[key] || {})) {
            st[key][k] = Math.max(st[key][k] || 0, Number(v) || 0);
          }
        }
      }
    } catch (e) { dbg("cursor load failed", String(e).slice(0, 80)); }
  }
  st.vendors = [...new Set([...SEED_VENDORS, ...st.vendors])].slice(0, MAX_VENDORS);
  return st;
}

async function saveState(st) {
  const slim = {
    vendors: st.vendors.slice(0, MAX_VENDORS),
    // keep `pending` bounded — one hacked site's junk credit must not accumulate forever
    pending: Object.fromEntries(Object.entries(st.pending).slice(0, 300)),
    tries: st.tries, wins: st.wins,
    ipIdx: st.ipIdx | 0, ctIdx: st.ctIdx | 0,
  };
  try { await fsp.writeFile(STATE_FILE, JSON.stringify(slim)); } catch {}
  if (!TOKEN) return;
  try {
    await fetch(API_BASE + "/cursor", {
      method: "POST",
      headers: { authorization: "Bearer " + TOKEN, "content-type": "application/json" },
      body: JSON.stringify({ source: CURSOR_SOURCE, cursor: JSON.stringify(slim) }),
      signal: AbortSignal.timeout(20000),
    });
  } catch (e) { dbg("cursor save failed", String(e).slice(0, 80)); }
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// REVERSE-IP. rapiddns first (verified 200/93KB for 65.60.45.202 while writing this), Mnemonic PDNS
// as fallback (rank 7's endpoint — genuinely paginated, ~100 anonymous requests/day, so it is used
// only when rapiddns fails rather than as the primary).
// ═════════════════════════════════════════════════════════════════════════════════════════════════
const RE_TD = /<td>\s*([a-z0-9][a-z0-9.-]{2,251}[a-z0-9])\s*<\/td>/gi;

async function reverseIpRapid(ip) {
  const out = new Set();
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      const r = await fetch(`https://rapiddns.io/sameip/${ip}?full=1`, {
        headers: { "user-agent": UA }, signal: AbortSignal.timeout(60000),
      });
      if (!r.ok) { await sleep(attempt * 5000); continue; }
      const txt = await r.text();
      RE_TD.lastIndex = 0;
      let m;
      while ((m = RE_TD.exec(txt))) { const h = cleanHost(m[1]); if (h) out.add(h); }
      return out;
    } catch { await sleep(attempt * 5000); }
  }
  return out;
}

async function reverseIpMnemonic(ip) {
  const out = new Set();
  try {
    const r = await fetch(`https://api.mnemonic.no/pdns/v3/${ip}?limit=1000&offset=0`, {
      headers: { "user-agent": UA, accept: "application/json" }, signal: AbortSignal.timeout(60000),
    });
    if (!r.ok) return out;
    const j = await r.json().catch(() => null);
    for (const row of j?.data || []) { const h = cleanHost(row?.query); if (h) out.add(h); }
  } catch {}
  return out;
}

async function reverseIp(ip) {
  const hosts = await reverseIpRapid(ip);
  // MEASURED on 65.60.45.202: rapiddns returned EXACTLY 100 rows even with ?full=1. That is its
  // documented fake pagination (TOP60 rank 7), not the real co-tenant count — a school-SaaS box holds
  // hundreds. A round 100 therefore means TRUNCATED, so union in Mnemonic (limit=1000, real paging)
  // rather than accepting the cap. Also covers the plain rapiddns-is-down case.
  if (hosts.size === 0 || hosts.size % 100 === 0) {
    dbg(`rapiddns gave ${hosts.size} for ${ip} — truncated or empty, unioning mnemonic`);
    for (const h of await reverseIpMnemonic(ip)) hosts.add(h);
  }
  return hosts;
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// crt.sh %.<vendor_apex> — tenant subdomain enumeration straight out of the vendor's certificates.
// Same discipline as harvest-crtsh.mjs: 150s timeout (30s is why crt.sh "looked dead for 3 days"),
// backoff on 502/429, one apex per run by default.
// ═════════════════════════════════════════════════════════════════════════════════════════════════
async function crtshApex(apex) {
  const url = `https://crt.sh/?q=${encodeURIComponent("%." + apex)}&output=json&exclude=expired`;
  for (let attempt = 1; attempt <= 4; attempt++) {
    try {
      const r = await fetch(url, {
        headers: { "user-agent": UA, accept: "application/json" },
        signal: AbortSignal.timeout(150000),
      });
      if (r.status === 429 || r.status === 502 || r.status === 503) {
        dbg(`crt.sh ${apex} HTTP ${r.status}, backing off`);
        await sleep(attempt * 15000); continue;
      }
      if (!r.ok) { await sleep(attempt * 10000); continue; }
      const txt = await r.text();
      let rows; try { rows = JSON.parse(txt); } catch { return null; }
      const out = new Set();
      for (const row of Array.isArray(rows) ? rows : []) {
        for (const raw of String(row?.name_value || "").split("\n")) {
          let h = raw.trim().toLowerCase();
          if (h.startsWith("*.")) h = h.slice(2);
          h = cleanHost(h);
          if (h) out.add(h);
        }
      }
      return out;
    } catch { await sleep(attempt * 10000); }
  }
  return null;
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// ADMISSION. The one place a candidate can become a harvested row. Two rungs, both evidence-based:
//   1. bdgate.isBdHost()   — BD hosting IP / BD nameserver / .bd registry
//   2. vendor-tenant       — strict subdomain of a known vendor apex (DNS-zone proof)
// Then liveness, so the queue fills with sites rather than corpses.
// ═════════════════════════════════════════════════════════════════════════════════════════════════
async function admit(host, vendorApexes, stats) {
  const lex = eduLexicon(host);
  if (lex.isSpammy) { stats.rejSpam++; dbg("reject spam", host, lex.hits.join(",")); return null; }

  let reason = "";
  if (await isBdHost(host)) reason = "bd-host";
  else {
    for (const a of vendorApexes) if (inZoneOf(host, a)) { reason = "vendor-tenant:" + a; break; }
  }
  if (!reason) { stats.rejNotBd++; dbg("reject not-bd", host); return null; }

  if (!(await alive(host))) { stats.rejDead++; dbg("reject dead", host); return null; }

  // bd_score mirrors harvest-crtsh.mjs: institutional TLDs are the highest-value lead type.
  const bd_score = /\.(edu|ac|gov|mil)\.bd$/.test(host) ? 65 : (lex.isEdu ? 50 : 40);
  stats.admitted++;
  return { domain: host, bd_score, business: lex.isEdu ? "education" : "" };
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// MAIN
// ═════════════════════════════════════════════════════════════════════════════════════════════════
async function main() {
  const t0 = Date.now();
  if (!TOKEN) { console.error("[vendors] SHARED_TOKEN missing — /harvest, /cursor and /api/leads all need it"); process.exit(1); }

  const req = { pages: 0, revip: 0, crtsh: 0, api: 0 };
  const stats = { admitted: 0, rejSpam: 0, rejNotBd: 0, rejDead: 0 };

  await loadBdRanges();
  const seedInfo = await loadSeen(API_BASE, TOKEN).catch((e) => { dbg("loadSeen failed", String(e)); return { total: 0 }; });
  log(`seen-set: ${seedInfo.total} known hostnames`);

  const st = await loadState();
  log(`vendors: ${st.vendors.length} known (${SEED_VENDORS.length} seed + ${st.vendors.length - SEED_VENDORS.length} discovered), pending ${Object.keys(st.pending).length}`);

  const blocklist = await govBlocklist();
  req.pages += GOV_PORTALS.length;

  const candidates = new Set();      // host -> awaiting admission
  const addCand = (h) => { if (h && candidates.size < MAX_CANDIDATES && !seen(h)) candidates.add(h); };

  // ── PASS A — footer loop over confirmed education leads (also feeds rank 15 for free) ──────────
  let leads = [];
  try {
    const r = await fetch(`${API_BASE}/api/leads?limit=600&slim=1`, {
      headers: { authorization: "Bearer " + TOKEN }, signal: AbortSignal.timeout(60000),
    });
    req.api++;
    const j = await r.json().catch(() => ({}));
    const rows = Array.isArray(j.leads) ? j.leads : (Array.isArray(j.rows) ? j.rows : []);
    leads = rows
      .map((x) => cleanHost(x.domain))
      .filter(Boolean)
      // education first — those are the ones with a school-SaaS vendor in the footer
      .sort((a, b) => (eduLexicon(b).isEdu ? 1 : 0) - (eduLexicon(a).isEdu ? 1 : 0))
      .slice(0, MAX_LEADS);
  } catch (e) { console.error("[vendors] /api/leads failed:", String(e).slice(0, 120)); }
  log(`pass A: fetching footers of ${leads.length} confirmed leads (concurrency ${CONCURRENCY})`);

  const credited = new Map();        // vendor apex -> Set of education sites that credited it
  let snowballFound = 0;
  await mapLimit(leads, CONCURRENCY, async (host) => {
    const res = await fetchHtml(host);
    req.pages++;
    if (!res) return;
    for (const v of footerVendors(res.html, res.finalHost)) {
      if (blocklist.has(v) || NEVER.test(v)) continue;
      if (!credited.has(v)) credited.set(v, new Set());
      credited.get(v).add(apexOf(host));
    }
    if (SNOWBALL) {
      for (const h of snowballHosts(res.html, res.finalHost, blocklist)) { addCand(h); snowballFound++; }
    }
  });
  log(`pass A: ${credited.size} vendor candidates credited in footers; snowball produced ${snowballFound} raw outbound hosts`);

  // Promote vendor candidates. A single footer is NOT enough — see trap #2 in the header.
  const newVendors = [];
  for (const [apex, sites] of credited) {
    if (st.vendors.includes(apex)) continue;
    if (eduLexicon(apex).isSpammy) { log(`pass A: refusing spam-branded vendor ${apex}`); continue; }
    const corroborations = (st.pending[apex] || 0) + sites.size;
    const bdHosted = await isBdHost(apex);
    if (bdHosted || corroborations >= MIN_FOOTER) {
      newVendors.push(apex);
      st.vendors.push(apex);
      delete st.pending[apex];
      log(`pass A: NEW VENDOR ${apex} (${bdHosted ? "BD-hosted" : `${corroborations} independent footers`})`);
    } else {
      st.pending[apex] = corroborations;
      dbg(`pending vendor ${apex} — ${corroborations}/${MIN_FOOTER} corroborations`);
    }
  }
  st.vendors = [...new Set(st.vendors)].slice(0, MAX_VENDORS);

  // ── PASS B — reverse-IP the vendor boxes (rotating slice) ───────────────────────────────────────
  const vendorApexes = st.vendors;
  const rotB = Array.from({ length: Math.min(MAX_REVIP, vendorApexes.length) },
    (_, k) => vendorApexes[(st.ipIdx + k) % vendorApexes.length]);
  st.ipIdx = vendorApexes.length ? (st.ipIdx + rotB.length) % vendorApexes.length : 0;
  log(`pass B: reverse-IP on ${rotB.length} vendors — ${rotB.join(" ")}`);

  const ips = new Map();             // ip -> vendor that pointed at it
  for (const v of rotB) {
    for (const ip of await resolveA(v)) if (!ips.has(ip)) ips.set(ip, v);
  }
  log(`pass B: ${ips.size} distinct vendor IPs`);
  const fromVendor = new Map();      // candidate host -> vendor it came from, for the scoreboard below
  for (const [ip, v] of ips) {
    const hosts = await reverseIp(ip);
    req.revip++;
    // CDN GUARD. MEASURED: amarschool.com.bd is behind Cloudflare, so its A records are edge IPs
    // (104.21.33.250, 172.67.152.14) and reverse-IP returned 1087 and 1080 hosts — the co-tenants of
    // a global CDN, which prove nothing about anything. That single vendor cost ~2,000 pointless gate
    // lookups. A real school-SaaS box holds tens to low hundreds of tenants, so an oversized result is
    // by definition shared infrastructure and gets discarded whole. This is a SHAPE test rather than a
    // hard-coded CDN CIDR list, so it needs no maintenance and covers every proxy, not just Cloudflare.
    if (hosts.size > REVIP_MAX) {
      log(`pass B: ${ip} (${v}) — ${hosts.size} co-tenants, that is a CDN/proxy edge not a vendor box, DISCARDED`);
      await sleep(4000);
      continue;
    }
    let bdish = 0;
    for (const h of hosts) { if (isBdTld(h)) bdish++; addCand(h); if (!fromVendor.has(h)) fromVendor.set(h, v); }
    st.tries[v] = (st.tries[v] || 0) + 1;
    log(`pass B: ${ip} (${v}) — ${hosts.size} co-tenants, ${bdish} on .bd`);
    await sleep(4000);               // rapiddns is free and public; do not hammer it
  }

  // ── PASS C — crt.sh %.<vendor_apex> (rotating slice) ────────────────────────────────────────────
  const rotC = Array.from({ length: Math.min(MAX_CRTSH, vendorApexes.length) },
    (_, k) => vendorApexes[(st.ctIdx + k) % vendorApexes.length]);
  st.ctIdx = vendorApexes.length ? (st.ctIdx + rotC.length) % vendorApexes.length : 0;
  for (const v of rotC) {
    const hosts = await crtshApex(v);
    req.crtsh++;
    if (!hosts) { log(`pass C: ${v} — crt.sh unavailable (429/502/timeout), retried next run`); continue; }
    for (const h of hosts) addCand(h);
    log(`pass C: crt.sh %.${v} — ${hosts.size} certificate hostnames`);
    await sleep(20000);
  }

  // ── ADMISSION + SUBMIT ──────────────────────────────────────────────────────────────────────────
  log(`gate: ${candidates.size} candidates → bdgate`);
  const rows = [];
  await mapLimit([...candidates], Math.min(CONCURRENCY * 2, 12), async (h) => {
    const row = await admit(h, vendorApexes, stats);
    if (row && markSeen(row.domain)) rows.push(row);
  });

  log(`gate: ${stats.admitted} admitted / ${stats.rejNotBd} not-BD / ${stats.rejDead} dead / ${stats.rejSpam} spam-branded → ${rows.length} new-to-run`);

  // ── VENDOR PRUNING — the other half of "self-growing" ────────────────────────────────────────────
  // A list that only grows is a list that rots. The footer loop admits plausible-but-wrong vendors —
  // MEASURED: youtubeembedcode.com was promoted on 2 footers because it is a WordPress embed artifact
  // that appears in many themes' credit blocks. Junk like that is harmless per run but permanently
  // steals a slot in the rotating slice, so the list degrades over months. A vendor that has been
  // reverse-IP'd VENDOR_PRUNE_TRIES times and never yielded ONE admitted BD host is not a vendor.
  // Seeds are pruned too — an unverified seed has no more standing than a discovered one.
  for (const r of rows) { const v = fromVendor.get(r.domain); if (v) st.wins[v] = (st.wins[v] || 0) + 1; }
  const pruned = [];
  for (const v of [...st.vendors]) {
    if (v === "eduman.com.bd" || v === "shikkhaloy.com") continue;      // verified by hand, never prune
    if ((st.tries[v] || 0) >= PRUNE_TRIES && !(st.wins[v] > 0)) {
      st.vendors = st.vendors.filter((x) => x !== v);
      delete st.tries[v]; delete st.wins[v];
      pruned.push(v);
    }
  }
  if (pruned.length) log(`prune: dropped ${pruned.length} barren vendors after ${PRUNE_TRIES} tries each — ${pruned.join(" ")}`);

  let res = { found: 0, inserted: 0, dups: 0, ok: true };
  if (rows.length && !DRY_RUN) {
    res = await submit(API_BASE, TOKEN, "vendors", rows);
    if (!res.ok) console.error("[vendors] SUBMIT REPORTED A FAILURE — see the bdgate message above");
  } else if (DRY_RUN) {
    log(`DRY RUN — would have posted ${rows.length} rows`);
  }

  await saveState(st);

  const secs = ((Date.now() - t0) / 1000).toFixed(0);
  const mb = (process.memoryUsage().rss / 1048576).toFixed(0);
  log(`DONE in ${secs}s — requests: ${req.pages} pages + ${req.revip} reverse-IP + ${req.crtsh} crt.sh + ${req.api} api`);
  log(`DONE — vendors ${vendorApexes.length} (+${newVendors.length} new), candidates ${candidates.size}, admitted ${rows.length}, found ${res.found}, INSERTED ${res.inserted}, dups ${res.dups}, rss ${mb}MB`);
  if (rows.length) log(`sample: ${rows.slice(0, 10).map((r) => r.domain).join(" ")}`);
}

// Importable as a library (snowballHosts / footerVendors) without running the harvest.
const isMain = process.argv[1] && fs.realpathSync(process.argv[1]) === fs.realpathSync(new URL(import.meta.url).pathname);
if (isMain) main().catch((e) => { console.error("[vendors] fatal:", e); process.exit(1); });
