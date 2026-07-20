// harvest.js — Worker-native domain harvesting (keeps the queue full 24/7, free, no card).
// reverseIp: snowball BD businesses. Seed = rotating known .bd domains -> DoH-resolve to their
// shared BD hosting IPs -> HackerTarget reverse-IP -> every co-hosted business (.com/.com.bd that
// never shows in the .bd zone). Newly-found .bd become future seeds, so it grows on its own.
// crtsh: pull fresh .bd certificate-transparency identities.

const HOST_PROVIDERS = new Set([
  "dhakacom.com", "link3.net", "exonhost.com", "webhostbd.com", "hostever.com", "bdwebservices.com",
  "alpha.net.bd", "aamranetworks.com", "bdcom.com", "adnsl.net", "cloudflare.com", "hostinger.com",
  "namecheap.com", "godaddy.com", "bluehost.com", "amazonaws.com", "digitalocean.com",
  "googleusercontent.com", "hostgator.com", "siteground.com", "cpanel.net", "litespeedtech.com",
  "hostnetbd.com", "sslwireless.com", "google.com", "facebook.com", "youtube.com",
]);
const BD_SLD = new Set(["com", "gov", "edu", "org", "net", "ac", "mil", "info", "co"]);

function registrable(host) {
  if (!host) return null;
  let h = String(host).toLowerCase().trim().replace(/^\*?\.+/, "").replace(/^www\./, "").replace(/[:/].*$/, "").replace(/\.$/, "");
  if (!/^[a-z0-9][a-z0-9.-]+\.[a-z]{2,}$/.test(h) || h.includes("..")) return null;
  if (/\.(png|jpe?g|gif|svg|css|js|ico|woff2?|ttf|pdf|zip|xml|json)$/.test(h)) return null;
  const p = h.split(".");
  if (p.length >= 3 && p[p.length - 1] === "bd" && BD_SLD.has(p[p.length - 2])) return p.slice(-3).join(".");
  return p.slice(-2).join(".");
}

async function doh(name) {
  try {
    const r = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=A`, { headers: { accept: "application/dns-json" }, signal: AbortSignal.timeout(6000) });
    const j = await r.json();
    const a = (j.Answer || []).find((x) => x.type === 1);
    return a ? a.data : null;
  } catch (e) { return null; }
}

// ---- BD-purity helpers (keep the harvest Bangladeshi-only) ----
// A domain on a country-code TLD that a BD business never uses = a FOREIGN business that merely
// happens to share a BD hosting server (a co-tenant). Dropping these at harvest time keeps the
// queue — and therefore the leads — Bangladeshi. Generic-use ccTLDs (io/co/me/tv/cc/ai) + all
// gTLDs are intentionally excluded so a BD business on .com/.org/.xyz/.co stays in.
const FOREIGN_TLD = new Set("af al dz ad ao aq ag ar am au at az bs bh bb by be bz bj bm bt bo ba bw br bn bg bf bi kh cm ca cv cf td cl cn km cg cd cr ci hr cu cy cz dk dj dm do ec eg sv gq er ee et fj fi fr ga gm ge de gh gr gl gd gt gn gw gy ht hn hk hu is in id ir iq ie il it jm jp jo kz ke ki kp kr kw kg la lv lb ls lr ly lt lu mo mk mg mw my mv ml mt mh mr mu mx md mc mn ma mz mm na nr np nl nz ni ne ng no om pk pw pa pg py pe ph pl pt qa ro ru rw sa sn rs sc sl sg sk si sb so za es lk sd sr sz se ch sy tw tj tz th tg tn tr tm ug ua ae gb uk us uy uz vu ve vn ye zm zw".split(" "));
function foreignCcTld(dom) { return FOREIGN_TLD.has((dom || "").split(".").pop()); }
// keep = a co-hosted domain we should queue: registrable, not a host/CDN, not a foreign-ccTLD co-tenant
function bdKeep(dom) { return dom && !HOST_PROVIDERS.has(dom) && !foreignCcTld(dom); }

// Bangladesh IPv4 ranges (ipdeny bd.zone) — sorted [start,end] int ranges, cached per isolate.
// Used to VERIFY that an IP discovered by snowball/recursion is actually inside BD before we trust
// it (keeps the IP-tree from drifting onto foreign hosting). Free, no key, Worker-fetchable.
let BD_RANGES = null;
function ipToInt(ip) { const p = String(ip).split("."); if (p.length !== 4) return -1; return ((+p[0] << 24) | (+p[1] << 16) | (+p[2] << 8) | +p[3]) >>> 0; }
async function loadBdRanges() {
  if (BD_RANGES) return BD_RANGES;
  const ranges = [];
  try {
    const r = await fetch("https://www.ipdeny.com/ipblocks/data/countries/bd.zone", { headers: { "user-agent": "Mozilla/5.0" }, signal: AbortSignal.timeout(10000) });
    const txt = await r.text();
    for (const line of txt.split("\n")) {
      const m = line.trim().match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)\/(\d+)$/);
      if (!m) continue;
      const base = (((+m[1]) << 24) | ((+m[2]) << 16) | ((+m[3]) << 8) | (+m[4])) >>> 0;
      const size = (+m[5]) >= 32 ? 1 : 2 ** (32 - (+m[5]));
      ranges.push([base, (base + size - 1) >>> 0]);
    }
    ranges.sort((a, b) => a[0] - b[0]);
  } catch (e) { /* leave empty → ipInBd returns false */ }
  BD_RANGES = ranges;
  return BD_RANGES;
}
async function ipInBd(ip) {
  const n = ipToInt(ip); if (n < 0) return false;
  const ranges = await loadBdRanges();
  let lo = 0, hi = ranges.length - 1;
  while (lo <= hi) { const mid = (lo + hi) >> 1; const [a, b] = ranges[mid]; if (n < a) hi = mid - 1; else if (n > b) lo = mid + 1; else return true; }
  return false;
}

async function insertDomains(env, source, rows) {
  if (!rows.length) return 0;
  const now = Math.floor(Date.now() / 1000);
  let inserted = 0;
  const PER = 14; // D1 caps bound params at 100/query (14*6=84)
  for (let i = 0; i < rows.length; i += PER) {
    const chunk = rows.slice(i, i + PER);
    const ph = chunk.map(() => "(?,?,?,?,?,?)").join(",");
    const binds = [];
    for (const r of chunk) binds.push(r.domain, source, r.bd || 0, "", "", now);
    const res = await env.DB.prepare("INSERT OR IGNORE INTO domains (domain,source,bd_score,business,phone,added_ts) VALUES " + ph).bind(...binds).run();
    inserted += (res.meta && res.meta.changes) || 0;
  }
  // harvest_log + daily_stats were written ONLY by the /harvest HTTP endpoint (index.js), i.e. only for the VM
  // and Mac pushes — so all 12 Worker-native harvesters (crux, ip-tree, lead-coip, reverse-ip, bd-ip-sweep …)
  // were invisible to the dashboard's Sources tab and to daily_stats.harvested. That understated some days by
  // ~900× (2026-07-16 read 43 harvested; domains.added_ts says 7,012) and is why "harvest has collapsed" has
  // been diagnosed more than once from an instrument rather than from the data.
  await env.DB.batch([
    env.DB.prepare("INSERT INTO harvest_log (source,found,new_domains,dups,ts) VALUES (?,?,?,?,?)").bind(source, rows.length, inserted, rows.length - inserted, now),
    env.DB.prepare("INSERT INTO source_state (source,last_run,total_harvested,enabled) VALUES (?,?,?,1) ON CONFLICT(source) DO UPDATE SET last_run=excluded.last_run, total_harvested=total_harvested+?").bind(source, now, inserted, inserted),
    env.DB.prepare("INSERT INTO daily_stats (day,harvested) VALUES (?,?) ON CONFLICT(day) DO UPDATE SET harvested=harvested+?").bind(dhakaDayH(now), inserted, inserted),
    env.DB.prepare("UPDATE counters SET value=value+? WHERE metric='total_harvested'").bind(inserted),
    env.DB.prepare("UPDATE counters SET value=value+? WHERE metric='total_domains'").bind(inserted),
  ]);
  return inserted;
}

// Dhaka is UTC+6 and every other day-bucket in this system uses that, so harvest must not silently use UTC.
function dhakaDayH(nowSec) {
  return new Date((nowSec + 6 * 3600) * 1000).toISOString().slice(0, 10);
}

async function setCounter(env, metric, v) {
  await env.DB.prepare("INSERT INTO counters (metric,value) VALUES (?,?) ON CONFLICT(metric) DO UPDATE SET value=?").bind(metric, v, v).run();
}
async function logHarvest(env, source, detail) {
  await env.DB.prepare("INSERT INTO events (kind,domain,detail,ts) VALUES ('harvest',?,?,?)").bind(source, detail.slice(0, 200), Math.floor(Date.now() / 1000)).run();
}
async function readCappedH(r, max) {
  if (!r.body) return (await r.text()).slice(0, max);
  const reader = r.body.getReader(); const chunks = []; let n = 0;
  try { while (n < max) { const { done, value } = await reader.read(); if (done) break; chunks.push(value); n += value.length; } } catch (e) {}
  try { await reader.cancel(); } catch (e) {}
  const buf = new Uint8Array(n); let o = 0; for (const c of chunks) { buf.set(c.subarray(0, Math.max(0, n - o)), o); o += c.length; }
  return new TextDecoder("utf-8", { fatal: false }).decode(buf.subarray(0, max));
}

// Common Crawl CDX — *.bd across the whole crawled web. FREE, no key, no signup, Worker-friendly.
// Walks one page per run (cursor); resets at the last page. Latest index id in CC_INDEX var.
export async function harvestCommonCrawl(env) {
  const idx = env.CC_INDEX || "CC-MAIN-2026-25";
  const cur = await env.DB.prepare("SELECT value FROM counters WHERE metric='cc_page'").first();
  let page = cur ? Number(cur.value) : 0;
  try {
    const r = await fetch(`https://index.commoncrawl.org/${idx}-index?url=*.bd&output=json&page=${page}`, { headers: { "user-agent": "Mozilla/5.0" }, signal: AbortSignal.timeout(28000) });
    if (r.status === 404 || r.status === 400) { await setCounter(env, "cc_page", 0); return { page, reset: true }; }
    const txt = await readCappedH(r, 320000); // ~first 800 records of the page (CPU/mem safe)
    const found = new Map();
    for (const line of txt.split("\n")) {
      if (!line.trim()) continue;
      let u; try { u = JSON.parse(line).url; } catch (e) { continue; }
      const dom = registrable(String(u || "").replace(/^https?:\/\//, "").split("/")[0]);
      if (dom && dom.endsWith(".bd") && !found.has(dom)) found.set(dom, { domain: dom, bd: 40 });
      if (found.size >= 700) break;
    }
    const inserted = await insertDomains(env, "commoncrawl", [...found.values()]);
    await setCounter(env, "cc_page", page + 1);
    await logHarvest(env, "commoncrawl", `page ${page}: ${found.size} .bd, ${inserted} new`);
    return { page, found: found.size, inserted };
  } catch (e) { return { page, error: String(e).slice(0, 70) }; }
}

export async function harvestReverseIp(env) {
  const SEEDN = Number(env.RIP_SEED || 25), MAXIP = Number(env.RIP_MAX_IPS || 20);
  const cur = await env.DB.prepare("SELECT value FROM counters WHERE metric='rip_seed_cursor'").first();
  let off = cur ? Number(cur.value) : 0;
  let rs = await env.DB.prepare("SELECT domain FROM domains WHERE bd_score >= 25 ORDER BY rowid LIMIT ? OFFSET ?").bind(SEEDN, off).all();
  let seeds = (rs.results || []).map((r) => r.domain);
  if (!seeds.length) { off = 0; rs = await env.DB.prepare("SELECT domain FROM domains WHERE bd_score >= 25 ORDER BY rowid LIMIT ?").bind(SEEDN).all(); seeds = (rs.results || []).map((r) => r.domain); }
  const ips = new Set();
  for (const s of seeds) {
    const ip = await doh(s);
    if (ip && !/^(104\.21\.|172\.67\.|104\.16\.|172\.64\.|188\.114\.|162\.159\.)/.test(ip)) ips.add(ip);
  }
  const ipList = [...ips].slice(0, MAXIP);
  const found = new Map();
  for (const ip of ipList) {
    if (!(await ipInBd(ip))) continue;   // BD-only: skip seeds that resolve to an international shared host
    // rapiddns works from the Worker's shared egress IP; HackerTarget needs a paid key there.
    for (const h of await reverseIpRapid(ip)) {
      const dom = registrable(h);
      if (dom && !found.has(dom) && bdKeep(dom)) found.set(dom, { domain: dom, bd: dom.endsWith(".bd") ? 50 : 30 });
    }
  }
  const inserted = await insertDomains(env, "reverse-ip", [...found.values()]);
  await env.DB.prepare("INSERT INTO counters (metric,value) VALUES ('rip_seed_cursor',?) ON CONFLICT(metric) DO UPDATE SET value=?").bind(off + SEEDN, off + SEEDN).run();
  await env.DB.prepare("INSERT INTO events (kind,domain,detail,ts) VALUES ('harvest','reverse-ip',?,?)").bind(`${ipList.length} IPs -> ${found.size} domains, ${inserted} new`, Math.floor(Date.now() / 1000)).run();
  return { seeds: seeds.length, ips: ipList.length, found: found.size, inserted };
}

// ---- BD business directories (Worker-friendly: sitemap -> listing pages -> business website) ----
// `via:"jina"` routes fetches through the r.jina.ai reader proxy — required for sites that block the
// Cloudflare Worker egress IP (bdtradeinfo returns EMPTY to workers but 200 via the proxy; verified
// 2026-06-30). `pages` caps listing pages/run (small for proxied sources to respect proxy limits).
// NOTE: bdtradeinfo + bdbusinessdirectory are Cloudflare-fronted and BLOCK the Cloudflare Worker
// egress IP — and the r.jina.ai reader-proxy also throttles Worker-origin traffic (verified
// 2026-06-30: both return empty to the Worker but 200 from a residential IP). They CANNOT be
// harvested from the cloud, so they're handled by the residential-IP Python booster instead
// (deploy/run_booster.sh via launchd → harvester/directories.py also covers kagoz.com). Only the two
// directories that DO respond to the Worker stay here (both confirmed live: ~30 + ~17 new/run).
const DIR_SOURCES = [
  { key: "businessdirectory", sitemap: "https://www.businessdirectory.com.bd/wp-sitemap.xml", child: "ait-item", filter: "/item/", apex: "businessdirectory.com.bd" },
  { key: "bangladeshbusinessdir", sitemap: "https://bangladeshbusinessdir.com/sitemap_index.xml", child: "listing-sitemap", filter: "", apex: "bangladeshbusinessdir.com" },
];

// Fetch a URL directly, or via the r.jina.ai reader proxy (bypasses Worker-IP blocks). Returns text.
async function dfetch(url, via, ms) {
  const t = ms || 18000;
  if (via === "jina") {
    const r = await fetch("https://r.jina.ai/" + url, { headers: { "user-agent": "Mozilla/5.0", "x-respond-with": "text" }, signal: AbortSignal.timeout(t) });
    return await r.text();
  }
  const r = await fetch(url, { headers: { "user-agent": "Mozilla/5.0" }, signal: AbortSignal.timeout(t) });
  return await r.text();
}
// Extract <loc> URLs from a sitemap; if the proxy/markdown stripped the XML tags, fall back to bare
// URLs on the source's own apex (so jina-proxied sitemaps still yield their listing URLs).
function locsFrom(txt, apex) {
  let locs = [...txt.matchAll(/<loc>\s*([^<\s]+)\s*<\/loc>/gi)].map((m) => m[1]);
  if (!locs.length) {
    const re = new RegExp("https?://[a-z0-9.\\-]*" + apex.replace(/\./g, "\\.") + "/[^\\s'\"<>)\\]]+", "gi");
    locs = [...new Set([...txt.matchAll(re)].map((m) => m[0].replace(/[.,)]+$/, "")))];
  }
  return locs;
}
const DIR_SKIP = /facebook\.|fb\.com|instagram\.|twitter\.|x\.com|linkedin\.|youtube\.|youtu\.be|wa\.me|whatsapp\.|t\.me|telegram\.|pinterest\.|tiktok\.|google\.|goo\.gl|g\.page|bit\.ly|gravatar\.|wp\.com|w\.org|wordpress\.|gstatic\.|googleapis\.|schema\.org|example\.com|cloudflare|jsdelivr\.|fontawesome\.|bootstrapcdn\.|jquery\.|gmpg\.org|visitorsdetective\.|crunchbase\.|similarweb\.|semrush\.|alexa\.|trustpilot\.|glassdoor\.|owler\.|zoominfo\.|dnb\.com|bbb\.org|statshow\.|siteworthtraffic\.|w3schools\.|basis\.org|tradekey\.|alibaba\.|indiamart\.|yellowpages\.|justdial\.|maps\.app/i;

function extractWebsite(text, apex) {
  const cands = [];
  for (const m of text.matchAll(/"url"\s*:\s*"([^"]+)"/gi)) cands.push(m[1]);
  for (const m of text.matchAll(/(?:web\s*site|website|web)\s*[:\-]?\s*(?:<\/[^>]+>\s*)*(?:<a[^>]+href=['"])?\s*((?:https?:\/\/)?[a-z0-9.\-]+\.[a-z]{2,}[^\s'"<>]*)/gi)) cands.push(m[1]);
  let n = 0;
  for (const m of text.matchAll(/<a\b[^>]*\bhref\s*=\s*['"]([^'"]+)['"]/gi)) { cands.push(m[1]); if (++n > 300) break; }
  // plain-text URLs (e.g. bdtradeinfo lists the website as bare text in an <h6>, no anchor)
  let p = 0;
  for (const m of text.matchAll(/https?:\/\/[a-z0-9.\-]+\.[a-z]{2,}[^\s'"<>,)]*/gi)) { cands.push(m[0]); if (++p > 300) break; }
  for (let raw of cands) {
    raw = (raw || "").trim();
    if (!raw || /^(#|mailto:|tel:|javascript:)/.test(raw)) continue;
    if (DIR_SKIP.test(raw)) continue;
    const dom = registrable(raw);
    if (!dom || dom === apex || DIR_SKIP.test(dom)) continue;
    if (dom.endsWith("." + apex) || apex.endsWith("." + dom)) continue;
    return dom;
  }
  return null;
}

export async function harvestDirectories(env) {
  const cur = await env.DB.prepare("SELECT value FROM counters WHERE metric='dir_cursor'").first();
  const ci = cur ? Number(cur.value) : 0;
  const src = DIR_SOURCES[ci % DIR_SOURCES.length];
  const MAX = Number(src.pages || env.DIR_MAX || 40);
  const smTimeout = src.via === "jina" ? 45000 : 22000; // jina has to fetch+process the page, so give it room
  let locs = [];
  try {
    const txt = (await dfetch(src.sitemap, src.via, smTimeout)).slice(0, 4000000);
    locs = locsFrom(txt, src.apex);
    // sitemap INDEX -> follow a rotating child listing-sitemap (bdbusinessdirectory, bangladeshbusinessdir, businessdirectory)
    if (src.child) {
      const children = locs.filter((u) => u.includes(src.child) && u.endsWith(".xml"));
      if (children.length) {
        const offc = await env.DB.prepare("SELECT value FROM counters WHERE metric=?").bind("dir_child_" + src.key).first();
        const cidx = (offc ? Number(offc.value) : 0) % children.length;
        try {
          const ctxt = (await dfetch(children[cidx], src.via, smTimeout)).slice(0, 4000000);
          const cl = locsFrom(ctxt, src.apex);
          if (cl.length) locs = cl;
        } catch (e) { /* keep index locs */ }
        await env.DB.prepare("INSERT INTO counters (metric,value) VALUES (?,?) ON CONFLICT(metric) DO UPDATE SET value=?").bind("dir_child_" + src.key, cidx + 1, cidx + 1).run();
      }
    }
    if (src.filter) { const f = locs.filter((u) => u.includes(src.filter)); if (f.length) locs = f; }
  } catch (e) { await bumpCursor(env, ci); return { source: src.key, inserted: 0, error: "sitemap " + String(e).slice(0, 50) }; }
  if (!locs.length) { await bumpCursor(env, ci); return { source: src.key, inserted: 0, note: "no listings" }; }

  const offRow = await env.DB.prepare("SELECT value FROM counters WHERE metric=?").bind("dir_off_" + src.key).first();
  let off = (offRow ? Number(offRow.value) : 0) % locs.length;
  const batch = [];
  for (let i = 0; i < MAX && i < locs.length; i++) batch.push(locs[(off + i) % locs.length]);
  off = (off + batch.length) % locs.length;

  const found = new Map();
  const grab = async (u) => {
    try {
      const txt = (await dfetch(u, src.via, src.via === "jina" ? 22000 : 12000)).slice(0, 250000);
      const dom = extractWebsite(txt, src.apex);
      if (dom && !found.has(dom)) found.set(dom, { domain: dom, bd: 30 });
    } catch (e) { /* skip page */ }
  };
  // small batch fetched in parallel — even for the jina proxy, batch.length (≤8 proxied) stays well
  // under the reader-proxy's per-minute budget while keeping the run fast enough for the cron window.
  await Promise.all(batch.map(grab));

  const inserted = await insertDomains(env, "directories", [...found.values()]);
  await env.DB.prepare("INSERT INTO counters (metric,value) VALUES (?,?) ON CONFLICT(metric) DO UPDATE SET value=?").bind("dir_off_" + src.key, off, off).run();
  await bumpCursor(env, ci);
  await logHarvest(env, "directories", `${src.key}: ${batch.length} pages -> ${found.size} sites, ${inserted} new`);
  return { source: src.key, listings: locs.length, fetched: batch.length, found: found.size, inserted };
}

// ---- Wikidata: Bangladeshi orgs/companies with an official website (P856, country=Q902) ----
// A clean structured firehose of LEGIT BD orgs (gov / edu / ngo / news / company) — precisely the
// kind of real sites that get hacked. Not CF-blocked, returns JSON. Paginates by OFFSET; cycles when
// exhausted (rows < limit -> reset to 0). Verified 2026-06-30.
export async function harvestWikidata(env) {
  const LIM = Number(env.WD_LIMIT || 200);
  const cur = await env.DB.prepare("SELECT value FROM counters WHERE metric='wd_offset'").first();
  let off = cur ? Number(cur.value) : 0;
  const sparql = `SELECT ?w WHERE { ?i wdt:P17 wd:Q902 ; wdt:P856 ?w . } ORDER BY ?i LIMIT ${LIM} OFFSET ${off}`;
  // query.wikidata.org occasionally 502/503s transiently — retry once before giving up for this run.
  let rows = null, lastErr = "wikidata error";
  for (let attempt = 0; attempt < 2 && rows === null; attempt++) {
    try {
      const r = await fetch("https://query.wikidata.org/sparql?format=json&query=" + encodeURIComponent(sparql), { headers: { "user-agent": "Mozilla/5.0 (bd-hack-audit research; mdanjurjaved@gmail.com)", accept: "application/sparql-results+json" }, signal: AbortSignal.timeout(28000) });
      if (!r.ok) { lastErr = "wikidata " + r.status; continue; }
      const j = await r.json();
      rows = ((j.results && j.results.bindings) || []).map((b) => b.w && b.w.value).filter(Boolean);
    } catch (e) { lastErr = "wikidata " + String(e).slice(0, 50); }
  }
  if (rows === null) return { error: lastErr };
  const found = new Map();
  for (const u of rows) {
    const dom = registrable(String(u).replace(/^https?:\/\//, "").split("/")[0]);
    if (dom && !found.has(dom) && !HOST_PROVIDERS.has(dom) && !DIR_SKIP.test(dom)) found.set(dom, { domain: dom, bd: dom.endsWith(".bd") ? 60 : 45 });
  }
  const inserted = await insertDomains(env, "wikidata", [...found.values()]);
  const next = rows.length < LIM ? 0 : off + LIM; // cycle when exhausted
  await setCounter(env, "wd_offset", next);
  await logHarvest(env, "wikidata", `offset ${off}: ${rows.length} orgs -> ${found.size} sites, ${inserted} new`);
  return { offset: off, rows: rows.length, found: found.size, inserted };
}
async function bumpCursor(env, ci) {
  await env.DB.prepare("INSERT INTO counters (metric,value) VALUES ('dir_cursor',?) ON CONFLICT(metric) DO UPDATE SET value=?").bind(ci + 1, ci + 1).run();
}

// ---- lead-coip: SHARED-IP lead multiplier (the 24/7 Worker port of harvester/lead_coip.py) ----
// Confirmed hacks -> their shared-host IP -> every co-hosted neighbour (prime victims). Also
// back-fills findings.ip so the dashboard can cluster leads by server. Bounded per run.
const CDN_RE = /^(104\.21\.|172\.67\.|104\.16\.|104\.1[789]\.|172\.6[456]\.|188\.114\.|162\.159\.|104\.2[678]\.|151\.101\.|199\.232\.)/;

async function reverseIpRapid(ip) {
  try {
    const r = await fetch(`https://rapiddns.io/sameip/${ip}?full=1`, { headers: { "user-agent": "Mozilla/5.0" }, signal: AbortSignal.timeout(12000) });
    const html = await readCappedH(r, 400000);
    const hosts = new Set();
    for (const m of html.matchAll(/>\s*([a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)+\.[a-z]{2,})\s*</gi)) hosts.add(m[1].toLowerCase());
    return [...hosts];
  } catch (e) { return []; }
}

// OTX (AlienVault) passive-DNS by-IP — free, NO key, Worker-fetchable (workflow-verified 2026-07-04).
// A SECOND, independent co-hosting source: for one BD hosting IP it returns up to 500 hostnames ever
// seen there (rapiddns often misses many). Complements reverseIpRapid so the shared-IP multiplier finds
// far more co-hosted BD victims. Capped per IP.
async function otxPassive(ip, cap = 250) {
  try {
    const r = await fetch(`https://otx.alienvault.com/api/v1/indicators/IPv4/${ip}/passive_dns`, { headers: { "user-agent": "Mozilla/5.0", accept: "application/json" }, signal: AbortSignal.timeout(12000) });
    if (!r.ok) return [];
    const j = await r.json();
    const hosts = new Set();
    for (const rec of (j.passive_dns || [])) { if (rec && rec.hostname) hosts.add(String(rec.hostname).toLowerCase()); if (hosts.size >= cap) break; }
    return [...hosts];
  } catch (e) { return []; }
}

export async function harvestLeadCoip(env) {
  const NRES = Number(env.LC_RESOLVE || 12), MAXIP = Number(env.LC_MAX_IPS || 10);
  // 1) back-fill the hosting IP of confirmed leads still missing one (powers the cluster view)
  const need = (await env.DB.prepare(
    "SELECT domain FROM findings WHERE confirmed=1 AND status!='rejected' AND (ip IS NULL OR ip='') ORDER BY id LIMIT ?"
  ).bind(NRES).all()).results || [];
  let stored = 0;
  const updates = [];
  for (const row of need) {
    const ip = await doh(row.domain);
    const val = (ip && !CDN_RE.test(ip)) ? ip : "cdn";   // sentinel: CDN/unresolved leads won't re-resolve every run
    if (val !== "cdn") stored++;
    updates.push(env.DB.prepare("UPDATE findings SET ip=? WHERE domain=?").bind(val, row.domain));
  }
  if (updates.length) await env.DB.batch(updates);

  // 2) reverse-IP a rotating slice of hotspot servers -> co-hosted neighbours -> queue them
  const allIps = ((await env.DB.prepare(
    "SELECT DISTINCT ip FROM findings WHERE confirmed=1 AND ip IS NOT NULL AND ip NOT IN ('','cdn') ORDER BY ip"
  ).all()).results || []).map((r) => r.ip);
  const curRow = await env.DB.prepare("SELECT value FROM counters WHERE metric='lc_ip_cursor'").first();
  let off = curRow ? Number(curRow.value) : 0;
  if (off >= allIps.length) off = 0;
  const slice = allIps.slice(off, off + MAXIP);
  const found = new Map();
  for (const ip of slice) {
    // ONLY multiply BD-hosted clusters: if a confirmed lead sits on an INTERNATIONAL shared host
    // (Shopify/Hetzner/…), its co-tenants are FOREIGN businesses — skip them so no foreign enters.
    if (!(await ipInBd(ip))) continue;
    // two independent co-hosting sources per hotspot IP — rapiddns (current DNS) + OTX passive-DNS
    // (historical, often 5-10× more hosts). Merge; the Map + INSERT OR IGNORE dedupe.
    const hosts = [...await reverseIpRapid(ip), ...await otxPassive(ip)];
    for (const h of hosts) {
      const dom = registrable(h);
      if (dom && !found.has(dom) && bdKeep(dom)) found.set(dom, { domain: dom, bd: 50 });
    }
  }
  const inserted = await insertDomains(env, "lead-coip", [...found.values()]);
  const nextOff = (off + slice.length) >= allIps.length ? 0 : off + slice.length;
  await setCounter(env, "lc_ip_cursor", nextOff);
  await logHarvest(env, "lead-coip", `${need.length} resolved(+${stored} ip), ${slice.length} servers -> ${found.size} neighbours, ${inserted} new`);
  return { resolved: stored, servers: slice.length, found: found.size, inserted };
}

// BD IP-space sweep — reverse-IP across Bangladesh's allocated IP blocks (ipdeny free CIDR list).
// Rotating: a window of CIDRs per run, sample a host IP in each, rapiddns reverse-IP -> BD-hosted
// domains. Supplementary firehose (blind IPs are lower-yield than the snowball, but it covers BD
// hosting we have no seed for). Bounded; no key, no card.
export async function harvestBdIpSweep(env) {
  // Systematic full-BD-space seeder. The old version blindly sampled ONE host IP per CIDR (very low
  // yield). Now it EXPLODES Bangladesh's allocated IP blocks (ipdeny bd.zone) into /24 bases and feeds
  // a rotating window of them into the ip_frontier (source='bdspace'), where the IP-tree's RapidDNS
  // CIDR sweeper reverse-IPs each /24 in ONE request (~256× more efficient). Over many runs this walks
  // the ENTIRE BD IPv4 space — the path to every BD-hosted business, not just the 18 known hosting
  // ASNs. Backlog-gated so the frontier never balloons: only tops up when the unswept queue is low.
  const MAXBLOCKS = Number(env.BDIP_BLOCKS || 250);
  const backlog = ((await env.DB.prepare("SELECT COUNT(*) c FROM ip_frontier WHERE yield<0").first()) || { c: 0 }).c;
  if (backlog > Number(env.FRONTIER_MAX || 4000)) return { skipped: "frontier backlog " + backlog };
  let cidrs = [];
  try {
    const r = await fetch("https://www.ipdeny.com/ipblocks/data/countries/bd.zone", { headers: { "user-agent": "Mozilla/5.0" }, signal: AbortSignal.timeout(15000) });
    cidrs = (await r.text()).split("\n").map((s) => s.trim()).filter((s) => /^\d+\.\d+\.\d+\.\d+\/\d+$/.test(s));
  } catch (e) { return { error: "ipdeny " + String(e).slice(0, 40) }; }
  if (!cidrs.length) return { cidrs: 0 };
  const curRow = await env.DB.prepare("SELECT value FROM counters WHERE metric='bdip_cursor'").first();
  let cur = curRow ? Number(curRow.value) : 0;
  const bases = new Set();
  let consumed = 0;
  for (let i = 0; i < cidrs.length && bases.size < MAXBLOCKS; i++) {
    const cidr = cidrs[(cur + i) % cidrs.length];
    const [net, bits] = cidr.split("/");
    const b = net.split(".").map(Number); const m = Number(bits);
    if (m >= 24) bases.add(`${b[0]}.${b[1]}.${b[2]}.0`);
    else { const n = Math.min(256, 1 << (24 - m)); for (let k = 0; k < n && bases.size < MAXBLOCKS; k++) { const t = b[2] + k; bases.add(`${b[0]}.${(b[1] + (t >> 8)) & 255}.${t & 255}.0`); } }
    consumed++;
  }
  const now = Math.floor(Date.now() / 1000);
  const arr = [...bases];
  let seeded = 0;
  for (let i = 0; i < arr.length; i += 50) {
    const res = await env.DB.batch(arr.slice(i, i + 50).map((ip) => env.DB.prepare("INSERT OR IGNORE INTO ip_frontier (ip,depth,yield,source,added_ts) VALUES (?,1,-1,'bdspace',?)").bind(ip, now)));
    for (const r of res) seeded += (r.meta && r.meta.changes) || 0;
  }
  await setCounter(env, "bdip_cursor", (cur + consumed) % cidrs.length);
  await logHarvest(env, "bd-ip-sweep", `seeded ${seeded} BD /24 into frontier (from ${consumed} CIDRs), cursor ${cur}->${(cur + consumed) % cidrs.length}`);
  return { cidrs: cidrs.length, consumed, blocks: arr.length, seeded, backlog };
}

// ============================================================================
// IP-TREE — the systematic BD shared-hosting gold-mine engine (CIDR /24 mode).
// "Bangladeshi website" = any domain hosted on a BD IP, ANY TLD (.com/.net/.xyz/.edu/.bd) — most BD
// businesses are .com/.net, so reverse-IP of BD hosting space is the ONLY way to find them (TLD can't
// tell you). The frontier is a queue of /24 BLOCKS. Each run: (1) seeds one BD hosting ASN's /24s +
// snowballs from confirmed leads' /24s; (2) sweeps a bounded slice of /24 blocks via RapidDNS CIDR
// mode (ONE request per /24 = ~256x more efficient than per-IP), keeping every registrable domain
// (CDN/junk stripped); (3) densifies — a dense /24 enqueues its neighbour /24s. Recurses: new domains
// resolve -> if on a BD IP, their /24 is enqueued. Bounded per run for the D1 free-tier write budget.
// Verified: one BD hosting /24 -> ~30-50 real BD businesses (brainstation23.com, skshospital.com.bd…).
// ============================================================================
const IPTREE_DENSE = 6; // registrable yield >= this on a /24 -> dense shared host, expand neighbours
// Junk that shows up as <script>/<link>/<a> refs in RapidDNS rows but is NOT co-hosted — strip it.
const CDN_JUNK = /(^|\.)(google|googleapis|gstatic|googleusercontent|cloudflare|jsdelivr|cdnjs|schema|w3|twitter|fbcdn|facebook|akamai|fastly|bootstrapcdn|jquery|fontawesome|gmpg|wordpress|gravatar|youtube|youtu|cloudns|remotewd|sucuri|incapsula|azureedge|amazonaws|microsoft|windows|apple|bing|yahoo|yandex|baidu|wixpress|squarespace|shopify|paypal|whatsapp|telegram|linkedin|instagram|pinterest|tiktok)\./;
// BD hosting / datacenter ASNs (telco/mobile ISPs excluded) — the dense space where BD businesses live
// (mostly .com/.net). Verified 2026-06-30: AmberIT/Dhakacom (23956) densest, + BDCOM, Link3, ExonHost,
// CodeForHost, WebHostBD, NazimHost, IT Nut, NamePart, BRACNet…
const HOSTING_ASNS = [
  23956, 24122, 7565, 23688, 24342, 139016, 134494, 140068, 138145, 153383, 154047, 151323, 58901, 138296, 132602, 64080, 45498, 137967,
  // +40 verified BD hosting / datacenter / ISP / transit ASNs (workflow-researched via bgp.he.net/country/BD, 2026-07-04),
  // ranked ~by announced IPv4 space. Dense hosting/DC (Tomato Web, Dot Internet, XeonBD, aamra, ADN, InterCloud, Coloasia,
  // CoLoCity, Netcocloud, NoorHost, SPNHOST, Bengalcloud, HOSTOMEGA, Pico Cloud…) + big national ISP/IIG space (Summit,
  // Fiber@Home, Earth, Apple Comm, bdHUB, Agni, Race, Windstream…) where BD businesses live on .com/.net.
  58717, 10075, 58682, 139009, 58715, 139901, 132884, 139931, 150178, 58656, 149994, 137491, 58655, 150748, 23923, 151412, 58945, 149765, 141731, 24323,
  56264, 9230, 58599, 38203, 38031, 63969, 134732, 58923, 133938, 154612, 136396, 138601, 138594, 134353, 137041, 141773, 153385, 63967, 141738, 149978,
];
const ip24 = (ip) => { const p = String(ip).split("."); return p.length === 4 ? `${p[0]}.${p[1]}.${p[2]}.0` : null; };
// Reverse-IP a whole /24 in ONE request (RapidDNS CIDR mode). Returns registrable BD-hosted domains
// (any TLD), CDN/junk stripped + collapsed to registrable (raw rows over-count ~3-5x via subdomains).
async function reverseIpCidr(base24) {
  try {
    const r = await fetch(`https://rapiddns.io/sameip/${base24}/24?full=1`, { headers: { "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" }, signal: AbortSignal.timeout(13000) });
    const html = await readCappedH(r, 700000);
    const regs = new Set();
    for (const m of html.matchAll(/>\s*([a-z0-9][a-z0-9.\-]*\.[a-z]{2,})\s*</gi)) {
      const h = m[1].toLowerCase();
      if (CDN_JUNK.test(h)) continue;
      const d = registrable(h);
      if (d && bdKeep(d)) regs.add(d);
    }
    return [...regs];
  } catch (e) { return []; }
}
// Seed the /24 frontier from ONE BD hosting ASN's announced prefixes per run (rotating) — systematic
// coverage of BD hosting space, not just snowball. RIPEstat is free, no key, Worker-fetchable.
async function seedHostingAsns(env) {
  const curRow = await env.DB.prepare("SELECT value FROM counters WHERE metric='asn_cursor'").first();
  const ci = curRow ? Number(curRow.value) : 0;
  const asn = HOSTING_ASNS[ci % HOSTING_ASNS.length];
  let prefixes = [];
  try {
    const r = await fetch(`https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS${asn}`, { headers: { "user-agent": "Mozilla/5.0" }, signal: AbortSignal.timeout(15000) });
    const j = await r.json();
    prefixes = ((j.data && j.data.prefixes) || []).map((p) => p.prefix).filter((p) => p && p.includes(".") && !p.includes(":"));
  } catch (e) { /* skip this run */ }
  const bases = new Set();
  for (const pfx of prefixes) {
    const [net, bits] = pfx.split("/");
    const b = net.split(".").map(Number); const m = Number(bits);
    if (m >= 24) bases.add(`${b[0]}.${b[1]}.${b[2]}.0`);
    else { const n = Math.min(1024, 1 << (24 - m)); for (let k = 0; k < n; k++) { const t = b[2] + k; bases.add(`${b[0]}.${(b[1] + (t >> 8)) & 255}.${t & 255}.0`); } }
    if (bases.size > 600) break;   // bound per-run ASN seed so the frontier never out-paces the sweeper (cursor still rotates all 18 ASNs over many runs)
  }
  const now = Math.floor(Date.now() / 1000);
  const arr = [...bases];
  for (let i = 0; i < arr.length; i += 50) await env.DB.batch(arr.slice(i, i + 50).map((ip) => env.DB.prepare("INSERT OR IGNORE INTO ip_frontier (ip,depth,yield,source,added_ts) VALUES (?,0,-1,'asn',?)").bind(ip, now)));
  await setCounter(env, "asn_cursor", ci + 1);
  return { asn, prefixes: prefixes.length, blocks: arr.length };
}
export async function harvestIpTree(env) {
  const SWEEP = Number(env.IPTREE_SWEEP || 14);    // /24 blocks swept per run (ip-tree now gets its own clean */20 invocation → full subreq budget)
  const RESOLVE = Number(env.IPTREE_RESOLVE || 8); // known domains resolved -> frontier per run
  const now = Math.floor(Date.now() / 1000);

  // 0) systematic seed: one hosting ASN's /24 blocks per run (rotates through HOSTING_ASNS).
  // Backlog-gated (same ceiling as bd-ip-sweep) so 58 ASNs + full BD-space seeding can't balloon the
  // unswept frontier faster than the CIDR sweeper drains it.
  let asnSeed = { blocks: 0 };
  const backlog0 = ((await env.DB.prepare("SELECT COUNT(*) c FROM ip_frontier WHERE yield<0").first()) || { c: 0 }).c;
  if (backlog0 < Number(env.FRONTIER_MAX || 4000)) { try { asnSeed = await seedHostingAsns(env); } catch (e) {} }

  // 1) snowball seed: resolve a rotating slice of known BD domains + confirmed leads -> their /24 base
  const seedCur = await env.DB.prepare("SELECT value FROM counters WHERE metric='iptree_seed_cursor'").first();
  let soff = seedCur ? Number(seedCur.value) : 0;
  let seeds = (await env.DB.prepare("SELECT domain FROM domains WHERE bd_score >= 30 ORDER BY rowid LIMIT ? OFFSET ?").bind(RESOLVE, soff).all()).results || [];
  if (!seeds.length) { soff = 0; seeds = (await env.DB.prepare("SELECT domain FROM domains WHERE bd_score >= 30 ORDER BY rowid LIMIT ?").bind(RESOLVE).all()).results || []; }
  const newBlocks = new Set();
  for (const s of seeds) { const ip = await doh(s.domain); if (ip && !CDN_RE.test(ip) && /^\d+\.\d+\.\d+\.\d+$/.test(ip)) newBlocks.add(ip24(ip)); }
  for (const r of (await env.DB.prepare("SELECT DISTINCT ip FROM findings WHERE confirmed=1 AND ip IS NOT NULL AND ip NOT IN ('','cdn') LIMIT 40").all()).results || [])
    if (/^\d+\.\d+\.\d+\.\d+$/.test(r.ip)) newBlocks.add(ip24(r.ip));
  newBlocks.delete(null);
  if (newBlocks.size) {
    // cap seed re-adds/run so the snowball can't perpetually out-grow the ASN gold-mine blocks (INSERT OR IGNORE already dedupes)
    const seedCap = Number(env.IPTREE_SEED_CAP || 40);
    const stmts = [...newBlocks].slice(0, seedCap).map((ip) => env.DB.prepare("INSERT OR IGNORE INTO ip_frontier (ip,depth,yield,source,added_ts) VALUES (?,0,-1,'seed',?)").bind(ip, now));
    for (let i = 0; i < stmts.length; i += 50) await env.DB.batch(stmts.slice(i, i + 50));
  }
  await setCounter(env, "iptree_seed_cursor", soff + seeds.length);

  // 2) SWEEP /24 blocks via RapidDNS CIDR mode — one request per /24.
  // FAIRNESS (the bug fix): the old `ORDER BY depth ASC, added_ts ASC` kept the oldest depth-0 'seed'
  // rows permanently on top, so the 624 ASN/dense24/nbr24 gold-mine blocks (30-68 BD domains each)
  // NEVER reached the 6/run cut-line → 0 swept. Round-robin per source (ROW_NUMBER within each source)
  // so every run pulls a mix from EVERY non-empty source and the dense ASN blocks actually drain.
  const todo = (await env.DB.prepare(
    "SELECT ip, depth FROM (" +
    "  SELECT ip, depth, source," +
    "    ROW_NUMBER() OVER (PARTITION BY source ORDER BY depth ASC, added_ts ASC) AS rnk" +
    "  FROM ip_frontier WHERE yield < 0" +
    ") ORDER BY rnk ASC, depth ASC LIMIT ?"
  ).bind(SWEEP).all()).results || [];
  let totalNew = 0, swept = 0, dense = 0;
  const recurse = new Set();
  for (const row of todo) {
    const base = ip24(row.ip) || row.ip;
    const regs = await reverseIpCidr(base);
    const found = regs.map((d) => ({ domain: d, bd: d.endsWith(".bd") ? 55 : 35 }));
    const inserted = await insertDomains(env, "ip-tree", found);
    totalNew += inserted; swept++;
    const y = regs.length;
    await env.DB.prepare("UPDATE ip_frontier SET yield=?, swept_ts=? WHERE ip=?").bind(y, now, row.ip).run();
    // 3) DENSIFY: a dense /24 -> enqueue its neighbour /24s (c±1..±2) at depth+1 (the tree grows outward)
    if (y >= IPTREE_DENSE && row.depth < 5) {
      dense++;
      const p = base.split(".").map(Number);
      const stmts = [];
      for (let d = -2; d <= 2; d++) { if (!d) continue; const c = p[2] + d; if (c < 0 || c > 255) continue; stmts.push(env.DB.prepare("INSERT OR IGNORE INTO ip_frontier (ip,depth,yield,source,added_ts) VALUES (?,?,-1,'nbr24',?)").bind(`${p[0]}.${p[1]}.${c}.0`, row.depth + 1, now)); }
      if (stmts.length) await env.DB.batch(stmts);
      regs.slice(0, 4).forEach((d) => recurse.add(d)); // sample new domains for IP recursion below
    }
  }
  // 4) RECURSION: resolve a few freshly-found domains -> if on a (non-CDN) IP, enqueue that /24 too.
  if (recurse.size) {
    const stmts = [];
    for (const d of [...recurse].slice(0, 8)) { const ip = await doh(d); if (ip && !CDN_RE.test(ip) && /^\d+\.\d+\.\d+\.\d+$/.test(ip) && await ipInBd(ip)) stmts.push(env.DB.prepare("INSERT OR IGNORE INTO ip_frontier (ip,depth,yield,source,added_ts) VALUES (?,2,-1,'recurse',?)").bind(ip24(ip), now)); }
    if (stmts.length) await env.DB.batch(stmts);
  }
  await logHarvest(env, "ip-tree", `swept ${swept} /24 (${dense} dense), ${totalNew} new domains, +${asnSeed.blocks} ASN(AS${asnSeed.asn || "?"}) +${newBlocks.size} seed blocks`);
  return { swept, dense, newDomains: totalNew, asnBlocks: asnSeed.blocks, seedBlocks: newBlocks.size };
}

// ---- CrUX Bangladesh top-list — the "smart, technical" BD firehose (workflow-verified 2026-07-04) ----
// Chrome UX Report country top-list for Bangladesh: ~238k origins BD Chrome users actually visit — ALL
// TLDs (~15.7k .bd + the rest .com/.net/.xyz that TLD alone can't reveal). Free, no key, GitHub raw
// (never blocks the Worker egress), gzip → DecompressionStream. Walks a rotating window per run via a
// cursor (CPU/mem-safe); cycles when exhausted. This is the modern replacement for scraping business
// directories. Scoring: .bd = 55 (sure BD, high scan priority); non-.bd = 20 (below the is_bd=25
// hosting threshold on purpose, so a globally-popular .com a BD user merely visits — softonic/savefrom
// — is NOT auto-tagged BD; its BD-ness is then decided accurately by hosting-IP at scan time).
export async function harvestCrux(env) {
  const month = env.CRUX_MONTH || "202605";        // latest published list; bump monthly (YYYYMM)
  const WIN = Number(env.CRUX_WIN || 1200);         // origins queued per run
  const url = `https://raw.githubusercontent.com/zakird/crux-top-lists/main/data/country/bd/${month}.csv.gz`;
  let body = [];
  try {
    const r = await fetch(url, { headers: { "user-agent": "Mozilla/5.0" }, signal: AbortSignal.timeout(28000) });
    if (!r.ok || !r.body) return { error: "crux " + r.status };
    const txt = await new Response(r.body.pipeThrough(new DecompressionStream("gzip"))).text();
    const lines = txt.split("\n");
    body = (lines[0] || "").toLowerCase().includes("origin") ? lines.slice(1) : lines;  // drop the "origin,rank" header
  } catch (e) { return { error: "crux " + String(e).slice(0, 60) }; }
  if (!body.length) return { rows: 0 };
  const cur = await env.DB.prepare("SELECT value FROM counters WHERE metric='crux_off'").first();
  let off = cur ? Number(cur.value) : 0;
  if (off >= body.length) off = 0;
  // CrUX "country=BD" means the origin was VISITED by Bangladeshi users — not that it IS Bangladeshi. bdKeep()
  // only drops known host providers and foreign ccTLDs, so this admitted investing.com, eccouncil.org,
  // medallia.com, alightmotion.com and a Peru trekking site as BD domains, ~3,240/day, and it has already
  // contributed 35,645 rows = 18.4% of the corpus. That is the 2026-07-04 "foreign dominates" regression coming
  // back through a different door, and the standing rule from 2026-07-19 is explicit: a non-.bd domain may be
  // admitted by HOSTING IP only, never by name. `.bd` still needs no lookup — the registry is the proof.
  const found = new Map();
  const GATE = Number(env.CRUX_IP_GATE || 220);    // DNS+range lookups per run; the rest wait for the next window
  let gated = 0, rejected = 0;
  for (let i = 0; i < WIN && off + i < body.length; i++) {
    const line = body[off + i]; if (!line) continue;
    const dom = registrable(line.split(",")[0].trim().replace(/^https?:\/\//, "").split("/")[0]);
    if (!dom || !bdKeep(dom) || found.has(dom)) continue;
    if (dom.endsWith(".bd")) { found.set(dom, { domain: dom, bd: 55 }); continue; }
    if (gated >= GATE) continue;                    // out of lookup budget — do not admit unverified
    gated++;
    let ip = "";
    try { ip = await doh(dom); } catch (e) { /* unresolvable → not admitted */ }
    if (ip && /^\d+\.\d+\.\d+\.\d+$/.test(ip) && !CDN_RE.test(ip) && (await ipInBd(ip))) found.set(dom, { domain: dom, bd: 35, ip });
    else rejected++;
  }
  const inserted = await insertDomains(env, "crux", [...found.values()]);
  const next = off + WIN >= body.length ? 0 : off + WIN;
  await setCounter(env, "crux_off", next);
  await logHarvest(env, "crux", `${month} off ${off}/${body.length}: ${found.size} BD-verified origins (${gated} ip-checked, ${rejected} rejected as non-BD), ${inserted} new`);
  return { month, offset: off, total: body.length, found: found.size, ipChecked: gated, rejected, inserted };
}

// RIPEstat country-resource-list — the REGISTRY's own authoritative BD IPv4 allocation (2314 prefixes).
// Explodes BD prefixes → /24 and seeds the ip_frontier (source='bdripe') for the CIDR sweeper. More
// authoritative + current than the ipdeny mirror bd-ip-sweep uses; the two overlap (INSERT OR IGNORE
// dedupes) and together give complete BD IP-space coverage. Backlog-gated. Free, no key.
export async function harvestRipeBd(env) {
  const MAXBLOCKS = Number(env.RIPE_BLOCKS || 250);
  const backlog = ((await env.DB.prepare("SELECT COUNT(*) c FROM ip_frontier WHERE yield<0").first()) || { c: 0 }).c;
  if (backlog > Number(env.FRONTIER_MAX || 4000)) return { skipped: "frontier backlog " + backlog };
  let prefixes = [];
  try {
    const r = await fetch("https://stat.ripe.net/data/country-resource-list/data.json?resource=BD", { headers: { "user-agent": "Mozilla/5.0" }, signal: AbortSignal.timeout(25000) });
    const j = await r.json();
    prefixes = ((((j.data || {}).resources) || {}).ipv4 || []).filter((p) => typeof p === "string" && p.includes("/") && !p.includes(":"));
  } catch (e) { return { error: "ripe " + String(e).slice(0, 40) }; }
  if (!prefixes.length) return { prefixes: 0 };
  const curRow = await env.DB.prepare("SELECT value FROM counters WHERE metric='ripe_cursor'").first();
  let cur = curRow ? Number(curRow.value) : 0;
  const bases = new Set();
  let consumed = 0;
  for (let i = 0; i < prefixes.length && bases.size < MAXBLOCKS; i++) {
    const pfx = prefixes[(cur + i) % prefixes.length];
    const [net, bits] = pfx.split("/");
    const b = net.split(".").map(Number); const m = Number(bits);
    consumed++;
    if (b.length !== 4 || b.some((x) => !(x >= 0 && x <= 255)) || !(m >= 0 && m <= 32)) continue;
    if (m >= 24) bases.add(`${b[0]}.${b[1]}.${b[2]}.0`);
    else { const n = Math.min(256, 1 << (24 - m)); for (let k = 0; k < n && bases.size < MAXBLOCKS; k++) { const t = b[2] + k; bases.add(`${b[0]}.${(b[1] + (t >> 8)) & 255}.${t & 255}.0`); } }
  }
  const now = Math.floor(Date.now() / 1000);
  const arr = [...bases];
  let seeded = 0;
  for (let i = 0; i < arr.length; i += 50) {
    const res = await env.DB.batch(arr.slice(i, i + 50).map((ip) => env.DB.prepare("INSERT OR IGNORE INTO ip_frontier (ip,depth,yield,source,added_ts) VALUES (?,1,-1,'bdripe',?)").bind(ip, now)));
    for (const r of res) seeded += (r.meta && r.meta.changes) || 0;
  }
  await setCounter(env, "ripe_cursor", (cur + consumed) % prefixes.length);
  await logHarvest(env, "ripe-bd", `seeded ${seeded} BD /24 (from ${consumed}/${prefixes.length} RIPE prefixes)`);
  return { prefixes: prefixes.length, consumed, blocks: arr.length, seeded, backlog };
}

// Wikipedia — Bangladeshi higher-ed institution websites (MediaWiki wikitext API; clean JSON, Worker-
// friendly, no key). Enumerates the official .edu.bd/.ac.bd/.edu (+ some .com) sites of BD universities
// & colleges — high-value hack-scan targets. Rotates a few list pages; edu domains get bd=60 (priority).
const WIKI_EDU_PAGES = ["List_of_universities_in_Bangladesh", "List_of_medical_colleges_in_Bangladesh", "List_of_universities_and_colleges_in_Bangladesh"];
const WIKI_SKIP = /wikipedia\.|wikimedia\.|wiktionary\.|wikidata\.|web\.archive|archive\.org|doi\.org|worldcat|4icu\.|webometrics|unirank|topuniversities|academicimpact|asian-university\.org|banbeis|ugc[.-]|moedu\.|portal\.gov\.bd|google\.|youtube\.|facebook\.|twitter\.|x\.com|jstor|researchgate|scholar\.|creativecommons/i;
export async function harvestWikiEdu(env) {
  const cur = await env.DB.prepare("SELECT value FROM counters WHERE metric='wikiedu_cursor'").first();
  const ci = cur ? Number(cur.value) : 0;
  const page = WIKI_EDU_PAGES[ci % WIKI_EDU_PAGES.length];
  let wt = "";
  try {
    const r = await fetch(`https://en.wikipedia.org/w/api.php?action=parse&page=${encodeURIComponent(page)}&prop=wikitext&format=json`, { headers: { "user-agent": "Mozilla/5.0 (bd-hack-audit; mdanjurjaved@gmail.com)" }, signal: AbortSignal.timeout(25000) });
    const j = await r.json();
    wt = (((j.parse || {}).wikitext) || {})["*"] || "";
  } catch (e) { await setCounter(env, "wikiedu_cursor", ci + 1); return { page, error: "wiki " + String(e).slice(0, 40) }; }
  const found = new Map();
  for (const m of wt.matchAll(/https?:\/\/([a-z0-9.\-]+\.[a-z]{2,})/gi)) {
    if (WIKI_SKIP.test(m[1])) continue;
    const dom = registrable(m[1]);
    if (!dom || !bdKeep(dom) || found.has(dom)) continue;
    const edu = /\.(edu|ac)\.bd$/.test(dom) || dom.endsWith(".edu");
    found.set(dom, { domain: dom, bd: edu ? 60 : 35 });
  }
  const inserted = await insertDomains(env, "wiki-edu", [...found.values()]);
  await setCounter(env, "wikiedu_cursor", ci + 1);
  await logHarvest(env, "wiki-edu", `${page}: ${found.size} edu sites, ${inserted} new`);
  return { page, found: found.size, inserted };
}

export async function harvestCrtsh(env) {
  // crt.sh is slow/overloaded — try twice, accept whatever returns.
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const r = await fetch("https://crt.sh/?q=%25.bd&output=json&exclude=expired", { headers: { "user-agent": "Mozilla/5.0", accept: "application/json" }, signal: AbortSignal.timeout(30000) });
      if (!r.ok) continue;
      const txt = await readCappedH(r, 3000000);
      let arr; try { arr = JSON.parse(txt); } catch (e) { continue; }
      const found = new Map();
      for (const row of (Array.isArray(arr) ? arr : []).slice(0, 20000)) {
        for (const nm of String(row.name_value || "").split(/\n/)) {
          const dom = registrable(nm);
          if (dom && dom.endsWith(".bd") && !found.has(dom)) found.set(dom, { domain: dom, bd: 40 });
        }
      }
      const inserted = await insertDomains(env, "crtsh", [...found.values()]);
      await logHarvest(env, "crtsh", `${found.size} .bd identities, ${inserted} new`);
      return { found: found.size, inserted };
    } catch (e) { if (attempt === 1) return { inserted: 0, error: String(e).slice(0, 80) }; }
  }
  return { inserted: 0, error: "crt.sh unavailable" };
}

// harvestOverpass — OpenStreetMap features physically INSIDE Bangladesh that carry a website tag. These are
// GEO-confirmed BD businesses (hotels, hospitals, colleges, shops, factories) — the .com/.net/.org long tail
// that pure IP/CT harvesting misses, at very high BD precision (the point is on BD soil). One Overpass area
// query, FREE, no key. Returns the same ~1.4k set each run (INSERT OR IGNORE dedups), so it lives on a slow
// cron. bd_score: .bd→50, non-.bd→28 (geo-confirmed BD → sits just above the 25 region threshold; scan-time
// is_bd still refines by hosting IP/content). Verified live: rajukcollege.net, hotellakecastle.com, khulna.gov.bd.
export async function harvestOverpass(env) {
  const q = `[out:json][timeout:120];area["ISO3166-1"="BD"][admin_level=2]->.bd;(nwr["website"](area.bd);nwr["contact:website"](area.bd););out tags;`;
  const endpoints = ["https://overpass-api.de/api/interpreter", "https://overpass.kumi.systems/api/interpreter"];
  let text = "";
  for (const ep of endpoints) {
    try {
      const r = await fetch(ep, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded", "user-agent": "bd-hack-audit/1.0 (BD website security scanner)" },
        body: "data=" + encodeURIComponent(q),
        signal: AbortSignal.timeout(150000),
      });
      if (!r.ok) continue;
      text = await readCappedH(r, 6000000);
      if (text.includes('"elements"')) break;
    } catch (e) { /* try next mirror */ }
  }
  if (!text) return { inserted: 0, error: "overpass unavailable" };
  let els;
  try { els = (JSON.parse(text).elements) || []; } catch (e) { return { inserted: 0, error: "overpass parse" }; }
  const found = new Map();
  for (const e of els) {
    const t = e.tags || {};
    const dom = registrable(t.website || t["contact:website"] || "");
    if (!dom || !bdKeep(dom) || found.has(dom)) continue;
    found.set(dom, { domain: dom, bd: dom.endsWith(".bd") ? 50 : 28 });
  }
  const inserted = await insertDomains(env, "osm-overpass", [...found.values()]);
  await logHarvest(env, "osm-overpass", `${els.length} OSM features -> ${found.size} sites, ${inserted} new`);
  return { found: found.size, inserted, features: els.length };
}
