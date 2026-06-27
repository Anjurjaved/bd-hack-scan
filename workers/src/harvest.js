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
  await env.DB.batch([
    env.DB.prepare("INSERT INTO source_state (source,last_run,total_harvested,enabled) VALUES (?,?,?,1) ON CONFLICT(source) DO UPDATE SET last_run=excluded.last_run, total_harvested=total_harvested+?").bind(source, now, inserted, inserted),
    env.DB.prepare("UPDATE counters SET value=value+? WHERE metric='total_harvested'").bind(inserted),
    env.DB.prepare("UPDATE counters SET value=value+? WHERE metric='total_domains'").bind(inserted),
  ]);
  return inserted;
}

export async function harvestReverseIp(env) {
  const SEEDN = Number(env.RIP_SEED || 25), MAXIP = Number(env.RIP_MAX_IPS || 12);
  const cur = await env.DB.prepare("SELECT value FROM counters WHERE metric='rip_seed_cursor'").first();
  let off = cur ? Number(cur.value) : 0;
  let rs = await env.DB.prepare("SELECT domain FROM domains WHERE domain LIKE '%.bd' ORDER BY rowid LIMIT ? OFFSET ?").bind(SEEDN, off).all();
  let seeds = (rs.results || []).map((r) => r.domain);
  if (!seeds.length) { off = 0; rs = await env.DB.prepare("SELECT domain FROM domains WHERE domain LIKE '%.bd' ORDER BY rowid LIMIT ?").bind(SEEDN).all(); seeds = (rs.results || []).map((r) => r.domain); }
  const ips = new Set();
  for (const s of seeds) {
    const ip = await doh(s);
    if (ip && !/^(104\.21\.|172\.67\.|104\.16\.|172\.64\.|188\.114\.|162\.159\.)/.test(ip)) ips.add(ip);
  }
  const ipList = [...ips].slice(0, MAXIP);
  const found = new Map();
  for (const ip of ipList) {
    try {
      // free HackerTarget per-IP quota is exhausted on shared Cloudflare egress IPs; a free
      // API key (env HACKERTARGET_KEY) makes the quota per-KEY so it works from the Worker.
      const kq = env.HACKERTARGET_KEY ? `&apikey=${env.HACKERTARGET_KEY}` : "";
      const r = await fetch(`https://api.hackertarget.com/reverseiplookup/?q=${ip}${kq}`, { headers: { "user-agent": "Mozilla/5.0" }, signal: AbortSignal.timeout(12000) });
      const txt = await r.text();
      if (/api count exceeded|too many|rate limit/i.test(txt)) break;
      for (const line of txt.split("\n")) {
        const dom = registrable(line.trim());
        if (dom && !found.has(dom) && !HOST_PROVIDERS.has(dom)) found.set(dom, { domain: dom, bd: 25 });
      }
    } catch (e) { /* skip this IP */ }
  }
  const inserted = await insertDomains(env, "reverse-ip", [...found.values()]);
  await env.DB.prepare("INSERT INTO counters (metric,value) VALUES ('rip_seed_cursor',?) ON CONFLICT(metric) DO UPDATE SET value=?").bind(off + SEEDN, off + SEEDN).run();
  await env.DB.prepare("INSERT INTO events (kind,domain,detail,ts) VALUES ('harvest','reverse-ip',?,?)").bind(`${ipList.length} IPs -> ${found.size} domains, ${inserted} new`, Math.floor(Date.now() / 1000)).run();
  return { seeds: seeds.length, ips: ipList.length, found: found.size, inserted };
}

// ---- BD business directories (Worker-friendly: sitemap -> listing pages -> business website) ----
const DIR_SOURCES = [
  { key: "bdtradeinfo", sitemap: "https://bdtradeinfo.com/sitemap-yellow-pages.xml", filter: "/company/", apex: "bdtradeinfo.com" },
  { key: "businessdirectory", sitemap: "https://businessdirectory.com.bd/wp-sitemap-posts-ait-item-1.xml", filter: "/item/", apex: "businessdirectory.com.bd" },
  { key: "bdbusinessdirectory", sitemap: "https://bdbusinessdirectory.com/business-directory-sitemap.xml", filter: "", apex: "bdbusinessdirectory.com" },
];
const DIR_SKIP = /facebook\.|fb\.com|instagram\.|twitter\.|x\.com|linkedin\.|youtube\.|youtu\.be|wa\.me|whatsapp\.|t\.me|telegram\.|pinterest\.|tiktok\.|google\.|goo\.gl|g\.page|bit\.ly|gravatar\.|wp\.com|w\.org|wordpress\.|gstatic\.|googleapis\.|schema\.org|example\.com|cloudflare|jsdelivr\.|fontawesome\.|bootstrapcdn\.|jquery\.|gmpg\.org/i;

function extractWebsite(text, apex) {
  const cands = [];
  for (const m of text.matchAll(/"url"\s*:\s*"([^"]+)"/gi)) cands.push(m[1]);
  for (const m of text.matchAll(/(?:web\s*site|website|web)\s*[:\-]?\s*(?:<\/[^>]+>\s*)*(?:<a[^>]+href=['"])?\s*((?:https?:\/\/)?[a-z0-9.\-]+\.[a-z]{2,}[^\s'"<>]*)/gi)) cands.push(m[1]);
  let n = 0;
  for (const m of text.matchAll(/<a\b[^>]*\bhref\s*=\s*['"]([^'"]+)['"]/gi)) { cands.push(m[1]); if (++n > 300) break; }
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
  const MAX = Number(env.DIR_MAX || 40);
  const cur = await env.DB.prepare("SELECT value FROM counters WHERE metric='dir_cursor'").first();
  const ci = cur ? Number(cur.value) : 0;
  const src = DIR_SOURCES[ci % DIR_SOURCES.length];
  let locs = [];
  try {
    const r = await fetch(src.sitemap, { headers: { "user-agent": "Mozilla/5.0" }, signal: AbortSignal.timeout(20000) });
    const txt = (await r.text()).slice(0, 4000000);
    locs = [...txt.matchAll(/<loc>\s*([^<\s]+)\s*<\/loc>/gi)].map((m) => m[1]);
    if (src.filter) { const f = locs.filter((u) => u.includes(src.filter)); if (f.length) locs = f; }
  } catch (e) { await bumpCursor(env, ci); return { source: src.key, inserted: 0, error: "sitemap " + String(e).slice(0, 50) }; }
  if (!locs.length) { await bumpCursor(env, ci); return { source: src.key, inserted: 0, note: "no listings" }; }

  const offRow = await env.DB.prepare("SELECT value FROM counters WHERE metric=?").bind("dir_off_" + src.key).first();
  let off = (offRow ? Number(offRow.value) : 0) % locs.length;
  const batch = [];
  for (let i = 0; i < MAX && i < locs.length; i++) batch.push(locs[(off + i) % locs.length]);
  off = (off + batch.length) % locs.length;

  const found = new Map();
  await Promise.all(batch.map(async (u) => {
    try {
      const r = await fetch(u, { headers: { "user-agent": "Mozilla/5.0" }, signal: AbortSignal.timeout(12000) });
      const txt = (await r.text()).slice(0, 250000);
      const dom = extractWebsite(txt, src.apex);
      if (dom && !found.has(dom)) found.set(dom, { domain: dom, bd: 30 });
    } catch (e) { /* skip page */ }
  }));
  const inserted = await insertDomains(env, "directories", [...found.values()]);
  await env.DB.prepare("INSERT INTO counters (metric,value) VALUES (?,?) ON CONFLICT(metric) DO UPDATE SET value=?").bind("dir_off_" + src.key, off, off).run();
  await bumpCursor(env, ci);
  return { source: src.key, listings: locs.length, fetched: batch.length, found: found.size, inserted };
}
async function bumpCursor(env, ci) {
  await env.DB.prepare("INSERT INTO counters (metric,value) VALUES ('dir_cursor',?) ON CONFLICT(metric) DO UPDATE SET value=?").bind(ci + 1, ci + 1).run();
}

export async function harvestCrtsh(env) {
  try {
    const r = await fetch("https://crt.sh/?q=%25.bd&output=json&exclude=expired&limit=4000", { headers: { "user-agent": "Mozilla/5.0", accept: "application/json" }, signal: AbortSignal.timeout(25000) });
    if (!r.ok) return { inserted: 0 };
    const arr = await r.json();
    const found = new Map();
    for (const row of (Array.isArray(arr) ? arr : []).slice(0, 6000)) {
      for (const nm of String(row.name_value || "").split(/\n/)) {
        const dom = registrable(nm);
        if (dom && dom.endsWith(".bd") && !found.has(dom)) found.set(dom, { domain: dom, bd: 40 });
      }
    }
    const inserted = await insertDomains(env, "crtsh", [...found.values()]);
    return { found: found.size, inserted };
  } catch (e) { return { inserted: 0, error: String(e).slice(0, 80) }; }
}
