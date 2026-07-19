// urlscan.io BD harvester — runs on the VM / Mac (Node). urlscan indexes every URL its community + crawlers
// scan, tagged by the page's hosting-IP GEO. `page.country:BD` therefore returns BD-HOSTED sites on ANY TLD
// (.com/.org/.io/…) — the exact non-.bd long tail that IP/CT/Overpass miss, decided by hosting IP = the
// project's BD definition. FREE, no key (public search, rate-limited). Paginates via search_after; loops a set
// of BD-scoped queries. POSTs apex domains to the Worker /harvest. Run periodically on the VM.
//
//   SHARED_TOKEN=… node scanner/harvest-urlscan.mjs
// Optional env: URLSCAN_KEY (a free key raises limits), PAGES (per-query pages, default 25), MAXQ.

const API_BASE = (process.env.API_BASE || "https://bd-hack-audit-api.javed-it.workers.dev").replace(/\/+$/, "");
const TOKEN = process.env.SHARED_TOKEN || "";
const KEY = process.env.URLSCAN_KEY || "";
const PAGES = Math.max(1, Number(process.env.PAGES || 25));
const SLEEP = Number(process.env.SLEEP_MS || 1600);   // be polite to the free API
const FOREIGN = new Set("af al dz ad ao aq ag ar am au at az bs bh bb by be bz bj bm bt bo ba bw br bn bg bf bi kh cm ca cv cf td cl cn km cg cd cr ci hr cu cy cz dk dj dm do ec eg sv gq er ee et fj fi fr ga gm ge de gh gr gl gd gt gn gw gy ht hn hk hu is in id ir iq ie il it jm jp jo kz ke ki kp kr kw kg la lv lb ls lr ly lt lu mo mk mg mw my mv ml mt mh mr mu mx md mc mn ma mz mm na nr np nl nz ni ne ng no om pk pw pa pg py pe ph pl pt qa ro ru rw sa sn rs sc sl sg sk si sb so za es lk sd sr sz se ch sy tw tj tz th tg tn tr tm ug ua ae gb uk us uy uz vu ve vn ye zm zw".split(" "));

// BD-scoped queries — country GEO (the big one) + TLD-scoped + a few keyword/city angles to page past the 10k/query cap.
const QUERIES = [
  "page.country:BD",
  "page.country:BD AND page.tlsIssuer:*",
  "domain:*.com.bd", "domain:*.org.bd", "domain:*.net.bd", "domain:*.edu.bd", "domain:*.gov.bd", "domain:*.ac.bd",
  "page.country:BD AND task.tags:phishing",
  "page.city:Dhaka", "page.city:Chittagong", "page.city:Sylhet", "page.city:Khulna",
];

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const hdr = KEY ? { "API-Key": KEY, "user-agent": "bd-hack-audit/1.0" } : { "user-agent": "bd-hack-audit/1.0" };

function apexOk(a) {
  if (!a || !/^[a-z0-9][a-z0-9.-]+\.[a-z]{2,}$/.test(a)) return false;
  return !FOREIGN.has(a.split(".").pop());
}

async function searchAll(q) {
  const found = new Map();
  let after = "";
  for (let pg = 0; pg < PAGES; pg++) {
    const url = `https://urlscan.io/api/v1/search/?q=${encodeURIComponent(q)}&size=100` + (after ? `&search_after=${after}` : "");
    let j;
    try {
      const r = await fetch(url, { headers: hdr, signal: AbortSignal.timeout(25000) });
      if (r.status === 429) { await sleep(5000); continue; }
      if (!r.ok) break;
      j = await r.json();
    } catch (e) { break; }
    const res = j.results || [];
    if (!res.length) break;
    for (const row of res) {
      const a = ((row.page || {}).apexDomain || "").toLowerCase();
      if (apexOk(a) && !found.has(a)) found.set(a, { domain: a, bd_score: a.endsWith(".bd") ? 45 : 26 });
    }
    if (!j.has_more) break;
    const last = res[res.length - 1];
    if (!last.sort) break;
    after = last.sort.join(",");
    await sleep(SLEEP);
  }
  return found;
}

async function main() {
  if (!TOKEN) { console.error("SHARED_TOKEN missing"); process.exit(1); }
  const all = new Map();
  for (const q of QUERIES) {
    const f = await searchAll(q);
    for (const [k, v] of f) if (!all.has(k)) all.set(k, v);
    console.log(`[urlscan] "${q}" -> ${f.size} apex (cumulative ${all.size})`);
    await sleep(SLEEP);
  }
  const list = [...all.values()];
  let inserted = 0;
  for (let i = 0; i < list.length; i += 1500) {
    const chunk = list.slice(i, i + 1500);
    const r = await fetch(API_BASE + "/harvest", { method: "POST", headers: { authorization: "Bearer " + TOKEN, "content-type": "application/json" }, body: JSON.stringify({ source: "urlscan", domains: chunk }) });
    const j = await r.json().catch(() => ({}));
    inserted += j.inserted || 0;
  }
  console.log(`[urlscan] ${list.length} unique BD apex -> ${inserted} NEW inserted`);
}
main().catch((e) => { console.error("fatal", e); process.exit(1); });
