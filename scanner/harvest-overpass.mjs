// Overpass BD-business harvester — runs on the VM / Mac (Node), NOT the Worker: the full-Bangladesh Overpass
// query takes ~150s, which exceeds Cloudflare Worker request/subrequest limits (verified: /harvest_now times out
// at 175s). Here there is no timeout. Pulls every OSM feature physically inside Bangladesh that carries a
// website tag — GEO-confirmed BD businesses (hotels/hospitals/colleges/shops), the .com/.net long tail that
// pure IP/CT harvesting misses — WITH the OSM business name + phone, and POSTs them to the Worker's /harvest
// (which stores business+phone, unlike the Worker-native insertDomains). Free, no key.
//
//   SHARED_TOKEN=… node scanner/harvest-overpass.mjs
// Run daily on the VM via a systemd timer (or cron).

const API_BASE = (process.env.API_BASE || "https://bd-hack-audit-api.javed-it.workers.dev").replace(/\/+$/, "");
const TOKEN = process.env.SHARED_TOKEN || "";
const Q = `[out:json][timeout:180];area["ISO3166-1"="BD"][admin_level=2]->.bd;(nwr["website"](area.bd);nwr["contact:website"](area.bd););out tags;`;
const ENDPOINTS = ["https://overpass-api.de/api/interpreter", "https://overpass.kumi.systems/api/interpreter"];
const FOREIGN = new Set("af al dz ad ao aq ag ar am au at az bs bh bb by be bz bj bm bt bo ba bw br bn bg bf bi kh cm ca cv cf td cl cn km cg cd cr ci hr cu cy cz dk dj dm do ec eg sv gq er ee et fj fi fr ga gm ge de gh gr gl gd gt gn gw gy ht hn hk hu is in id ir iq ie il it jm jp jo kz ke ki kp kr kw kg la lv lb ls lr ly lt lu mo mk mg mw my mv ml mt mh mr mu mx md mc mn ma mz mm na nr np nl nz ni ne ng no om pk pw pa pg py pe ph pl pt qa ro ru rw sa sn rs sc sl sg sk si sb so za es lk sd sr sz se ch sy tw tj tz th tg tn tr tm ug ua ae gb uk us uy uz vu ve vn ye zm zw".split(" "));
const BD_SLD = new Set(["com", "gov", "edu", "org", "net", "ac", "mil", "info", "co"]);

function registrable(host) {
  if (!host) return null;
  let h = String(host).toLowerCase().trim().replace(/^\*?\.+/, "").replace(/^https?:\/\//, "").replace(/^www\./, "").replace(/[:/].*$/, "").replace(/\.$/, "");
  if (!/^[a-z0-9][a-z0-9.-]+\.[a-z]{2,}$/.test(h) || h.includes("..")) return null;
  if (/\.(png|jpe?g|gif|svg|css|js|ico|woff2?|ttf|pdf|zip|xml|json)$/.test(h)) return null;
  const p = h.split(".");
  if (p.length >= 3 && p[p.length - 1] === "bd" && BD_SLD.has(p[p.length - 2])) return p.slice(-3).join(".");
  return p.slice(-2).join(".");
}

async function main() {
  if (!TOKEN) { console.error("SHARED_TOKEN missing"); process.exit(1); }
  let text = "";
  for (const ep of ENDPOINTS) {
    try {
      console.log("[overpass] querying", ep, "…");
      const r = await fetch(ep, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded", "user-agent": "bd-hack-audit/1.0 (BD website security scanner)" },
        body: "data=" + encodeURIComponent(Q),
        signal: AbortSignal.timeout(240000),
      });
      if (r.ok) { text = await r.text(); if (text.includes('"elements"')) break; }
    } catch (e) { console.log("[overpass]", ep, "failed:", String(e).slice(0, 60)); }
  }
  if (!text) { console.error("overpass unavailable on all mirrors"); process.exit(1); }
  const els = (JSON.parse(text).elements) || [];
  const found = new Map();
  for (const e of els) {
    const t = e.tags || {};
    const dom = registrable(t.website || t["contact:website"] || "");
    if (!dom || FOREIGN.has(dom.split(".").pop()) || found.has(dom)) continue;
    found.set(dom, { domain: dom, bd_score: dom.endsWith(".bd") ? 50 : 28, business: (t.name || "").slice(0, 200), phone: (t.phone || t["contact:phone"] || "").slice(0, 40) });
  }
  const list = [...found.values()];
  let inserted = 0;
  for (let i = 0; i < list.length; i += 1500) {
    const chunk = list.slice(i, i + 1500);
    const r = await fetch(API_BASE + "/harvest", { method: "POST", headers: { authorization: "Bearer " + TOKEN, "content-type": "application/json" }, body: JSON.stringify({ source: "osm-overpass", domains: chunk }) });
    const j = await r.json().catch(() => ({}));
    inserted += j.inserted || 0;
  }
  console.log(`[overpass] ${els.length} OSM features -> ${list.length} BD sites -> ${inserted} NEW inserted`);
}
main().catch((e) => { console.error("fatal", e); process.exit(1); });
