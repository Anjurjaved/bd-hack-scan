// scan.js — Cloudflare-Worker scan engine. A cron tick claims a few unscanned
// domains from D1, runs a lean multi-layer scan (port of detect.py's highest-signal
// layers), Bayesian-fuses to a verdict (score.py), applies the genuine-vs-hacked gate
// (classify.py), optionally Groq Stage-2-verifies gambling hits, and ingests findings.
// Free-tier safe: tiny batch per invocation, capped page reads, per-domain claim.
import * as S from "./signatures.js";

const UA_BR = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36";
const UA_GB = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";
const REF_G = "https://www.google.com/";

const RE_TAGSTRIP = /<(script|style|noscript|template)\b[\s\S]*?<\/\1>/gi;
const RE_TAGS = /<[^>]+>/g;
const RE_ENT = /&[a-z#0-9]+;/gi;
const RE_WS = /\s+/g;
const RE_TITLE = /<title[^>]*>([\s\S]*?)<\/title>/i;
const RE_HTMLLANGTITLE = /<html[^>]*\blang="([a-zA-Z]{2})/i;

function stripHtml(h) {
  return h.replace(RE_TAGSTRIP, " ").replace(RE_TAGS, " ").replace(RE_ENT, " ").replace(RE_WS, " ").trim();
}
function getTitle(h) {
  const m = RE_TITLE.exec(h);
  return m ? m[1].replace(RE_WS, " ").trim().slice(0, 120) : "";
}
function distinct(text, src) {
  const rx = new RegExp(src, "gi");
  const out = new Set();
  let m;
  let guard = 0;
  while ((m = rx.exec(text)) && guard++ < 400) out.add(m[0].toLowerCase());
  return [...out];
}
function hostOf(url) {
  if (!url) return "";
  let s = url.toLowerCase().replace(/^[a-z]+:\/\//, "");
  s = s.replace(/\/.*$/, "").replace(/:.*$/, "");
  return s;
}
function sameHost(host, reg) {
  return host === reg || host.endsWith("." + reg);
}

async function readCapped(r, max = 170000) {
  if (!r.body) {
    const t = await r.text();
    return t.slice(0, max);
  }
  const reader = r.body.getReader();
  const chunks = [];
  let received = 0;
  try {
    while (received < max) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
      received += value.length;
    }
  } catch (e) { /* truncated read is fine */ }
  try { await reader.cancel(); } catch (e) {}
  const buf = new Uint8Array(received);
  let o = 0;
  for (const c of chunks) { buf.set(c.subarray(0, Math.max(0, received - o)), o); o += c.length; }
  return new TextDecoder("utf-8", { fatal: false }).decode(buf.subarray(0, max));
}

async function fetchPage(url, ua, referer, ms = 11000) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), ms);
  try {
    const headers = { "user-agent": ua };
    if (referer) headers["referer"] = referer;
    const r = await fetch(url, { headers, redirect: "follow", signal: ctl.signal });
    const text = await readCapped(r);
    return { status: r.status, finalUrl: r.url || url, text, headers: r.headers };
  } catch (e) {
    return { status: 0, finalUrl: "", text: "", headers: null };
  } finally {
    clearTimeout(t);
  }
}

// ---- Bayesian fusion (port of score.py, ported-layer subset) ----
const PRIOR = 0.12;
const W = {
  L1KW_STRONG: [0.80, 0.030], L1KW_WEAK: [0.55, 0.120], L10LANG: [0.45, 0.080], L17HIDDEN: [0.85, 0.010],
  L2UACLOAK: [0.92, 0.020], L3REFCLOAK: [0.90, 0.020], L9REDIR: [0.70, 0.060], L4MOBILE: [0.75, 0.040],
  L11REST: [0.88, 0.010], L20SCRIPT: [0.82, 0.020], L11SITEMAP: [0.78, 0.020], L20SHAPE: [0.80, 0.020],
  L8IFRAME: [0.85, 0.010], L16HDR: [0.80, 0.030], L20RELAY: [0.50, 0.050],
  L14CAMPAIGN: [0.97, 0.002], L10DEFACE: [0.97, 0.002],
};
const HARD = new Set(["L14CAMPAIGN", "L10DEFACE"]);
const LAYER_CAT = { L2UACLOAK: "cloak", L3REFCLOAK: "cloak", L9REDIR: "redirect", L4MOBILE: "redirect", L16HDR: "redirect", L20RELAY: "redirect", L10DEFACE: "deface", L14CAMPAIGN: "malware", L8IFRAME: "malware", L10LANG: "foreign_lang", L20SCRIPT: "foreign_lang" };

function category(eff) {
  for (const s of eff) { const c = S.categoryOf(s.match); if (c) return c; }
  for (const pref of ["deface", "malware", "cloak", "redirect", "foreign_lang"]) {
    for (const s of eff) if (LAYER_CAT[s.layer] === pref) return pref;
  }
  return "gambling";
}

function score(signals, ctx) {
  const eff = signals.filter((s) => s.bucket !== "control");
  const layers = new Set(eff.map((s) => s.layer));
  const best = {};
  let hard = false;
  for (const s of eff) {
    if (HARD.has(s.layer)) hard = true;
    const [D, F] = W[s.layer] || [0.55, 0.10];
    const ratio = D / F;
    if (!best[s.bucket] || ratio > best[s.bucket][0]) best[s.bucket] = [ratio, s];
  }
  let lo = Math.log(PRIOR / (1 - PRIOR));
  for (const k in best) lo += Math.log(best[k][0]);
  const posterior = 1 / (1 + Math.exp(-lo));
  const nbuckets = Object.keys(best).length;
  let verdict;
  if (!eff.length) verdict = "CLEAN";
  else if (hard || (posterior >= 0.97 && nbuckets >= 2)) verdict = "CONFIRM_CANDIDATE";
  else if (posterior >= 0.50 || nbuckets >= 1) verdict = "SUSPECT";
  else verdict = "CLEAN";

  let lead = null;
  for (const k in best) if (!lead || best[k][0] > lead[0]) lead = best[k];
  const cat = eff.length ? category(eff) : "";
  const evidence = [];
  const seen = new Set();
  for (const s of eff) {
    if (s.url && !seen.has(s.url)) { seen.add(s.url); evidence.push({ layer: s.layer, url: s.url.slice(0, 300), match: s.match.slice(0, 160) }); }
    if (evidence.length >= 10) break;
  }
  // genuine-vs-hacked gate
  const stealth = ["L2UACLOAK", "L3REFCLOAK", "L17HIDDEN", "L16HDR", "L20RELAY"].some((l) => layers.has(l));
  const malwareDeface = ["L14CAMPAIGN", "L10DEFACE", "L8IFRAME"].some((l) => layers.has(l));
  const doorway = ["L11REST", "L20SCRIPT", "L11SITEMAP", "L20SHAPE", "L4MOBILE"].some((l) => layers.has(l));
  const homepageOpen = layers.has("L1KW_STRONG");
  const hackFp = stealth || malwareDeface || (doorway && !homepageOpen);
  const spammy = !!(ctx && ctx.domainSpammy);
  const identity = !!(ctx && ctx.bdSignal);
  let status, confirmed, flagged;
  if (spammy || (homepageOpen && !hackFp && !identity)) { status = "spam_site"; confirmed = 0; flagged = false; }
  else if (verdict === "CONFIRM_CANDIDATE") { status = "lead"; confirmed = 1; flagged = true; }
  else if (verdict === "SUSPECT") { status = "review"; confirmed = 0; flagged = true; }
  else { status = "clean"; confirmed = 0; flagged = false; }

  return {
    verdict, posterior: Math.round(posterior * 1e4) / 1e4, nbuckets, hard, category: cat,
    proof: (lead ? lead[1].match : "").slice(0, 500), proofUrl: (lead ? lead[1].url : ""),
    layers: [...layers].sort(), evidence, status, confirmed, flagged,
  };
}

// ---- one domain ----
export async function scanDomain(env, rec) {
  const d = (rec.domain || "").trim().toLowerCase();
  const reg = d.replace(/^www\./, "");
  const base = "https://" + d;
  const sigs = [];
  const emit = (bucket, layer, match, url = "") => sigs.push({ bucket, layer, match: String(match).slice(0, 200), url });

  const B = await fetchPage(base, UA_BR, null);
  if (B.status === 0) return { error: "unreachable" };
  const G = await fetchPage(base, UA_GB, REF_G);

  const visB = stripHtml(B.text);
  const visG = stripHtml(G.text);
  if (S.RE.WAF.test(B.text)) emit("control", "L18CHALLENGE", "waf", base + "/");

  const kwS = distinct(visB, S.REG.ALL_STRONG.source);
  if (kwS.length) emit("homepage-content", "L1KW_STRONG", kwS.join(";"), base + "/");
  const kwW = distinct(visB, S.REG.ALL_WEAK.source);
  if (kwW.length) emit("homepage-content", "L1KW_WEAK", kwW.join(";"), base + "/");

  // L2 UA cloak — strong kw shown to googlebot but not browser
  const setB = new Set(kwS);
  const kgS = distinct(visG, S.REG.ALL_STRONG.source).filter((x) => !setB.has(x));
  if (kgS.length) emit("cloak-diff", "L2UACLOAK", kgS.join(";"), base + "/");

  // L9 redirect off-domain
  const bh = hostOf(B.finalUrl);
  if (bh && !sameHost(bh, reg)) emit("redirect", "L9REDIR", bh, B.finalUrl);

  // L10 foreign title / deface
  const ttl = getTitle(B.text) || getTitle(G.text);
  if (ttl && S.RE.FOREIGN.test(ttl)) emit("homepage-content", "L10LANG", ttl, base + "/");
  const defm = distinct(B.text + G.text, S.RE.DEFACE.source);
  if (defm.length) emit("deface", "L10DEFACE", defm.join(";"), base + "/");

  // L14 malware-js
  const bad = distinct(B.text + G.text, S.RE.MALJS.source);
  if (bad.length) emit("malware-js", "L14CAMPAIGN", bad.slice(0, 3).join(";"), base + "/");

  // L17 hidden-link spam (lean: a display:none/offscreen block with a strong kw)
  const hid = /<(div|span|p|section|footer|ul|a)\b[^>]*style="[^"]*(display\s*:\s*none|visibility\s*:\s*hidden|text-indent\s*:\s*-\s*\d{3,}|position\s*:\s*absolute[^"]*(left|top)\s*:\s*-\s*\d{3,})[^"]*"[^>]*>([\s\S]{0,1500}?)<\/\1>/i.exec(B.text);
  if (hid && S.ALL_STRONG.test(stripHtml(hid[0]))) emit("homepage-content", "L17HIDDEN", "hidden:" + stripHtml(hid[0]).slice(0, 120), base + "/");

  // L8 — gambling iframe/script injection (no extra fetch)
  const ifr = (B.text + G.text).match(/<(?:iframe|script)[^>]+src="https?:\/\/[^"]*(?:casino|slot|judi|togel|xbet|melbet|bet[0-9]|gacor|sbobet)[^"]*"/i);
  if (ifr) emit("malware-js", "L8IFRAME", ifr[0].slice(0, 140), base + "/");

  // L16HDR — server header redirect to gambling / junk TLD (no extra fetch)
  if (G.headers) {
    const loc = G.headers.get("location") || G.headers.get("refresh") || "";
    const lh = hostOf((loc.match(/https?:\/\/[^\s"']+/) || [""])[0]);
    if (lh && !sameHost(lh, reg) && (S.RE.GAMB_STRONG.test(loc) || S.RE.JUNKTLD.test(loc))) emit("redirect", "L16HDR", loc.slice(0, 140), base + "/");
  }

  // L20RELAY — off-domain canonical/alternate to a non-CDN/non-platform host (from googlebot body)
  const relaySkip = /cloudflare|cloudfront|akamai|fastly|jsdelivr|gstatic|googleusercontent|bunny|wp\.com|w\.org|gravatar|youtube|facebook|googleapis|lovable|webflow|wixsite|weebly|netlify|vercel|github\.io|blogspot|myshopify/i;
  const relays = [];
  const relayRx = /<link[^>]+rel="(?:alternate|canonical)"[^>]+href="https?:\/\/([^/"]+)/gi;
  let rm, rg = 0;
  while ((rm = relayRx.exec(G.text)) && rg++ < 10) {
    const h = rm[1].toLowerCase();
    if (h && !sameHost(h, reg) && !relaySkip.test(h)) relays.push(h);
  }
  if (relays.length) emit("redirect", "L20RELAY", [...new Set(relays)].slice(0, 2).join(";"), base + "/");

  let fired = sigs.length > 0;

  // L11REST — WordPress REST enumeration (the crown jewel for doorway/injected posts)
  try {
    const probe = await fetchPage(base + "/wp-json/wp/v2/posts?per_page=1", UA_GB, null, 9000);
    const wptot = probe.headers ? probe.headers.get("x-wp-total") : null;
    if (wptot && /^\d+$/.test(wptot)) {
      const pages = Number(wptot) <= 100 ? 1 : Math.min(Math.ceil(Number(wptot) / 100), 3);
      let foreign = 0, total = 0;
      for (const typ of ["posts", "pages"]) {
        const tp = typ === "posts" ? pages : 1;
        for (let pg = 1; pg <= tp; pg++) {
          const rr = await fetchPage(`${base}/wp-json/wp/v2/${typ}?per_page=100&page=${pg}&_fields=slug,title,link`, UA_GB, null, 10000);
          if (!rr.text || !rr.text.includes('"slug"')) break;
          let arr;
          try { arr = JSON.parse(rr.text); } catch (e) { break; }
          if (!Array.isArray(arr)) break;
          for (const p of arr) {
            const slug = (p && p.slug || "").trim();
            let title = (p && p.title && (p.title.rendered ?? p.title)) || "";
            title = String(title).replace(RE_WS, " ").trim();
            total++;
            if (S.RE.FOREIGN.test(title)) foreign++;
            if ((slug && S.RE.SLUG_SPAM.test(slug)) || (title && S.ALL_STRONG.test(title))) {
              emit("content-enum", "L11REST", `slug=${slug.slice(0, 60)}::${title.slice(0, 90)}`, (p.link || "").slice(0, 130));
            }
          }
        }
      }
      if (foreign >= 4 && total && foreign * 100 < total * 30)
        emit("content-enum", "L20SCRIPT", `foreign=${foreign}/${total}`, base + "/wp-json/wp/v2/posts");
    }
  } catch (e) { /* not WP / blocked — fine */ }

  // L11SITEMAP / L20SHAPE — sitemap doorway (gated: only when something already smells, to save fetches)
  if (sigs.length > 0) {
    try {
      const rob = await fetchPage(base + "/robots.txt", UA_GB, null, 8000);
      let smaps = [...(rob.text || "").matchAll(/sitemap:\s*(https?:\/\/\S+)/gi)].map((m) => m[1]);
      if (!smaps.length) smaps = [base + "/sitemap_index.xml", base + "/wp-sitemap.xml", base + "/sitemap.xml"];
      let sm = "";
      for (const u of smaps.slice(0, 2)) {
        if (!u.includes(reg)) continue;
        const r = await fetchPage(u, UA_GB, null, 8000);
        sm += r.text || "";
        const children = [...new Set([...(r.text || "").matchAll(/https?:\/\/[^<\s"]+\.xml/gi)].map((m) => m[0]))].slice(0, 3);
        for (const child of children) { if (child.includes(reg)) { const c = await fetchPage(child, UA_GB, null, 7000); sm += c.text || ""; } }
        if (sm.length > 220000) break;
      }
      if (sm) {
        const su = [...new Set([...sm.matchAll(/https?:\/\/[^<\s"]+/gi)].map((m) => m[0]))].filter((u) => u.includes(reg) && !u.toLowerCase().endsWith(".xml") && S.RE.SLUG_SPAM.test(u)).slice(0, 3);
        if (su.length) emit("sitemap-doorway", "L11SITEMAP", su.join(";"), su[0]);
        const locs = [...sm.matchAll(/<loc>\s*([^<\s]+)/gi)].map((m) => m[1]);
        let gib = 0;
        for (const u of locs) {
          if (!u.includes(reg)) continue;
          const seg = (u.replace(/\.html?$/, "").split("/").filter(Boolean).pop() || "").toLowerCase();
          if (seg.length > 9) { const v = (seg.match(/[aeiou]/g) || []).length; if (v / seg.length < 0.22 && /[bcdfghjklmnpqrstvwxz]{6,}/.test(seg)) gib++; }
        }
        if (gib >= 10) emit("sitemap-doorway", "L20SHAPE", "gibberish=" + gib, base + "/");
      }
    } catch (e) { /* sitemap missing/blocked — fine */ }
  }

  const sc = score(sigs, { domainSpammy: S.domainSpammy(reg), bdSignal: S.bdSignal(reg, visB) });
  sc.title = ttl;
  sc.excerpt = visB.slice(0, 1800);
  sc.httpStatus = B.status;
  sc.isBd = S.bdSignal(reg, visB) ? 1 : 0;
  sc.bizType = S.bizType(reg, ttl, visB);
  return sc;
}

// ---- Groq Stage-2 (gambling/adult only; keeps the lead list clean) ----
const GROQ_SYS = `You triage website-security scan hits for a Bangladesh cleanup service. Classify the flagged site:
- "hacked_client": a LEGITIMATE business/org site HACKED with injected gambling/adult/foreign spam (doorway/cloaked/hidden/inner pages) while a real business still exists. KEEP.
- "genuine_spam": the site ITSELF is a gambling/casino/betting/adult brand by design. DROP.
- "false_positive": actually clean; the keyword was incidental/legitimate. DROP.
Rule: spam hidden in inner/cloaked/doorway pages behind a normal homepage = hacked_client; whole site openly gambling = genuine_spam.
Return STRICT JSON only: {"classification":"hacked_client|genuine_spam|false_positive","business_type":"healthcare|education|ecommerce|garments|realestate|food|finance|it|ngo|travel|news|government|agro|pharma|automobile|professional|general-business","confidence":0-100,"reason":"<=12 words"}`;

async function groqVerify(env, domain, title, excerpt, evidence) {
  const keys = (env.GROQ_API_KEY || "").split(",").map((k) => k.trim()).filter(Boolean);
  if (!keys.length) return null;
  const model = env.GROQ_MODEL || "llama-3.1-8b-instant";
  const user = `domain: ${domain}\ntitle: ${title}\nhomepage excerpt: ${excerpt.slice(0, 1500)}\n\nDETECTED SPAM EVIDENCE:\n${evidence.slice(0, 1100)}`;
  for (let i = 0; i < keys.length; i++) {
    const key = keys[(Date.now() + i) % keys.length];
    try {
      const r = await fetch("https://api.groq.com/openai/v1/chat/completions", {
        method: "POST",
        headers: { authorization: "Bearer " + key, "content-type": "application/json", "user-agent": UA_BR },
        body: JSON.stringify({ model, temperature: 0, max_tokens: 170, response_format: { type: "json_object" }, messages: [{ role: "system", content: GROQ_SYS }, { role: "user", content: user }] }),
      });
      if (r.status === 429 || r.status === 403) continue;
      if (!r.ok) return null;
      const j = await r.json();
      const obj = JSON.parse(j.choices[0].message.content);
      const cls = String(obj.classification || "").toLowerCase();
      if (!["hacked_client", "genuine_spam", "false_positive"].includes(cls)) return null;
      return { classification: cls, business_type: (obj.business_type || "").toLowerCase(), reason: (obj.reason || "").slice(0, 200) };
    } catch (e) { continue; }
  }
  return null;
}

const DHAKA = 6 * 3600;
const dDay = (ts) => new Date((ts + DHAKA) * 1000).toISOString().slice(0, 10);
const dHour = (ts) => new Date((ts + DHAKA) * 1000).toISOString().slice(0, 13).replace("T", "-");
const CATS = ["gambling", "pharma", "adult", "deface", "cloak", "foreign_lang", "malware", "redirect"];

// scanSlice — read this shard's slice of the queue and SCAN it. Returns results WITHOUT
// touching D1 (besides the read). The sibling shard Workers run this and return the JSON to
// the main Worker, which is the SINGLE writer (ingestResults) — so 8 parallel shards never
// collide on D1 writes (that collision was silently losing ~75% of scans). Pure read+compute.
export async function scanSlice(env, n) {
  const N = n || Number(env.SCAN_PER_TICK || 5);
  const SHARDS = Math.max(1, Number(env.SCAN_SHARDS || 1));
  const SHARD = Math.max(0, Number(env.SCAN_SHARD || 0)) % SHARDS;
  const rs = await env.DB.prepare(
    "SELECT rowid,domain,business,phone FROM domains WHERE pass_no=0 AND (rowid % ?)=? ORDER BY bd_score DESC, rowid LIMIT ?"
  ).bind(SHARDS, SHARD, N).all();
  const rows = rs.results || [];
  const findings = [], rowids = [];
  let errors = 0;
  for (const r of rows) {
    rowids.push(r.rowid);   // every claimed row gets marked done by ingestResults (no re-scan)
    let sc;
    try { sc = await scanDomain(env, r); } catch (e) { errors++; continue; }
    if (sc.error) { errors++; continue; }
    if (!sc.flagged) continue;
    let status = sc.status, confirmed = sc.confirmed, verdict = sc.verdict, reason = `posterior=${sc.posterior} buckets=${sc.nbuckets}${sc.hard ? " HARD" : ""}`, biz = sc.bizType;
    if (["gambling", "adult", "foreign_lang"].includes(sc.category)) {
      const v = await groqVerify(env, r.domain, sc.title, sc.excerpt, sc.evidence.map((e) => e.url + " " + e.match).join("; "));
      if (v) {
        if (v.classification === "hacked_client") { status = "lead"; confirmed = 1; }
        else continue;
        biz = v.business_type || biz; verdict = "groq-" + v.classification; reason = "groq:" + v.classification + " — " + v.reason;
      } else if (sc.status === "spam_site") continue;
    } else if (sc.status === "spam_site") continue;
    findings.push({ domain: r.domain, business: r.business, phone: r.phone, category: sc.category, layers: sc.layers.join(","), proof: sc.proof, proofUrl: sc.proofUrl, httpStatus: sc.httpStatus, nbuckets: sc.nbuckets, verdict, reason, confirmed, evidence: sc.evidence, isBd: sc.isBd, bizType: biz, status });
  }
  return { rowids, findings, scanned: rows.length, errors };
}

// ingestResults — the SINGLE writer. Marks all scanned rowids done + writes findings + stats
// in ONE batch. If it fails, the rowids stay pass_no=0 and simply retry next tick (no loss).
export async function ingestResults(env, agg) {
  const now = Math.floor(Date.now() / 1000);
  const rowids = agg.rowids || [], findings = agg.findings || [];
  const scanned = agg.scanned || 0, errors = agg.errors || 0;
  const stmts = [];
  for (let i = 0; i < rowids.length; i += 90) {
    const chunk = rowids.slice(i, i + 90);
    stmts.push(env.DB.prepare(`UPDATE domains SET pass_no=1 WHERE rowid IN (${chunk.map(() => "?").join(",")})`).bind(...chunk));
  }
  const catc = Object.fromEntries(CATS.map((c) => [c, 0]));
  let flagged = 0, confirmed = 0;
  for (const f of findings) {
    flagged++;
    const conf = f.confirmed ? 1 : 0;
    if (conf) { confirmed++; if (catc[f.category] !== undefined) catc[f.category]++; }
    stmts.push(env.DB.prepare("DELETE FROM findings WHERE domain=?").bind(f.domain));
    stmts.push(env.DB.prepare(
      "INSERT INTO findings (domain,business,phone,category,layers,proof_snippet,proof_url,http_status,stage1_score,stage2_verdict,stage2_reason,stage2_category,confirmed,pass_no,first_ts,ts,evidence,is_bd,biz_type,status) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
    ).bind(f.domain, (f.business || "").slice(0, 200), (f.phone || "").slice(0, 40), f.category, (f.layers || "").slice(0, 200), (f.proof || "").slice(0, 600), (f.proofUrl || "").slice(0, 300), f.httpStatus || 0, f.nbuckets || 0, (f.verdict || "").slice(0, 20), (f.reason || "").slice(0, 400), f.category, conf, 1, now, now, JSON.stringify(f.evidence || []).slice(0, 4000), f.isBd ? 1 : 0, (f.bizType || "").slice(0, 30), (f.status || "lead").slice(0, 16)));
    if (conf) stmts.push(env.DB.prepare("INSERT INTO events (kind,domain,detail,ts) VALUES ('confirmed',?,?,?)").bind(f.domain, (f.category + " | " + (f.proof || "")).slice(0, 200), now));
  }
  const day = dDay(now), hour = dHour(now);
  const catSet = CATS.map((c) => `${c}=${c}+${catc[c]}`).join(",");
  stmts.push(env.DB.prepare(
    `INSERT INTO daily_stats (day,scanned,flagged,confirmed,errors,${CATS.join(",")}) VALUES (?,?,?,?,?,${CATS.map(() => "?").join(",")}) ON CONFLICT(day) DO UPDATE SET scanned=scanned+?,flagged=flagged+?,confirmed=confirmed+?,errors=errors+?,${catSet}`
  ).bind(day, scanned, flagged, confirmed, errors, ...CATS.map((c) => catc[c]), scanned, flagged, confirmed, errors));
  stmts.push(env.DB.prepare("INSERT INTO hourly_stats (hour,scanned,flagged,confirmed,errors) VALUES (?,?,?,?,?) ON CONFLICT(hour) DO UPDATE SET scanned=scanned+?,flagged=flagged+?,confirmed=confirmed+?,errors=errors+?").bind(hour, scanned, flagged, confirmed, errors, scanned, flagged, confirmed, errors));
  stmts.push(env.DB.prepare("UPDATE counters SET value=value+? WHERE metric='total_scanned'").bind(scanned));
  stmts.push(env.DB.prepare("UPDATE counters SET value=value+? WHERE metric='total_flagged'").bind(flagged));
  stmts.push(env.DB.prepare("UPDATE counters SET value=value+? WHERE metric='total_confirmed'").bind(confirmed));
  stmts.push(env.DB.prepare("UPDATE counters SET value=value+? WHERE metric='total_errors'").bind(errors));
  if (stmts.length) await env.DB.batch(stmts);
  return { scanned, flagged, confirmed };
}

// single-worker convenience (used by POST /scan_tick and main shard-0 fallback)
export async function scanTick(env, n) {
  return await ingestResults(env, await scanSlice(env, n));
}
