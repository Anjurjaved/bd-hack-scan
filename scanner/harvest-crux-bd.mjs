// harvest-crux-bd.mjs — Chrome UX Report "country = Bangladesh" origin lists, run ON THE ORACLE VM.
//
// Why (2026-07-19): harvest intake had collapsed to ONE new domain in 24 hours. The zakird/crux-top-lists mirror
// publishes a per-country monthly list of every origin real Chrome users in Bangladesh actually visited. Verified
// live: 18 monthly BD files exist, and a single month (202505) holds 224,909 unique hosts of which 15,453 are .bd.
// That one file therefore carries more BD domains than every current harvester produced in a day, by ~4 orders of
// magnitude, and it refreshes every month forever.
//
//   API_BASE=… SHARED_TOKEN=… node scanner/harvest-crux-bd.mjs
//
// ── THE TRAP THIS SCRIPT DELIBERATELY AVOIDS ────────────────────────────────────────────────────────────────
// "country = BD" means "visited BY people in Bangladesh", NOT "a Bangladeshi website". The raw list is full of
// google/facebook/CDN origins and, worse, foreign gambling brands that put "bd"/"bangladesh" in their domain to
// target Bangladesh for SEO — measured: of 3,166 non-.bd hosts carrying a BD name token, the overwhelming
// majority are 1xbet-bd.org / 22bet-bd.com / 1win-bangladesh.net style casino spam. Filtering by NAME would have
// flooded the queue with exactly the genuine-spam this project spends Gemini calls trying to reject, and would
// have repeated the 2026-07-04 "foreign dominates" incident that cost a 24k-row purge.
// So v1 ingests ONLY the unambiguous .bd set. Non-.bd BD businesses (the majority of the real market) must be
// admitted by HOSTING-IP-in-Bangladesh instead — see harvest-crux-bd-ip.mjs / the ipInBd path — never by name.

const API_BASE = (process.env.API_BASE || "https://bd-hack-audit-api.javed-it.workers.dev").replace(/\/+$/, "");
const TOKEN = process.env.SHARED_TOKEN || "";
const CHUNK = 500;
const LIST_API = "https://api.github.com/repos/zakird/crux-top-lists/contents/data/country/bd";
const RAW = "https://raw.githubusercontent.com/zakird/crux-top-lists/main/data/country/bd/";
const STATE = process.env.CRUX_STATE || "/opt/bd-scanner/.crux-bd-done";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function doneMonths() {
  try { const fs = await import("node:fs/promises"); return new Set((await fs.readFile(STATE, "utf8")).split("\n").filter(Boolean)); }
  catch { return new Set(); }
}
async function markDone(m) {
  try { const fs = await import("node:fs/promises"); await fs.appendFile(STATE, m + "\n"); } catch {}
}

async function listMonths() {
  const r = await fetch(LIST_API, { headers: { "user-agent": "bd-hack-audit/1.0", accept: "application/vnd.github+json" }, signal: AbortSignal.timeout(60000) });
  if (!r.ok) throw new Error("github list " + r.status);
  const a = await r.json();
  return a.map((x) => x.name).filter((n) => /^\d{6}\.csv\.gz$/.test(n)).sort();
}

// Node can gunzip natively via DecompressionStream — no dependency, and package.json stays empty.
async function fetchMonthHosts(file) {
  const r = await fetch(RAW + file, { headers: { "user-agent": "bd-hack-audit/1.0" }, signal: AbortSignal.timeout(120000) });
  if (!r.ok) return null;
  const text = await new Response(r.body.pipeThrough(new DecompressionStream("gzip"))).text();
  const hosts = new Set();
  for (const line of text.split("\n").slice(1)) {
    const origin = line.split(",")[0];
    if (!origin) continue;
    const h = origin.replace(/^https?:\/\//, "").split("/")[0].toLowerCase().trim();
    // ONLY the unambiguous .bd set — see the trap note above.
    if (h.endsWith(".bd") && /^[a-z0-9.-]+$/.test(h)) hosts.add(h);
  }
  return hosts;
}

const BD_INST = /\.(edu|ac|gov|mil)\.bd$/i;
// /harvest (workers/src/index.js:222) reads d.domain and d.bd_score off each ITEM — objects, never bare strings.
const toRow = (h) => ({ domain: h, bd_score: BD_INST.test(h) ? 60 : 50 });

async function post(domains) {
  let inserted = 0;
  for (let i = 0; i < domains.length; i += CHUNK) {
    try {
      const r = await fetch(API_BASE + "/harvest", {
        method: "POST",
        headers: { authorization: "Bearer " + TOKEN, "content-type": "application/json" },
        body: JSON.stringify({ source: "crux-bd", domains: domains.slice(i, i + CHUNK).map(toRow) }),
      });
      const j = await r.json().catch(() => ({}));
      inserted += j.inserted || 0;
    } catch (e) { console.error("[crux-bd] post failed:", String(e).slice(0, 80)); }
  }
  return inserted;
}

async function main() {
  if (!TOKEN) { console.error("SHARED_TOKEN missing"); process.exit(1); }
  const months = await listMonths();
  const done = await doneMonths();
  const todo = months.filter((m) => !done.has(m));
  console.log(`[crux-bd] ${months.length} BD month files, ${done.size} already ingested, ${todo.length} to do`);
  if (!todo.length) { console.log("[crux-bd] nothing new — a fresh month appears roughly monthly"); return; }

  let grand = 0;
  // Newest first: the most recent month has the most live sites and the best chance of new domains.
  for (const file of todo.reverse()) {
    const t0 = Date.now();
    let hosts;
    try { hosts = await fetchMonthHosts(file); } catch (e) { console.error(`[crux-bd] ${file} failed: ${String(e).slice(0, 60)}`); continue; }
    if (!hosts) { console.error(`[crux-bd] ${file} not fetchable, will retry next run`); continue; }
    const ins = await post([...hosts]);
    grand += ins;
    await markDone(file);
    console.log(`[crux-bd] ${file} — ${hosts.size} .bd hosts, ${ins} NEW inserted (${((Date.now() - t0) / 1000).toFixed(0)}s)`);
    await sleep(2000);
  }
  console.log(`[crux-bd] DONE — ${grand} NEW .bd domains added to the queue`);
}

main().catch((e) => { console.error("[crux-bd] fatal:", e); process.exit(1); });
