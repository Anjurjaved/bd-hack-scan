// harvest-crtsh.mjs — Certificate Transparency harvester for Bangladeshi domains, run ON THE ORACLE VM.
//
// Why this exists (2026-07-19): the in-Worker harvestCrtsh() had been silent for 3 days and had produced only
// 2,854 domains lifetime. Measured cause: it fires ONE giant `%.bd` query with a 30s AbortSignal, but crt.sh
// needs 60s+ to answer even the small `%.edu.bd` slice and returns HTTP 502 under load. So every run timed out.
// A Cloudflare Worker cannot safely sit on a 60-120s fetch (that CPU wall is what froze the engine before), so
// the work belongs here on the VM, which has no CPU limit. Results are POSTed to the Worker /harvest endpoint,
// exactly like harvest-urlscan.mjs / harvest-overpass.mjs.
//
//   API_BASE=… SHARED_TOKEN=… node scanner/harvest-crtsh.mjs
//
// Certificate Transparency is the single best source of NEW .bd hostnames: every TLS certificate issued to any
// Bangladeshi site is logged publicly, including the institutional TLDs (.edu.bd/.gov.bd/.ac.bd) that the
// IP-based harvesters systematically miss.

const API_BASE = (process.env.API_BASE || "https://bd-hack-audit-api.javed-it.workers.dev").replace(/\/+$/, "");
const TOKEN = process.env.SHARED_TOKEN || "";
const CHUNK = 500;

// Queried one slice at a time — a per-TLD query is small enough for crt.sh to actually answer, whereas the old
// single `%.bd` query is what made it time out. Institutional TLDs come FIRST because they are the highest-value
// lead type (a .gov.bd/.edu.bd carrying injected spam is always a hacked victim, never a genuine spam brand).
const SLICES = [
  "%.edu.bd", "%.gov.bd", "%.ac.bd", "%.mil.bd",
  "%.com.bd", "%.net.bd", "%.org.bd", "%.info.bd", "%.co.bd",
];

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// crt.sh is a FREE public service and it rate-limits hard: firing all nine slices back-to-back got every slice
// 502'd within minutes. So each run takes only SLICES_PER_RUN of them, rotating through the list via a tiny
// cursor file. With the systemd timer every 2h that covers all nine TLDs about every 6h while staying polite.
const SLICES_PER_RUN = Number(process.env.CRTSH_SLICES || 3);
const STATE = process.env.CRTSH_STATE || "/opt/bd-scanner/.crtsh-cursor";
async function readCursor() {
  try { const fs = await import("node:fs/promises"); return Number(await fs.readFile(STATE, "utf8")) || 0; }
  catch { return 0; }
}
async function writeCursor(n) {
  try { const fs = await import("node:fs/promises"); await fs.writeFile(STATE, String(n)); } catch {}
}

// crt.sh flaps between 200 / 502 / timeout. Retry with backoff and accept a partial win — a slice that fails
// this run is simply picked up on the next run, so nothing is ever permanently lost.
async function fetchSlice(q) {
  const url = `https://crt.sh/?q=${encodeURIComponent(q)}&output=json&exclude=expired`;
  for (let attempt = 1; attempt <= 4; attempt++) {
    try {
      const r = await fetch(url, {
        headers: { "user-agent": "Mozilla/5.0 (compatible; bd-hack-audit/1.0)", accept: "application/json" },
        signal: AbortSignal.timeout(150000), // crt.sh genuinely needs 60s+; the old 30s guaranteed failure
      });
      if (!r.ok) { await sleep(attempt * 8000); continue; }
      const txt = await r.text();
      try { return JSON.parse(txt); } catch { return null; }   // truncated/HTML body → treat as a miss
    } catch { await sleep(attempt * 8000); }
  }
  return null;
}

// A certificate's name_value holds one hostname per line and may carry wildcards. We keep BOTH the full hostname
// and its registrable apex: a hacked `result.xyz.edu.bd` subdomain is a real lead in its own right, and the apex
// keeps the existing IP/cluster logic working. Wildcards (*.foo.edu.bd) contribute only the apex.
function extractHosts(rows) {
  const out = new Set();
  for (const row of Array.isArray(rows) ? rows : []) {
    for (const raw of String(row?.name_value || "").split("\n")) {
      let h = raw.trim().toLowerCase();
      if (!h || h.includes(" ")) continue;
      const wild = h.startsWith("*.");
      if (wild) h = h.slice(2);
      if (!h.endsWith(".bd") || h.includes("@")) continue;
      if (!/^[a-z0-9.-]+$/.test(h)) continue;              // skip punycode/garbage
      out.add(h);
      const parts = h.split(".");
      if (parts.length > 3) out.add(parts.slice(-3).join("."));  // apex for x.y.edu.bd → y.edu.bd
    }
  }
  return out;
}

// The /harvest endpoint (workers/src/index.js:222) reads `d.domain || d.host || d.url` and `d.bd_score` off each
// ITEM — it needs OBJECTS, not bare strings. Posting strings silently normalises every row to null and returns
// inserted:0, which is exactly what happened on the first run (3,086 institutional hostnames found, 0 stored).
const BD_INST = /\.(edu|ac|gov|mil)\.bd$/i;
const toRow = (h) => ({ domain: h, bd_score: BD_INST.test(h) ? 60 : 40 });

async function post(source, domains) {
  let inserted = 0;
  for (let i = 0; i < domains.length; i += CHUNK) {
    const chunk = domains.slice(i, i + CHUNK).map(toRow);
    try {
      const r = await fetch(API_BASE + "/harvest", {
        method: "POST",
        headers: { authorization: "Bearer " + TOKEN, "content-type": "application/json" },
        body: JSON.stringify({ source, domains: chunk }),
      });
      const j = await r.json().catch(() => ({}));
      inserted += j.inserted || 0;
    } catch (e) { console.error("[crtsh] post failed:", String(e).slice(0, 80)); }
  }
  return inserted;
}

async function main() {
  if (!TOKEN) { console.error("SHARED_TOKEN missing"); process.exit(1); }
  const all = new Set();
  let totalInserted = 0;
  const start = await readCursor();
  const todo = Array.from({ length: Math.min(SLICES_PER_RUN, SLICES.length) }, (_, k) => SLICES[(start + k) % SLICES.length]);
  await writeCursor((start + todo.length) % SLICES.length);
  console.log(`[crtsh] run covers ${todo.join(" ")} (cursor ${start} -> ${(start + todo.length) % SLICES.length})`);
  for (const q of todo) {
    const t0 = Date.now();
    const rows = await fetchSlice(q);
    if (!rows) { console.log(`[crtsh] ${q} — no data (crt.sh 502/timeout), will retry next run`); continue; }
    const hosts = extractHosts(rows);
    const fresh = [...hosts].filter((h) => !all.has(h));
    fresh.forEach((h) => all.add(h));
    const ins = fresh.length ? await post("crtsh", fresh) : 0;
    totalInserted += ins;
    console.log(`[crtsh] ${q} — ${rows.length} certs, ${hosts.size} hosts, ${fresh.length} new-to-run, ${ins} NEW inserted (${((Date.now() - t0) / 1000).toFixed(0)}s)`);
    await sleep(30000); // be a good citizen to a free public service — short gaps got us 502'd on every slice
  }
  console.log(`[crtsh] DONE — ${all.size} unique .bd hostnames seen, ${totalInserted} NEW inserted into the queue`);
}

main().catch((e) => { console.error("[crtsh] fatal:", e); process.exit(1); });
