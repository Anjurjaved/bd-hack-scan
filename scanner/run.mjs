// bd-scanner — the heavy fetch+detect engine, running on an always-free Oracle A1 VM (or any Linux box / the
// owner's Mac). It removes the Cloudflare Free-plan CPU wall (1102) and the 50-subrequest cap entirely: it fetches
// + detects thousands of sites concurrently on real cores, then POSTs findings back to the Cloudflare Worker, which
// stays the SINGLE D1 writer. Detection is the EXACT same code the Workers use — it imports scanDomain +
// geminiVerify + groqVerify from the shared ./scan.js, and replicates scanSlice()'s per-domain decision verbatim,
// so results are identical to (just far faster + unthrottled versus) the CF shard engine. No npm dependencies.
//
// Config via env (systemd EnvironmentFile): API_BASE, SHARED_TOKEN, GEMINI_API_KEYS, GROQ_API_KEY, GROQ_MODEL,
// CONCURRENCY (default 400), BATCH (default 500), DOMAIN_MS (per-domain cap, default 30000), IDLE_MS.

// Detection is the SHARED Worker code. On the VM, scan.js + signatures.js sit next to this file (./scan.js).
// For local Mac testing, point SCAN_JS at the repo copy: SCAN_JS=../workers/src/scan.js
const { scanDomain, geminiVerify, groqVerify, domainSpammy, BD_INST_TLD, BD_TLD } = await import(process.env.SCAN_JS || "./scan.js");

const API_BASE = (process.env.API_BASE || "https://bd-hack-audit-api.javed-it.workers.dev").replace(/\/+$/, "");
const TOKEN = process.env.SHARED_TOKEN || "";
const CONCURRENCY = Math.max(1, Number(process.env.CONCURRENCY || 400));
const BATCH = Math.max(1, Number(process.env.BATCH || 500));
const DOMAIN_MS = Number(process.env.DOMAIN_MS || 30000);
const IDLE_MS = Number(process.env.IDLE_MS || 15000);
const PUSH_CHUNK = 300;   // findings per /vm-push (keep the Worker's D1 batch small)

// scan.js reads Gemini/Groq keys off this env object (same shape as the Worker's env binding).
const ENV = {
  GEMINI_API_KEYS: process.env.GEMINI_API_KEYS || "",
  GROQ_API_KEY: process.env.GROQ_API_KEY || "",
  GROQ_MODEL: process.env.GROQ_MODEL || "llama-3.1-8b-instant",
  GEMINI_MODEL: process.env.GEMINI_MODEL || "gemini-2.5-flash",
};

const HDR = { "authorization": "Bearer " + TOKEN, "content-type": "application/json" };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const nowMs = () => Date.now();
let scannedTotal = 0, confirmedTotal = 0, startTs = nowMs();

async function api(path, body, tries = 4) {
  for (let i = 0; i < tries; i++) {
    try {
      const r = await fetch(API_BASE + path, { method: "POST", headers: HDR, body: JSON.stringify(body), signal: AbortSignal.timeout(60000) });
      if (r.ok) return await r.json();
      if (r.status === 401) { console.error("AUTH FAILED — check SHARED_TOKEN"); process.exit(1); }
    } catch (e) { /* transient — retry */ }
    await sleep(1500 * (i + 1));
  }
  return null;
}

// EXACT replica of scanSlice()'s per-domain decision (workers/src/scan.js). Returns {rowid, finding?, dead?, error?}.
async function scanOne(rec) {
  let sc;
  try { sc = await scanDomain(ENV, rec, nowMs() + DOMAIN_MS); } catch (e) { return { rowid: rec.rowid, error: true }; }
  if (sc.error) return { rowid: rec.rowid, error: true, dead: sc.error === "unreachable" };
  const reg = String(rec.domain).replace(/^www\./, "");
  const isGA = ["gambling", "adult", "foreign_lang"].includes(sc.category);
  // restricted BD institutional TLD (.gov/.edu/.ac/.mil.bd) + spam = ALWAYS a hacked victim (highest-value lead),
  // whether flagged OR fully-defaced (spam_site). Confirm without an AI call, before the !flagged drop below.
  if (isGA && BD_INST_TLD.test(reg) && (sc.flagged || sc.status === "spam_site")) {
    return { rowid: rec.rowid, finding: { domain: rec.domain, business: rec.business, phone: rec.phone || sc.contactPhone, category: sc.category, layers: (sc.layers || []).join(","), proof: sc.proof, proofUrl: sc.proofUrl, httpStatus: sc.httpStatus, nbuckets: sc.nbuckets, verdict: "inst-hacked", reason: "restricted BD institutional TLD + injected " + sc.category + " = hacked victim", confirmed: 1, evidence: sc.evidence, isBd: 1, bizType: sc.bizType, status: "lead", address: sc.address, district: sc.district, area: sc.area, ip: sc.ip } };
  }
  // Not flagged: PARK only when the domain NAME is a gambling/adult brand (safe); an openly-spam foreign homepage
  // stays droppable so it re-scans later and is never permanently lost.
  if (!sc.flagged) return { rowid: rec.rowid, park: sc.status === "spam_site" && domainSpammy(reg) };
  let status = sc.status, confirmed = sc.confirmed, verdict = sc.verdict, biz = sc.bizType;
  let reason = `posterior=${sc.posterior} buckets=${sc.nbuckets}${sc.hard ? " HARD" : ""}`;
  if (isGA) {
    // gambling/adult BRAND in the domain NAME → genuine spam → park, spend NO Gemini.
    if (domainSpammy(reg)) return { rowid: rec.rowid, park: true };
    {
      const ev = sc.evidence.map((e) => e.url + " " + e.match).join("; ");
      const v = (await geminiVerify(ENV, rec.domain, sc.title, sc.excerpt, ev)) || (await groqVerify(ENV, rec.domain, sc.title, sc.excerpt, ev));
      if (v) {
        if (v.classification === "hacked_client") { status = "lead"; confirmed = 1; biz = v.business_type || biz; verdict = "ai-" + v.classification; reason = "ai:" + v.classification + " — " + v.reason; }
        else return { rowid: rec.rowid };  // genuine_spam / false_positive → drop, re-scan later. NOT parked: a BD business
                                           // often uses a .com the AI may misjudge as genuine_spam; only a NAME-brand parks.
      } else {
        // AI pool exhausted → gambling/adult can't be confirmed without a positive verdict (that fallthrough leaked
        // ~331 genuine porn/betting sites). Drop this scan; the domain re-scans later when the pool has refilled.
        return { rowid: rec.rowid };
      }
    }
  }
  // SAFETY GATE (2026-07-19) — mirrors workers/src/scan.js: a gambling/adult BRAND in the domain NAME must never be
  // confirmed, whatever category the fuse resolved. Closes the non-GA (malware/deface/cloak/redirect) door that
  // genuine porn tubes walked through (their ad-malware/redirect layers make the category non-GA, which skipped both
  // the name test and the AI). Same narrow brand list as above — no new false-positive surface.
  if (domainSpammy(reg)) return { rowid: rec.rowid, park: true };
  // (non-GA categories — malware/deface/cloak/redirect — reach here; they need no AI. A spam_site is always
  // flagged=false and was handled by the !sc.flagged guard above, so no branch is needed here.)
  return {
    rowid: rec.rowid,
    finding: {
      domain: rec.domain, business: rec.business, phone: rec.phone || sc.contactPhone, category: sc.category,
      layers: (sc.layers || []).join(","), proof: sc.proof, proofUrl: sc.proofUrl, httpStatus: sc.httpStatus,
      nbuckets: sc.nbuckets, verdict, reason, confirmed, evidence: sc.evidence, isBd: sc.isBd, bizType: biz,
      status, address: sc.address, district: sc.district, area: sc.area, ip: sc.ip,
    },
  };
}

// bounded-concurrency map (no deps): keep CONCURRENCY scans in flight at once.
async function runPool(items, limit, fn) {
  const out = new Array(items.length);
  let idx = 0;
  const workers = new Array(Math.min(limit, items.length)).fill(0).map(async () => {
    while (idx < items.length) {
      const i = idx++;
      out[i] = await fn(items[i]);
    }
  });
  await Promise.all(workers);
  return out;
}

async function pushResults(batch, results) {
  const rowids = batch.map((r) => r.rowid);
  const findings = results.filter((r) => r && r.finding).map((r) => r.finding);
  const dead = results.filter((r) => r && r.dead).map((r) => r.rowid);
  const parked = results.filter((r) => r && r.park).map((r) => r.rowid);
  const errors = results.filter((r) => r && r.error).length;
  confirmedTotal += findings.filter((f) => f.confirmed).length;
  // chunk the findings so each /vm-push writes a small D1 batch; the LAST chunk carries the scanned/dead/errors totals
  const chunks = [];
  for (let i = 0; i < findings.length; i += PUSH_CHUNK) chunks.push(findings.slice(i, i + PUSH_CHUNK));
  if (!chunks.length) chunks.push([]);
  for (let i = 0; i < chunks.length; i++) {
    const last = i === chunks.length - 1;
    await api("/vm-push", {
      rowids: last ? rowids : [],
      findings: chunks[i],
      scanned: last ? batch.length : 0,
      errors: last ? errors : 0,
      dead: last ? dead : [],
      parked: last ? parked : [],
      workers: CONCURRENCY,
    });
  }
}

async function main() {
  console.log(`[bd-scanner] start · API=${API_BASE} · concurrency=${CONCURRENCY} · batch=${BATCH}`);
  if (!TOKEN) { console.error("SHARED_TOKEN missing"); process.exit(1); }
  let emptyStreak = 0;
  for (;;) {
    const pulled = await api("/vm-pull", { n: BATCH });
    const batch = (pulled && pulled.domains) || [];
    if (!batch.length) {
      emptyStreak++;
      console.log(`[bd-scanner] queue empty (${emptyStreak}) — sleeping ${IDLE_MS}ms`);
      await sleep(IDLE_MS);
      continue;
    }
    emptyStreak = 0;
    const t0 = nowMs();
    const results = await runPool(batch, CONCURRENCY, scanOne);
    await pushResults(batch, results);
    scannedTotal += batch.length;
    const secs = (nowMs() - t0) / 1000;
    const rate = Math.round((scannedTotal / ((nowMs() - startTs) / 1000)) * 3600);
    console.log(`[bd-scanner] +${batch.length} in ${secs.toFixed(1)}s · total=${scannedTotal} confirmed=${confirmedTotal} · ~${rate}/hr`);
  }
}

main().catch((e) => { console.error("[bd-scanner] fatal", e); process.exit(1); });
