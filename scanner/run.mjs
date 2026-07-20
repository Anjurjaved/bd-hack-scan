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
const { scanDomain, geminiVerify, groqVerify, domainSpammy, hasCustomer, adultNeedsReview, BD_INST_TLD, BD_TLD, DETECTOR_GEN } = await import(process.env.SCAN_JS || "./scan.js");

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
  // This box is the whole reason the deep detector exists — real cores, no Cloudflare CPU wall — so it
  // defaults to the full profile. scan.js reads this off the env object exactly as the Worker does.
  SCAN_PROFILE: process.env.SCAN_PROFILE || "full",
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
  const r = await decide(rec, sc);
  // The fingerprint rides along on EVERY outcome, not just findings. Its whole purpose is to notice the pass
  // where a previously-clean site changes, so a clean scan is precisely the one that must record a baseline.
  if (r && sc && sc.fp) { r.fp = sc.fp; r.base = sc.base || ""; }
  return r;
}

// The per-domain decision, byte-for-byte the same rules as scanSlice() in workers/src/scan.js.
async function decide(rec, sc) {
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
  // `clear` retracts a stale confirmed lead (see ingestResults). It is set ONLY on a definite negative — the site
  // answered 2xx and the current gate returned `clean`. Never on unreachable, never on a gambling/adult hit the AI
  // pool could not adjudicate: losing a real lead to a momentary blip is the worse mistake.
  // Two guards, both mirroring workers/src/scan.js:
  //  - 2xx: `unreachable` covers only transport failure, so a WAF 403, a 429 (routine at CONCURRENCY=400 against
  //    shared BD hosting), a 503 or a captcha page arrives here as an ordinary scan with no scoring signals at all
  //    → verdict CLEAN. One blocked re-scan must not retract a real lead.
  //  - status must be `clean`, not merely un-flagged: `spam_site` is what a TOTAL homepage takeover looks like once
  //    the Bengali identity is gone, so retracting there drops the lead exactly when the compromise completes.
  //    A gambling/adult BRAND in the NAME is the safe exception — no real BD business carries one.
  const answered2xx = sc.httpStatus >= 200 && sc.httpStatus < 300;
  const okClear = (extra) => (answered2xx && (sc.status === "clean" || extra) ? rec.domain : undefined);
  if (!sc.flagged) {
    const nameSpam = domainSpammy(reg);
    return { rowid: rec.rowid, park: sc.status === "spam_site" && nameSpam, clear: okClear(nameSpam) };
  }
  let status = sc.status, confirmed = sc.confirmed, verdict = sc.verdict, biz = sc.bizType;
  let reason = `posterior=${sc.posterior} buckets=${sc.nbuckets}${sc.hard ? " HARD" : ""}`;
  if (isGA) {
    // gambling/adult BRAND in the domain NAME → genuine spam → park, spend NO Gemini.
    if (domainSpammy(reg)) return { rowid: rec.rowid, park: true, clear: okClear(true) };
    {
      const ev = sc.evidence.map((e) => e.url + " " + e.match).join("; ");
      const v = (await geminiVerify(ENV, rec.domain, sc.title, sc.excerpt, ev)) || (await groqVerify(ENV, rec.domain, sc.title, sc.excerpt, ev));
      if (v) {
        // Mirrors workers/src/scan.js: an AI "hacked_client" verdict is necessary but NOT sufficient. It is
        // exactly what the AI answered for all 26 porn sites that reached the sales list. There has to be a
        // business on the other end to sell a cleanup to.
        if (v.classification === "hacked_client" && !hasCustomer(reg, sc)) return { rowid: rec.rowid, clear: okClear(true) };
        if (v.classification === "hacked_client") {
          biz = v.business_type || biz; verdict = "ai-" + v.classification; reason = "ai:" + v.classification + " — " + v.reason;
          // Adult on a non-.bd domain never auto-publishes — see adultNeedsReview in workers/src/scan.js.
          if (adultNeedsReview(reg, sc.category)) { status = "review"; confirmed = 0; reason = "adult on a non-.bd domain — needs human approval before it becomes a lead"; }
          else { status = "lead"; confirmed = 1; }
        }
        else return { rowid: rec.rowid, clear: okClear(true) };  // genuine_spam / false_positive → drop, re-scan later. NOT parked: a BD business
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
  if (domainSpammy(reg)) return { rowid: rec.rowid, park: true, clear: okClear(true) };
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
  const cleared = results.filter((r) => r && r.clear).map((r) => r.clear);
  const fps = results.filter((r) => r && r.fp).map((r) => ({ rowid: r.rowid, fp: r.fp, base: r.base || "" }));
  const errors = results.filter((r) => r && r.error).length;
  confirmedTotal += findings.filter((f) => f.confirmed).length;
  // chunk the findings so each /vm-push writes a small D1 batch; the LAST chunk carries the scanned/dead/errors totals
  const chunks = [];
  for (let i = 0; i < findings.length; i += PUSH_CHUNK) chunks.push(findings.slice(i, i + PUSH_CHUNK));
  if (!chunks.length) chunks.push([]);
  // api() returns null after 4 failed attempts instead of throwing, so a NON-final chunk can be dropped while the
  // loop carries on. The findings in it are gone either way, but stamping gen on the final push would additionally
  // declare those rows v2-qualified — dropping them out of every gen<DETECTOR_GEN re-qualification tier, so the
  // lost leads would only ever come back through the slow least-recently-scanned rotation. Withhold gen when any
  // chunk failed and the rows stay queued for a proper deep re-scan.
  let pushFailed = false;
  for (let i = 0; i < chunks.length; i++) {
    const last = i === chunks.length - 1;
    const res = await api("/vm-push", {
      rowids: last ? rowids : [],
      findings: chunks[i],
      scanned: last ? batch.length : 0,
      errors: last ? errors : 0,
      dead: last ? dead : [],
      parked: last ? parked : [],
      cleared: last ? cleared : [],
      fps: last ? fps : [],
      workers: CONCURRENCY,
      // Claim the detector generation this box actually ran, so the Worker can stamp these rows as
      // re-qualified. It comes from the shared scan.js we imported, never from a constant here — a VM
      // running yesterday's code must claim yesterday's generation and get its rows re-queued.
      gen: last && !pushFailed ? DETECTOR_GEN : 0,
    });
    if (!res) pushFailed = true;
  }
}

// The self-learned spam-host blocklist (detector layer L45KNOWNHOST) is mined from confirmed findings by the
// Worker, because only it has D1. Refreshed periodically rather than per batch: the list changes slowly, and a
// failed refresh must leave the previous list in place rather than blank the layer.
async function refreshSpamHosts() {
  try {
    // /api/* is behind the dashboard session gate; SHARED_TOKEN is the documented Bearer bypass for
    // cron/shards/owner tooling, which is exactly what this box is.
    const r = await fetch(API_BASE + "/api/spamhosts", { headers: HDR, signal: AbortSignal.timeout(20000) });
    if (!r.ok) return;
    const j = await r.json();
    const hosts = (j.hosts || []).map((h) => h.host).filter(Boolean);
    if (hosts.length) { ENV.SPAM_HOSTS = hosts.join(","); console.log(`[bd-scanner] spam-host blocklist: ${hosts.length} hosts from ${j.victimsScanned} victims`); }
  } catch (e) { /* keep whatever we already had */ }
}

async function main() {
  console.log(`[bd-scanner] start · API=${API_BASE} · concurrency=${CONCURRENCY} · batch=${BATCH} · profile=${ENV.SCAN_PROFILE}`);
  if (!TOKEN) { console.error("SHARED_TOKEN missing"); process.exit(1); }
  await refreshSpamHosts();
  setInterval(refreshSpamHosts, 6 * 3600 * 1000).unref?.();
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
