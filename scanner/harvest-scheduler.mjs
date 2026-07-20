// harvest-scheduler.mjs — the ROUND-ROBIN HARVEST SCHEDULER + per-source health ledger.
// Runs ON THE ORACLE VM (946MB / 1 OCPU). Plain node ESM, ZERO npm dependencies.
//
// TOP60 ranks implemented here:
//   57. Round-robin scheduler + per-source last_success_ts  (family: infra, effort: S)
//   59. bd_score recalibration from crt.sh O= labelled pairs (family: infra, effort: S)
//
// ═════════════════════════════════════════════════════════════════════════════════════════════════
// THE BUG THIS FILE EXISTS TO KILL
//
// MEASURED on the live system while writing this (GET /api/stats, source_state, 2026-07-20):
//
//     existing-bulk    27,970 harvested   last_run 534.2h ago     ← 22 days silent
//     domains-project  10,374 harvested   last_run 363.4h ago     ← 15 days silent
//     urlscan             946 harvested   last_run 113.5h ago     ←  4 days silent
//     bd-ip-sweep           1 harvested   last_run 409.2h ago     ← 17 days silent, lifetime yield 1
//     osm-overpass          6 harvested   last_run 113.5h ago
//     wiki-edu             42 harvested   last_run  20.8h ago
//
// Six sources had not run in a day or more. Nothing in the system can tell you WHY, because
// source_state has exactly one timestamp — `last_run` — and the Worker writes it inside /harvest,
// i.e. ONLY when a harvester successfully posts rows. So:
//
//     • a harvester that crashed on line 1                 → last_run never moves
//     • a harvester that ran fine and found nothing new    → last_run never moves
//     • a harvester whose payload shape was wrong (found=0)→ last_run never moves
//
// Three completely different conditions, one identical symptom. "Exhausted" is indistinguishable
// from "broken" is indistinguishable from "silently dropping every row". That is the same starvation
// class of bug that already had to be fixed once for the 624 never-swept ASN blocks, and it is why
// only 2 of 12 harvesters ran in a measured 24-hour window.
//
// This scheduler adds the missing dimensions, in a ledger it owns (not in the Worker's schema):
//
//     last_run          when the child process was last STARTED       (always advances)
//     last_success_ts   when the child last actually INSERTED rows    (advances only on real yield)
//     last_ok_ts        when the child last EXITED 0 and reached D1   (yield or not)
//     last_error        the reason string of the last failure         (survives later successes)
//     last_error_ts     when that failure happened
//     health            ok | exhausted | silent | broken | missing
//
// `silent` is the new one and it is the important one: exit code 0, but not a single source_state row
// moved. That is the `{items:[…]}`-instead-of-`{domains:[…]}` failure that cost this project 3,126
// institution hostnames while returning HTTP 200 the whole time. It is NOT exhaustion and must never
// be reported as exhaustion.
//
// ═════════════════════════════════════════════════════════════════════════════════════════════════
// HOW YIELD IS ATTRIBUTED — no stdout scraping, no hardcoded source names
//
// Every VM harvester ultimately POSTs to the Worker's /harvest, which does:
//
//     INSERT INTO source_state (source,last_run,total_harvested,…) … ON CONFLICT DO UPDATE
//
// So D1 already holds an authoritative, source-attributed counter. The scheduler snapshots
// source_state BEFORE a child starts and AFTER it exits, and diffs. Whatever moved during that
// window is that child's yield. This is deliberately better than parsing each harvester's log lines:
//
//     • it cannot drift when another agent renames a source string or adds a phase
//     • it discovers source names the registry below does not know about
//     • it counts what D1 actually stored, not what the script claimed
//
// The declared `sources:` list per entry is used only for display and for the (non-default)
// SCHED_CONCURRENCY>1 case, where windows overlap and diffing alone cannot attribute.
//
// ═════════════════════════════════════════════════════════════════════════════════════════════════
// BACKOFF — skip the exhausted, never drop them
//
// A source that legitimately has nothing new (crt.sh %.mil.bd after you already have every .mil.bd
// host) should not burn a slot every 30 minutes. But it must NEVER be disabled, because "exhausted"
// is a statement about today, not about next week — CT logs get new certs, CrUX publishes a new
// month, a school finally buys a domain.
//
//     health=ok         → multiplier resets to 1
//     health=exhausted  → multiplier ×2, capped at SCHED_EXHAUST_MAX_MULT (default 12)
//     health=broken     → multiplier ×2, capped at SCHED_ERR_MAX_MULT (default 8)
//     health=silent     → treated as broken (it IS broken), never as exhausted
//
// and two hard floors that make permanent starvation structurally impossible:
//
//     1. the effective interval is capped at SCHED_BACKOFF_CAP_H (default 24h), so the sleepiest
//        source on the list is still attempted once a day, forever;
//     2. any source whose last_run is older than SCHED_STARVE_H (default 26h) is promoted to the
//        FRONT of the queue regardless of its backoff — the direct analogue of the round-robin
//        ordering fix that unstarved the 624 ASN blocks.
//
// ═════════════════════════════════════════════════════════════════════════════════════════════════
// STATUS THE DASHBOARD CAN RENDER — without touching the Worker or dashboard/index.html
//
// Other agents own those files, so this emits status through endpoints that already exist:
//
//   1. <SCHED_DIR>/status.json     full ledger, for `harvest-scheduler.mjs status` and for humans
//   2. one STATUS= line on stdout  → journald / /var/log/bd-harvest.log, greppable
//   3. POST /cursor {source:"_sched_status", cursor:"<compact JSON>"}
//        → persisted in source_state.cursor, D1-durable, readable with
//          POST /cursor {"source":"_sched_status"}. The dashboard can render it with a one-line
//          fetch and zero schema change. Compacted to stay well under a KB.
//   4. POST /heartbeat {worker_id:"harvest-sched", state:"<=30 chars", scanned_total:<inserted>}
//        → shows up in the System tab's worker list, which already renders whatever it is given.
//
// The `_sched_status` row is prefixed with an underscore so it sorts to the bottom of the
// "ORDER BY total_harvested DESC" source list and is never mistaken for a harvest source.
//
// ═════════════════════════════════════════════════════════════════════════════════════════════════
// USAGE
//
//   node harvest-scheduler.mjs run          one scheduling tick (what the systemd timer calls)
//   node harvest-scheduler.mjs daemon       same, looping every SCHED_TICK_S (alternative to a timer)
//   node harvest-scheduler.mjs status       print the ledger, exit 0
//   node harvest-scheduler.mjs list         print the registry + next-due times, exit 0
//   node harvest-scheduler.mjs enable  <n>  clear a source's backoff and force it due now
//   node harvest-scheduler.mjs disable <n>  park a source (survives restarts; nothing else can)
//   node harvest-scheduler.mjs calibrate    RANK 59 — bd_score calibration vs crt.sh O= ground truth
//   node harvest-scheduler.mjs systemd [d]  write bd-harvest.service/.timer (+daemon unit) to dir d
//
// ENV (all optional; defaults tuned for the Oracle VM)
//
//   API_BASE                https://bd-hack-audit-api.javed-it.workers.dev
//   SHARED_TOKEN            —          required for run/daemon/status-push and calibrate's seen-set
//   SCHED_DIR               /opt/bd-scanner/.sched     ledger dir; falls back to os.tmpdir()
//   SCHED_SCRIPT_DIR        <dir of this file>         where the harvest-*.mjs live
//   SCHED_NODE              process.execPath           node binary used for children
//   SCHED_TICK_S            600        daemon loop interval (also the recommended timer cadence)
//   SCHED_MAX_PER_TICK      3          how many harvesters may start in one tick
//   SCHED_CONCURRENCY       1          parallel children (1 OCPU → keep at 1; >1 blurs attribution)
//   SCHED_TIMEOUT_S         2700       per-child wall clock before SIGTERM (then SIGKILL at +20s)
//   SCHED_BACKOFF_CAP_H     24         hard ceiling on any backed-off interval
//   SCHED_EXHAUST_MAX_MULT  12         exhausted-source backoff multiplier cap
//   SCHED_ERR_MAX_MULT      8          broken-source backoff multiplier cap
//   SCHED_STARVE_H          26         older than this → jump the queue no matter what
//   SCHED_ONLY              —          comma list: run only these registry names
//   SCHED_SKIP              —          comma list: never run these
//   SCHED_CADENCE_<NAME>    —          override one cadence in hours, e.g. SCHED_CADENCE_CTTAIL=1
//   SCHED_LOG_TAIL          4000       bytes of child stdout/stderr kept for last_error
//   SCHED_CHILD_LOG         1          0 = do not forward child output into the scheduler's log
//   SCHED_DRY_RUN           0          1 = pick and report, never spawn
//   SCHED_PUSH              1          0 = do not POST status to the Worker
//   SCHED_DEBUG             0
//   CAL_POS_URL / CAL_NEG_URLS / CAL_SAMPLE / CAL_TIMEOUT_MS      calibrate-mode knobs (see below)
// ═════════════════════════════════════════════════════════════════════════════════════════════════

import fs from "node:fs";
import fsp from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

import {
  loadBdRanges, isBdHostDetail, eduLexicon, alive, mapLimit,
} from "./bdgate.mjs";

const env = process.env;
const HERE = path.dirname(fileURLToPath(import.meta.url));

const API_BASE = (env.API_BASE || "https://bd-hack-audit-api.javed-it.workers.dev").replace(/\/+$/, "");
const TOKEN = env.SHARED_TOKEN || "";
const SCRIPT_DIR = env.SCHED_SCRIPT_DIR || HERE;
const NODE_BIN = env.SCHED_NODE || process.execPath;

const TICK_S = num(env.SCHED_TICK_S, 600);
const MAX_PER_TICK = num(env.SCHED_MAX_PER_TICK, 3);
const CONCURRENCY = Math.max(1, num(env.SCHED_CONCURRENCY, 1));
const CHILD_TIMEOUT_S = num(env.SCHED_TIMEOUT_S, 2700);
const BACKOFF_CAP_S = num(env.SCHED_BACKOFF_CAP_H, 24) * 3600;
const EXHAUST_MAX_MULT = num(env.SCHED_EXHAUST_MAX_MULT, 12);
const ERR_MAX_MULT = num(env.SCHED_ERR_MAX_MULT, 8);
const STARVE_S = num(env.SCHED_STARVE_H, 26) * 3600;
const LOG_TAIL = num(env.SCHED_LOG_TAIL, 4000);
const CHILD_LOG = env.SCHED_CHILD_LOG !== "0";
const DRY_RUN = env.SCHED_DRY_RUN === "1";
const PUSH = env.SCHED_PUSH !== "0";
const DEBUG = env.SCHED_DEBUG === "1";

function num(v, d) { const n = Number(v); return Number.isFinite(n) && n > 0 ? n : d; }
const nowSec = () => Math.floor(Date.now() / 1000);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const dbg = (...a) => { if (DEBUG) console.error("[sched]", ...a); };
const hAgo = (ts) => (ts ? ((nowSec() - ts) / 3600).toFixed(1) + "h" : "never");

// ── ledger location ──────────────────────────────────────────────────────────────────────────────
// Same fallback shape as bdgate: prefer the VM path, degrade to tmpdir rather than crashing on a Mac.
function resolveDir() {
  const want = env.SCHED_DIR || "/opt/bd-scanner/.sched";
  for (const d of [want, path.join(os.tmpdir(), "bd-sched")]) {
    try { fs.mkdirSync(d, { recursive: true }); fs.accessSync(d, fs.constants.W_OK); return d; } catch {}
  }
  return os.tmpdir();
}
const SCHED_DIR = resolveDir();
const STATE_FILE = path.join(SCHED_DIR, "state.json");
const STATUS_FILE = path.join(SCHED_DIR, "status.json");

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// THE REGISTRY
//
// One entry per harvester script that lives on the VM. `cadence_h` is the natural refresh period of
// the UNDERLYING DATA, not a guess at how often the script feels like running:
//
//   ct-tail     1h   Static-CT tiles are appended continuously (~9.5M certs/day); lag is the enemy.
//   crtsh       2h   Nine TLD slices, 3 per run → full rotation every 6h, which is polite to a free
//                    public service that 502s when hammered.
//   pdns-iptree 2h   Mnemonic caps anonymous use at ~100 req/day, so slots are the scarce resource.
//   tls-san     4h   2.08M BD addresses; a full sweep is a multi-run cursor walk, not a one-shot.
//   crux-full   6h   CrUX publishes MONTHLY. 6h is purely so a new month is noticed the day it lands
//                    — every other run will legitimately report `exhausted`, and that is correct
//                    behaviour, not a fault. This is exactly the case backoff exists for.
//   commoncrawl 6h   New crawl every ~6 weeks; same reasoning as CrUX.
//   crtsh-org   6h   The O=%Bangladesh% pivot is ~1,156 certs total — it saturates fast.
//   vendors     6h   Vendor tenant lists grow slowly; the footer snowball is the compounding part.
//   bdren-asn  12h   ~5,000 addresses. A daily-ish full sweep is plenty.
//   edu-portals12h   Government portals are slow-moving and must not be hammered.
//   eiin       12h   BANBEIS/EIIN registries are static between publication events.
//   urlscan    12h   Free tier is quota-limited.
//   openweb    24h   Wikidata/OSM change on a human timescale.
//   crux-bd    off   Superseded by harvest-crux-full.mjs (same data, narrower slice).
//   overpass   off   Superseded by harvest-openweb.mjs (rank 37 folded in).
//
// `sources` = the source_state strings each script is expected to write, verified against the live
// /api/stats source list on 2026-07-20. Display/attribution aid only — the diff is the real measure.
// ═════════════════════════════════════════════════════════════════════════════════════════════════
const REGISTRY = [
  { name: "ct-tail",     script: "harvest-ct-tail.mjs",     cadence_h: 1,  sources: ["ct-tail"] },
  { name: "crtsh",       script: "harvest-crtsh.mjs",       cadence_h: 2,  sources: ["crtsh"] },
  { name: "pdns-iptree", script: "harvest-pdns-iptree.mjs", cadence_h: 2,  sources: ["pdns-iptree", "ip-tree"] },
  { name: "tls-san",     script: "harvest-tls-san.mjs",     cadence_h: 4,  sources: ["tlssan"] },
  { name: "crux-full",   script: "harvest-crux-full.mjs",   cadence_h: 6,  sources: ["crux-full", "crux", "crux-bd", "crux-bq", "crux-radar"] },
  { name: "commoncrawl", script: "harvest-commoncrawl.mjs", cadence_h: 6,  sources: ["commoncrawl"] },
  { name: "crtsh-org",   script: "harvest-crtsh-org.mjs",   cadence_h: 6,  sources: ["crtsh-org"] },
  { name: "vendors",     script: "harvest-vendors.mjs",     cadence_h: 6,  sources: ["vendors"] },
  { name: "bdren-asn",   script: "harvest-bdren-asn.mjs",   cadence_h: 12, sources: ["bdren-asn"] },
  { name: "edu-portals", script: "harvest-edu-portals.mjs", cadence_h: 12, sources: ["edu-portals", "edu"] },
  { name: "eiin",        script: "harvest-eiin.mjs",        cadence_h: 12, sources: ["eiin"] },
  { name: "urlscan",     script: "harvest-urlscan.mjs",     cadence_h: 12, sources: ["urlscan"], needs: ["URLSCAN_KEY"] },
  { name: "openweb",     script: "harvest-openweb.mjs",     cadence_h: 24, sources: ["openweb", "wikidata", "osm", "wiki-edu"] },
  // Superseded, parked by default. Kept in the registry ON PURPOSE: a parked entry is visible in
  // `list`/`status` as parked, whereas a deleted entry is indistinguishable from one nobody noticed
  // was missing — which is the whole disease this file treats.
  { name: "crux-bd",     script: "harvest-crux-bd.mjs",     cadence_h: 24, sources: ["crux-bd"],     off: "superseded by crux-full" },
  { name: "overpass",    script: "harvest-overpass.mjs",    cadence_h: 24, sources: ["osm-overpass"], off: "superseded by openweb" },
];

function cadenceSecFor(e) {
  const key = "SCHED_CADENCE_" + e.name.toUpperCase().replace(/[^A-Z0-9]/g, "");
  const h = Number(env[key]);
  return (Number.isFinite(h) && h > 0 ? h : e.cadence_h) * 3600;
}

const csv = (s) => String(s || "").split(",").map((x) => x.trim()).filter(Boolean);
const ONLY = csv(env.SCHED_ONLY);
const SKIP = csv(env.SCHED_SKIP);

// ── ledger I/O ───────────────────────────────────────────────────────────────────────────────────
// Written atomically (tmp + rename): a scheduler killed mid-write must never leave a truncated JSON
// ledger behind, because an unreadable ledger silently resets every backoff and every last_success_ts.
async function loadState() {
  try { return JSON.parse(await fsp.readFile(STATE_FILE, "utf8")) || {}; } catch { return {}; }
}
async function saveJson(file, obj) {
  const tmp = file + ".tmp";
  await fsp.writeFile(tmp, JSON.stringify(obj, null, 1));
  await fsp.rename(tmp, file);
}
function blank(e) {
  return {
    name: e.name, script: e.script, cadence_h: e.cadence_h,
    last_run: 0, last_success_ts: 0, last_ok_ts: 0,
    last_error: null, last_error_ts: 0,
    health: "unknown", runs: 0, fails: 0,
    last_inserted: 0, last_found: 0, total_inserted: 0,
    last_duration_ms: 0, last_exit: null,
    mult: 1, next_due: 0,
    // A registry entry carrying `off:` starts parked. `enable <name>` un-parks it and the ledger
    // remembers that forever — the operator's decision outranks the default, in both directions.
    disabled: !!e.off, disabled_reason: e.off || null,
    moved_sources: [],
  };
}

// ── the Worker: source_state snapshot + status push ──────────────────────────────────────────────
/** Snapshot source → {total_harvested, last_run} from the live D1 via /api/stats. */
async function snapshotSources() {
  if (!TOKEN) return null;
  for (let a = 1; a <= 3; a++) {
    try {
      const r = await fetch(API_BASE + "/api/stats", {
        headers: { authorization: "Bearer " + TOKEN },
        signal: AbortSignal.timeout(45000),
      });
      if (!r.ok) { await sleep(a * 1500); continue; }
      const j = await r.json();
      const out = {};
      for (const row of j.sources || []) out[row.source] = { t: Number(row.total_harvested) || 0, r: Number(row.last_run) || 0 };
      return out;
    } catch { await sleep(a * 1500); }
  }
  return null;
}

/**
 * Diff two source_state snapshots, CREDITING ONLY THE ENTRY'S DECLARED SOURCES.
 *
 * ⚠ WHY THE DECLARED LIST IS LOAD-BEARING, not decoration. MEASURED during the first live test of
 * this file: a stub that posted NOTHING was classified `ok` with inserted=3, because another
 * process on the same box (bd-crtsh.timer, or another agent's harvester) posted to `crux-bd` inside
 * the measurement window. Un-scoped window diffing credits whoever happens to be running, which
 * would mark a genuinely broken harvester healthy — the exact failure mode this file exists to
 * prevent, reintroduced by its own instrument. So:
 *
 *   • declared sources (exact, or "<declared>-<phase>") → credited to this entry
 *   • everything else that moved                       → reported as `foreign`, credited to nobody
 *
 * `foreign` is not noise: a source name that moves while no registry entry claims it means a
 * harvester is writing under a name the registry does not know. That is surfaced in the status so
 * it gets fixed, instead of being silently mis-credited.
 *
 * @returns {{inserted:number, moved:string[], touched:boolean, foreign:string[], unknown?:boolean}}
 *   touched = a DECLARED row's last_run advanced — proof this child reached /harvest at all, even
 *   when every row it posted was a duplicate.
 */
function diffSources(before, after, declared) {
  const moved = [], foreign = [];
  let inserted = 0, touched = false;
  if (!before || !after) return { inserted: 0, moved, foreign, touched: false, unknown: true };
  const owns = (src) => !declared || declared.length === 0
    ? true
    : declared.some((d) => src === d || src.startsWith(d + "-"));
  for (const [src, b] of Object.entries(after)) {
    const a = before[src] || { t: 0, r: 0 };
    const d = b.t - a.t;
    const label = src + "+" + Math.max(0, d);
    if (d <= 0 && b.r <= a.r) continue;                   // did not move
    if (owns(src)) { inserted += Math.max(0, d); moved.push(label); touched = true; }
    else foreign.push(label);
  }
  return { inserted, moved, foreign, touched };
}

// One letter per health for the compact wire form. Explicit, NOT health[0] — "unknown" and
// "unconfigured" both start with 'u', and a dashboard that cannot tell "never measured" from
// "missing an API key" is the ambiguity this whole file is here to remove.
const HEALTH_CODE = { ok: "o", exhausted: "e", silent: "s", broken: "b", missing: "m", unknown: "u", unconfigured: "c", parked: "p" };

async function pushStatus(status) {
  if (!PUSH || !TOKEN) return false;
  // Compact wire form — one array-of-arrays per source, no key repetition. ~40 bytes/source, so all
  // 15 fit in well under a kilobyte of source_state.cursor.
  const compact = {
    v: 1, ts: status.ts, tick_ms: status.tick_ms,
    n: status.counts,
    legend: HEALTH_CODE,
    cols: ["name", "health", "last_run", "last_success_ts", "last_inserted", "next_due", "mult"],
    s: status.sources.map((s) => [s.name, HEALTH_CODE[s.health] || "?", s.last_run, s.last_success_ts, s.last_inserted, s.next_due, s.mult]),
  };
  let ok = true;
  try {
    const r = await fetch(API_BASE + "/cursor", {
      method: "POST",
      headers: { authorization: "Bearer " + TOKEN, "content-type": "application/json" },
      body: JSON.stringify({ source: "_sched_status", cursor: JSON.stringify(compact) }),
      signal: AbortSignal.timeout(30000),
    });
    if (!r.ok) ok = false;
  } catch { ok = false; }
  try {
    const c = status.counts;
    await fetch(API_BASE + "/heartbeat", {
      method: "POST",
      headers: { authorization: "Bearer " + TOKEN, "content-type": "application/json" },
      // `state` is truncated to 30 chars by the Worker — keep it inside that budget on purpose.
      body: JSON.stringify({
        worker_id: "harvest-sched",
        state: `${c.ok}ok ${c.exhausted}exh ${c.broken + c.silent + c.missing}bad`.slice(0, 30),
        scanned_total: status.inserted_tick,
      }),
      signal: AbortSignal.timeout(30000),
    });
  } catch { ok = false; }
  return ok;
}

// ── running one harvester ────────────────────────────────────────────────────────────────────────
/**
 * Spawn a harvester, bound its wall clock, keep a bounded tail of its output.
 * The tail is a RING, not an accumulator: a chatty harvester (tls-san logs per IP) must not be able
 * to grow the scheduler's RSS on a 946MB box.
 */
function runChild(entry) {
  return new Promise((resolve) => {
    const file = path.join(SCRIPT_DIR, entry.script);
    const t0 = Date.now();
    let out = "", err = "", killed = null;
    const keep = (buf, s) => { const j = buf + s; return j.length > LOG_TAIL ? j.slice(j.length - LOG_TAIL) : j; };

    let child;
    try {
      child = spawn(NODE_BIN, [file], {
        cwd: SCRIPT_DIR,
        env: { ...env, HARVEST_RUN_BY: "scheduler" },
        stdio: ["ignore", "pipe", "pipe"],
      });
    } catch (e) {
      return resolve({ exit: -1, signal: null, ms: 0, out: "", err: String(e).slice(0, 400), killed: "spawn" });
    }

    // Forward the child's own logging into the scheduler's stdout (→ /var/log/bd-harvest.log), each
    // line tagged with the source name. Without this the scheduler would SWALLOW every harvester's
    // diagnostics and replace them with a one-word health verdict — trading one blind spot for
    // another. Line-split so a partial chunk never produces a mangled prefix.
    const forward = (stream, tag, sink) => {
      let pending = "";
      stream.on("data", (d) => {
        const s = d.toString();
        sink(s);
        pending += s;
        const lines = pending.split("\n");
        pending = lines.pop();
        if (CHILD_LOG) for (const l of lines) if (l.trim()) console.log(`  [${entry.name}${tag}] ${l}`);
      });
      stream.on("end", () => { if (CHILD_LOG && pending.trim()) console.log(`  [${entry.name}${tag}] ${pending}`); });
    };
    forward(child.stdout, "", (s) => { out = keep(out, s); });
    forward(child.stderr, "!", (s) => { err = keep(err, s); });

    const term = setTimeout(() => { killed = "timeout"; try { child.kill("SIGTERM"); } catch {} }, CHILD_TIMEOUT_S * 1000);
    const kill9 = setTimeout(() => { try { child.kill("SIGKILL"); } catch {} }, (CHILD_TIMEOUT_S + 20) * 1000);

    child.on("error", (e) => { err = keep(err, "\nspawn error: " + e.message); });
    child.on("close", (code, signal) => {
      clearTimeout(term); clearTimeout(kill9);
      resolve({ exit: code, signal, ms: Date.now() - t0, out, err, killed });
    });
  });
}

/** Last non-empty line of the child's output — the harvesters all end with a "DONE — …" summary. */
function lastLine(s) {
  const lines = String(s || "").split("\n").map((x) => x.trim()).filter(Boolean);
  return lines.length ? lines[lines.length - 1].slice(0, 300) : "";
}

/**
 * Classify one completed run. The whole point of the file lives in this function.
 *
 *   (missing is decided before we get here — a registry entry pointing at a script that is not on
 *    disk is a deployment bug and must be LOUD, never a silent skip.)
 *   broken    — non-zero exit, a signal, or a timeout kill.
 *   silent    — exit 0, but no source_state row moved at all. The harvester never reached /harvest,
 *               or every row it posted was dropped by the wire-format bug. NOT exhaustion.
 *   exhausted — exit 0, rows reached D1, zero of them were new. Legitimate and expected for the
 *               monthly/6-weekly corpora; this is what backoff is for.
 *   ok        — exit 0 and D1 stored at least one new domain.
 *   unknown   — exit 0 but the snapshot itself failed (no token / stats down), so yield cannot be
 *               judged. Deliberately does NOT touch the backoff multiplier: an unmeasurable run must
 *               never be able to back a healthy source off.
 */
function classify(res, diff) {
  if (res.killed === "timeout") return { health: "broken", reason: `timeout after ${CHILD_TIMEOUT_S}s` };
  if (res.signal) return { health: "broken", reason: `killed by ${res.signal}` };
  if (res.exit !== 0) return { health: "broken", reason: `exit ${res.exit}: ${lastLine(res.err) || lastLine(res.out) || "no output"}` };
  if (diff.unknown) return { health: "unknown", reason: "source_state snapshot unavailable" };
  if (!diff.touched) return { health: "silent", reason: `exit 0 but none of its declared sources moved — the harvester never reached /harvest, or every row was dropped (the items-vs-domains wire bug).${diff.foreign?.length ? ` Other sources DID move during the window (${diff.foreign.join(" ")}) — if one of those belongs to this harvester, add it to the registry's sources list.` : ""} Last line: ${lastLine(res.out) || "(no stdout)"}` };
  if (diff.inserted === 0) return { health: "exhausted", reason: null };
  return { health: "ok", reason: null };
}

/** Apply the classification to the ledger row: timestamps, backoff multiplier, next_due. */
function applyResult(st, entry, res, diff, cls) {
  const now = nowSec();
  const cad = cadenceSecFor(entry);
  st.runs++;
  st.last_exit = res.exit;
  st.last_duration_ms = res.ms;
  st.last_inserted = diff.inserted || 0;
  st.moved_sources = diff.moved || [];
  st.foreign_movers = diff.foreign || [];
  st.health = cls.health;

  if (cls.health === "ok") {
    st.last_success_ts = now;                 // real yield
    st.last_ok_ts = now;
    st.total_inserted += diff.inserted;
    st.mult = 1;                              // healthy → back to full cadence immediately
  } else if (cls.health === "exhausted") {
    st.last_ok_ts = now;                      // it RAN correctly; only last_success_ts stays put
    st.mult = Math.min(Math.max(1, st.mult) * 2, EXHAUST_MAX_MULT);
  } else if (cls.health === "unknown") {
    st.last_ok_ts = now;
    // multiplier untouched on purpose — see classify()
  } else {                                    // broken | silent | missing
    st.fails++;
    st.last_error = cls.reason ? cls.reason.slice(0, 600) : "unclassified failure";
    st.last_error_ts = now;
    st.mult = Math.min(Math.max(1, st.mult) * 2, ERR_MAX_MULT);
  }

  const interval = Math.min(cad * Math.max(1, st.mult), BACKOFF_CAP_S);
  st.next_due = now + interval;
  st.cadence_h = entry.cadence_h;
  return st;
}

/** Ordering = the anti-starvation guarantee. Starved first, then oldest-run first. */
function pickDue(state, now) {
  const due = [], parked = [];
  for (const e of REGISTRY) {
    if (ONLY.length && !ONLY.includes(e.name)) continue;
    if (SKIP.includes(e.name)) continue;
    const st = state[e.name] || (state[e.name] = blank(e));
    if (st.disabled) { parked.push(e.name); continue; }
    const missingEnv = (e.needs || []).filter((k) => !env[k]);
    if (missingEnv.length) {
      // Not a failure and not a backoff event — the source is simply unconfigured. Recorded so the
      // status line says WHY it never runs instead of leaving another silent zero.
      st.health = "unconfigured";
      st.last_error = "missing env: " + missingEnv.join(",");
      parked.push(e.name);
      continue;
    }
    const starved = st.last_run > 0 && now - st.last_run > STARVE_S;
    const neverRan = st.last_run === 0;
    if (starved || neverRan || now >= (st.next_due || 0)) {
      due.push({ e, st, pri: starved ? 0 : neverRan ? 1 : 2, key: st.last_run || 0 });
    }
  }
  due.sort((a, b) => a.pri - b.pri || a.key - b.key);   // round-robin: least-recently-run wins
  return { due, parked };
}

function buildStatus(state, tickMs, insertedTick, started) {
  const now = nowSec();
  const counts = { ok: 0, exhausted: 0, silent: 0, broken: 0, missing: 0, unknown: 0, unconfigured: 0, parked: 0 };
  const sources = [];
  for (const e of REGISTRY) {
    const st = state[e.name] || blank(e);
    const h = st.disabled ? "parked" : (st.health || "unknown");
    counts[h] = (counts[h] || 0) + 1;
    sources.push({
      name: e.name, script: e.script, health: h, cadence_h: e.cadence_h,
      last_run: st.last_run, last_success_ts: st.last_success_ts, last_ok_ts: st.last_ok_ts,
      last_error: st.last_error, last_error_ts: st.last_error_ts,
      last_inserted: st.last_inserted, total_inserted: st.total_inserted,
      last_duration_ms: st.last_duration_ms, runs: st.runs, fails: st.fails,
      mult: st.mult, next_due: st.next_due, moved_sources: st.moved_sources, foreign_movers: st.foreign_movers || [],
      stale_h: st.last_success_ts ? Number(((now - st.last_success_ts) / 3600).toFixed(1)) : null,
    });
  }
  return {
    v: 1, ts: now, tick_ms: tickMs, ran: started, inserted_tick: insertedTick,
    counts, sources, api: API_BASE, dir: SCHED_DIR,
  };
}

function statusLine(s) {
  const c = s.counts;
  const bad = s.sources.filter((x) => ["broken", "silent", "missing"].includes(x.health)).map((x) => x.name);
  return `STATUS ok=${c.ok} exhausted=${c.exhausted} silent=${c.silent} broken=${c.broken} missing=${c.missing} parked=${c.parked} unconfigured=${c.unconfigured} unknown=${c.unknown} | ran=${s.ran.join(",") || "-"} inserted=${s.inserted_tick} tick=${(s.tick_ms / 1000).toFixed(1)}s${bad.length ? " | NEEDS-ATTENTION: " + bad.join(",") : ""}`;
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// SINGLE-INSTANCE LOCK
//
// Attribution assumes the scheduler is the ONLY thing starting harvesters, because yield is measured
// by diffing a shared, global source_state. Two overlapping ticks break that assumption in the worst
// possible way: each credits the other's inserts, so a dead harvester reads as healthy. MEASURED
// while testing this file — a stub that posted nothing was classified `ok` purely because another
// process wrote to D1 inside its window.
//
// A slow tick (tls-san can run 45 minutes) overlapping the next timer fire is the realistic way that
// happens in production, so the lock is not optional. Stale locks (crash, OOM, SIGKILL) are reclaimed
// by checking whether the recorded pid is still alive.
// ═════════════════════════════════════════════════════════════════════════════════════════════════
const LOCK_FILE = path.join(SCHED_DIR, "tick.lock");

function acquireLock() {
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const fd = fs.openSync(LOCK_FILE, "wx");            // atomic create-or-fail
      fs.writeSync(fd, JSON.stringify({ pid: process.pid, ts: nowSec() }));
      fs.closeSync(fd);
      return true;
    } catch (e) {
      if (e.code !== "EEXIST") throw e;
      let held = null;
      try { held = JSON.parse(fs.readFileSync(LOCK_FILE, "utf8")); } catch {}
      const pid = held?.pid;
      let running = false;
      try { if (pid) { process.kill(pid, 0); running = true; } } catch { running = false; }
      const ageS = nowSec() - (held?.ts || 0);
      if (running && ageS < (CHILD_TIMEOUT_S * MAX_PER_TICK + 600)) {
        console.log(`[sched] another tick is running (pid ${pid}, ${ageS}s old) — skipping this slot, which is correct, not an error.`);
        return false;
      }
      console.error(`[sched] reclaiming stale lock (pid ${pid ?? "?"}, ${ageS}s old, running=${running})`);
      try { fs.unlinkSync(LOCK_FILE); } catch {}
    }
  }
  return false;
}
function releaseLock() { try { fs.unlinkSync(LOCK_FILE); } catch {} }

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// ONE TICK
// ═════════════════════════════════════════════════════════════════════════════════════════════════
async function tick() {
  const t0 = Date.now();
  const state = await loadState();
  const now = nowSec();
  const { due, parked } = pickDue(state, now);
  const batch = due.slice(0, MAX_PER_TICK);

  console.log(`[sched] ${new Date().toISOString()} due=${due.length} parked=${parked.length} running=${batch.map((x) => x.e.name).join(",") || "-"}${DRY_RUN ? " (DRY RUN)" : ""}`);

  let insertedTick = 0;
  const started = [];
  // Serial mode reuses the previous child's "after" snapshot as the next child's "before" — one
  // fewer /api/stats round trip per harvester, and the windows are guaranteed to abut with no gap.
  let carried = null;

  const runOne = async ({ e, st }) => {
    const file = path.join(SCRIPT_DIR, e.script);
    const exists = fs.existsSync(file);
    started.push(e.name);
    // A dry run must leave the ledger EXACTLY as it found it. Advancing last_run here would make the
    // next real tick believe the source had just run and skip it — a dry run that causes a real skip
    // is a starvation bug wearing a debugging flag.
    if (DRY_RUN) { console.log(`[sched] ${e.name}: would run ${file}${exists ? "" : "  [SCRIPT MISSING]"}`); return; }
    st.last_run = nowSec();                    // ALWAYS advances — the whole point vs the Worker's field
    if (!exists) {
      applyResult(st, e, { exit: -1, signal: null, ms: 0, out: "", err: "" }, { inserted: 0, moved: [], foreign: [], touched: false }, { health: "missing", reason: `script not found: ${file}` });
      console.log(`[sched] ${e.name}: MISSING ${file}`);
      return;
    }

    const before = (CONCURRENCY === 1 && carried) || (await snapshotSources());
    const res = await runChild(e);
    // /harvest → source_state is a synchronous D1 write, but /api/stats caches for 15s. Wait past
    // that window, otherwise a fast harvester's real yield reads back as 0 and gets mislabelled
    // "exhausted" — a false exhaustion is exactly as damaging as the bug this file fixes.
    await sleep(18000);
    const after = await snapshotSources();
    if (CONCURRENCY === 1) carried = after;
    const diff = diffSources(before, after, e.sources);
    const cls = classify(res, diff);
    applyResult(st, e, res, diff, cls);
    insertedTick += diff.inserted || 0;
    console.log(`[sched] ${e.name}: ${cls.health} exit=${res.exit} ${(res.ms / 1000).toFixed(0)}s inserted=${diff.inserted} moved=[${(diff.moved || []).join(" ")}]${(diff.foreign || []).length ? ` foreign=[${diff.foreign.join(" ")}]` : ""} mult=${st.mult} next=${new Date(st.next_due * 1000).toISOString()}${cls.reason ? "\n[sched]   reason: " + cls.reason : ""}`);
  };

  if (CONCURRENCY > 1) await mapLimit(batch, CONCURRENCY, runOne);
  else for (const item of batch) await runOne(item);

  const status = buildStatus(state, Date.now() - t0, insertedTick, started);
  await saveJson(STATE_FILE, state);
  await saveJson(STATUS_FILE, status);
  const pushed = await pushStatus(status);
  console.log(statusLine(status) + (PUSH ? ` | pushed=${pushed}` : ""));
  return status;
}

/** tick() under the single-instance lock, released even if a child throws. */
async function lockedTick() {
  if (!acquireLock()) return null;
  const off = () => { releaseLock(); process.exit(130); };
  process.once("SIGTERM", off);
  process.once("SIGINT", off);
  try { return await tick(); } finally { releaseLock(); }
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// RANK 59 — bd_score calibration against crt.sh O= ground truth
//
// The problem: CrUX / Common Crawl / CZDS hand this system hundreds of thousands of hostnames with
// NO country label. Something has to decide which of them are worth a scan slot. That decision is a
// number — bd_score — and until now nobody had measured what any particular value of it means.
//
// The ground truth: crt.sh's O= parameter searches the certificate SUBJECT ORGANISATION, which for
// an OV/EV certificate is a legal entity a Certificate Authority independently VALIDATED. Querying
//   https://crt.sh/?O=%25Bangladesh%25&output=json
// returns certs whose subject organisation contains "Bangladesh" — BRAC Bangladesh, icddr,b, etc.
// (NOTE the field swap on this query: `common_name` holds the DOMAIN and `name_value` holds the ORG,
// the reverse of the ?q= query.) That is a CA-validated organisation→domain pair: exactly the kind
// of evidence a hostname string can never be.
//
// The negatives: the same query for India and Pakistan. They are the correct control precisely
// because they are South Asian — same registrars, same hosting brands, same cheap-CA mix, often
// neighbouring IP space. A negative set of random US .coms would flatter the score enormously and
// prove nothing.
//
// The scorer below uses ONLY signals a bulk harvester can afford on an unlabelled corpus, and it is
// deliberately built on isBdHostDetail(): hosting IP, nameserver, TLD. The name lexicon contributes
// a few points of tie-break and can never carry a domain over the line on its own — the same rule
// bdgate enforces, expressed as arithmetic.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────────
// MEASURED CALIBRATION — 2026-07-20, 53 positives vs 79 negatives, live DoH, 26s
//
//   positives  crt.sh O=%Bangladesh%  1,156 certs → 104 apexes / 88 orgs → 53 on non-.bd TLDs
//   negatives  crt.sh O=%Nepal%         693 certs →  80 apexes / 68 orgs → 79 after de-dup
//
//   threshold   TP  FP  precision  recall  recall_live
//     >=  0     53  79    0.402     1.000     1.000     ← degenerate: admits everything
//     >=  5     13   0    1.000     0.245     0.333     ← KNEE, recommended
//     >= 30     10   0    1.000     0.189     0.256
//     >= 60      2   0    1.000     0.038     0.051
//
// THREE FINDINGS, and the second one is the one that matters:
//
// 1. PRECISION IS PERFECT AND CHEAP. Not one of 79 Nepali organisations scored above zero —
//    including nepalarmy.mil.np, nta.gov.np, nepalbank.com.np and ntc.net.np, all of which are
//    exactly the institutional shapes this system hunts. The IP/NS gate simply does not confuse a
//    neighbouring South Asian country for Bangladesh. There is no precision/recall trade-off to
//    tune here: every threshold from 5 to 80 has precision 1.000.
//
// 2. THE THRESHOLD IS NOT THE BINDING CONSTRAINT — THE EVIDENCE IS. Thresholds 5/10/15/20/25 are
//    bit-identical on this sample, so the score carries NO resolution across that range and the
//    decision is effectively binary: any BD hosting/NS evidence, or none. Raising the bar only
//    destroys recall (>=30 drops 3 true BD orgs, >=60 drops 11). Recall stalls at 33% of LIVE
//    positives not because the cut is wrong but because 26 of 39 resolving BD organisations are
//    hosted OUTSIDE Bangladesh — brac.net, rahimafrooz.com, eximbankbd.com, sharetrip.net,
//    communitybankbd.com. This is bdgate's documented and accepted limit, now quantified: roughly
//    two thirds of Bangladeshi organisations on a .com are invisible to every free BD-ness signal.
//    Note eximbankbd.com and communitybankbd.com score 0 despite "bd" in the name — correct, and
//    precisely why the recall ceiling cannot be raised by relaxing the name rule.
//
// 3. 26% OF CERTIFICATE-DERIVED POSITIVES ARE ALREADY DEAD (14 of 53, reason=no-a-record). Rank
//    58's corpse problem, confirmed on an independent sample. Any recall number quoted against a
//    CT-derived corpus without an aliveness filter is understated by about a quarter.
//
// OPERATIONAL CONCLUSION: keep the admission cut at bd_score >= 5, i.e. "any positive BD evidence".
// Do not spend effort tuning the number. The way to raise BD yield is to add EVIDENCE — the rank 11
// crt.sh O= pivot is itself the strongest available oracle for exactly the foreign-hosted .com case
// the IP gate misses, which is why harvest-crtsh-org.mjs exists and why it earns a 6h slot in the
// registry above despite a lifetime yield of only 31 rows so far.
//
// Reproduce with:  node harvest-scheduler.mjs calibrate      (crt.sh responses are cached 7 days)
// ═════════════════════════════════════════════════════════════════════════════════════════════════

const W = {
  bdTld: 60, instBdTld: 15, ipInBd: 55, nsBdTld: 30, nsIpInBd: 25,
  isEdu: 8, isBdish: 5, aliveBonus: 5, spam: -60, foreignHosting: -10, noA: -5,
};

/**
 * bd_score for an unlabelled hostname, 0-100.
 * @param {string} host
 * @param {{checkAlive?:boolean}} [opts]
 * @returns {Promise<{score:number, reason:string, parts:string[]}>}
 */
export async function bdScoreOf(host, opts = {}) {
  const d = await isBdHostDetail(host);
  const lex = eduLexicon(host);
  const parts = [];
  let s = 0;

  if (/\.bd$/.test(d.host || "")) {
    s += W.bdTld; parts.push("bd-tld+" + W.bdTld);
    if (/\.(edu|ac|gov|mil)\.bd$/.test(d.host)) { s += W.instBdTld; parts.push("inst-bd+" + W.instBdTld); }
  }
  if (d.reason === "ip-in-bd") { s += W.ipInBd; parts.push("ip-in-bd+" + W.ipInBd); }
  if (d.reason === "ns-bd-tld") { s += W.nsBdTld; parts.push("ns-bd-tld+" + W.nsBdTld); }
  if (d.reason === "ns-ip-in-bd") { s += W.nsIpInBd; parts.push("ns-ip-in-bd+" + W.nsIpInBd); }
  if (d.reason === "foreign-hosting") { s += W.foreignHosting; parts.push("foreign-host" + W.foreignHosting); }
  if (d.reason === "no-a-record") { s += W.noA; parts.push("no-a" + W.noA); }
  if (lex.isEdu) { s += W.isEdu; parts.push("edu-name+" + W.isEdu); }
  if (lex.isBdish) { s += W.isBdish; parts.push("bd-name+" + W.isBdish); }
  if (lex.isSpammy) { s += W.spam; parts.push("SPAM" + W.spam); }
  if (opts.checkAlive && (await alive(host))) { s += W.aliveBonus; parts.push("alive+" + W.aliveBonus); }

  return { score: Math.max(0, Math.min(100, Math.round(s))), reason: d.reason, parts };
}

/**
 * Fetch (and cache) a crt.sh organisation query.
 *
 * The response is cached on disk because these queries are EXPENSIVE for a free public service —
 * O=%Bangladesh% measured 126.7s / 455KB / 1,156 certs — and because crt.sh answers 429 the moment
 * several processes ask at once (MEASURED: two sequential org queries 20s apart both returned
 * HTTP 429 while other harvesters on this box were also querying crt.sh). Calibration is an offline
 * analysis of a slow-moving ground truth; re-downloading it on every run would be rude and would
 * make the result non-reproducible. CAL_TTL_H (default 168 = one week) bounds the staleness.
 */
async function crtshOrg(pattern, timeoutMs) {
  const cache = path.join(SCHED_DIR, "crtorg-" + pattern.replace(/[^A-Za-z0-9]/g, "") + ".json");
  const ttlMs = num(env.CAL_TTL_H, 168) * 3600 * 1000;
  try {
    if (Date.now() - (await fsp.stat(cache)).mtimeMs < ttlMs) {
      const rows = JSON.parse(await fsp.readFile(cache, "utf8"));
      // A crt.sh 502/503 answers with an HTML error page, and a killed download leaves a truncated
      // body. Either one cached as "the ground truth" would silently produce a calibration computed
      // on nothing. Only a non-empty array counts.
      if (!Array.isArray(rows) || rows.length === 0) throw new Error("unusable cache");
      console.log(`[cal] O=${pattern}: ${rows.length} certs from cache ${cache}`);
      return rows;
    }
  } catch {}

  const url = `https://crt.sh/?O=${encodeURIComponent(pattern)}&output=json`;
  for (let a = 1; a <= 4; a++) {
    try {
      const r = await fetch(url, {
        headers: { "user-agent": "Mozilla/5.0 (compatible; bd-hack-audit/1.0)", accept: "application/json" },
        signal: AbortSignal.timeout(timeoutMs),   // crt.sh needs 120s+ for these; 30s guarantees failure
      });
      if (!r.ok) { console.error(`[cal] crt.sh O=${pattern} HTTP ${r.status} (try ${a}/4)`); await sleep(a * 30000); continue; }
      const txt = await r.text();
      const rows = JSON.parse(txt);
      try { await fsp.writeFile(cache, txt); } catch {}
      return rows;
    } catch (e) { console.error(`[cal] crt.sh O=${pattern} ${String(e).slice(0, 70)} (try ${a}/4)`); await sleep(a * 30000); }
  }
  return null;
}

/** Registrable-ish apex from a cert common_name. Wildcards contribute their apex only. */
function apexOf(cn) {
  let h = String(cn || "").trim().toLowerCase().replace(/^\*\./, "");
  if (!h || h.includes(" ") || h.includes("@") || !/^[a-z0-9.-]+$/.test(h)) return null;
  const p = h.split(".");
  if (p.length < 2) return null;
  const multi = /\.(com|net|org|edu|ac|gov|mil|co|info)\.[a-z]{2}$/.test(h);
  return p.slice(multi ? -3 : -2).join(".");
}

async function calibrate() {
  const TIMEOUT = num(env.CAL_TIMEOUT_MS, 200000);
  const SAMPLE = num(env.CAL_SAMPLE, 220);
  const posPat = env.CAL_POS_URL || "%Bangladesh%";
  // Four negative patterns, not one, because crt.sh org queries are heavy and flaky: %India% is a
  // very large result set and was MEASURED returning 503/429/connection-reset repeatedly while other
  // harvesters on the box were also querying crt.sh. Nepal and Sri Lanka are small enough to answer
  // when India will not. Dead patterns are dropped and the surviving ones still form a valid negative
  // set — a calibration that silently ran on zero negatives would be worse than no calibration.
  const negPats = csv(env.CAL_NEG_URLS || "%Nepal%,%Sri Lanka%,%Pakistan%,%India%");

  await loadBdRanges();
  console.log(`[cal] scoring weights: ${JSON.stringify(W)}`);

  const grab = async (pat) => {
    const rows = await crtshOrg(pat, TIMEOUT);
    if (!rows) return { pat, apexes: [], orgs: 0, certs: 0, dead: true };
    const byApex = new Map();
    for (const r of rows) {
      const a = apexOf(r.common_name);
      if (!a) continue;
      if (!byApex.has(a)) byApex.set(a, String(r.name_value || "").split("\n")[0].slice(0, 80));
    }
    return { pat, apexes: [...byApex.keys()], orgs: new Set([...byApex.values()]).size, certs: rows.length, dead: false };
  };

  const pos = await grab(posPat);
  console.log(`[cal] POS ${posPat}: ${pos.certs} certs → ${pos.apexes.length} apexes, ${pos.orgs} distinct orgs`);
  if (pos.dead) { console.error("[cal] positive set unavailable — crt.sh refused. Aborting rather than reporting a fake calibration."); process.exit(1); }

  const negSets = [];
  for (const p of negPats) { await sleep(20000); const g = await grab(p); console.log(`[cal] NEG ${p}: ${g.certs} certs → ${g.apexes.length} apexes, ${g.orgs} orgs${g.dead ? " (DEAD)" : ""}`); if (!g.dead) negSets.push(g); }

  const posSet = new Set(pos.apexes);
  const negApexes = [...new Set(negSets.flatMap((g) => g.apexes))].filter((a) => !posSet.has(a));
  if (!negApexes.length) { console.error("[cal] every negative pattern failed — refusing to report a one-sided calibration."); process.exit(1); }

  // A BD org's own .bd domain is trivially scorable and would inflate every number. The interesting
  // population — and the one CrUX/CC/CZDS actually deliver — is BD organisations on non-.bd TLDs.
  const posNonBd = pos.apexes.filter((a) => !a.endsWith(".bd"));
  const sample = (arr, n) => { const c = [...arr]; for (let i = c.length - 1; i > 0; i--) { const j = (i * 2654435761) % (i + 1); [c[i], c[j]] = [c[j], c[i]]; } return c.slice(0, n); };

  const P = sample(posNonBd, SAMPLE), N = sample(negApexes, SAMPLE);
  console.log(`[cal] scoring ${P.length} positives (BD org, non-.bd TLD) vs ${N.length} negatives (IN/PK org)…`);

  const scoreAll = async (list, label) => {
    let done = 0;
    return mapLimit(list, 8, async (h) => {
      const r = await bdScoreOf(h);
      if (++done % 50 === 0) console.error(`[cal]   ${label} ${done}/${list.length}`);
      return { host: h, ...r };
    });
  };
  const t0 = Date.now();
  const ps = await scoreAll(P, "pos");
  const ns = await scoreAll(N, "neg");
  console.log(`[cal] scored ${ps.length + ns.length} hosts in ${((Date.now() - t0) / 1000).toFixed(0)}s`);

  const hist = (rows) => { const h = {}; for (const r of rows) h[r.score] = (h[r.score] || 0) + 1; return h; };
  const reasons = (rows) => { const h = {}; for (const r of rows) h[r.reason] = (h[r.reason] || 0) + 1; return h; };
  console.log(`[cal] POS score histogram: ${JSON.stringify(hist(ps))}`);
  console.log(`[cal] NEG score histogram: ${JSON.stringify(hist(ns))}`);
  console.log(`[cal] POS reasons: ${JSON.stringify(reasons(ps))}`);
  console.log(`[cal] NEG reasons: ${JSON.stringify(reasons(ns))}`);

  // Recall is also reported over LIVE positives only. 26% of the certificate-derived positives no
  // longer resolve at all (rank 58's corpse problem, visible here as reason=no-a-record), and a
  // recall figure that counts dead domains as misses understates the gate against the population
  // that actually matters — the hosts a scanner could ever reach.
  const posLive = ps.filter((r) => r.reason !== "no-a-record");

  const table = [];
  for (const th of [0, 5, 10, 15, 20, 25, 30, 40, 50, 55, 60, 70, 80]) {
    const tp = ps.filter((r) => r.score >= th).length;
    const fp = ns.filter((r) => r.score >= th).length;
    const fn = ps.length - tp, tn = ns.length - fp;
    const prec = tp + fp ? tp / (tp + fp) : 1;
    const rec = ps.length ? tp / ps.length : 0;
    const recLive = posLive.length ? posLive.filter((r) => r.score >= th).length / posLive.length : 0;
    const f1 = prec + rec ? (2 * prec * rec) / (prec + rec) : 0;
    table.push({ th, tp, fp, fn, tn, precision: +prec.toFixed(3), recall: +rec.toFixed(3), recall_live: +recLive.toFixed(3), f1: +f1.toFixed(3) });
  }
  console.log("[cal] threshold  TP   FP   FN   TN  precision recall  recall_live    F1");
  for (const r of table) console.log(`[cal]   >=${String(r.th).padStart(3)}  ${String(r.tp).padStart(4)} ${String(r.fp).padStart(4)} ${String(r.fn).padStart(4)} ${String(r.tn).padStart(4)}     ${r.precision.toFixed(3)}  ${r.recall.toFixed(3)}       ${r.recall_live.toFixed(3)}  ${r.f1.toFixed(3)}`);

  // ⚠ F1 IS THE WRONG OBJECTIVE HERE AND THE RECOMMENDER MUST SAY SO.
  //
  // With a positive set this hard, raw F1 peaks at threshold 0 — "admit everything" — which scores
  // well only because recall is free there. Shipping that number would be advice to fill the scan
  // queue with every unlabelled domain on earth, i.e. the exact 24,000-row purge this project
  // already survived once. So the degenerate region (precision below chance-level) is excluded from
  // the F1 recommendation, and the operating point that is actually reported is the KNEE: the
  // LOWEST threshold that still holds precision, because everything above the knee costs recall and
  // buys nothing.
  const baseRate = ps.length / (ps.length + ns.length);
  const usable = table.filter((r) => r.tp > 0 && r.precision > Math.max(0.5, baseRate));
  const bestF1raw = table.reduce((a, b) => (b.f1 > a.f1 ? b : a));
  const bestF1 = usable.length ? usable.reduce((a, b) => (b.f1 > a.f1 ? b : a)) : null;
  const knee = table.filter((r) => r.precision >= 0.95 && r.tp > 0).sort((a, b) => a.th - b.th)[0] || null;
  const degenerate = bestF1raw.precision <= Math.max(0.5, baseRate);

  if (degenerate) console.log(`[cal] NOTE: raw best-F1 lands at >=${bestF1raw.th} with precision ${bestF1raw.precision} (base rate ${baseRate.toFixed(3)}) — that is the degenerate "admit everything" point and is NOT a recommendation.`);
  if (knee) console.log(`[cal] RECOMMENDED operating threshold (knee): bd_score >= ${knee.th}  P=${knee.precision}  R=${knee.recall}  R_live=${knee.recall_live}`);
  if (bestF1) console.log(`[cal] best non-degenerate F1: bd_score >= ${bestF1.th} (F1=${bestF1.f1})`);

  // Granularity check: if a run of thresholds is identical, the score has no resolution there and
  // pretending otherwise invites someone to "tune" a number that does nothing.
  const plateau = knee ? table.filter((r) => r.tp === knee.tp && r.fp === knee.fp).map((r) => r.th) : [];
  if (plateau.length > 1) console.log(`[cal] NOTE: thresholds ${plateau.join("/")} are IDENTICAL on this sample — the score carries no resolution across that range; the decision is effectively binary (any BD evidence vs none).`);

  const out = {
    ts: nowSec(), weights: W,
    positives: { pattern: posPat, certs: pos.certs, apexes: pos.apexes.length, nonBd: posNonBd.length, scored: ps.length },
    negatives: { patterns: negPats, apexes: negApexes.length, scored: ns.length },
    posHist: hist(ps), negHist: hist(ns), posReasons: reasons(ps), negReasons: reasons(ns),
    posLive: posLive.length, baseRate: +baseRate.toFixed(3),
    table, knee, bestF1, bestF1raw, degenerate, plateau,
    posSamples: ps.slice(0, 25).map((r) => ({ host: r.host, score: r.score, reason: r.reason })),
    negSamples: ns.slice(0, 25).map((r) => ({ host: r.host, score: r.score, reason: r.reason })),
  };
  await saveJson(path.join(SCHED_DIR, "calibration.json"), out);
  console.log(`[cal] written ${path.join(SCHED_DIR, "calibration.json")}`);
  return out;
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// systemd units. bd-scanner.service is the reference for the Restart/logging shape.
//
// The scheduler is a TIMER + oneshot, not a daemon: a oneshot cannot leak, cannot wedge, and if the
// box reboots mid-run systemd simply fires it again. Persistent=true is the load-bearing flag — it
// makes systemd run a missed slot after downtime instead of silently waiting for the next one, which
// is the same class of silent skip this whole file exists to eliminate.
// ═════════════════════════════════════════════════════════════════════════════════════════════════
const UNITS = {
  "bd-harvest.service": `[Unit]
Description=BD Hack-Audit harvest scheduler (round-robin, one tick)
Documentation=file:///opt/bd-scanner/harvest-scheduler.mjs
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
WorkingDirectory=/opt/bd-scanner
EnvironmentFile=/opt/bd-scanner/scanner.env
ExecStart=/usr/bin/node /opt/bd-scanner/harvest-scheduler.mjs run
# One tick may start up to SCHED_MAX_PER_TICK children at SCHED_TIMEOUT_S each. The ceiling below is
# the scheduler's own guard: if it is ever exceeded, systemd kills the tick rather than letting two
# ticks overlap and double-run a harvester.
TimeoutStartSec=9000
# 946MB box. The scheduler itself is ~50MB; the cap is a backstop against a child that misbehaves.
MemoryMax=700M
Nice=10
StandardOutput=append:/var/log/bd-harvest.log
StandardError=append:/var/log/bd-harvest.log

[Install]
WantedBy=multi-user.target
`,

  "bd-harvest.timer": `[Unit]
Description=Run the BD Hack-Audit harvest scheduler every 10 minutes
Documentation=file:///opt/bd-scanner/harvest-scheduler.mjs

[Timer]
# Fire 2 minutes after boot so a reboot does not cost a whole slot.
OnBootSec=2min
OnUnitInactiveSec=10min
# THE IMPORTANT ONE: after downtime, run the missed slot immediately instead of silently skipping it.
Persistent=true
# Spread load so this never lands on the same second as bd-crtsh.timer.
RandomizedDelaySec=60
AccuracySec=30s
Unit=bd-harvest.service

[Install]
WantedBy=timers.target
`,

  "bd-harvest-daemon.service": `[Unit]
Description=BD Hack-Audit harvest scheduler (daemon mode — ALTERNATIVE to bd-harvest.timer)
Documentation=file:///opt/bd-scanner/harvest-scheduler.mjs
After=network-online.target
Wants=network-online.target
# Mutually exclusive with the timer. Enable ONE of them, never both, or every harvester double-runs.
Conflicts=bd-harvest.timer

[Service]
Type=simple
WorkingDirectory=/opt/bd-scanner
EnvironmentFile=/opt/bd-scanner/scanner.env
ExecStart=/usr/bin/node /opt/bd-scanner/harvest-scheduler.mjs daemon
Restart=always
RestartSec=15
StartLimitIntervalSec=0
MemoryMax=700M
Nice=10
StandardOutput=append:/var/log/bd-harvest.log
StandardError=append:/var/log/bd-harvest.log

[Install]
WantedBy=multi-user.target
`,
};

async function emitSystemd(dir) {
  const target = dir || SCHED_DIR;
  await fsp.mkdir(target, { recursive: true });
  for (const [name, body] of Object.entries(UNITS)) {
    await fsp.writeFile(path.join(target, name), body);
    console.log("wrote " + path.join(target, name));
  }
  console.log(`
Install (as root on the VM):
  cp ${target}/bd-harvest.service ${target}/bd-harvest.timer /etc/systemd/system/
  systemctl daemon-reload
  systemctl enable --now bd-harvest.timer
  systemctl list-timers bd-harvest.timer
  journalctl -u bd-harvest.service -n 50 --no-pager
  # or, instead of the timer:  systemctl enable --now bd-harvest-daemon.service`);
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// CLI
// ═════════════════════════════════════════════════════════════════════════════════════════════════
function printStatus(s) {
  console.log(`# harvest scheduler status  ${new Date(s.ts * 1000).toISOString()}  dir=${s.dir}`);
  console.log("name         health        cadence  last_run  last_success  last_ins  total   mult  next_due   last_error");
  for (const r of s.sources) {
    console.log(
      r.name.padEnd(12) +
      r.health.padEnd(13) +
      (r.cadence_h + "h").padStart(6) + "  " +
      hAgo(r.last_run).padStart(8) + "  " +
      hAgo(r.last_success_ts).padStart(12) + "  " +
      String(r.last_inserted).padStart(8) + "  " +
      String(r.total_inserted).padStart(6) + "  " +
      String("x" + r.mult).padStart(4) + "  " +
      (r.next_due ? new Date(r.next_due * 1000).toISOString().slice(11, 16) : "  -  ").padStart(8) + "  " +
      // last_error is deliberately NOT cleared by a later success — "it broke 3 hours ago and then
      // recovered" is information an operator wants. It is tagged stale so a healed source is never
      // mistaken for a currently-broken one.
      (r.last_error ? (r.last_ok_ts > r.last_error_ts ? "(healed " + hAgo(r.last_error_ts) + ") " : "") + r.last_error.slice(0, 70) : "")
    );
  }
  console.log(statusLine(s));
}

async function main() {
  const cmd = (process.argv[2] || "run").toLowerCase();
  const arg = process.argv[3];

  if (cmd === "help" || cmd === "-h" || cmd === "--help") {
    console.log("usage: harvest-scheduler.mjs run|daemon|status|list|enable <n>|disable <n>|calibrate|systemd [dir]");
    return;
  }

  if (cmd === "systemd") return void (await emitSystemd(arg));

  if (cmd === "calibrate") return void (await calibrate());

  if (cmd === "list") {
    const state = await loadState();
    const now = nowSec();
    console.log("name         script                        cadence  next_due          health");
    for (const e of REGISTRY) {
      const st = state[e.name] || blank(e);
      const due = st.disabled ? "PARKED (" + (st.disabled_reason || e.off || "") + ")"
        : (!st.next_due || now >= st.next_due) ? "DUE NOW" : new Date(st.next_due * 1000).toISOString();
      const ex = fs.existsSync(path.join(SCRIPT_DIR, e.script)) ? "" : "  [SCRIPT MISSING]";
      console.log(e.name.padEnd(12) + e.script.padEnd(30) + (e.cadence_h + "h").padStart(6) + "  " + due.padEnd(26) + (st.health || "unknown") + ex);
    }
    return;
  }

  if (cmd === "enable" || cmd === "disable") {
    if (!arg) { console.error("need a source name"); process.exit(1); }
    const state = await loadState();
    const e = REGISTRY.find((x) => x.name === arg);
    if (!e) { console.error("unknown source: " + arg + " (known: " + REGISTRY.map((x) => x.name).join(",") + ")"); process.exit(1); }
    const st = state[arg] || (state[arg] = blank(e));
    if (cmd === "enable") { st.disabled = false; st.disabled_reason = null; st.mult = 1; st.next_due = 0; console.log(arg + " enabled, backoff cleared, due now"); }
    else { st.disabled = true; st.disabled_reason = "manual"; console.log(arg + " parked"); }
    await saveJson(STATE_FILE, state);
    return;
  }

  if (cmd === "status") {
    let s = null;
    try { s = JSON.parse(await fsp.readFile(STATUS_FILE, "utf8")); } catch {}
    if (!s) s = buildStatus(await loadState(), 0, 0, []);
    printStatus(s);
    return;
  }

  if (cmd === "daemon") {
    console.log(`[sched] daemon mode, tick every ${TICK_S}s, dir=${SCHED_DIR}`);
    for (;;) {
      try { await lockedTick(); } catch (e) { console.error("[sched] tick failed:", e); }
      await sleep(TICK_S * 1000);
    }
  }

  if (cmd !== "run") { console.error("unknown command: " + cmd); process.exit(2); }

  if (!TOKEN) {
    // Without the token the scheduler still schedules, but it cannot read source_state, so every run
    // classifies as "unknown" and no backoff learns anything. Say so loudly.
    console.error("[sched] WARNING: SHARED_TOKEN missing — yield cannot be measured, every run will classify as 'unknown' and no status will be pushed.");
  }
  await lockedTick();
}

main().catch((e) => { console.error("[sched] fatal:", e); process.exit(1); });
