// harvest-bdren-asn.mjs — routed-address-space harvester for Bangladeshi EDUCATION + the full BD ASN set.
// Runs ON THE ORACLE VM (946MB / 1 OCPU). Plain node ESM, ZERO npm dependencies.
//
//   API_BASE=… SHARED_TOKEN=… node scanner/harvest-bdren-asn.mjs
//
// ─────────────────────────────────────────────────────────────────────────────────────────────────
// WHAT THIS COVERS — TOP60 ranks 9, 28, 45, 46
//
//   RANK 9  — BdREN AS63961, the national research & education network. MEASURED: 14 announced
//             prefixes, 5,632 IPv4 addresses. Nearly every host inside it is a university or an
//             affiliated institute, which makes it the highest precision-per-request source for the
//             owner's stated primary target (schools/colleges/madrasas/universities first).
//             Measured on 1,280 of those addresses: 37 PTR hits and 90 TLS-SAN hits, yielding
//             hau.ac.bd, nbiu.edu.bd, rub.ac.bd, iu.ac.bd, sbpgc.edu.bd, bup.edu.bd, kuet.ac.bd,
//             bou.ac.bd, jnu.ac.bd, sau.edu.bd, bsmmu.edu.bd, buet.ac.bd, cu.ac.bd, kiu.ac.bd,
//             brur.ac.bd. That is ~15 distinct universities from a quarter of one ASN.
//
//   RANK 28 — the BD ASN set. The system currently uses 58 ASNs. RIPEstat country-resource-list
//             returns 1,990 BD ASNs and 2,315 BD IPv4 prefixes. This file unions
//             country-resource-list(BD).ipv4 with announced-prefixes(AS<n>) for a rotating slice of
//             those ASNs and persists the result as a reusable prefix file (see PREFIX FILE below).
//             The deliverable of rank 28 is an INPUT LIST for the other IP-space harvesters, so
//             sweeping it here is OFF by default (BDASN_SWEEP=1 turns it on).
//
//   RANK 45 — 159.13.20.227/24, the education-ministry cluster. MEASURED live: InternetDB reports
//             dshe.gov.bd + banbeis.gov.bd on that single address (the brief said dpe.gov.bd; the
//             live answer is dshe.gov.bd — both are Ministry of Education directorates).
//
//   RANK 46 — 94.23.146.151, the national result portals (educationboardresults / eboardresults).
//             ⚠ HONESTY NOTE, MEASURED: 94.23.146.151 is OVH (France), NOT Bangladeshi address
//             space, and its TLS default cert is CN=localhost while InternetDB reports only
//             smtp.nixtec.xyz. So its neighbours are NOT admissible by hosting IP and this rank is
//             expected to be near-zero yield. It is swept anyway because it is cheap (a /27 window),
//             but do not be surprised by 0 — that is the correct answer, not a bug.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────────
// HOW A HOSTNAME IS FOUND (reverse-IP without rapiddns)
//
//   1. PTR via DoH        — one cached, rate-limited dns-json query per address.
//   2. TLS-SAN via node:tls — connect to :443, read the default certificate's subjectAltName.
//                             No third party at all: we handshake the address ourselves, so there is
//                             no quota and nobody who can cut us off. This out-yielded PTR 90 to 37
//                             on the measured sample and is the primary method.
//   3. Shodan InternetDB  — keyless reverse oracle, 404 = "no information" and is normal. Used only
//                           for the two named co-IP clusters (ranks 45/46), where it is the only
//                           method that sees dshe.gov.bd, because sweeping all of BdREN through a
//                           free third party would be exactly the rank-2 hammering trap.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────────
// TWO TRAPS THIS FILE DEFENDS AGAINST
//
//   TRAP 1 — "bd in the name". Not applicable by construction: this harvester never reads a name to
//   decide BD-ness. Every candidate goes through bdgate.isBdHost(), which admits only on .bd TLD,
//   an A record inside APNIC BD space, or a .bd/BD-hosted nameserver. Names are never consulted.
//
//   TRAP 1b — THE CDN-CACHE QUESTION. I expected a hole here and MEASURED THAT THERE IS NOT ONE.
//   Worth writing down, because the reasoning is not obvious and the next person will worry about it
//   too. ISPs and BdREN host Facebook/Google/Akamai edge caches inside their own address space:
//   TLS-SAN at 203.96.188.17-43 (BdREN) really does return fdac181-1.fna.fbcdn.net and
//   fdac181-1.fna.whatsapp.net, and ipInBd("203.96.188.17") really is TRUE. So it looks like the
//   gate must admit Facebook's CDN as a Bangladeshi business.
//   It does not, and the reason is a deliberate property of bdgate: isBdHost() FORWARD-RESOLVES the
//   hostname and never trusts the IP the hostname was discovered on. MEASURED:
//       fdac181-1.fna.fbcdn.net        → bd:false  reason:no-a-record   (cache names are internal)
//       fna002.01.fdac181.facebook.com → bd:false  reason:no-a-record
//       www.google.com / dl.google.com → bd:false  reason:foreign-hosting
//       tplinkwifi.net / e-1.duckdns.org → bd:false  reason:foreign-hosting
//   The gate is airtight here. INFRA_JUNK below is therefore a COST filter, not a correctness fix:
//   it skips ~2 DoH lookups per junk candidate and keeps the logs readable. It only ever rejects —
//   it can never admit anything — so it cannot widen the attack surface even if an entry is wrong.
//
//   TRAP 2 — hammering free services. RIPEstat gets serial requests with exponential backoff on
//   429/5xx and a 60s timeout; only RIPE_ASNS_PER_RUN ASNs are touched per run via a persisted
//   rotating cursor. DoH goes through a local token bucket. InternetDB is used on a handful of
//   addresses, never on a sweep. The address sweep itself also rotates: BDREN_IP_BUDGET addresses
//   per run, cursor persisted, so all 5,632 BdREN addresses are covered over a few runs forever.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────────
// MEMORY (946MB box). Addresses are never materialised for a whole ASN — sliceAddresses() builds
// only the current budget's worth (a few thousand short strings). The prefix union is appended to
// disk, not accumulated. Peak RSS measured on a full run: see the run log at the bottom of the notes.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────────
// ENV VARS (all optional except SHARED_TOKEN)
//
//   API_BASE              Worker base URL.            default https://bd-hack-audit-api.javed-it.workers.dev
//   SHARED_TOKEN          Bearer token for /harvest.  REQUIRED — without it every write 401s.
//   BDREN_PHASES          comma list of phases to run: bdren,bdasn,coip.   default "bdren,bdasn,coip"
//   BDREN_ASN             the education ASN to sweep.                      default 63961
//   BDREN_IP_BUDGET       addresses swept per run in the bdren phase.      default 2000
//   BDREN_TLS_CONC        concurrent TLS handshakes.                       default 40
//   BDREN_TLS_TIMEOUT_MS  per-handshake timeout.                           default 4000
//   BDREN_DNS_RPS         local PTR token-bucket rate.                     default 25
//   BDREN_DNS_CONC        concurrent PTR lookups.                          default 30
//   BDREN_DOH             DoH endpoint.                        default https://cloudflare-dns.com/dns-query
//   BDREN_STATE           cursor file.                         default <bdgate CACHE_DIR>/bdren-asn-state.json
//   BDREN_PREFIX_FILE     rank-28 prefix union output.         default <bdgate CACHE_DIR>/bd-asn-prefixes.txt
//   RIPE_ASNS_PER_RUN     BD ASNs expanded per run (of 1,990). default 60
//   RIPE_TIMEOUT_MS       RIPEstat fetch timeout.                          default 60000
//   BDASN_SWEEP           1 = also sweep the rank-28 prefix union.         default 0 (list-only)
//   BDASN_IP_BUDGET       addresses swept when BDASN_SWEEP=1.              default 1500
//   BDREN_COIP_IPS        comma list for the co-IP phase.  default 159.13.20.227/24,94.23.146.151/27
//   BDREN_ALIVE_CHECK     1 = drop non-resolving hosts before submit.      default 1
//   BDREN_DRY_RUN         1 = do everything except POST /harvest.          default 0
//   BDREN_LIMIT_PREFIXES  cap prefixes per phase (probing aid).            default 0 = no cap
//
// CADENCE: systemd timer every 6h. Each run costs ~1 RIPEstat call + RIPE_ASNS_PER_RUN calls +
// BDREN_IP_BUDGET TLS handshakes + BDREN_IP_BUDGET PTR queries. Four runs a day walks all of BdREN
// roughly every 17h and the full 1,990-ASN list every ~8 days.
// ─────────────────────────────────────────────────────────────────────────────────────────────────

import tls from "node:tls";
import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import {
  CACHE_DIR, API_BASE_DEFAULT,
  loadBdRanges, ipInBd, bdRangeStats,
  isBdHostDetail, normHost, alive,
  loadSeen, seen, markSeen, seenSize,
  submit, mapLimit,
} from "./bdgate.mjs";

const env = process.env;
const num = (v, d) => (Number.isFinite(Number(v)) && Number(v) >= 0 ? Number(v) : d);
const API_BASE = (env.API_BASE || API_BASE_DEFAULT).replace(/\/+$/, "");
const TOKEN = env.SHARED_TOKEN || "";

const PHASES = String(env.BDREN_PHASES || "bdren,bdasn,coip").split(",").map((s) => s.trim()).filter(Boolean);
const BDREN_ASN = num(env.BDREN_ASN, 63961);
const IP_BUDGET = num(env.BDREN_IP_BUDGET, 2000);
const TLS_CONC = Math.max(1, num(env.BDREN_TLS_CONC, 40));
const TLS_TIMEOUT = num(env.BDREN_TLS_TIMEOUT_MS, 4000);
const DNS_RPS = Math.max(1, num(env.BDREN_DNS_RPS, 25));
const DNS_CONC = Math.max(1, num(env.BDREN_DNS_CONC, 30));
const DOH = env.BDREN_DOH || "https://cloudflare-dns.com/dns-query";
const STATE_FILE = env.BDREN_STATE || path.join(CACHE_DIR, "bdren-asn-state.json");
const PREFIX_FILE = env.BDREN_PREFIX_FILE || path.join(CACHE_DIR, "bd-asn-prefixes.txt");
const ASNS_PER_RUN = num(env.RIPE_ASNS_PER_RUN, 60);
const RIPE_TIMEOUT = num(env.RIPE_TIMEOUT_MS, 60000);
const BDASN_SWEEP = env.BDASN_SWEEP === "1";
const BDASN_IP_BUDGET = num(env.BDASN_IP_BUDGET, 1500);
const COIP_IPS = String(env.BDREN_COIP_IPS || "159.13.20.227/24,94.23.146.151/27").split(",").map((s) => s.trim()).filter(Boolean);
const ALIVE_CHECK = env.BDREN_ALIVE_CHECK !== "0";
const DRY_RUN = env.BDREN_DRY_RUN === "1";
const LIMIT_PREFIXES = num(env.BDREN_LIMIT_PREFIXES, 0);

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const log = (...a) => console.log("[bdren]", ...a);
const secs = (t) => ((Date.now() - t) / 1000).toFixed(0) + "s";

const STATS = { ripeCalls: 0, ptrQueries: 0, tlsHandshakes: 0, idbCalls: 0, requests: 0 };

// ═══════════════════════════════════════════════════════════════════════════════════════════════
// IPv4 / CIDR helpers. Kept integer-based so a whole prefix never becomes an array until asked.
// ═══════════════════════════════════════════════════════════════════════════════════════════════

function ipToInt(ip) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(String(ip).trim());
  if (!m) return null;
  let n = 0;
  for (let i = 1; i <= 4; i++) {
    const o = Number(m[i]);
    if (o > 255) return null;
    n = n * 256 + o;
  }
  return n >>> 0;
}
const intToIp = (n) => [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");

/** "103.28.120.0/22" → {base, size, cidr}. IPv6 and garbage return null. */
function parseCidr(cidr) {
  const s = String(cidr).trim();
  if (!s || s.includes(":")) return null;                 // IPv6 — out of scope, we sweep IPv4 only
  const [addr, lenRaw] = s.split("/");
  const base = ipToInt(addr);
  const len = lenRaw === undefined ? 32 : Number(lenRaw);
  if (base === null || !Number.isInteger(len) || len < 0 || len > 32) return null;
  const size = len === 0 ? 4294967296 : 2 ** (32 - len);
  return { base: (base & (len === 0 ? 0 : (0xffffffff << (32 - len)) >>> 0)) >>> 0, size, cidr: s };
}

const totalAddresses = (prefixes) => prefixes.reduce((a, p) => a + p.size, 0);

/**
 * Merge overlapping and adjacent prefixes into disjoint address ranges.
 *
 * NOT cosmetic — MEASURED on AS63961: RIPEstat announces 203.96.188.0/22 AND, separately,
 * 203.96.188.0/24, 203.96.189.0/24 and 203.96.190.0/24. Summing the raw prefix list counts 768
 * addresses twice, so ~14% of every BdREN sweep would be handshaking the same hosts a second time
 * and the cursor would never line up with the real address space. Ranges are kept as {base,size}
 * and need not be power-of-two — sliceAddresses() only ever reads those two fields.
 */
function coalesce(prefixes) {
  const sorted = prefixes.slice().sort((a, b) => a.base - b.base || b.size - a.size);
  const out = [];
  for (const p of sorted) {
    const end = p.base + p.size;                            // exclusive
    const last = out[out.length - 1];
    if (last && p.base <= last.base + last.size) {          // overlapping or adjacent → extend
      const lastEnd = last.base + last.size;
      if (end > lastEnd) { last.size = end - last.base; last.cidr += "+" + p.cidr; }
    } else {
      out.push({ base: p.base, size: p.size, cidr: p.cidr });
    }
  }
  return out;
}

/**
 * Take `budget` addresses starting at virtual index `cursor` across the ordered prefix list,
 * wrapping at the end. ONLY the budget's worth is ever materialised — this is the reason a /8 in
 * the rank-28 union cannot blow up RAM.
 */
function sliceAddresses(prefixes, cursor, budget) {
  const total = totalAddresses(prefixes);
  if (!total || budget <= 0) return { ips: [], next: 0, total };
  const take = Math.min(budget, total);
  const ips = new Array(take);
  let idx = cursor % total;
  for (let k = 0; k < take; k++) {
    let rem = idx;
    let pi = 0;
    while (pi < prefixes.length && rem >= prefixes[pi].size) { rem -= prefixes[pi].size; pi++; }
    ips[k] = intToIp((prefixes[pi].base + rem) >>> 0);
    idx = (idx + 1) % total;
  }
  return { ips, next: idx, total };
}

// ═══════════════════════════════════════════════════════════════════════════════════════════════
// Persisted cursor state.
// ═══════════════════════════════════════════════════════════════════════════════════════════════

async function readState() {
  try { return JSON.parse(await fsp.readFile(STATE_FILE, "utf8")) || {}; } catch { return {}; }
}
async function writeState(s) {
  try {
    await fsp.mkdir(path.dirname(STATE_FILE), { recursive: true });
    await fsp.writeFile(STATE_FILE, JSON.stringify(s, null, 2));
  } catch (e) { console.error("[bdren] state write failed:", String(e).slice(0, 90)); }
}

// ═══════════════════════════════════════════════════════════════════════════════════════════════
// RIPEstat. Serial, backed off, generously timed out. RANK 2 TRAP: this is a free public service.
// ═══════════════════════════════════════════════════════════════════════════════════════════════

async function ripe(url) {
  for (let attempt = 1; attempt <= 4; attempt++) {
    try {
      STATS.ripeCalls++; STATS.requests++;
      const r = await fetch(url, {
        headers: { "user-agent": "bd-hack-audit/1.0 (+https://javeditsolution.com)", accept: "application/json" },
        signal: AbortSignal.timeout(RIPE_TIMEOUT),
      });
      if (r.status === 429 || r.status >= 500) { await sleep(attempt * 5000); continue; }
      if (!r.ok) return null;                              // 4xx other than 429 — a real "no"
      const j = await r.json().catch(() => null);
      if (j && j.status === "ok") return j.data;
      return j ? j.data || null : null;
    } catch { await sleep(attempt * 5000); }
  }
  return null;
}

/** RIPEstat announced-prefixes for one ASN → array of parsed IPv4 CIDRs. */
async function announcedPrefixes(asn) {
  const d = await ripe(`https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS${asn}`);
  const out = [];
  for (const row of (d && d.prefixes) || []) {
    const p = parseCidr(row && row.prefix);
    if (p) out.push(p);
  }
  return out;
}

/** RIPEstat country-resource-list for BD → {asns:string[], ipv4:parsed[]}. */
async function bdCountryResources() {
  const d = await ripe("https://stat.ripe.net/data/country-resource-list/data.json?resource=BD");
  const res = (d && d.resources) || {};
  const asns = (res.asn || []).map(String).filter((a) => /^\d+$/.test(a));
  const ipv4 = [];
  for (const c of res.ipv4 || []) { const p = parseCidr(c); if (p) ipv4.push(p); }
  return { asns, ipv4 };
}

// ═══════════════════════════════════════════════════════════════════════════════════════════════
// Reverse lookups.
// ═══════════════════════════════════════════════════════════════════════════════════════════════

// Local token bucket for PTR. bdgate has one for A/NS but does not export a PTR helper or the
// bucket itself, so this file limits its own PTR traffic rather than resolving unthrottled.
let tokens = DNS_RPS, lastRefill = Date.now();
async function takeToken() {
  for (;;) {
    const now = Date.now();
    tokens = Math.min(DNS_RPS, tokens + ((now - lastRefill) / 1000) * DNS_RPS);
    lastRefill = now;
    if (tokens >= 1) { tokens -= 1; return; }
    await sleep(Math.max(5, Math.ceil(((1 - tokens) / DNS_RPS) * 1000)));
  }
}

/** PTR via DoH. @returns {Promise<string[]>} */
async function ptr(ip) {
  const rev = ip.split(".").reverse().join(".") + ".in-addr.arpa";
  await takeToken();
  for (let attempt = 1; attempt <= 2; attempt++) {
    try {
      STATS.ptrQueries++; STATS.requests++;
      const r = await fetch(`${DOH}?name=${encodeURIComponent(rev)}&type=PTR`, {
        headers: { accept: "application/dns-json" },
        signal: AbortSignal.timeout(8000),
      });
      if (!r.ok) { await sleep(attempt * 800); continue; }
      const j = await r.json().catch(() => null);
      return ((j && j.Answer) || []).filter((a) => a.type === 12).map((a) => String(a.data).replace(/\.$/, ""));
    } catch { await sleep(attempt * 800); }
  }
  return [];
}

/**
 * TLS-SAN: handshake the address on :443 and read the default certificate's names.
 * rejectUnauthorized:false on purpose — an expired or mismatched cert still names its host, and
 * naming the host is the entire point. No servername is sent, so we get the box's default vhost.
 * @returns {Promise<string[]>}
 */
function tlsSan(ip) {
  return new Promise((resolve) => {
    let settled = false;
    let socket = null;
    const done = (v) => {
      if (settled) return;
      settled = true;
      try { if (socket) socket.destroy(); } catch {}
      resolve(v);
    };
    // Belt-and-braces timer: `timeout` only fires on socket inactivity, and a half-open TLS peer can
    // hang past it. On a 1-OCPU box a stuck handshake holds a concurrency slot, so this is the guard
    // that keeps the sweep's wall-clock predictable.
    const hard = setTimeout(() => done([]), TLS_TIMEOUT + 600);
    try {
      STATS.tlsHandshakes++;
      socket = tls.connect({ host: ip, port: 443, rejectUnauthorized: false, timeout: TLS_TIMEOUT, ALPNProtocols: ["http/1.1"] }, () => {
        let names = [];
        try {
          const cert = socket.getPeerCertificate();
          if (cert) {
            for (const part of String(cert.subjectaltname || "").split(",")) {
              const t = part.trim();
              if (t.toLowerCase().startsWith("dns:")) names.push(t.slice(4).trim());
            }
            const cn = cert.subject && cert.subject.CN;
            if (cn) names.push(String(cn).trim());
          }
        } catch {}
        clearTimeout(hard);
        done(names);
      });
      socket.on("error", () => { clearTimeout(hard); done([]); });
      socket.on("timeout", () => { clearTimeout(hard); done([]); });
    } catch { clearTimeout(hard); done([]); }
  });
}

/** Shodan InternetDB — keyless reverse oracle. 404 "No information available" is the normal empty. */
async function internetDb(ip) {
  try {
    STATS.idbCalls++; STATS.requests++;
    const r = await fetch(`https://internetdb.shodan.io/${ip}`, {
      headers: { accept: "application/json" },
      signal: AbortSignal.timeout(12000),
    });
    if (r.status !== 200) return [];
    const j = await r.json().catch(() => null);
    return (j && Array.isArray(j.hostnames) ? j.hostnames : []).map(String);
  } catch { return []; }
}

// ═══════════════════════════════════════════════════════════════════════════════════════════════
// INFRA_JUNK — reject-only prefilter. See TRAP 1b in the header.
//
// Everything here is either (a) global CDN/cloud infrastructure that is physically hosted inside BD
// address space and would otherwise be admitted as a "BD business", or (b) an internal placeholder
// name that is not a real public host. This list NEVER admits anything and never overrides the gate;
// it only saves DNS lookups and keeps CDN caches out of the scan queue.
//
// Every entry below was observed in the live measured sweep, not guessed:
//   fbcdn.net / whatsapp.net / facebook.com   203.96.188.17-43   (BdREN-hosted Facebook FNA caches)
//   traefik.default                           163.47.36.209/242  (Kubernetes ingress placeholder)
//   ingress.local                             159.13.20.227      (ditto)
//   localhost / localhost.localdomain         94.23.146.151, 103.157.135.23
//   tplinkwifi.net                            103.28.120.166     (a consumer router's web UI)
// The dynamic-DNS and cloud-hostname suffixes are added for the same reason: they name a tunnel or a
// VM, never a Bangladeshi institution, and a hacked one is not a lead the owner can sell to.
// ═══════════════════════════════════════════════════════════════════════════════════════════════

const INFRA_JUNK = [
  // CDN / big-tech edge caches commonly embedded in national ISP and NREN space
  "fbcdn.net", "whatsapp.net", "facebook.com", "instagram.com", "fbsbx.com",
  "akamai.net", "akamaiedge.net", "akamaitechnologies.com", "akadns.net", "edgekey.net", "edgesuite.net",
  "1e100.net", "googlevideo.com", "gvt1.com", "gvt2.com", "ggpht.com", "youtube.com", "google.com",
  "nflxvideo.net", "nflxso.net", "netflix.com", "cloudfront.net", "cdn77.org", "llnwd.net",
  "cloudflare.com", "cloudflare-dns.com", "fastly.net", "fastlylb.net", "azureedge.net",
  // cloud/VM auto-generated hostnames
  "amazonaws.com", "compute.amazonaws.com", "cloudapp.azure.com", "cloudapp.net", "bc.googleusercontent.com",
  "digitalocean.com", "linodeusercontent.com", "vultrusercontent.com", "contaboserver.net", "ovh.net", "ovh.com",
  // dynamic DNS / tunnels — names a home connection, never an institution
  "duckdns.org", "no-ip.org", "no-ip.com", "ddns.net", "dynu.com", "hopto.org", "zapto.org",
  "sslip.io", "nip.io", "ngrok.io", "ngrok-free.app", "trycloudflare.com", "serveo.net",
  // routers / appliances / placeholders
  "tplinkwifi.net", "tplinklogin.net", "routerlogin.net", "mikrotik.com", "asusrouter.com",
];
const INFRA_SUFFIX = new RegExp("(^|\\.)(" + INFRA_JUNK.map((s) => s.replace(/\./g, "\\.")).join("|") + ")$", "i");
// Internal / non-public TLDs and placeholder certificate names.
const INFRA_EXACT = /^(localhost|localhost\.localdomain|ingress\.local|kubernetes|example\.com|invalid)$/i;
const INTERNAL_TLD = /\.(local|localdomain|internal|lan|home|arpa|test|invalid|example|default|cluster|svc)$/i;

function isInfraJunk(h) {
  if (!h || !h.includes(".")) return true;
  if (INFRA_EXACT.test(h)) return true;
  if (INTERNAL_TLD.test(h)) return true;
  if (INFRA_SUFFIX.test(h)) return true;
  return false;
}

// ═══════════════════════════════════════════════════════════════════════════════════════════════
// Apex derivation. `mail.hau.ac.bd` is a real lead, but `hau.ac.bd` is the institution's actual site
// and is what the owner wants to sell to — so both are submitted. Only the registrable apex under a
// known two-label BD suffix is derived; nothing is invented for other TLDs.
// ═══════════════════════════════════════════════════════════════════════════════════════════════

const BD_2LABEL = /\.(edu|ac|gov|mil|com|net|org|info|co)\.bd$/i;
const BD_INST = /\.(edu|ac|gov|mil)\.bd$/i;

function withApex(host) {
  const out = [host];
  const parts = host.split(".");
  if (BD_2LABEL.test(host)) {
    if (parts.length > 3) out.push(parts.slice(-3).join("."));
  } else if (/\.bd$/i.test(host) && parts.length > 2) {
    out.push(parts.slice(-2).join("."));
  }
  return out;
}

const scoreFor = (h) => (BD_INST.test(h) ? 70 : /\.bd$/i.test(h) ? 45 : 30);

// ═══════════════════════════════════════════════════════════════════════════════════════════════
// The sweep: addresses in → gated, deduped, submitted hostnames out.
// ═══════════════════════════════════════════════════════════════════════════════════════════════

async function sweep(ips, source, { useIdb = false } = {}) {
  const t0 = Date.now();
  const raw = new Map();                                    // host → first IP it was seen on
  let junked = 0;

  const note = (host, ip) => {
    const h = normHost(host);
    if (!h) return;
    if (isInfraJunk(h)) { junked++; return; }
    for (const cand of withApex(h)) if (!raw.has(cand)) raw.set(cand, ip);
  };

  // Pass 1 — TLS-SAN. Primary method: no third party, no quota, highest measured yield.
  const tStart = Date.now();
  await mapLimit(ips, TLS_CONC, async (ip) => { for (const n of await tlsSan(ip)) note(n, ip); });
  const afterTls = raw.size;
  log(`${source}: TLS-SAN ${ips.length} addrs in ${secs(tStart)} → ${afterTls} candidate hosts`);

  // Pass 2 — PTR.
  const pStart = Date.now();
  await mapLimit(ips, DNS_CONC, async (ip) => { for (const n of await ptr(ip)) note(n, ip); });
  log(`${source}: PTR ${ips.length} addrs in ${secs(pStart)} → +${raw.size - afterTls} (total ${raw.size})`);

  // Pass 3 — InternetDB, only for the small named clusters.
  if (useIdb) {
    const before = raw.size;
    await mapLimit(ips, 5, async (ip) => {
      for (const n of await internetDb(ip)) note(n, ip);
      await sleep(120);                                     // free service, small list — stay polite
    });
    log(`${source}: InternetDB ${ips.length} addrs → +${raw.size - before} (total ${raw.size})`);
  }

  if (!raw.size) { log(`${source}: no hosts found`); return { candidates: 0, admitted: 0, submitted: null }; }

  // Gate. bdgate.isBdHost() is the ONLY thing allowed to admit a domain as Bangladeshi.
  const hosts = [...raw.keys()];
  log(`${source}: ${junked} infra/junk names rejected before the gate (~${junked * 2} DoH lookups saved)`);
  const reasons = Object.create(null);
  const admitted = [];
  await mapLimit(hosts, 12, async (h) => {
    const d = await isBdHostDetail(h);
    reasons[d.reason] = (reasons[d.reason] || 0) + 1;
    if (d.bd) admitted.push(h);
  });
  log(`${source}: gate admitted ${admitted.length}/${hosts.length} — ${JSON.stringify(reasons)}`);

  // Liveness: a corpse costs the scanner a full HTTP timeout for nothing.
  let live = admitted;
  if (ALIVE_CHECK && admitted.length) {
    const flags = await mapLimit(admitted, 12, (h) => alive(h));
    live = admitted.filter((_, i) => flags[i]);
    log(`${source}: alive ${live.length}/${admitted.length}`);
  }

  // Seen-set: avoid re-POSTing the 161k domains already in the registry.
  const fresh = live.filter((h) => !seen(h));
  log(`${source}: ${fresh.length} not already in the registry (of ${live.length} live)`);
  if (fresh.length) log(`${source}: sample ${fresh.slice(0, 10).join(" ")}`);

  let res = null;
  if (fresh.length && !DRY_RUN) {
    res = await submit(API_BASE, TOKEN, source, fresh.map((h) => ({ domain: h, bd_score: scoreFor(h) })));
    // found>0 & inserted===0 is the normal mature-harvester steady state (all dups), NOT a failure.
    // found===0 with posted>0 is rows VANISHING — submit() already screams about that one.
    log(`${source}: POST found=${res.found} inserted=${res.inserted} dups=${res.dups} failed=${res.failed} ok=${res.ok}`);
    fresh.forEach(markSeen);
  } else if (fresh.length) {
    log(`${source}: DRY RUN — would have posted ${fresh.length} rows`);
  }

  log(`${source}: phase done in ${secs(t0)}`);
  return { candidates: hosts.length, admitted: admitted.length, live: live.length, fresh: fresh.length, submitted: res };
}

// ═══════════════════════════════════════════════════════════════════════════════════════════════
// Phases
// ═══════════════════════════════════════════════════════════════════════════════════════════════

/** RANK 9 — BdREN AS63961 rotating sweep. */
async function phaseBdren(state) {
  log(`RANK 9 — BdREN AS${BDREN_ASN}`);
  let prefixes = await announcedPrefixes(BDREN_ASN);
  if (!prefixes.length) { console.error(`[bdren] AS${BDREN_ASN} returned no IPv4 prefixes — RIPEstat down or ASN unrouted`); return null; }
  if (LIMIT_PREFIXES) prefixes = prefixes.slice(0, LIMIT_PREFIXES);
  const raw = prefixes.length, rawTotal = totalAddresses(prefixes);
  prefixes = coalesce(prefixes);
  const total = totalAddresses(prefixes);
  const cursor = num(state.bdrenCursor, 0);
  const { ips, next } = sliceAddresses(prefixes, cursor, IP_BUDGET);
  log(`AS${BDREN_ASN}: ${raw} announced IPv4 prefixes (${rawTotal} addrs) → ${prefixes.length} disjoint ranges (${total} addrs, ${rawTotal - total} duplicates removed); sweeping ${ips.length} from cursor ${cursor} → ${next}`);
  const r = await sweep(ips, "bdren-asn");
  state.bdrenCursor = next;
  state.bdrenTotal = total;
  return r;
}

/**
 * RANK 28 — union the full BD ASN set's announced prefixes with country-resource-list(BD).ipv4 and
 * persist it. Rotating slice so 1,990 ASNs are covered over days without hammering RIPEstat.
 */
async function phaseBdAsn(state) {
  log("RANK 28 — full BD ASN set");
  const { asns, ipv4 } = await bdCountryResources();
  if (!asns.length) { console.error("[bdren] country-resource-list BD returned no ASNs — RIPEstat down"); return null; }
  log(`country-resource-list BD: ${asns.length} ASNs, ${ipv4.length} IPv4 prefixes`);

  // Load the persisted union so this run only appends what is genuinely new.
  const union = new Map();
  try {
    const rl = (await import("node:readline")).createInterface({
      input: fs.createReadStream(PREFIX_FILE, { encoding: "utf8" }), crlfDelay: Infinity,
    });
    for await (const line of rl) {
      const cidr = line.trim().split(/\s+/)[0];
      if (cidr && !cidr.startsWith("#")) union.set(cidr, true);
    }
  } catch {}
  const preexisting = union.size;

  const added = [];
  for (const p of ipv4) if (!union.has(p.cidr)) { union.set(p.cidr, true); added.push(`${p.cidr}\tBD-registry`); }

  const start = num(state.asnCursor, 0) % asns.length;
  const slice = Array.from({ length: Math.min(ASNS_PER_RUN, asns.length) }, (_, k) => asns[(start + k) % asns.length]);
  let asnOk = 0;
  for (const asn of slice) {                                 // SERIAL on purpose — free public service
    const pl = await announcedPrefixes(asn);
    if (pl.length) asnOk++;
    for (const p of pl) if (!union.has(p.cidr)) { union.set(p.cidr, true); added.push(`${p.cidr}\tAS${asn}`); }
    await sleep(400);
  }
  state.asnCursor = (start + slice.length) % asns.length;
  state.bdAsnCount = asns.length;

  if (added.length) {
    try {
      await fsp.mkdir(path.dirname(PREFIX_FILE), { recursive: true });
      await fsp.appendFile(PREFIX_FILE, added.join("\n") + "\n");
    } catch (e) { console.error("[bdren] prefix file append failed:", String(e).slice(0, 90)); }
  }
  log(`ASN slice ${start}..${state.asnCursor} — ${slice.length} ASNs queried, ${asnOk} announced prefixes; union ${preexisting} → ${union.size} (+${added.length}) at ${PREFIX_FILE}`);

  if (!BDASN_SWEEP) { log("BDASN_SWEEP=0 — rank 28 delivers the prefix list only; no sweep this run"); return { prefixes: union.size, added: added.length }; }

  const parsed = coalesce([...union.keys()].map(parseCidr).filter(Boolean));
  const cur = num(state.bdAsnIpCursor, 0);
  const { ips, next, total } = sliceAddresses(parsed, cur, BDASN_IP_BUDGET);
  log(`BD union: ${parsed.length} prefixes, ${total} addresses; sweeping ${ips.length} from cursor ${cur} → ${next}`);
  const r = await sweep(ips, "bd-asn-sweep");
  state.bdAsnIpCursor = next;
  return { prefixes: union.size, added: added.length, ...r };
}

/** RANKS 45 + 46 — the two verified education co-IP clusters. */
async function phaseCoip(state) {
  log(`RANKS 45/46 — education co-IP clusters: ${COIP_IPS.join(" ")}`);
  const prefixes = [];
  for (const spec of COIP_IPS) {
    const p = parseCidr(spec.includes("/") ? spec : spec + "/32");
    if (p) prefixes.push(p); else console.error(`[bdren] bad co-IP spec ignored: ${spec}`);
  }
  if (!prefixes.length) return null;
  const merged = coalesce(prefixes);
  prefixes.length = 0; prefixes.push(...merged);
  const total = totalAddresses(prefixes);
  // Small and fixed — swept whole every run, with InternetDB on, because these are the two named
  // clusters where the third-party oracle is the only thing that sees dshe.gov.bd/banbeis.gov.bd.
  const { ips } = sliceAddresses(prefixes, 0, Math.min(total, 512));
  log(`co-IP: ${prefixes.length} blocks, ${ips.length} addresses (full pass)`);
  return await sweep(ips, "edu-coip", { useIdb: true });
}

// ═══════════════════════════════════════════════════════════════════════════════════════════════
// Seen-set seeding, with a resume loop around bdgate.loadSeen().
//
// WHY THE EXTRA LOOP — MEASURED, not defensive coding. /api/domains flaps 503 under normal D1 load
// (limit=2000 returned 503 twice and then 200 on the third identical request). bdgate.loadSeen()
// retries a page 3 times and then `break`s out of the whole paging loop, so ONE transient 503
// truncates the entire seed: a measured run stopped at page 25 with 37,396 of ~161,000 hostnames.
// A truncated seen-set does not corrupt anything — the Worker's INSERT OR IGNORE is the real dedup
// authority — but it makes this harvester re-POST tens of thousands of known domains and report them
// as "new", which is exactly the misleading intake number the seen-set exists to prevent.
//
// So: loadSeen() first (it owns the on-disk fast path and is the fast case), then, if it stopped
// early, keep paging from where it stopped with continue-on-failure instead of abort-on-failure.
// The seen-set itself is still entirely bdgate's — markSeen() is its function and its disk format.
// PAGE_SIZE is 1500 because 2000+ is where the 503s cluster.
// ═══════════════════════════════════════════════════════════════════════════════════════════════

const SEED_PAGE = num(env.BDREN_SEED_PAGE, 1500);
const SEED_MAX_PAGES = num(env.BDREN_SEED_MAX_PAGES, 400);

async function seedSeen() {
  const first = await loadSeen(API_BASE, TOKEN, { pageSize: SEED_PAGE, maxPages: SEED_MAX_PAGES })
    .catch((e) => { console.error("[bdren] loadSeen failed:", String(e).slice(0, 120)); return null; });
  const base = first ? first.pages : 0;
  if (!TOKEN) return { ...(first || {}), resumed: 0, truncated: false };
  // If loadSeen served purely from a fresh disk file it did no paging at all — nothing to resume.
  if (first && first.fromApi === 0 && first.fromDisk > 0) return { ...first, resumed: 0, truncated: false };

  let resumed = 0, fails = 0, page = base;
  for (; page < SEED_MAX_PAGES; page++) {
    let batch = null;
    for (let attempt = 1; attempt <= 5 && !batch; attempt++) {
      try {
        const r = await fetch(`${API_BASE}/api/domains?type=all&limit=${SEED_PAGE}&offset=${page * SEED_PAGE}`, {
          headers: { authorization: "Bearer " + TOKEN },
          signal: AbortSignal.timeout(90000),
        });
        if (!r.ok) { await sleep(attempt * 1200); continue; }
        batch = (await r.json()).domains || [];
      } catch { await sleep(attempt * 1200); }
    }
    if (!batch) { fails++; if (fails >= 3) break; continue; }  // skip a stubborn page, do not abort
    for (const row of batch) if (markSeen(row.domain)) resumed++;
    if (batch.length < SEED_PAGE) return { ...(first || {}), resumed, truncated: false, pagesTotal: page + 1 };
    await sleep(150);
  }
  return { ...(first || {}), resumed, truncated: true, pagesTotal: page };
}

// ═══════════════════════════════════════════════════════════════════════════════════════════════

async function main() {
  const t0 = Date.now();
  if (!TOKEN && !DRY_RUN) { console.error("[bdren] SHARED_TOKEN missing — every /harvest write would 401. Set it, or run with BDREN_DRY_RUN=1."); process.exit(1); }

  await loadBdRanges();
  log("APNIC BD ranges:", JSON.stringify(bdRangeStats()));

  const s = await seedSeen();
  log(`seen-set: ${seenSize()} hosts ${JSON.stringify(s)}`);
  if (s && s.truncated) console.error("[bdren] seen-set seed was TRUNCATED — 'new' counts this run are inflated (dups will absorb it)");

  const state = await readState();
  const results = {};
  for (const phase of PHASES) {
    try {
      if (phase === "bdren") results.bdren = await phaseBdren(state);
      else if (phase === "bdasn") results.bdasn = await phaseBdAsn(state);
      else if (phase === "coip") results.coip = await phaseCoip(state);
      else console.error(`[bdren] unknown phase "${phase}" ignored`);
    } catch (e) {
      console.error(`[bdren] phase ${phase} failed:`, String((e && e.stack) || e).slice(0, 400));
    }
    await writeState(state);                                 // checkpoint after every phase
  }

  const mem = Math.round(process.memoryUsage().rss / 1048576);
  log(`DONE in ${secs(t0)} — requests: ripe=${STATS.ripeCalls} ptr=${STATS.ptrQueries} tls=${STATS.tlsHandshakes} idb=${STATS.idbCalls} total=${STATS.requests}; peak RSS ~${mem}MB`);
  log("summary " + JSON.stringify(results));
}

main().catch((e) => { console.error("[bdren] fatal:", e); process.exit(1); });
