// harvest-tls-san.mjs — ACTIVE TLS/SAN sweep of Bangladeshi IPv4 space. Runs ON THE ORACLE VM.
//
// TOP60 ranks implemented here: 3 (BD IPv4 TLS/SAN sweep), 13 (multi-tenant SAN cluster mining),
// 27 (APNIC delegated-extended as the address authority — imported from bdgate), 52 (Cloudflare
// de-cloaking via provider serverNN.<provider> hostnames).
//
//   API_BASE=… SHARED_TOKEN=… node scanner/harvest-tls-san.mjs
//
// ─────────────────────────────────────────────────────────────────────────────────────────────────
// WHY THIS SOURCE IS DIFFERENT FROM EVERY OTHER ONE IN THE SYSTEM
//
// Bangladesh has 2,078,272 delegated IPv4 addresses (APNIC, measured). That is small. A full sweep is
// genuinely finishable, and unlike crt.sh / Mnemonic / OTX / Shodan / RapidDNS there is:
//   • no API key, no quota, no rate-limit page, and nobody who can switch it off;
//   • no third party between us and the data — we handshake the IP ourselves.
//
// And BD-ness here is DEFINITIONAL, not inferred. The brief's rule is that a domain is never
// Bangladeshi because its NAME says so (1xbet-bd.org, 1win-bangladesh.net …). Here we never look at
// the name: we open a TCP connection to an address that APNIC delegated to Bangladesh and read the
// certificate that machine presents. The hostname came OUT of BD infrastructure. That is the
// strongest BD evidence this project can obtain short of a registry lookup.
//
// RANK 13 is why the yield-per-connection is so high: one cPanel AutoSSL / Plesk / Sectigo
// multi-domain certificate lists every tenant of a shared server in a single SAN extension. One
// handshake can enumerate an entire hosting box — a pre-computed neighbour list, for free, with zero
// extra network calls. This reproduces the ip-tree "dense /24" effect without RapidDNS (whose
// pagination is fake) or HackerTarget (whose quota dies at ~10 requests).
//
// RANK 52 falls out of the same stream. Shared-hosting certs almost always also carry the box's own
// serverNN.<provider> hostname. That hostname is NOT proxied — it resolves straight to the real
// origin. So when a BD business hides behind Cloudflare and IP-based detection fails, its host's
// server hostname still points at the true BD origin and hands us the true /24. Every such hostname
// found is resolved and, if it lands inside APNIC BD space, its /24 is appended to a de-cloak target
// file that later runs sweep FIRST (dense shared hosting, before generic address space).
//
// MEASURED, and this is the single best number in the file: a cold run over generic BD address space
// handshaked 140 certificates per 6,000 addresses (2.3%). The next run, which started with 2,816
// de-cloak addresses harvested from the first run's provider hostnames, handshaked 1,099 per 12,000
// (9.2%) — a 4x denser hit rate. Rank 52 does not just recover proxied sites; it makes the sweep
// self-targeting, so the longer this runs the less of Bangladesh's empty address space it wastes
// time on.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────────
// WHAT IS DELIBERATELY *NOT* DONE
//
// • No isBdHost() call per harvested name. It would be 2-4 DoH lookups per host to re-derive a fact
//   we already established by handshaking BD address space. Instead every row is submitted with a
//   high bd_score and the reason logged.
// • No name-based admission of any kind. eduLexicon() is used ONLY to (a) drop casino/adult brand
//   names (the porn-FP incident) and (b) label institutional rows for a higher bd_score.
// • No SNI. We connect to an IP with no servername so the box shows its DEFAULT certificate — which
//   on shared hosting is exactly the fat multi-tenant AutoSSL cert we want. Sending SNI would return
//   a single-domain cert and destroy the rank-13 multiplier.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────────
// PORT POLICY (measured, not guessed)
//
// A naive 4-ports-×-2.08M sweep is 8.3M connections. So :443 is probed first, and the cPanel/Plesk
// ports (2083/2087/8443) are probed ONLY on addresses whose :443 answered — i.e. on machines already
// proven to be webservers. That keeps the sweep at ~1.0x connections for the dead 95% of the address
// space and spends the extra probes exactly where the fat AutoSSL/WHM certs live. Set
// TLSSAN_ALWAYS_EXTRA=1 to probe every port on every address (slower, marginal extra yield).
//
// ─────────────────────────────────────────────────────────────────────────────────────────────────
// SWEEP ORDER — a stride permutation, not a linear walk
//
// A linear walk from the first APNIC block spends its first hours inside one ISP's /16 and looks
// broken. Instead the flat address index i is mapped through addr = flat[(i*STRIDE) % total] with
// STRIDE coprime to total. That is a full-coverage permutation of the entire space using ONE integer
// of state: every address is visited exactly once per full cycle, early results are spread across
// every operator in the country, and no single BD network is hammered. Resuming is just a cursor.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────────
// MEASURED — what this actually sustains (identical 6,000-address slice of BD space, no liveness
// gate, so the only variable is concurrency; peak RSS from /usr/bin/time -l):
//
//     CONC    rate      wall    peak RSS    CPU (user+sys)
//     100     17.9/s    112s     ~55MB      4.4s
//     250     54.6/s    110s     108MB      4.4s
//     300     67.3/s     89s     134MB      4.3s
//     500    112.0/s     54s     147MB      3.2s
//    1000    175.9/s     34s     226MB      2.7s
//
// Scaling is essentially linear because the sweep is timeout-bound, not CPU-bound: 80% of BD addresses
// never answer, so a worker spends TLSSAN_TIMEOUT_MS waiting and the rate is ≈ CONC/timeout. Total CPU
// for 6,000 handshake attempts is under 5 seconds — this is not a load problem for 1 OCPU, it is a
// socket and RAM problem. DEFAULT IS 250: CONC=1000 blows the 200MB budget on its own, and CONC=300
// was measured peaking at 192MB RSS during a dense burst with the liveness gate on — before adding the
// ~60MB the full 161k-host seen-set costs on the VM. 250 leaves headroom for the scanner running
// alongside. At 250 a complete sweep of all 2,078,272 BD addresses takes ~10.6 hours, so the whole
// country fits comfortably in one pass per day with no API, no key and no quota.
//
// Full live run, 12,000 addresses (CONC=300, liveness gate ON, real submit to production):
//     210s · 57.1/s · 1,099 handshakes · 963 certs carrying names · 1,947 unique hostnames
//     → 763 provider/infra hostnames, 655 dead (rank-58 gate), 1 casino brand dropped
//     → 482 new submitted · found=443 inserted=298 dups=145
//
// ─────────────────────────────────────────────────────────────────────────────────────────────────
// MEMORY (the 946MB / 1 OCPU budget)
//
// Nothing here holds a dataset. The APNIC blocks are two Uint32Arrays (~1,970 entries) plus one
// prefix-sum array; addresses are generated one at a time from an integer; harvested hosts are
// flushed to the Worker every TLSSAN_FLUSH names and dropped. The only large resident structure is
// bdgate's seen-set (measured 108MB with 161k hosts loaded), which is shared by all harvesters.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────────
// ENV (all optional; defaults tuned for the Oracle Always-Free VM)
//
//   API_BASE               https://bd-hack-audit-api.javed-it.workers.dev
//   SHARED_TOKEN           —          bearer token for /harvest (required unless TLSSAN_DRY=1)
//   TLSSAN_CONC            250        concurrent TLS handshakes (measured table below)
//   TLSSAN_HOST_CONC       16         concurrent liveness lookups per certificate
//   TLSSAN_IPS             40000      addresses to sweep this run (0 = until TLSSAN_MAX_MS)
//   TLSSAN_MAX_MS          3300000    hard wall-clock stop (55 min — fits an hourly systemd timer)
//   TLSSAN_TIMEOUT_MS      5000       per-connection timeout (connect + handshake)
//   TLSSAN_EXTRA_TIMEOUT_MS 2500      shorter timeout for the secondary cPanel ports
//   TLSSAN_PORT            443        the primary port, always probed
//   TLSSAN_EXTRA_PORTS     2083,2087,8443   probed only when the primary answered
//   TLSSAN_ALWAYS_EXTRA    0          1 = probe extra ports on every address too
//   TLSSAN_DECLOAK_SHARE   0.25       max fraction of a run's budget spent on the rank-52 queue
//   TLSSAN_ALIVE           1          DoH A-record liveness gate before submit (rank 58)
//   TLSSAN_FLUSH           500        submit every N new hostnames (streaming, never buffer a run)
//   TLSSAN_STRIDE          104729     permutation stride; must be coprime with the address count
//   TLSSAN_STATE           <bdgate cache dir>/tlssan-cursor
//   TLSSAN_DECLOAK         <bdgate cache dir>/tlssan-decloak.txt   rank-52 /24s, swept first
//   TLSSAN_TARGETS         —          explicit IP/CIDR/a.b.c.d-e.f.g.h list (or @file) instead of
//                                     the rotating cursor — used for co-IP sweeps (ranks 45/46)
//   TLSSAN_DRY             0          1 = do everything except POST to the Worker
//   TLSSAN_LEGACY          1          allow TLS1.0/weak ciphers (old BD cPanel boxes) — 0 to disable
//   TLSSAN_SOURCE          tlssan     source name recorded in D1
//
// ─────────────────────────────────────────────────────────────────────────────────────────────────
// CADENCE — hourly systemd timer, defaults as shipped. Each run takes a 40,000-address bite with a
// 55-minute wall-clock stop, so 24 runs/day ≈ 960k addresses and the whole country is covered every
// ~2.2 days, forever, with the cursor surviving reboots. There is nothing to exhaust and nothing to
// rate-limit: when the cursor wraps, every certificate has had time to be renewed or replaced, so the
// second pass is a genuine delta, not a re-read. Run it on the SAME box as the scanner but do NOT run
// two copies concurrently — they would share the bdgate seen file and double the socket count.

import tls from "node:tls";
import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import {
  loadBdRanges, bdRangeStats, ipInBd, eduLexicon, alive,
  loadSeen, seen, markSeen, submit, resolveA, normHost, mapLimit,
  CACHE_DIR, API_BASE_DEFAULT,
} from "./bdgate.mjs";

const env = process.env;
const int = (v, d) => (Number.isFinite(Number(v)) && Number(v) >= 0 ? Number(v) : d);

const API_BASE = (env.API_BASE || API_BASE_DEFAULT).replace(/\/+$/, "");
const TOKEN = env.SHARED_TOKEN || "";
const SOURCE = env.TLSSAN_SOURCE || "tlssan";
const CONC = Math.max(1, int(env.TLSSAN_CONC, 250));
const IP_BUDGET = int(env.TLSSAN_IPS, 40000);
const MAX_MS = int(env.TLSSAN_MAX_MS, 55 * 60 * 1000);
const TIMEOUT = Math.max(1000, int(env.TLSSAN_TIMEOUT_MS, 5000));
// A closed cPanel port is the common case and it costs a full timeout, so the secondary ports get a
// short one: if 2083/2087/8443 are open at all they answer in well under a second.
const EXTRA_TIMEOUT = Math.max(500, int(env.TLSSAN_EXTRA_TIMEOUT_MS, 2500));
const PORT = int(env.TLSSAN_PORT, 443);
const EXTRA_PORTS = String(env.TLSSAN_EXTRA_PORTS ?? "2083,2087,8443")
  .split(",").map((s) => Number(s.trim())).filter((n) => n > 0 && n < 65536);
const ALWAYS_EXTRA = env.TLSSAN_ALWAYS_EXTRA === "1";
const DO_ALIVE = env.TLSSAN_ALIVE !== "0";
const FLUSH_AT = Math.max(1, int(env.TLSSAN_FLUSH, 500));
// Concurrent liveness lookups per certificate — see the note on handleCert().
const HOST_CONC = Math.max(1, int(env.TLSSAN_HOST_CONC, 16));
const STRIDE = Math.max(1, int(env.TLSSAN_STRIDE, 104729));
const STATE = env.TLSSAN_STATE || path.join(CACHE_DIR, "tlssan-cursor");
const DECLOAK = env.TLSSAN_DECLOAK || path.join(CACHE_DIR, "tlssan-decloak.txt");
const DRY = env.TLSSAN_DRY === "1";
const LEGACY = env.TLSSAN_LEGACY !== "0";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const t0 = Date.now();
const left = () => MAX_MS - (Date.now() - t0);

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// The BD address space (rank 27, via bdgate).
//
// bdgate owns the APNIC fetch/parse/cache and exposes ipInBd(), but not the raw block list — and this
// harvester needs to ENUMERATE the space, not just test membership. So we load through bdgate (which
// guarantees the parsed blocks are written to its on-disk cache) and then read that cache. If the
// cache is unreadable for any reason we fall back to streaming APNIC ourselves with the identical
// parse rule, so the sweep can never be silently starved of targets.
// ═════════════════════════════════════════════════════════════════════════════════════════════════

const APNIC_URL = env.BDGATE_APNIC_URL || "https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest";

function ipToInt(ip) {
  const p = String(ip).split(".");
  if (p.length !== 4) return null;
  let v = 0;
  for (const s of p) {
    if (!/^\d{1,3}$/.test(s)) return null;
    const n = Number(s);
    if (n > 255) return null;
    v = v * 256 + n;
  }
  return v >>> 0;
}
const intToIp = (v) => `${(v >>> 24) & 255}.${(v >>> 16) & 255}.${(v >>> 8) & 255}.${v & 255}`;

async function* streamLines(body) {
  const reader = body.getReader();
  const dec = new TextDecoder();
  let buf = "";
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    buf += dec.decode(value, { stream: true });
    let nl;
    while ((nl = buf.indexOf("\n")) >= 0) { yield buf.slice(0, nl); buf = buf.slice(nl + 1); }
    if (buf.length > 1 << 20) { yield buf; buf = ""; }
  }
  if (buf) yield buf;
}

async function loadBlocks() {
  await loadBdRanges();                       // authoritative load + disk cache write happens here
  const cachePath = path.join(CACHE_DIR, "bd-ranges.txt");
  const pairs = [];
  try {
    const rl = (await import("node:readline")).createInterface({
      input: fs.createReadStream(cachePath, { encoding: "utf8" }), crlfDelay: Infinity,
    });
    for await (const line of rl) {
      if (!line) continue;
      const [s, e] = line.split(",").map(Number);
      if (Number.isFinite(s) && Number.isFinite(e) && e >= s) pairs.push([s >>> 0, e >>> 0]);
    }
  } catch {}
  if (!pairs.length) {
    console.error("[tlssan] bdgate range cache unreadable — streaming APNIC directly");
    const r = await fetch(APNIC_URL, {
      headers: { "user-agent": "bd-hack-audit/1.0 (+javeditsolution.com)" },
      signal: AbortSignal.timeout(120000),
    });
    if (!r.ok) throw new Error("apnic http " + r.status);
    for await (const line of streamLines(r.body)) {
      if (line.charCodeAt(0) === 35 || line.indexOf("|BD|ipv4|") < 0) continue;
      const f = line.split("|");
      if (f[1] !== "BD" || f[2] !== "ipv4") continue;
      const st = ipToInt(f[3]), cnt = Number(f[4]);
      if (st !== null && Number.isFinite(cnt) && cnt >= 1) pairs.push([st, st + cnt - 1]);
    }
  }
  pairs.sort((a, b) => a[0] - b[0]);
  const lo = [], hi = [];
  for (const [s, e] of pairs) {
    if (lo.length && s <= hi[hi.length - 1] + 1) { if (e > hi[hi.length - 1]) hi[hi.length - 1] = e; }
    else { lo.push(s); hi.push(e); }
  }
  const LO = Uint32Array.from(lo), HI = Uint32Array.from(hi);
  // Prefix sums so a flat index maps to an address in O(log blocks). Float64 because the cumulative
  // total (2.08M here, but this must survive a larger delegation file) is not bounded by uint32 math
  // once you add block sizes together in the general case.
  const CUM = new Float64Array(LO.length + 1);
  for (let i = 0; i < LO.length; i++) CUM[i + 1] = CUM[i] + (HI[i] - LO[i] + 1);
  return { LO, HI, CUM, total: CUM[LO.length] };
}

// flat index (0..total-1) → IPv4 integer
function addrAt(B, idx) {
  let lo = 0, hi = B.LO.length - 1;
  while (lo <= hi) {
    const m = (lo + hi) >> 1;
    if (idx < B.CUM[m]) hi = m - 1;
    else if (idx >= B.CUM[m + 1]) lo = m + 1;
    else return (B.LO[m] + (idx - B.CUM[m])) >>> 0;
  }
  return null;
}

// gcd so we can prove the stride really is a full-coverage permutation before using it.
const gcd = (a, b) => (b ? gcd(b, a % b) : a);
function pickStride(total) {
  let s = STRIDE % total;
  if (s < 1) s = 1;
  while (gcd(s, total) !== 1) s = (s + 1) % total || 1;
  return s;
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// Cursor + rank-52 de-cloak target file.
// ═════════════════════════════════════════════════════════════════════════════════════════════════

async function readCursor() {
  try { return Number(await fsp.readFile(STATE, "utf8")) || 0; } catch { return 0; }
}
async function writeCursor(n) { try { await fsp.writeFile(STATE, String(n)); } catch {} }

// RANK 52 de-cloak queue.
//
// The file holds /24 BASE addresses, one per line — not the 256 members. The first version stored
// members and grew by 512 entries per 2,000 addresses swept (measured), which would have made the
// queue outgrow the sweep it is supposed to prioritise. As a base list it is 256x smaller, it is a
// real WORK QUEUE (bases consumed this run are removed and rewritten), and the number of de-cloak
// addresses spent per run is capped at DECLOAK_SHARE of the run's budget so it can never starve the
// systematic sweep.
const DECLOAK_MAX = 50000;                                  // /24 bases retained on disk (≈600KB)
const DECLOAK_SHARE = Math.min(0.9, Math.max(0, Number(env.TLSSAN_DECLOAK_SHARE ?? 0.25)));

async function readDecloakBases() {
  const out = [];
  try {
    const rl = (await import("node:readline")).createInterface({
      input: fs.createReadStream(DECLOAK, { encoding: "utf8" }), crlfDelay: Infinity,
    });
    for await (const line of rl) { const v = Number(line.trim()); if (Number.isFinite(v) && v > 0) out.push(v >>> 0); }
  } catch {}
  return out;
}
async function writeDecloakBases(bases) {
  const arr = [...new Set(bases)].slice(-DECLOAK_MAX);
  try { await fsp.writeFile(DECLOAK, arr.join("\n")); } catch {}
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// The probe. No SNI (see the header), certificate NOT verified — we are reading it, not trusting it.
// ═════════════════════════════════════════════════════════════════════════════════════════════════

function tlsProbe(ip, port, timeoutMs = TIMEOUT) {
  return new Promise((resolve) => {
    let sock = null, settled = false, hard = null;
    const finish = (v) => {
      if (settled) return;
      settled = true;
      if (hard) clearTimeout(hard);
      try { sock && sock.destroy(); } catch {}
      resolve(v);
    };
    const opts = {
      host: ip, port,
      rejectUnauthorized: false,
      servername: undefined,        // ← deliberately no SNI: we want the box's DEFAULT (multi-tenant) cert
      requestCert: false,
      session: undefined,
    };
    // Old BD shared-hosting boxes still speak TLS1.0 with pre-SECLEVEL2 ciphers. Node 18+ refuses
    // those by default, which would silently skip exactly the neglected/hackable servers we hunt.
    if (LEGACY) { opts.minVersion = "TLSv1"; opts.ciphers = "ALL:@SECLEVEL=0"; }
    try {
      sock = tls.connect(opts, () => {
        let cert = null;
        try { cert = sock.getPeerCertificate(false); } catch {}
        finish({ ok: true, cert });
      });
    } catch (e) { return finish({ ok: false, err: String(e && e.code || e).slice(0, 40) }); }
    sock.setTimeout(timeoutMs, () => finish({ ok: false, err: "timeout" }));
    sock.on("error", (e) => finish({ ok: false, err: String((e && e.code) || e).slice(0, 40) }));
    hard = setTimeout(() => finish({ ok: false, err: "hard-timeout" }), timeoutMs + 2000);
    if (hard.unref) hard.unref();
  });
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// Certificate → hostnames.
//
// subjectaltname looks like: "DNS:foo.com.bd, DNS:*.foo.com.bd, DNS:server12.exonhost.com,
// IP Address:103.x.x.x". IP entries are dropped. A wildcard contributes only its apex — "*.foo.com"
// is not itself a resolvable host. The CN is included because a handful of ancient certs have no SAN.
// ═════════════════════════════════════════════════════════════════════════════════════════════════

// Anything a hosting company puts on its own boxes rather than a customer site. These are NOT leads,
// but they ARE the rank-52 de-cloaking key, so they are separated out instead of thrown away.
const PROVIDER_HOST = /^(server|srv|host|vps|web|cp|cpanel|whm|plesk|node|box|mail|mx|smtp|ns|dns|pop|imap|webmail|ftp|cloud|shared|reseller|panel|direct-?admin)[-_]?\d*\./i;
// Certificate placeholders that are never real customer sites.
const JUNK_HOST = /^(localhost|localhost\.localdomain|example\.(com|org|net)|invalid|test|plesk|default|ssl|sni\d*\.|\*)$/i;
// MEASURED in the first live run: a bare `192.168.0.106` SAN on a router's self-signed cert sailed
// through normHost() (it is a syntactically legal hostname) and its "apex" came out as `0.106`.
// Anything that is a dotted-quad, or whose TLD is numeric, is not a domain.
const IPISH = /^\d{1,3}(\.\d{1,3}){3}$/;
const NUMERIC_TLD = /\.\d+$/;

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// GLOBAL INFRASTRUCTURE FILTER — the one non-obvious failure mode of an IP-based sweep.
//
// Also measured in the first live run: googlevideo.com, fbcdn.net, fdac136-1.fna.fbcdn.net and
// nperf.net came back from BD addresses. They are hosted in Bangladesh and the BD test is honest —
// Google/Facebook/Netflix put edge caches (GGC / FNA / OCA) and speed-test nodes inside every BD ISP,
// and ISPs run their own captive-portal and CPE boxes on public IPs. All of it is BD-hosted and none
// of it is a Bangladeshi business we can sell a cleanup to. Filtering by apex is safe here precisely
// because these are global brands, not BD names — the reverse of the banned name test.
// ─────────────────────────────────────────────────────────────────────────────────────────────────
const GLOBAL_INFRA = new Set([
  "google.com", "googlevideo.com", "gstatic.com", "googleapis.com", "googleusercontent.com",
  "gvt1.com", "gvt2.com", "1e100.net", "youtube.com", "ytimg.com", "doubleclick.net",
  "facebook.com", "fbcdn.net", "fb.com", "instagram.com", "whatsapp.net", "whatsapp.com", "messenger.com",
  "netflix.com", "nflxvideo.net", "nflxso.net", "nflximg.net",
  "akamai.net", "akamaized.net", "akamaiedge.net", "akamaitechnologies.com", "edgekey.net", "edgesuite.net",
  "cloudflare.com", "cloudflaressl.com", "cloudflare-dns.com", "cdn77.org", "llnwd.net", "edgecastcdn.net",
  "fastly.net", "fastlylb.net", "stackpathdns.com", "bunnycdn.com", "b-cdn.net", "jsdelivr.net",
  "apple.com", "aaplimg.com", "icloud.com", "microsoft.com", "windowsupdate.com", "azureedge.net",
  "msftncsi.com", "office.com", "live.com", "skype.com", "amazonaws.com", "cloudfront.net",
  "tiktokcdn.com", "tiktokv.com", "byteoversea.com", "ttvnw.net", "twitch.tv",
  "nperf.net", "speedtest.net", "ooklaserver.net", "steamcontent.com", "valve.net",
  "xiaomi.com", "miui.com", "huawei.com", "hicloud.com", "samsungcloud.com", "samsung.com",
  "letsencrypt.org", "digicert.com", "sectigo.com", "comodoca.com",
  // CPE / router / modem default certs — a BD subscriber's TP-Link is on a BD IP and is not a lead.
  // Measured live: tplinkwifi.net came back from the sweep on the first 6,000 addresses.
  "tplinkwifi.net", "tplinklogin.net", "tplinkmodem.net", "tplinkrepeater.net", "tp-link.com",
  "routerlogin.net", "routerlogin.com", "netgear.com", "asusrouter.com", "asus.com",
  "dlinkrouter.local", "dlink.com", "mikrotik.com", "tendawifi.com", "netis.cc",
  "huaweimobilewifi.com", "hikvision.com", "dahuasecurity.com", "ui.com", "unifi.local",
]);
function isGlobalInfra(h) {
  const p = h.split(".");
  for (let i = 0; i < p.length - 1; i++) if (GLOBAL_INFRA.has(p.slice(i).join("."))) return true;
  return false;
}

function certHosts(cert) {
  const hosts = new Set();
  if (!cert || typeof cert !== "object") return hosts;
  const raw = [];
  if (cert.subjectaltname) raw.push(...String(cert.subjectaltname).split(","));
  if (cert.subject && cert.subject.CN) raw.push("DNS:" + cert.subject.CN);
  for (let entry of raw) {
    entry = entry.trim();
    if (!entry) continue;
    if (/^IP Address:/i.test(entry)) continue;              // an IP SAN is not a domain
    entry = entry.replace(/^DNS:/i, "").trim().toLowerCase();
    if (!entry || entry.includes(" ") || entry.includes("@")) continue;
    const wild = entry.startsWith("*.");
    const bare = wild ? entry.slice(2) : entry;
    if (JUNK_HOST.test(bare) || IPISH.test(bare)) continue;
    const h = normHost(bare);
    if (!h || IPISH.test(h) || NUMERIC_TLD.test(h) || isGlobalInfra(h)) continue;
    if (!wild) hosts.add(h);
    const apex = registrable(h);
    if (apex && !IPISH.test(apex) && !NUMERIC_TLD.test(apex)) hosts.add(apex);
  }
  return hosts;
}

// Registrable apex. .bd is a 2-label public suffix in practice (edu.bd, com.bd, gov.bd, ac.bd,
// net.bd, org.bd, mil.bd), so a .bd host keeps THREE labels; everything else keeps two. This is the
// same rule harvest-crtsh.mjs uses, deliberately — the two harvesters must agree or they will
// double-report the same site as new.
function registrable(h) {
  const p = h.split(".");
  if (p.length < 2) return null;
  const keep = p[p.length - 1] === "bd" ? 3 : 2;
  if (p.length <= keep) return null;                         // already an apex — nothing to add
  return p.slice(-keep).join(".");
}

const BD_INST = /\.(edu|ac|gov|mil)\.bd$/i;

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// main
// ═════════════════════════════════════════════════════════════════════════════════════════════════

function parseTargets(spec) {
  const out = [];
  for (const tok of String(spec).split(/[\s,]+/).filter(Boolean)) {
    const m = /^(\d+\.\d+\.\d+\.\d+)\/(\d{1,2})$/.exec(tok);
    if (m) {
      const base = ipToInt(m[1]), bits = Number(m[2]);
      if (base === null || bits < 8 || bits > 32) continue;
      const size = 2 ** (32 - bits);
      const start = (base & (bits === 0 ? 0 : (-1 << (32 - bits)))) >>> 0;
      for (let i = 0; i < size; i++) out.push((start + i) >>> 0);
      continue;
    }
    const r = /^(\d+\.\d+\.\d+\.\d+)-(\d+\.\d+\.\d+\.\d+)$/.exec(tok);
    if (r) {
      const a = ipToInt(r[1]), b = ipToInt(r[2]);
      if (a !== null && b !== null && b >= a && b - a < 1e6) for (let v = a; v <= b; v++) out.push(v >>> 0);
      continue;
    }
    const v = ipToInt(tok);
    if (v !== null) out.push(v);
  }
  return out;
}

async function main() {
  if (!TOKEN && !DRY) { console.error("[tlssan] SHARED_TOKEN missing (set TLSSAN_DRY=1 to test without it)"); process.exit(1); }

  const B = await loadBlocks();
  const stats = bdRangeStats();
  console.log(`[tlssan] BD space: ${B.LO.length} disjoint blocks / ${B.total} addresses (apnic source=${stats.source || "?"})`);

  await loadSeen(API_BASE, TOKEN).then(
    (s) => console.log(`[tlssan] seen-set ${s.total} hosts (disk ${s.fromDisk}, api ${s.fromApi}, ${s.pages} pages)`),
    (e) => console.error("[tlssan] seen-set seed failed:", String(e).slice(0, 120)),
  );

  // ── target stream ────────────────────────────────────────────────────────────────────────────
  const explicit = env.TLSSAN_TARGETS
    ? parseTargets(env.TLSSAN_TARGETS.startsWith("@") ? await fsp.readFile(env.TLSSAN_TARGETS.slice(1), "utf8") : env.TLSSAN_TARGETS)
    : null;

  const stride = pickStride(B.total);
  let cursor = explicit ? 0 : await readCursor();

  const budget = IP_BUDGET || Number.MAX_SAFE_INTEGER;

  // De-cloak: take a bounded slice of the pending /24 bases, expand them into addresses, and keep the
  // rest on disk for later runs. `keepBases` is what gets written back at the end, plus whatever new
  // bases this run discovers.
  const allBases = explicit ? [] : await readDecloakBases();
  const spendable = budget === Number.MAX_SAFE_INTEGER ? DECLOAK_MAX : Math.floor(budget * DECLOAK_SHARE);
  const takeBases = allBases.slice(0, Math.max(0, Math.floor(spendable / 256)));
  const keepBases = new Set(allBases.slice(takeBases.length));
  const decloakQueue = [];
  for (const b of takeBases) for (let k = 0; k < 256; k++) decloakQueue.push((b + k) >>> 0);

  let issued = 0;
  function nextAddr() {
    if (issued >= budget || left() <= 0) return null;
    issued++;
    if (explicit) return issued <= explicit.length ? explicit[issued - 1] : null;
    if (decloakQueue.length) return decloakQueue.pop();
    const a = addrAt(B, (cursor * stride) % B.total);
    cursor = (cursor + 1) % B.total;
    return a;
  }

  // ── counters ────────────────────────────────────────────────────────────────────────────────
  const M = {
    probes: 0, tcpOk: 0, handshakes: 0, extraProbes: 0,
    hostsSeenRaw: 0, hostsUnique: 0, provider: 0, spam: 0, dead: 0,
    newHosts: 0, found: 0, inserted: 0, dups: 0, decloakNew: 0, ipsWithCert: 0, aliveSkipped: 0,
  };
  const errs = new Map();
  const bump = (e) => errs.set(e, (errs.get(e) || 0) + 1);
  const uniq = new Set();                                    // per-run dedupe (bounded by flushes below)
  const sample = [];
  let pending = [];

  async function flush(force) {
    if (!pending.length || (!force && pending.length < FLUSH_AT)) return;
    const batch = pending; pending = [];
    // A dry run must NOT markSeen(): markSeen appends to bdgate's shared on-disk seen file, so a dry
    // run that marked its finds would permanently hide them from the next REAL run. (Observed while
    // measuring: the second dry run reported "0 new" because the first had poisoned the seen file.)
    if (DRY) { console.log(`[tlssan] DRY — would submit ${batch.length} rows`); return; }
    try {
      const res = await submit(API_BASE, TOKEN, SOURCE, batch);
      M.found += res.found; M.inserted += res.inserted; M.dups += res.dups;
      if (res.ok) batch.forEach((r) => markSeen(r.domain));
      console.log(`[tlssan] submit ${batch.length} rows → found=${res.found} inserted=${res.inserted} dups=${res.dups} ok=${res.ok}`);
    } catch (e) { console.error("[tlssan] submit failed:", String(e).slice(0, 140)); }
  }

  // Handle one harvested hostname. Note the ORDER: cheap string rejects first, seen-set next, and the
  // one network call (liveness) last — so a repeat sweep of a known box costs zero DNS.
  async function offer(h, ip, port) {
    M.hostsSeenRaw++;
    if (uniq.has(h)) return;
    uniq.add(h);
    M.hostsUnique++;

    if (PROVIDER_HOST.test(h)) {
      // RANK 52 — not a lead, but the key that de-cloaks every Cloudflare-proxied tenant of this box.
      M.provider++;
      const ips = await resolveA(h);
      for (const p of ips) {
        if (!ipInBd(p)) continue;                             // only BD origins are worth sweeping
        const v = ipToInt(p);
        if (v === null) continue;
        const base = (v & 0xffffff00) >>> 0;                  // the true /24 behind the proxy
        if (!keepBases.has(base)) { keepBases.add(base); M.decloakNew++; }
      }
      return;
    }

    const lex = eduLexicon(h);
    if (lex.isSpammy) { M.spam++; return; }                   // porn/gambling brand — never a lead
    if (seen(h)) return;

    // Rank 58 — keep corpses out of the scan queue. Once the wall clock is spent the gate is skipped
    // rather than the host dropped: we already paid a TLS handshake for it, and a name on a live
    // certificate served by a BD address is decent evidence on its own. This also guarantees the drain
    // terminates instead of running the clock out on DNS, which is what the serial version did.
    if (DO_ALIVE && left() > 0) {
      if (!(await alive(h))) { M.dead++; return; }
    } else if (DO_ALIVE) M.aliveSkipped++;

    M.newHosts++;
    if (sample.length < 40) sample.push(h);
    pending.push({
      domain: h,
      // BD-ness is definitional here: the cert came off an APNIC-delegated BD address we handshaked.
      // Institutional TLDs get the top score because a hacked .edu.bd/.gov.bd is always a victim.
      bd_score: BD_INST.test(h) ? 90 : (lex.isEdu ? 80 : 70),
    });
    await flush(false);
  }

  // MEASURED BUG THIS FIXES: the first version awaited offer() serially for every SAN on a cert. A fat
  // AutoSSL cert is exactly what rank 13 is hunting, so the good case — 200 tenants on one shared box —
  // became 200 sequential DoH liveness lookups on one worker. A run of 12,000 addresses finished its
  // probes in ~3 minutes and then spent 20+ MINUTES draining hosts at ~0.1/s, sailing straight past
  // TLSSAN_MAX_MS. Names within one cert are independent, so they are resolved concurrently (bdgate's
  // global token bucket still caps the process at BDGATE_DNS_RPS, so this is polite, just not idle).
  async function handleCert(ip, port, cert) {
    const hosts = [...certHosts(cert)];
    if (!hosts.length) return;
    M.ipsWithCert++;
    await mapLimit(hosts, HOST_CONC, (h) => offer(h, ip, port));
  }

  // ── worker pool ─────────────────────────────────────────────────────────────────────────────
  async function worker() {
    for (;;) {
      const a = nextAddr();
      if (a === null) return;
      const ip = intToIp(a);
      M.probes++;
      const r = await tlsProbe(ip, PORT);
      if (r.ok) {
        M.tcpOk++; M.handshakes++;
        await handleCert(ip, PORT, r.cert);
      } else bump(r.err || "err");

      if (EXTRA_PORTS.length && (ALWAYS_EXTRA || r.ok)) {
        for (const p of EXTRA_PORTS) {
          if (left() <= 0) return;
          M.extraProbes++;
          const r2 = await tlsProbe(ip, p, EXTRA_TIMEOUT);
          if (r2.ok) { M.handshakes++; await handleCert(ip, p, r2.cert); }
        }
      }
    }
  }

  console.log(`[tlssan] sweeping ${explicit ? explicit.length + " explicit targets" : `${budget === Number.MAX_SAFE_INTEGER ? "unbounded" : budget} addresses from cursor ${cursor} (stride ${stride})`} · conc=${CONC} timeout=${TIMEOUT}ms alive=${DO_ALIVE ? "on" : "off"}${DRY ? " DRY" : ""}`);
  if (decloakQueue.length) console.log(`[tlssan] ${decloakQueue.length} rank-52 de-cloak addresses queued first`);

  // Last-resort watchdog. Every stall this project has had (the Worker CPU wall, the poison-domain
  // deadlock) looked like "the harvester is still running" from the outside, so this one refuses to
  // outlive its budget: it persists the cursor synchronously and exits, and the next timer tick simply
  // resumes from there.
  const watchdog = setTimeout(() => {
    console.error(`[tlssan] watchdog: exceeded TLSSAN_MAX_MS+120s — persisting cursor ${cursor} and exiting`);
    try { if (!explicit) fs.writeFileSync(STATE, String(cursor)); } catch {}
    process.exit(0);
  }, MAX_MS + 120000);
  if (watchdog.unref) watchdog.unref();

  const hb = setInterval(() => {
    const s = (Date.now() - t0) / 1000;
    console.log(`[tlssan] … ${M.probes} probes (${(M.probes / s).toFixed(1)}/s) · ${M.handshakes} certs · ${M.hostsUnique} hosts · ${M.newHosts} new · rss ${(process.memoryUsage().rss / 1048576).toFixed(0)}MB`);
  }, 30000);
  if (hb.unref) hb.unref();

  await Promise.all(Array.from({ length: CONC }, worker));
  clearInterval(hb);
  clearTimeout(watchdog);
  await flush(true);

  if (!explicit) { await writeCursor(cursor); await writeDecloakBases(keepBases); }

  const secs = (Date.now() - t0) / 1000;
  const topErr = [...errs.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6).map(([k, v]) => `${k}=${v}`).join(" ");
  console.log(
    `[tlssan] DONE in ${secs.toFixed(0)}s — ${M.probes} primary probes (${(M.probes / secs).toFixed(1)}/s) + ${M.extraProbes} extra · ` +
    `${M.handshakes} handshakes · ${M.ipsWithCert} certs with names · ${M.hostsUnique} unique hosts ` +
    `(provider ${M.provider}, spam-dropped ${M.spam}, dead ${M.dead}, alive-gate-skipped ${M.aliveSkipped}) · ${M.newHosts} new submitted · ` +
    `found=${M.found} inserted=${M.inserted} dups=${M.dups} · decloak+${M.decloakNew} · cursor→${cursor} · rss ${(process.memoryUsage().rss / 1048576).toFixed(0)}MB`,
  );
  if (topErr) console.log(`[tlssan] probe errors: ${topErr}`);
  if (sample.length) console.log(`[tlssan] sample: ${sample.slice(0, 10).join(" ")}`);
}

main().catch((e) => { console.error("[tlssan] fatal:", e); process.exit(1); });
