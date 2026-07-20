// fetchers.js — the core fetch strategy for detector v2. NOT a layer module: it emits no
// signals and has no WEIGHTS/CATS. It owns the bytes every other layer module reasons over.
//
// Covers proposals P1 (reachability ladder), P5-fetch-half (manual redirect chain), P15 (tail
// read), and the plumbing P3 (referer-only fetch) and P4 (mobile fetch) need.
//
// THE SAME FILE IS BUNDLED INTO CLOUDFLARE WORKERS AND RUN ON THE ORACLE VM UNDER PLAIN NODE.
// Workers has no node:https, so every node import here is dynamic, built from a runtime-assembled
// specifier (so the Workers bundler cannot try to resolve it) and wrapped in try/catch. On Workers
// the node path is simply never taken and the TLS-tolerant rung of the ladder is skipped.
//
// Hard rule inherited from CONTRACT.md: NOTHING here throws. Every export resolves to a null-ish
// result on failure ({status:0,…}, [], or "") so a broken host can never kill a scan.

// ---------------------------------------------------------------------------
// Identities. Exported so the P3/P4 modules cloak-diff against byte-identical
// request signatures — a diff between two DIFFERENT browser UA strings would be
// a false positive, not a cloak.
// ---------------------------------------------------------------------------
export const UA_BR = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36";
export const UA_GB = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";
export const UA_MOB = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1";
export const REF_G = "https://www.google.com/";

// 96KB head cap — unchanged from scan.js. On the Workers FREE plan the 1102 is a CPU wall and
// regex over the page body is the #1 CPU cost, so this stays exactly where it was. P15's tail
// read is the answer to what the cap truncates, NOT a bigger cap.
export const HEAD_CAP = 96000;
const TAIL_BYTES = 32768;         // ~32KB: a wp_footer link-farm injection is a few KB at most
const TAIL_MAX_STREAM = 3000000;  // if a server ignores Range we stream at most 3MB before giving up

const NULL_PAGE = { status: 0, finalUrl: "", text: "", headers: null, chain: [] };

// ---------------------------------------------------------------------------
// runtime detection
// ---------------------------------------------------------------------------
// Workers sets navigator.userAgent = "Cloudflare-Workers", and with nodejs_compat it ALSO exposes a
// partial `process` — so process.versions.node alone would wrongly report node inside a Worker and
// send us down the node:https path. The negative navigator check is the load-bearing half.
const IS_WORKERS = typeof navigator !== "undefined" && /Cloudflare-Workers/i.test((navigator && navigator.userAgent) || "");
const IS_NODE = !IS_WORKERS
  && typeof globalThis.process !== "undefined"
  && !!(globalThis.process.versions && globalThis.process.versions.node)
  && typeof globalThis.process.versions.node === "string";

let NODE_HTTPS = null, NODE_HTTP = null, nodeModsTried = false;
async function loadNodeMods() {
  if (nodeModsTried) return;
  nodeModsTried = true;
  if (!IS_NODE) return;
  try {
    // The specifier is assembled at runtime on purpose: esbuild/wrangler statically analyse literal
    // dynamic imports and would try (and fail) to resolve node:https when bundling for Workers.
    const s = "node:";
    NODE_HTTPS = await import(s + "https");
    NODE_HTTP = await import(s + "http");
  } catch (e) { NODE_HTTPS = null; NODE_HTTP = null; }
}

// ---------------------------------------------------------------------------
// small host helpers (local copies — this module must not import scan.js, which imports it)
// ---------------------------------------------------------------------------
export function hostOf(url) {
  if (!url) return "";
  let s = String(url).toLowerCase().replace(/^[a-z]+:\/\//, "");
  s = s.replace(/\/.*$/, "").replace(/:.*$/, "");
  return s;
}
export function sameHost(host, reg) {
  if (!host || !reg) return false;
  return host === reg || host.endsWith("." + reg);
}

// Registrable ("eTLD+1") for the BD-heavy corpus. resolveBase used to take `reg` as simply the
// host minus "www.", which is wrong for a SUBDOMAIN: 18,008 of the 160,682 corpus entries (11.2%)
// are BD third-level hosts like hrm.bdren.net.bd or mobile.bmd.gov.bd, largely because the crt.sh
// harvester enumerates certificate identities. Under the old rule, such a host redirecting to its
// OWN parent (mail.foo.com.bd -> www.foo.com.bd, an extremely ordinary configuration) scored as
// landing OFF-domain, which both burned a pointless redirect-chain walk and synthesised a chain hop
// carrying an off-domain Location for the redirect layers to read. redirect.js happens to be
// insulated by its own sibling() test, but this module should not be producing the wrong answer and
// handing consumers the job of catching it.
const BD_SLD = /^(?:com|net|org|edu|gov|ac|mil|info|co)$/;
export function registrableOf(host) {
  const h = String(host || "").toLowerCase().replace(/^www\./, "");
  const p = h.split(".").filter(Boolean);
  if (p.length <= 2) return h;
  // three-level public suffixes: *.com.bd, *.gov.bd, *.ac.bd, *.co.uk, …
  if (p.length >= 3 && p[p.length - 1].length === 2 && BD_SLD.test(p[p.length - 2])) return p.slice(-3).join(".");
  return p.slice(-2).join(".");
}

function headersFrom(obj) {
  try {
    const h = new Headers();
    for (const k in obj) {
      const v = obj[k];
      h.set(k, Array.isArray(v) ? v.join(", ") : String(v));
    }
    return h;
  } catch (e) { return null; }
}

// ---------------------------------------------------------------------------
// placeholder classification — the safety catch on the P1 ladder
//
// The ladder makes thousands of previously-"dead" domains reachable, but a large slice of what the
// http:// and www rungs actually return is NOT the site: registrar parking farms, BTCL's expired-
// domain notice, unconfigured cPanel accounts, suspended accounts. Measured over 450 live domains
// from the real corpus, 36 were one of these — and on the confirmed-hacked sample they were 13 of
// the 18 "rescues", i.e. most of what the ladder recovers there is a lapsed domain, not a site.
//
// These are served GLOBALLY, not by a local ISP: the 122-byte "contact your service provider" stub
// resolves to 208.91.197.0/24 (Sedo / Above.com parking). So this gate is load-bearing on the
// Oracle VM and on Workers exactly as much as on the Mac booster — do not assume it is local noise.
//
// Handing those bytes to the detector as if they were the homepage is the single most dangerous
// thing this module could do. Parking and interception pages routinely carry casino/pharma ad text,
// off-domain canonicals and junk-TLD redirects — and scan.js:584 auto-confirms gambling/adult on a
// restricted institutional TLD with NO AI call. So a school whose domain merely EXPIRED would be
// sold to itself as "hacked". uchschool.edu.bd hit exactly this path in the dry run.
//
// Two tiers, because precision here is everything:
//   HARD — verbatim infrastructure strings no real site can carry. Safe at any document size.
//   SOFT — generic server-default/suspension text that could in principle appear in real prose,
//          so it only counts on a SMALL document or inside the <title>. Deliberately does NOT
//          include "under construction": a half-built BD business site is a real site, and it can
//          be hacked — suppressing it would cost a genuine lead.
// ---------------------------------------------------------------------------
// 2026-07-20 adversarial review: the BTCL marker below was DEAD CODE. It was written as
// `Domain Expired\s*Service Discontinued`, but the live page (verified against a full untruncated
// 92,272-byte fetch of ecotech.com.bd) actually serves:
//     Domain Expired &amp; Service\n  Discontinued
// i.e. an HTML-entity ampersand between the two phrases AND a newline inside "Service Discontinued".
// The old regex matched at NO offset in the real document — only the `bdia.btcl.com.bd` link (byte
// 70,743) was holding this gate up, and BTCL's server is slow enough that the 11s abort truncates
// the read before that byte on ~2 of 3 fetches. Repaired below, plus the verbatim
// "Please renew to reactivate the domain" string which appears ~10KB earlier (byte 60,017) and so
// survives truncation more often. Both dry-run against 7 real clean BD homepages (thedailystar,
// bracu, bdnews24, robi, grameenphone, brac, du.ac.bd) — zero hits.
const RE_PH_HARD = /\/cgi-sys\/defaultwebpage\.cgi|bdia\.btcl\.com\.bd|domain@btcl\.gov\.bd|Domain Expired\s*(?:&amp;|&|and)?\s*Service\s*Discontinued|Please renew to reactivate the domain|Error\.\s*Page cannot be displayed\.\s*Please contact your service provider|sedoparking\.com|parkingcrew\.net|parklogic\.com|bodis\.com|hugedomains\.com|afternic\.com|dan\.com\/buy-domain/i;
const RE_PH_SOFT = /Account Suspended|Bandwidth Limit Exceeded|Welcome to nginx!|Apache2? (?:Ubuntu |Debian |CentOS )?Default Page|IIS Windows Server|iisstart|Future home of something quite cool|Domain is not available|This site is temporarily unavailable|Default Web Site Page|Site Not Configured|The requested URL was not found on this server/i;
const SOFT_MAX = 15000;   // placeholder templates are tiny; real BD homepages that mention such text are not
const RE_TITLE_PH = /<title[^>]*>([\s\S]{0,300}?)<\/title>/i;

/**
 * classifyPlaceholder(text) -> "" | "hard" | "soft"
 * "" means these bytes look like a real document and are safe to score.
 * Exported so scan.js and layer modules can refuse to build evidence out of a parking page.
 */
export function classifyPlaceholder(text) {
  try {
    const t = String(text || "");
    if (!t) return "";
    if (RE_PH_HARD.test(t)) return "hard";
    const title = (RE_TITLE_PH.exec(t) || [, ""])[1] || "";
    if (RE_PH_SOFT.test(title)) return "soft";
    if (t.length <= SOFT_MAX && RE_PH_SOFT.test(t)) return "soft";
    return "";
  } catch (e) { return ""; }
}

// ---------------------------------------------------------------------------
// body readers
// ---------------------------------------------------------------------------
export async function readCapped(r, max = HEAD_CAP) {
  try {
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
    } catch (e) { /* truncated read is fine — partial bytes still detect */ }
    try { await reader.cancel(); } catch (e) {}
    const buf = new Uint8Array(received);
    let o = 0;
    for (const c of chunks) { buf.set(c, o); o += c.length; }
    return new TextDecoder("utf-8", { fatal: false }).decode(buf.subarray(0, max));
  } catch (e) { return ""; }
}

// Sliding-window tail read, used only when a server answers 200 to a Range request (i.e. ignores it).
// Keeps just the trailing ~32KB in memory no matter how big the document is — the whole point is to
// stay safe on the 946MB Oracle box, where buffering a 400MB response would OOM the scanner.
async function readTail(r, tail = TAIL_BYTES, maxTotal = TAIL_MAX_STREAM) {
  try {
    if (!r.body) {
      const t = await r.text();
      return t.slice(-tail);
    }
    const reader = r.body.getReader();
    const chunks = [];
    let held = 0, total = 0;
    try {
      while (total < maxTotal) {
        const { done, value } = await reader.read();
        if (done) break;
        chunks.push(value); held += value.length; total += value.length;
        while (chunks.length > 1 && held - chunks[0].length >= tail) { held -= chunks[0].length; chunks.shift(); }
      }
    } catch (e) { /* partial tail is still a usable tail */ }
    try { await reader.cancel(); } catch (e) {}
    const buf = new Uint8Array(held);
    let o = 0;
    for (const c of chunks) { buf.set(c, o); o += c.length; }
    return new TextDecoder("utf-8", { fatal: false }).decode(buf.subarray(Math.max(0, held - tail)));
  } catch (e) { return ""; }
}

// ---------------------------------------------------------------------------
// fetchPage — redirect-following capped read. Behaviour-identical to the one in scan.js today.
// ---------------------------------------------------------------------------
export async function fetchPage(url, ua, referer, ms = 11000) {
  const ctl = new AbortController();
  const t = setTimeout(() => { try { ctl.abort(); } catch (e) {} }, ms);
  if (t && typeof t.unref === "function") t.unref();
  try {
    const headers = { "user-agent": ua || UA_BR };
    if (referer) headers["referer"] = referer;
    const r = await fetch(url, { headers, redirect: "follow", signal: ctl.signal });
    const text = await readCapped(r);
    return { status: r.status, finalUrl: r.url || url, text, headers: r.headers, chain: [] };
  } catch (e) {
    return { ...NULL_PAGE };
  } finally {
    clearTimeout(t);
  }
}

// ---------------------------------------------------------------------------
// fetchManual — redirect:"manual". The reason L16HDR is effectively dead today: with
// redirect:"follow" the headers you get back belong to the FINAL 200, which by definition
// carries no Location. The junk-TLD hop lives in the hops nobody was looking at.
// ---------------------------------------------------------------------------
export async function fetchManual(url, ua, referer, ms = 9000) {
  const ctl = new AbortController();
  const t = setTimeout(() => { try { ctl.abort(); } catch (e) {} }, ms);
  if (t && typeof t.unref === "function") t.unref();
  try {
    const headers = { "user-agent": ua || UA_BR };
    if (referer) headers["referer"] = referer;
    const r = await fetch(url, { headers, redirect: "manual", signal: ctl.signal });
    const status = r.status;
    const loc = (r.headers && (r.headers.get("location") || "")) || "";
    // A 3xx body is a throwaway "Moved Permanently" stub — read 4KB just in case it carries a
    // meta-refresh/JS hop, but never pay the 96KB regex cost for it. A 2xx body is a real document.
    const text = (status >= 300 && status < 400) ? await readCapped(r, 4000) : await readCapped(r);
    return { status, location: loc, headers: r.headers, text, finalUrl: r.url || url };
  } catch (e) {
    return { status: 0, location: "", headers: null, text: "", finalUrl: "" };
  } finally {
    clearTimeout(t);
  }
}

// ---------------------------------------------------------------------------
// followChain — every hop, in order. Feeds P5's L16HDR/L21HOPS.
// ---------------------------------------------------------------------------
// `over` (optional) — the caller's overBudget(). Without it this walks up to 5 hops at 8s each,
// i.e. up to 40 SECONDS of blocking fetches with no deadline check, on top of a ladder that has
// already spent up to 32s. resolveBase only checked the budget BEFORE entering the walk, so a
// domain whose deadline expired on hop 1 still paid for hops 2-5. Checked per hop now.
export async function followChain(url, ua, referer, max = 5, over = null) {
  const out = [];
  let cur = url;
  const seen = new Set();
  const stop = typeof over === "function" ? over : () => false;
  try {
    for (let i = 0; i < Math.max(1, max); i++) {
      if (seen.has(cur)) break;   // redirect loop — a real hack pattern, but stop walking it
      if (i > 0 && stop()) break; // deadline passed mid-walk — keep the hops we already proved
      seen.add(cur);
      const r = await fetchManual(cur, ua, referer, 8000);
      out.push({ status: r.status, url: cur, location: r.location || "" });
      if (!r.status || r.status < 300 || r.status >= 400 || !r.location) break;
      let next;
      try { next = new URL(r.location, cur).href; } catch (e) { break; }
      if (!/^https?:\/\//i.test(next)) break;
      cur = next;
    }
  } catch (e) { /* return whatever hops we already proved */ }
  return out;
}

// ---------------------------------------------------------------------------
// fetchTail (P15) — the last ~32KB of the document.
//
// Footer link-farm injection (footer.php / wp_footer) lands in the LAST few KB of a 150-400KB
// Elementor/WooCommerce page, i.e. entirely past the 96KB head cap. One Range request retrieves
// exactly the bytes the head read threw away.
//
// opts.headLen / opts.contentLength let the caller prove the head read already saw the whole
// document, in which case this costs ZERO requests — which is most BD SMB homepages.
// ---------------------------------------------------------------------------
export async function fetchTail(url, ua, ms = 9000, opts = {}) {
  try {
    const headLen = Number(opts.headLen || 0);
    const clen = Number(opts.contentLength || 0);
    // Head read came back short of the cap ⇒ we already have the footer. Nothing to fetch.
    if (headLen && headLen < HEAD_CAP - 512) return "";
    if (clen && clen <= HEAD_CAP) return "";
    const ctl = new AbortController();
    const t = setTimeout(() => { try { ctl.abort(); } catch (e) {} }, ms);
    if (t && typeof t.unref === "function") t.unref();
    try {
      const headers = { "user-agent": ua || UA_BR, "range": `bytes=-${TAIL_BYTES}` };
      const r = await fetch(url, { headers, redirect: "follow", signal: ctl.signal });
      // A 206 is only usable if it is actually the TAIL. Servers exist that answer a suffix range
      // with a range of their own choosing (commonly bytes=0-32767), which would hand back the HEAD
      // — bytes the content layers have already scored out of B.text. The same bytes then get
      // scored a second time out of ctx.tail in a different bucket, and CONTRACT.md is explicit
      // that two layers reading the same bytes in different buckets inflate the posterior. So the
      // Content-Range must reach the last byte of the document before we trust it.
      // Costs nothing in recall: of 8 large BD sites probed (thedailystar, grameenphone, robi,
      // bdnews24, …) exactly ZERO answered 206 at all — they all ignore Range and take the
      // readTail() streaming path below, which is tail-correct by construction.
      if (r.status === 206) {
        const cr = String((r.headers && r.headers.get("content-range")) || "");
        const m = /bytes\s+(\d+)-(\d+)\/(\d+|\*)/i.exec(cr);
        if (m && m[3] !== "*" && Number(m[2]) < Number(m[3]) - 1) return "";  // not the tail — refuse
        return await readCapped(r, TAIL_BYTES + 8000);
      }
      if (r.status === 416) return "";                 // server has no range for us
      if (r.status >= 200 && r.status < 300) return await readTail(r);  // Range ignored → stream, keep the tail
      return "";
    } finally { clearTimeout(t); }
  } catch (e) { return ""; }
}

// ---------------------------------------------------------------------------
// node-only TLS-tolerant GET (the last rung of the P1 ladder)
//
// Expired Let's Encrypt certs, self-signed certs and SAN/hostname mismatches make global fetch()
// throw, and scan.js turns that into dead=1 — the site is never scanned even once. Abandoned and
// already-compromised sites are exactly the population with broken TLS, so this rung is positively
// correlated with the thing we are hunting. Node gives us rejectUnauthorized:false; Workers does
// not, so on Workers this rung silently does not exist.
// ---------------------------------------------------------------------------
function nodeGet(url, ua, referer, ms, hops = 4) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (v) => { if (!done) { done = true; resolve(v); } };
    let u;
    try { u = new URL(url); } catch (e) { return finish({ ...NULL_PAGE }); }
    const lib = u.protocol === "http:" ? NODE_HTTP : NODE_HTTPS;
    if (!lib || !lib.request) return finish({ ...NULL_PAGE });
    const hdr = { "user-agent": ua || UA_BR, "accept-encoding": "identity" };
    if (referer) hdr["referer"] = referer;
    let req;
    try {
      req = lib.request({
        protocol: u.protocol,
        hostname: u.hostname,
        port: u.port || undefined,
        path: (u.pathname || "/") + (u.search || ""),
        method: "GET",
        headers: hdr,
        timeout: ms,
        rejectUnauthorized: false,   // the entire point of this function
        servername: u.hostname,
      }, (res) => {
        const st = res.statusCode || 0;
        const loc = res.headers && res.headers.location;
        if (st >= 300 && st < 400 && loc && hops > 0) {
          try { res.destroy(); } catch (e) {}
          let nx;
          try { nx = new URL(loc, url).href; } catch (e) { return finish({ ...NULL_PAGE }); }
          return nodeGet(nx, ua, referer, ms, hops - 1).then(finish, () => finish({ ...NULL_PAGE }));
        }
        const parts = [];
        let len = 0;
        const end = () => finish({
          status: st,
          finalUrl: url,
          text: parts.length ? Buffer.concat(parts).toString("utf8").slice(0, HEAD_CAP) : "",
          headers: headersFrom(res.headers || {}),
          chain: [],
        });
        res.on("data", (c) => {
          if (len >= HEAD_CAP) return;
          parts.push(c); len += c.length;
          if (len >= HEAD_CAP) { try { res.destroy(); } catch (e) {} }
        });
        res.on("end", end);
        res.on("close", end);
        res.on("error", end);
      });
    } catch (e) { return finish({ ...NULL_PAGE }); }
    req.on("error", () => finish({ ...NULL_PAGE }));
    req.on("timeout", () => { try { req.destroy(); } catch (e) {} finish({ ...NULL_PAGE }); });
    const guard = setTimeout(() => { try { req.destroy(); } catch (e) {} finish({ ...NULL_PAGE }); }, ms + 800);
    if (guard && typeof guard.unref === "function") guard.unref();
    try { req.end(); } catch (e) { finish({ ...NULL_PAGE }); }
  });
}

// ---------------------------------------------------------------------------
// resolveBase (P1) — the reachability ladder
// ---------------------------------------------------------------------------
function ladder(d) {
  const apex = d.replace(/^www\./, "");
  const alt = /^www\./.test(d) ? apex : "www." + apex;
  return [
    { url: "https://" + d, scheme: "https" },
    { url: "https://" + alt, scheme: "https" },
    { url: "http://" + d, scheme: "http" },
    { url: "http://" + alt, scheme: "http" },
  ];
}

// How good is this answer? The ladder returns on the FIRST rung that scores GOOD, and otherwise
// keeps the best-scoring rung it saw. The ordering matters more than it looks:
//   404 outranks 5xx  — an apex that 404s usually means www is the real door, so keep climbing,
//                       whereas a 5xx means the whole site is down and no other rung will help.
//   401/403/429 rank above 404 — a WAF challenge IS the site answering; scan.js already handles
//                       that page via the L18CHALLENGE control signal, so it is a valid base.
//   a placeholder outranks nothing but loses to every real document — so when the apex is a
//                       parking page and www serves the actual site, the ladder keeps climbing and
//                       takes the real site. If EVERY rung is a placeholder we still return it,
//                       carrying the flag, so the caller can decline to score those bytes.
// Memoised: classifyPlaceholder runs two alternation regexes over a document up to 96KB, and
// quality() is called once per ladder rung (up to 6) with resolveBase calling it once more on the
// winner — 7 full-document regex passes per domain. On the Workers FREE plan the CPU wall is the
// documented cause of the 1102 stall, so the result is cached on the response object instead.
function phOf(r) {
  if (!r) return "";
  if (typeof r.__ph === "string") return r.__ph;
  const v = classifyPlaceholder(r.text);
  try { Object.defineProperty(r, "__ph", { value: v, enumerable: false }); } catch (e) {}
  return v;
}

function quality(r) {
  if (!r || !r.status) return 0;
  const s = r.status;
  const ph = (s >= 200 && s < 400) ? phOf(r) : "";
  if (ph) return 2.5;                                                    // not the site — keep climbing
  if (s >= 200 && s < 400 && r.text && r.text.length > 200) return 5;   // real document
  if (s >= 200 && s < 400) return 4;                                     // answered, thin/empty body
  if (s === 401 || s === 403 || s === 429) return 3;                     // alive, gated (WAF)
  if (s === 404 || s === 410) return 2;                                  // alive, wrong door
  return 1;                                                              // 5xx and friends
}
const GOOD = 5;

/**
 * resolveBase(domain, opts) — find an origin that actually answers, and return its bytes.
 *
 * opts:
 *   ua, referer, ms      request identity + per-attempt timeout for the FIRST rung
 *   retryMs              timeout for rungs 2..4 (default 7000 — a dead domain must not burn 4x11s)
 *   knownBase            a base cached from a previous scan; tried first, so re-scans pay the
 *                        ladder cost exactly once per domain (P1's own cost mitigation)
 *   tls                  false to skip the node TLS-tolerant rung
 *   chain                true  = always resolve the redirect chain (extra fetches)
 *                        false = never
 *                        default "auto" = only when the winning fetch landed OFF the registrable,
 *                        which is the only case P5 cares about and is a few % of domains
 *   overBudget()         called before every rung; stops the ladder cold when the per-domain
 *                        deadline has passed
 *
 * returns {base, status, text, headers, finalUrl, chain, scheme, tlsBad, attempts}
 * base === "" means every rung failed → the caller may mark the domain unreachable.
 */
export async function resolveBase(domain, opts = {}) {
  const out = { base: "", status: 0, text: "", headers: null, finalUrl: "", chain: [], scheme: "", tlsBad: false, attempts: 0, placeholder: "", parkedBase: "" };
  try {
    const d = String(domain || "").trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
    if (!d || !/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(d)) return out;
    const reg = registrableOf(d);
    const ua = opts.ua || UA_BR;
    const ref = opts.referer || null;
    const ms = Number(opts.ms || 11000);
    const retryMs = Number(opts.retryMs || 7000);
    const over = typeof opts.overBudget === "function" ? opts.overBudget : () => false;

    let cands = ladder(d);
    if (opts.knownBase) {
      const kb = String(opts.knownBase).replace(/\/+$/, "");
      cands = [{ url: kb, scheme: kb.startsWith("http://") ? "http" : "https" }, ...cands.filter((c) => c.url !== kb)];
    }

    let best = null, bestQ = 0, bestC = null;
    // The http:// rungs exist for one reason: hosts that do not speak TLS at all. So the moment ANY https rung
    // comes back with a real HTTP status — even 403 from a WAF, even 404 — the http:// rungs are provably
    // pointless and get dropped. Without this a bot-blocked site like bracu.ac.bd walked all four rungs and
    // spent 5s to learn what the first rung already knew, on every domain, on every pass.
    let httpsAnswered = false;
    for (const c of cands) {
      if (over()) break;
      if (c.scheme === "http" && httpsAnswered) continue;
      out.attempts++;
      const r = await fetchPage(c.url, ua, ref, out.attempts === 1 ? ms : retryMs);
      const q = quality(r);
      if (c.scheme === "https" && r && r.status > 0) httpsAnswered = true;
      if (q > bestQ) { bestQ = q; best = r; bestC = c; }
      if (q >= GOOD) break;
    }

    // Every plain rung failed to even connect. On node only, retry TLS-tolerantly: an expired or
    // mismatched cert is a connect-level throw, so it looks identical to "domain does not exist"
    // to global fetch, and that is how live sites end up marked dead=1.
    if (bestQ === 0 && IS_NODE && opts.tls !== false && !over()) {
      await loadNodeMods();
      if (NODE_HTTPS) {
        for (const c of cands.filter((x) => x.scheme === "https")) {
          if (over()) break;
          out.attempts++;
          const r = await nodeGet(c.url, ua, ref, retryMs);
          const q = quality(r);
          if (q > bestQ) { bestQ = q; best = r; bestC = c; out.tlsBad = true; }
          if (q >= GOOD) break;
        }
      }
    }

    if (!best || !bestQ) return out;
    out.base = bestC.url.replace(/\/+$/, "");
    out.scheme = bestC.scheme;
    out.status = best.status;
    out.text = best.text || "";
    out.headers = best.headers || null;
    out.finalUrl = best.finalUrl || bestC.url;
    // Non-empty ⇒ these bytes are a parking / ISP-interception / expired-domain page, NOT the site.
    out.placeholder = phOf(best);

    // FAIL CLOSED. The original version of this module returned the parking bytes and merely SET
    // this flag, documenting a "REQUIRED_of_scan.js" contract that scan.js does not implement:
    // scan.js:353-356 destructures status/text/headers/chain and never reads .placeholder. So the
    // ladder was handing an expired-domain page to the detector as if it were the homepage.
    //
    // Measured on 320 domains from clean-live.txt: 112 answered, and 18 of those 112 (16%) were
    // placeholders — 17 BTCL expired-.com.bd notices plus darularqam.ac.bd, a REAL Bangladeshi
    // madrasa whose hosting is merely SUSPENDED. Scoring a suspended madrasa's 789-byte host page
    // and selling it back to them as "your site is hacked" is precisely the failure CONTRACT.md
    // rule 4 exists to prevent, and parking pages routinely carry casino/pharma ad text that
    // reaches the no-AI auto-confirm branch at scan.js:584.
    //
    // A parked/expired/suspended domain is not a scannable site, so it is reported as unreachable —
    // the one verdict that is true. Diagnostics are preserved on .placeholder/.parkedBase, and a
    // caller that genuinely wants the parked bytes (reporting, dashboards) passes
    // opts.allowPlaceholder = true. Costing ourselves a lead here is the cheap direction.
    if (out.placeholder && opts.allowPlaceholder !== true) {
      out.parkedBase = out.base;
      out.base = ""; out.status = 0; out.text = ""; out.headers = null; out.finalUrl = ""; out.chain = [];
      return out;
    }

    // Redirect chain. Default "auto": only walk it when the follow-fetch actually landed off the
    // registrable — that is exactly the L16HDR/L21HOPS case, and it keeps the common site at zero
    // extra requests. A same-registrable chain (http→https→www→trailing slash) proves nothing.
    const landedHost = hostOf(out.finalUrl);
    const offDomain = !!landedHost && !sameHost(landedHost, reg);
    const wantChain = opts.chain === true || (opts.chain !== false && offDomain);
    if (wantChain && !over()) {
      const hops = await followChain(out.base + "/", ua, ref, Number(opts.maxHops || 5), over);
      if (hops.length) out.chain = hops;
    }
    if (!out.chain.length) out.chain = [{ status: out.status, url: out.base + "/", location: offDomain ? out.finalUrl : "" }];
    return out;
  } catch (e) {
    return out;
  }
}

// ---------------------------------------------------------------------------
// fetchVariant — the P3/P4 plumbing.
//
// P3 needs the bot fetch SPLIT: today scan.js sends UA_GB and REF_G together, so a cloak that
// fires can never be attributed to UA vs referer, and a referer-only cloaker that ignores UA is
// missed entirely because the browser fetch sends no referer at all.
//   "browser"        UA_BR, no referer            — the control
//   "googlebot-ua"   UA_GB, no referer            — UA cloak only            (L2UACLOAK)
//   "google-referer" UA_BR + Referer: google.com  — referer cloak only       (L3REFCLOAK)
//   "mobile"         iPhone UA, manual redirect   — mobile-only redirect     (L4MOBILE)
// ---------------------------------------------------------------------------
export async function fetchVariant(url, kind, ms) {
  switch (kind) {
    case "googlebot-ua": return await fetchPage(url, UA_GB, null, ms || 11000);
    case "google-referer": return await fetchPage(url, UA_BR, REF_G, ms || 11000);
    case "googlebot": return await fetchPage(url, UA_GB, REF_G, ms || 11000);  // legacy combined fetch
    case "mobile": return await fetchManual(url, UA_MOB, REF_G, ms || 9000);
    case "browser":
    default: return await fetchPage(url, UA_BR, null, ms || 11000);
  }
}

// Exposed for tests/diagnostics — which runtime path this build took.
export const RUNTIME = { isNode: IS_NODE, isWorkers: IS_WORKERS };
