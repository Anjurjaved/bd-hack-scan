// links.js — outbound-link forensics (P11 · P12 · P32 · P33).
//
// WHY THIS MODULE EXISTS: stripHtml() (scan.js:27) deletes every tag before keyword matching, so
// `href="https://slot-gacor-xyz.top/"` is invisible to L1KW_STRONG and to every other layer. Nothing
// in the live detector reads a single href. The classic WordPress link-farm injection — 60 <a> tags
// appended by footer.php, anchor text an image or an innocuous word — therefore scores CLEAN today.
// Everything here reads bytes that were already fetched: ZERO extra HTTP requests, tier-1 safe.
//
// FP DISCIPLINE: these leads are sold to real BD schools and SMBs. Every threshold below is set at
// the point where the clean-BD control group (2,000 scanned-clean domains) stopped producing hits,
// not at the point where recall stopped improving.

export const TIER = "t1";

// Bayesian [P(fires | hacked), P(fires | clean)].
//
// MEASURED 2026-07-19 by fetching live homepages:
//   hacked  = 398 reachable of a 500-domain spread across confirmed.tsv (is_bd=1)
//   clean   = 822 reachable of a 2,000-domain spread across clean-bd.txt
//           + 138 reachable link-heavy BD news/directory sites pulled from corpus.txt (the worst
//             case for outbound-link layers — those legitimately link off-domain the most)
//   → L27 18/398 hacked, 0/960 clean.  L28 37/398 hacked, 0/960 clean.
// The clean column below is set FAR above the measured 0/960 on purpose: 960 samples cannot
// distinguish 0 from 1-in-300, and an over-confident denominator silently manufactures leads
// (CONTRACT.md rule 4).
export const WEIGHTS = {
  // Generic neighbourhood evidence. Deliberately the weakest of the four: "this page links to spam
  // hosts" is one inference step away from "this page was edited by someone who is not the owner".
  // Held at 0.030 rather than the measured 0 because the junk-TLD arm has real theoretical FP
  // surface (a BD news site quoting three .ru sources) that 960 samples may simply not have hit.
  // REVIEW 2026-07-20: an independent 403-live-site corpus sweep put 401/403 at ZERO junk-TLD hosts
  // and 1/403 at three. 0.030 survives that unchanged.
  L27OUTLINK: [0.72, 0.030],
  // Anchor TEXT is stronger than anchor TARGET: a hijacked footer writes the keyword the campaign is
  // ranking for, and a legitimate BD business never has three distinct anchors reading `slot gacor`.
  // REVIEW 2026-07-20: raised 0.012 → 0.020 for two reasons the original measurement could not see.
  //  (a) CONTROL BIAS. clean-bd.txt is a list of domains the CURRENT detector scored clean, i.e. a
  //      population already filtered for spam KEYWORDS. Measuring a keyword-shaped layer against a
  //      keyword-filtered control understates its FP rate by construction.
  //  (b) THE NEWS CYCLE. S.ALL_STRONG contains unbounded `casin[oò]` and `\bporn\b`, so three distinct
  //      headlines about the Dhaka casino raids fire this layer on a clean newspaper. vocab.js already
  //      concedes this exact hazard and suppresses its generic-casino arm on `biz === "news"`
  //      (vocab.js:~330). A fresh 403-site sweep found 2 clean-ish sites already sitting at TWO
  //      distinct spam anchors — one headline short of firing — so 0/960 is a snapshot, not a bound.
  // The news guard added in run() covers (b); 0.020 prices in (a) and the residual. LR is still 39, so
  // one corroborating bucket confirms — the layer is not weakened, only priced honestly.
  L28ANCHOR: [0.78, 0.020],
  // Self-learned host, admitted only after appearing on >=3 DISTINCT confirmed victims. By
  // construction it cannot be a shared library host (those are allowlisted below before counting).
  // REVIEW 2026-07-20: raised 0.010 → 0.020. This is the ONE layer here with no measurement at all —
  // the blocklist is empty today, so 0.010 was a prior wearing a measurement's clothes. It is also the
  // only layer with a FEEDBACK LOOP (confirmed leads mint hosts that confirm the next leads), and its
  // safety rests entirely on a finite hand-written allowlist: one popular BD shared asset host that
  // nobody thought of (a Bangla webfont CDN, an agency's shared jQuery) reaching 3 confirmed victims
  // fires on every clean BD site that uses it. 0.020 still leaves LR 45.
  L45KNOWNHOST: [0.90, 0.020],
  // URLhaus-listed resource LOADED (not merely linked) by the page. abuse.ch lists confirmed
  // malware-distribution URLs; a BD school page executing one is not an SEO-spam judgement call.
  // REVIEW 2026-07-20: raised 0.004 → 0.008. URLhaus lists COMPROMISED LEGITIMATE HOSTS, not only
  // dedicated droppers. Host-level matching therefore fired on any innocent site that happened to
  // hotlink an asset from a hacked neighbour — and BD SMBs sharing one web agency's server is the
  // premise this project's own lead-coip harvester is built on. Path-scoping (parseUrlhaus below) now
  // removes most of that; 0.008 prices the rest. It matters more than the number looks: category
  // "malware" routes AROUND the Gemini gate in scan.js and confirms with no AI review at all.
  L46URLHAUS: [0.95, 0.008],
};

// L27/L28 are intentionally absent: their evidence IS the spam vocabulary, so the keyword-derived
// category (gambling / pharma / adult) is more accurate than any fixed label we could pin on them.
export const CATS = {
  L46URLHAUS: "malware",
};

// ---------------------------------------------------------------------------
// Host allowlist. MANDATORY, not optional — P32's own analysis notes that without it
// googletagmanager.com is harvested into the self-learned blocklist within a day, because it
// legitimately appears on thousands of hacked victims. Superset of scan.js:338 relaySkip.
// ---------------------------------------------------------------------------
import { registrableOf } from "../signatures.js";

const SAFE_HOST = /(?:^|\.)(?:google|googleapis|gstatic|googletagmanager|google-analytics|googleusercontent|googlesyndication|doubleclick|youtube|youtu\.be|ytimg|facebook|fbcdn|instagram|twitter|x\.com|t\.co|linkedin|licdn|pinterest|whatsapp|wa\.me|telegram|t\.me|tiktok|snapchat|vimeo|dailymotion|soundcloud|spotify|apple|microsoft|office|live|bing|msn|yahoo|amazon|amazonaws|cloudfront|akamai|akamaihd|fastly|cloudflare|cloudflareinsights|jsdelivr|unpkg|cdnjs|bootstrapcdn|jquery|fontawesome|typekit|adobe|gravatar|wp|wordpress|w\.org|woocommerce|elementor|yoast|shopify|myshopify|wix|wixsite|wixstatic|weebly|squarespace|webflow|netlify|vercel|github|githubusercontent|gitlab|bitbucket|sourceforge|npmjs|stackoverflow|medium|blogspot|blogger|tumblr|reddit|quora|wikipedia|wikimedia|archive\.org|creativecommons|schema\.org|mozilla|w3\.org|bunny|bunnycdn|b-cdn|imgur|flickr|500px|unsplash|pexels|pixabay|freepik|recaptcha|hcaptcha|hotjar|clarity\.ms|mailchimp|sendgrid|mailgun|hubspot|zendesk|intercom|tawk|crisp|livechat|calendly|zoom|teams|paypal|stripe|visa|mastercard|bkash|nagad|rocket|sslcommerz|aamarpay|shurjopay|portwallet|dhl|fedex|ups|pathao|daraz|foodpanda|banglalink|grameenphone|robi|teletalk|btcl|bdix|bttb|dot\.gov\.bd|nic\.gov\.bd|maateen|ekushey|omicronlab|iconify|iconscout|flaticon|boxicons|remixicon|lineicons|tailwindcss|datatables|sweetalert2|swiperjs|owlcarousel2|animate\.style|emailjs|jivosite|disqus|addthis|sharethis|cookieyes|cookiebot|trustpilot)\./i;
// The tail from `maateen` on was added by the 2026-07-20 review. Every entry is a shared asset host
// that thousands of ordinary BD sites load — `fonts.maateen.me` alone serves the free Bangla webfonts
// used across most of the .bd web. Reaching a self-learned blocklist (L45) via three hacked victims that
// merely happened to use Bangla fonts would then fire on every clean BD site on the internet. Note the
// direction of this edit: growing an ALLOWLIST can only ever lose recall on a spam host that named
// itself after a font CDN, never manufacture a false positive.

// Public-suffix approximation. We only need "count each registrable ONCE" so a 60-link footer to a
// single spam domain scores 1, not 60. Full PSL is 200KB+ and this runs on a 946MB VM per domain.
const MULTI_SUFFIX = new Set([
  "com.bd", "net.bd", "org.bd", "edu.bd", "gov.bd", "ac.bd", "mil.bd", "info.bd",
  "co.uk", "org.uk", "ac.uk", "gov.uk", "co.in", "net.in", "org.in", "co.jp", "or.jp", "ne.jp",
  "com.au", "net.au", "org.au", "com.br", "com.cn", "net.cn", "org.cn", "com.pk", "com.np",
  "com.my", "com.sg", "com.tr", "com.mx", "com.ar", "co.za", "co.nz", "co.id", "or.id", "web.id",
  "com.ph", "com.vn", "com.hk", "com.tw", "com.sa", "com.eg", "com.ng", "com.gh", "com.lk",
]);

// Platforms that hand out a subdomain per customer. Their REGISTRABLE is meaningless as an identity:
// `pub-c0a3….r2.dev` (a Cloudflare R2 bucket) and a malware bucket on r2.dev share a registrable but
// share nothing else. MEASURED: registrable-level URLhaus matching fired L46 on joinnavy.navy.mil.bd
// — the Bangladesh Navy recruitment site — because it serves its own PDFs from r2.dev and URLhaus
// lists some other r2.dev bucket. That is precisely the "tell a real institution it is hacked" failure
// this system cannot afford. Hosts under these suffixes are therefore only ever matched FULL-HOST,
// never by registrable, and are never admitted to the self-learned blocklist.
const SHARED_SUFFIX = new Set([
  "r2.dev", "pages.dev", "workers.dev", "vercel.app", "netlify.app", "web.app", "firebaseapp.com",
  "appspot.com", "azurewebsites.net", "windows.net", "herokuapp.com", "glitch.me", "repl.co",
  "replit.dev", "ngrok.io", "ngrok-free.app", "trycloudflare.com", "githubusercontent.com",
  "github.io", "gitlab.io", "surge.sh", "onrender.com", "fly.dev", "cyclic.app", "koyeb.app",
  "amazonaws.com", "digitaloceanspaces.com", "linodeobjects.com", "backblazeb2.com", "storage.googleapis.com",
  "blogspot.com", "wordpress.com", "wixsite.com", "weebly.com", "webnode.com", "000webhostapp.com",
  "sharepoint.com", "dropbox.com", "dropboxusercontent.com", "mediafire.com", "discordapp.com", "discord.com",
]);

const RE_IPV4 = /^\d{1,3}(?:\.\d{1,3}){3}$/;

function sharedSuffix(reg) {
  return SHARED_SUFFIX.has(reg);
}

// Organisation-of-host. Delegates to signatures.registrableOf so the blocklist, the lead rollup and the
// dashboard all agree on what "one organisation" means — a local copy with its own suffix list drifted and
// mined `co.ke` as if it were a spam host, which is a public suffix, not anybody's domain.
function regOf(host) {
  if (!host) return "";
  host = host.replace(/^www\./, "");
  if (RE_IPV4.test(host)) return host;
  // A hostname must have a real TLD. A truncated URL yields fragments like "alhaqaeq.n", which used to reach
  // the blocklist as a "spam host" and would then match nothing — or worse, match by prefix somewhere else.
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(host)) return "";
  return registrableOf(host);
}

// ATTRIBUTE RUNS ARE BOUNDED — `[^>]{0,400}`, never `[^>]*`. This is not style. These regexes run over
// HTML written by the attacker who owns the hacked site, and with an unbounded quantifier a document of
// `<a ` openers that never close makes every start position rescan to EOF and backtrack. cloak.js:279
// documents the same trap measured at 2,633ms vs 36ms; MEASURED HERE 2026-07-20 on the unfixed file:
//   138KB of "<a " x46000        → 8,633 ms of pure CPU in run()
//   210KB of "<a href" x30000    → 10,455 ms
// The free-plan CPU wall (error 1102) is this project's documented failure mode and 8.6s is thousands of
// times over it — one hostile page could freeze a shard. Bounded, the same inputs cost single-digit ms.
// Real anchor tags are far under 400 chars, so the bound costs no recall.
//
// Built PER CALL, not module-level: a module-level /g regex carries lastIndex between concurrent
// scanDomain() calls in one isolate (vocab.js:~268 states the same policy). run() has no `await` on
// these paths today, so nothing is broken yet — this removes the landmine before someone adds one.
//
// <a href="http…"> only. Relative and mailto/tel/javascript hrefs carry no neighbourhood signal.
const SRC_HREF = String.raw`<a\b[^>]{0,400}?\bhref\s*=\s*["'](https?://[^"'\s>]{4,300})`;
// Resources the browser EXECUTES or EMBEDS. Kept separate from hrefs on purpose: loading a host is
// materially stronger evidence than linking to it, and only this set feeds L46URLHAUS.
const SRC_RES = String.raw`<(?:script|iframe|embed|source|video|audio)\b[^>]{0,400}?\bsrc\s*=\s*["'](https?://[^"'\s>]{4,300})|<object\b[^>]{0,400}?\bdata\s*=\s*["'](https?://[^"'\s>]{4,300})`;
// Inner text capped at 120 chars: a real link-farm anchor is a keyword phrase, not a paragraph.
const SRC_ANCHOR = String.raw`<a\b([^>]{0,400})>([\s\S]{0,120}?)</a>`;

const MAX_LINKS = 1200;   // beyond this a page is a directory/aggregator; the ratio stops meaning anything
const MAX_ANCHORS = 800;  // per P12
const MAX_BYTES = 400000; // CPU guard — B.text is capped at 96KB but tail/G may be appended by the caller

function harvest(rx, html, cap) {
  const out = [];
  rx.lastIndex = 0;
  let m, n = 0;
  while ((m = rx.exec(html)) && n++ < cap) {
    const u = m[1] || m[2];
    if (u) out.push(u);
  }
  return out;
}

// ---------------------------------------------------------------------------
// P33 — abuse.ch URLhaus loader. One download serves every domain in the queue, so this is a
// process-level cache with an explicit TTL, never a per-domain fetch. Callers may hand in a
// {get,put} store (Workers KV, or a file on the VM) to survive isolate/process restarts.
// ---------------------------------------------------------------------------
// text_online = URLs abuse.ch has re-checked and found STILL SERVING. The full dump
// (/downloads/text/, ~3.8MB) also carries years of dead URLs whose domains have since expired and
// been re-registered by innocent parties — matching those would invent hacks. Precision wins here;
// pass {full:true} only if you accept that trade.
const URLHAUS_FEED = "https://urlhaus.abuse.ch/downloads/text_online/";
const URLHAUS_FEED_FULL = "https://urlhaus.abuse.ch/downloads/text/";
const URLHAUS_TTL = 20 * 60 * 60 * 1000; // ~daily, with slack so a cron at a fixed hour never misses
const URLHAUS_MAX = 250000;              // memory guard for the 946MB VM

let _uh = { set: null, at: 0 };

// Full hostnames, NOT registrables. See SHARED_SUFFIX above for the FP this prevents.
//
// PATH-SCOPED (2026-07-20 review). Host-only matching was the module's biggest remaining FP door, and
// it is the SAME failure that produced the joinnavy.navy.mil.bd hit, one level up. URLhaus does not
// only list dedicated dropper domains — a large share of its feed is COMPROMISED LEGITIMATE SITES
// serving one payload out of one directory. So `https://somebdagency.com/wp-content/uploads/x.exe`
// blocklisted the whole of somebdagency.com — and every innocent client site that loads
// `https://somebdagency.com/js/main.js` from that same shared server then fired L46 at LR 237,
// category "malware", which in scan.js confirms with NO AI review. BD SMBs sharing one agency's
// server is not a hypothetical; it is the premise this project's own lead-coip harvester runs on.
//
// The set therefore holds two shapes and run() tests both:
//   "host"            — added ONLY when the listed URL is root-ish (<=1 path segment), i.e. the shape
//                       of a dedicated dropper: evil.top/, evil.top/a.exe, 1.2.3.4/bins.sh
//   "host/firstseg"   — added always, so a deep listing scopes to its own directory
// Result: /wp-content/uploads/x.exe blocklists "site.com/wp-content", never "site.com/js". Recall on
// real dropper hosts is untouched, because those list at the root.
function parseUrlhaus(txt) {
  const set = new Set();
  if (!txt) return set;
  for (const line of txt.split("\n")) {
    if (!line || line.charCodeAt(0) === 35) continue; // '#' comment header
    const m = /^https?:\/\/([^/:?#\s]+)([^?#\s]*)/i.exec(line.trim());
    if (!m) continue;
    const h = m[1].toLowerCase().replace(/:\d+$/, "").replace(/^www\./, "");
    if (!h || h.length < 4) continue;
    // A shared library/CDN host would blocklist itself for every site that uses it.
    if (SAFE_HOST.test(h + ".") || SAFE_HOST.test(regOf(h) + ".")) continue;
    const segs = String(m[2] || "").split("/").filter(Boolean);
    if (segs.length <= 1) set.add(h);                                    // dedicated dropper shape
    if (segs.length) set.add(h + "/" + segs[0].toLowerCase().slice(0, 60));
    if (set.size >= URLHAUS_MAX) break;
  }
  return set;
}

// The two keys a loaded resource is tested against, mirroring parseUrlhaus.
function urlhausKeys(host, url) {
  const p = /^https?:\/\/[^/?#]+([^?#]*)/i.exec(url || "");
  const segs = String((p && p[1]) || "").split("/").filter(Boolean);
  return segs.length ? [host, host + "/" + segs[0].toLowerCase().slice(0, 60)] : [host];
}

/**
 * Returns a Set of registrable hosts listed by URLhaus. Never throws: on any failure it returns the
 * last good set, or an empty set — a dead feed must degrade to "no threat-intel signal", never to a
 * scan crash and never to an empty set overwriting a good one.
 */
export async function loadUrlhausHosts(opts = {}) {
  const now = Date.now();
  const ttl = opts.ttlMs || URLHAUS_TTL;
  if (_uh.set && now - _uh.at < ttl && !opts.force) return _uh.set;
  const store = opts.store;
  try {
    if (store && typeof store.get === "function" && !opts.force) {
      const cached = await store.get("urlhaus");
      if (cached) {
        const at = Number(cached.at || 0);
        if (now - at < ttl && cached.text) {
          const s = parseUrlhaus(cached.text);
          if (s.size) { _uh = { set: s, at }; return s; }
        }
      }
    }
  } catch (e) { /* cache miss is not an error */ }
  try {
    const f = opts.fetch || (typeof fetch === "function" ? fetch : null);
    if (!f) return _uh.set || new Set();
    const r = await f(opts.full ? URLHAUS_FEED_FULL : URLHAUS_FEED, { signal: AbortSignal.timeout(opts.timeoutMs || 25000) });
    if (!r || !r.ok) return _uh.set || new Set();
    const txt = await r.text();
    const s = parseUrlhaus(txt);
    if (!s.size) return _uh.set || new Set();
    _uh = { set: s, at: now };
    if (store && typeof store.put === "function") {
      try { await store.put("urlhaus", { at: now, text: txt }); } catch (e) {}
    }
    return s;
  } catch (e) {
    // NEGATIVE CACHE. Without this a dead feed re-fetches on EVERY call: scan.js's own urlhaus()
    // wrapper happens to hold a 6h cache in front, but the VM scanner calls this directly, and a
    // 300k-domain re-scan against a down abuse.ch would be 300k requests at a free service.
    if (!_uh.set) _uh = { set: new Set(), at: now - ttl + 10 * 60 * 1000 };  // retry in ~10 min
    return _uh.set;
  }
}

// ---------------------------------------------------------------------------
// P32 — self-learned spam-host blocklist, built OFFLINE from confirmed findings.
// Injection campaigns reuse one loader host across thousands of victims, so every confirmed hack
// sharpens detection of the next dozen at zero HTTP cost.
// ---------------------------------------------------------------------------
/**
 * @param findings rows shaped {domain, evidence, proof_url} — evidence is the JSON array scan.js
 *                 stores (or an already-parsed array). Anything unparseable is skipped silently.
 * @param minVictims a host must appear on this many DISTINCT victim domains. 3 is the floor: at 2,
 *                 a single campaign hitting two co-hosted neighbours (which lead-coip harvesting
 *                 makes routine) is enough to enshrine a host, and one bad entry then fires on
 *                 every site that shares it.
 */
export function buildSpamHosts(findings, minVictims = 3) {
  const victims = new Map(); // host -> Set(victim registrable)
  for (const f of findings || []) {
    if (!f) continue;
    const victim = regOf(String(f.domain || "").toLowerCase().replace(/^www\./, ""));
    if (!victim) continue;
    let ev = f.evidence;
    if (typeof ev === "string") { try { ev = JSON.parse(ev); } catch (e) { ev = null; } }
    const blobs = [];
    if (Array.isArray(ev)) for (const e of ev) { if (e) blobs.push(String(e.url || ""), String(e.match || "")); }
    if (f.proof_url) blobs.push(String(f.proof_url));
    if (f.proof) blobs.push(String(f.proof));
    for (const blob of blobs) {
      if (!blob) continue;
      for (const m of blob.matchAll(/https?:\/\/([^/:?#\s"'<>]{4,255})/gi)) {
        const full = m[1].toLowerCase().replace(/:\d+$/, "").replace(/^www\./, "");
        const h = regOf(full);
        // Exclusions in order of how badly they burn: the victim itself (its own proof URLs are in
        // every row), shared infrastructure, then per-customer-subdomain platforms whose registrable
        // identifies nobody.
        if (!h || h === victim || h.endsWith("." + victim) || SAFE_HOST.test(h + ".") || sharedSuffix(h)) continue;
        if (!victims.has(h)) victims.set(h, new Set());
        victims.get(h).add(victim);
      }
    }
  }
  const out = [];
  for (const [h, vs] of victims) if (vs.size >= minVictims) out.push({ host: h, victims: vs.size });
  out.sort((a, b) => b.victims - a.victims);
  return out;
}

// ---------------------------------------------------------------------------
// run
// ---------------------------------------------------------------------------
export async function run(ctx) {
  const out = [];
  try {
    const reg = ctx.reg;
    const base = ctx.base || ("https://" + reg);
    const hostOf = ctx.hostOf;
    const sameHost = ctx.sameHost;
    const S = ctx.S;
    if (!reg || !hostOf || !sameHost || !S) return out;
    // CONTRACT rule 3. This module issues zero fetches, but it is not free: it is pure regex CPU over
    // up to 400KB, and CPU is exactly what the 1102 wall measures. A domain that has already blown its
    // deadline gets nothing from us.
    if (typeof ctx.overBudget === "function" && ctx.overBudget()) return out;

    // The browser document plus the tail. The tail matters more than the head here: footer link
    // injection lands in the LAST few KB and the 96KB head cap throws it away (scan.js:56).
    let html = (ctx.B && ctx.B.text) || "";
    if (ctx.tail && !html.endsWith(ctx.tail)) html += "\n" + ctx.tail;
    if (html.length > MAX_BYTES) html = html.slice(0, MAX_BYTES);
    if (html.length < 40) return out;

    const spamHosts = ctx.spamHosts instanceof Set ? ctx.spamHosts : null;
    const urlhaus = ctx.urlhausHosts instanceof Set ? ctx.urlhausHosts : (_uh.set || null);

    // ---- collect off-domain registrables -------------------------------------------------
    const hrefs = harvest(new RegExp(SRC_HREF, "gi"), html, MAX_LINKS);
    const resources = harvest(new RegExp(SRC_RES, "gi"), html, 300);

    const linkCount = new Map();  // registrable -> how many <a> point at it
    const sampleUrl = new Map();  // registrable -> one verbatim URL, for the proof string
    const resHosts = new Map();   // registrable -> one verbatim resource URL
    const fullHosts = new Map();  // FULL host -> one verbatim resource URL (URLhaus matches on this)

    for (const u of hrefs) {
      const h = hostOf(u);
      if (!h || sameHost(h, reg)) continue;
      const r = regOf(h);
      if (!r || r === regOf(reg) || SAFE_HOST.test(r + ".")) continue;
      linkCount.set(r, (linkCount.get(r) || 0) + 1);
      if (!sampleUrl.has(r)) sampleUrl.set(r, u.slice(0, 120));
    }
    for (const u of resources) {
      const h = hostOf(u);
      if (!h || sameHost(h, reg)) continue;
      const r = regOf(h);
      if (!r || r === regOf(reg) || SAFE_HOST.test(r + ".")) continue;
      if (!resHosts.has(r)) resHosts.set(r, u.slice(0, 120));
      const fh = h.replace(/^www\./, "");
      if (!fullHosts.has(fh)) fullHosts.set(fh, u.slice(0, 120));
    }

    // ---- P33 · L46URLHAUS ----------------------------------------------------------------
    // Loaded resources ONLY. A page that merely *links* to a URLhaus host (a forum quoting a bad
    // URL, a security blog) is not distributing malware; a page that <script src>s one is. That
    // distinction is the whole reason SRC_RES is separate from SRC_HREF.
    //
    // BUCKET (2026-07-20 review): "malware-js", NOT a private "threat-intel" bucket. scan.js:409
    // already reads these exact bytes — `<iframe|script src="…casino|slot|judi|togel|xbet…">` — and
    // emits L8IFRAME into "malware-js". A spam loader that is both keyword-shaped and blocklisted
    // therefore scored TWICE, in two buckets, off ONE script tag: LR 85 × LR 237 pushed the posterior
    // to 0.999 with nbuckets=2, which is the exact CONFIRM condition. CONTRACT.md is explicit — "two
    // layers that read the same bytes MUST share a bucket or the posterior double-counts". Nothing is
    // lost: when L46 fires alone it is still the strongest signal in the bucket and still the lead
    // proof, and scan.js's malwareDeface gate keys on the LAYER id, not the bucket.
    const uhHit = [];
    if (urlhaus && urlhaus.size) {
      for (const [fh, u] of fullHosts) {
        if (urlhausKeys(fh, u).some((k) => urlhaus.has(k))) uhHit.push(fh + " <- " + u);
      }
    }
    if (uhHit.length) {
      out.push({ bucket: "malware-js", layer: "L46URLHAUS", match: "urlhaus:" + uhHit.slice(0, 2).join(" ; "), url: base + "/" });
    }

    // ---- P32 · L45KNOWNHOST --------------------------------------------------------------
    // Split by WHERE the host was seen, because the two sources are different bytes read by different
    // existing layers. A blocklisted host in an <a href> is link-neighbourhood evidence (same bytes as
    // L27/L28). A blocklisted host in a <script src> is the same tag L8IFRAME reads, so it belongs in
    // "malware-js" for exactly the reason spelled out above L46.
    const knownLink = [];
    const knownRes = [];
    if (spamHosts && spamHosts.size) {
      for (const r of linkCount.keys()) if (!sharedSuffix(r) && spamHosts.has(r)) knownLink.push(r);
      for (const r of resHosts.keys()) if (!sharedSuffix(r) && spamHosts.has(r)) knownRes.push(r);
    }
    // A host already proven by URLhaus is the SAME observation; re-emitting it under the
    // self-learned layer would be double-counting one embedded script.
    const provenByUh = (r) => uhHit.some((x) => x.endsWith(r) || x.includes(r + " <-"));
    const linkOnly = knownLink.filter((r) => !provenByUh(r));
    const resOnly = knownRes.filter((r) => !provenByUh(r) && !linkOnly.includes(r));
    if (linkOnly.length) {
      const proof = linkOnly.slice(0, 3).map((r) => sampleUrl.get(r) || r).join(" ; ");
      out.push({ bucket: "link-neighbourhood", layer: "L45KNOWNHOST", match: "known-campaign-host: " + proof, url: base + "/" });
    } else if (resOnly.length) {
      const proof = resOnly.slice(0, 3).map((r) => resHosts.get(r) || r).join(" ; ");
      out.push({ bucket: "malware-js", layer: "L45KNOWNHOST", match: "known-campaign-host: " + proof, url: base + "/" });
    }

    // ---- P11 · L27OUTLINK ----------------------------------------------------------------
    const spamRegs = [];
    const junkRegs = [];
    for (const r of linkCount.keys()) {
      if (S.RE.SPAMMY_DOMAIN.test(r) || S.RE.SPAMMY_TLD.test(r)) spamRegs.push(r);
      else if (S.RE.JUNKTLD.test(r + "/")) junkRegs.push(r);   // JUNKTLD needs a terminator after the TLD
    }
    const spamLinks = spamRegs.reduce((a, r) => a + (linkCount.get(r) || 0), 0);

    // Thresholds. Each of the three arms is a different way for the same claim — "someone appended a
    // link farm to this page" — to be true, and each is calibrated separately:
    //   >=2 distinct spam brands : one incidental link to a betting site (a news article, a "sites we
    //     block" list) must never fire, so a single brand is never enough on distinctness alone.
    //   1 brand but >=3 links    : editorial mentions are singular; a template/footer injection
    //     repeats the same target across the page.
    //   >=3 distinct junk TLDs   : .top/.xyz/.icu/.cyou/.ru are cheap-registration or bulk-spam TLDs.
    //     Legit BD sites do occasionally link to ONE (a .xyz startup, a .ru supplier). Three distinct
    //     ones on one page is link-farm shape — it caught avijatri.com.bd and riziqbd.com, both real
    //     injected Russian link farms, at 0 cost on the clean control.
    const spamArm = spamRegs.length >= 2 || (spamRegs.length === 1 && spamLinks >= 3);
    const junkArm = junkRegs.length >= 3;
    if (spamArm || junkArm) {
      const show = (spamArm ? spamRegs : junkRegs).slice(0, 4);
      const proof = show.map((r) => sampleUrl.get(r) || r).join(" ; ");
      out.push({
        bucket: "link-neighbourhood",
        layer: "L27OUTLINK",
        match: (spamArm ? `outbound spam links (${spamRegs.length} host/${spamLinks} links): ` : `outbound junk-TLD links (${junkRegs.length} hosts): `) + proof,
        url: base + "/",
      });
    }

    // ---- P12 · L28ANCHOR -----------------------------------------------------------------
    // These words DO survive stripHtml today, but they land in the saturated `homepage-content`
    // bucket where L1KW_STRONG already sits, so they contribute exactly zero confirmation power.
    // Read from the anchor structure, they are a distinct observation and get their own bucket.
    // NEWS GUARD. S.ALL_STRONG matches `casin[oò]` and `\bporn\b` with no bounding, so three distinct
    // headlines about a casino raid or a porn ban fire this layer on a clean newspaper — and a BD paper
    // is a `.com.bd` with Bengali text, so scan.js's bdSignal marks it as having identity, the
    // genuine-spam drop does not apply, and it lands in the lead list as a CONFIRMED hack. vocab.js
    // already concedes this hazard for its own generic-casino arm (`biz === "news" ? null : …`).
    // The discriminator is the TARGET, not the word: a newspaper's casino headlines link to its own
    // article pages, whereas an injected anchor farm exists to pass link equity OFF the domain. So on
    // news sites only, a spam anchor must also point off-domain to count. Injected doorway anchors that
    // stay on-domain are still caught on news sites by vocab.js L54SLUGSPAM reading the same URLs.
    let isNews = false;
    try {
      if (S.bizType) {
        const ttl = (/<title[^>]{0,200}>([\s\S]{0,300}?)<\/title>/i.exec(html) || [, ""])[1];
        isNews = S.bizType(reg, ttl, ctx.visB || "") === "news";
      }
    } catch (e) { isNews = false; }

    const anchorTexts = new Set();
    const RX_ANCHOR = new RegExp(SRC_ANCHOR, "gi");
    let am, an = 0;
    while ((am = RX_ANCHOR.exec(html)) && an++ < MAX_ANCHORS) {
      const raw = am[2];
      if (!raw || raw.length < 3) continue;
      const t = ctx.stripHtml ? ctx.stripHtml(raw) : raw.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();
      if (!t || t.length < 3 || t.length > 90) continue;
      if (!S.ALL_STRONG.test(t)) continue;
      if (isNews) {
        const href = (/\bhref\s*=\s*["']([^"'\s>]{1,300})/i.exec(am[1]) || [, ""])[1];
        if (!/^https?:\/\//i.test(href)) continue;              // relative → the paper's own article
        const ah = hostOf(href);
        if (!ah || sameHost(ah, reg) || regOf(ah) === regOf(reg)) continue;
      }
      anchorTexts.add(t.toLowerCase());
    }
    // >=3 DISTINCT texts. One or two is an editorial mention; a link farm always ships a keyword
    // list. Distinctness (not count) is the guard — 40 identical "Play Now" anchors score 1.
    if (anchorTexts.size >= 3) {
      out.push({
        bucket: "link-neighbourhood",
        layer: "L28ANCHOR",
        match: `spam anchor text x${anchorTexts.size}: ` + [...anchorTexts].slice(0, 5).join(" | "),
        url: base + "/",
      });
    }
  } catch (e) {
    return out; // CONTRACT rule 1 — degrade to whatever we already had, never throw
  }
  return out;
}
