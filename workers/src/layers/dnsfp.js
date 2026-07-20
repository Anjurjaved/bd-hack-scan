// dnsfp.js — DNS probes (P30) and cross-scan fingerprint diffing (P31).
//
// Two techniques that share nothing with the byte-level detectors, and that is the point: both of
// them see things that are invisible in a single HTTP response.
//
//   P30  A spam subdomain (slot.school.edu.bd) is a DNS record. It does not appear anywhere in the
//        homepage HTML, so no amount of reading the homepage will ever find it. Creating one takes
//        cPanel/DNS-panel access, which means the compromise is at the hosting-account level — the
//        most expensive kind, and the easiest to sell a cleanup for.
//
//   P31  A site that today serves a script from a host it did not serve one from last month has
//        changed in exactly the way an injection changes a site. That fact is not in today's bytes;
//        it is in the difference between today's bytes and last month's.
//
// THE ONE FAILURE MODE THAT MATTERS FOR P30 — wildcard DNS.
// Shared BD hosting (cPanel, and most of the local providers) very commonly publishes `*.domain.com`.
// On such a zone EVERY label resolves, so a naive "does slot.<reg> resolve?" test fires on every
// single customer of that host. That is not a rare edge case, it is the majority of the corpus. The
// nonce control is therefore not a nicety bolted on to the probe — it IS the probe. We ask for two
// labels that cannot possibly have been created on purpose; if either answers, the zone is a wildcard
// and this module says nothing at all about that domain, forever.
//
// A subtler variant of the same trap: if the CONTROL query merely *fails* (timeout, resolver hiccup,
// SERVFAIL) we do not know whether there is a wildcard or not. Treating a failed control as "no
// wildcard" would turn every network blip on a wildcard host into a false positive. So the control
// must come back as a DEFINITE negative — NXDOMAIN, or NOERROR with an empty answer — before any
// spam label is allowed to speak. Silence from the resolver buys silence from this layer.

import * as S from "../signatures.js";

export const TIER = "t1";

// Bayesian [P(fires | hacked), P(fires | clean)].
//
// MEASURED (see the report accompanying this module):
//   L42SUBDOM       0 fires / 1,100 clean-side domains (400 clean-BD control + 700 general corpus).
//                   0 fires / 172 non-wildcard confirmed-hacked domains.
//   L43NEWHOST      0 scoring fires / 171 clean BD sites re-fetched; 0 / 260 confirmed hacked.
//   L44TITLECHANGE  0 / 171 clean; fired on the confirmed-hacked sites whose homepage title had
//                   actually been replaced with spam.
//
// Every clean-side number below is therefore a deliberate pessimism rather than the observed rate:
// 0/1,100 only bounds the true FP rate at roughly 0.3%, and the contract says to declare the
// pessimistic figure. The hacked-side numbers are honest too, and they are low: 0/172 for L42SUBDOM
// says most BD injections never touch DNS, and 0/260 for L43NEWHOST is measured against a SYNTHETIC
// baseline (see the recall note in diffFingerprint) which can only prove the mechanism fires, not
// what it will catch once real month-old baselines exist. These are priced as rare-but-decisive
// signals, not broad ones.
//
// L43NEWHOST is deliberately cheap for what it looks like. A newly-appeared off-domain script host
// reads as near-proof, and on its own merits it nearly is — but the same script tag is also read by
// the current-state script/iframe layers, so a large weight here would let one injected <script>
// contribute twice to the posterior through two different buckets. The modest ratio (18) pays for
// that overlap: its real job is to ADD A BUCKET (which is what promotes a domain into the deep tier
// and what the 2-bucket confirmation rule needs), not to carry a confirmation by itself.
//
// L44TITLECHANGE sits in the EXISTING homepage-content bucket for the same reason, spelled out at
// the emit site: the keyword that makes it interesting is the same keyword L1KW_STRONG already read.
//
// L44TITLECHANGE was declared [0.90, 0.010] (ratio 90) and that was over-confident, for a reason the
// stability test cannot see: it re-fetched each site MINUTES apart, and the real baseline is a MONTH
// old. Over a month a Bangladeshi NEWS site rewrites its <title> continuously — the homepage title IS
// the top headline — and ALL_STRONG contains `casin[oò]` unbounded, `\bporn\b`, `1xbet`, `\bjudi\b`.
// Bangladesh ran a national anti-casino drive that was front-page news for months; "Casino scandal:
// verdict today" is a clean headline that changes the title AND matches ALL_STRONG. Same for an
// e-commerce homepage whose title rotates with the campaign of the week. Priced at 1 in 100 that is a
// lie; 1 in 33 is the honest pessimistic figure for a corpus that is a few percent news/media.
// It also matters that this layer SHARES the homepage-content bucket with L1KW_STRONG (ratio 26.7):
// at ratio 90 it did not merely win the bucket, it multiplied the posterior 3.4x over the well
// calibrated layer reading the very same keyword. Ratio 30 still lets the stronger reading win —
// which is the point — without that jump.
export const WEIGHTS = {
  L42SUBDOM:      [0.88, 0.005],
  L43NEWHOST:     [0.72, 0.040],
  L44TITLECHANGE: [0.90, 0.030],
  // control-bucket diagnostics — never scored, declared only because the contract requires an entry
  L42WILDCARD:    [0.50, 0.500],
  L43NEWHOSTW:    [0.40, 0.200],
  L43NEWLINK:     [0.45, 0.150],
  L44SMAPJUMP:    [0.45, 0.150],
  L44FPSTATE:     [0.50, 0.500],
};

// L42SUBDOM is intentionally ABSENT from CATS. `slot.`/`togel.`/`judi.`/`casino.` are gambling by
// construction, and letting the keyword-derived category win routes the finding through scan.js's
// gambling path — which is where the domainSpammy brand gate and the AI adjudication live. A spam
// subdomain on a genuine casino brand must still be dropped, and only that path drops it.
// L44TITLECHANGE is absent for the same reason: the new title carries its own category.
export const CATS = {
  L43NEWHOST: "malware",
};

export const FP_VERSION = 1;

// ---------------------------------------------------------------------------
// P30 — spam subdomain probe
// ---------------------------------------------------------------------------

// Two fixed controls, not one. A fixed label is deliberate: it is cacheable at the resolver, so
// across a 300k sweep most of these cost nothing. Two of them because a single control query that
// happens to fail is the entire false-positive surface of this layer, and requiring two independent
// definite negatives makes that surface vanishingly small. They are hyphenated nonsense so that no
// plausible hand-configured record could ever collide with them.
const CONTROL_LABELS = ["zq7x9k4v2m-ctl", "nx8w3f1p7t-ctl"];

// Labels a Bangladeshi business would not create.
//
// REJECTED here, and the reasoning is the same one that keeps `choti` out of SPAMMY_DOMAIN:
//   `bet`    → bet.<reg> is short enough to be an initialism for anything; also "beta".
//   `game`   → a real BD gaming/e-sports vendor subdomain.
//   `link`   → link.<reg> is a completely ordinary shortener/redirector subdomain.
//   `xxx`    → same XXXL garment trap that the domain list already documents.
// `slot` was the one genuinely arguable member of the list: an appointment-booking system could
// plausibly live at slot.<hospital>.com.bd. It survived because it measured 0 hits across the clean
// BD control, and because the nonce control means a hit is always a DELIBERATELY created record —
// but it is the first thing to remove if this layer ever produces a complaint.
export const SPAM_LABELS = ["slot", "togel", "judi", "casino"];

// Raw DoH so we can read Status. ctx.doh() returns answers only, and "no answers" from a failed
// query is indistinguishable from "no answers because NXDOMAIN" — which is exactly the distinction
// the control depends on, so this module resolves for itself.
async function dohQuery(name, ms = 4500) {
  try {
    const r = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=A`,
      { headers: { accept: "application/dns-json" }, signal: AbortSignal.timeout(ms) }
    );
    if (!r.ok) return { ok: false };
    const j = await r.json();
    const ans = Array.isArray(j.Answer) ? j.Answer : [];
    // type 1 = A, type 5 = CNAME. A CNAME with no A behind it still means somebody created a record
    // on purpose, which is all this layer claims.
    const rec = ans.filter((a) => a && (a.type === 1 || a.type === 5));
    return { ok: true, status: j.Status, exists: rec.length > 0, data: rec.length ? String(rec[0].data) : "" };
  } catch (e) {
    return { ok: false };
  }
}
// A definite "this label does not exist": NXDOMAIN, or NOERROR carrying no A/CNAME.
const definiteAbsent = (q) => q.ok && (q.status === 3 || (q.status === 0 && !q.exists));

async function subdomainProbe(ctx) {
  const out = [];
  const reg = String(ctx.reg || "").replace(/^www\./, "");
  if (!reg || reg.split(".").length < 2) return out;

  // Controls and probes go out together. On a wildcard zone the probe queries are wasted, but a
  // wildcard is the minority case and serialising would add a full RTT to every domain in a 300k
  // sweep — latency is the scarce resource here, not DNS queries.
  const names = [...CONTROL_LABELS.map((l) => `${l}.${reg}`), ...SPAM_LABELS.map((l) => `${l}.${reg}`)];
  const res = await Promise.all(names.map((n) => dohQuery(n)));
  const ctlA = res[0], ctlB = res[1];

  // A wildcard zone is exempted OUTRIGHT. This is worth spelling out because the obvious
  // improvement is a trap I built, measured, and threw away:
  //
  //   "A wildcard answers every label with the same address, so if slot.<reg> answers with a
  //    DIFFERENT address than the control, somebody created that record deliberately."
  //
  // It fires. On 600 confirmed-hacked domains it produced 23 hits, one of them a .edu.bd school —
  // exactly the lead this project wants most. Every single one was wrong. Re-probing those domains
  // with EIGHT distinct nonce labels showed the wildcards answer from a rotating pool of 2-3
  // addresses, so any two labels disagree roughly half the time by pure chance; requiring the two
  // controls to agree filters nothing, because they are different names and each gets its own
  // rotation. On ramjibonpurihs.edu.bd the "different address" was Cloudflare's own anycast pair
  // returned in a different ORDER. 23/23 false, including the one lead that looked most valuable —
  // which is precisely why the differential is not in this file. Wildcard means silence.
  if (ctlA.exists || ctlB.exists) {
    out.push({ bucket: "control", layer: "L42WILDCARD", match: `wildcard DNS on ${reg} — subdomain probe cannot speak here`, url: "" });
    return out;
  }
  if (!definiteAbsent(ctlA) || !definiteAbsent(ctlB)) return out;   // no clean negative from the resolver → say nothing

  for (let i = 0; i < SPAM_LABELS.length; i++) {
    const q = res[CONTROL_LABELS.length + i];
    if (!q.ok || !q.exists) continue;
    const host = `${SPAM_LABELS[i]}.${reg}`;
    out.push({
      bucket: "subdomain",
      layer: "L42SUBDOM",
      // The leading words are load-bearing, not decoration. scan.js's category() resolves a finding by
      // running S.categoryOf() over the match text, and ONLY a gambling/adult/foreign_lang category is
      // routed through the domainSpammy brand gate and the AI adjudication; every other category is
      // pushed straight to `confirmed` with no AI at all (scan.js:804-807). Three of the four labels
      // self-identify — "judi"/"togel" hit GAMB_STRONG and "casino" hits GAMB_WEAK — but `slot.` alone
      // matches NOTHING in categoryOf (GAMB_STRONG carries only `slot online`/`slot88`/`slot gacor`,
      // GAMB_WEAK only `\bslots\b`). So a `slot.` hit sitting beside any layer carrying a malware or
      // redirect category inherited THAT category and walked past the AI gate — the same door the
      // 2026-07-19 porn false-positive fix closed for the other layers. `gambling subdomain` is both
      // literally true of all four labels and matched by GAMB_WEAK, which pins the routing.
      match: `gambling subdomain: DNS record ${host} -> ${q.data.slice(0, 40)} (${CONTROL_LABELS[0]}.${reg} = NXDOMAIN, so not a wildcard zone)`.slice(0, 200),
      url: "https://" + host,
    });
    break;   // one is proof; the rest of the labels add nothing but noise to the owner-facing evidence
  }
  return out;
}

// ---------------------------------------------------------------------------
// P31 — per-scan fingerprint
// ---------------------------------------------------------------------------
//
// STORAGE SHAPE (one TEXT column, `fp`, on `domains`; JSON, typically 180-450 bytes):
//
//   {"v":1,"b":"https://x.com","t":"1k2j3h","tt":"Site title…","k":0,"f":3,
//    "s":["cdn.foo.com"],"o":["facebook.com","daraz.com.bd"],"x":["evil.xyz"],"xb":[],"n":142,"ts":1753000000}
//
//   v   schema version — a bump must invalidate every stored baseline, because a fingerprint written
//       by a different extractor is not comparable and a bogus diff is a false positive
//   b   base origin the fingerprint was taken from (so diffFingerprint is self-contained for `url`)
//   t   FNV-1a of the normalised full title — the cheap equality test
//   tt  first 80 chars of that title — kept because the contract demands QUOTABLE proof and a hash
//       cannot be shown to a business owner
//   k   1 if the current title matches ALL_STRONG
//   f   which documents contributed: bit 1 = browser body, bit 2 = googlebot body. Two fingerprints
//       with different f are NOT comparable; see the note at the flag's assignment.
//   s   off-domain SCRIPT-src hosts, registrable, sorted, ≤16
//   o   other off-domain outbound hosts (link/iframe/a), registrable, sorted, ≤16
//   x   subset of s+o that is spam-suspicious ON ITS OWN EVIDENCE (junk TLD, non-vendor) — scoring
//   xb  subset of s+o suspicious only because ctx.spamHosts says so — promoter, never scored
//   n   sitemap URL count, -1 when unknown
//   ts  unix seconds
//
// x and xb are precomputed at scan time so diffFingerprint stays a pure function of two stored rows:
// whatever reads these back out of D1 has no ctx.spamHosts and should not need one.
//
// Hosts are stored REGISTRABLE, not verbatim. This is the difference between a fingerprint that is
// stable and one that is useless: a1.wp.com / a2.wp.com, cdn3.example.net / cdn7.example.net and
// every other round-robin asset host rotate between two fetches of the SAME page, and a fingerprint
// that churns on its own produces a stream of "new host!" signals about nothing. Measured on 120
// clean BD sites fetched twice: 5.0% of sites churned at least one full hostname between the two
// fetches, 0.0% churned a registrable.
//
// FIRST-PASS RULE (non-negotiable, enforced by the caller): a domain with no stored fingerprint must
// have one WRITTEN and must not be diffed. Every row starts with an empty baseline, so a rollout that
// diffs against "nothing" would report the entire corpus as newly-hosting-everything on day one.

const RX_GUARD = 200;
const HOST_CAP = 16;
// scan.js persists the fingerprint with `String(f.fp).slice(0, 1200)`. A fingerprint longer than that
// is stored as truncated JSON, JSON.parse fails on the next pass, and the layer is silently dead on
// that domain forever — and the domains that overflow are precisely the busy news/e-commerce sites
// this layer most wants to watch. Measured: 16 script + 16 outbound + 16 suspicious long registrable
// hosts serialises to 1,473 bytes. Kept under the column budget with room to spare.
const FP_BYTES = 1000;

// A DOCUMENT THAT IS NOT THE SITE MUST NEVER BECOME A BASELINE. This is the single largest
// false-positive surface in the module and it was open: scan.js runs the layer modules under
// `if (FULL && !overBudget())` with NO `answered` test (scan.js:532 — `answered` gates only ctx.deep),
// so a 403/503/WAF interstitial was fingerprinted and written to the `fp` column exactly like a real
// homepage. Those pages are not `empty()` either: they carry a <title> and their own script hosts.
//
// Live counter-example, straight out of clean-bd.txt: chhs.edu.bd — a real Bangladeshi school —
// answers the scanner's browser UA with HTTP 403 and the body "Vercel Security Checkpoint". Stored,
// that becomes the baseline {t:"Vercel Security Checkpoint", s:[]}. Next month the school answers
// normally, and every off-domain script it has ever loaded is "new since last scan". Its developer's
// CDN on a .xyz (JUNKTLD) is then a SCORING L43NEWHOST hit, category malware — which is a non-GA
// category, so it reaches scan.js:807 having seen neither the AI nor any keyword test, and confirms.
// Reproduced end to end: a Cloudflare "Just a moment..." baseline against the same school's real
// homepage emits exactly one signal, L43NEWHOST on a site that never changed.
//
// So: 2xx only, not an interstitial, and long enough to be a page. Anything else contributes nothing
// and clears its coverage bit, which makes the fingerprint uncomparable rather than wrong.
// S.RE.WAF catches Cloudflare/Sucuri/Incapsula/DDoS-Guard; the local list adds the interstitials that
// answer 200 and are therefore not caught by the status test alone.
const INTERSTITIAL = /Vercel Security Checkpoint|Attention Required!|Access denied|Request unsuccessful|Please enable (?:JS|JavaScript) and disable any ad ?blocker|One more step|Bot Verification|You are being rate limited/i;
function usableDoc(r) {
  try {
    if (!r || typeof r.text !== "string") return "";
    const t = r.text;
    if (t.length < 500) return "";                                  // a stub, a maintenance page, an error body
    const st = typeof r.status === "number" ? r.status : 0;
    if (st < 200 || st >= 300) return "";
    if (S.RE.WAF.test(t) || INTERSTITIAL.test(t)) return "";
    return t;
  } catch (e) { return ""; }
}

function h32(s) {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = (h + ((h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24))) >>> 0;
  }
  return h.toString(36);
}

function hostFrom(u) {
  if (!u) return "";
  let s = String(u).trim().toLowerCase();
  if (s.startsWith("//")) s = "https:" + s;
  if (!/^https?:\/\//.test(s)) return "";          // relative/data:/javascript: — not an outbound host
  s = s.slice(s.indexOf("//") + 2);
  s = s.replace(/[/?#].*$/, "").replace(/:.*$/, "").replace(/^www\./, "");
  return /^[a-z0-9.-]+\.[a-z]{2,}$/.test(s) ? s : "";
}
const regOf = (h) => { try { return S.registrableOf(h) || h; } catch (e) { return h; } };

// Hosts that are allowed to appear out of nowhere on a BD site without it meaning anything. A new
// developer wiring up Tag Manager, a new chat widget, a new payment gateway — all of these look
// exactly like an injection to a diff, and all of them happen constantly.
const KNOWN_VENDOR = new Set([
  "google.com", "googleapis.com", "gstatic.com", "google-analytics.com", "googletagmanager.com",
  "googlesyndication.com", "doubleclick.net", "googleadservices.com", "recaptcha.net", "youtube.com",
  "ytimg.com", "jquery.com", "cloudflare.com", "cloudflareinsights.com", "jsdelivr.net", "unpkg.com",
  "bootstrapcdn.com", "fontawesome.com", "typekit.net", "wp.com", "w.org", "gravatar.com",
  "facebook.com", "facebook.net", "fbcdn.net", "instagram.com", "twitter.com", "linkedin.com",
  "tawk.to", "crisp.chat", "hotjar.com", "clarity.ms", "zendesk.com", "intercom.io", "livechatinc.com",
  "smartsuppchat.com", "jivosite.com", "olark.com", "elfsight.com", "trustindex.io", "disqus.com",
  "addthis.com", "sharethis.com", "mailchimp.com", "hubspot.com", "sentry.io", "amazonaws.com",
  "azureedge.net", "akamaized.net", "akamai.net", "fastly.net", "bunny.net", "b-cdn.net",
  "stripe.com", "paypal.com", "bkash.com", "sslcommerz.com", "aamarpay.com", "shurjopay.com.bd",
  "onesignal.com", "pushengage.com", "statcounter.com", "histats.com", "vimeo.com", "adobe.com",
  "calendly.com", "typeform.com", "whatsapp.com", "wa.me", "tiktok.com", "cloudfront.net",
]);

// Suspicion is deliberately narrow. "Not a vendor I recognise" is NOT suspicious — half of BD web
// development runs on some local agency's own CDN. Only two things count: the self-learned blocklist
// (a host seen on ≥3 confirmed victims, so membership is already evidence) and a junk TLD.
//
// THE VENDOR ALLOWLIST IS CHECKED FIRST, AND THAT ORDERING IS THE WHOLE SAFETY PROPERTY.
// It is tempting to trust the blocklist over a static list — the blocklist is learned from real
// confirmed victims, after all. It is also wrong, and measurably so. Building that blocklist the
// documented way (every off-domain host seen on ≥3 confirmed-hacked sites) over 174 hacked domains
// produced 23 hosts, and the top entries were google.com, googletagmanager.com, googlesyndication.com,
// cloudflare.com, wp.com and jsdelivr.net. Of course they were: hacked sites are still WordPress
// sites, and every WordPress site on earth loads those. With the blocklist checked first, this layer
// happily reported "new off-domain script host: google.com" as evidence of compromise on 32 of 174
// hacked sites — and would have said the same about any clean site that installed Analytics.
// A learned blocklist can only ever ADD hosts; it must never be able to add a host that the
// allowlist has already vouched for.
//
// The two reasons are NOT equal, and only one of them is allowed to score — see diffFingerprint.
// A junk TLD is a property of the host itself that this module can check for itself. Blocklist
// membership is an assertion made by a table this module cannot audit, and the reconstruction above
// shows what an unaudited blocklist looks like in practice: after the allowlist fix it still
// contained adobedtm.com (Adobe's tag manager), samsung.com and googlecode.com, and still contained
// no actual spam infrastructure at all. So "blocklisted" is downgraded to a promoter. If the
// production spam_hosts table is cleaner than this reconstruction, that is a reason to raise the
// weight later on measured evidence — not a reason to assume it now.
function suspicious(regHost, spamHosts, fullHost) {
  if (KNOWN_VENDOR.has(regHost)) return "";
  if (S.RE.JUNKTLD.test(regHost)) return "junk-tld";
  if (spamHosts && (spamHosts.has(regHost) || (fullHost && spamHosts.has(fullHost)))) return "blocklisted";
  return "";
}

export function computeFingerprint(ctx) {
  const fp = { v: FP_VERSION, b: "", t: "", tt: "", k: 0, f: 0, s: [], o: [], x: [], xb: [], n: -1, ts: Math.floor(Date.now() / 1000) };
  try {
    const reg = String(ctx.reg || "").replace(/^www\./, "");
    const selfReg = regOf(reg);
    fp.b = String(ctx.base || (reg ? "https://" + reg : ""));
    const html = usableDoc(ctx.B);
    // The googlebot body is unioned in, and on this corpus that is not a refinement — it is most of
    // the layer. The dominant confirmed hack here is UA cloaking (L2UACLOAK is the single most common
    // layer in the 2,750 confirmed leads), and a cloaked site by definition shows the BROWSER a clean
    // page. Fingerprinting only ctx.B therefore watches the one response the attacker took care to
    // keep innocent. It costs nothing — scan.js has already fetched G — but it does mean the two
    // documents have to be tracked as a SET, which is what fp.f below exists for.
    const htmlG = usableDoc(ctx.G);
    const spamHosts = ctx.spamHosts instanceof Set ? ctx.spamHosts : null;

    let title = (/<title[^>]*>([\s\S]*?)<\/title>/i.exec(html) || [, ""])[1].replace(/\s+/g, " ").trim();
    if (!title) title = (/<title[^>]*>([\s\S]*?)<\/title>/i.exec(htmlG) || [, ""])[1].replace(/\s+/g, " ").trim();
    fp.t = h32(title.toLowerCase());
    fp.tt = title.slice(0, 80);
    try { fp.k = S.ALL_STRONG.test(title) ? 1 : 0; } catch (e) { fp.k = 0; }

    const scripts = new Set(), other = new Set(), susp = new Map();
    const take = (raw, into) => {
      const h = hostFrom(raw);
      if (!h) return;
      const r = regOf(h);
      if (!r || r === selfReg || r.endsWith("." + selfReg)) return;   // own organisation — not outbound
      into.add(r);
      const why = suspicious(r, spamHosts, h);
      if (why) susp.set(r, why);
    };

    let m, g;
    for (const doc of [html, htmlG]) {
      if (!doc) continue;
      g = 0;
      const scriptRx = /<script\b[^>]*\bsrc\s*=\s*["']?([^"'\s>]{4,300})/gi;
      while ((m = scriptRx.exec(doc)) && g++ < RX_GUARD) take(m[1], scripts);
      g = 0;
      const otherRx = /<(?:link|iframe|a)\b[^>]*\b(?:href|src)\s*=\s*["']?(https?:)?\/\/([^"'\s>]{4,300})/gi;
      while ((m = otherRx.exec(doc)) && g++ < RX_GUARD) take("//" + m[2], other);
    }

    fp.s = [...scripts].sort().slice(0, HOST_CAP);
    fp.o = [...other].filter((h) => !scripts.has(h)).sort().slice(0, HOST_CAP);
    const inFp = (h) => fp.s.includes(h) || fp.o.includes(h);
    fp.x = [...susp.keys()].filter((h) => inFp(h) && susp.get(h) === "junk-tld").sort().slice(0, HOST_CAP);
    fp.xb = [...susp.keys()].filter((h) => inFp(h) && susp.get(h) === "blocklisted").sort().slice(0, HOST_CAP);

    // Which documents actually contributed. Without this the layer invents changes: BD government and
    // university sites frequently serve the Googlebot UA a challenge, a 403 or nothing at all, and
    // that decision is not stable between two scans. A fingerprint taken from B+G is simply not
    // comparable to one taken from B alone — every host that only ever appears in the G document
    // looks "new" the first time G succeeds. Measured on 148 clean BD sites fetched twice, this one
    // flag is the difference between 4.1% host churn and the number recorded below.
    fp.f = (html ? 1 : 0) | (htmlG ? 2 : 0);

    const n = ctx.sitemapN;
    if (typeof n === "number" && n >= 0 && isFinite(n)) fp.n = Math.min(Math.round(n), 9999999);

    // Fit the storage column (see FP_BYTES). Shed the least load-bearing fields first: outbound link
    // hosts, then the promoter-only blocklist set, then script hosts — never the title or the flags,
    // because those are what make two fingerprints comparable at all. Bounded loop, no `while (true)`.
    for (let guard = 0; guard < 80 && JSON.stringify(fp).length > FP_BYTES; guard++) {
      if (fp.o.length) fp.o.pop();
      else if (fp.xb.length) fp.xb.pop();
      else if (fp.x.length > 4) fp.x.pop();
      else if (fp.s.length > 4) fp.s.pop();
      else break;
    }
    // x/xb are subsets of s+o by construction and must stay that way after the shed, or the next scan
    // diffs a host set against a suspicion set that mentions hosts the set no longer contains.
    const kept = new Set([...fp.s, ...fp.o]);
    fp.x = fp.x.filter((h) => kept.has(h));
    fp.xb = fp.xb.filter((h) => kept.has(h));
  } catch (e) { /* contract rule 1 */ }
  return fp;
}

export const serializeFingerprint = (fp) => { try { return JSON.stringify(fp); } catch (e) { return ""; } };

function asFp(x) {
  if (!x) return null;
  if (typeof x === "string") { try { x = JSON.parse(x); } catch (e) { return null; } }
  if (!x || typeof x !== "object" || x.v !== FP_VERSION) return null;   // wrong schema → not comparable
  return {
    b: String(x.b || ""), t: String(x.t || ""), tt: String(x.tt || ""), k: x.k ? 1 : 0,
    f: typeof x.f === "number" ? x.f : -1,
    s: Array.isArray(x.s) ? x.s : [], o: Array.isArray(x.o) ? x.o : [],
    x: Array.isArray(x.x) ? x.x : [], xb: Array.isArray(x.xb) ? x.xb : [],
    n: typeof x.n === "number" ? x.n : -1,
  };
}

// diffFingerprint(prev, now) -> signals
// Pure, no network, no ctx. Accepts either the object from computeFingerprint or the raw JSON string
// straight out of the D1 column. Returns [] whenever the comparison is not trustworthy — a missing
// baseline, a schema mismatch, a document-coverage mismatch, or a side that looks like a failed fetch.
//
// ON THE RECALL NUMBERS IN `WEIGHTS`: they are measured against a SYNTHETIC baseline, because no real
// ones exist yet — the corpus has 2,750 confirmed hacks but no record of what any of those sites
// looked like before they were hacked. The synthetic prev is the site as it is now with its
// suspicious hosts removed and an ordinary title, which proves the diff fires on the right shape of
// change but says nothing about how often that change will be there to see. The number that IS
// real, and the one that decides whether this layer is safe to ship, is the stability measurement:
// 171 clean BD sites fetched twice, diffed against themselves, 0 scoring signals. Anything this
// emits on a site that did not change is a false positive by construction, and that is the figure
// that was driven to zero — three separate times, after three separate bugs.
export function diffFingerprint(prev, now) {
  const out = [];
  try {
    const P = asFp(prev), N = asFp(now);
    if (!P || !N) return out;                                  // no baseline / not comparable → first pass writes only
    // A fetch that returned a stub (WAF page, 502 body, empty response) drops every host and clears
    // the title. Diffing against that manufactures a "site changed completely" event on a site that
    // did not change at all, so a fingerprint with nothing in it is never allowed to be either side
    // of a comparison.
    const empty = (f) => !f.t && !f.s.length && !f.o.length;
    if (empty(P) || empty(N)) return out;
    const url = N.b || P.b || "";

    // Host sets are only comparable when the SAME documents went into both. See fp.f.
    const comparable = P.f >= 0 && N.f >= 0 && P.f === N.f;
    if (comparable) {
      const prevS = new Set(P.s), prevAll = new Set([...P.s, ...P.o]);
      const newScripts = N.s.filter((h) => !prevS.has(h));
      const hard = new Set(N.x), soft = new Set(N.xb);
      // A baseline that recorded NO off-domain host of any kind is the shape of a document that was
      // not the site — a challenge page, an error body, a placeholder. usableDoc() now refuses most of
      // those before they are ever written, but rows written before that fix are already in D1, and a
      // second, cheaper guard costs one comparison: against such a baseline EVERY host the real site
      // loads reads as new, which is the whole false positive. Genuinely third-party-free sites exist
      // in Bangladesh and this does silence the layer on them — that is the correct trade, because on
      // exactly those sites the layer has never seen a single host and has nothing to compare.
      const usableBaseline = P.s.length > 0 || P.o.length > 0;

      // L43NEWHOST — the only scoring host signal, and it rests on a property of the host itself
      // (junk TLD, not a known vendor) rather than on any table this module cannot audit.
      const hot = usableBaseline ? newScripts.filter((h) => hard.has(h)) : [];
      if (hot.length) {
        out.push({
          bucket: "delta",
          layer: "L43NEWHOST",
          match: `new off-domain script host since last scan: ${hot.slice(0, 3).join(", ")}${P.s.length ? "" : " (site previously loaded NO off-domain scripts)"}`,
          url,
        });
      } else if (newScripts.length && usableBaseline) {
        // Everything else that is merely new — including blocklisted hosts. Control bucket: it must
        // never move the posterior, but a script host that was not there last month is exactly the
        // kind of change that should pull a domain into the deep tier for a proper look.
        const soft2 = newScripts.filter((h) => soft.has(h));
        out.push({
          bucket: "control",
          layer: "L43NEWHOSTW",
          match: `new script host(s)${soft2.length ? " [on spam-host list: " + soft2.slice(0, 3).join(", ") + "]" : ""}: ${newScripts.slice(0, 4).join(", ")}`,
          url,
        });
      }

      const newLinks = usableBaseline ? N.o.filter((h) => !prevAll.has(h) && (hard.has(h) || soft.has(h))) : [];
      if (newLinks.length) {
        out.push({ bucket: "control", layer: "L43NEWLINK", match: `new outbound host(s): ${newLinks.slice(0, 4).join(", ")}`, url });
      }
    }

    // L44TITLECHANGE — the title changed AND the new one carries a STRONG spam keyword.
    // Bucket "homepage-content" on purpose. That keyword is also sitting in visB, where L1KW_STRONG
    // reads it; giving this layer its own bucket would count one injected word twice. Sharing the
    // bucket lets the stronger reading of the SAME evidence win, which is what the fuser is for:
    // "the title now says this and last month it did not" strictly dominates "the title says this".
    // Both sides must have had a real browser document, or "the title changed" may only mean that
    // one scan fell back to the Googlebot copy of it.
    // `!P.k` is the claim this layer actually makes: the title did not say this before and now it does.
    // Without it the layer also fired when the PREVIOUS title was already spam — a site hacked before
    // the baseline was taken, whose attacker merely rotated the doorway keyword — where "it changed"
    // adds nothing to L1KW_STRONG already reading the same title, in the same bucket.
    if (N.k && !P.k && P.t !== N.t && (P.f & 1) && (N.f & 1)) {
      out.push({
        bucket: "homepage-content",
        layer: "L44TITLECHANGE",
        match: `title changed to: ${N.tt}${P.tt ? ` (was: ${P.tt.slice(0, 60)})` : ""}`,
        url,
      });
    }

    // Sitemap explosion. A doorway flood adds thousands of URLs overnight; a real site that migrates
    // its catalogue can too, which is why this is a control-only promoter and not a scoring layer.
    // Both thresholds are required: 10x catches the shape, +500 absolute stops a 20-page site that
    // grew to 210 from looking like an attack.
    if (P.n >= 0 && N.n >= 0 && N.n >= P.n * 10 && N.n - P.n >= 500) {
      out.push({ bucket: "control", layer: "L44SMAPJUMP", match: `sitemap URLs ${P.n} -> ${N.n}`, url });
    }
  } catch (e) { /* contract rule 1 */ }
  return out;
}

// ---------------------------------------------------------------------------

export async function run(ctx) {
  const out = [];

  try {
    // DoH, not a page fetch. It is not charged against ctx.budget.fetches (which meters reads of the
    // victim's own server, and these do not touch it) but it does respect the wall-clock deadline —
    // ~40ms of resolver latency is still 40ms we may not have. ctx.budget.doh is honoured if the
    // caller ever chooses to meter DNS separately.
    // Six parallel DoH queries are still six SUBREQUESTS. On the Oracle VM that is free, but
    // SCAN_PROFILE is an env var and nothing stops "full" being set on a Cloudflare shard, where the
    // per-invocation subrequest cap applies to every fetch() regardless of what it is for — and a
    // scanSlice that runs many domains per invocation would hit that wall and take the whole slice
    // down with it. So the probe also stands down when the caller has no fetch budget left, and it
    // pays one unit for the whole probe (it is one logical question, asked six ways).
    const dohLeft = !ctx.budget || typeof ctx.budget.doh !== "number" || ctx.budget.doh > 0;
    const fetchLeft = !ctx.budget || typeof ctx.budget.fetches !== "number" || ctx.budget.fetches > 0;
    if (!(ctx.overBudget && ctx.overBudget()) && dohLeft && fetchLeft) {
      if (ctx.budget && typeof ctx.budget.doh === "number") ctx.budget.doh -= CONTROL_LABELS.length + SPAM_LABELS.length;
      if (ctx.budget && typeof ctx.budget.fetches === "number") ctx.budget.fetches -= 1;
      out.push(...(await subdomainProbe(ctx)));
    }
  } catch (e) { /* contract rule 1 */ }

  try {
    const now = computeFingerprint(ctx);
    // Side channel for the caller: scan.js writes ctx.fpNow into the `fp` column. It is handed over
    // as an object rather than through a signal because the signal `match` field is truncated to
    // 200 chars upstream and a truncated fingerprint is a corrupt baseline, not a short one.
    //
    // ONLY a fingerprint taken from a real document is handed over. `now.f === 0` means neither fetch
    // survived usableDoc() — a WAF page, a 5xx, a stub — and publishing that would overwrite a good
    // month-old baseline with a record of the outage, destroying the only history this layer has. Left
    // UNSET rather than set to null so the caller writes nothing at all for this pass and the stored
    // row survives untouched; a caller that treats an absent fpNow as "" would wipe it just as surely.
    if (now.f !== 0) ctx.fpNow = now;
    out.push({
      bucket: "control",
      layer: "L44FPSTATE",
      match: `fp v${FP_VERSION}: ${now.s.length} script host(s), ${now.o.length} outbound, ${now.x.length} suspicious`,
      url: now.b,
    });
    if (ctx.prevFp) out.push(...diffFingerprint(ctx.prevFp, now));
  } catch (e) { /* contract rule 1 */ }

  return out;
}
