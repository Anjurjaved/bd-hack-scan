// content.js — P24/P25/P26/P27/P28/P29/P49: the page-content layers that read bytes stripHtml() throws away.
//
// scan.js matches keywords against `visB` = stripHtml(browser HTML). stripHtml deletes <script> bodies
// outright and collapses every tag to a space, so four whole regions of the document are invisible to the
// live keyword matcher: <meta content="…">, JSON-LD, the <html lang> attribute, and any structural property
// of the markup (anchor density, link targets). Everything in this file reads one of those.
//
// Zero extra fetches. Every layer here runs on bytes scan.js already holds (B / G / tail), so the module is
// free to run on all ~300k domains on the 946MB Oracle VM.
//
// BUCKETS. The fuser takes only the strongest signal per bucket, so bucket assignment IS the double-count
// guard.
//   homepage-content — L37TITLEONLY, L41DENSITY, L42WSTUFF   (bytes stripHtml() KEEPS, i.e. visB)
//   meta-injection   — L36META      (attribute/JSON-LD bytes stripHtml() THROWS AWAY, and only when the
//                                    token is absent from visB — see the gate at the emit site)
//   foreign-body     — L38LANGBODY, L39LANGMISMATCH, L40FLATIN  (the visible body's LANGUAGE, not its keywords)
//   doorway-shape    — L53SHAPE2   (markup structure, content-agnostic)
//
// The first three assignments are a CORRECTION of the original draft, which put L37/L41/L42 in private
// buckets ("meta-injection"/"stuffing") on the theory that they answer a different question about visB
// (HOW MUCH, not WHETHER) than scan.js's L1KW_STRONG. Measured over 2266 cached pages that theory is false:
//   L41DENSITY/L42WSTUFF  18/18 signals co-occurred with L1KW_STRONG
//   L37TITLEONLY           6/6   — and this one is a THEOREM, not a measurement: stripHtml() keeps <title>
//                                  text, so a title carrying a STRONG token is inside visB by construction,
//                                  which means L1KW_STRONG has already scored it.
//   L36META               30/30
// A private bucket therefore did not add evidence, it added a SECOND COUNT of one fact — and because the
// fuser confirms at `posterior >= 0.97 && nbuckets >= 2`, that second count is exactly the thing that turns
// an honest 1-bucket "review" into a CONFIRMED lead sold to a real business. Worked example: a BD site with
// "casino" x8 in its body scored 1 bucket / posterior 0.78 (review) before this module and 2 buckets /
// posterior 0.995 (CONFIRMED) after it, on identical bytes and zero new information.
// `meta-injection` survives as its own bucket ONLY because of the gate: it now fires only when the token is
// invisible to visB, which is the one case where it really is evidence scan.js does not already hold.

import * as SIG from "../signatures.js";

export const WEIGHTS = {
  // Measured on 271 live confirmed-hacked pages and 800 live scanned-clean BD pages (see the numbers on
  // each layer below). Every declared P(clean) is well above the observed rate: 800 clean samples with 0
  // hits only bound the true rate at ~1/267 at 95% confidence, so a declared 0.000 would be a lie that
  // silently manufactures leads.
  //
  // ⚠️ THE CLEAN CONTROL IS CIRCULAR FOR THE LEXICAL LAYERS, and every P(clean) below is set with that in
  // mind. `clean-bd.txt` is the list of domains the LIVE detector already marked clean — and the live
  // detector marks anything carrying a STRONG token as at least "review". So a clean BD site that merely
  // *mentions* casino/porn/betting cannot appear in the control by construction: re-measured here, 792 of
  // 793 control pages contain ZERO STRONG tokens. "0/800 clean" therefore measures the control's selection
  // rule, not this layer's false-positive rate, and cannot justify a floor near 0.010 for anything keyed on
  // STRONG vocabulary. The floor for those layers is 0.020.

  // ⚠️ NOW UNMEASURED, AND THAT IS THE HONEST STATE. Raw, it fired 30 times over 2266 cached pages and ALL
  // 30 were already carrying the token in visB — i.e. its entire measured record (6/271 hacked included) was
  // re-counting detections scan.js had already made, and nothing would have been missed had the layer not
  // existed. With the independence gate applied it fires 0 times on that corpus, so 0.85/0.020 is a prior
  // about an unobserved population, not a measurement. It is kept because it covers a genuine blind spot
  // (stripHtml() erases attributes, so meta/JSON-LD-only injection is invisible to every other layer) and
  // because the gate bounds its risk: the body must be entirely free of STRONG tokens before it can speak.
  // The population still at risk is a clean BD site whose og:description alone mentions a STRONG term — note
  // `casin[oò]` in signatures.js is UNBOUNDED, so ordinary English "casino" is a STRONG token, and a BD news
  // site running a casino-raid story is exactly that shape. Hence 0.020, not 0.010. Revisit with real
  // measurements before ever tightening it.
  L36META: [0.85, 0.020],
  // 1/271 hacked, 0/800 clean. The divergence itself is the anomaly. Shares `homepage-content` with
  // L1KW_STRONG because the <title> it reads is inside visB by construction — its ratio (42.5) is above
  // L1KW_STRONG's (26.7), so it correctly WINS that bucket rather than adding a second one.
  L37TITLEONLY: [0.85, 0.020],

  // 1/271 hacked, 0/800 clean under the BD-identity gate. A BD site whose body is 10%+ CJK/Cyrillic/Thai
  // is compromised with near-certainty — but the sample is thin (n=1), so 0.015 rather than 0.005.
  L38LANGBODY: [0.85, 0.015],
  // 2/271 hacked, 0/800 clean. Same evidence family, same bucket, same weight.
  L39LANGMISMATCH: [0.85, 0.015],
  // 1/271 hacked + 1 more on a site mislabelled clean that turned out to be genuinely hacked
  // (course.cuet.ac.bd, below). 0/800 real clean. Softer than the script layers because the lexicon is
  // Latin text and therefore collidable — and three of the original ANCHOR phrases turned out to be
  // ordinary Indonesian (see FLATIN_ANCHOR) and have been demoted. 0.020.
  L40FLATIN: [0.82, 0.020],

  // 8/271 hacked, 0/800 real clean — subject to the circularity note above, so 0.020, not 0.015. Sanity
  // check on the number: L1KW_STRONG (the same vocabulary, threshold >=1 instead of >=8) declares 0.030, and
  // a page stuffed 8x is only modestly rarer among clean sites than a page that says it once.
  L41DENSITY: [0.85, 0.020],
  // The WEAK-vocabulary variant: 2/271 hacked, 0/800 clean, but "casino"/"escort"/"poker" at 3% of all
  // tokens is a shape a legitimate gaming or classifieds site could reach, so it is deliberately weak. It
  // shares `homepage-content` with L41DENSITY and with scan.js's L1KW_WEAK (ratio 4.6), which it reads the
  // same bytes as — it can never outrank the STRONG-token evidence, only sharpen the weak evidence.
  L42WSTUFF: [0.60, 0.080],

  // 1/271 hacked, 0/800 clean at the thresholds below — but a shape heuristic generalises far worse than a
  // measurement, so this is deliberately declared much weaker than measured. ratio 13 means one bucket of
  // L53SHAPE2 alone lands at posterior 0.64: enough to raise a review, never enough to confirm anything.
  L53SHAPE2: [0.65, 0.050],
};

// Only the two script-takeover layers need an explicit category. Every other layer here carries the actual
// spam token in its `match`, so scan.js's categoryOf() derives gambling/pharma/adult from the proof itself,
// which is more useful on the dashboard than anything this module could hard-code. L53SHAPE2 is left out
// too: it is content-agnostic by construction and has no category to claim.
export const CATS = { L38LANGBODY: "foreign_lang", L39LANGMISMATCH: "foreign_lang" };

export const TIER = "t1";

// ---------------------------------------------------------------------------
// CPU budgets. Worst case per domain is a 96KB document plus a 32KB tail; every
// loop below is bounded so a pathological page cannot stall the sweep.
// ---------------------------------------------------------------------------
const MAX_HTML = 200000;
const MAX_META = 120;
const MAX_LD_BLOCKS = 8;
const MAX_LD_CHARS = 24000;
const MAX_LD_VALUES = 80;
const MAX_ANCHORS = 800;
const MAX_TOKENS = 20000;

// ---------------------------------------------------------------------------
// P26/P27 — which scripts count as a TAKEOVER.
//
// This list is a whitelist-by-omission and the omissions are the whole point:
//   Bengali  (U+0980–U+09FF) — the site's OWN language. Never foreign. Not in the set.
//   Arabic   (U+0600–U+06FF) — normal and expected on madrasa, mosque and Islamic-finance sites, and on
//                              any BD site carrying Qur'anic text. Not in the set.
//   Latin    — English is the default second language of BD business sites. Not in the set.
//   Devanagari — deliberately excluded. Hindi spam exists (कैसीनो/सट्टा are already in GAMB_STRONG so the
//                lexical layers own it), but Devanagari also shows up on India-facing BD trade sites, and
//                a script-ratio test cannot tell those apart.
// What remains — Kana, Han, Hangul, Thai, Cyrillic — has no ordinary reason to occupy a tenth of a
// Bangladeshi business homepage. The set is byte-identical to signatures.js RE.FOREIGN on purpose: that
// regex is already the project's definition of "foreign script", it is just only ever applied to <title>.
const RE_TAKEOVER = /[぀-ヿ㐀-鿿Ѐ-ӿ฀-๿가-힣]/g;

// If the document DECLARES itself to be in one of the takeover languages, there is no takeover — it is a
// foreign site, doing foreign-site things. This suppression is not a nicety: without it the layer fires on
// konai.com (a Korean fintech), biojoycare.com (a Taiwanese health portal), hermiorihuela.com (a Chinese
// hardware trader) and ala-truck.com (a Ukrainian haulier) — all four are sitting in the confirmed table
// today, categorised foreign_lang by L10LANG, and all four are genuine foreign-language businesses.
const RE_LANG_FOREIGN = /^(zh|ja|ko|th|ru|uk|be|bg|sr|mk|kk|ky|mn|tg|el|yue|cmn)\b/i;
const RE_HTML_LANG = /<html[^>]*\blang\s*=\s*["']?([a-zA-Z][a-zA-Z0-9-]{0,9})/i;

// P26 thresholds. 10% density with at least 200 characters, OR 30% with at least 60 — the second arm
// exists because a fully replaced page is often SHORT (a 90-character Chinese landing stub replacing a real
// site is a total takeover but never reaches 200 characters). Measured 0/800 on the clean BD control; the
// worst clean page in that set was a 17-character error stub with 4 stray characters, which the absolute
// floors reject. Density, not raw count, is load-bearing: a raw-count rule fires on any BD site with a
// Chinese product datasheet pasted into a corner.
const P26_MIN_CHARS = 200;
const P26_MIN_RATIO = 0.10;
const P26_ALT_CHARS = 60;
const P26_ALT_RATIO = 0.30;
// P27 asks a stricter question of a weaker premise (a lang attribute can be stale theme boilerplate), so
// it wants a higher density before it will call the mismatch.
const P27_MIN_CHARS = 200;
const P27_MIN_RATIO = 0.15;

// ---------------------------------------------------------------------------
// P28 — Latin-script foreign spam.
//
// RE.FOREIGN is a Unicode-script test and is structurally blind to Indonesian, Vietnamese, Turkish and
// Portuguese spam: those are written in the same alphabet as English. But the individual words are ordinary
// vocabulary in their own languages — `terbaik` is just "best", `resmi` is just "official", `bermain` is
// just "playing" — so firing on them one at a time would be the Latin-script version of the choti trap.
//
// The binding rule, which mirrors banglachoti/chotigolpo in signatures.js: nothing fires without at least
// one ANCHOR phrase, and an anchor phrase is one that has NO non-gambling reading in any language. Generic
// vocabulary can only ever corroborate an anchor, never trigger on its own.
//
// Bounded, not bare — corpus.txt proves why. A bare `resmi` matches coresmith.net; a bare `cassino` matches
// industrialservicecassino.it, because Cassino is an Italian town. Every entry below is either a multi-word
// phrase or \b-bounded, and both of those hits die on the boundary.
//
// DEMOTED FROM ANCHOR TO GENERIC (this is the whole rule being applied to itself). The draft listed
// `situs resmi`, `daftar sekarang`, `deposit dana`, `akun pro`, `situs thailand` and `palpites` as anchors,
// i.e. as phrases with "NO non-gambling reading in any language". They all have one:
//   situs resmi     = "official site"      — every Indonesian government portal and university says it
//   daftar sekarang = "register now"       — the standard Indonesian CTA button
//   deposit dana    = "deposit funds", and DANA is Indonesia's largest e-wallet, so any legitimate
//                     Indonesian shop that accepts it says this verbatim
//   akun pro        = "pro account"        — any Indonesian SaaS pricing page
//   situs thailand  = "Thailand site"      — an Indonesian travel agency
//   palpites        = "hunches / opinions" — ordinary Portuguese ("dar palpites")
// Dry-run: four hand-written, entirely innocuous Indonesian paragraphs (a district government portal, a
// university admissions page, an e-wallet shop, a sports club) ALL fired the layer on these anchors alone.
// Demoted, they still corroborate a real anchor; they can no longer trigger the layer by themselves. This is
// the same discipline signatures.js applies to `choti` and `chudi`.
const FLATIN_ANCHOR = [
  // Indonesian — slot/judi doorway boilerplate
  [/gampang menang/i, "gampang menang"],
  [/link alternatif/i, "link alternatif"],
  [/situs gacor/i, "situs gacor"],
  [/pola gacor/i, "pola gacor"],
  [/rtp gacor/i, "rtp gacor"],
  [/anti rungkad/i, "anti rungkad"],
  [/\bjam hoki\b/i, "jam hoki"],
  [/\bbo slot\b/i, "bo slot"],
  [/slot thailand/i, "slot thailand"],
  [/bocoran admin/i, "bocoran admin"],
  // Turkish
  [/bonus veren/i, "bonus veren"],
  [/giri[sş] adresi/i, "giriş adresi"],
  [/deneme bonusu/i, "deneme bonusu"],
  [/casino sitesi/i, "casino sitesi"],
  [/g[uü]venilir bahis/i, "güvenilir bahis"],
  // Vietnamese
  [/nh[aà] c[aá]i uy t[ií]n/i, "nhà cái uy tín"],
  [/c[aá] c[uư][oợ]c b[oó]ng [dđ][aá]/i, "cá cược bóng đá"],
  [/\bsoi k[eè]o\b/i, "soi kèo"],
  [/t[yỷ] l[eệ] k[eè]o/i, "tỷ lệ kèo"],
  // Portuguese / Spanish
  [/cassino online/i, "cassino online"],
  [/casas? de apostas/i, "casa de apostas"],
  [/apostas online/i, "apostas online"],
];
const FLATIN_GENERIC = [
  // the six demotions — corroboration only, never a trigger
  /situs resmi/i, /daftar sekarang/i, /deposit dana/i, /\bakun pro\b/i, /situs thailand/i, /\bpalpites\b/i,
  /\bterpercaya\b/i, /\bterbaik\b/i, /\bresmi\b/i, /\bbermain\b/i, /\bpemain\b/i, /\bpermainan\b/i,
  /\bgulungan\b/i, /\bputaran\b/i, /\bkemenangan\b/i, /\bkeuntungan\b/i, /\bmodal\b.{0,20}\bbermain\b/i,
  /\bg[uü]venilir\b/i, /\bho[sş] ?geldin\b/i, /\bkay[ií]t ol\b/i, /\b[cç]ekili[sş]\b/i,
  /\buy t[ií]n\b/i, /\b[dđ][aă]ng nh[aậ]p\b/i, /\b[dđ][aă]ng k[yý]\b/i, /\bmi[eễ]n ph[ií]\b/i, /\bkhuy[eế]n m[aã]i\b/i,
];
// One anchor is not enough on its own — three distinct phrases total means the page is written in the
// language, not merely mentioning it. Measured: 0 false positives over 800 clean BD pages.
const FLATIN_MIN_ANCHOR = 1;
const FLATIN_MIN_TOTAL = 3;

// ---------------------------------------------------------------------------
// P29 — stuffing density.
//
// The existing distinct() test at scan.js:34 is binary: it cannot separate "the word casino appears once in
// a news headline" from "the word casino appears 67 times". 8 is the STRONG threshold because the worst
// clean BD page in the 800-page control reached 0 — the only control page over the line was
// course.cuet.ac.bd (a real CUET student portal, `.ac.bd`) carrying 66 repetitions of "mahjong ways" and 12
// distinct STRONG tokens. That page is in the scanned-clean list and is in fact HACKED: a live Indonesian
// slot link-farm the current detector missed. It is a true positive, so the measured clean FP rate is 0/800.
const DENSITY_MIN = 8;
// The WEAK arm needs a corpus large enough for a percentage to mean anything, and 3% of every word on a
// page is a number no editorial copy reaches by accident.
const WSTUFF_MIN_TOKENS = 150;
const WSTUFF_MIN_COUNT = 10;
const WSTUFF_MIN_FRAC = 0.03;

// ---------------------------------------------------------------------------
// P49 — doorway page shape.
//
// Content-agnostic, so it is the only layer here that can catch a doorway written in a language no lexicon
// covers. It is also the only one with a real false-positive story, and the measurements say exactly where:
// at the proposal's thresholds (anchor-text ratio > 0.55, < 8 internal links, < 1500 chars) it fires on
// 20/800 clean BD pages — moodle.ulab.edu.bd, noticeboard.diu.edu.bd, ems.ccj.edu.bd, taxeszonedinajpur.gov.bd
// — the .edu.bd / .gov.bd portals that are the single most expensive thing in this system to accuse falsely.
//
// Two additions collapse that to 0/800 while keeping the one real hit:
//   1. A TEXT FLOOR. Half the raw hits were 44-character parked/placeholder pages, where a ratio over a
//      near-empty denominator is arithmetic, not evidence.
//   2. OFF-DOMAIN CONCENTRATION on one registrable. A login portal's links go to itself; a doorway's go
//      somewhere else, en masse. Note that an absolute self-link (https://own-host/path) MUST be counted as
//      internal — treating it as off-domain is what produced most of the original 20 false hits.
const P49_MIN_TEXT = 400;
const P49_MAX_TEXT = 1500;
const P49_MIN_ANCHORS = 12;
const P49_MIN_RATIO = 0.55;
const P49_MAX_INTERNAL = 8;
const P49_MIN_OFFDOMAIN = 8;
// An HTML sitemap, a tag index and a category archive are all legitimately shaped like a doorway.
const P49_URL_EXCLUDE = /\/(tag|tags|category|categories|archive|archives|sitemap[^/]*)(\/|$)/i;

// Which <meta> names carry human-readable copy worth keyword-matching. Deliberately excludes generator,
// viewport, robots, csrf-token and the rest — those are machine values and can only add noise.
const META_NAMES = /^(keywords|news_keywords|description|abstract|subject|og:title|og:description|og:site_name|twitter:title|twitter:description|dc\.title|dc\.description)$/i;
// JSON-LD keys worth reading. articleBody is deliberately NOT here: on a news site it is the entire article,
// which would make this layer a duplicate of the body keyword matcher — and would fire on a legitimate BD
// newspaper reporting a casino raid.
const LD_KEYS = /^(name|headline|alternateName|description|keywords|slogan|jobTitle|about)$/i;

const RE_TAGSTRIP = /<(script|style|noscript|template)\b[\s\S]*?<\/\1>/gi;
const RE_TAGS = /<[^>]+>/g;
const RE_WS = /\s+/g;
const RE_TITLE = /<title[^>]*>([\s\S]*?)<\/title>/i;

// Entities must be DECODED here, not blanked. scan.js's stripHtml() replaces `&#233;` with a space, which
// on a French page turns "spécialisée" into "sp cialis e" and hands \bcialis\b a clean word boundary on a
// silver platter — the same false positive as the accented-boundary artefact, arriving by a second route.
// bansard.com.bd serves exactly this: `sp&#233;cialis&#233;e` in its meta description. Decoding restores the
// é, and the accented guard below then does its job.
const NAMED = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " ", ndash: "–", mdash: "—", hellip: "…", rsquo: "’", lsquo: "‘", ldquo: "“", rdquo: "”" };
const RE_ENT_DEC = /&(#x[0-9a-f]{1,6}|#[0-9]{1,7}|[a-z][a-z0-9]{1,9});/gi;

function decodeEntities(s) {
  if (!s || s.indexOf("&") === -1) return s || "";
  return s.replace(RE_ENT_DEC, (all, body) => {
    try {
      if (body[0] === "#") {
        const cp = body[1] === "x" || body[1] === "X" ? parseInt(body.slice(2), 16) : parseInt(body.slice(1), 10);
        if (cp > 0 && cp <= 0x10ffff) return String.fromCodePoint(cp);
        return all;
      }
      const k = body.toLowerCase();
      return Object.prototype.hasOwnProperty.call(NAMED, k) ? NAMED[k] : all;
    } catch (e) { return all; }
  });
}

function strip(h) {
  if (!h) return "";
  return decodeEntities(h.replace(RE_TAGSTRIP, " ").replace(RE_TAGS, " ")).replace(RE_WS, " ").trim();
}

function countOf(s, rx) {
  const m = s.match(rx);
  return m ? m.length : 0;
}

// ---------------------------------------------------------------------------
// The accented-boundary artefact. This is a REAL false positive that was measured, not a hypothetical.
//
// JavaScript's \b is defined over [A-Za-z0-9_] only — it is not Unicode-aware. So in the French word
// "spécialisée" the é on either side of "cialis" counts as a NON-word character, both \b assertions in
// PHARMA_STRONG's \bcialis\b are satisfied, and the pattern matches inside an ordinary French adjective.
// Measured hits on real corpus pages: bansard.com.bd (Bansard Bangladesh, a genuine BD freight forwarder,
// meta description "SEKO est spécialisée dans les solutions globales…"), atgcomposite.com and
// installations-sportives.ch. The same trap is waiting in "especializada", "especialista", "specialisatie".
//
// The fix rejects a match only when it BUTTS UP AGAINST AN ACCENTED LATIN LETTER, which is the only way this
// artefact can arise. ASCII adjacency is deliberately left alone, because the signature library depends on
// it: `casin[oò]` is meant to match "casinos", `\bbahis\b` is meant to match "bahisleri".
//
// NOTE FOR WHOEVER OWNS signatures.js: this guard lives here because this module may only edit its own file,
// but the bug is in the shared library and L1KW_STRONG in scan.js has no protection from it at all.
// U+0300–U+036F (combining marks) is in the class for the DECOMPOSED (NFD) form of the same text: "spécialisée"
// normalised to NFD is s-p-e-U+0301-c-i-a-l-i-s-U+0301-e, where the character adjacent to "cialis" is a bare
// combining acute rather than "é". Without that range the guard passes NFD French straight through and the
// artefact returns by a third route.
const RE_ACCENTED = /[À-ɏḀ-ỿ̀-ͯ]/;

function boundaryArtefact(text, i, tok) {
  if (!tok) return true;
  if (/^[A-Za-z]/.test(tok) && i > 0 && RE_ACCENTED.test(text[i - 1])) return true;
  const after = text[i + tok.length];
  if (/[A-Za-z]$/.test(tok) && after && RE_ACCENTED.test(after)) return true;
  return false;
}

// First STRONG token in `text` that is not an accented-boundary artefact. Returns null when the only
// matches are artefacts — which is exactly what must happen on a French-language business page.
// ALL_STRONG is a ~3KB alternation and firstStrong() is called once per <meta>/JSON-LD value, i.e. up to
// MAX_META + MAX_LD_VALUES = 200 times per page. Compiling it 200 times per domain across ~300k domains is
// pure waste; one entry keyed on the source string is enough (the source never varies within a sweep).
let _rxCache = null;
let _rxCacheSrc = "";
function strongRx(src) {
  if (_rxCacheSrc !== src) { _rxCache = new RegExp(src, "gi"); _rxCacheSrc = src; }
  _rxCache.lastIndex = 0;
  return _rxCache;
}

function firstStrong(text, strongSrc) {
  const rx = strongRx(strongSrc);
  let m;
  let guard = 0;
  while ((m = rx.exec(text)) && guard++ < 200) {
    if (!boundaryArtefact(text, m.index, m[0])) return { tok: m[0], index: m.index };
    if (rx.lastIndex === m.index) rx.lastIndex++;
  }
  return null;
}

function quote(label, value) {
  return (label + ': "' + String(value).replace(RE_WS, " ").trim() + '"').slice(0, 200);
}

// ---- <head> extraction -----------------------------------------------------

function metaValues(html) {
  const out = [];
  const tags = html.match(/<meta\b[^>]*>/gi);
  if (!tags) return out;
  for (let i = 0; i < tags.length && i < MAX_META; i++) {
    const t = tags[i];
    const nm = (/\b(?:name|property|itemprop)\s*=\s*["']?([a-z0-9:_.-]+)/i.exec(t) || [])[1] || "";
    if (!META_NAMES.test(nm)) continue;
    const c = (/\bcontent\s*=\s*"([^"]*)"/i.exec(t) || /\bcontent\s*=\s*'([^']*)'/i.exec(t) || [])[1];
    if (c && c.trim()) out.push([nm.toLowerCase(), decodeEntities(c)]);
  }
  return out;
}

function ldValues(html) {
  const out = [];
  const rx = /<script\b[^>]*type\s*=\s*["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi;
  let m;
  let n = 0;
  while ((m = rx.exec(html)) && n++ < MAX_LD_BLOCKS && out.length < MAX_LD_VALUES) {
    const raw = m[1].slice(0, MAX_LD_CHARS);
    let parsed = false;
    try {
      const o = JSON.parse(raw);
      parsed = true;
      const walk = (x, d) => {
        if (d > 8 || out.length >= MAX_LD_VALUES) return;
        if (Array.isArray(x)) { for (const y of x) walk(y, d + 1); return; }
        if (x && typeof x === "object") {
          for (const k in x) {
            const v = x[k];
            if (typeof v === "string") { if (LD_KEYS.test(k) && v.trim()) out.push(["ld:" + k, decodeEntities(v)]); }
            else walk(v, d + 1);
          }
        }
      };
      walk(o, 0);
    } catch (e) { parsed = false; }
    // Injected JSON-LD is routinely malformed (the injector concatenates rather than serialises), and a
    // malformed block is if anything more suspicious than a valid one — so fall back to a flat key scan.
    if (!parsed) {
      for (const mm of raw.matchAll(/"(name|headline|description|keywords|alternateName)"\s*:\s*"((?:[^"\\]|\\.){0,400})"/gi)) {
        out.push(["ld:" + mm[1].toLowerCase(), decodeEntities(mm[2])]);
        if (out.length >= MAX_LD_VALUES) break;
      }
    }
  }
  return out;
}

// The visible text of the BODY only. P25's whole premise is "the head says casino and the body does not",
// and stripHtml() keeps <title> text, so testing scan.js's visB would make the comparison always false.
function bodyText(html) {
  const i = html.search(/<body\b/i);
  return strip(i >= 0 ? html.slice(i) : html.replace(/<head\b[\s\S]*?<\/head>/i, " "));
}

// ---- anchors ---------------------------------------------------------------

function anchorShape(html, reg, total) {
  let anchorText = 0;
  let n = 0;
  const internal = new Set();
  const off = Object.create(null);
  // The anchor-text quantifier is BOUNDED, not bare `[\s\S]*?`. With the bare form every `<a` that has no
  // matching `</a>` makes the engine scan to the end of the document before failing, once per `<a`. Measured
  // on a 205KB page of 5000 unclosed anchors carrying 430 chars of text — i.e. one that passes the cheap P49
  // length gate — the bare walk costs 79.5ms against 0.9ms for the same page with its anchors closed. That
  // is ~80x this module's entire typical cost, landing on a Worker whose free-plan CPU wall has frozen this
  // engine before (error 1102).
  // The bound is P49_MAX_TEXT and that is not arbitrary: this function is only ever called on a page whose
  // TOTAL text is already known to be under P49_MAX_TEXT, so an anchor whose inner text exceeds it cannot
  // exist inside a qualifying page and nothing reachable is lost. Measured 10.6ms on the same adversarial
  // page. (Missing an anchor could only lower `anchors` and `ratio`, i.e. make P49 fire LESS — safe.)
  const rx = new RegExp("<a\\b([^>]*)>([\\s\\S]{0," + P49_MAX_TEXT + "}?)<\\/a>", "gi");
  let m;
  while ((m = rx.exec(html)) && n < MAX_ANCHORS) {
    n++;
    anchorText += strip(m[2]).length;
    const href = (/href\s*=\s*["']([^"']+)/i.exec(m[1]) || [])[1];
    if (!href) continue;
    if (/^(https?:)?\/\//i.test(href)) {
      const host = href.replace(/^(https?:)?\/\//i, "").split("/")[0].split(":")[0].toLowerCase().replace(/^www\./, "");
      if (!host) continue;
      // Absolute self-links are NAVIGATION, not outbound. See the P49 comment block.
      if (reg && (host === reg || host.endsWith("." + reg))) internal.add(href.replace(/^(https?:)?\/\/[^/]*/i, "").split("?")[0].replace(/\/$/, "") || "/");
      else off[host] = (off[host] || 0) + 1;
    } else if (!/^(mailto:|tel:|javascript:|data:|#)/i.test(href)) {
      internal.add(href.split("?")[0].replace(/\/$/, "") || "/");
    }
  }
  let maxOff = 0;
  let maxHost = "";
  for (const k in off) if (off[k] > maxOff) { maxOff = off[k]; maxHost = k; }
  return { ratio: anchorText / total, internal: internal.size, text: total, anchors: n, maxOff, maxHost };
}

// ---- main ------------------------------------------------------------------

export async function run(ctx) {
  const out = [];
  try {
    if (!ctx) return out;
    if (typeof ctx.overBudget === "function" && ctx.overBudget()) return out;
    const S = ctx.S || SIG;
    const STRONG = S.ALL_STRONG || SIG.ALL_STRONG;
    const STRONG_SRC = (S.REG && S.REG.ALL_STRONG ? S.REG.ALL_STRONG : SIG.REG.ALL_STRONG).source;
    const WEAK_SRC = (S.REG && S.REG.ALL_WEAK ? S.REG.ALL_WEAK : SIG.REG.ALL_WEAK).source;
    const reg = (ctx.reg || "").toLowerCase().replace(/^www\./, "");
    const url = (ctx.base || (reg ? "https://" + reg : "")) + "/";

    let html = (ctx.B && ctx.B.text) || "";
    if (!html) return out;
    if (html.length > MAX_HTML) html = html.slice(0, MAX_HTML);

    // Computed here rather than taken from ctx.visB because this module needs entity-DECODED text — see
    // decodeEntities. visB stays the browser document ALONE: it is the denominator of the P26/P27 ratio
    // tests, and folding in the tail would move that denominator using bytes that may already be inside it.
    const visB = strip(html);
    // For the lexical layers, footer-injected text matters and lives past the 96KB cap. Append the tail only
    // when it is demonstrably not already part of the document we have.
    let vis = visB;
    const tail = ctx.tail || "";
    if (tail.length > 200 && html.indexOf(tail.slice(-200)) === -1) vis = visB + " " + strip(tail);

    // ---------------- P24 — meta + JSON-LD keyword scan ----------------
    // `visOpen` is scan.js's L1KW_STRONG, recomputed. It is the independence gate for `meta-injection`:
    // this bucket may only carry evidence the homepage-content bucket does NOT already hold. Measured
    // 30/30 of this layer's raw signals were already visible in visB, i.e. without the gate the bucket was
    // pure double-count. `visB` (not `vis`) is the right operand — it is exactly what L1KW_STRONG tests.
    const visOpen = STRONG.test(visB);
    let headHit = null;
    try {
      if (!visOpen) {
        const values = metaValues(html).concat(ldValues(html));
        for (const [k, v] of values) {
          if (firstStrong(v, STRONG_SRC)) { headHit = [k, v]; break; }
        }
        if (headHit) out.push({ bucket: "meta-injection", layer: "L36META", match: quote(headHit[0], headHit[1].slice(0, 170)), url });
      }
    } catch (e) { /* a malformed <head> must never kill the scan */ }

    // ---------------- P25 — head-only spam over a clean body ----------------
    try {
      const ttl = decodeEntities((RE_TITLE.exec(html) || [])[1] || "");
      const desc = (metaValues(html).find(([k]) => /description/.test(k)) || [])[1] || "";
      // Asymmetric on purpose. The HEAD must contain a real token (artefacts rejected) before anything can
      // fire; the BODY test is the raw regex, because there it is an EXCLUSION — a spurious body match only
      // ever suppresses this layer, and suppressing is the safe direction.
      const headSpam = firstStrong(ttl, STRONG_SRC) ? ttl : (firstStrong(desc, STRONG_SRC) ? desc : "");
      if (headSpam && !STRONG.test(bodyText(html))) {
        // The divergence IS the finding: a genuine gambling site carries the keyword in its body too and is
        // handled by the spam_site gate in scan.js, so this shape only occurs on a lightweight injection
        // that rewrote wp_title/description to rank for spam terms while looking clean to a human visitor.
        // bucket `homepage-content`, NOT a private one: stripHtml() keeps <title>, so the token this layer
        // reports is inside visB and L1KW_STRONG has already scored it. Same fact, one bucket.
        out.push({ bucket: "homepage-content", layer: "L37TITLEONLY", match: quote("head-only spam, body clean", headSpam.slice(0, 150)), url });
      }
    } catch (e) { /* ditto */ }

    // ---------------- P26 / P27 — foreign-script body takeover ----------------
    try {
      const lang = ((RE_HTML_LANG.exec(html) || [])[1] || "").toLowerCase();
      const declaredForeign = !!lang && RE_LANG_FOREIGN.test(lang);
      if (!declaredForeign && visB.length >= 40) {
        const n = countOf(visB, RE_TAKEOVER);
        const r = n / visB.length;
        const sample = () => {
          const i = visB.search(/[぀-ヿ㐀-鿿Ѐ-ӿ฀-๿가-힣]/);
          return visB.slice(Math.max(0, i - 20), Math.max(0, i - 20) + 110);
        };
        // P26 first: it is the BD-identity-gated arm and carries the more defensible claim.
        const isBd = (() => { try { return !!(S.bdSignal ? S.bdSignal(reg, visB) : SIG.bdSignal(reg, visB)); } catch (e) { return false; } })();
        const shapeHit = (n >= P26_MIN_CHARS && r >= P26_MIN_RATIO) || (n >= P26_ALT_CHARS && r >= P26_ALT_RATIO);
        if (isBd && shapeHit) {
          out.push({ bucket: "foreign-body", layer: "L38LANGBODY", match: quote(`foreign script ${n} chars = ${Math.round(r * 100)}% of body`, sample()), url });
        } else if (lang && n >= P27_MIN_CHARS && r >= P27_MIN_RATIO) {
          // P27. The premise is weaker than P26's (a lang attribute is theme boilerplate, not a claim the
          // owner consciously made) but it is exactly what survives a takeover: the injector replaces the
          // rendered page and leaves the theme's <html lang="en"> in place. rskrubberbd.com — a Bangladeshi
          // rubber company — currently serves a wholly Chinese page under lang="en".
          out.push({ bucket: "foreign-body", layer: "L39LANGMISMATCH", match: quote(`lang="${lang}" but ${Math.round(r * 100)}% of body is another script`, sample()), url });
        }
      }
    } catch (e) { /* ditto */ }

    // ---------------- P28 — Latin-script foreign spam lexicon ----------------
    try {
      if (!out.some((s) => s.bucket === "foreign-body")) {
        const anchors = [];
        for (const [rx, label] of FLATIN_ANCHOR) { if (rx.test(vis)) anchors.push(label); if (anchors.length >= 4) break; }
        if (anchors.length >= FLATIN_MIN_ANCHOR) {
          let total = anchors.length;
          for (const rx of FLATIN_GENERIC) { if (rx.test(vis)) total++; if (total >= 8) break; }
          if (total >= FLATIN_MIN_TOTAL) {
            const i = vis.toLowerCase().indexOf(anchors[0].toLowerCase().slice(0, 6));
            const win = i >= 0 ? vis.slice(Math.max(0, i - 40), Math.max(0, i - 40) + 150) : anchors.join(", ");
            out.push({ bucket: "foreign-body", layer: "L40FLATIN", match: quote(`${total} foreign spam phrases incl. "${anchors[0]}"`, win), url });
          }
        }
      }
    } catch (e) { /* ditto */ }

    // ---------------- P29 — keyword stuffing density ----------------
    try {
      const rx = new RegExp(STRONG_SRC, "gi");
      const counts = Object.create(null);
      let m;
      let guard = 0;
      while ((m = rx.exec(vis)) && guard++ < 3000) {
        // Without this the layer counts every "spécialisée" on a French-language page as a cialis hit, and
        // a French site that says it 8 times becomes a pharma lead.
        if (!boundaryArtefact(vis, m.index, m[0])) {
          const k = m[0].toLowerCase();
          counts[k] = (counts[k] || 0) + 1;
        }
        if (rx.lastIndex === m.index) rx.lastIndex++;
      }
      let top = "";
      let topN = 0;
      let distinct = 0;
      for (const k in counts) { distinct++; if (counts[k] > topN) { topN = counts[k]; top = k; } }
      if (topN >= DENSITY_MIN) {
        const i = vis.toLowerCase().indexOf(top);
        const win = vis.slice(Math.max(0, i - 40), Math.max(0, i - 40) + 150);
        out.push({ bucket: "homepage-content", layer: "L41DENSITY", match: quote(`"${top}" x${topN} (${distinct} distinct spam terms)`, win), url });
      } else {
        // WEAK arm — only reached when no STRONG token stuffed the page, so the two can never both occupy
        // the bucket and the weak weight can never displace the strong one.
        const toks = vis.toLowerCase().match(/[a-z][a-z0-9'-]{2,}/g);
        if (toks && toks.length >= WSTUFF_MIN_TOKENS) {
          const tt = toks.length > MAX_TOKENS ? toks.slice(0, MAX_TOKENS) : toks;
          const c = Object.create(null);
          for (const t of tt) c[t] = (c[t] || 0) + 1;
          const weak = new RegExp(WEAK_SRC, "i");
          let wt = "";
          let wn = 0;
          for (const k in c) { if (c[k] > wn && c[k] >= WSTUFF_MIN_COUNT && weak.test(k)) { wn = c[k]; wt = k; } }
          if (wt && wn / tt.length >= WSTUFF_MIN_FRAC) {
            const i = vis.toLowerCase().indexOf(wt);
            const win = vis.slice(Math.max(0, i - 40), Math.max(0, i - 40) + 150);
            out.push({ bucket: "homepage-content", layer: "L42WSTUFF", match: quote(`"${wt}" x${wn} = ${Math.round((wn / tt.length) * 100)}% of all words`, win), url });
          }
        }
      }
    } catch (e) { /* ditto */ }

    // ---------------- P49 — doorway page shape ----------------
    try {
      const finalUrl = (ctx.B && ctx.B.finalUrl) || url;
      // The text-length window is checked BEFORE the anchor walk, not after. It is the cheapest of the six
      // conditions and it rejects almost every real page, which keeps the one genuinely superlinear regex in
      // this file (the lazy <a>…</a> scan) off the hot path: a document with thousands of UNCLOSED <a> tags
      // costs ~60ms to walk, and there is no reason to pay that on a page whose body text already disqualifies it.
      if (!P49_URL_EXCLUDE.test(finalUrl) && visB.length >= P49_MIN_TEXT && visB.length < P49_MAX_TEXT) {
        const s = anchorShape(html, reg, visB.length);
        if (s.anchors >= P49_MIN_ANCHORS &&
            s.ratio > P49_MIN_RATIO && s.internal < P49_MAX_INTERNAL && s.maxOff >= P49_MIN_OFFDOMAIN) {
          out.push({
            bucket: "doorway-shape", layer: "L53SHAPE2",
            match: `doorway shape: ${s.anchors} links / ${s.text} chars of text, ${Math.round(s.ratio * 100)}% of it link text, ${s.internal} internal pages, ${s.maxOff} links to ${s.maxHost}`.slice(0, 200),
            url: finalUrl,
          });
        }
      }
    } catch (e) { /* ditto */ }
  } catch (e) {
    return [];
  }
  return out;
}
