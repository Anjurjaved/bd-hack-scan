// sitemapx.js — sitemap + robots.txt doorway discovery (P19 · P20 · P21 · P22 · P23).
//
// WHY THIS MODULE EXISTS: the live sitemap block in scan.js walks at most 2 parent sitemaps and, inside
// each, `.slice(0, 3)` of the children. On a WordPress site the sitemap index is emitted in ascending
// order — post-sitemap1.xml, post-sitemap2.xml, … post-sitemap11.xml — so the first three children hold
// the site's OLDEST posts. Injected doorway posts are, by definition, the site's NEWEST content. They
// live in the LAST child, which the current slice guarantees will never be fetched. L11SITEMAP is
// therefore structurally blind on exactly the sites it was written for: the big, long-lived, heavily
// indexed WordPress installs that are the most valuable cleanup leads. P19 is the fix, and it is pure
// recall — no new claim, just reading the bytes we were already trying to read.
//
// The other four proposals are analysis over those same bytes and cost nothing extra once they are in
// hand: foreign-script slugs (P20), volume anomaly (P21), lastmod burst (P22), and robots.txt mining
// (P23), which is free because robots.txt is the request that discovers the sitemap in the first place.
//
// BUCKET DISCIPLINE — every layer in this file emits into `sitemap-doorway`, the same bucket the live
// L11SITEMAP/L20SHAPE use. Non-negotiable, for two reasons:
//   1. All of it is derived from ONE download. A spam slug in the sitemap and a lastmod burst around
//      that same slug are one fact observed twice; separate buckets would multiply a single observation
//      into an independent-looking posterior — the exact arithmetic behind the 331-junk-lead incident.
//   2. It makes the two statistical layers structurally incapable of stacking on the keyword layers.
//      The fuser takes the strongest layer per bucket, so when a real spam slug is present the volume
//      and lastmod layers contribute nothing at all, and when they are alone they contribute only their
//      own deliberately feeble weight. That is precisely the "corroborate, never confirm" behaviour
//      P21 and P22 were specified with, enforced by the bucket rather than by hoping.
//
// robots.txt lives in the same bucket for the same reason: an attacker who Disallows /slot-gacor/ has
// also, nine times out of ten, left it in the sitemap. Same fact, one bucket.

// Tier 1. This module is the *replacement* for a t1 layer that is silently under-reading; deferring it
// to the VM would leave the Worker fleet exactly as blind as it is today. It is nonetheless the most
// fetch-hungry t1 module in the tree, so every request is spent through `spend()` in strict
// value-descending order and the whole thing degrades gracefully to zero signals under a tight budget.
export const TIER = "t1";

// Bayesian [P(fires | hacked), P(fires | clean)]. P(clean) is the false-positive rate and is declared
// pessimistically throughout — a layer measured at 0/2000 on the clean control is still declared at
// 0.004, not 0.0005, because 2000 samples cannot distinguish those two numbers.
export const WEIGHTS = {
  // P19. The SAME assertion as the live L11SITEMAP [0.78, 0.020] — a spam slug published in the site's
  // own sitemap — read with better coverage. So the detect rate goes UP (that is the entire point of
  // the deeper recursion) while the clean rate stays exactly where L11SITEMAP's is. It must NOT be
  // declared cleaner than L11SITEMAP: reading more sitemaps means more chances to trip over an odd
  // legitimate URL, so the honest statement is "more sensitive at the same specificity", never "more
  // sensitive AND more specific". Fusing at a lower FP rate here would be free confidence out of thin air.
  L38SMAPDEEP: [0.86, 0.020],
  // P20. The Japanese-keyword hack. Very high specificity once conditioned on the homepage not being in
  // that script, on the URLs not sitting under a /ja/-style language prefix, and on each slug carrying
  // at least four foreign characters — a BD business site that publishes five such pages outside a
  // language subtree has essentially one explanation. Measured 10/112 hacked, 0/644 clean BD.
  L32FOREIGNSLUG: [0.72, 0.006],
  // P21. Statistical, corroborating only. 0.10 clean is a deliberately awful number: it says one clean
  // BD site in ten could look like this, which is far more pessimistic than measured, and it caps the
  // layer's contribution at a log-ratio too small to carry a domain anywhere near the confirm line.
  L33VOLUME: [0.60, 0.100],
  // P22. Weakest layer in the module — a bulk product import and a mass injection genuinely do produce
  // the same histogram, and the gates below only separate the common cases. Its job is to promote a
  // domain into the Tier-2 deep queue, not to flag it. Ratio 3.75 cannot confirm anything alone.
  L34LASTMOD: [0.45, 0.120],
  // P23. A spam slug in a Disallow line. Attackers hide doorway directories from crawlers they do not
  // want (and site owners never write these), so the clean rate is genuinely low.
  // 0.004 WAS OVER-CONFIDENT AND IS NOT SUPPORTED BY THE MEASUREMENT. Re-measured 2026-07-20 over 450
  // random .bd domains from the live queue corpus: only 85 served a parseable robots.txt at all, and
  // between them they carried just 198 Disallow lines. 0/85 sites fired — but 85 samples cannot
  // distinguish 0.004 from 0.03, and the module's own stated doctrine ("2000 samples cannot
  // distinguish 0.0005 from 0.004") demands the same discipline scaled to the evidence that actually
  // exists. robots.txt is a far thinner sample than a sitemap: most BD sites have no Disallow line for
  // this layer to be right or wrong about, so the denominator is ~85, not ~2000.
  // 0.010 keeps it the strongest layer in the module (ratio 62, on a par with L11REST's 88) while
  // requiring a genuine second bucket to confirm. At 0.004 the ratio was 155, and 155 x ANY second
  // bucket down to ratio 1.6 cleared the 0.97 confirm line — i.e. one Disallow line plus almost any
  // other signal in the system was a sold lead.
  L35ROBOTSPAM: [0.62, 0.010],
};

// NOT SHIPPED — P23b, the off-domain `Sitemap:` directive layer. The proposal called this
// "near-conclusive evidence of injection". It was implemented, dry-run over 1,436 reachable control
// domains, and REMOVED, because in Bangladesh it is near-conclusive evidence of a shared web
// developer. Measured: 18/1436 clean (1.25%) against 3/116 hacked (2.6%) — a likelihood ratio of ~2,
// which is noise. Every clean hit had the same innocent shape:
//   gcbghs.edu.bd → scbbhs.edu.bd            one contractor, two school sites, one pasted robots.txt
//   matrisaya.edu.bd → canvasictinstitute.com    the developer's OWN agency domain
//   pmp.pharmacy.du.ac.bd → innovativeitbd.com   likewise
//   app.bau.edu.bd → bau.edu.bd                  a subdomain pointing at its own parent university
//   asthaexpress-bd.com + econoservicebd.com → deshtravelsbd.com   the same contractor twice
//   ittehad.bd → supabase.co                 a sitemap generated by an edge function; modern, fine
//   edwardjonesmortgage.com → edwardjones.com     the same company
// Worse than useless: five of those are .edu.bd/.ac.bd/.gov.bd, the restricted institutional TLDs
// where scan.js confirms gambling/adult WITHOUT an AI call. A noisy layer aimed straight at the one
// code path that has no second opinion is precisely how a real school gets told it is hacked.
// Do not re-add it without a mechanism that distinguishes "another domain" from "my web developer".

// Only the foreign-slug layer gets a fixed category. Everything else deliberately has none, so
// S.categoryOf() derives gambling/pharma/adult from the token that actually matched — always more
// accurate than a label pinned on the transport we happened to read it through.
export const CATS = {
  L32FOREIGNSLUG: "foreign_lang",
};

// ---------------------------------------------------------------------------
// P19 — sitemap variant order.
//
// Probed in order, stopping at the first 200 that actually contains <urlset or <sitemapindex, and only
// reached at all when robots.txt named no sitemap of its own. Two lists rather than the proposal's
// single seven-entry sweep, selected on the homepage's CMS fingerprint: a blind probe of seven paths
// spends seven requests to find a file that a WordPress site keeps at a known location.
//
// /sitemap.xml.gz is deliberately absent. `fetch` transparently decodes Content-Encoding, but a .gz
// FILE arrives as an opaque gzip member with no encoding header, and neither the Workers runtime nor a
// dependency-free node build can inflate it here. Fetching it would burn a request to receive bytes we
// cannot read.
const VARIANTS_WP = ["/wp-sitemap.xml", "/sitemap_index.xml", "/sitemap.xml", "/post-sitemap.xml"];
const VARIANTS_GEN = ["/sitemap_index.xml", "/sitemap.xml", "/sitemap-index.xml", "/sitemap1.xml"];

const MAX_PARENTS = 3;          // proposal: raise from 2
const MAX_CHILD_PER_PARENT = 7; // last 5 + first 2
const MAX_VARIANT_PROBES = 4;   // a miss costs a whole request; four is the point of diminishing returns
const MAX_SM_BYTES = 900000;    // ~9x the live 220KB cap: the deep children are the payload, not the index
const MAX_LOCS = 60000;         // parse ceiling; a 946MB VM must not build a 300k-element array

// ---------------------------------------------------------------------------
// THE BENGALI-WORD TRAP, IN LATIN SCRIPT.
//
// Two tokens inside the live S.RE.SLUG_SPAM are not spam-only words, and reading five times as many
// sitemap URLs as the old code turns that from a theoretical problem into a measured one:
//   `judi`  — a given name. The corpus dry-run caught cinevabd.com/director/JUDI-TOWNSEND, a film
//             director on a Bangladeshi movie site. Judi Dench is the same collision waiting to happen
//             on any BD entertainment or news site with a cast/crew index.
//   `situs` — "situs inversus" is a real congenital condition, so a BD hospital or diagnostic centre
//             publishing /situs-inversus-totalis/ is medicine, not a casino.
// The remedy is the doctrine CONTRACT rule 6 already sets out for Bengali — never trust a bare
// ambiguous token, bind it to a second spam-only one — applied here to English and Latin collisions.
// A URL whose ONLY evidence is a bare `judi` or `situs` is accepted only if some other SLUG_SPAM token
// survives with those two removed, or if the token appears in a bound Indonesian gambling phrase.
// This keeps "daftar-situs-game-judi-slot-online-gacor" and "terjerat-judi-online"; it drops
// "judi-townsend" and "situs-inversus". Fixed here rather than in signatures.js because that file is
// shared with the live L11SITEMAP and is not this module's to change.
const SLUG_AMBIG = /^(situs|judi)$/i;
const SLUG_BOUND = /judi[-_]?(online|bola|slot|togel|casino|kartu|poker|qq|terpercaya)|(?:situs|link|daftar|bandar|agen)[-_]?(judi|slot|togel|toto|bola|casino)/i;
const SLUG_STRIP = /situs|judi/gi;

// True when a URL's SLUG_SPAM match is real spam evidence rather than a name collision.
function slugSpamReal(S, u) {
  const m = S.RE.SLUG_SPAM.exec(u);
  if (!m) return false;
  if (!SLUG_AMBIG.test(m[0])) return true;               // gacor / togel / sbobet / slot-88 — unambiguous
  if (S.RE.SLUG_SPAM.test(u.replace(SLUG_STRIP, ""))) return true;  // a second, unambiguous token
  return SLUG_BOUND.test(u);                             // or the ambiguous token in a bound phrase
}

// ---------------------------------------------------------------------------
// THE SAME TRAP, ON THE ROBOTS.TXT SIDE — and the guard above did not cover it.
//
// L35ROBOTSPAM tested `S.RE.SLUG_SPAM || S.ALL_STRONG`. slugSpamReal() only ever saw the SLUG_SPAM
// arm, so the ALL_STRONG arm walked straight around it: `\bjudi\b` is in GAMB_STRONG as well, and
// /director/judi-townsend matches ALL_STRONG directly. ALL_STRONG is a BODY-text lexicon; run against
// a URL PATH, where `/` `-` `_` are all word boundaries, its unbounded arms collide with ordinary
// Bangladeshi paths. Measured against signatures.js, every one of these returns category "gambling":
//   bahis   → `\bbahis\b` matches /bahis/, /bahis-admin/, /bahis-report. bahis.dls.gov.bd IS IN THE
//             CORPUS — the Bangladesh Animal Health Information System, a .gov.bd, i.e. precisely the
//             restricted-institutional path scan.js confirms as "inst-hacked" with NO AI second
//             opinion. This is the exact failure mode the P23b removal note above was written about.
//   1win    → an UNANCHORED substring: /2021winter-collection/ on a garments site, /2011winners/ or
//             /awards/2001winter on a school site.
//   pin-up  → `\bpin-?up\b` matches /pinup-gallery/ on a salon, photography or retro-fashion site.
// vocab.js reached the same conclusion independently from the homepage side (its AMBIGUOUS_TOKEN list
// names bahis and pin-up for the same reason), which is corroboration, not coincidence.
const ROBOT_AMBIG = /^(?:bahis|1win|pin-?up|judi)$/i;
const ROBOT_STRIP = /bahis|1win|pin-?up|\bjudi\b/gi;

// PHARMA_STRONG (kamagra/sildenafil/tadalafil/viagra/cialis) is product vocabulary for a business that
// legitimately sells medicine. A BD online pharmacy or health marketplace disallowing a drug path is
// running a shop, not hosting an injection. Gambling and adult vocabulary is never exempted.
const PHARMA_SAFE_BIZ = new Set(["pharma", "healthcare", "ecommerce"]);

// True when a robots.txt Disallow path is real spam evidence. Same doctrine as slugSpamReal(), applied
// to BOTH arms of the test instead of only one of them.
function robotsSpamReal(S, p, dec, biz) {
  if (slugSpamReal(S, p) || slugSpamReal(S, dec)) return true;
  const m = S.ALL_STRONG.exec(dec);
  if (!m) return false;
  if (PHARMA_SAFE_BIZ.has(biz) && !S.RE.GAMB_STRONG.test(dec) && !S.RE.ADULT_STRONG.test(dec)) return false;
  if (!ROBOT_AMBIG.test(m[0])) return true;              // togel / gacor / sbobet / bokep — unambiguous
  return S.ALL_STRONG.test(dec.replace(ROBOT_STRIP, ""));  // else demand a second, unambiguous token
}

// ---------------------------------------------------------------------------
// P20 — percent-encoded foreign scripts, as they appear in a raw <loc>.
//
// WHAT IS DELIBERATELY MISSING FROM THIS REGEX IS THE WHOLE POINT:
//   %E0%A6 / %E0%A7  Bengali (U+0980–U+09FF). CONTRACT rule 5 — this is the site's own language. A
//                    Bengali slug is a BD school publishing a notice, and treating it as takeover would
//                    fire on a large fraction of the entire corpus.
//   %D8 / %D9        Arabic. Madrasah, mosque and Islamic-foundation sites across BD publish Arabic
//                    slugs as a matter of course. Not foreign, not a takeover.
//   %E0%A4 / %E0%A5  Devanagari. Sub-continental, plausible on a legitimate BD site, excluded.
// What remains is Kana + CJK + Cyrillic + Thai + Hangul, i.e. exactly the scripts in S.RE.FOREIGN, and
// exactly the scripts that a Dhaka trading company has no reason to have in a URL path.
const PCT_FOREIGN = /%E3%[89AB][0-9A-F]|%E[4-9]%[89AB][0-9A-F]|%D[01]%[89AB][0-9A-F]|%E0%B[89]|%E[A-D]%[89AB][0-9A-F]/i;

// A genuine multilingual site keeps its translations in a language subtree. An injection is sprayed
// flat at the site root. Any URL sitting under one of these prefixes is a translation, not a doorway.
const LANG_PREFIX = /\/(ja|jp|zh|zh-cn|zh-tw|cn|ko|kr|th|ru|vi|hi|ar|tw|hk)(\/|$)/i;

// MOJIBAKE GUARD #2 — THE BENGALI SLUG THAT COMES BACK AS RUSSIAN.
//
// Excluding %E0%A6/%E0%A7 from PCT_FOREIGN protects a CORRECTLY encoded Bengali slug, and it works:
// encodeURIComponent("ভর্তি-বিজ্ঞপ্তি-২০২৬") decodes to Bengali, which S.RE.FOREIGN does not match, so
// the layer stays silent. It does nothing for a MANGLED one. A Bengali slug written through a
// latin1/cp1251 database collation — endemic on the cheap BD cPanel shared hosting this scanner
// exists to find — re-encodes as Cyrillic:
//     "ভর্তি বিজ্ঞপ্তি"  →  "а¦­а¦°а§Ќа¦¤а¦ї а¦¬а¦їа¦ња§Ќа¦ћа¦Єа§Ќа¦¤а¦ї"
// Measured: 23 characters inside S.RE.FOREIGN. The 4-character floor does not see it, and a BD school
// publishing Bengali notices reads as a Russian takeover — a direct breach of CONTRACT rule 5, on a
// .edu.bd, where scan.js confirms foreign_lang with no AI call.
//
// A character COUNT cannot separate these; the tell is structural. UTF-8 lead and continuation bytes
// misread through a Latin codepage always drag Latin-1 supplement symbols (¦ § ­ ° ± ¬ Â Ã) or smart
// quotes along with the letters. No genuine Japanese, Chinese, Korean, Thai or Russian slug ever
// contains one. Verified against every case in this file: it silences the Bengali mojibake above and
// leaves オンラインカジノ登録方法, лучшие-казино-онлайн and — the one a run-length test would have lost —
// the homoglyph cloak "exрloring-the-toр-english-sрeаking-clаsses" all firing.
const MOJIBAKE = /[\u00A0-\u00BF\u00C2\u00C3\u00D7\u00F7\u0098\u0099\u2018-\u201F\uFFFD]/;

// ---------------------------------------------------------------------------
// P21 / P22 — business categories exempt from the statistical layers.
//
// A news outlet, an online shop and a government portal all legitimately publish tens of thousands of
// URLs, and an ecommerce catalogue import legitimately re-stamps thousands of lastmods in one night.
// Running volume statistics on them measures their business model, not a compromise. This exclusion is
// mandatory, not a tuning knob.
// "education" IS ON THIS LIST AND MUST STAY ON IT — it is not a tuning knob either, it is the single
// most dangerous omission the module had. S.bizType() returns "education" for EVERY .edu.bd/.ac.bd by
// TLD alone, and a Bangladeshi university, college or madrasa is a bulk publisher by nature: course
// pages, notices, results, past papers, faculty profiles, department archives — tens of thousands of
// URLs behind whatever navigation the homepage happens to render. Without this entry the chain ran:
//   L33VOLUME fires on a big sitemap + a thin (JS-rendered) homepage nav
//     → the signal carries NO keyword, and L33VOLUME has no CATS entry, so scan.js category()
//       falls through its whole preference list to its default — literally `return "gambling"`
//     → one bucket, posterior 0.955 → SUSPECT → flagged = true
//     → BD_INST_TLD + category "gambling" + flagged → findings.push({verdict:"inst-hacked",
//       confirmed:1}), the one path in the system that spends NO AI call
// i.e. a pure URL-COUNT STATISTIC, with no spam evidence of any kind attached to it, sold a
// Bangladeshi university as a confirmed casino injection. Verified by running S.bizType() and
// scan.js's category() directly: du.ac.bd/buet.ac.bd/nu.ac.bd → "education", and a lone L33VOLUME or
// L34LASTMOD signal → "gambling". Adding "education" closes it for both statistical layers, because
// the institutional TLDs are exactly the ones bizType classifies from the name.
const BULK_BIZ = new Set(["news", "ecommerce", "government", "education"]);

// ...but bizType ALONE is not enough, and the clean control proved it in the worst possible way:
// prothomalo.com — the most-read website in Bangladesh — classifies as "general-business" with 19
// homepage links, because it is a JS-rendered SPA whose server HTML carries almost no anchors and
// whose Bengali masthead copy misses every token in the `news` category regex. It is numerically
// INDISTINGUISHABLE from the hacked sobcheye.com (17 links, biz=travel). Any publisher test built on
// homepage nav size or bizType therefore flags Prothom Alo, and a detector that flags Prothom Alo is
// not shippable at any weight.
//
// This is the test that does separate them, and it works precisely because it reads the sitemap tree
// instead of the homepage: real publishers emit a Google-News sitemap and/or date-partitioned sitemap
// children. It is language-independent, framework-independent, and an injected doorway farm has no
// reason whatsoever to produce it.
const PUBLISHER_SMAP = /xmlns:news|<news:|news-?sitemap|sitemap-?news|google-?news|sitemap[-_/]?20\d\d[-_/]/i;

// P22 recency. We sell cleanup for a hack that is live NOW. A lastmod burst from 2018 is site history,
// not evidence of a current compromise — and it is exactly what an old, long-running publisher's
// archive looks like. Requiring the burst to be recent is therefore both an FP fix and a correctness
// fix; it is the gate that silences Prothom Alo's 2022 burst while keeping the 2026 injections.
const BURST_MAX_AGE_DAYS = 540;

const DAY = 86400000;

function safeHost(ctx, u) { try { return ctx.hostOf(u) || ""; } catch (e) { return ""; } }

// Last meaningful path segment of a URL, extension stripped. Kept as-is (NOT lowercased) for the
// percent-encoding test, which is case-insensitive anyway.
function lastSeg(u) {
  const q = u.split(/[?#]/)[0];
  const parts = q.replace(/\/+$/, "").split("/");
  const seg = parts.length > 3 ? parts[parts.length - 1] : "";
  return seg.replace(/\.(html?|php|aspx?)$/i, "");
}

export async function run(ctx) {
  const out = [];
  try {
    const S = ctx.S;
    const reg = ctx.reg;
    const base = ctx.base;
    const bodyB = (ctx.B && ctx.B.text) || "";
    const visB = ctx.visB || "";
    if (!base || !reg) return out;

    // SELF-IMPOSED SHARE OF A SHARED BUDGET.
    // ctx.budget.fetches (6 shallow / 14 deep) is the allowance for ALL TEN modules, and index.js runs
    // this one SEVENTH — ahead of wpprobe (L11REST, ratio 88, the most diagnostic layer in the whole
    // system), cloak (L2UACLOAK, 46) and deep. Uncapped, this module's worst case is
    // 1 robots + 4 variant probes + 3 parents + 3x7 children = 29 fetches, so on any site with a real
    // sitemap tree it drained the budget to zero and silently switched those modules off — trading the
    // single best layer in the detector for a deeper read of one we already have. It also removes the
    // corroborating buckets that keep THIS module's own signals honest, which is the wrong trade twice.
    // Capped at ~55% of the allowance it was handed (floor 3, ceiling 8) so the downstream modules
    // always keep a working share.
    const budget0 = (ctx.budget && typeof ctx.budget.fetches === "number") ? ctx.budget.fetches : 8;
    const myMax = Math.min(8, Math.max(3, Math.round(budget0 * 0.55)));
    let mySpent = 0;
    const spend = (n) => {
      if (ctx.overBudget && ctx.overBudget()) return false;
      if (mySpent + n > myMax) return false;
      if (ctx.budget && typeof ctx.budget.fetches === "number") {
        if (ctx.budget.fetches < n) return false;
        ctx.budget.fetches -= n;
      }
      mySpent += n;
      return true;
    };
    const push = (layer, match, url) => {
      const m = String(match || "").replace(/\s+/g, " ").trim().slice(0, 200);
      if (m) out.push({ bucket: "sitemap-doorway", layer, match: m, url: String(url || base).slice(0, 300) });
    };
    const mine = (u) => { try { return ctx.sameHost(safeHost(ctx, u), reg); } catch (e) { return false; } };
    const get = async (u, ms) => {
      if (!spend(1)) return null;
      try { return await ctx.fetchPage(u, ctx.UA_GB, null, ms); } catch (e) { return null; }
    };

    const bizType = (() => {
      try {
        const t = (bodyB.match(/<title[^>]*>([\s\S]*?)<\/title>/i) || ["", ""])[1] || "";
        return S.bizType(reg, t, visB);
      } catch (e) { return ""; }
    })();

    // =====================================================================
    // robots.txt — one request, and the only unconditional one this module makes. It pays for itself
    // three times over: it yields P23 outright, it names the sitemaps so the variant probes below are
    // usually skipped entirely, and a 404 here is a decent hint that the variant probes will also miss.
    // =====================================================================
    const rob = await get(base + "/robots.txt", 8000);
    const robTxt = (rob && rob.status === 200 && rob.text) ? rob.text.slice(0, 60000) : "";
    let declared = [];

    if (robTxt) {
      // ---- P23 · L35ROBOTSPAM — Disallow paths.
      // Zero extra requests. An attacker keeping a doorway tree out of a crawler's way writes exactly
      // this line; a site owner has no reason to ever type it.
      const badPaths = [];
      for (const m of robTxt.matchAll(/^\s*disallow:\s*(\S+)/gim)) {
        const p = m[1];
        if (!p || p === "/" || p.length > 160) continue;
        let dec = p;
        try { dec = decodeURIComponent(p); } catch (e) { /* malformed escape — test the raw form */ }
        // robotsSpamReal(), NOT the raw regexes: the ALL_STRONG arm bypassed slugSpamReal() entirely
        // and re-opened /director/judi-townsend, plus bahis / 1win / pin-up. See ROBOT_AMBIG.
        if (robotsSpamReal(S, p, dec, bizType)) {
          badPaths.push(p.slice(0, 70));
          if (badPaths.length >= 3) break;
        }
      }
      if (badPaths.length) push("L35ROBOTSPAM", "robots.txt hides spam paths: Disallow: " + badPaths.join(" ; Disallow: "), base + "/robots.txt");

      // `Sitemap:` directives are still harvested — they are how we find the sitemap tree below.
      // They are NOT scored; see the removal note above WEIGHTS for the measurement that killed P23b.
      for (const m of robTxt.matchAll(/^\s*sitemap:\s*(https?:\/\/\S+)/gim)) declared.push(m[1]);
    }

    // =====================================================================
    // P19 — locate the sitemap tree.
    // =====================================================================
    let parents = declared.filter(mine);
    if (!parents.length) {
      const wpish = /wp-content|wp-includes|\/wp-json|rel=["']https:\/\/api\.w\.org/i.test(bodyB);
      const cand = (wpish ? VARIANTS_WP : VARIANTS_GEN).slice(0, MAX_VARIANT_PROBES);
      for (const v of cand) {
        const r = await get(base + v, 7000);
        if (!r) break;                                   // budget gone — stop, do not keep probing
        if (r.status === 200 && /<(urlset|sitemapindex)\b/i.test(r.text || "")) { parents = [base + v]; break; }
      }
    }
    if (!parents.length) return out;

    // Fetch parents, then children. Children are ordered LAST-FIRST — the whole reason this module
    // exists. post-sitemap11.xml holds this month's posts; post-sitemap1.xml holds 2016's. If the
    // budget dies halfway we want to have spent it on the recent end.
    let sm = "";
    const fetched = new Set();
    for (const p of parents.slice(0, MAX_PARENTS)) {
      if (fetched.has(p)) continue;
      fetched.add(p);
      const r = await get(p, 8000);
      if (!r || r.status !== 200 || !r.text) continue;
      sm += r.text;
      if (sm.length > MAX_SM_BYTES) break;

      const kids = [...new Set([...r.text.matchAll(/https?:\/\/[^<\s"']+\.xml/gi)].map((m) => m[0]))].filter((u) => mine(u) && !fetched.has(u));
      const tail = kids.slice(-5);
      const head = kids.slice(0, 2).filter((u) => !tail.includes(u));
      for (const c of [...tail, ...head].slice(0, MAX_CHILD_PER_PARENT)) {
        if (fetched.has(c)) continue;
        fetched.add(c);
        const cr = await get(c, 7000);
        if (!cr) break;                                  // out of budget/time
        if (cr.status === 200 && cr.text) sm += cr.text;
        if (sm.length > MAX_SM_BYTES) break;
      }
      if (sm.length > MAX_SM_BYTES) break;
    }
    if (!sm) return out;

    // ---- parse <loc> / <lastmod> once.
    const locs = [];
    let guard = 0;
    for (const m of sm.matchAll(/<loc>\s*([^<\s]+)/gi)) {
      if (guard++ >= MAX_LOCS) break;
      locs.push(m[1]);
    }
    const pages = locs.filter((u) => mine(u) && !/\.xml(\.gz)?$/i.test(u));
    if (!pages.length) return out;

    // =====================================================================
    // P19 · L38SMAPDEEP — spam slugs. The recall payload.
    // =====================================================================
    const spamUrls = [];
    for (const u of pages) {
      if (!slugSpamReal(S, u)) continue;   // see SLUG_AMBIG — bare `judi`/`situs` are name collisions
      spamUrls.push(u);
      if (spamUrls.length >= 3) break;
    }
    if (spamUrls.length) push("L38SMAPDEEP", "sitemap publishes spam URLs: " + spamUrls.join(" ; "), spamUrls[0]);

    // =====================================================================
    // P20 · L32FOREIGNSLUG — Kana/CJK/Cyrillic/Thai/Hangul slugs on a non-that-script site.
    // =====================================================================
    // A site whose own homepage is in one of those scripts is exempt outright: telling a genuinely
    // Japanese site that its Japanese URLs are a takeover is the mirror image of CONTRACT rule 5.
    // An EMPTY homepage is exempt too, for the same reason the catch clause below returns true: with no
    // visible text there is no basis on which to claim the site's own script is not the one in its URLs.
    // A WAF page, a 403 or a pure JS shell all land here, and "we could not look" must never read as
    // "we looked and it was not Japanese".
    const homeForeign = (() => {
      try { return visB.length < 200 || S.RE.FOREIGN.test(visB.slice(0, 8000)); } catch (e) { return true; }
    })();
    if (!homeForeign) {
      const fseen = new Set();
      const fsamp = [];
      const FOREIGN_G = new RegExp(S.RE.FOREIGN.source, "g");   // hoisted: `pages` runs to 60k entries
      for (const u of pages) {
        if (LANG_PREFIX.test(u)) continue;              // /ja/… is a translation subtree, not a doorway
        const seg = lastSeg(u);
        if (!seg || seg.length < 3) continue;
        // MOJIBAKE GUARD. A stray Cyrillic char or two inside an otherwise Latin slug is almost never
        // a takeover — it is double-encoding damage. The clean control caught the exact case:
        // aedownload.com publishes ".../videohive-cosmic-particle-logo-reveal-%d0%b2%d1%92-stellar-
        // explosion-intro", where %d0%b2%d1%92 is "в’", the CP1251 misread of a typographic en-dash.
        // Requiring FOUR foreign characters in the slug drops that (2 chars) while keeping every real
        // hit measured: 登録方法 (4), казино (6), and — the nicest one — oidigitalinstitute.com's
        // homoglyph cloak "ex[р]loring-the-to[р]-english-s[р]e[а]king-cl[а]sses", 5 Cyrillic letters
        // wearing Latin faces, which no character-count-blind test would separate from a typo.
        // Cheap pre-filter. Sitemaps carry foreign slugs either percent-encoded (the common case) or
        // as literal UTF-8, so both forms have to reach the decode+count below.
        if (!PCT_FOREIGN.test(seg) && !/%[0-9A-F]{2}/i.test(seg) && !S.RE.FOREIGN.test(seg)) continue;
        let dec = seg;
        try { dec = decodeURIComponent(seg); } catch (e) { /* malformed escape — keep the raw form */ }
        // See MOJIBAKE. A Latin-1 supplement symbol or a smart quote riding along with the "foreign"
        // characters means this is a mangled Bengali slug, not a takeover — CONTRACT rule 5.
        if (MOJIBAKE.test(dec)) continue;
        FOREIGN_G.lastIndex = 0;
        const fchars = dec.match(FOREIGN_G);
        const hit = !!(fchars && fchars.length >= 4);
        if (!hit || fseen.has(seg)) continue;
        fseen.add(seg);
        if (fsamp.length < 2) fsamp.push(u);
      }
      // n>=5 DISTINCT slugs. One or two are a stray import or an old translated page; five is a
      // deliberate publishing pattern, and the injection always produces hundreds.
      if (fseen.size >= 5) {
        push("L32FOREIGNSLUG", `sitemap publishes ${fseen.size} non-Bengali/Latin-script URLs: ` + fsamp.join(" ; "), fsamp[0] || base + "/");
      }
    }

    // NOT IMPLEMENTED, DELIBERATELY: a deep-recursion twin of the live L20SHAPE gibberish-slug test.
    // It was written, dry-run, and deleted. Over 116 confirmed-hacked sites it fired ZERO times — the
    // live L20SHAPE already catches everything it would have — while on the clean control it fired on
    // ajkerpatrika.com, whose Google Web Stories carry CMS-generated slugs like "ajp2ppvfpwnq1" that
    // are gibberish by every measure because a machine legitimately generated them. A layer with zero
    // marginal recall and a demonstrated false positive on a national newspaper is negative value at
    // any weight. Do not re-add it; if the shape test needs more URLs, widen L20SHAPE in scan.js.

    // =====================================================================
    // P21 · L33VOLUME — sitemap volume against site size.
    // =====================================================================
    // THRESHOLDS, AND WHY A DARAZ-SCALE BD SHOP STAYS SILENT.
    //   * bizType exclusion (news/ecommerce/government) is the primary defence and is mandatory. A real
    //     catalogue site classifies as ecommerce off its own homepage copy — "order now", "cash on
    //     delivery", "wholesale" — and never reaches this code at all.
    //   * 3000 URLs is the floor from the proposal, kept.
    //   * <15 distinct internal homepage links is the real discriminator. Any site that legitimately
    //     publishes thousands of pages has a navigation to reach them: a category menu, a footer
    //     sitemap, a news river. Measured on the clean BD control the median homepage carries well over
    //     40 internal links; under 15 means a brochure site. A doorway farm bolted onto a 12-page
    //     trading-company site has the trading company's tiny nav and 18,000 orphan URLs.
    //   * >=200 URLs per homepage link. Belt and braces on the same idea, expressed as a ratio so that
    //     a slightly-bigger brochure site does not tip over just for crossing 3000.
    // Even with all four satisfied the weight is [0.60, 0.100] — ratio 6, in a bucket it shares with
    // every keyword layer here, so it can nudge a domain into review and can never confirm one.
    const homeLinks = (() => {
      const s = new Set();
      let g = 0;
      for (const m of bodyB.matchAll(/<a\b[^>]+href=["']([^"'#]+)["']/gi)) {
        if (g++ > 3000) break;
        let h = m[1].trim();
        if (!h || /^(mailto|tel|javascript|data):/i.test(h)) continue;
        if (/^https?:\/\//i.test(h)) { if (!mine(h)) continue; h = h.replace(/^https?:\/\/[^/]+/i, ""); }
        else if (h.startsWith("//")) continue;
        h = h.split(/[?#]/)[0].replace(/\/+$/, "");
        if (h && h !== "/") s.add(h.toLowerCase());
      }
      return s.size;
    })();
    // Two independent publisher tests, either of which exempts the site. bizType reads the homepage
    // and is defeated by SPAs and by Bengali-only copy; PUBLISHER_SMAP reads the sitemap tree and is
    // not. Neither is sufficient alone — see the note at PUBLISHER_SMAP for the Prothom Alo case.
    const bulkBiz = BULK_BIZ.has(bizType) || PUBLISHER_SMAP.test(sm.slice(0, 200000));
    const volAnom = !bulkBiz && pages.length >= 3000 && homeLinks < 15 && pages.length >= homeLinks * 200;
    if (volAnom) {
      push("L33VOLUME", `${pages.length} sitemap URLs behind a ${homeLinks}-link homepage (${bizType || "general-business"})`, base + "/");
    }

    // =====================================================================
    // P22 · L34LASTMOD — mass-injection burst.
    // =====================================================================
    // Mass injection writes thousands of posts in one night. So does a site migration and so does a
    // bulk product import, and no threshold can fully separate them — hence the weakest weight in the
    // module and the three structural gates:
    //   1. Same publisher exclusion as P21 (bizType OR news/dated sitemap tree).
    //   2. The site must have a LONG TAIL: its oldest lastmod at least a year before the burst. A
    //      migration or a CMS regeneration re-stamps EVERY url with today's date, so its oldest and
    //      newest collapse to the same day and this gate rejects it. That is the whole trick.
    //   3. The burst must be a MINORITY (<=70%) of dated URLs. If nearly everything moved at once it
    //      is a regeneration, not an injection sitting inside an otherwise normal history.
    //   4. The burst must be RECENT (<=540 days). See BURST_MAX_AGE_DAYS — this is the gate that
    //      silenced prothomalo.com's 2022 burst, and it is honest on its own terms: an eight-year-old
    //      publishing spike is not evidence that a site is hacked today, which is the only claim we
    //      are entitled to sell.
    // 200 URLs in a 72h window, from the proposal. Deliberately not lowered: a small shop posting a
    // 40-product batch on a Friday is a completely normal thing to do.
    const days = [];
    let gl = 0;
    for (const m of sm.matchAll(/<lastmod>\s*(\d{4}-\d{2}-\d{2})/gi)) {
      if (gl++ >= MAX_LOCS) break;
      const t = Date.parse(m[1] + "T00:00:00Z");
      if (!isNaN(t)) days.push(Math.floor(t / DAY));
    }
    if (!bulkBiz && days.length >= 400) {
      const hist = new Map();
      for (const d of days) hist.set(d, (hist.get(d) || 0) + 1);
      const keys = [...hist.keys()].sort((a, b) => a - b);
      const oldest = keys[0];
      let burst = 0, burstDay = 0;
      for (const k of keys) {
        // 72h window = the day plus the two following it.
        const n = (hist.get(k) || 0) + (hist.get(k + 1) || 0) + (hist.get(k + 2) || 0);
        if (n > burst) { burst = n; burstDay = k; }
      }
      const tailYears = (burstDay - oldest) / 365;
      const burstAge = Math.floor(Date.now() / DAY) - burstDay;
      if (burst >= 200 && tailYears >= 1 && burst <= days.length * 0.7 && burstAge <= BURST_MAX_AGE_DAYS) {
        const iso = new Date(burstDay * DAY).toISOString().slice(0, 10);
        push("L34LASTMOD", `${burst} of ${days.length} sitemap URLs were all written within 72h of ${iso}, on a site publishing since ${new Date(oldest * DAY).toISOString().slice(0, 10)}`, base + "/");
      }
    }
  } catch (e) { return out; }
  return out;
}
