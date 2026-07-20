// wpprobe.js — CMS content probes that still work when /wp-json is blocked (P16 · P17 · P18 · P43).
//
// WHY THIS MODULE EXISTS: L11REST (0.88/0.010) is the strongest doorway layer in the detector, and on
// every site that has hardened /wp-json — a one-line snippet in a dozen "WordPress security" blog posts,
// and the default in Wordfence/iThemes lockdown presets — it is *entirely dead*. The site still publishes
// the exact same injected posts; we simply stop asking through the one door that is bolted. This module
// asks through three other doors that hardening guides almost never mention (RSS, the REST *search*
// endpoint, the front-end search form) and then, on the VM only, fetches the doorway page itself so the
// outreach message quotes the spam verbatim instead of describing a slug.
//
// BUCKET DISCIPLINE — read this before adding a layer here. Every layer in this file emits into
// `content-enum`, the same bucket as the live L11REST. That is deliberate and non-negotiable: the feed,
// the REST search index and the front-end search all answer ONE question ("does this site's own CMS
// content contain injected spam?") and on a real victim they all answer it by finding the SAME injected
// post. Giving them separate buckets would let one doorway post multiply into three independent-looking
// buckets and push the posterior past the confirm line off a single observation — the precise arithmetic
// that produced the 331-junk-lead incident. Same fact, one bucket. The fuser then takes the strongest
// layer, which is exactly the intended behaviour: verbatim body proof (L52) supersedes a slug guess.
//
// FP DISCIPLINE: these leads are sold to real Bangladeshi schools and SMBs. Every gate below was chosen
// at the point the clean-BD control stopped producing hits, not at the point recall stopped improving.

// Mixed-tier module. P16/P17/P18 are t1 (they are the *replacement* for a dead t1 layer, so deferring
// them to the VM would leave the Worker fleet exactly as blind as it is today). P43 is t2 and is gated
// internally on ctx.deep — a module only gets one TIER, same arrangement as cloak.js.
export const TIER = "t1";

// Bayesian [P(fires | hacked), P(fires | clean)].
export const WEIGHTS = {
  // P16. Conditioned on hacked, this fires well short of certainty: the site must have a feed at all,
  // it must be reachable, and the injected posts must be recent enough to sit in the (usually 10-item)
  // window. The clean rate is low but NOT zero — a feed is publisher-controlled text, so it inherits
  // every ambiguity of a headline. The news-outlet guard below is what keeps it at 0.008.
  L29FEED: [0.45, 0.008],
  // P16-title (SPLIT OUT IN REVIEW). A feed-item TITLE hit is NOT the same quality of evidence as a
  // published spam PERMALINK and must not be priced as if it were.
  //   * A permalink path is structural: no editorial process produces /slot-gacor-terbaik-2024/.
  //   * A title is publisher prose, and `casin[oò]` in signatures.js is UNBOUNDED — ordinary English
  //     "Casino" is a STRONG token. A BD site running one story or blog post about the betting-app
  //     crackdown carries it legitimately.
  // The "0/663 clean" measurement CANNOT price this half, and content.js already documents why in
  // detail: clean-bd.txt is the set the LIVE detector marked clean, and the live detector flags
  // anything carrying a STRONG token, so a clean BD site that merely *mentions* casino/betting is
  // excluded from the control BY CONSTRUCTION. content.js sets the floor for STRONG-vocabulary
  // layers at 0.020 for exactly this reason (see its L36META note). Same floor here. Ratio 20 —
  // corroborating evidence, structurally unable to confirm a lead on its own.
  L29FEEDTITLE: [0.40, 0.020],
  // P16b. Foreign-script post titles on a site whose homepage is Bengali/English. Weakest layer here:
  // the same assertion as the live L20SCRIPT, just read out of RSS instead of REST, so it is capped at
  // the same modest confidence. Never confirms alone.
  L29FEEDFOREIGN: [0.40, 0.012],
  // P17. Three gates stand between a clean site and this layer: X-WP-Total > 0, the NONCE_TERM
  // control proving the search filter is not being ignored, and the term re-found at a word boundary
  // in text we can see. Requiring all three cost 6 of 9 raw header hits on the confirmed set — every
  // one of them a substring artefact — so the survivors are worth 0.006 rather than the ~0.03 the
  // header alone would deserve.
  L30WPSEARCH: [0.60, 0.006],
  // P18. Structurally weaker than P17 because a front-end search page is theme-rendered HTML rather
  // than a filtered index, so the reflection problem is real and the match is restricted to permalink
  // PATHS. Measured 0 hits across both clean controls; declared at 0.010 anyway, because "never
  // observed on 2k domains" bounds the rate near 1/2000, not at zero.
  L31SEARCH: [0.50, 0.010],
  // P43. The doorway page itself, fetched and read. This is the layer that earns its keep: the match
  // is a quotable sentence from the victim's own URL, not an inference from a slug. Still not HARD —
  // promotion into HARD is P44's decision and belongs in scan.js, not here.
  //
  // 0.004 → 0.006 (REVIEW). 0.004 was inconsistent with this file's own arithmetic: L52 fires on a
  // SUPERSET of L29FEED's triggers (every doorway candidate, including the title hits L29FEED refuses
  // to emit on and the "wp-search-unproven" URLs), so it cannot honestly be declared half of
  // L29FEED's clean rate. It is held near-strong only because the review added a keyword-soup gate
  // below: an editorial mention of one brand no longer qualifies as a doorway body.
  L52DOORBODY: [0.86, 0.006],
};

// Only the foreign-script layer gets a fixed category. The keyword layers deliberately have none, so
// S.categoryOf() derives gambling/pharma/adult from the matched token — always more accurate than a
// label pinned on the transport we happened to read it through.
export const CATS = {
  L29FEEDFOREIGN: "foreign_lang",
};

// ---------------------------------------------------------------------------
// P17 vocabulary. WordPress search is a full-text `LIKE '%term%'` over post_title, post_excerpt AND
// post_content. That is a SUBSTRING match with no word boundary anywhere in it, which makes the
// English half of the Bengali-word trap: a term is not safe because it is meaningless in English,
// it is safe only if no ordinary word CONTAINS it.
//
// MEASURED, not assumed. Probing the live corpus turned up both halves of the trap:
//   `gacor`  is a substring of **megacorp** — X-WP-Total said 6 on dailytrust.com and every match
//            was the phrase "Megacorp, a reputable company" in ordinary news copy. Worse, the live
//            queue itself contains **megacorpagro.com**, a real BD agro business whose own NAME
//            carries the token on every page it publishes.
//   `togel`  is a substring of **autogel / Autogelle / protogel** (Protogel is a lab reagent — a BD
//            chemical or lab-supply firm would match on its own product list).
// Both are exactly the "tell a real Bangladeshi business it is hacked" failure. The leading-boundary
// guard in boundedHit() below is therefore mandatory, not defensive tidiness.
//
// REJECTED for this probe, and the reasoning matters more than the list:
//   `maxwin`             — dropped after the above. "Maxwin" is also a legitimate trading-company
//                          name, and unlike gacor/togel a leading boundary does NOT save it because
//                          the brand starts the word. Its marginal recall was one site that
//                          L52DOORBODY caught anyway.
//   `viagra` / `kamagra` — a BD online pharmacy can legitimately publish a product page for either.
//                          Fine as evidence in a page BODY we already suspect; fatal as a search key
//                          that promotes an otherwise-clean pharmacy into the lead list.
//   `casino` / `slot`    — GAMB_WEAK for good reason. Substring-matches "slot" in "slotted",
//                          and BD news outlets report on casino raids constantly.
//   `judi` / `situs`     — multi-word in practice ("situs judi"); modern WP ANDs space-separated
//                          terms, and the bare halves collide (Indonesian `judi`, Latin `situs`).
//   `bet` anything       — the sylhet/cabinet/alphabet substring trap, same as SPAMMY_DOMAIN.
const SEARCH_TERMS = ["gacor", "togel", "sbobet"];

// Nonsense token used to prove the `search` parameter is actually honoured. A broken or
// aggressively-cached REST install that IGNORES ?search= returns its full post count in X-WP-Total,
// which without this control would fire L30WPSEARCH on every single WordPress site on the internet.
// This is the difference between a probe and a random number generator.
const NONCE_TERM = "zqxjvkbnwpq";

const MAX_FEED_ITEMS = 60;
const MAX_DOORWAY_FETCHES = 3;

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------

const RE_ITEM = /<(item|entry)\b[\s\S]{0,8000}?<\/\1>/gi;
const RE_CDATA = /<!\[CDATA\[([\s\S]*?)\]\]>/;

function ent(s) {
  return String(s || "")
    .replace(/&amp;/gi, "&").replace(/&lt;/gi, "<").replace(/&gt;/gi, ">")
    .replace(/&quot;/gi, '"').replace(/&#0*39;|&apos;/gi, "'")
    .replace(/&#8217;|&rsquo;/gi, "'").replace(/&nbsp;/gi, " ")
    .replace(/&#(\d{2,5});/g, (m, d) => { try { return String.fromCodePoint(Number(d)); } catch (e) { return " "; } })
    .replace(/\s+/g, " ").trim();
}

function tagText(block, tag) {
  const m = new RegExp("<" + tag + "[^>]*>([\\s\\S]*?)</" + tag + ">", "i").exec(block);
  if (!m) return "";
  const c = RE_CDATA.exec(m[1]);
  return ent(c ? c[1] : m[1]);
}

// Atom puts the permalink in an attribute, RSS in element text. Try both.
function itemLink(block) {
  const t = tagText(block, "link");
  if (/^https?:\/\//i.test(t)) return t;
  const a = /<link[^>]*\bhref=["']([^"']+)["']/i.exec(block);
  if (a && /^https?:\/\//i.test(a[1])) return ent(a[1]);
  const g = tagText(block, "guid");
  return /^https?:\/\//i.test(g) ? g : "";
}

// Path only, query stripped. Stripping the query is load-bearing for P18: WordPress pagination and
// the search form itself carry `?s=gacor`, so a naive href test would match the term we just sent.
function pathOf(u) {
  try {
    const url = new URL(u);
    return url.pathname || "/";
  } catch (e) {
    const s = String(u || "").replace(/^https?:\/\/[^/]*/i, "").split(/[?#]/)[0];
    return s || "/";
  }
}

// Leading-boundary check against the SIGNATURE LIBRARY's own unbounded tokens.
//
// ALL_STRONG is not uniformly boundary-anchored: `\bgacor\b` is anchored but `togel`, `casin[oò]`
// and `porn` are bare, so a raw ALL_STRONG test matches inside autogel / Autogelle / protogel and
// inside megacorp. signatures.js is shared by every layer and is another agent's file this cycle, so
// the guard lives here: accept a match only when the character immediately before it is not an ASCII
// letter. Real spam always writes these tokens at the start of a word, so nothing genuine is lost.
//
// The test is ASCII-only ON PURPOSE. Chinese, Japanese and Thai are written without spaces, so
// `赌场` or `คาสิโน` is routinely glued to the character before it; a script-agnostic boundary test
// would silently disable every CJK/Thai token in the library.
function boundedHit(text, rxG) {
  const t = String(text || "");
  if (!t) return null;
  // A private copy, never rxG itself. S.REG.* are module-level /g regexes shared by every layer and
  // every domain in the batch, and .exec() on a /g regex mutates lastIndex — reusing the shared
  // object here would make this function's result depend on whichever layer scanned the previous
  // domain. That class of bug is invisible in a single-domain test and only shows up at scale.
  const rx = new RegExp(rxG.source, rxG.flags.includes("g") ? rxG.flags : rxG.flags + "g");
  rx.lastIndex = 0;
  let m, guard = 0;
  while ((m = rx.exec(t)) && guard++ < 400) {
    const prev = m.index > 0 ? t[m.index - 1] : "";
    if (!/[A-Za-z]/.test(prev)) return m;
    if (rx.lastIndex <= m.index) rx.lastIndex = m.index + 1;
  }
  return null;
}

// Same guard for a single plain search term (P17), which is not part of the signature library.
function termBounded(text, term) {
  return new RegExp("(?:^|[^A-Za-z0-9])" + term, "i").test(String(text || ""));
}

// SLUG_SPAM carries two tokens this module refuses to trust ALONE on a URL path. The leading-boundary
// guard in boundedHit() does not save either of them, because in both cases the innocent word STARTS
// with the token:
//   `situs`  — "situs inversus" / "situs inversus totalis" is standard clinical vocabulary. A BD
//              hospital or diagnostic centre publishing a case report at /blog/situs-inversus-totalis/
//              is a perfectly clean site, and healthcare is one of the biggest categories in the queue.
//   `maxwin` — this file's own SEARCH_TERMS block already rejects it in writing ("Maxwin is also a
//              legitimate trading-company name, and unlike gacor/togel a leading boundary does NOT save
//              it"). That reasoning was then not applied to the path test, which used the same token
//              through SLUG_SPAM. Applying it here makes the module internally consistent.
// A genuine Indonesian doorway slug never carries one of these alone — it is always glued to a second
// spam token (/situs-judi-bola/, /situs-slot-gacor/, /maxwin-slot88/). Requiring that second token
// costs no measurable recall and removes both BD counter-examples.
// Tokens that are real words/brands outside the spam context and that the leading-boundary guard
// cannot rescue, because the innocent word BEGINS with them. Never evidence on their own — in a title
// they need a second distinct strong token, in a path a second spam token.
//   `maxwin`  — "Maxwin Trading Ltd" (see SEARCH_TERMS rejection above).
//   `situs`   — "situs inversus", standard clinical vocabulary (path only; ALL_STRONG carries `situs`
//               only in the bounded phrases situs judi/slot/toto, never bare).
//   `pg soft` — `pg ?soft` in GAMB_STRONG matches "PG Software", an ordinary phrase for a BD IT firm.
const SOFT_TOKEN = /^(?:situs|maxwin|pg ?soft)$/i;
const SOFT_SLUG = SOFT_TOKEN;
const HARD_SLUG = /\bjudi|togel|\bgacor|sbobet|\bpkv\b|slot|toto|918kiss|pussy888|mega888|mahjong|pragmatic|joker123|sabung|bandar|bocoran|taruhan/i;

// Bounded SLUG_SPAM test for a URL PATH. Returns the match, or null.
function pathSpam(S, p) {
  const m = boundedHit(p, S.RE.SLUG_SPAM);
  if (!m) return null;
  if (SOFT_SLUG.test(m[0]) && !HARD_SLUG.test(p)) return null;
  return m;
}

// Bounded ALL_STRONG test for PROSE (feed titles, page bodies). Rejects a hit whose ONLY strong token
// is a SOFT_TOKEN — "Maxwin Trading annual report 2026" is a company filing, not a doorway.
function proseSpam(S, text) {
  const m = boundedHit(text, S.REG.ALL_STRONG);
  if (!m) return null;
  if (!SOFT_TOKEN.test(m[0])) return m;
  return boundedDistinct(text, S.REG.ALL_STRONG, 3).length >= 2 ? m : null;
}

// Distinct BOUNDED spam tokens in a body — ctx.distinct() cannot be used because it has no boundary
// guard and would count "megacorp"/"protogel" as tokens. Cheap: one pass, hard-capped.
function boundedDistinct(text, rxG, cap) {
  const t = String(text || "");
  const rx = new RegExp(rxG.source, rxG.flags.includes("g") ? rxG.flags : rxG.flags + "g");
  rx.lastIndex = 0;
  const out = new Set();
  let m, guard = 0;
  while ((m = rx.exec(t)) && guard++ < 400 && out.size < cap) {
    const prev = m.index > 0 ? t[m.index - 1] : "";
    if (!/[A-Za-z]/.test(prev)) out.add(m[0].toLowerCase());
    if (rx.lastIndex <= m.index) rx.lastIndex = m.index + 1;
  }
  return [...out];
}

// ≤200-char verbatim window around the first BOUNDED match — shown verbatim to the business owner.
function proofNear(text, rxG) {
  const t = String(text || "");
  const m = boundedHit(t, rxG);
  if (!m) return "";
  const i = Math.max(0, m.index - 70);
  return t.slice(i, i + 190).replace(/\s+/g, " ").trim();
}

export async function run(ctx) {
  const out = [];
  try {
    const S = ctx.S;
    const reg = ctx.reg;
    const base = ctx.base;
    const B = ctx.B;
    const bodyB = (B && B.text) || "";
    const visB = ctx.visB || "";
    if (!base || !reg || !bodyB) return out;

    // ctx.budget is SHARED across every module and this one is 8th of 10, ahead of cloak.js and
    // deep.js. Left uncapped it can legitimately spend 9 of the deep tier's 14 fetches (feed + 3
    // search terms + control + front-search + 3 doorways) and starve cloak.js — which owns the
    // cloak-diff bucket, i.e. the SECOND bucket a lead needs to reach CONFIRM_CANDIDATE. Self-cap so
    // a probe module can never crowd out a stronger one.
    let spent = 0;
    const MAX_SPEND = 6;
    const spend = (n) => {
      if (ctx.overBudget && ctx.overBudget()) return false;
      if (spent + n > MAX_SPEND) return false;
      if (ctx.budget && typeof ctx.budget.fetches === "number") {
        if (ctx.budget.fetches < n) return false;
        ctx.budget.fetches -= n;
      }
      spent += n;
      return true;
    };
    const push = (layer, match, url) => {
      const m = String(match || "").replace(/\s+/g, " ").trim().slice(0, 200);
      if (m) out.push({ bucket: "content-enum", layer, match: m, url: String(url || base).slice(0, 300) });
    };
    const mine = (u) => { try { return ctx.sameHost(ctx.hostOf(u), reg); } catch (e) { return false; } };

    // A BD news outlet reporting "মেলবেট-বাবু৮৮ অ্যাপে জুয়া, গ্রেপ্তার ৫" puts a GAMB_STRONG brand in
    // its own headline as journalism. That is the one realistic way a clean BD site produces a
    // spam-keyword post title, and it is not hypothetical — betting-app arrests are a recurring BD
    // news beat. For news sites we therefore ignore titles entirely and accept only the URL-path
    // evidence below, which journalism cannot produce.
    const bizType = (() => {
      try { return S.bizType(reg, (bodyB.match(/<title[^>]*>([\s\S]*?)<\/title>/i) || ["", ""])[1] || "", visB); }
      catch (e) { return ""; }
    })();
    const isNews = bizType === "news";

    // Homepage script baseline for the foreign-title layer. A genuinely Japanese-language site is
    // exempt from being told its Japanese posts are a takeover (CONTRACT.md rule 5's sibling case).
    const homeForeign = (() => { try { return S.RE.FOREIGN.test(visB.slice(0, 6000)); } catch (e) { return true; } })();

    const wpish = /wp-content|wp-includes|\/wp-json|rel=["']https:\/\/api\.w\.org/i.test(bodyB);
    const doorways = [];              // {url, why} candidates for P43
    const seenDoor = new Set();
    const addDoor = (u, why) => {
      if (!u || !mine(u) || seenDoor.has(u) || doorways.length >= 12) return;
      // THE JOURNALISM GUARD HAD A BACK DOOR (found in review). The isNews test below suppressed the
      // L29FEED *emit* for a title hit — but the very same title hit still queued its article as a
      // P43 doorway, and L52DOORBODY, the STRONGEST layer in this file, has no isNews test of its own.
      // On a BD outlet's own report of a betting-app arrest the article body of course contains the
      // brand verbatim, so L52 would fetch that article, quote the journalism, and emit at ratio ~143
      // — re-manufacturing on the strongest path exactly the lead the guard exists to prevent, and
      // with a "verbatim proof" quote that makes it look better-evidenced than a slug guess.
      // Only URL-PATH evidence, which journalism cannot produce, may send a news site to a body read.
      if (isNews && /^(?:feed-title|wp-search-unproven)/.test(String(why || ""))) return;
      seenDoor.add(u); doorways.push({ url: u, why });
    };

    // =====================================================================
    // P16 · L29FEED — RSS/Atom item titles and links.
    //
    // The feed URL is taken from the homepage's own <link rel="alternate"> autodiscovery tag wherever
    // possible rather than guessed. That single detail is why this works on Joomla, Drupal, Blogger and
    // custom CMSes and not only on WordPress: we ask the site where its feed is instead of assuming
    // /feed/ and burning a request on a 404.
    // =====================================================================
    let feedUrl = "";
    // [^>]{0,400}, NOT [^>]+ (bounded in review, same reasoning cloak.js already documents for its
    // anchor scan). This runs over HTML written by whoever owns the hacked site: with an unbounded
    // quantifier every `<link` opener in a document with no `>` rescans to EOF, and the cost is burned
    // INSIDE a single .exec() where the iteration guard cannot reach it. On the free plan that is the
    // documented 1102 CPU wall. Real <link> tags are far under 400 chars.
    const auto = /<link[^>]{0,400}type=["']application\/(?:rss|atom)\+xml["'][^>]{0,400}>/gi;
    const headHay = bodyB.slice(0, 96000);
    let am, ag = 0;
    while ((am = auto.exec(headHay)) && !feedUrl && ag++ < 40) {
      const h = /href=["']([^"']+)["']/i.exec(am[0]);
      if (!h) continue;
      let u = h[1];
      if (u.startsWith("//")) u = "https:" + u;
      else if (u.startsWith("/")) u = base + u;
      // Comment feeds are noise — they carry commenter text, not published posts.
      if (/comments?\/feed|\/comments\b/i.test(u)) continue;
      if (mine(u)) feedUrl = u;
    }
    if (!feedUrl && wpish) feedUrl = base + "/feed/";

    if (feedUrl && spend(1)) {
      try {
        const F = await ctx.fetchPage(feedUrl, ctx.UA_GB, null, 9000);
        const ft = (F && F.text) || "";
        // Require actual feed markup. A 200-returning "soft 404" HTML page would otherwise be scanned
        // as if it were the feed, and its nav menu is not published content.
        if (F && F.status === 200 && /<rss|<feed\b|<rdf:RDF/i.test(ft.slice(0, 4000))) {
          const items = ft.match(RE_ITEM) || [];
          let foreignT = 0, totalT = 0;
          const titleHits = [], pathHits = [];
          for (const blk of items.slice(0, MAX_FEED_ITEMS)) {
            const title = tagText(blk, "title");
            const link = itemLink(blk);
            if (title) {
              totalT++;
              if (S.RE.FOREIGN.test(title)) foreignT++;
              if (proseSpam(S, title)) { titleHits.push({ title, link }); addDoor(link, "feed-title"); }
            }
            // The item LINK is the strong half. A path segment like /slot-gacor-terbaik-2024/ is a
            // published permalink on the victim's own domain — no editorial process produces that.
            // SLUG_SPAM carries the same unbounded `togel` / `situs` tokens as ALL_STRONG, so it goes
            // through the boundary guard too: `/protogel-reagent/` is a lab product, not a lottery.
            // Real spam slugs are hyphen-separated, so the token always follows `/` or `-` and passes.
            if (link && mine(link) && pathSpam(S, pathOf(link))) {
              pathHits.push(link); addDoor(link, "feed-slug");
            }
          }
          if (pathHits.length) {
            push("L29FEED", "published post URL: " + pathHits.slice(0, 2).map(pathOf).join(" ; "), pathHits[0]);
          } else if (titleHits.length && !isNews) {
            // Separate layer id, NOT L29FEED (review). Same bucket, so the fuser still keeps only the
            // strongest — but a headline that says "casino" is now priced as the corroborating
            // evidence it is instead of borrowing a published-permalink's likelihood ratio.
            const h = titleHits[0];
            push("L29FEEDTITLE", "feed item title: " + h.title, h.link || feedUrl);
          }
          // >=4 foreign-script titles out of a mostly-non-foreign feed, on a site whose homepage is
          // not in that script. Threshold corrected to 30% in review: the comment claimed "same
          // threshold as the live L20SCRIPT" but the live gate is `foreign*100 < total*30` and this
          // said 60 — twice as loose, at a weight justified by the tighter number. At 60% a BD
          // garments exporter or trading house running a Chinese-language product section for its
          // buyers (4 of 8 recent posts) fired; at 30% it does not.
          if (!homeForeign && foreignT >= 4 && totalT && foreignT * 100 < totalT * 30) {
            push("L29FEEDFOREIGN", "foreign-script post titles in own feed: " + foreignT + "/" + totalT, feedUrl);
          }
        }
      } catch (e) { /* no feed / blocked — expected on plenty of healthy sites */ }
    }

    // =====================================================================
    // P17 · L30WPSEARCH — REST search, X-WP-Total header only.
    //
    // Answers "does ANY post body on this site contain `gacor`" in one request, where L11REST has to
    // page through up to 400 posts and still only sees slugs and titles. Note the ordering: the
    // ignored-parameter control (NONCE_TERM) is issued ONLY after a positive, so its cost is paid on
    // the rare true-positive path and effectively never on a clean site.
    // =====================================================================
    let restReachable = false;
    if (wpish) {
      const terms = ctx.deep ? SEARCH_TERMS : SEARCH_TERMS.slice(0, 1);
      let hitTerm = "", hitLink = "", hitTitle = "";
      for (const term of terms) {
        if (hitTerm) break;
        if (!spend(1)) break;
        try {
          // _fields carries the excerpt so the boundary re-check below costs no extra request.
          const q = `${base}/wp-json/wp/v2/posts?search=${term}&per_page=1&_fields=link,title,excerpt`;
          const R = await ctx.fetchPage(q, ctx.UA_GB, null, 9000);
          if (!R || R.status !== 200 || !R.headers) continue;
          const tot = R.headers.get("x-wp-total");
          if (!tot || !/^\d+$/.test(tot)) continue;
          restReachable = true;                     // REST answered → P18 is redundant, skip it
          if (Number(tot) <= 0) continue;
          let link = "", title = "", excerpt = "";
          try {
            const arr = JSON.parse(R.text || "[]");
            if (Array.isArray(arr) && arr[0]) {
              link = String(arr[0].link || "");
              const t = arr[0].title, x = arr[0].excerpt;
              title = String((t && (t.rendered ?? t)) || "").replace(/<[^>]+>/g, " ").trim();
              excerpt = String((x && (x.rendered ?? x)) || "").replace(/<[^>]+>/g, " ").trim();
            }
          } catch (e) { /* shape varies across WP versions — absence just means no cheap proof */ }
          // The match X-WP-Total counted may be a SUBSTRING artefact (megacorp / autogel), so the
          // term must be re-found at a word boundary in text we can actually see before this
          // becomes a signal. When it cannot be — the classic case is spam injected deep into an
          // existing post's body, past the excerpt — we do NOT emit on the header. The URL becomes
          // a P43 candidate instead and the tier-2 body read decides. Cheap probe, earned proof.
          const visible = `${title} ${excerpt} ${ent(link)}`;
          if (termBounded(visible, term)) { hitTerm = term; hitLink = link; hitTitle = ent(title); }
          else addDoor(link, "wp-search-unproven:" + term);
        } catch (e) { /* not WP / REST blocked */ }
      }

      if (hitTerm) {
        // The control. If a term that cannot exist anywhere also reports >0, this install is not
        // filtering on `search` and its X-WP-Total is a post count, not an answer. Emit nothing.
        let honest = true;
        if (spend(1)) {
          try {
            const C = await ctx.fetchPage(`${base}/wp-json/wp/v2/posts?search=${NONCE_TERM}&per_page=1&_fields=link`, ctx.UA_GB, null, 8000);
            const ct = C && C.headers ? C.headers.get("x-wp-total") : null;
            if (!ct || !/^\d+$/.test(ct) || Number(ct) > 0) honest = false;
          } catch (e) { honest = false; }
        } else {
          honest = false;   // could not afford the control → refuse to emit rather than guess
        }
        if (honest) {
          // A multisite or mirrored install can answer with permalinks on a DIFFERENT registrable
          // (measured: chemwhat.com.bd returns www.chemwhat.com links). Never hand outreach a proof
          // URL that does not belong to the business we are about to contact.
          const proofUrl = hitLink && mine(hitLink) ? hitLink : `${base}/wp-json/wp/v2/posts?search=${hitTerm}`;
          push("L30WPSEARCH", `site's own post index matches "${hitTerm}"` + (hitTitle ? ' — "' + hitTitle + '"' : ""), proofUrl);
          addDoor(hitLink, "wp-search:" + hitTerm);
        }
      }
    }

    // =====================================================================
    // P18 · L31SEARCH — front-end /?s=gacor, for sites where REST never answered.
    //
    // THE REFLECTION TRAP: essentially every theme prints the query back ("Search Results for: gacor",
    // "Nothing found for gacor"), and the search form's own value attribute and every pagination href
    // carry `?s=gacor`. Matching the raw HTML would make this probe self-fulfilling on 100% of
    // WordPress sites — the single worst failure mode available in this file. The match is therefore
    // restricted to the PATH of a same-host permalink, with the query string stripped before testing.
    // A path segment cannot be produced by echoing our query; it can only exist because the site
    // published a post at that URL. Anchor TEXT is deliberately NOT matched: <mark>-highlighted
    // excerpts put the reflected term inside result anchors on several popular themes.
    // =====================================================================
    // `wpish || feedUrl` is budget discipline, not detection logic: without it every static brochure
    // site in the queue — a large share of BD SMBs, with no CMS and nothing to enumerate — would pay
    // one request to ask a search engine it does not have. Tier-1 spends nothing on those.
    if ((wpish || feedUrl) && !restReachable && !out.length && spend(1)) {
      try {
        const su = base + "/?s=gacor";
        const R = await ctx.fetchPage(su, ctx.UA_GB, null, 9000);
        const rt = (R && R.text) || "";
        if (R && R.status === 200 && rt) {
          const hits = [];
          // Bounded quantifiers + capped haystack, for the reason cloak.js measured at 2,633ms on a
          // 140KB input: `[^>]*` / `[^"']+` over attacker-authored HTML with unclosed tags rescans to
          // EOF from every `<a` position, and that cost is inside a single .exec() where the n<400
          // iteration guard never runs. This page is a search-results page on a possibly-hacked site.
          const ar = /<a\b[^>]{0,400}\bhref=["']([^"']{4,300})["']/gi;
          const hay = rt.slice(0, 96000);
          let m, n = 0;
          while ((m = ar.exec(hay)) && n++ < 400) {
            let u = m[1];
            if (u.startsWith("//")) u = "https:" + u;
            else if (u.startsWith("/")) u = base + u;
            if (!/^https?:\/\//i.test(u) || !mine(u)) continue;
            const p = pathOf(u);
            // The root path is what every reflected search link (`/?s=gacor`, `/page/2/?s=gacor`,
            // the form action) collapses to once the query is stripped. Requiring a real path
            // segment is what makes this probe evidence instead of an echo.
            if (p.length < 4) continue;
            if (pathSpam(S, p)) { hits.push(u); addDoor(u, "front-search"); }
          }
          const uniq = [...new Set(hits)];
          if (uniq.length) {
            push("L31SEARCH", "site search returns published spam URLs: " + uniq.slice(0, 2).map(pathOf).join(" ; "), uniq[0]);
          }
        }
      } catch (e) { /* no search / not a CMS — fine */ }
    }

    // =====================================================================
    // P43 · L52DOORBODY — [TIER 2] fetch the doorway page and read it.
    //
    // Everything above is an index talking about a page. This fetches the page. The difference is the
    // whole outreach pitch: "your site publishes https://yourschool.edu.bd/slot-gacor-2024/ which reads
    // 'Situs slot gacor terpercaya…'" versus "a slug looked odd". Fetched as Googlebot WITH the Google
    // referer because doorways routinely cloak — serving the real spam only to search traffic and a
    // 404 or a redirect to everyone else, which is exactly the condition under which the site owner
    // insists nothing is wrong.
    // =====================================================================
    if (ctx.deep && doorways.length) {
      let done = 0;
      for (const d of doorways) {
        if (done >= MAX_DOORWAY_FETCHES) break;
        if (!spend(1)) break;
        done++;
        try {
          const P = await ctx.fetchPage(d.url, ctx.UA_GB, ctx.REF_G, 9000);
          if (!P || P.status !== 200 || !P.text) continue;
          const vis = ctx.stripHtml(P.text);
          if (!vis || vis.length < 60) continue;
          // WAF interstitials and parked pages are not doorway bodies.
          if (S.RE.WAF.test(vis.slice(0, 1200))) continue;
          // KEYWORD-SOUP GATE (added in review). Without it this layer's assertion is only "a page on
          // this site contains a strong token somewhere in its text" — which is true of every clean BD
          // page that mentions the betting crackdown, a casino film, or a pharmacy product, and which
          // the 0/663 clean control provably cannot measure (that control is the set the LIVE detector
          // marked clean, and the live detector already excludes anything carrying a STRONG token —
          // see the same circularity argument written out in content.js's WEIGHTS block).
          // A real doorway body is keyword soup: "situs slot gacor terpercaya maxwin togel 2024".
          // Editorial prose carries ONE brand. So require either two distinct bounded tokens, or one
          // token that the site also put in the URL PATH — a site does not name its own article
          // /slot-gacor-2024/ by accident, and that is the case an editorial mention cannot reach.
          const toks = boundedDistinct(vis.slice(0, 96000), S.REG.ALL_STRONG, 4);
          if (!toks.length) continue;
          if (toks.length < 2 && !pathSpam(S, pathOf(d.url))) continue;
          const quote = proofNear(vis, S.REG.ALL_STRONG);
          if (!quote) continue;
          push("L52DOORBODY", "live page text: " + quote, d.url);
          break;   // one verbatim proof is what outreach needs; further fetches buy nothing
        } catch (e) { /* dead doorway — the index lied or the page was cleaned */ }
      }
    }
  } catch (e) { return out; }
  return out;
}
