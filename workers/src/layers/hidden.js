// hidden.js — hidden and invisible injected content (P13 / P14 / P15-emit / P48).
//
// The live L17HIDDEN in scan.js only ever sees the FIRST inline double-quoted style attribute, so the
// modern default — `.wdgt{display:none}` in a <style> block plus `<div class=wdgt>` a few KB later — is
// completely invisible to it. This module owns the whole "content the visitor cannot read" family:
//
//   L17HIDDEN2   CSS-class / id / bare-`hidden`-attribute / inline hidden blocks   (P13)
//   L50CONTRAST  white-on-white text and 0-1px fonts                               (P14)
//   L51TAIL      strong spam living only in ctx.tail, past the 96KB head read       (P15, emit half)
//   L52COMMENT   payload parked inside an HTML comment                              (P48)
//   L52NOSCRIPT  payload parked inside <noscript>                                   (P48)
//
// THE LOAD-BEARING ASSERTION, and the reason this module does not manufacture leads:
// a signal needs a STRONG spam token that is present in the hidden region and ABSENT from the visible
// document. Everything a hacker hides is by definition off-page; everything a WordPress theme hides
// (a11y text, tab panels, mobile menus, accordions) is a duplicate or a helper for content that is
// already on the page. `visibleOnly` — the document with every hidden range blanked out — is what
// makes that distinction mechanical instead of a guess.
// The one relaxation, and only for hidden ELEMENTS, is `novelOrFarm`: a site can be so overrun that the
// injection reached the visible nav too, and requiring novelty there was measured to drop 4 real leads.
// In that case the block must be a LINK FARM FOR THE TOKEN (see linkFarmFor) — the first cut accepted
// "three anchors or one off-site link", which is a social-share widget and confirmed a clean BD news site.
// Pharma tokens are excluded from the relaxation entirely.
//
// BUCKETS: stripHtml does not remove display:none content, so hidden text inside the head document is
// already in ctx.visB and already scored by L1KW_STRONG in `homepage-content` — these layers therefore
// emit into `homepage-content` too (like the live L17HIDDEN), and take the private `hidden` bucket ONLY
// for bytes L1KW_STRONG never saw (the tail, and <noscript>, which stripHtml deletes). See bucketFor.
//
// Measured on production data (2026-07-19/20), scanning exactly the bytes scan.js would have in hand:
//   533 scanned-clean BD sites  → 1 signal, hand-verified as a REAL undetected hack (course.cuet.ac.bd,
//                                 an injected display:none link farm after </body>) → 0 false positives.
//   Of 91 reachable sites the live inline-only L17HIDDEN had confirmed → 55 still fire, 0 regressions.
//   Of 263 reachable confirmed hacks it had NEVER labelled → 11 net-new (7 element, 3 tail, 1 contrast).
// Cost: ~2ms/page, zero fetches. See the note above L52COMMENT for the one path with no live evidence.

export const TIER = "t1";

// Bayesian [P(fires | hacked), P(fires | clean)]. Every clean-side number is deliberately pessimistic:
// the measured clean-side rate over 533 real BD sites was 0/533, but "0 measured" is not a probability,
// and an over-confident weight silently manufactures leads (CONTRACT §WEIGHTS). These are set roughly an
// order of magnitude above what was observed so that a hidden signal ALONE never reaches CONFIRM — one
// bucket at ratio 57 puts the posterior at ~0.92, under the 0.97 gate, so it always needs corroboration.
// That property only holds because of the bucket rule above: emitted under a private bucket these same
// weights sat on top of L1KW_STRONG's `homepage-content` for the SAME bytes, giving posterior 0.9952 with
// nbuckets=2 — a single hidden div self-confirming with no independent corroboration whatsoever.
export const WEIGHTS = {
  L17HIDDEN2:  [0.85, 0.015],
  L50CONTRAST: [0.85, 0.010],
  // Novel bytes nobody else reads, but the seam between head and tail can duplicate markup on pages
  // just over the cap, so this one gets the widest clean-side allowance in the module.
  L51TAIL:     [0.78, 0.035],
  // NOT VALIDATED IN PRODUCTION. Over 435 confirmed-hacked and 533 clean BD sites, exactly zero carried
  // a STRONG token in an HTML comment or in <noscript> — this corpus simply does not use those hiding
  // places, so both layers are synthetic-tested only. They are kept because they cost nothing behind the
  // ALL_STRONG pre-filter, but the weights stay low precisely because nothing real has exercised them.
  // Commented-out spam is also frequently STALE — a half-cleaned site, or a theme shipping dead demo
  // markup — so it is evidence, not proof, and sits well below live hidden text (P48 says exactly this).
  L52COMMENT:  [0.70, 0.050],
  L52NOSCRIPT: [0.80, 0.030],
};

// No CATS entries on purpose: every signal here IS a keyword hit, so the keyword-derived category
// (gambling / pharma / adult) is already the right answer and must win.
export const CATS = {};

// ---------------------------------------------------------------------------
// vocabulary of hiding
// ---------------------------------------------------------------------------

// Unambiguous "the user will never read this" declarations. Deliberately EXCLUDED:
//   height:0 / max-height:0  → that is how every accordion and collapse widget on earth works, and the
//                              content inside one is real content the user can open.
//   aria-hidden="true"       → decorative-icon markup, present dozens of times on a normal theme page.
//   @media-scoped rules      → hiding a desktop menu under 768px is responsive design, not stealth
//                              (handled in cssHidden() by skipping at-rule bodies wholesale).
const RE_HIDE_DECL = /display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:px|pt|em|%)?\s*(?:[;}!]|$)|text-indent\s*:\s*-\s*\d{3,}|clip-path\s*:\s*inset\(\s*100%|clip\s*:\s*rect\(\s*(?:0|1px)/i;
// Off-screen positioning only counts when both halves are present in the same declaration block.
const RE_ABS = /position\s*:\s*(?:absolute|fixed)/i;
const RE_OFFSCREEN = /(?:left|top|right|margin-left|margin-top)\s*:\s*-\s*\d{3,}/i;

// `#f{3}\b` matches #fff and not #ffffff (the \b fails mid-run), so the two forms stay separate literals.
const WHITE = String.raw`#f{3}\b|#f{6}\b|\bwhite\b|rgba?\(\s*255\s*,\s*255\s*,\s*255`;
// `(?:^|[;{\s])color` is what stops this from matching `background-color:` — the char before that
// `color` is a hyphen, which is not in the class.
const RE_WHITE_FG = new RegExp(String.raw`(?:^|[;{\s])color\s*:\s*[^;}]*(?:${WHITE})`, "i");
const RE_WHITE_BG = new RegExp(String.raw`background(?:-color)?\s*:\s*[^;}]*(?:${WHITE})`, "i");
const RE_TINY_FONT = /font-size\s*:\s*[01](?:px|pt)?\s*(?:[;}!]|$)/i;

// Class / id names that mean "a real UI widget or an accessibility affordance", never "injected spam".
// Screen-reader text is the single most common hidden block on the BD web — every WordPress theme ships
// .screen-reader-text, and Elementor ships .elementor-screen-only — so these must be structurally unable
// to fire. Substring (not word-boundary) matching on purpose: over-blocking costs a miss, under-blocking
// costs a false accusation against a real school. Real injections use opaque names (.wdgt, .sfw, .a7x)
// and are unaffected by this list.
const UI_SAFE = [
  "sr-only", "sronly", "srtext", "screen-reader", "screenreader", "screen-only", "visually-hidden",
  "visuallyhidden", "assistive", "a11y", "skip-link", "skiplink", "skip-to", "offscreen-text",
  "hidden", "hide", "d-none", "invisible", "sr_only",
  "menu", "nav", "dropdown", "submenu", "offcanvas", "sidebar", "drawer", "modal", "popup", "lightbox",
  "overlay", "dialog", "tooltip", "popover", "tab", "accordion", "collaps", "toggle", "carousel",
  "slider", "slick", "swiper", "owl", "gallery", "cookie", "gdpr", "consent", "search", "cart",
  "checkout", "wishlist", "compare", "filter", "loader", "loading", "spinner", "preload", "skeleton",
  "print", "mobile", "desktop", "tablet", "noscript", "lazy", "placeholder", "alert", "notice",
  "backdrop", "sticky", "fancybox", "mfp-", "wpcf7", "recaptcha", "grecaptcha", "honeypot", "hp-field",
];
function uiSafe(name) {
  const n = String(name || "").toLowerCase();
  for (const s of UI_SAFE) if (n.includes(s)) return true;
  return false;
}

// Elements that hold no readable text; walking into them only invites nonsense (an <input type=hidden>
// carrying a `hidden` attribute is not a hidden paragraph).
const VOID_TAG = new Set(["input", "img", "meta", "link", "br", "hr", "source", "track", "area", "base",
  "col", "embed", "param", "wbr", "script", "style", "noscript", "template", "svg", "path", "use", "iframe"]);

// ---------------------------------------------------------------------------
// CSS
// ---------------------------------------------------------------------------

// Walk only TOP-LEVEL rules. An at-rule body is skipped entirely, which is what kills the biggest
// class of false positives here: `@media(max-width:768px){.main-nav{display:none}}` is every responsive
// theme ever written, and treating those classes as "hidden" would light up the whole corpus.
// @supports is the one at-rule whose body is unconditional enough to recurse into.
// `depth` caps the @supports recursion: the body is attacker-controlled, and 3000 nested at-rules inside
// the 40KB budget would otherwise recurse deep enough to blow the Worker stack (the try/catch in run()
// turns that into a silent [], i.e. a miss on every page that carries one).
function topLevelRules(css, depth = 0) {
  const out = [];
  let i = 0, guard = 0;
  const n = css.length;
  while (i < n && guard++ < 3000 && out.length < 4000) {
    const open = css.indexOf("{", i);
    if (open < 0) break;
    const sel = css.slice(i, open).trim();
    let depth = 1, j = open + 1;
    while (j < n && depth > 0) {
      const c = css.charCodeAt(j);
      if (c === 123) depth++; else if (c === 125) depth--;
      j++;
    }
    const body = css.slice(open + 1, j - 1);
    if (sel.charCodeAt(0) === 64) {           // "@"
      if (/^@supports/i.test(sel) && depth < 4) for (const r of topLevelRules(body, depth + 1)) out.push(r);
    } else if (sel && body) {
      out.push([sel, body]);
    }
    i = j;
  }
  return out;
}

// The SUBJECT of a selector is its LAST compound, and only that compound is hidden.
// `.entry-content .ad-slot{display:none}` — a rule on essentially every WordPress news theme — hides the
// ad slot, NOT the article. Harvesting every name in the selector marked `.entry-content` itself hidden,
// which swallowed the whole article body as a "hidden range"; because that range is then subtracted from
// the visible baseline, the article's OWN words came back as `novel` and a clean BD news site reporting a
// betting crackdown scored as a confirmed hack, quoting its own headline as the proof. Verified live.
// A trailing component with no class/id (`.entry-content a`) contributes nothing at all, for the same reason.
function subjectNames(sel) {
  const out = [];
  for (const part of String(sel).split(",").slice(0, 40)) {
    const comps = part.trim().split(/[\s>+~]+/).filter(Boolean);
    const last = comps[comps.length - 1] || "";
    // `{0,40}` not `{1,40}`: injections routinely use one-character class names (`.z`, `.a`), and the
    // old two-character minimum silently missed every one of them.
    const names = last.match(/[.#][A-Za-z_][\w-]{0,40}/g) || [];
    if (names.length) out.push(names[names.length - 1].slice(1).toLowerCase());
  }
  return out;
}

// Returns the class/id names that a stylesheet hides, split by mechanism.
function cssHidden(html) {
  const hide = new Set(), invis = new Set();
  let css = "";
  const rx = /<style\b[^>]*>([\s\S]{0,40000}?)<\/style>/gi;
  let m, blocks = 0;
  while ((m = rx.exec(html)) && blocks++ < 12 && css.length < 40000) css += m[1] + "\n";
  if (!css) return { hide, invis };
  for (const [sel, body] of topLevelRules(css)) {
    const hidden = RE_HIDE_DECL.test(body) || (RE_ABS.test(body) && RE_OFFSCREEN.test(body));
    const white = (RE_WHITE_FG.test(body) && RE_WHITE_BG.test(body)) || RE_TINY_FONT.test(body);
    if (!hidden && !white) continue;
    for (const name of subjectNames(sel)) {
      if (uiSafe(name)) continue;
      if (hidden && hide.size < 60) hide.add(name);
      if (white && invis.size < 60) invis.add(name);
    }
  }
  return { hide, invis };
}

// ---------------------------------------------------------------------------
// element extraction
// ---------------------------------------------------------------------------

// Depth-matched inner HTML of the element whose opening tag ends at `from`. A fixed-size window would
// bleed into the VISIBLE content after a hidden element, which is the exact way a naive version of this
// layer promotes a genuine casino site from "spam_site" to "hacked lead" — so we count tags properly.
function innerOf(html, tag, from, cap = 6000) {
  const end = Math.min(html.length, from + cap);
  const rx = new RegExp("<(/?)" + tag + "\\b", "gi");
  rx.lastIndex = from;
  let depth = 1, mm, guard = 0;
  while ((mm = rx.exec(html)) && mm.index < end && guard++ < 400) {
    if (mm[1]) { depth--; if (depth === 0) return html.slice(from, mm.index); }
    else depth++;
  }
  return html.slice(from, end);
}

// One pass over every opening tag: decide hidden / invisible from the inline style, the bare `hidden`
// attribute, or a class or id the stylesheet hides. Returns the ranges so the caller can both test them
// and subtract them from the visible document.
function hiddenRanges(html, hide, invis) {
  const out = [];
  const rx = /<([a-z][a-z0-9]{0,9})\b([^>]{0,700})>/gi;
  let m, seen = 0;
  while ((m = rx.exec(html)) && seen++ < 6000 && out.length < 30) {
    const tag = m[1].toLowerCase();
    if (VOID_TAG.has(tag)) continue;
    const attrs = m[2];
    if (attrs.charCodeAt(attrs.length - 1) === 47) continue;   // self-closing → no inner text
    const style = (attrs.match(/\bstyle\s*=\s*(?:"([^"]{0,600})"|'([^']{0,600})'|([^\s">]{1,300}))/i) || []);
    const st = style[1] || style[2] || style[3] || "";
    const cls = ((attrs.match(/\bclass\s*=\s*(?:"([^"]{0,300})"|'([^']{0,300})')/i) || [])[1] || (attrs.match(/\bclass\s*=\s*'([^']{0,300})'/i) || [])[1] || "").toLowerCase();
    const id = ((attrs.match(/\bid\s*=\s*(?:"([^"]{0,100})"|'([^']{0,100})')/i) || [])[1] || "").toLowerCase();
    const names = (cls ? cls.split(/\s+/) : []).concat(id ? [id] : []).filter(Boolean);
    // If ANY name on the element is an a11y/widget name, the element is a theme feature — a spam block
    // does not also carry class="screen-reader-text".
    if (names.some(uiSafe)) continue;

    let why = "";
    let kind = "";
    if (st) {
      if (RE_HIDE_DECL.test(st) || (RE_ABS.test(st) && RE_OFFSCREEN.test(st))) { kind = "hide"; why = "style"; }
      else if ((RE_WHITE_FG.test(st) && RE_WHITE_BG.test(st)) || RE_TINY_FONT.test(st)) { kind = "invis"; why = "style"; }
    }
    // Bare `hidden` attribute. The whitespace requirement keeps `data-hidden` and `aria-hidden` out — the
    // character before those is a hyphen. It does NOT keep out the word `hidden` sitting inside a quoted
    // VALUE: `<div title="our hidden gems of Bangladesh">` has a space before it and matched, marking a
    // tour operator's visible copy as hidden. Blank the quoted values before testing.
    const bareAttrs = attrs.replace(/"[^"]{0,700}"|'[^']{0,700}'/g, '""');
    if (!kind && /(?:^|\s)hidden(?=[\s/>=]|$)/i.test(bareAttrs)) { kind = "hide"; why = "attr"; }
    if (!kind) {
      for (const n of names) {
        if (hide.has(n)) { kind = "hide"; why = "." + n; break; }
        if (invis.has(n)) { kind = "invis"; why = "." + n; break; }
      }
    }
    if (!kind) continue;
    const from = rx.lastIndex;
    const inner = innerOf(html, tag, from);
    if (!inner) continue;
    out.push({ kind, why, start: from, end: from + inner.length, inner });
  }
  return out;
}

// ---------------------------------------------------------------------------
// run
// ---------------------------------------------------------------------------

export async function run(ctx) {
  try {
    const S = ctx && ctx.S;
    if (!S || !S.ALL_STRONG) return [];
    const head = (ctx.B && ctx.B.text) || "";
    const tail = ctx.tail || "";
    if (!head && !tail) return [];
    // CONTRACT hard rule 3. This module issues no fetches, but the CSS parse and the tag walk are real CPU
    // on a plan with a hard CPU wall, and a domain past its deadline is being abandoned anyway.
    if (ctx.overBudget && ctx.overBudget()) return [];
    const html = tail ? head + "\n" + tail : head;

    // Cheap gate. Roughly 99% of the queue carries no STRONG token anywhere in its bytes, and this one
    // test lets those pages skip the CSS parse and the tag walk entirely — the module then costs about
    // as much as a single regex. This matters: regex over the page body is the #1 CPU cost on the free
    // plan and the reason the head read was capped at 96KB in the first place.
    if (!S.ALL_STRONG.test(html)) return [];

    const strongSrc = S.REG.ALL_STRONG.source;
    const sigs = [];
    const claimed = new Set();   // lowercased matches already used as proof — keeps buckets honest

    const { hide, invis } = cssHidden(html);
    const ranges = hiddenRanges(html, hide, invis);

    // The visible document = everything the hidden ranges do NOT cover, with comments and <noscript>
    // also removed. A token that survives here is part of the site's own content and can never be
    // evidence of hiding.
    // Removing the comments is not cosmetic: stripHtml's `<[^>]+>` treats `<!-- <a href=x>` as one tag
    // and stops at the first `>`, so a comment containing markup LEAKS its text into the stripped
    // document. Leave that in the baseline and every commented-out payload looks like visible content
    // and L52COMMENT can never fire.
    let vis = html;
    if (ranges.length) {
      let out = "", cur = 0;
      for (const r of ranges) { if (r.start >= cur) { out += html.slice(cur, r.start); cur = r.end; } }
      vis = out + html.slice(cur);
    }
    vis = vis.replace(/<!--[\s\S]{0,4000}?-->/g, " ").replace(/<noscript\b[^>]*>[\s\S]{0,4000}?<\/noscript>/gi, " ");
    const visibleOnly = ctx.stripHtml(vis).toLowerCase();

    // A pharma catalogue is a real Bangladeshi business. Square, Incepta and every online pharmacy list
    // sildenafil and tadalafil as products, sometimes inside collapsed markup — so on a pharma/healthcare
    // site a pharma-only hit is a product list, not an injection. Gambling or adult on the same site is
    // still evidence, because no pharmacy stocks "slot gacor".
    const ttl = ((html.match(/<title[^>]*>([\s\S]{0,200}?)<\/title>/i) || [])[1] || "").replace(/\s+/g, " ").trim();
    const biz = S.bizType ? S.bizType(ctx.reg, ttl, ctx.visB || visibleOnly) : "";
    const pharmaSite = biz === "pharma" || biz === "healthcare";
    const nonPharma = (m) => (S.RE.GAMB_STRONG.test(m) || S.RE.ADULT_STRONG.test(m));

    // novel = present in this region, absent from the visible page, not already claimed.
    const novel = (text) => {
      const hits = ctx.distinct(text, strongSrc).filter((m) => !visibleOnly.includes(m) && !claimed.has(m));
      if (!hits.length) return [];
      if (pharmaSite && !hits.some(nonPharma)) return [];
      return hits;
    };

    // A hidden block IS still evidence when the same spam is ALSO visible on the page — that is a site
    // so far gone the injection has reached the nav as well as the off-screen div. Requiring novelty
    // there was measured to drop 4 real hacked leads (vdlbd.com, gadgetfly.xyz, soaar.net,
    // imagineair.com), and dropping the stealth proof is what pushes a hacked victim into the
    // "spam_site" bucket in scan.js's genuine-vs-hacked gate — the lead is then lost entirely.
    // So for a hidden ELEMENT we accept a non-novel hit, but only on spam SHAPE: a link farm. A real
    // widget that happens to repeat a page keyword is prose, not three anchors or an off-site link.
    // Comments, <noscript> and the tail do NOT get this relaxation — there the strict novelty test is
    // the only thing separating a payload from a theme's own commented-out demo markup.
    // Host comparison is done inline rather than through ctx.hostOf/ctx.sameHost: those are optional
    // helpers, and a missing one would silently turn the whole off-domain test into "false" — failing
    // open on the exact check that is holding the relaxation above safe.
    const reg = String(ctx.reg || "").toLowerCase();
    // "three anchors or one off-site link" is NOT a link farm — it is a social-share widget, and every
    // themed page has one. On a clean BD news article about a betting crackdown the hidden `.post-share`
    // block had three off-domain anchors and the visible token, so the relaxation fired and the site
    // confirmed. A farm is a block that LINKS THE SPAM: the token must appear in an anchor's href or its
    // text, and at least one anchor must point off-domain to something that is not a share endpoint.
    // Spam in prose next to unrelated links (a school notice warning pupils about 1xbet, linking to
    // police.gov.bd) is reporting, not injection, and no longer qualifies.
    const socialHost = (h) => /facebook|fbcdn|twitter|^x\.com$|linkedin|pinterest|whatsapp|wa\.me|telegram|^t\.me$|instagram|youtube|youtu\.be|reddit|tumblr|^vk\.com$|threads\.net|messenger|addtoany|sharethis|addthis|line\.me|viber|skype|pinimg|digg|flipboard|getpocket/i.test(h);
    const linkFarmFor = (inner, hits) => {
      const rx = /<a\b([^>]{0,400})>([\s\S]{0,300}?)<\/a>/gi;
      let m, n = 0, external = 0, carries = false;
      while ((m = rx.exec(inner)) && n++ < 40) {
        const hm = m[1].match(/href\s*=\s*(?:"([^"]{0,300})"|'([^']{0,300})'|([^\s>]{1,300}))/i) || [];
        const u = (hm[1] || hm[2] || hm[3] || "").toLowerCase();
        const h = u.replace(/^[a-z]+:\/\//, "").replace(/[/?#].*$/, "").replace(/:.*$/, "");
        if (h && reg && h !== reg && !h.endsWith("." + reg) && !socialHost(h)) external++;
        const blob = u + " " + m[2].toLowerCase();
        if (hits.some((x) => blob.includes(x))) carries = true;
      }
      return carries && external >= 1;
    };
    const novelOrFarm = (text) => {
      const fresh = novel(text);
      if (fresh.length) return fresh;
      // Pharma is excluded from the relaxation on purpose: every online pharmacy in Bangladesh lists
      // sildenafil/tadalafil as real products, so a pharma token already present in visible content is
      // a catalogue entry no matter what shape the markup around it takes.
      const ga = ctx.distinct(text, strongSrc).filter((m) => !claimed.has(m) && nonPharma(m));
      return ga.length && linkFarmFor(text, ga) ? ga : [];
    };
    const take = (hits) => { for (const h of hits) claimed.add(h); };
    const quote = (t) => ctx.stripHtml(t).replace(/\s+/g, " ").trim().slice(0, 110);

    // BUCKET CHOICE — the difference between "needs corroboration" and "auto-confirms".
    // stripHtml does NOT remove display:none content, so a hidden block inside the head document is
    // already inside ctx.visB and has ALREADY been scored by L1KW_STRONG in `homepage-content`. Emitting
    // it again under a private `hidden` bucket double-counts one set of bytes across two buckets: the
    // posterior goes 0.92 → 0.9952 AND nbuckets hits 2, so a single hidden div self-confirms with no
    // independent corroboration at all. That is exactly why the live L17HIDDEN has always emitted into
    // `homepage-content` (CONTRACT §bucket: same bytes MUST share a bucket).
    // Only bytes L1KW_STRONG genuinely never read — the tail past the 96KB cap, and <noscript>, which
    // stripHtml deletes outright — are new evidence and earn the separate bucket.
    const scored = String(ctx.visB || ctx.stripHtml(head)).toLowerCase();
    const bucketFor = (hits) => (hits.every((h) => !scored.includes(h)) ? "hidden" : "homepage-content");

    // ---- P13 + P14: hidden and invisible blocks -------------------------------------------------
    const grp = { hide: { hits: [], why: [], quote: "" }, invis: { hits: [], why: [], quote: "" } };
    for (const r of ranges) {
      const hits = novelOrFarm(r.inner);
      if (!hits.length) continue;
      const g = grp[r.kind];
      take(hits);
      for (const h of hits) if (g.hits.length < 6) g.hits.push(h);
      if (g.why.length < 3) g.why.push(r.why);
      if (!g.quote) g.quote = quote(r.inner);
    }
    const url = (ctx.base || "https://" + ctx.reg) + "/";
    if (grp.hide.hits.length) {
      sigs.push({ bucket: bucketFor(grp.hide.hits), layer: "L17HIDDEN2", url,
        match: `hidden[${grp.hide.why.join(",")}] ${grp.hide.hits.join(";")} :: ${grp.hide.quote}` });
    }
    if (grp.invis.hits.length) {
      sigs.push({ bucket: bucketFor(grp.invis.hits), layer: "L50CONTRAST", url,
        match: `invisible[${grp.invis.why.join(",")}] ${grp.invis.hits.join(";")} :: ${grp.invis.quote}` });
    }

    // ---- P48: HTML comments ----------------------------------------------------------------------
    {
      const rx = /<!--([\s\S]{0,4000}?)-->/g;
      let m, n = 0, hits = [], q = "";
      while ((m = rx.exec(html)) && n++ < 250 && hits.length < 6) {
        const body = m[1];
        if (/^\s*\[(?:if|endif)/i.test(body)) continue;     // downlevel-revealed IE conditionals
        const h = novel(body);
        if (!h.length) continue;
        take(h);
        for (const x of h) if (hits.length < 6) hits.push(x);
        if (!q) q = quote(body);
      }
      if (hits.length) sigs.push({ bucket: bucketFor(hits), layer: "L52COMMENT", url, match: `comment ${hits.join(";")} :: ${q}` });
    }

    // ---- P48: <noscript> -------------------------------------------------------------------------
    {
      const rx = /<noscript\b[^>]*>([\s\S]{0,4000}?)<\/noscript>/gi;
      let m, n = 0, hits = [], q = "";
      while ((m = rx.exec(html)) && n++ < 40 && hits.length < 6) {
        const h = novel(m[1]);
        if (!h.length) continue;
        take(h);
        for (const x of h) if (hits.length < 6) hits.push(x);
        if (!q) q = quote(m[1]);
      }
      if (hits.length) sigs.push({ bucket: bucketFor(hits), layer: "L52NOSCRIPT", url, match: `noscript ${hits.join(";")} :: ${q}` });
    }

    // ---- P15 (emit half): the tail ---------------------------------------------------------------
    // Everything above already ran over head+tail, so anything still unclaimed here is plain, visible
    // footer text that simply lives past the 96KB cap — the injected-footer link farm this proposal
    // exists for. Its own bucket is justified only because these bytes were never read by any other
    // layer; the `claimed` set is what guarantees we are not re-scoring the hidden signals above.
    if (tail) {
      const tv = ctx.stripHtml(tail).toLowerCase();
      const hits = ctx.distinct(tv, strongSrc).filter((m) => !claimed.has(m) && !(ctx.visB || "").toLowerCase().includes(m));
      const usable = pharmaSite && !hits.some(nonPharma) ? [] : hits;
      if (usable.length) {
        const i = tv.indexOf(usable[0]);
        sigs.push({ bucket: "tail-content", layer: "L51TAIL", url,
          match: `tail ${usable.slice(0, 6).join(";")} :: ${tv.slice(Math.max(0, i - 40), i + 90).trim()}` });
      }
    }

    for (const s of sigs) s.match = String(s.match).slice(0, 200);
    return sigs;
  } catch (e) {
    return [];
  }
}
