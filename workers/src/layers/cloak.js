// cloak.js — cloaking layers. The unifying assertion of every layer here is the same one that
// already powers the most trusted layer in the system (L2UACLOAK, 0.92/0.020): "strong spam
// vocabulary appears in ONE view of this page and not in the view a human visitor gets."
// No legitimate business serves casino brands to Googlebot and hides them from its customers,
// which is why this family is allowed to score high while pure keyword layers are not.
//
// What scan.js gets wrong today and this module fixes:
//   scan.js:303 sends UA_GB **and** REF_G in ONE fetch, so when a diff IS found nothing can say
//   WHICH of the two headers triggered it. We split the axes: R = browser UA + Google referer
//   isolates the referer, M = iPhone UA isolates the device, and the gclid/utm probe isolates
//   paid traffic.
//
//   CORRECTED (review): an earlier draft of this header claimed a referer-only cloaker is
//   "invisible" to scan.js. That is false — scan.js's G fetch carries REF_G, so a referer-keyed
//   cloak already trips L2UACLOAK. L3REFCLOAK therefore adds almost no RECALL over L2UACLOAK
//   (measured: 10/10 of its fires were on sites where L2UACLOAK also fired). What it adds is
//   ATTRIBUTION, and attribution must not be paid for with a second bucket — see the bucket note
//   on L3REFCLOAK below. The one genuinely new case it catches is a kit that keys on the referer
//   while actively suppressing for the Googlebot UA; there L2UACLOAK is silent and this layer is
//   the only detector, and sharing the bucket costs that case nothing.
//
// Layers: L3REFCLOAK (P3, t1) · L4MOBILE (P4, t1) · L51PARAMCLOAK (P42, t2) · L47URLCLOAK (P34, t2).

export const WEIGHTS = {
  // Same order of evidence as L2UACLOAK, so the same shape of weight. 0.020 clean is deliberately
  // pessimistic — the guards below should make a genuine FP far rarer than 1-in-50, but an
  // over-confident weight silently manufactures leads and that mistake has been made here before.
  L3REFCLOAK: [0.90, 0.020],
  // Mobile is the loosest of the four: phones legitimately get different markup (AMP, m.*, app
  // interstitials), so the clean rate is declared double the referer layer's.
  L4MOBILE: [0.75, 0.040],
  // Doorway-URL cloak = the L2UACLOAK assertion applied to the page the kit actually cloaks.
  L47URLCLOAK: [0.90, 0.020],
  // Paid-traffic personalisation is a real, legitimate practice (landing-page A/B tests key on
  // utm_*), so this carries the highest clean rate of the family even after the STRONG-only gate.
  L51PARAMCLOAK: [0.80, 0.030],
};

// L3REFCLOAK/L47URLCLOAK/L51PARAMCLOAK are cloak evidence; L4MOBILE is a redirect, matching the
// LAYER_CAT scan.js already declares for it. Note that scan.js's category() consults the matched
// TEXT first, so whenever the proof contains an actual gambling/adult keyword the finding still
// lands in gambling/adult and still has to pass the AI genuine-vs-hacked gate. Good: these
// categories must not become a side door around that gate.
export const CATS = { L3REFCLOAK: "cloak", L4MOBILE: "redirect", L47URLCLOAK: "cloak", L51PARAMCLOAK: "cloak" };

// The module is t1 because P3 and P4 must run on every domain (they are the two dead layers).
// The t2 halves (P42, P34) are gated internally on ctx.deep — a module only gets one TIER, and
// declaring t2 would kill the two layers that are the whole point of this file.
export const TIER = "t1";

const UA_MOB = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1";

// One combined marker instead of P42's two separate fetches: a redirect kit keys on the PRESENCE
// of gclid or of utm_source=google, never on their absence, so one URL carrying both fires
// everything two URLs would and costs one request instead of two.
const PARAM_Q = "?gclid=EAIaIQobChMIx7Ck0aTsgAMV&utm_source=google&utm_medium=cpc&utm_campaign=search";

// A diff is only meaningful against a browser view that actually exists. A WAF interstitial, a
// 403, a 502 or a 12-byte stub makes EVERY token in the other view look "new" — that is not a
// cloak, that is a broken baseline, and it is the single most likely way this family could start
// firing on clean sites. Every layer below refuses to run unless the baseline is usable.
function usable(r, S) {
  if (!r || r.status < 200 || r.status >= 300) return false;
  const t = r.text || "";
  if (t.length < 500) return false;
  return !S.RE.WAF.test(t);
}

// Tokens present in the probe view and absent from the baseline. The absence test runs against the
// baseline's RAW html, not its stripped text: a keyword sitting inside a <script>, an attribute or
// past the 96KB read cap is invisible to stripHtml, and counting that as "only shown to the bot"
// would be a pure artefact of our own parsing rather than anything the site did.
function newTokens(probeVis, baselineRaw, ctx) {
  const S = ctx.S;
  const found = ctx.distinct(probeVis, S.REG.ALL_STRONG.source);
  if (!found.length) return [];
  const hay = String(baselineRaw || "").toLowerCase();
  return found.filter((t) => t && !hay.includes(t));
}

// A cloaked payload is a WALL of spam, never one passing word. Measured: blubela.com 2 distinct
// tokens / 11 occurrences, syedanasjamal.com 2 / 3 — against rhwatch.store, a Bangladeshi watch
// shop selling a product literally named "Casino primium watch black daimond", which produced a
// single incidental token and then returned ZERO on an immediate re-fetch because its homepage
// rotates products at random. That is the whole rotating-content false-positive class in one
// example: it is indistinguishable from a cloak on one token and obvious on two. So a keyword
// diff must bring either two distinct tokens or one token repeated three times before it counts.
function payloadStrong(vis, toks) {
  if (toks.length >= 2) return true;
  const hay = vis.toLowerCase();
  let occ = 0;
  for (const t of toks) { let i = 0; while ((i = hay.indexOf(t, i)) >= 0 && occ < 9) { occ++; i += t.length; } }
  return occ >= 3;
}

// Verbatim proof: the injected sentence as the business owner would read it, not a description.
function proofNear(vis, tok) {
  const i = vis.toLowerCase().indexOf(String(tok).toLowerCase());
  if (i < 0) return String(tok);
  return vis.slice(Math.max(0, i - 70), i + 110).replace(/\s+/g, " ").trim();
}

export async function run(ctx) {
  const out = [];
  try {
    const S = ctx.S;
    const B = ctx.B;
    const base = ctx.base;
    const reg = ctx.reg;
    const visB = ctx.visB || "";
    // No trustworthy human-visitor baseline → every layer in this file is unattributable. Bail.
    if (!usable(B, S) || visB.length < 200) return out;

    const spend = (n) => {
      if (ctx.overBudget && ctx.overBudget()) return false;
      if (ctx.budget && typeof ctx.budget.fetches === "number") {
        if (ctx.budget.fetches < n) return false;
        ctx.budget.fetches -= n;
      }
      return true;
    };
    const push = (bucket, layer, match, url) => out.push({ bucket, layer, match: String(match).slice(0, 200), url });

    // ONE cloaking behaviour must never fill more than one bucket. Measured on blubela.com: a
    // referer-keyed cloak fired L3REFCLOAK, L4MOBILE and L51PARAMCLOAK on the identical token set
    // (because all three probes originally carried REF_G), which alone satisfies nbuckets>=2 and
    // drives the posterior past the confirm line off a single observation. Two fixes: the mobile
    // and param probes below send NO referer, so each isolates its own axis; and a keyword-based
    // layer must contribute at least one token no earlier layer already claimed. The mobile
    // REDIRECT branch is exempt — a Location header is structurally different evidence, not the
    // same tokens seen again.
    const claimed = new Set();
    const unclaimed = (toks) => toks.filter((t) => !claimed.has(t));
    const claim = (toks) => { for (const t of toks) claimed.add(t); };

    // The ledger above only sees layers in THIS module — it cannot see L2UACLOAK, which scan.js
    // emits from its own G fetch, so on its own it does not stop this module re-reporting a payload
    // the homepage cloak check already found. The fix costs no fetch: the no-referer probes below
    // test token ABSENCE against the browser view AND the Googlebot view. Their whole assertion is
    // "only a phone / only an ad click sees this", and that claim is simply false if Googlebot saw
    // it too — such a token is homepage spam or a UA cloak (already owned by L1KW_STRONG /
    // L2UACLOAK), never independent evidence. Using G's RAW text also means a token sitting in a
    // <script> counts as "seen", which is the conservative direction.
    // L3REFCLOAK deliberately does NOT get this treatment: G carries REF_G, so for the referer
    // cloak it is trying to detect the token is EXPECTED in G. Its double-count is prevented by
    // sharing the cloak-diff bucket instead.
    const gRaw = (ctx.G && ctx.G.text) ? ctx.G.text : "";
    const quietBase = B.text + "\n" + gRaw;

    // ---------------------------------------------------------------------
    // P3 · L3REFCLOAK — referer-only cloak.
    // R holds the User-Agent constant at a real browser and changes ONLY the Referer, so spam that
    // appears in R and not in B was triggered by the referer and nothing else.
    //
    // BUCKET (corrected in review): this MUST share "cloak-diff" with L2UACLOAK. scan.js's G fetch
    // is UA_GB + REF_G, so for a referer-keyed cloak G and R see the SAME payload for the SAME
    // reason — one behaviour, observed twice. The earlier "cloak-diff-ref" bucket turned that single
    // observation into nbuckets=2, and the arithmetic is not subtle: prior odds 0.1364 × L2UACLOAK
    // 46 = posterior 0.8625 (nbuckets 1 → "review"), × L3REFCLOAK 45 = 0.9965 (nbuckets 2 →
    // CONFIRM_CANDIDATE). Every one of the 10 measured fires co-occurred with L2UACLOAK, so the
    // separate bucket's ONLY measured effect was to promote parked sites to confirmed leads off no
    // new evidence. That is exactly the "two layers reading the same bytes" double-count CONTRACT.md
    // forbids, and it manufactures leads sold to real businesses. Shared bucket: the fuser keeps the
    // stronger of the two and the posterior stays honest.
    // ---------------------------------------------------------------------
    if (spend(1)) {
      const R = await ctx.fetchPage(base, ctx.UA_BR, ctx.REF_G, 10000);
      if (usable(R, S)) {
        const visR = ctx.stripHtml(R.text);
        const toks = newTokens(visR, B.text, ctx);
        if (toks.length && payloadStrong(visR, toks)) {
          claim(toks);
          push("cloak-diff", "L3REFCLOAK", proofNear(visR, toks[0]) + " [only with google referer: " + toks.slice(0, 4).join(";") + "]", base + "/");
        }
      }
    }

    // ---------------------------------------------------------------------
    // P4 · L4MOBILE — mobile-only redirect or mobile-only spam.
    // redirect:"manual" so we read the Location the phone is actually sent to instead of following
    // it. Two independent triggers, both requiring that the desktop browser view did NOT do the
    // same thing — a site-wide off-domain redirect is L9REDIR's finding, not this one.
    // The m.example.com trap: sameHost() exempts anything under the registrable, so m./mobile./
    // amp. hosts can never fire. On top of that the destination must itself carry a gambling brand
    // or a junk TLD, which is what keeps a legitimate redirect to an app store or a Facebook page
    // out of the lead list.
    // ---------------------------------------------------------------------
    // NOTE the deliberate deviation from P4, which specified REF_G on this fetch: sending a Google
    // referer here would make every referer-cloak also look like a mobile-cloak, which is the exact
    // attribution failure P3 exists to repair. No referer → this probe changes the device and
    // nothing else.
    if (typeof ctx.fetchManual === "function" && spend(1)) {
      const M = await ctx.fetchManual(base, UA_MOB, null, 9000);
      const bh = ctx.hostOf(B.finalUrl || base);
      const desktopLeft = bh && !ctx.sameHost(bh, reg);
      if (M && M.status >= 300 && M.status < 400 && M.location && !desktopLeft) {
        const loc = String(M.location);
        const lh = ctx.hostOf(loc.startsWith("http") ? loc : base + (loc.startsWith("/") ? loc : "/" + loc));
        // JUNKTLD is tested against the destination HOST, never the whole URL. JUNKTLD anchors on
        // ([/:?#]|$), so against a full URL it matches any path or query that merely ENDS in a junk
        // label — verified: "play.google.com/store/apps/details?id=com.bracbank.loan" matches
        // \.loan$. Android package ids are reverse-DNS and BD fintech/microfinance apps really do
        // end in .loan (also .men, .club). A clean bank whose site sends phones to its Play Store
        // listing would have been reported as a malicious mobile redirect. GAMB/ADULT stay on the
        // full URL — spam destinations legitimately carry the brand in the path.
        if (lh && !ctx.sameHost(lh, reg) && (S.RE.GAMB_STRONG.test(loc) || S.RE.ADULT_STRONG.test(loc) || S.RE.JUNKTLD.test(lh) || (ctx.spamHosts && ctx.spamHosts.has(lh)))) {
          push("cloak-mobile", "L4MOBILE", "iPhone UA -> " + M.status + " Location: " + loc.slice(0, 140), base + "/");
        }
      } else if (M && usable(M, S)) {
        const visM = ctx.stripHtml(M.text);
        const toks = unclaimed(newTokens(visM, quietBase, ctx));
        if (toks.length && payloadStrong(visM, toks)) {
          claim(toks);
          push("cloak-mobile", "L4MOBILE", proofNear(visM, toks[0]) + " [shown only to mobile: " + toks.slice(0, 4).join(";") + "]", base + "/");
        }
      }
    }

    if (!ctx.deep) return out;

    // ---------------------------------------------------------------------
    // P42 · L51PARAMCLOAK [t2] — paid-traffic cloak.
    // A large family of redirect malware wakes up only for visitors carrying ad-click markers, so
    // it stays dormant for both crawlers and the site owner. This is the loosest probe in the file
    // because legitimate landing pages DO personalise on utm_*, so a mere content difference is
    // never enough: we require either a STRONG spam token that is absent from the plain view, or a
    // redirect that leaves the registrable for a gambling/junk-TLD host.
    // ---------------------------------------------------------------------
    // Referer stays null here too, for the same attribution reason as the mobile probe: the only
    // variable between B and P must be the ad-click parameters.
    if (spend(1)) {
      const P = await ctx.fetchPage(base + "/" + PARAM_Q, ctx.UA_BR, null, 10000);
      if (P && P.status) {
        const ph = ctx.hostOf(P.finalUrl);
        const bh = ctx.hostOf(B.finalUrl || base);
        const desktopLeft = bh && !ctx.sameHost(bh, reg);
        // JUNKTLD on the destination HOST only — same reason as the mobile branch above.
        if (ph && !ctx.sameHost(ph, reg) && !desktopLeft && (S.RE.GAMB_STRONG.test(P.finalUrl) || S.RE.ADULT_STRONG.test(P.finalUrl) || S.RE.JUNKTLD.test(ph) || (ctx.spamHosts && ctx.spamHosts.has(ph)))) {
          push("cloak-diff-param", "L51PARAMCLOAK", "gclid/utm visitor redirected off-site -> " + String(P.finalUrl).slice(0, 140), base + "/" + PARAM_Q);
        } else if (usable(P, S)) {
          const visP = ctx.stripHtml(P.text);
          const toks = unclaimed(newTokens(visP, quietBase, ctx));
          if (toks.length && payloadStrong(visP, toks)) {
            claim(toks);
            push("cloak-diff-param", "L51PARAMCLOAK", proofNear(visP, toks[0]) + " [shown only to ad-click traffic: " + toks.slice(0, 4).join(";") + "]", base + "/" + PARAM_Q);
          }
        }
      }
    }

    // ---------------------------------------------------------------------
    // P34 · L47URLCLOAK [t2] — per-URL cloak on discovered doorway URLs.
    // The homepage cloak check only ever tests "/". A competent doorway kit leaves "/" untouched
    // precisely so that a homepage-only scanner sees nothing, and cloaks the doorway URLs instead.
    // Candidates come free: whatever the sitemap/REST stage handed us on ctx, plus any internal
    // link on the pages we already hold whose path hits SLUG_SPAM.
    //
    // This deliberately shares the EXISTING cloak-diff bucket with L2UACLOAK rather than taking a
    // new one. It is the same assertion read from the same axis, just on a different URL — giving
    // it its own bucket would let one cloaking behaviour count twice toward nbuckets>=2 and
    // manufacture confirmations. When the homepage is clean (the case this layer exists for)
    // L2UACLOAK is silent anyway, so sharing costs nothing.
    // ---------------------------------------------------------------------
    const cands = [];
    const seen = new Set();
    const addCand = (u) => {
      if (!u || cands.length >= 3) return;
      let abs;
      try { abs = new URL(u, base).href; } catch (e) { return; }
      if (!/^https?:\/\//.test(abs)) return;
      if (!ctx.sameHost(ctx.hostOf(abs), reg)) return;
      if (/\.(xml|jpe?g|png|gif|webp|svg|css|js|pdf|zip)(\?|$)/i.test(abs)) return;
      if (seen.has(abs) || abs.replace(/\/$/, "") === base.replace(/\/$/, "")) return;
      seen.add(abs); cands.push(abs);
    };
    for (const u of (ctx.doorways || ctx.doorwayUrls || ctx.urls || [])) addCand(u);
    if (cands.length < 3) {
      // [^>]{0,400}, NOT [^>]+. This regex runs over HTML written by the attacker who owns the
      // hacked site, and with an unbounded quantifier a page of "<a " openers with no ">" makes
      // every start position rescan to EOF and backtrack: measured 2,633ms of pure CPU on a 140KB
      // input, versus 36ms bounded — a 73x blow-up on the free plan whose documented failure mode
      // is exactly the 1102 CPU wall. The guard below does not help, because the cost is burned
      // INSIDE a single rx.exec() call before it ever returns. Real anchor tags are far under 400
      // chars, so the bound costs no recall. Haystack capped for the same reason.
      const rx = /<a\b[^>]{0,400}href="([^"]{4,300})"/gi;
      let m, guard = 0;
      const hay = ((B.text || "") + (ctx.G && ctx.G.text ? ctx.G.text : "")).slice(0, 200000);
      while ((m = rx.exec(hay)) && guard++ < 600 && cands.length < 3) {
        if (S.RE.SLUG_SPAM.test(m[1])) addCand(m[1]);
      }
    }
    for (const u of cands) {
      if (!spend(2)) break;
      const Ub = await ctx.fetchPage(u, ctx.UA_BR, null, 9000);
      if (!usable(Ub, S)) continue;
      const Ug = await ctx.fetchPage(u, ctx.UA_GB, ctx.REF_G, 9000);
      if (!usable(Ug, S)) continue;
      const visUg = ctx.stripHtml(Ug.text);
      // Absent from BOTH the doorway's own browser view and the homepage — a token already visible
      // on the homepage proves nothing about this URL and would just re-report L1KW_STRONG.
      const toks = unclaimed(newTokens(visUg, Ub.text + "\n" + B.text, ctx));
      if (toks.length && payloadStrong(visUg, toks)) {
        push("cloak-diff", "L47URLCLOAK", proofNear(visUg, toks[0]) + " [bot-only on " + u.slice(0, 60) + ": " + toks.slice(0, 3).join(";") + "]", u);
        break;   // one proven cloaked doorway is the whole finding; more fetches add no score
      }
    }
  } catch (e) { /* never throw — a dead cloak module must not kill the scan */ }
  return out;
}
