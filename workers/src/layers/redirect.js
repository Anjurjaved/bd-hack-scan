// redirect.js — redirect-MECHANISM layers (P5 emit half, P6, P7).
//
// Three mechanisms move a visitor off a hacked BD site, and today the detector sees none of them:
//
//   1. HTTP hops.  scan.js fetches with redirect:"follow", so G.headers is the FINAL 200 response,
//      which by definition carries no Location — L16HDR is wired into W/LAYER_CAT and fires
//      essentially never (0 rows in 2,750 confirmed leads). We rebuild it from the real hop chain.
//   2. <meta http-equiv=refresh>.  No JS needed, survives script blockers, matched nowhere today.
//   3. location.href = "…" in an injected <script>.  stripHtml() deletes every <script> body
//      (scan.js:28) so the keyword layers are structurally blind to it.
//
// The whole design problem here is that *redirecting is normal*. A BD school that moved from
// school.com to school.edu.bd, a shop whose old domain points at its Facebook page, a login form
// doing location.href="/dashboard" — all of these redirect and all of them are clean. So no layer
// below fires on "a redirect happened". Every one of them requires a redirect PLUS a reason to
// believe the destination is spam infrastructure.

const CHAIN_MAX = 6;          // hops we will read from a supplied chain
const WALK_MAX = 4;           // hops we will walk ourselves in the fallback path
const RX_GUARD = 120;         // regex iteration cap — these run over 96KB of attacker-controlled HTML

export const TIER = "t1";

// Bayesian [P(fires | hacked), P(fires | clean)].
// The whole module measured 0 fires across the 2,000-domain scanned-clean BD control (781 reachable),
// so every clean-side number below is a deliberate pessimism, not the observed rate — 0/781 only
// bounds the true FP rate at roughly 0.4%, and the contract says to declare the pessimistic figure.
// The two-tier split (…X / …LOC strong vs …META / …TLD / HOPS weak) is the load-bearing part: the
// strong ids require a NAMED spam brand in the destination, the weak ids do not and are priced so
// they can add a corroborating bucket but never drive a confirmation on their own.
export const WEIGHTS = {
  L16HDR:   [0.80, 0.030],  // unchanged from scan.js:216 — this restores the existing layer, it does not re-tune it
  L21HOPS:  [0.55, 0.120],  // bare multi-hop is weak evidence on purpose; ad/affiliate chains look identical
  L22META:  [0.72, 0.055],  // off-domain meta-refresh on a still-live site, destination not identifiably spam
  L22METAX: [0.90, 0.020],  // off-domain meta-refresh straight into a named spam brand / known spam host
  L23JSLOC: [0.88, 0.012],  // JS location assignment to a spam brand or a self-learned spam host
  L23JSTLD: [0.70, 0.050],  // JS location assignment to a junk TLD only — .xyz/.top have legitimate BD users
  L23JSOBF: [0.86, 0.015],  // location = atob("…") / fromCharCode(…) decoding to an off-domain URL
};

export const CATS = {
  L16HDR: "redirect", L21HOPS: "redirect",
  L22META: "redirect", L22METAX: "redirect",
  L23JSLOC: "redirect", L23JSTLD: "redirect", L23JSOBF: "redirect",
};

// ---------------------------------------------------------------------------
// Destinations that are allowed to be off-domain.
//
// Parking/registrar pages and the big platforms are where a *real* dead BD business points its old
// domain. Shorteners are deliberately NOT exempt here even though the proposal suggested it: on a
// live business homepage a meta-refresh into bit.ly is not a rebrand, it is a cloak.
// Every entry is a bare LABEL, never "brand.tld" — the pattern appends the TLD itself, so writing
// `youtu\.be` here would have demanded youtu.be.<something> and silently never matched.
const BENIGN_DEST = /(^|\.)(facebook|fb|instagram|linkedin|twitter|x|youtube|youtu|google|googleusercontent|blogger|blogspot|wordpress|wixsite|wix|weebly|squarespace|shopify|myshopify|webflow|netlify|vercel|github|gitlab|linktr|daraz|shopup|bikroy|apple|microsoft|office|zoom|whatsapp|telegram|tiktok|sedoparking|sedo|afternic|hugedomains|bodis|parkingcrew|namecheap|godaddy|dynadot|porkbun|namesilo|cloudflare)\.[a-z.]{2,10}$/i;

// --- "is this really off-site?" ------------------------------------------------------------------
// Two FP families showed up the moment this ran against the 2,000-domain clean BD control, and both
// are structural rather than incidental:
//
//   web.bepza.gov.bd  --meta refresh-->  automation.bepza.gov.bd
// `reg` in this pipeline is the full scanned HOST, not the registrable, and sameHost() only walks
// downward — so a sideways hop between two subdomains of one BD government department read as
// off-domain. BD gov/edu sprawl across subdomains constantly and those are the highest-value leads
// we have, so this had to be fixed at the root, not patched per-case.
//
//   abcschool.com --> abcschool.edu.bd
// The .com -> .com.bd re-registration is a whole cottage industry here. Same organisation, new
// paperwork; never a hack.
//
// orgDomain() is a deliberately small public-suffix approximation. It can only ever make this module
// QUIETER (more things judged same-site), never louder, so being wrong at the margins is safe.
const CC_SLD = /^(gov|edu|ac|mil|com|net|org|co|info|nic|res|sch)$/;
function orgDomain(host) {
  const p = String(host || "").toLowerCase().replace(/^www\./, "").replace(/\.$/, "").split(".").filter(Boolean);
  if (p.length <= 2) return p.join(".");
  const tld = p[p.length - 1], sld = p[p.length - 2];
  if (tld.length === 2 && CC_SLD.test(sld)) return p.slice(-3).join(".");   // school.edu.bd, dept.gov.bd
  return p.slice(-2).join(".");
}
function coreLabel(host) {
  const o = orgDomain(host);
  return o ? o.split(".")[0] : "";
}
function sibling(host, reg) {
  if (orgDomain(host) && orgDomain(host) === orgDomain(reg)) return true;   // same org, different subdomain
  const a = coreLabel(host), b = coreLabel(reg);
  return a.length >= 4 && a === b;                                          // same name, different TLD
}

function absolutize(raw, base) {
  let u = String(raw || "").trim().replace(/^["']|["']$/g, "");
  if (!u) return "";
  if (/^\/\//.test(u)) u = "https:" + u;
  else if (/^https?:\/\//i.test(u)) { /* absolute already */ }
  else if (/^[a-z][a-z0-9+.-]*:/i.test(u)) return "";      // javascript:, data:, mailto: — not a redirect target
  else return "";                                           // relative => same host by definition, nothing to report
  return u.slice(0, 300);
}

// Accepts every plausible shape the fetch half (P1/P5) might hand us — array of URL strings, or of
// {url|from|href, status, location|to} — so this module keeps working whichever way that lands.
function normalizeChain(chain) {
  const out = [];
  if (!Array.isArray(chain)) return out;
  for (const h of chain.slice(0, CHAIN_MAX)) {
    if (!h) continue;
    if (typeof h === "string") { out.push({ url: h, status: 0, location: "" }); continue; }
    if (typeof h === "object") {
      out.push({
        url: String(h.url || h.from || h.href || ""),
        status: Number(h.status || h.code || 0) || 0,
        location: String(h.location || h.to || h.Location || ""),
      });
    }
  }
  return out;
}

// Fallback when nobody supplied a chain. Costs fetches, so the caller gates it hard (see run()).
async function walkChain(ctx, start) {
  const hops = [];
  let url = start;
  for (let i = 0; i < WALK_MAX; i++) {
    if (ctx.overBudget && ctx.overBudget()) break;
    if (ctx.budget && typeof ctx.budget.fetches === "number") {
      if (ctx.budget.fetches <= 0) break;
      ctx.budget.fetches--;
    }
    let r;
    try { r = await ctx.fetchManual(url, ctx.UA_BR, null, 8000); } catch (e) { break; }
    if (!r || !r.status) break;
    const loc = r.location || (r.headers && r.headers.get ? r.headers.get("location") : "") || "";
    hops.push({ url, status: r.status, location: String(loc || "") });
    if (r.status < 300 || r.status >= 400 || !loc) break;
    const next = /^https?:\/\//i.test(loc) ? loc : new URL(loc, url).href;
    if (!next || next === url) break;
    url = next;
  }
  return hops;
}

export async function run(ctx) {
  const out = [];
  try {
    const { reg, base, B, S } = ctx;
    if (!B || !B.text) return out;
    // Local fallbacks for the ctx helpers. The contract guarantees them, but this whole module
    // exists because L16HDR sat wired-up and silently dead for 2,750 leads — a missing helper
    // must not be able to recreate that failure mode by throwing us into the catch below.
    const hostOf = ctx.hostOf || ((u) => String(u || "").toLowerCase().replace(/^[a-z]+:\/\//, "").replace(/\/.*$/, "").replace(/:.*$/, ""));
    const sameHost = ctx.sameHost || ((h, r) => h === r || h.endsWith("." + r));
    const emit = (bucket, layer, match, url) =>
      out.push({ bucket, layer, match: String(match).replace(/\s+/g, " ").slice(0, 200), url: url || base + "/" });

    const isSpamHost = (h) => {
      if (!h) return false;
      try { return !!(ctx.spamHosts && ctx.spamHosts.has(h)); } catch (e) { return false; }
    };
    const offDomain = (h) => !!h && !sameHost(h, reg) && !sibling(h, reg);

    // "Is the business's own site still standing here?"
    //
    // Measured discriminator, and the most useful one in this module. A LEGITIMATE off-domain
    // redirect is almost always a bare stub whose entire job is to forward — the corpus run caught
    // three and every one of them was near-empty:
    //     austrofood.com     -> wanabana.com     (10 visible chars: "Page Moved")
    //     windt-partners.com -> windtlegal.com   (0 visible chars)
    //     web.bepza.gov.bd   -> automation.…     (35 visible chars)
    // all three real rebrands/handoffs, not hacks. An INJECTED redirect, by contrast, rides on top
    // of the victim's intact homepage — the school's content is still all there underneath.
    // So the weak layers (destination not identifiably spam) only fire when there is a real site to
    // have been hacked. 500 chars is a wide moat: a genuine BD homepage runs into the thousands,
    // and the loudest stub we measured was 35. Layers carrying brand-grade proof skip this gate,
    // because a full-takeover redirect legitimately DOES leave a stub behind.
    const visible = (ctx.visB || (ctx.stripHtml ? ctx.stripHtml(B.text) : B.text) || "").length;
    const liveSite = visible >= 500;
    // Why (if at all) a destination is suspect. This module contributes NO vocabulary of its own —
    // it only asks signatures.js about a URL we were actually being sent to, so the Bengali-word
    // trap cannot reach it: chotibd.com / khankitchen.com / enterogermina.com.bd are not spam under
    // SPAMMY_DOMAIN and therefore can never earn a strong id here. Verified against all 18 of the
    // rejected-token domains listed at signatures.js:31-39 — none produced a confirmable signal.
    // All regexes read are non-global, so there is no shared lastIndex to corrupt across calls.
    const suspectDest = (u) => {
      const h = hostOf(u);
      if (!offDomain(h)) return "";
      if (S.ALL_STRONG.test(u)) return "brand";              // gambling/pharma/adult token in host or path
      if (isSpamHost(h)) return "spamhost";                  // self-learned + URLhaus
      if (S.RE.SPAMMY_DOMAIN.test(h)) return "brand";        // a spam BRAND is the registrable name
      if (S.RE.JUNKTLD.test(u) || S.RE.SPAMMY_TLD.test(h)) return "junktld";
      return "";
    };

    // ===================================================================== P5
    // L16HDR / L21HOPS — the real HTTP hop chain.
    //
    // We only pay for our own walk when the browser fetch actually LANDED off-domain: that is the
    // only situation where hidden intermediate hops can exist and matter, and it keeps the module
    // at zero extra fetches on ~99% of the corpus. Once the P5 fetch half lands and populates
    // B.chain, this branch never runs at all.
    let hops = normalizeChain(B.chain);
    const finalHost = hostOf(B.finalUrl);
    if (!hops.length && ctx.fetchManual && offDomain(finalHost) &&
        !(ctx.overBudget && ctx.overBudget()) && (!ctx.budget || ctx.budget.fetches > 0)) {
      hops = await walkChain(ctx, base);
    }

    if (hops.length) {
      // Destinations we were SENT to. hops[0] is the origin we asked for, so it is not one of them;
      // every later hop URL is. A trailing Location on the last hop (the walk stopped there, or a
      // stray Location rode along on the final 200) counts too — that is the header the old L16HDR
      // was looking for in the one place it can never be.
      const sent = [];
      for (let i = 1; i < hops.length; i++) {
        const prev = hops[i - 1];
        sent.push({ url: hops[i].url, raw: (prev && prev.location) || hops[i].url, status: prev ? prev.status : 0 });
      }
      const last = hops[hops.length - 1];
      if (last && last.location) {
        const abs = absolutize(last.location, last.url || base) || last.location;
        if (!sent.some((x) => x.url === abs)) sent.push({ url: abs, raw: last.location, status: last.status });
      }

      // NOTE the `why !== "junktld"` guard. P5 proposed "off-domain hop AND (GAMB_STRONG|JUNKTLD)",
      // but the clean control produced exactly the FP that predicts:
      //     idp.portal.gov.bd  --302-->  admin-login-npf-v2.softbd.xyz
      // a Bangladeshi government SSO portal handing off to its vendor's staging host, which happens
      // to sit on .xyz. Cheap TLDs are cheap for BD vendors too. A server-level 30x is the site
      // OWNER's configuration, so it needs brand-grade proof; junk-TLD alone is not that. Real
      // gambling chains almost always carry the brand in the host or path anyway
      // (slot-gacor-88.top, 1xbet-bd.xyz), so this costs close to nothing in recall.
      for (const t of sent) {
        const why = suspectDest(t.url);
        if (why && why !== "junktld") {
          emit("redirect", "L16HDR", `HTTP ${t.status || 3} Location: ${t.raw.slice(0, 150)}`, hops[0] && hops[0].url ? hops[0].url : base + "/");
          break;                                    // one proof is enough; the bucket takes the max anyway
        }
      }

      // L21HOPS — a long laundering chain with no recognisable brand in it. Kept genuinely weak
      // [0.55,0.12]: affiliate networks, consent walls and ad servers all bounce 3+ times legitimately.
      //
      // It shares the `redirect` bucket with L9REDIR and L16HDR by design, and that makes it inert
      // on most sites it fires on — measured on habibdental.co and sankairaghs.edu.bd, L9REDIR had
      // already claimed the bucket with a higher ratio, so L21HOPS added nothing to the posterior.
      // That is the correct trade: all three read the same redirect, and giving this its own bucket
      // would let one redirect be counted twice, which is precisely the arithmetic that manufactured
      // the 331 junk leads. Its real job is the case L9REDIR cannot see — a chain that launders
      // through three strangers and then lands back on the victim's own host.
      const offHosts = new Set();
      for (const t of sent) {
        const h = hostOf(t.url);
        if (offDomain(h) && !BENIGN_DEST.test(h)) offHosts.add(h);
      }
      if (offHosts.size >= 3) {
        emit("redirect", "L21HOPS", `${offHosts.size} off-domain hops: ` + [...offHosts].slice(0, 4).join(" -> "), base + "/");
      }
    }

    // ===================================================================== P6
    // L22META — <meta http-equiv="refresh" content="0;url=…">.
    //
    // Attribute order is attacker-controlled, so match http-equiv and content independently inside
    // one tag rather than assuming refresh-then-content. Relative targets return "" from absolutize()
    // and are dropped: a same-host meta refresh is ordinary "page moved" behaviour.
    const metaRx = /<meta\b[^>]{0,300}>/gi;
    let mm, mg = 0;
    while ((mm = metaRx.exec(B.text)) && mg++ < RX_GUARD) {
      const tag = mm[0];
      if (!/http-equiv\s*=\s*["']?refresh/i.test(tag)) continue;
      const c = /content\s*=\s*["']([^"']{0,300})["']/i.exec(tag) || /content\s*=\s*([^\s>]{1,300})/i.exec(tag);
      if (!c) continue;
      const u = /url\s*=\s*(.+)$/i.exec(c[1]);
      if (!u) continue;
      const abs = absolutize(u[1], base);
      const h = hostOf(abs);
      if (!offDomain(h) || BENIGN_DEST.test(h)) continue;
      // Same rule as the HTTP chain: the STRONG id is reserved for a named spam brand or a
      // self-learned spam host. A junk TLD only earns the weak id — it is a price signal, not proof.
      const why = suspectDest(abs);
      const strong = why === "brand" || why === "spamhost";
      if (!strong && !liveSite) break;                       // bare forwarding stub — a rebrand, not a hack
      emit("redirect-inpage", strong ? "L22METAX" : "L22META", tag.slice(0, 190), base + "/");
      break;
    }

    // ===================================================================== P7
    // L23JSLOC / L23JSTLD / L23JSOBF — JavaScript location assignment.
    //
    // Read RAW B.text: stripHtml deletes every <script> body, so visB can never contain this.
    // The bar is deliberately high. A bare off-domain location.href is NOT enough — SSO handoffs,
    // consent managers, payment gateways (SSLCommerz, bKash) and "visit our new site" banners all
    // assign location off-domain on perfectly clean BD sites. We fire only when the destination
    // itself is spam infrastructure, or when the destination is hidden behind a decoder.
    //
    // DELIBERATELY NOT IMPLEMENTED: "off-domain location.href sitting near an obfuscation marker
    // (eval/atob/fromCharCode within ±200 chars)". It reads as a great injection tell, but every
    // minified vendor bundle on earth puts those tokens within 200 chars of everything else, and it
    // would have fired on ordinary jQuery/webpack output in the clean control. Proximity is not
    // evidence; the decoded destination is.
    const jsRx = /(?:window\.|self\.|top\.|parent\.|document\.)?location(?:\s*\.\s*(?:href|replace|assign))?\s*(?:=|\()\s*["'](https?:\/\/[^"'\s<>]{4,250})/gi;
    let jm, jg = 0, firedJs = false;
    while ((jm = jsRx.exec(B.text)) && jg++ < RX_GUARD) {
      const u = jm[1];
      const h = hostOf(u);
      if (!offDomain(h) || BENIGN_DEST.test(h)) continue;
      const why = suspectDest(u);
      if (!why) continue;                                   // bare off-domain assignment — silent, by design
      if (why === "junktld" && !liveSite) continue;         // vendor handoff stub on a cheap TLD (see liveSite)
      const layer = why === "junktld" ? "L23JSTLD" : "L23JSLOC";
      emit("redirect-inpage", layer, jm[0].slice(0, 190), base + "/");
      firedJs = true;
      break;
    }

    // L23JSOBF — location = atob("…") / String.fromCharCode(…). There is no legitimate reason to
    // hide the destination of a top-level navigation from the reader of the page. We still decode
    // and require the result to be off-domain, so a site obfuscating its own internal handoff
    // (rare, but it happens in old BD e-commerce themes) stays silent. decodeURIComponent and
    // unescape are excluded on purpose: `location.href = decodeURIComponent(next)` is a normal
    // login-return-URL pattern and would have made this layer unusable.
    if (!firedJs) {
      const obfRx = /(?:window\.|self\.|top\.|parent\.)?location(?:\s*\.\s*(?:href|replace|assign))?\s*(?:=|\()\s*(?:window\.)?(atob|String\.fromCharCode)\s*\(\s*([^)]{0,600})\)/gi;
      let om, og = 0;
      while ((om = obfRx.exec(B.text)) && og++ < 20) {
        let dec = "";
        try {
          if (om[1] === "atob") {
            const lit = /["']([A-Za-z0-9+/=\s]{8,400})["']/.exec(om[2]);
            if (lit) dec = atob(lit[1].replace(/\s+/g, ""));
          } else {
            const codes = om[2].match(/\d{2,3}/g) || [];
            if (codes.length >= 8) dec = codes.slice(0, 300).map((n) => String.fromCharCode(Number(n))).join("");
          }
        } catch (e) { dec = ""; }
        if (!/^https?:\/\//i.test(dec)) continue;            // decoded to something that is not a URL — not our business
        const h = hostOf(dec);
        if (!offDomain(h) || BENIGN_DEST.test(h)) continue;
        emit("redirect-inpage", "L23JSOBF", `${om[1]}(…) -> ${dec.slice(0, 150)}`, base + "/");
        break;
      }
    }
  } catch (e) { /* contract rule 1: degrade to [], never kill the scan */ }
  return out;
}
