// deep.js — TIER-2 deep probes (P35 · P36 · P37 · P38 · P39 · P40 · P41).
//
// WHY THIS MODULE EXISTS: everything in tier 1 reads bytes the site volunteered — the homepage, its feed,
// its sitemap. That is enough to notice spam, and not enough to prove WHERE it lives. This module goes and
// looks: it fetches the AMP twin that cleanup crews forget, it asks whether a named web shell is still
// sitting on disk, it reads the uploads directory, it speaks the four non-WordPress CMSes that roughly a
// quarter of BD SMB sites actually run, and it pulls the certificate-transparency log for subdomains that
// no longer resolve. It runs ONLY on the VM (TIER "t2"), and only for domains that already smell.
//
// ---------------------------------------------------------------------------------------------------
// THE ONE RULE THAT GOVERNS THIS WHOLE FILE: **A 200 PROVES NOTHING.**
//
// Most Bangladeshi shared hosting (cPanel + LiteSpeed, and every "parked/for-sale" reseller template)
// answers 200 for literally any path you ask for. A probe module written as `if (status === 200) emit()`
// would report a web shell on a majority of the BD corpus. So every file probe in here passes through
// TWO gates before it may emit:
//
//   1. CALIBRATION. Before any file probe we ask for a random nonce path that cannot exist. If THAT
//      returns 200, the host is a soft-404 server and its status codes are noise. We do not then throw
//      the probe away (see below), we downgrade what a probe is allowed to conclude.
//   2. CONTENT FINGERPRINT. The body must contain a string that only the real artefact contains —
//      "IndoXploit" for a shell, "repositoryformatversion" for a git config, "APP_KEY=" for a Laravel
//      .env. Status is never evidence; bytes are.
//
// P36 as written in the proposal says a soft-404 host should skip the shell probe entirely. We calibrate
// exactly as instructed but then apply a STRICTER rule instead of a blunter one: on a soft-404 host a hit
// must ALSO differ materially from the nonce body. Skipping outright would lose real shells on exactly the
// cheap shared hosting where shells are most common, and it buys no safety that the fingerprint does not
// already buy — no soft-404 page in the world contains the string "IndoXploit".
// ---------------------------------------------------------------------------------------------------
//
// BUCKET DISCIPLINE (read before adding a layer here):
//   webshell      — P36 + P37. Both answer ONE question: "is there an attacker-planted executable on this
//                   host?" A shell dropped in uploads is usually found by BOTH probes, so they share a
//                   bucket and the fuser takes the stronger. Separate buckets would let one file become
//                   two independent-looking observations.
//   homepage-content — P35. The AMP twin is a rendering of the same page. Sharing the bucket with
//                   L1KW_STRONG means AMP contributes exactly when it should: when the main page is clean
//                   and the forgotten AMP copy is not.
//   content-enum  — P38. Same bucket as L11REST and the wpprobe.js layers, for the same reason: they are
//                   all one assertion ("this CMS publishes injected content"), read through different doors.
//   ct-subdomain  — P40. Genuinely independent of the page bytes: a certificate is third-party testimony.
//   control       — P39 and P41. See below.
//
// P39 (exposure) AND P41 (TLS) EMIT INTO `control` ON PURPose AND MUST STAY THERE.
//   `score()` filters `bucket === "control"` out of the posterior entirely, which is precisely the
//   requirement. An exposed /.env is a VULNERABILITY, not a hack; the moment it can nudge the posterior it
//   starts manufacturing "your site is hacked" leads out of a misconfigured backup file, and the confirmed=1
//   metric the whole dashboard rests on stops meaning anything. They still carry stable layer ids and a
//   CATS entry of "exposure" so that scan.js can lift them out of the RAW signal array and write them as
//   the separate `category='exposure', confirmed=0, status='risk-lead'` product. That wiring belongs in
//   scan.js, not here — this module's job is to make the finding available without contaminating anything.
//
// FP DISCIPLINE: these leads are sold to real Bangladeshi schools and SMBs. Every gate below was set at
// the point the clean-BD control stopped producing hits, not at the point recall stopped improving.

export const TIER = "t2";

// Bayesian [P(fires | hacked), P(fires | clean)]. The hacked-side numbers are deliberately LOW: these are
// narrow probes that fire on a specific artefact most compromises do not leave behind. Low recall with a
// tiny FP rate is exactly the trade we want at tier 2 — tier 1 already caught the ordinary cases.
export const WEIGHTS = {
  // P35. Fires only when the site publishes an AMP twin at all (a minority) AND that twin carries spam.
  // Clean rate is not zero: an AMP homepage is still publisher-controlled prose. 0.004 is the same order
  // as the tier-1 keyword layer's clean rate, discounted for the extra requirement that AMP exist.
  L53AMP: [0.10, 0.004],
  // P35b. AMP page whose own final URL leaves the domain for a gambling/junk-TLD host. Structurally the
  // same claim as L9REDIR, on a page nobody looks at.
  L53AMPREDIR: [0.05, 0.0015],
  // P36. THE strongest layer in this file. Ratio ~190 — one hit plus any single other bucket clears the
  // confirm line, which is the intended behaviour: a named web shell responding on the victim's own host
  // is not ambiguous and needs no AI adjudication. The clean rate is declared at 0.0008 rather than 0
  // because "declare zero" is how a layer becomes unfalsifiable; the honest measurement was 0/60.
  L48SHELL: [0.15, 0.0008],
  // P37. A .php inside wp-content/uploads is malicious by WordPress's own design — uploads is a media
  // directory. Held to 0.004 rather than lower because a handful of plugins (backup/file-manager kits)
  // do legitimately drop helper PHP there, and index.php/.htaccess exclusion does not cover all of them.
  L49UPLOADPHP: [0.10, 0.004],
  // P38. Same assertion as the WP search probe, spoken to Joomla/Drupal/OpenCart. Weaker than L30WPSEARCH
  // because these result pages are theme-rendered HTML, so the reflection risk is real and is beaten back
  // by a nonce differential rather than by a clean API contract.
  L55CMSDOOR: [0.35, 0.008],
  // P38 fingerprint + P39 exposure + P41 TLS: control-bucket only. Weights present because CONTRACT.md
  // requires an entry per layer id; a 1.0 ratio means that even if one of these ever escaped the control
  // bucket by mistake it would contribute exactly zero to the log-odds. Belt and braces.
  L54CMS: [0.5, 0.5],
  L56GITEXP: [0.5, 0.5],
  L57ENVEXP: [0.5, 0.5],
  L58BAKEXP: [0.5, 0.5],
  L60TLS: [0.5, 0.5],
  // P40. A certificate issued for slot-gacor.someschool.edu.bd is third-party, timestamped, and survives
  // the attacker deleting the vhost — but it is also only a NAME, and this module never confirms on a
  // name. Ratio ~60 makes it a strong promoter that still needs corroboration to reach the confirm line.
  L59CTSUB: [0.06, 0.001],
};

// Only fixed where the transport genuinely determines the category. The keyword-bearing layers (L53AMP,
// L55CMSDOOR, L59CTSUB) are left out so S.categoryOf() derives gambling/pharma/adult from the matched
// token — always more accurate than a label pinned on the door we happened to knock on.
//
// "exposure" is deliberately OUTSIDE CONTRACT.md's category vocabulary. It is not a hack category and must
// never be written as one; it exists so the exposure lead product can be filtered out of the raw signals.
// These layers are control-bucket, so scan.js's category() never sees the value.
export const CATS = {
  L48SHELL: "malware",
  L49UPLOADPHP: "malware",
  L53AMPREDIR: "redirect",
  L56GITEXP: "exposure",
  L57ENVEXP: "exposure",
  L58BAKEXP: "exposure",
};

// ---------------------------------------------------------------------------
// P36 — web-shell paths and fingerprints
// ---------------------------------------------------------------------------
// Ordered by observed prevalence on BD shared hosting, because the probe list is truncated by whatever
// fetch budget survives the earlier stages. wp-log.php / wp-conflg.php are the two that actually turn up
// (the second is a homoglyph of wp-config.php — deliberately chosen by the kit so an admin skims past it).
const SHELL_PATHS = [
  "/wp-content/uploads/wp-log.php",
  "/wp-conflg.php",
  "/wp-includes/wp-tmp.php",
  "/alfa.php",
  "/wso.php",
  "/shell.php",
];

// The fingerprint is the ENTIRE basis for a P36 emission. Every alternative is a banner, a title or a
// function name that only a shell prints.
//
// REJECTED from this list, and the reasoning matters more than the list itself:
//   `eval(`      — appears in half the minified JS on the internet; it was already removed from MALJS
//                  for false-confirming proshikkhon.com.
//   `base64_decode(` — legitimate in a hundred plugins; also this is a PHP *source* string and we are
//                  reading rendered OUTPUT, so it only shows up when the server is not executing PHP at
//                  all — i.e. exactly the case where we are looking at a source listing, not a live shell.
//   `<title>...login` — every locked shell prints a login form, but so does every wp-admin redirect and
//                  every cPanel error page. Missing a password-protected shell is the right trade.
const SHELL_FP = /wso\s*\d|indoxploit|\bb374k\b|alfa\s*(?:team|shell|v\d)|\bpriv8\b|symlink\s*sa|\bfilesman\b|<title>[^<]{0,60}(?:shell|bypass|webshell)[^<]{0,40}<\/title>|passthru\s*\(|\bshell_exec\s*\(|uname\s*-a\s*:|safe[_ ]mode\s*:\s*off/i;

// ---------------------------------------------------------------------------
// P37 — uploads-directory listing
// ---------------------------------------------------------------------------
const EXEC_EXT = /\.(php\d?|phtml|phps|pht|shtml|suspected|cgi|pl)$/i;
// Files that genuinely belong to WordPress plugins. index.php is the standard "Silence is golden" guard
// that dozens of plugins drop into every directory they create; .htaccess is WooCommerce's own protection.
const UPLOAD_ALLOW = /^(?:index\.php\d?|\.htaccess|web\.config)$/i;

// ---------------------------------------------------------------------------
// P38 — CMS fingerprints and their doorway search endpoints
// ---------------------------------------------------------------------------
// Only ONE search term is used, and it is `gacor`: Indonesian slang for a chirpy songbird, repurposed by
// the slot-spam industry. It is the single highest-prevalence token in BD WordPress hacks and — the part
// that matters — no English or Bengali word contains it as a substring. `casino`, `slot`, `bet` and
// `judi` were all rejected for this probe for the reasons written out in wpprobe.js: a full-text LIKE over
// post bodies with a colliding term promotes clean businesses into the lead list.
const DOOR_TERM = "gacor";
// A token that cannot exist in any corpus, used to prove the search endpoint actually filters. Without
// this control, a CMS that ignores its own search parameter returns its full catalogue and we would report
// every Joomla site on earth as compromised.
const NONCE_TERM = "zqxjvkbnwpq";

// ---------------------------------------------------------------------------
// P39 — exposure artefacts. path → [content proof, layer, human label]
// ---------------------------------------------------------------------------
// Order is by sales value, because this list is also truncated by remaining budget: a readable .git/config
// means the whole repository (and its history, and whatever credentials were ever committed) is
// downloadable; a readable .env is the live database password.
const EXPOSURE = [
  ["/.git/config", /repositoryformatversion\s*=/i, "L56GITEXP", "git repository config is publicly readable"],
  ["/.env", /^\s*(?:APP_KEY|DB_PASSWORD|DB_DATABASE|MAIL_PASSWORD|APP_ENV)\s*=/im, "L57ENVEXP", "environment file with live credentials is publicly readable"],
  ["/wp-config.php.bak", /DB_PASSWORD|DB_NAME|AUTH_KEY|SECURE_AUTH_KEY/i, "L58BAKEXP", "WordPress config backup is publicly downloadable"],
  ["/db.sql", /CREATE\s+TABLE|INSERT\s+INTO|MySQL\s+dump/i, "L58BAKEXP", "database dump is publicly downloadable"],
];

// ---------------------------------------------------------------------------
// P40 — certificate-transparency name test
// ---------------------------------------------------------------------------
// This is NOT S.RE.SPAMMY_DOMAIN. That regex was dry-run against a corpus of REGISTRABLE domains, where a
// bare `slot\d` or `\bbet\d` is safe because nobody registers "slot1.com" for a school. A SUBDOMAIN LABEL
// is a different namespace with different conventions: `slot1.college.edu.bd` is an entirely plausible
// class-timetable host, `bet2.` a plausible internal beta. So the digit-suffixed generics are removed and
// what remains is brand names and spam-only compounds, every one of which is either a registered gambling
// brand or a two-token construction that cannot occur by accident.
//
// Deliberately NOT included, for the reasons already burned into signatures.js: bare `xxx` (XXXL is a
// garment size), bare `sex` (Unisex Salon), bare `choti` (সandal), bare `chudi` (bangles), bare `bet`
// (sylhet/cabinet/alphabet), bare `slot` (timetable slots).
//
// DRY-RUN, 2026-07-20: derived every subdomain label present in the live queue (19,123 hostnames whose
// host differs from their registrable) and ran this regex over the LABEL only. 21 hits, all 21 eyeballed:
// vavada-casino-reviews-*, world-casino-*, pin-up-casino-*, casinox-*, najlepsze-polskie-kasyno-online —
// every one a genuine casino doorway parked under a hijacked .bd domain. Zero legitimate BD hostnames.
// The same sweep with the full SPAMMY_DOMAIN found only two more (1win-indian.in.bd, 1winen.in.bd), which
// is why the branded tail below was added back: brands are safe as labels, generics are not.
const CT_SPAM_LABEL = /casino|kasino|kasyno|kazino|cazino|cassino|togel|maxwin|sbobet|bocoran|gacor|situsjudi|judi-?(?:online|bola|slot)|slot-?(?:gacor|online|deposit|pulsa|thailand|dana|88|777)|toto-?(?:macau|hk|sgp|sdy|4d)|1xbet|melbet|betwinner|mostbet|parimatch|4rabet|jeetbuzz|jeetwin|bajilive|baji999|betvisa|bettilt|glorycasino|marvelbet|crickex|linebet|babu88|krikya|jaya9|rajabets|9wickets|pussy888|mega888|joker123|918kiss|pkvgames|sabungayam|mahjongways|pragmaticplay|\b1win|\b22bet|\b22win|\bbwin|dafabet|betway|betfair|betano|betsson|unibet|jilibet|netbet|donbet|betjili|winbet|megabet|betflix|porn|hentai|xhamster|redtube|youporn|brazzers|xvideos|xnxx|bokep|sexcam|sextube|kompoz|onlyfans|camgirl|desixxx|desichick|mmsviral|uncutullu|banglachoti|chotigolpo|chudachudi|chodachudi|banglapanu|banglaxxx|bangladeshixxx|xxxbanla|xxvid|bfvideo/i;

// crt.sh is a free, unfunded public service and the proposal's binding constraint. A per-isolate rolling
// hour cap keeps a 19k-domain/hr VM sweep from turning into an accidental denial of service; when the cap
// is hit the layer simply does not run, which is the correct degradation for a promoter-grade signal.
const CT_MAX_PER_HOUR = 120;
let CT_WINDOW_START = 0;
let CT_COUNT = 0;

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// Collapse a body to something comparable across two fetches of the same soft-404 template. Timestamps,
// request ids and CSRF nonces differ between two responses of an identical page, so raw equality is
// useless; digits and whitespace are dropped and only the first 400 chars of markup are kept.
function shape(t) {
  return String(t || "").slice(0, 4000).replace(/\d+/g, "#").replace(/\s+/g, " ").toLowerCase().slice(0, 400);
}

// "Materially different from the nonce response". Two soft-404s off the same template share a shape and a
// length; a real artefact does not.
function differs(text, cal) {
  if (!cal || !cal.soft404) return true;
  const a = shape(text), b = cal.shape;
  if (a === b) return false;
  const la = String(text || "").length, lb = cal.len || 0;
  if (lb && Math.abs(la - lb) < Math.max(64, lb * 0.05) && a.slice(0, 200) === b.slice(0, 200)) return false;
  return true;
}

function isHtml(r) {
  try {
    const ct = r && r.headers ? String(r.headers.get("content-type") || "") : "";
    if (/text\/html/i.test(ct)) return true;
  } catch (e) { /* headers unreadable — fall through to sniffing */ }
  return /^\s*(?:<!doctype html|<html|<\?xml[^>]*\?>\s*<!doctype html)/i.test(String((r && r.text) || "").slice(0, 200));
}

// ≤200-char verbatim window around the first match — this string is quoted to the business owner.
function proofNear(text, rx) {
  const t = String(text || "");
  const m = new RegExp(rx.source, rx.flags.replace(/g/g, "")).exec(t);
  if (!m) return "";
  const i = Math.max(0, m.index - 60);
  return t.slice(i, i + 180).replace(/\s+/g, " ").trim();
}

function pathOf(u) {
  try { return new URL(u).pathname || "/"; } catch (e) {
    return (String(u || "").replace(/^https?:\/\/[^/]*/i, "").split(/[?#]/)[0]) || "/";
  }
}

// Every same-host href on a page, absolutised. Used by the P38 nonce differential.
function linksOf(html, base, mine) {
  const out = new Set();
  const rx = /<a\b[^>]*\bhref=["']([^"']+)["']/gi;
  let m, n = 0;
  while ((m = rx.exec(html)) && n++ < 400) {
    let u = m[1];
    if (u.startsWith("//")) u = "https:" + u;
    else if (u.startsWith("/")) u = base + u;
    else if (!/^https?:\/\//i.test(u)) continue;
    if (mine(u)) out.add(u.split("#")[0]);
  }
  return out;
}

// ---------------------------------------------------------------------------
// P41 — TLS peer certificate (VM only)
// ---------------------------------------------------------------------------
// The Workers runtime has no socket API and this deployment carries no nodejs_compat flag, so `node:tls`
// must never become a statically-analysable import specifier — wrangler's bundler would try to resolve it
// at BUILD time and break the deploy of every shard. Building the specifier at runtime keeps esbuild from
// seeing it, and the process check means the branch is never even reached under Workers.
async function tlsCert(host) {
  try {
    if (typeof process === "undefined" || !process.versions || !process.versions.node) return null;
    const spec = ["node", "tls"].join(":");
    const tls = await import(/* webpackIgnore: true */ /* @vite-ignore */ spec);
    return await new Promise((resolve) => {
      let done = false;
      const finish = (v) => { if (!done) { done = true; try { sock.destroy(); } catch (e) {} resolve(v); } };
      // rejectUnauthorized:false is the whole point — an EXPIRED or MISMATCHED certificate is the finding.
      // Refusing the handshake would throw away exactly the sites we are trying to describe.
      const sock = tls.connect({ host, port: 443, servername: host, rejectUnauthorized: false, timeout: 7000 }, () => {
        let c = null;
        try { c = sock.getPeerCertificate(false); } catch (e) { c = null; }
        finish(c && c.valid_to ? c : null);
      });
      sock.on("error", () => finish(null));
      sock.on("timeout", () => finish(null));
      setTimeout(() => finish(null), 8000);
    });
  } catch (e) { return null; }
}

// RFC 6125 wildcard matching, one level only: *.example.com covers a.example.com and NOT a.b.example.com.
function certCovers(cert, host) {
  const names = [];
  try {
    const san = String(cert.subjectaltname || "");
    for (const p of san.split(",")) { const m = /DNS:(\S+)/i.exec(p.trim()); if (m) names.push(m[1].toLowerCase()); }
    if (cert.subject && cert.subject.CN) names.push(String(cert.subject.CN).toLowerCase());
  } catch (e) { return true; }
  if (!names.length) return true;   // nothing to test against → do not claim a mismatch
  const h = String(host || "").toLowerCase();
  for (const n of names) {
    if (n === h) return true;
    if (n.startsWith("*.") && h.endsWith(n.slice(1)) && h.split(".").length === n.split(".").length) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
export async function run(ctx) {
  const out = [];
  try {
    const S = ctx.S;
    const reg = ctx.reg;
    const base = ctx.base;
    const B = ctx.B;
    const bodyB = (B && B.text) || "";
    const visB = ctx.visB || "";
    if (!ctx.deep || !base || !reg) return out;

    // Hard local ceiling on top of ctx.budget. Tier 2 shares its fetch allowance with every other t2
    // module in the pipeline; a module that drains the pool on speculative file probes starves the ones
    // that read actual content. 16 is the proposal's upper bound for the whole tier-2 stage.
    let localLeft = 16;
    const spend = (n) => {
      if (ctx.overBudget && ctx.overBudget()) return false;
      if (localLeft < n) return false;
      if (ctx.budget && typeof ctx.budget.fetches === "number") {
        if (ctx.budget.fetches < n) return false;
        ctx.budget.fetches -= n;
      }
      localLeft -= n;
      return true;
    };
    const push = (bucket, layer, match, url) => {
      const m = String(match || "").replace(/\s+/g, " ").trim().slice(0, 200);
      if (m) out.push({ bucket, layer, match: m, url: String(url || base).slice(0, 300) });
    };
    const mine = (u) => { try { return ctx.sameHost(ctx.hostOf(u), reg); } catch (e) { return false; } };
    const get = (u, ms) => ctx.fetchPage(u, ctx.UA_BR, null, ms || 8000);

    const bizType = (() => {
      try { return S.bizType(reg, (bodyB.match(/<title[^>]*>([\s\S]*?)<\/title>/i) || ["", ""])[1] || "", visB); }
      catch (e) { return ""; }
    })();

    // =====================================================================
    // P35 · L53AMP — the forgotten twin.
    //
    // An AMP page is generated by a separate plugin into a separate template. Cleanup crews clean the
    // theme, the database and the uploads directory, declare victory, and leave /?amp= serving the same
    // injected footer — which Google is still indexing, which is why the site's rankings never recover
    // and the owner is still angry. Fetched as Googlebot with the Google referer because AMP exists for
    // search traffic and several doorway kits serve it conditionally.
    // =====================================================================
    let ampUrl = "";
    const amp = /<link[^>]+rel=["']amphtml["'][^>]*>/i.exec(bodyB) || /<link[^>]*\bhref=["'][^"']+["'][^>]*rel=["']amphtml["'][^>]*>/i.exec(bodyB);
    if (amp) {
      const h = /href=["']([^"']+)["']/i.exec(amp[0]);
      if (h) {
        let u = h[1];
        if (u.startsWith("//")) u = "https:" + u;
        else if (u.startsWith("/")) u = base + u;
        // cdn.ampproject.org serves Google's own cached copy. That is Google's bytes, not the site's,
        // and reporting spam found there as if it were on the customer's server is simply wrong.
        if (/^https?:\/\//i.test(u) && mine(u)) ampUrl = u;
      }
    }
    if (ampUrl && spend(1)) {
      try {
        const A = await ctx.fetchPage(ampUrl, ctx.UA_GB, ctx.REF_G, 9000);
        if (A && A.status === 200 && A.text) {
          const av = ctx.stripHtml(A.text);
          // A BD news outlet's AMP homepage legitimately carries "মেলবেট অ্যাপে জুয়া, গ্রেপ্তার ৫" —
          // betting-app arrests are a recurring news beat here. Same guard as wpprobe.js: for news sites
          // the keyword half is dropped entirely and only the redirect half survives, because journalism
          // cannot produce an off-domain redirect to a casino.
          if (bizType !== "news" && av && S.ALL_STRONG.test(av) && !S.RE.WAF.test(av.slice(0, 1200))) {
            push("homepage-content", "L53AMP", "AMP copy of this page still serves: " + (proofNear(av, S.REG.ALL_STRONG) || av.slice(0, 160)), ampUrl);
          }
          const fh = ctx.hostOf(A.finalUrl || "");
          if (fh && !ctx.sameHost(fh, reg) && (S.RE.GAMB_STRONG.test(A.finalUrl) || S.RE.JUNKTLD.test(A.finalUrl))) {
            push("redirect", "L53AMPREDIR", "AMP page redirects off-domain to " + fh, A.finalUrl);
          }
        }
      } catch (e) { /* no AMP / blocked — the common case */ }
    }

    // =====================================================================
    // CALIBRATION — run once, lazily, before the first file probe.
    // =====================================================================
    let cal = null;
    const calibrate = async () => {
      if (cal) return cal;
      cal = { ok: false, soft404: false, shape: "", len: 0 };
      // A path that no installer, plugin or attacker would ever create. Randomised per scan so a host
      // cannot have it cached or whitelisted.
      const nonce = "zq7x9k2m" + Math.random().toString(36).slice(2, 8);
      if (!spend(1)) return cal;
      try {
        const R = await get(base + "/" + nonce + ".php", 7000);
        if (!R || !R.status) return cal;         // host refused to answer at all → probes stay off
        cal.ok = true;
        if (R.status === 200) { cal.soft404 = true; cal.shape = shape(R.text); cal.len = String(R.text || "").length; }
      } catch (e) { /* leave cal.ok false → every file probe below declines to run */ }
      return cal;
    };

    // =====================================================================
    // P36 · L48SHELL — verified web-shell probe.
    //
    // The emission condition is: 200 AND fingerprint AND (host is not soft-404, or the body differs
    // materially from the nonce body). Status alone is never enough, and on a soft-404 host status is not
    // even an input. This is the layer with the highest likelihood ratio in the file and it earns it by
    // quoting a shell's own banner back to the site owner.
    // =====================================================================
    const c = await calibrate();
    if (c.ok) {
      for (const p of SHELL_PATHS) {
        if (!spend(1)) break;
        try {
          const R = await get(base + p, 7000);
          if (!R || R.status !== 200 || !R.text) continue;
          if (!SHELL_FP.test(R.text)) continue;
          if (!differs(R.text, c)) continue;
          push("webshell", "L48SHELL", "live web shell responding: " + (proofNear(R.text, SHELL_FP) || p), base + p);
          break;   // one proven shell is the whole pitch; further probes buy nothing and cost budget
        } catch (e) { /* path absent — the overwhelmingly common outcome */ }
      }
    }

    // =====================================================================
    // P37 · L49UPLOADPHP — an executable sitting in the media directory.
    //
    // wp-content/uploads is where WordPress puts images. A .php file there was placed by something that
    // was not WordPress. The proof URL is screenshotable, which makes this unusually persuasive in an
    // outreach message: the owner can click it and see the file listed on their own site.
    // =====================================================================
    const wpish = /wp-content|wp-includes|\/wp-json|rel=["']https:\/\/api\.w\.org/i.test(bodyB);
    if (wpish && c.ok) {
      const yr = new Date().getFullYear();
      for (const dir of ["/wp-content/uploads/", "/wp-content/uploads/" + yr + "/"]) {
        if (!spend(1)) break;
        try {
          const R = await get(base + dir, 8000);
          if (!R || R.status !== 200 || !R.text) continue;
          // Autoindex markup from Apache, nginx and LiteSpeed all carry this string. A themed 200 page
          // does not, which is also why this probe does not need the soft-404 differential: no soft-404
          // template announces "Index of /".
          if (!/index of \//i.test(R.text)) continue;
          const files = [];
          const rx = /<a\b[^>]*\bhref=["']([^"'?#]+)["']/gi;
          let m, n = 0;
          while ((m = rx.exec(R.text)) && n++ < 500) {
            const name = decodeURIComponent(m[1].split("/").filter(Boolean).pop() || "");
            if (!name || UPLOAD_ALLOW.test(name)) continue;
            if (EXEC_EXT.test(name)) files.push(name);
          }
          const uniq = [...new Set(files)];
          if (uniq.length) {
            push("webshell", "L49UPLOADPHP", "executable file in the media folder: " + uniq.slice(0, 3).join(" , "), base + dir);
            break;
          }
        } catch (e) { /* listing disabled — normal and healthy */ }
      }
    }

    // =====================================================================
    // P38 · L54CMS / L55CMSDOOR — the three-quarters of the corpus that is WordPress, and the quarter
    // that is not.
    //
    // L11REST (0.88/0.010) is the strongest doorway layer in the detector and it is *completely dead* on
    // Joomla, Drupal and OpenCart. Those sites get hacked at least as often — arguably more, since an
    // abandoned Joomla 3 install is the archetypal BD SMB site — and today the detector has nothing to
    // say about their content at all. This restores content enumeration for them.
    //
    // THE REFLECTION TRAP is worse here than in wpprobe.js, because these are theme-rendered result pages
    // that print the query back in the <title>, in the form's value attribute, and in every pagination
    // href. Matching raw HTML would fire on 100% of Joomla sites. Two defences: (1) the search term is
    // masked out of the text before any keyword test, so a hit requires OTHER spam vocabulary to survive;
    // (2) a nonce query is fetched and its result links are subtracted, so only URLs that appeared
    // *because of* the real term count.
    // =====================================================================
    let cms = "";
    let cmsHint = "";
    try {
      const hdr = (k) => { try { return B && B.headers ? String(B.headers.get(k) || "") : ""; } catch (e) { return ""; } };
      const gen = hdr("x-generator") + " " + hdr("x-powered-by") + " " + hdr("set-cookie");
      if (wpish) { cms = "wordpress"; }
      else if (/joomla/i.test(gen) || /\/media\/(?:jui|system|vendor)\/|option=com_(?:content|contact|users)|\/templates\/[a-z0-9_-]+\/css\/template/i.test(bodyB)) cms = "joomla";
      else if (/drupal/i.test(gen) || /\/sites\/(?:default|all)\/(?:files|themes|modules)\/|drupal-settings-json|Drupal\.settings/i.test(bodyB)) cms = "drupal";
      else if (/opencart/i.test(gen) || /index\.php\?route=(?:common|product|account|checkout)\//i.test(bodyB)) cms = "opencart";
      else if (/laravel_session/i.test(gen) || /\/(?:build|vendor)\/laravel|csrf-token/i.test(bodyB) && /laravel/i.test(bodyB)) cms = "laravel";
      else if (/magento|Mage\.Cookies|\/static\/version\d+\//i.test(bodyB)) cms = "magento";
      const gm = /<meta[^>]+name=["']generator["'][^>]+content=["']([^"']{0,80})["']/i.exec(bodyB);
      if (gm) cmsHint = gm[1];
    } catch (e) { /* fingerprinting is best-effort */ }
    if (cms) push("control", "L54CMS", "cms=" + cms + (cmsHint ? " generator=" + cmsHint : ""), base + "/");

    // WordPress is excluded here on purpose: wpprobe.js already owns the WP search probe and running both
    // would spend budget to re-derive the same fact into the same bucket.
    const DOORS = {
      joomla: (t) => base + "/index.php?option=com_search&searchword=" + t,
      drupal: (t) => base + "/search/node?keys=" + t,
      opencart: (t) => base + "/index.php?route=product/search&search=" + t,
    };
    if (DOORS[cms] && spend(2)) {
      try {
        const [H, N] = await Promise.all([
          ctx.fetchPage(DOORS[cms](DOOR_TERM), ctx.UA_GB, null, 9000),
          ctx.fetchPage(DOORS[cms](NONCE_TERM), ctx.UA_GB, null, 9000),
        ]);
        if (H && H.status === 200 && H.text && N && N.status === 200 && N.text) {
          const hl = linksOf(H.text, base, mine), nl = linksOf(N.text, base, mine);
          // THE ECHO LIVES IN THE QUERY STRING, NOT THE PATH. Pagination, sort and the search form itself
          // all re-emit `?searchword=gacor`, so any URL carrying the term in its QUERY is our own voice
          // coming back and is dropped. A URL carrying it in its PATH is the opposite — /slot-gacor-2024/
          // is a permalink the site published, and it is the single best piece of evidence this probe can
          // return. An earlier version filtered on the whole URL and threw that away; it silently reduced
          // the layer to the text branch alone.
          const echoed = (u) => { try { return (new URL(u).search || "").toLowerCase().includes(DOOR_TERM); } catch (e) { return u.toLowerCase().includes("=" + DOOR_TERM); } };
          const delta = [...hl].filter((u) => !nl.has(u) && !echoed(u));
          const slugHit = delta.filter((u) => S.RE.SLUG_SPAM.test(pathOf(u)));
          // Mask the term out of both bodies, then ask whether OTHER strong spam vocabulary is present in
          // the real result page and absent from the nonce page. "Search results for gacor" contributes
          // nothing after masking; "Situs slot gacor terpercaya deposit pulsa" still does.
          const maskRx = new RegExp(DOOR_TERM, "gi");
          const hv = ctx.stripHtml(H.text).replace(maskRx, " ");
          const nv = ctx.stripHtml(N.text).replace(maskRx, " ");
          const textHit = S.ALL_STRONG.test(hv) && !S.ALL_STRONG.test(nv);
          if (slugHit.length) {
            push("content-enum", "L55CMSDOOR", cms + " site search returns published spam URLs: " + slugHit.slice(0, 2).map(pathOf).join(" ; "), slugHit[0]);
          } else if (textHit && delta.length) {
            push("content-enum", "L55CMSDOOR", cms + " site search returns spam content: " + (proofNear(hv, S.REG.ALL_STRONG) || hv.slice(0, 150)), DOORS[cms](DOOR_TERM));
          }
        }
      } catch (e) { /* search component removed/disabled — common on hardened Joomla 4 */ }
    }

    // =====================================================================
    // P39 · L56GITEXP / L57ENVEXP / L58BAKEXP — the SEPARATE product.
    //
    // Everything here is bucket:"control" and therefore arithmetically incapable of moving the hack
    // posterior. That is not caution, it is the product definition: "your database password is on the
    // public internet" is a real, sellable finding and a completely different sentence from "your site is
    // hacked". Mixing them would corrupt confirmed=1, which is the number the dashboard, the export and
    // the outreach all rest on.
    //
    // Content confirmation is mandatory and doing it by content-type alone is not enough: a soft-404 host
    // serving its themed 404 for /.env returns text/html, but a host serving a REAL .env may also be
    // mislabelled by a misconfigured mime map. So: must not look like HTML, must match the artefact's own
    // structure, and must differ from the nonce body.
    // =====================================================================
    if (c.ok) {
      for (const [p, proof, layer, label] of EXPOSURE) {
        if (!spend(1)) break;
        try {
          const R = await get(base + p, 7000);
          if (!R || R.status !== 200 || !R.text) continue;
          if (isHtml(R)) continue;                 // a themed error page, not a config file
          if (!proof.test(R.text)) continue;
          if (!differs(R.text, c)) continue;
          // The proof string is shown to the business owner and travels into D1, an export and an email,
          // so it must NAME the artefact without REPRODUCING the credential. Quote the matching line
          // itself (not a context window — that would start 60 chars earlier on an unrelated key) and
          // redact anything to the right of the `=`.
          const line = (String(R.text).split(/[\r\n]+/).find((l) => proof.test(l)) || "")
            .trim().slice(0, 90).replace(/(=\s*)\S.*$/, "$1<redacted>");
          push("control", layer, label + " — " + line, base + p);
        } catch (e) { /* absent — the normal case */ }
      }
    }

    // =====================================================================
    // P40 · L59CTSUB — certificate transparency.
    //
    // Attackers provision slot-gacor.<victim>.edu.bd, let Let's Encrypt log it, run the doorway for a few
    // months and then remove the vhost. The DNS record is gone, the page is gone, the spam is still in
    // Google's index and the CT log still holds a timestamped, third-party record of the day it happened.
    // That date is the most persuasive line in the outreach email: "your domain issued a certificate for
    // slot-gacor.yourschool.edu.bd on 12 March — you did not do that."
    //
    // The name test is CT_SPAM_LABEL, not SPAMMY_DOMAIN, and it is applied to the SUBDOMAIN LABELS only.
    // See the comment on that constant for why the difference is load-bearing.
    // =====================================================================
    const ctAllowed = () => {
      const now = Date.now();
      if (now - CT_WINDOW_START > 3600000) { CT_WINDOW_START = now; CT_COUNT = 0; }
      if (CT_COUNT >= CT_MAX_PER_HOUR) return false;
      CT_COUNT++;
      return true;
    };
    // If the registrable itself is a gambling/porn brand, every subdomain matches and the finding is
    // meaningless — scan.js parks those domains anyway.
    if (!S.domainSpammy(reg) && ctAllowed() && spend(1)) {
      try {
        const R = await ctx.fetchPage("https://crt.sh/?q=%25." + encodeURIComponent(reg) + "&output=json", ctx.UA_BR, null, 12000);
        const txt = (R && R.text) || "";
        if (R && R.status === 200 && txt) {
          const names = new Set();
          let rows = null;
          try { rows = JSON.parse(txt); } catch (e) { rows = null; }
          if (Array.isArray(rows)) {
            for (const r of rows.slice(0, 3000)) {
              for (const nm of String((r && r.name_value) || "").split(/\s+/)) if (nm) names.add(nm.toLowerCase());
              if (r && r.common_name) names.add(String(r.common_name).toLowerCase());
            }
          } else {
            // crt.sh JSON for a busy domain exceeds the capped read and arrives truncated. A regex sweep
            // over whatever bytes did arrive is strictly better than discarding the whole response.
            let m, g = 0;
            const rx = /"(?:name_value|common_name)":"([^"]{1,300})"/g;
            while ((m = rx.exec(txt)) && g++ < 3000) for (const nm of m[1].split(/\\n|\s+/)) if (nm) names.add(nm.toLowerCase());
          }
          const hits = [];
          for (const nm of names) {
            const h = nm.replace(/^\*\./, "").replace(/\.$/, "");
            if (!h.endsWith("." + reg)) continue;              // strict subdomain of THIS organisation only
            const sub = h.slice(0, h.length - reg.length - 1);
            if (!sub || sub === "www") continue;
            if (CT_SPAM_LABEL.test(sub)) hits.push(h);
          }
          const uniq = [...new Set(hits)];
          if (uniq.length) {
            push("ct-subdomain", "L59CTSUB", "certificate issued for a spam subdomain of your own domain: " + uniq.slice(0, 3).join(" , "), "https://crt.sh/?q=%25." + reg);
          }
        }
      } catch (e) { /* crt.sh down or rate-limiting — a promoter signal, safe to lose */ }
    }

    // =====================================================================
    // P41 · L60TLS — certificate forensics. CONTROL ONLY, FOREVER.
    //
    // An expired certificate is not a hack; it is an unmaintained site, and plenty of healthy businesses
    // let one lapse over Eid. Its value is twofold and neither involves the posterior: it is a promoter
    // (an unmaintained site is where compromises live, so it deserves the deep pass) and it is a second,
    // honest sales angle ("your HTTPS expired 40 days ago, visitors see a browser warning").
    // =====================================================================
    const cert = await tlsCert(reg);
    if (cert && cert.valid_to) {
      const to = Date.parse(cert.valid_to), from = Date.parse(cert.valid_from);
      const now = Date.now();
      const expired = Number.isFinite(to) && to < now ? 1 : 0;
      const ageDays = Number.isFinite(from) ? Math.max(0, Math.round((now - from) / 86400000)) : -1;
      const daysLeft = Number.isFinite(to) ? Math.round((to - now) / 86400000) : -1;
      const mismatch = certCovers(cert, reg) ? 0 : 1;
      let issuer = "";
      try { issuer = String((cert.issuer && (cert.issuer.O || cert.issuer.CN)) || "").slice(0, 40); } catch (e) {}
      push("control", "L60TLS", `tls_expired=${expired} tls_mismatch=${mismatch} cert_age_days=${ageDays} days_left=${daysLeft} issuer=${issuer}`, base + "/");
    }
  } catch (e) { return out; }
  return out;
}
