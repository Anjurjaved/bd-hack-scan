// obfusc.js — P8/P9/P10: decode obfuscated payloads and re-run the STRONG keyword set on the plaintext.
//
// The whole point of this module is that the signal comes from the DECODED text hitting ALL_STRONG,
// never from the presence of base64/escapes/atob. Legitimate sites carry encoded bytes constantly:
// inline WOFF2 fonts, data:image PNGs, source maps, page-builder settings blobs, Bengali URL slugs
// (%E0%A6%…), `&#39;` apostrophes. Every one of those must decode to something harmless and be dropped.
//
// Three invariants keep this at a near-zero false-positive rate. They are load-bearing; do not relax them:
//
//   1. data: URIs are blanked out BEFORE blob extraction. They are ~all of the base64 on a normal page
//      and 100% of the binary. Decoding them is pure CPU cost and pure FP risk.
//   2. A decoded blob must survive a TEXT-LIKENESS gate (U+FFFD replacement ratio + control-char ratio)
//      before any keyword regex touches it. Without this, random bytes are a genuine FP source, not a
//      theoretical one: at 160KB decoded per site × 300k sites we scan ~5e10 byte positions, and a
//      3-letter alternative like `\bpkv\b` has a ~6e-8 per-position hit rate in uniform noise — that is
//      thousands of manufactured "leads" from decoded JPEGs alone.
//   3. REVEAL-ONLY: a decoded token is discarded if it already appears verbatim in the raw HTML. If the
//      keyword is sitting in plain sight, L1KW_STRONG in scan.js already owns it — re-emitting it here
//      would hand the fuser a SECOND bucket for ONE piece of evidence and let a single visible keyword
//      cross the nbuckets>=2 confirmation gate on its own.
//
//   4. OBFUSCATION IS NOT EVIDENCE. Only what it hides is. The corpus proved this outright: prayasbd.com
//      (hacked) and erp.bcsadminacademy.gov.bd (a real BD government academy) carry the *byte-identical*
//      `_0x` obfuscator shape — hex string table, hex identifiers, the lot. The hacked one decodes to
//      `http://kutlly.com/sJG2c7`; the government one decodes to `toLowerCase`, `contextmenu` and
//      "Sorry, This Functionality Has Been Disabled!", i.e. a right-click blocker. Any layer that scored
//      the shape would have sold a hack-cleanup to a government academy. That is why L26LOADER is
//      `control`-bucket and why P10 is not, and must not become, a scoring layer.
//
// L24B64, L25ESCAPE and L25URL share the `obfuscated` bucket because they read the same bytes (raw B/G/tail
// HTML). L26LOADER emits into `control` and never scores — see the measurement note on its WEIGHTS entry.

import * as SIG from "../signatures.js";

export const WEIGHTS = {
  // P(clean) MEASURED: 0 hits in 1,720 live non-hacked pages (812 scanned-clean BD control + 908 sampled
  // straight from the live queue). That bounds the true rate at roughly 1/570 at 95%, so the declared 0.005
  // is still ~3x pessimistic against the measurement, which is the direction the contract asks for.
  //
  // P(hacked) is an ESTIMATE, not a measurement, and is deliberately low. It measured 0/561 on the confirmed
  // set — but that set is selection-biased by construction: it only contains hacks the *existing* plaintext
  // detector could already see, so it under-represents the encoded payloads this module exists to find. A low
  // P(hacked) is the honest encoding of "this fires rarely"; the discriminating power lives in the tiny
  // P(clean), and the resulting ratio (60) deliberately lands a lone decoded payload in `review`, not `lead`.
  // Confirmation still requires a second bucket from another module. That is the intended behaviour.
  L24B64: [0.30, 0.005],
  L25ESCAPE: [0.25, 0.008],
  // P(clean) MEASURED: 0 in 2,130 non-hacked pages (1,786 corpus + 344 freshly fetched BD news/school/
  // madrasa/hospital sites, the population most likely to run an obfuscated right-click blocker). The
  // rule-of-three 95% bound is 0.0014, so the declared 0.004 stays ~3x pessimistic. Kept as-is.
  //
  // P(hacked) LOWERED 0.30 -> 0.06 on adversarial review. 0.30 was not a measurement: the same comment
  // block records the measurement as 3/561 = 0.0053, and then declared a number 57x larger. Selection bias
  // in the confirmed set genuinely justifies going ABOVE the measurement (that set only contains hacks the
  // plaintext detector already caught, so encoded-only payloads are systematically missing) — but not by
  // 57x. Laplace-smoothed over the real counts (3/561 vs 0/2130) the likelihood ratio is 15, not 75.
  //
  // The ratio is what the fuser consumes, and 75 was doing real damage at the confirmation gate: it put a
  // lone L25URL at posterior 0.911, so ANY second bucket with LR >= 3.2 — i.e. essentially every layer in
  // the system, including weak ones like L52COMMENT (LR 14, fires on a LiteSpeed Cache banner) — tipped the
  // site to CONFIRM and sold a cleanup. At LR 15 a lone hit sits at 0.672 and the second bucket must supply
  // LR >= 15.8, which is the contract's "widen the corroboration requirement" (rule 4).
  //
  // This costs ZERO recall on every hit ever measured: all 3 confirmed hacks carry 2-4 further buckets from
  // other modules (hidden/tail-content/stuffing/link-neighbourhood) and still confirm at 0.9996+.
  // This is also the only scoring layer here with no keyword grounding — it fires on URL shape alone — so it
  // is the one that most needs corroboration. L24B64/L25ESCAPE are bound to ALL_STRONG and are left as-is.
  L25URL: [0.06, 0.004],
  // NOT USED — L26LOADER emits into the `control` bucket, which score() filters out before fusing. The entry
  // exists because the contract requires a WEIGHTS key per layer id. Retained here as the record of why:
  // every candidate loader shape was measured across 561 hacked / 812 clean / 908 queue pages and NONE of
  // them discriminates on the Bangladeshi population. `document.write(unescape(` and `unescape("%XX` have a
  // likelihood ratio of ~0 — they fire on join.army.mil.bd, olm.ccie.gov.bd, sims.pu.edu.bd and other
  // legitimate institutions, because BD government and school sites run 2005-era JavaScript where those are
  // ordinary idioms. `atob(` alone: 0.12% clean / 2.09% queue / 0.71% hacked, LR 0.61. The shapes with LR>1
  // (packer 3.07, long \x run 4.60, _0x hex-array 2.30) rest on 1-3 hacked hits and are statistically empty.
  // Do not promote this layer to a scoring bucket without new measurement — as scored evidence it would have
  // manufactured roughly 1,800 spurious `review` rows over a 300k-domain pass while adding no recall.
  L26LOADER: [0.55, 0.120],
};

// L24B64/L25ESCAPE carry a decoded gambling/pharma/adult token as their `match`, so scan.js's categoryOf()
// derives the right category from the proof itself — declaring them here would only override a better answer.
// L25URL is different: its proof is a bare hostname, which categoryOf() cannot classify, so without an entry
// here it would fall through to the default "gambling". Every instance measured was a hidden off-domain
// redirect (URL shorteners in a mobile-redirect payload), so "redirect" is the honest label.
// L26LOADER is control-bucket and never reaches category() at all.
export const CATS = { L25URL: "redirect" };

export const TIER = "t1";

// ---------------------------------------------------------------------------
// Budgets. Sized for the 946MB Oracle VM at ~300k domains: worst case per domain
// is 20 blobs × 8KB decoded + 64KB of escape output ≈ 224KB of regex input on top
// of the page itself. Everything below is a hard stop, not a hint.
// ---------------------------------------------------------------------------
const MAX_INPUT = 230000;      // total raw HTML we will look at (B + G + tail, deduped)
const MAX_BLOBS = 20;          // base64 candidates decoded per domain
const MIN_BLOB = 80;           // shorter than this is an integrity hash / nonce / tracking id, not a payload
const MAX_BLOB_IN = 12000;     // encoded chars fed to atob (→ ~9KB decoded)
const MAX_BLOB_OUT = 8000;     // decoded chars we keep per blob
const MAX_ESCAPE_OUT = 64000;  // total decoded escape output per domain
const MAX_RUNS = 300;          // escape runs decoded per domain

// A decoded blob is TEXT if it is valid-ish UTF-8 and free of control bytes. Binary (JPEG/WOFF/ZIP) fails
// both by a wide margin, so the thresholds do not need to be finely tuned — 2% is simply "not zero, but
// nowhere near what a compressed stream produces".
const MAX_REPLACEMENT_RATIO = 0.02;
const MAX_CONTROL_RATIO = 0.02;

// Blanked before blob extraction. `data:` covers inline images, fonts and source maps in one stroke; the
// others are fixed-shape base64 that is structurally incapable of being a payload.
// The MIME/parameter part is ONE bounded character class on purpose. It was written as
// `[a-z0-9.+-]*\/?[a-z0-9.+-]*`, i.e. two unbounded greedy classes over the same alphabet separated by an
// optional `/`. That is ambiguous: for `data:` followed by N matching chars and no `;base64,`, the engine
// tries every split of N between the two stars, which is O(N^2). It is reachable on attacker-controlled
// input — a page containing `data:` + 230KB of `a` (the MAX_INPUT cap) measured **46.7 seconds** in one
// call, and 9.6s at the 96KB per-fetch cap. On the Cloudflare shards that is the documented CPU-wall stall;
// on the VM it wedges a worker slot. Single class + `{0,80}` is linear and bounded: same input, 0-6ms.
// `;=` are inside the class so `data:application/font-woff2;charset=utf-8;base64,` is stripped too — those
// inline WOFF2 blobs are the largest base64 on a normal page, so blanking them is also the cheapest win.
const RE_DATA_URI = /data:[a-z0-9.+/;=-]{0,80}base64,[A-Za-z0-9+/=\s]{40,}/gi;
const RE_SOURCEMAP = /\/\/[#@]\s*source(?:Mapping)?URL\s*=\s*\S+/gi;
const RE_INTEGRITY = /\bintegrity\s*=\s*["'][^"']*["']/gi;
const RE_B64_BLOB = /[A-Za-z0-9+/]{80,}={0,2}/g;

// Escape RUNS only. Isolated escapes are ordinary code and ordinary markup: minified JS is full of `\x22`,
// every WordPress page emits `&#39;`, and every Bengali permalink is a wall of `%E0%A6%xx`. A run of four or
// more consecutive escapes is a deliberate act — nobody hand-encodes four characters in a row by accident.
const RE_HEX_RUN = /(?:\\x[0-9A-Fa-f]{2}){4,}/g;
const RE_UNI_RUN = /(?:\\u[0-9A-Fa-f]{4}){4,}/g;
const RE_PCT_RUN = /(?:%[0-9A-Fa-f]{2}){4,}/g;
const RE_ENT_RUN = /(?:&#(?:x[0-9A-Fa-f]{1,5}|[0-9]{1,7});){4,}/g;

// P10 loader shapes — DIAGNOSTIC ONLY, emitted into the `control` bucket.
//
// The list below is what is left after dropping every shape the measurement showed to be a Bangladeshi
// legacy-code idiom rather than an attacker fingerprint: `document.write(unescape(`, `unescape("%XX` and
// bare `atob(`/`unescape(` are gone (details on the L26LOADER WEIGHTS entry). What remains is obfuscator
// output — code shapes a human does not hand-write. It earns its place by explaining HOW a decoded payload
// executes when L24B64/L25ESCAPE fire alongside it, which is worth having in the outreach conversation.
// It does NOT earn a vote in the fuser, and the `control` bucket is what enforces that.
const LOADERS = [
  [/eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e/i, "packer"],
  [/(?:eval|new\s+Function|document\.write(?:ln)?|setTimeout|setInterval)\s*\(\s*(?:window\s*\.\s*)?atob\s*\(/i, "atob-to-sink"],
  [/\beval\s*\(\s*(?:unescape|decodeURIComponent)\s*\(/i, "unescape-to-eval"],
  [/String\.fromCharCode\s*\(\s*\d{1,3}(?:\s*,\s*\d{1,3}){19,}/, "charcode-array"],
  [/\[\s*["']constructor["']\s*\]\s*\[\s*["']constructor["']\s*\]/, "constructor-chain"],
  [/(?:\\x[0-9A-Fa-f]{2}){8,}/, "hex-string-run"],
  [/\b_0x[a-f0-9]{4,6}\b/, "hex-identifier"],
];

function textDecode(bytes) {
  try {
    return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  } catch (e) {
    return "";
  }
}

function ratio(s, re) {
  const m = s.match(re);
  return m ? m.length / s.length : 0;
}

// Rejects binary before it ever meets a keyword regex. See invariant 2 at the top of the file.
function looksLikeText(s) {
  if (s.length < 8) return false;
  if (ratio(s, /\uFFFD/g) > MAX_REPLACEMENT_RATIO) return false;
  // eslint-disable-next-line no-control-regex
  if (ratio(s, /[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g) > MAX_CONTROL_RATIO) return false;
  return true;
}

function b64decode(s) {
  try {
    let t = s.replace(/=+$/, "");
    const rem = t.length % 4;
    if (rem === 1) t = t.slice(0, -1);       // impossible length; drop the stray char rather than throw
    else if (rem) t += "=".repeat(4 - rem);
    const bin = atob(t);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i) & 0xff;
    return textDecode(bytes);
  } catch (e) {
    return "";
  }
}

function fromHexRun(run) {
  let out = "";
  for (const m of run.matchAll(/\\x([0-9A-Fa-f]{2})/g)) out += String.fromCharCode(parseInt(m[1], 16));
  // \xHH is latin1-per-byte, so a UTF-8 payload arrives as mojibake; re-assemble it as bytes.
  const bytes = new Uint8Array(out.length);
  for (let i = 0; i < out.length; i++) bytes[i] = out.charCodeAt(i) & 0xff;
  const utf8 = textDecode(bytes);
  return utf8.indexOf("\uFFFD") === -1 ? utf8 : out;
}

function fromUniRun(run) {
  let out = "";
  for (const m of run.matchAll(/\\u([0-9A-Fa-f]{4})/g)) out += String.fromCharCode(parseInt(m[1], 16));
  return out;
}

function fromPctRun(run) {
  try {
    return decodeURIComponent(run);
  } catch (e) {
    // Malformed sequences are common in injected junk; fall back to a byte-wise read.
    let out = "";
    for (const m of run.matchAll(/%([0-9A-Fa-f]{2})/g)) out += String.fromCharCode(parseInt(m[1], 16));
    return out;
  }
}

function fromEntRun(run) {
  let out = "";
  for (const m of run.matchAll(/&#(x[0-9A-Fa-f]{1,5}|[0-9]{1,7});/g)) {
    const cp = m[1][0] === "x" || m[1][0] === "X" ? parseInt(m[1].slice(1), 16) : parseInt(m[1], 10);
    if (cp > 0 && cp <= 0x10ffff) out += String.fromCodePoint(cp);
  }
  return out;
}

// Benign infrastructure that has no business being a lead. The measurement below never saw any of these
// arrive via an escape run, so this list is insurance for the 297k domains the sample could not cover
// rather than a fix for an observed false positive.
const URL_SKIP = /(?:^|\.)(?:google|gstatic|googleapis|googletagmanager|google-analytics|doubleclick|youtube|facebook|fbcdn|instagram|twitter|linkedin|cloudflare|cloudfront|akamai|fastly|jsdelivr|unpkg|bootstrapcdn|jquery|fontawesome|w3\.org|schema\.org|wordpress|wp\.com|gravatar|paypal|stripe|trustpilot|bing|microsoft|apple|adobe)\./i;

// A decoded off-domain URL. Measured on 561 hacked / 812 clean / 908 queue pages: 3 hacked, 0 non-hacked —
// and all three were URL shorteners (kutlly.com, urlcuttly.net, zeep.ly) inside the `_0x` obfuscator string
// table of the mobile-redirect malware family.
//
// Restricted to ESCAPE runs on purpose. The identical test over base64 blobs was measured and REJECTED:
// it fired 1/561 hacked but 3/908 queue, and every hit was a legitimate widget config blob carrying
// gstatic.com (reCAPTCHA) or trustpilot.com. Encoding a URL in base64 is ordinary; hand-writing it as
// \x68\x74\x74\x70 is not.
function offDomainUrlHost(dec, reg, rawLower) {
  const m = dec.match(/https?:\/\/[^\s"'<>\\)]{4,}/i);
  if (!m) return "";
  const h = m[0].toLowerCase().replace(/^[a-z]+:\/\//, "").replace(/[/:?#].*$/, "");
  if (!h || h.indexOf(".") === -1 || !/^[a-z0-9.-]+$/.test(h)) return "";
  if (reg && (h === reg || h.endsWith("." + reg))) return "";
  if (URL_SKIP.test(h)) return "";
  // Reveal-only, same rule as the keyword path: if the host is already written plainly somewhere on the
  // page, it is not being hidden and this is not evidence of anything.
  if (rawLower.indexOf(h) !== -1) return "";
  return h;
}

// Quotable proof: the decoded spam token plus a little surrounding plaintext, so the business owner sees
// the actual injected string rather than a description of one.
function proof(kind, decoded, token) {
  const i = decoded.toLowerCase().indexOf(token.toLowerCase());
  const from = Math.max(0, i - 45);
  const win = decoded.slice(from, from + 150).replace(/\s+/g, " ").trim();
  return (kind + ' → "' + win + '"').slice(0, 200);
}

export async function run(ctx) {
  const out = [];
  try {
    if (!ctx || typeof ctx.overBudget === "function" && ctx.overBudget()) return out;
    const S = ctx.S || SIG;
    const STRONG_G = S.REG && S.REG.ALL_STRONG ? S.REG.ALL_STRONG.source : SIG.REG.ALL_STRONG.source;
    const base = (ctx.base || "https://" + (ctx.reg || "")) + "/";

    // Assemble the raw bytes once. G is skipped when it is byte-identical to B (the common case) so we do
    // not pay twice for the same page; tail is where footer injection lands and is outside B's 96KB cap.
    const parts = [];
    const bt = (ctx.B && ctx.B.text) || "";
    const gt = (ctx.G && ctx.G.text) || "";
    const tl = ctx.tail || "";
    if (bt) parts.push(bt);
    if (gt && gt !== bt) parts.push(gt);
    if (tl && bt.indexOf(tl) === -1) parts.push(tl);
    let raw = parts.join("\n");
    if (!raw) return out;
    if (raw.length > MAX_INPUT) raw = raw.slice(0, MAX_INPUT);
    const rawLower = raw.toLowerCase();

    // ---- shared: reveal-only test (invariant 3) ----
    // Memoised: this is an indexOf over up to 230KB, and the caller below can invoke it 40 times per decoded
    // fragment across up to 320 fragments. The token set is tiny and repeats heavily (a spam blob decodes to
    // the same handful of keywords over and over), so the cache turns a worst case of ~3e9 char comparisons
    // into a few hundred.
    const revealCache = new Map();
    const revealed = (tok) => {
      const k = tok.toLowerCase();
      let v = revealCache.get(k);
      if (v === undefined) { v = rawLower.indexOf(k) === -1; revealCache.set(k, v); }
      return v;
    };

    // Compiled ONCE per domain, not once per decoded fragment. ALL_STRONG is a ~4KB alternation and this
    // is called up to MAX_RUNS + MAX_BLOBS (320) times per domain; recompiling it each time was the single
    // largest CPU cost in this module.
    const strongRx = new RegExp(STRONG_G, "gi");
    const firstStrong = (text) => {
      strongRx.lastIndex = 0;
      let m;
      let guard = 0;
      while ((m = strongRx.exec(text)) && guard++ < 40) {
        if (m[0] && revealed(m[0])) return m[0];
        if (strongRx.lastIndex === m.index) strongRx.lastIndex++;
      }
      return "";
    };

    // ---------------- P8 — base64 ----------------
    try {
      const stripped = raw
        .replace(RE_DATA_URI, " ")
        .replace(RE_SOURCEMAP, " ")
        .replace(RE_INTEGRITY, " ");
      RE_B64_BLOB.lastIndex = 0;
      const seen = new Set();
      let m;
      let n = 0;
      while (n < MAX_BLOBS && (m = RE_B64_BLOB.exec(stripped))) {
        const enc = m[0].slice(0, MAX_BLOB_IN);
        if (enc.length < MIN_BLOB) continue;
        if (seen.has(enc)) continue;
        seen.add(enc);
        n++;
        const dec = b64decode(enc).slice(0, MAX_BLOB_OUT);
        if (!dec || !looksLikeText(dec)) continue;
        const tok = firstStrong(dec);
        if (tok) {
          out.push({ bucket: "obfuscated", layer: "L24B64", match: proof("base64", dec, tok), url: base });
          break;   // one proof is all the fuser can use; stop burning CPU
        }
      }
    } catch (e) { /* a malformed page must never kill the scan */ }

    // ---------------- P9 — hex / unicode / percent / entity escapes ----------------
    // One pass collects two different findings: a decoded STRONG keyword (L25ESCAPE) and a decoded
    // off-domain URL (L25URL). Keyword wins when both are present — it is the more quotable proof and
    // it carries the spam category. Both land in the same `obfuscated` bucket, so emitting one is all
    // the fuser can use anyway.
    // The contract asks for overBudget() to be respected, and checking it only once on entry is not enough
    // for a module that is pure CPU: the base64 pass above can legitimately decode 20 blobs before we get
    // here, and on a shard the per-domain deadline may well have passed in the meantime. Re-check between
    // phases so a slow domain degrades to the signals already found instead of overrunning the slice.
    const spent = () => typeof ctx.overBudget === "function" && ctx.overBudget();

    if (!out.length && !spent()) {
      try {
        let budget = MAX_ESCAPE_OUT;
        let runs = 0;
        let hit = "", hitText = "", kind = "";
        let urlHost = "", urlText = "", urlKind = "";
        const passes = [
          [RE_HEX_RUN, fromHexRun, "\\xHH"],
          [RE_UNI_RUN, fromUniRun, "\\uHHHH"],
          [RE_PCT_RUN, fromPctRun, "percent-encoding"],
          [RE_ENT_RUN, fromEntRun, "&#nnn;"],
        ];
        for (const [rx, fn, label] of passes) {
          if (hit) break;
          rx.lastIndex = 0;
          let mm;
          while (budget > 0 && runs < MAX_RUNS && (mm = rx.exec(raw))) {
            runs++;
            const dec = fn(mm[0]);
            if (!dec) continue;
            budget -= dec.length;
            const tok = firstStrong(dec);
            if (tok) { hit = tok; hitText = dec; kind = label; break; }
            if (!urlHost) {
              const h = offDomainUrlHost(dec, ctx.reg || "", rawLower);
              if (h) { urlHost = h; urlText = dec; urlKind = label; }
            }
          }
        }
        if (hit) out.push({ bucket: "obfuscated", layer: "L25ESCAPE", match: proof(kind, hitText, hit), url: base });
        else if (urlHost) out.push({ bucket: "obfuscated", layer: "L25URL", match: proof(urlKind, urlText, urlHost), url: base });
      } catch (e) { /* ditto */ }
    }

    // ---------------- P10 — loader shapes (control bucket, never scores) ----------------
    try {
      if (spent()) return out;
      for (const [rx, name] of LOADERS) {
        const mm = rx.exec(raw);
        if (mm) {
          out.push({ bucket: "control", layer: "L26LOADER", match: (name + ": " + mm[0].replace(/\s+/g, " ")).slice(0, 200), url: base });
          break;
        }
      }
    } catch (e) { /* ditto */ }
  } catch (e) {
    return [];
  }
  return out;
}
