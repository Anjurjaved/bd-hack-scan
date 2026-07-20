# Detector v2 — layer-module contract

Every file in `workers/src/layers/` is an independent detection module. `scan.js` imports them all,
runs them, and merges their signals into the existing Bayesian fuser. Modules never talk to each other
and never write to D1.

## What a module exports

```js
// WEIGHTS — Bayesian [P(signal | hacked), P(signal | clean)] for every layer id this module can emit.
// P(clean) is the false-positive rate: be pessimistic. A layer that fires on 1 in 50 clean BD sites
// must declare 0.02, not 0.002 — an over-confident weight silently manufactures leads.
export const WEIGHTS = { L21METAREFRESH: [0.85, 0.020] };

// CATS — layer id → finding category. One of:
//   "cloak" | "redirect" | "deface" | "malware" | "foreign_lang"
// Omit a layer to let the keyword-derived category (gambling/pharma/adult) win.
export const CATS = { L21METAREFRESH: "redirect" };

// TIER — "t1" runs on every domain; "t2" only when ctx.deep is true (VM, and only for domains that
// already emitted at least one signal). Default "t1" if omitted.
export const TIER = "t1";

// run — returns an array of signals. MUST NOT throw; MUST respect ctx.overBudget().
export async function run(ctx) {
  return [{ bucket: "redirect", layer: "L21METAREFRESH", match: "…", url: "https://…" }];
}
```

## The signal shape

| field    | meaning |
|----------|---------|
| `bucket` | Evidence family. The fuser takes only the **strongest signal per bucket**, so two layers that read the same bytes MUST share a bucket or the posterior double-counts. Use `"control"` for diagnostics that must never affect the score. |
| `layer`  | Stable id, `L<nn><NAME>`. Must have a `WEIGHTS` entry. |
| `match`  | Verbatim proof, ≤200 chars. This is shown to the business owner — it must be quotable evidence, not a description. |
| `url`    | Where the proof lives. |

Existing buckets already in use (reuse only when you are reading the same evidence):
`homepage-content`, `cloak-diff`, `redirect`, `deface`, `malware-js`, `content-enum`, `sitemap-doorway`.

## ctx

```js
{
  reg,          // registrable host, no "www."
  base,         // working origin found by the reachability ladder, e.g. "http://example.com"
  B, G,         // browser + googlebot fetches: {status, finalUrl, text, headers, chain}
  visB, visG,   // stripHtml() output of each
  tail,         // last ~32KB of the browser document (footer injection lives here), "" if not fetched
  S,            // the signatures module
  fetchPage(url, ua, referer, ms),   // follows redirects, capped read
  fetchManual(url, ua, referer, ms), // redirect:"manual" — returns {status, location, headers, text}
  doh(name, type),                   // DNS-over-HTTPS, returns array of answer strings
  stripHtml, distinct, hostOf, sameHost,
  UA_BR, UA_GB, REF_G,
  overBudget(),  // true once the per-domain deadline has passed — stop issuing fetches
  deep,          // tier-2 allowed
  budget,        // { fetches: n }  remaining extra fetches this module may spend; decrement as you go
  spamHosts,     // Set of known spam script/iframe hosts (self-learned + URLhaus)
}
```

## Hard rules

1. **Never throw.** Wrap everything. A module that throws must degrade to `[]`, not kill the scan.
2. **Never confirm on a name.** Modules emit evidence only. Genuine-vs-hacked and the porn/gambling
   brand gate live in `scan.js` and stay there.
3. **Budget the network.** Check `ctx.overBudget()` before every fetch and respect `ctx.budget.fetches`.
   Tier-1 modules should issue **zero** extra fetches unless the proposal explicitly requires one.
4. **False positives cost more than misses.** These leads are sold to real Bangladeshi businesses.
   A layer that fires on a normal site is worse than a layer that misses a hack — when unsure, widen
   the corroboration requirement rather than the pattern.
5. **Bengali is not foreign.** `ঀ-৿` is the site's own language. Never treat it as takeover.
6. **Beware the Bengali-word trap.** `choti` = sandal, `chudi` = bangles, `khanki` → khankitchen.com,
   `sex` → "Unisex Salon", `xxx` → XXXL garment sizing. Bare tokens like these have already been
   dry-run over the full corpus and rejected. Any new vocabulary must be bound to a second
   spam-only token, exactly like `banglachoti` / `chotigolpo`.
