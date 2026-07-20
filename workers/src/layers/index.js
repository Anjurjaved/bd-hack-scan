// layers/index.js — the detector v2 registry.
//
// Static imports on purpose: this file is bundled into a Cloudflare Worker, where a dynamic import of a
// path built at runtime cannot be resolved at build time. Adding a module means adding it here.
//
// Each module owns its own evidence family and declares its own WEIGHTS/CATS/TIER (see CONTRACT.md).
// Nothing here decides whether a site is hacked — modules only produce evidence. The genuine-vs-hacked
// gate and the porn/gambling brand test stay in scan.js, which is the one place they can be reasoned about.
import * as cloak from "./cloak.js";
import * as content from "./content.js";
import * as deep from "./deep.js";
import * as dnsfp from "./dnsfp.js";
import * as hidden from "./hidden.js";
import * as links from "./links.js";
import * as obfusc from "./obfusc.js";
import * as redirect from "./redirect.js";
import * as sitemapx from "./sitemapx.js";
import * as vocab from "./vocab.js";
import * as wpprobe from "./wpprobe.js";

// Order matters only for budget: the cheap, zero-extra-fetch modules run first, so when a domain blows its
// deadline the layers that were skipped are the expensive ones rather than a random subset.
// vocab.js carries the highest-FP-risk vocabulary in the system (Bengali gambling collocations), so it is
// included on evidence rather than on faith. Its slug layer reads only the site's OWN URL tree and suppresses
// the generic-casino arm on news sites; its Bengali layer requires TWO distinct phrases and is priced at
// 0.55/0.035 — a likelihood ratio of 16, which cannot reach the 0.97 confirmation line on its own no matter
// what it sees. The failure it could cause is a `review` entry, not a lead sold to an innocent school.
export const MODULES = [obfusc, content, hidden, links, redirect, dnsfp, sitemapx, vocab, wpprobe, cloak, deep];

export const WEIGHTS = {};
export const CATS = {};
for (const m of MODULES) {
  Object.assign(WEIGHTS, m.WEIGHTS || {});
  Object.assign(CATS, m.CATS || {});
}

// L3REFCLOAK, L4MOBILE and L16HDR were already weighted and already consumed by the genuine-vs-hacked gate
// in scan.js but had no emit site anywhere — three layers wired to nothing. cloak.js and redirect.js now
// fire them, re-declaring the identical weights. scan.js keeps its own values authoritative regardless, so
// a future edit on either side can never silently reweight a live layer.
export const LAYER_COUNT = Object.keys(WEIGHTS).length;
