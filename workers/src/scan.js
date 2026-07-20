// scan.js — Cloudflare-Worker scan engine. A cron tick claims a few unscanned
// domains from D1, runs a lean multi-layer scan (port of detect.py's highest-signal
// layers), Bayesian-fuses to a verdict (score.py), applies the genuine-vs-hacked gate
// (classify.py), optionally Groq Stage-2-verifies gambling hits, and ingests findings.
// Free-tier safe: tiny batch per invocation, capped page reads, per-domain claim.
import * as S from "./signatures.js";
import * as F from "./layers/fetchers.js";
import { MODULES, WEIGHTS as LAYER_W, CATS as LAYER_C } from "./layers/index.js";
// re-export so the shared VM/Mac scanner (scanner/run.mjs) gets the SAME genuine-spam-brand test from this module.
export const domainSpammy = (d) => S.domainSpammy(String(d || "").replace(/^www\./, ""));
// Restricted BD institutional TLDs — allocated ONLY to real govt / university / college / military bodies (you can
// NOT register a .gov.bd/.edu.bd/.ac.bd/.mil.bd as a gambling or porn brand). So gambling/adult content on one of
// these is ALWAYS a hacked victim, never a genuine spam brand — and it is the single highest-value lead type. We
// confirm it as hacked WITHOUT spending an AI call, so these leads survive even when the Gemini/Groq pool is dry.
export const BD_INST_TLD = /\.(gov|edu|ac|mil)\.bd$/i;
export const BD_TLD = /\.bd$/i;

// hasCustomer — is there a BUSINESS here to sell a cleanup to?
//
// This exists because 26 genuine porn sites reached the sales list, every one of them confirmed by the AI
// answering "hacked_client". Chasing that with vocabulary does not work: their titles were "XXM Clips .Live -
// Free Xxx Tube", "JAV HAY, Xem phim sex khiêu dâm miễn phí", "Tio Eroge - Juegos H", Bengali "অশ্লীল ভিডিও",
// and three were behind a WAF showing only "Just a moment...". No regex covers every language's porn vocabulary,
// and each new bare token risks a real BD business (চটি = sandal, XXXL = a garment size).
//
// So the question is inverted. A lead is worth money only if a real organisation is on the other end, and that
// is cheap to establish positively:
//   · a registrar-locked institutional TLD — nobody registers a porn brand on .gov.bd/.edu.bd/.ac.bd/.mil.bd
//   · any .bd registrable — BTCL-gated, so it cannot be self-asserted the way .com/.top/.club can
//   · a Bangladeshi phone number on the page — a business publishes one to be called; a tube page does not
//   · a recognised business type — bizType() returning something other than "general-business"
//
// Measured against all 56: every one of the 9 genuine victims satisfies at least one; not one of the 26 porn
// sites satisfies any (all were general-business on .com/.top/.club/.site/.digital/.skin/.beauty with no +880).
export function hasCustomer(reg, sc) {
  if (BD_INST_TLD.test(reg) || BD_TLD.test(reg)) return true;
  if (sc && sc.contactPhone && S.RE.BD_PHONE.test(sc.contactPhone)) return true;
  const biz = (sc && sc.bizType) || "";
  return !!biz && biz !== "general-business";
}

// weakOnly — is the ONLY spam evidence a bare generic English word?
//
// GAMB_WEAK is `\bcasino\b|\bpoker\b|\bslots\b|jackpot|sweepstakes|…` — ordinary English that any real business
// writes. Measured 2026-07-20: 329 confirmed leads had a single bare weak token as their ENTIRE proof (slots 117,
// casino 44, jackpot 20 …) and the AI approved 239 of them as `hacked_client`. What it actually matched:
//   xiclass.bd                 the national HSC admission portal — "use all 10 slots with a mix of colleges"
//   sandbox.fhir.dghs.gov.bd   a Ministry of Health FHIR API — "Appointment-slot", "The slots that this…"
//   olt.beeonline.com.bd       a minified Vue.js runtime — this.$slots.default, $scopedSlots
//   doctorbari.com.bd / crx.bd appointment booking — "check available time slots"
//   egallery.com.bd            "Jackpot Automatic Dry Iron" — Jackpot is a BD iron brand
// Publishing a government admission portal as a hacked gambling site is a reputational hazard, not a bad lead.
// The AI cannot save us here: it is shown the same weak token and agrees. So this is a hard structural gate —
// a lone weak token can flag a site for review, but it can never on its own confirm one.
const STRONG_EV = new Set([
  "L1KW_STRONG", "L11REST", "L11SITEMAP", "L17HIDDEN", "L2UACLOAK", "L3REFCLOAK", "L14CAMPAIGN", "L10DEFACE",
  "L8IFRAME", "L20SCRIPT", "L17HIDDEN2", "L54SLUGSPAM", "L55BNSPAM", "L56FAMILY", "L32FOREIGNSLUG", "L35ROBOTSPAM",
  "L29FEEDFOREIGN", "L30WPSEARCH", "L52DOORBODY", "L47URLCLOAK", "L51PARAMCLOAK",
]);
export function weakOnly(sc) {
  const L = (sc && sc.layers) || [];
  if (!L.includes("L1KW_WEAK")) return false;
  return !L.some((l) => STRONG_EV.has(l));
}

// adultNeedsReview — the last line, and the one that does not depend on vocabulary.
//
// Measured on the 56: no keyword rule closes this category. The residue that beats every list is titled
// "Tio Eroge - Juegos H", "Pompomhub.site", "Viral Video Link - Bangladeshi Viral Video Link", "LMHMOD - Tải
// Game", "네트워크의 모든 것" — self-descriptions in languages and euphemisms no BD-safe token list can cover.
// Widening the list is how চটি (sandal) and XXXL (a garment size) get destroyed, so it is not an option.
//
// So the category itself is treated as high-risk. Adult is the RAREST genuine lead type here (9 of 2,914) and
// the most damaging to get wrong — a porn screenshot in a sales list sent to Bangladeshi schools. Only a
// registrar-locked BD TLD, which nobody can register a porn brand on, auto-confirms. Everything else lands in
// `review` for one-click approval, so a real victim is delayed, never lost, and a tube never publishes itself.
export function adultNeedsReview(reg, category) {
  if (category !== "adult") return false;
  return !(BD_INST_TLD.test(reg) || BD_TLD.test(reg));
}

// DETECTOR GENERATION. Every domain row carries the generation of the detector that last looked at it.
// Bumping this number is how a detector upgrade re-qualifies the ENTIRE corpus: every row with gen < this
// is owed a fresh look, and the queue serves them ahead of the ordinary least-recently-scanned rotation.
// It is deliberately separate from pass_no — pass_no counts how many times a site has been visited (and
// re-scanning 300k domains through pass_no would double every "scanned" figure on the dashboard), whereas
// gen answers a different question: has this row been seen by the CURRENT detector at all?
//   gen 1 = the original 16-layer detector
//   gen 2 = detector v2: reachability ladder (http:// fallback + www/apex swap + TLS-tolerant retry),
//           ungated doorway discovery, and the new layer modules in ./layers/
export const DETECTOR_GEN = 2;

const UA_BR = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36";
const UA_GB = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";
const REF_G = "https://www.google.com/";

const RE_TAGSTRIP = /<(script|style|noscript|template)\b[\s\S]*?<\/\1>/gi;
const RE_TAGS = /<[^>]+>/g;
const RE_ENT = /&[a-z#0-9]+;/gi;
const RE_WS = /\s+/g;
const RE_TITLE = /<title[^>]*>([\s\S]*?)<\/title>/i;
const RE_HTMLLANGTITLE = /<html[^>]*\blang="([a-zA-Z]{2})/i;

function stripHtml(h) {
  return h.replace(RE_TAGSTRIP, " ").replace(RE_TAGS, " ").replace(RE_ENT, " ").replace(RE_WS, " ").trim();
}
function getTitle(h) {
  const m = RE_TITLE.exec(h);
  return m ? m[1].replace(RE_WS, " ").trim().slice(0, 120) : "";
}
function distinct(text, src) {
  // Callers pass `.source` (a bare pattern string), which drops the original regex's flags. PHARMA_STRONG's letter
  // guard is `(?<![\p{L}\p{N}])`, and WITHOUT `u` that is parsed as a literal character class of `p{LN}\` — so the
  // guard silently inverts into "match anything not one of those punctuation chars" and `spécialisé` matched again.
  // Rebuilding with `u` whenever the pattern uses a Unicode property escape keeps every call site correct at once
  // (scan.js has 5, layers/cloak.js and layers/hidden.js reach the same helper through ctx.distinct).
  const rx = new RegExp(src, /\\[pP]\{/.test(src) ? "giu" : "gi");
  const out = new Set();
  let m;
  let guard = 0;
  while ((m = rx.exec(text)) && guard++ < 400) out.add(m[0].toLowerCase());
  return [...out];
}
function hostOf(url) {
  if (!url) return "";
  let s = url.toLowerCase().replace(/^[a-z]+:\/\//, "");
  s = s.replace(/\/.*$/, "").replace(/:.*$/, "");
  return s;
}
// Same ORGANISATION, not same hostname. `reg` here is only `domain` minus a leading `www.`, i.e. still a host —
// so the old host-equality test called every subdomain→apex and subdomain→sibling hop a foreign redirect:
// sandbox.sslcommerz.com → developer.sslcommerz.com, mail.udoi.org.bd → udoi.org.bd, jobs.bdjobs.com → bdjobs.com.
// That is the whole redirect review flood: ~8,000 rows, +600/day, essentially all of it redirect-family layers
// with no spam corroboration at all. registrableOf() (signatures.js) already existed for the org rollup and
// handles multi-part suffixes (.com.bd, .gov.bd) and multi-tenant hosts; it was simply never used here.
function sameHost(host, reg) {
  if (host === reg || host.endsWith("." + reg)) return true;
  const a = S.registrableOf(host), b = S.registrableOf(reg);
  return !!a && a === b;
}

// 170KB → 96KB cap. On the FREE plan the 1102 is a CPU wall, and regex over the page body is the #1 CPU cost;
// injected casino/pharma/redirect markers live in <head>/meta/early-body/doorway paths (WP-REST + sitemap are
// fetched + scanned separately), so 96KB keeps detection recall while cutting the per-page regex CPU ~44%. This
// targets exactly the oversized pages that were 1102-ing shards, with negligible recall loss on normal homepages.
async function readCapped(r, max = 96000) {
  if (!r.body) {
    const t = await r.text();
    return t.slice(0, max);
  }
  const reader = r.body.getReader();
  const chunks = [];
  let received = 0;
  try {
    while (received < max) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
      received += value.length;
    }
  } catch (e) { /* truncated read is fine */ }
  try { await reader.cancel(); } catch (e) {}
  const buf = new Uint8Array(received);
  let o = 0;
  for (const c of chunks) { buf.set(c.subarray(0, Math.max(0, received - o)), o); o += c.length; }
  return new TextDecoder("utf-8", { fatal: false }).decode(buf.subarray(0, max));
}

async function fetchPage(url, ua, referer, ms = 11000) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), ms);
  try {
    const headers = { "user-agent": ua };
    if (referer) headers["referer"] = referer;
    const r = await fetch(url, { headers, redirect: "follow", signal: ctl.signal });
    const text = await readCapped(r);
    return { status: r.status, finalUrl: r.url || url, text, headers: r.headers };
  } catch (e) {
    return { status: 0, finalUrl: "", text: "", headers: null };
  } finally {
    clearTimeout(t);
  }
}

// ============================================================================
// BD-ness = HOSTING-IP based (the load-bearing definition, not just TLD/text).
// "Bangladeshi website" = a site hosted on a BD IP, ANY TLD (.com/.net/.xyz/.bd).
// Most BD SMBs are on .com with English content — and a hacked site's Bengali text
// is often buried by the injected spam — so TLD/text alone MISLABELS ~86% of real BD
// businesses as "International". We instead trust, in order: .bd TLD → +880/Bengali
// text → (foreign ccTLD ⇒ NOT BD, so a Canadian/Austrian co-tenant on a BD shared
// host is excluded) → bd_score≥25 (the domain was DISCOVERED via a BD-hosting/BD-
// identity harvest source: ip-tree/reverse-ip/lead-coip/bd-ip-sweep/directories/etc)
// → the resolved hosting IP is inside Bangladesh's allocated IP space (ipdeny bd.zone).
// ============================================================================
const CDN_IP = /^(104\.21\.|172\.67\.|104\.16\.|104\.1[789]\.|172\.6[456]\.|188\.114\.|162\.159\.|104\.2[678]\.|151\.101\.|199\.232\.)/;
// Country ccTLDs a Bangladeshi business essentially never uses (generic-use ccTLDs like
// io/co/me/tv/cc/ai and all gTLDs are intentionally EXCLUDED → they stay eligible for BD-by-IP).
const FOREIGN_TLD = new Set("af al dz ad ao aq ag ar am au at az bs bh bb by be bz bj bm bt bo ba bw br bn bg bf bi kh cm ca cv cf td cl cn km cg cd cr ci hr cu cy cz dk dj dm do ec eg sv gq er ee et fj fi fr ga gm ge de gh gr gl gd gt gn gw gy ht hn hk hu is in id ir iq ie il it jm jp jo kz ke ki kp kr kw kg la lv lb ls lr ly lt lu mo mk mg mw my mv ml mt mh mr mu mx md mc mn ma mz mm na nr np nl nz ni ne ng no om pk pw pa pg py pe ph pl pt qa ro ru rw sa sn rs sc sl sg sk si sb so za es lk sd sr sz se ch sy tw tj tz th tg tn tr tm ug ua ae gb uk us uy uz vu ve vn ye zm zw".split(" "));
function foreignCcTld(reg) { return FOREIGN_TLD.has((reg || "").split(".").pop()); }

// ---- support for the v2 layer modules ----
// dohAll: the modules' generic DNS helper. Returns the answer strings for any record type (dohA below stays
// as-is because the BD-ness path only ever wants a single A record and is on the hot path for every flagged site).
async function dohAll(name, type = "A") {
  try {
    const r = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`,
      { headers: { accept: "application/dns-json" }, signal: AbortSignal.timeout(5000) });
    const j = await r.json();
    return (j.Answer || []).map((a) => a.data).filter(Boolean);
  } catch (e) { return []; }
}

// URLhaus: one download serves every domain, so it is fetched once per isolate and reused. A failed load is
// cached as an empty set for a short while rather than retried per domain — abuse.ch is a free service and a
// 300k-domain re-scan must not turn into 300k requests against it.
// IN-FLIGHT MEMOISATION is what actually enforces the "once per isolate" above. URLHAUS is only assigned AFTER
// the await, and loadUrlhausHosts' own `_uh.set` guard is likewise only set post-await, so on a cold start (and
// again at every TTL expiry) EVERY scan that reaches here before the first download completes used to start its
// own. On the VM that is CONCURRENCY (400 by default) simultaneous multi-MB downloads plus 400 independent
// ~35k-entry Sets built from 400 independent split() arrays — an OOM on the 946MB Oracle box, and precisely the
// request burst against abuse.ch the note above forbids. Concurrent callers now share the one promise.
let URLHAUS = null, URLHAUS_AT = 0, URLHAUS_INFLIGHT = null;
async function urlhaus() {
  const now = Date.now();
  if (URLHAUS && now - URLHAUS_AT < 6 * 3600 * 1000) return URLHAUS;
  if (URLHAUS_INFLIGHT) return await URLHAUS_INFLIGHT;
  URLHAUS_INFLIGHT = (async () => {
    try {
      const mod = await import("./layers/links.js");
      return await mod.loadUrlhausHosts({ timeoutMs: 20000 });
    } catch (e) { return new Set(); }   // a failed load is cached as empty, exactly as before
  })();
  try {
    URLHAUS = await URLHAUS_INFLIGHT;
  } finally {
    URLHAUS_AT = now;
    URLHAUS_INFLIGHT = null;
  }
  return URLHAUS;
}

// Self-learned spam-host blocklist (L45KNOWNHOST). Injection campaigns reuse the same delivery hosts across
// hundreds of victims, so a host already seen on confirmed victims is strong corroboration on the next one —
// and it costs no HTTP request at all, which is what makes it the best-value layer in the set.
// The list is mined from confirmed findings by GET /api/spamhosts and handed to the scanner through env, because
// the VM (where the full detector runs) has no D1 access of its own. A host must appear on 3+ DISTINCT victims
// before it counts, so one lead's own CDN can never become a signal.
let SPAM_CACHE = null, SPAM_CACHE_SRC = "";
function spamHosts(env) {
  const src = (env && env.SPAM_HOSTS) || "";
  if (SPAM_CACHE && src === SPAM_CACHE_SRC) return SPAM_CACHE;
  SPAM_CACHE_SRC = src;
  SPAM_CACHE = new Set(String(src).split(",").map((h) => h.trim().toLowerCase()).filter(Boolean));
  return SPAM_CACHE;
}

function parseFp(s) { try { return s ? JSON.parse(s) : null; } catch (e) { return null; } }

async function dohA(name) {
  try {
    const r = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=A`, { headers: { accept: "application/dns-json" }, signal: AbortSignal.timeout(5000) });
    const j = await r.json();
    const a = (j.Answer || []).find((x) => x.type === 1);
    return a ? a.data : null;
  } catch (e) { return null; }
}

// Bangladesh IPv4 ranges (ipdeny bd.zone, ~2300 CIDRs) → sorted [start,end] int ranges, cached
// per isolate. binary-search membership. Free, no key, Worker-fetchable. Falls back to empty on error.
let BD_RANGES = null;
function ipToInt(ip) { const p = String(ip).split("."); if (p.length !== 4) return -1; return ((+p[0] << 24) | (+p[1] << 16) | (+p[2] << 8) | +p[3]) >>> 0; }
async function loadBdRanges() {
  if (BD_RANGES) return BD_RANGES;
  const ranges = [];
  try {
    const r = await fetch("https://www.ipdeny.com/ipblocks/data/countries/bd.zone", { headers: { "user-agent": UA_BR }, signal: AbortSignal.timeout(8000) });
    const txt = await r.text();
    for (const line of txt.split("\n")) {
      const m = line.trim().match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)\/(\d+)$/);
      if (!m) continue;
      const base = (((+m[1]) << 24) | ((+m[2]) << 16) | ((+m[3]) << 8) | (+m[4])) >>> 0;
      const size = (+m[5]) >= 32 ? 1 : 2 ** (32 - (+m[5]));
      ranges.push([base, (base + size - 1) >>> 0]);
    }
    ranges.sort((a, b) => a[0] - b[0]);
  } catch (e) { /* leave empty → ipInBd returns false, other signals still apply */ }
  BD_RANGES = ranges;
  return BD_RANGES;
}
async function ipInBd(ip) {
  const n = ipToInt(ip); if (n < 0) return false;
  const ranges = await loadBdRanges();
  let lo = 0, hi = ranges.length - 1;
  while (lo <= hi) { const mid = (lo + hi) >> 1; const [a, b] = ranges[mid]; if (n < a) hi = mid - 1; else if (n > b) lo = mid + 1; else return true; }
  return false;
}
// A BD name token in the registrable = a strong Bangladesh signal (…bd, bangla*, dhaka, chattogram/
// chittagong, sylhet, khulna, rajshahi…). Catches exceltech**bd**.com / graphicclan**bd**.com etc.
const BD_NAME = /(bd|bangla|bangladesh|dhaka|chattogram|chittagong|sylhet|khulna|rajshahi|barisal|rangpur|mymensingh)$/i;
// The one place BD-ness is decided — TRUTH = hosting IP + page content + .bd/name, NOT the harvest
// source. (Trusting the source leaked foreign sites: RapidDNS "sameip" can return a domain that isn't
// really on that BD /24, and co-hosting neighbours can be foreign — so chargeursolaire/jjkmanga slipped
// in. We now require an actual BD signal.)
async function computeIsBd(reg, body, source, ip) {
  reg = reg || "";
  if (reg.endsWith(".bd")) return 1;
  if (S.bdSignal(reg, body)) return 1;              // +880 phone / ≥15 Bengali chars = real BD identity
  if (ip && await ipInBd(ip)) return 1;             // hosted on a Bangladesh IP = BD (the core definition)
  const p = reg.split("."); const sld = p.length >= 2 ? p[p.length - 2] : reg;
  if (BD_NAME.test(sld)) return 1;                  // BD token in the domain name
  return 0;                                          // no BD signal at all → not Bangladeshi
}

// ---- BD address / contact extraction (regex only, ZERO LLM) — feeds geographic grouping ----
const BD_DISTRICTS = ["Dhaka","Gazipur","Narayanganj","Narsingdi","Manikganj","Munshiganj","Tangail","Kishoreganj","Faridpur","Gopalganj","Madaripur","Shariatpur","Rajbari","Chattogram","Chittagong","Cox's Bazar","Coxs Bazar","Cumilla","Comilla","Brahmanbaria","Chandpur","Feni","Lakshmipur","Noakhali","Khagrachhari","Rangamati","Bandarban","Sylhet","Moulvibazar","Habiganj","Sunamganj","Rajshahi","Bogura","Bogra","Pabna","Sirajganj","Natore","Naogaon","Joypurhat","Chapainawabganj","Khulna","Jashore","Jessore","Satkhira","Bagerhat","Jhenaidah","Magura","Narail","Kushtia","Chuadanga","Meherpur","Barishal","Barisal","Bhola","Patuakhali","Pirojpur","Barguna","Jhalokati","Rangpur","Dinajpur","Thakurgaon","Panchagarh","Nilphamari","Lalmonirhat","Kurigram","Gaibandha","Mymensingh","Jamalpur","Sherpur","Netrokona"];
const BD_AREAS = ["Mirpur","Pallabi","Kazipara","Shewrapara","Kafrul","Agargaon","Mohammadpur","Shyamoli","Adabor","Dhanmondi","Lalmatia","Gulshan","Banani","Baridhara","Bashundhara","Badda","Rampura","Khilgaon","Motijheel","Paltan","Segunbagicha","Malibagh","Moghbazar","Mohakhali","Tejgaon","Farmgate","Karwan Bazar","Kawran Bazar","Panthapath","Uttara","Khilkhet","Mugda","Jatrabari","Demra","Old Dhaka","Lalbagh","Wari","Kamrangirchar","Savar","Keraniganj","Tongi","Gabtoli","Mirpur DOHS","Banasree","Aftabnagar","Cantonment","Eskaton","Bijoy Nagar","Bangla Motor","Shantinagar","New Market","Elephant Road","Green Road","Shahbagh","Hazaribagh","Azimpur","Shahjadpur","Vatara","Kuril","Nadda","Ramna","Siddeshwari","Kakrail","Naya Paltan","Purana Paltan","Fakirapool","Arambagh","Kamalapur","Tikatuli","Gopibagh","Mouchak","Nakhalpara","Indira Road","Asad Gate","Kalyanpur","Darus Salam","Rupnagar","Monipur","Ibrahimpur","Niketan","Nikunja","Joar Sahara","Notun Bazar","Dakshinkhan","Uttarkhan","Ashkona","Meradia","Nandipara","Maniknagar","Manda","Sayedabad","Jurain","Postogola","Shyampur","Kadamtali","Matuail","Donia","Rayerbagh","Shanir Akhra","Dania","Gendaria","Sutrapur","Bangshal","Chawkbazar","Kotwali","Sadarghat","Islampur","Gulistan","Dilkusha","Goran","Bashabo","Mugdapara","Khilgaon Taltola","Agrabad","Nasirabad","Khulshi","Pahartali","Halishahar","Chandgaon","Zindabazar","Ambarkhana","Bandar Bazar","Lamabazar","Subid Bazar","Upashahar","Boalia","Uposhohor","Rajpara"];
const RE_ADDR_TOKEN = /\b(house|holding|plot|flat|road|block|sector|level|floor|suite|lane|avenue|tower|bhaban|bhavan|villa|complex|plaza|market|bazar|bazaar|para|nagar)\b/i;

function nearestName(lower, list, cueIdx) {
  let best = "", bestD = 1e15;
  for (const name of list) {
    const i = lower.indexOf(name.toLowerCase());
    if (i < 0) continue;
    const d = cueIdx >= 0 ? Math.abs(i - cueIdx) : i;
    if (d < bestD) { bestD = d; best = name; }
  }
  return best;
}
function extractContact(html, text) {
  const out = { phone: "", email: "", address: "", district: "", area: "" };
  const t = (text || "").slice(0, 60000);
  const pm = t.match(/(?:\+?880[\s-]?|0)1[3-9]\d{8}/);
  if (pm) out.phone = pm[0].replace(/[\s-]/g, "");
  const em = ((html || "").match(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/i) || [])[0];
  if (em && !/(example|sentry|wixpress|godaddy|\.png|\.jpg|domain\.com|email\.com|yourdomain|wordpress)/i.test(em)) out.email = em.toLowerCase();
  // A REAL address = a window that has an address token (House/Road/Block/Sector/…) AND a BD
  // district/area near it. This skips nav menus ("Contact", "About") and incidental place names.
  const addrRe = /(house|holding|plot|flat|road|block|sector|level|floor|suite|lane|avenue|tower|bhaban|bhavan|plaza|complex|রোড|সড়ক|বাড়ি|ব্লক|সেক্টর)/gi;
  let m, scanned = 0;
  while ((m = addrRe.exec(t)) && scanned++ < 200) {
    const win = t.slice(Math.max(0, m.index - 45), m.index + 155);
    const wl = win.toLowerCase();
    let area = "", dist = "";
    const wb = (name) => new RegExp("\\b" + name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "\\b", "i").test(win);
    for (const a of BD_AREAS) { if (wb(a)) { area = a; break; } }
    for (const d of BD_DISTRICTS) { if (wb(d)) { dist = d; break; } }
    if (area || dist) {
      out.address = win.replace(/\s+/g, " ").replace(/^[^A-Za-zঀ-৿]+/, "").trim().slice(0, 160);
      out.area = area;
      out.district = dist || (area ? "Dhaka" : "");
      break;
    }
  }
  return out;
}

// ---- Bayesian fusion (port of score.py, ported-layer subset) ----
const PRIOR = 0.12;
const W = {
  L1KW_STRONG: [0.80, 0.030], L1KW_WEAK: [0.55, 0.120], L10LANG: [0.45, 0.080], L17HIDDEN: [0.85, 0.010],
  L2UACLOAK: [0.92, 0.020], L3REFCLOAK: [0.90, 0.020], L9REDIR: [0.70, 0.060], L4MOBILE: [0.75, 0.040],
  L11REST: [0.88, 0.010], L20SCRIPT: [0.82, 0.020], L11SITEMAP: [0.78, 0.020], L20SHAPE: [0.80, 0.020],
  L8IFRAME: [0.85, 0.010], L16HDR: [0.80, 0.030], L20RELAY: [0.50, 0.050],
  L14CAMPAIGN: [0.97, 0.002], L10DEFACE: [0.97, 0.002],
};
const HARD = new Set(["L14CAMPAIGN", "L10DEFACE"]);
const LAYER_CAT = { L2UACLOAK: "cloak", L3REFCLOAK: "cloak", L9REDIR: "redirect", L4MOBILE: "redirect", L16HDR: "redirect", L20RELAY: "redirect", L10DEFACE: "deface", L14CAMPAIGN: "malware", L8IFRAME: "malware", L10LANG: "foreign_lang", L20SCRIPT: "foreign_lang" };

// Fold in the v2 layer modules. The weights declared HERE always win: three of the module layers
// (L3REFCLOAK, L4MOBILE, L16HDR) were already weighted above and merely had no emit site, and a module
// edit must never be able to silently reweight a live layer that the genuine-vs-hacked gate reads.
for (const [k, v] of Object.entries(LAYER_W)) if (!W[k]) W[k] = v;
for (const [k, v] of Object.entries(LAYER_C)) if (!LAYER_CAT[k]) LAYER_CAT[k] = v;

function category(eff) {
  for (const s of eff) { const c = S.categoryOf(s.match); if (c) return c; }
  for (const pref of ["deface", "malware", "cloak", "redirect", "foreign_lang"]) {
    for (const s of eff) if (LAYER_CAT[s.layer] === pref) return pref;
  }
  return "gambling";
}

// selfSpam — is this homepage the adult/gambling PRODUCT rather than a business carrying injected spam?
// Deliberately narrow, because a false positive here silently DROPS a genuine hacked lead. Two independent
// tests, either of which is sufficient, both measured against the 56 confirmed-adult leads of 2026-07-20:
//
//   TITLE — the <title> is what a site declares itself to be. "Free Porn Videos & XXX Movies", "XXM Clips
//   .Live - Free Xxx Tube", "Bangla Choti Golpo" are self-descriptions; no hacked business has one. Injected
//   spam overwhelmingly leaves the title alone (a title-only injection exists but is handled by L37TITLEONLY,
//   which reaches the AI, not this gate). This test alone caught 18 of the 26.
//
//   DENSITY — a real business page that mentions "casino" once in a news item scores ~1 hit in thousands of
//   characters. A tube page is wall-to-wall: distinct strong terms repeated throughout a SHORT body. The
//   threshold demands BOTH several distinct terms AND a short document, so a long editorial about the Dhaka
//   casino raids (many hits, long body) does not qualify.
//
// A real BD business identity overrides neither test — that is decided in score(), not here.
function isSelfSpam(title, visible) {
  const t = String(title || "");
  if (t && S.ALL_STRONG.test(t)) return true;
  const body = String(visible || "");
  if (body.length > 6000) return false;              // a substantial site is not a tube page
  const distinct = new Set((body.match(S.REG.ALL_STRONG) || []).map((x) => x.toLowerCase()));
  return distinct.size >= 3 && body.length < 4000;
}

function score(signals, ctx) {
  const eff = signals.filter((s) => s.bucket !== "control");
  const layers = new Set(eff.map((s) => s.layer));
  const best = {};
  let hard = false;
  for (const s of eff) {
    if (HARD.has(s.layer)) hard = true;
    const [D, F] = W[s.layer] || [0.55, 0.10];
    const ratio = D / F;
    if (!best[s.bucket] || ratio > best[s.bucket][0]) best[s.bucket] = [ratio, s];
  }
  let lo = Math.log(PRIOR / (1 - PRIOR));
  for (const k in best) lo += Math.log(best[k][0]);
  const posterior = 1 / (1 + Math.exp(-lo));
  const nbuckets = Object.keys(best).length;
  // A redirect, on its own, is not evidence of a hack — it is how the web works. `nbuckets >= 1` below turns ANY
  // single signal into SUSPECT, i.e. a row in the human review queue, and the redirect family alone produced
  // ~8,000 of the 10,257 rows there (+600/day), drowning 1,117 gambling and 170 hard-evidence BD findings that a
  // human should actually be looking at. Every one of those redirect rows was a site moving between its own
  // hosts, an hreflang alternate, a rebrand or a parking hop. So: redirect-family layers must be corroborated by
  // something that is actually about spam before they cost anyone attention. L16HDR is exempt — it only fires
  // when the redirect TARGET already matched GAMB_STRONG or a junk TLD, so it carries its own corroboration.
  const REDIR_FAMILY = new Set(["L9REDIR", "L20RELAY", "L4MOBILE", "L21HOPS", "L22META", "L22METAX", "L23JSLOC", "L23JSOBF", "L23JSTLD"]);
  const redirectOnly = eff.length > 0 && eff.every((s) => REDIR_FAMILY.has(s.layer));
  let verdict;
  if (!eff.length) verdict = "CLEAN";
  else if (hard || (posterior >= 0.97 && nbuckets >= 2)) verdict = "CONFIRM_CANDIDATE";
  else if (redirectOnly) verdict = "CLEAN";
  else if (posterior >= 0.50 || nbuckets >= 1) verdict = "SUSPECT";
  else verdict = "CLEAN";

  let lead = null;
  for (const k in best) if (!lead || best[k][0] > lead[0]) lead = best[k];
  const cat = eff.length ? category(eff) : "";
  const evidence = [];
  const seen = new Set();
  for (const s of eff) {
    if (s.url && !seen.has(s.url)) { seen.add(s.url); evidence.push({ layer: s.layer, url: s.url.slice(0, 300), match: s.match.slice(0, 160) }); }
    if (evidence.length >= 10) break;
  }
  // genuine-vs-hacked gate
  //
  // selfSpam = the homepage IS the adult/gambling product, not a business carrying injected spam. Two doors
  // let 26 genuine porn sites into the sales list before this existed, and both are closed here:
  //
  //  1. CLOAKING IS NOT VICTIMHOOD. A porn tube serves different content to Googlebot in order to rank, so
  //     L2UACLOAK fires, `stealth` goes true, `hackFp` goes true, and the spam_site test below was skipped
  //     entirely — the site went to the AI, which answered "hacked_client". That was the door for
  //     potnhub.org, viexx.com, xxmclips.live, xxxrough.com, gayteam.club and kompoz2.com (all L2UACLOAK),
  //     and for premiumplasticltd.com (L17HIDDEN). When the homepage itself is the product, hiding and
  //     cloaking are how it operates, not evidence that someone else put it there.
  //  2. BENGALI PORN IS NOT A BD BUSINESS IDENTITY. bdSignal() returns true on 15+ Bengali characters, so
  //     banglachotigolpo1.com — whose homepage reads "বাংলা নতুন চুদাচুদির চটি" — satisfied `identity` and
  //     took the protected path meant for real Bangladeshi businesses. Identity has to mean a BUSINESS is
  //     there, so text that is itself the spam cannot supply it.
  //
  // Institutional victims stay safe: scanSlice checks BD_INST_TLD (.gov/.edu/.ac/.mil.bd) BEFORE this and
  // confirms them even at status spam_site, because those TLDs are registrar-locked and cannot be a porn brand.
  // The v2 layers are folded into the same three families. This matters more than it looks: the gate reads
  // "spam hidden away from the homepage, on a site that still has a real business on its front page" as HACKED,
  // and everything else openly spammy as a spam site to be dropped. A new layer that finds injected content in a
  // feed, a search result or a doorway post but is not listed here would push its victim towards `spam_site`
  // and quietly lose a genuine hacked lead.
  const stealth = ["L2UACLOAK", "L3REFCLOAK", "L17HIDDEN", "L16HDR", "L20RELAY",
    "L47URLCLOAK", "L51PARAMCLOAK", "L17HIDDEN2", "L50CONTRAST", "L51TAIL", "L52COMMENT", "L52NOSCRIPT",
    "L24B64", "L25ESCAPE", "L25URL", "L26LOADER"].some((l) => layers.has(l));
  const malwareDeface = ["L14CAMPAIGN", "L10DEFACE", "L8IFRAME", "L46URLHAUS", "L45KNOWNHOST",
    "L48SHELL", "L49UPLOADPHP", "L57DRAINER"].some((l) => layers.has(l));
  const doorway = ["L11REST", "L20SCRIPT", "L11SITEMAP", "L20SHAPE", "L4MOBILE",
    "L38SMAPDEEP", "L32FOREIGNSLUG", "L33VOLUME", "L34LASTMOD", "L35ROBOTSPAM",
    "L29FEED", "L29FEEDFOREIGN", "L30WPSEARCH", "L31SEARCH", "L52DOORBODY",
    "L55CMSDOOR", "L53AMP", "L42SUBDOM", "L53SHAPE2", "L54SLUGSPAM"].some((l) => layers.has(l));
  const homepageOpen = layers.has("L1KW_STRONG");
  // NOTE — the `doorway` term is currently INERT, and the list above is documentation only. hackFp is read at
  // exactly one place (the spam_site test below) and that read is already inside `homepageOpen && …`, so
  // `!homepageOpen` is false there by construction and hackFp always reduces to `stealth || malwareDeface`.
  // Adding or removing a doorway id cannot change any verdict for any input. That is deliberate and must stay
  // that way until it is measured: dropping the `!homepageOpen` guard would let doorway-only evidence pull
  // openly-spammy no-identity sites out of the free spam_site drop and into the Gemini/Groq queue, which is
  // the token burn CLAUDE.md exists to prevent. Keep the ids listed so a future change has the full set.
  const hackFp = stealth || malwareDeface || (doorway && !homepageOpen);
  const spammy = !!(ctx && ctx.domainSpammy);
  const selfSpam = !!(ctx && ctx.selfSpam);
  const identity = !!(ctx && ctx.bdSignal) && !selfSpam;
  let status, confirmed, flagged;
  if (spammy || selfSpam || (homepageOpen && !hackFp && !identity)) { status = "spam_site"; confirmed = 0; flagged = false; }
  else if (verdict === "CONFIRM_CANDIDATE") { status = "lead"; confirmed = 1; flagged = true; }
  else if (verdict === "SUSPECT") { status = "review"; confirmed = 0; flagged = true; }
  else { status = "clean"; confirmed = 0; flagged = false; }

  return {
    verdict, posterior: Math.round(posterior * 1e4) / 1e4, nbuckets, hard, category: cat,
    proof: (lead ? lead[1].match : "").slice(0, 500), proofUrl: (lead ? lead[1].url : ""),
    layers: [...layers].sort(), evidence, status, confirmed, flagged,
  };
}

// ---- one domain ----
export async function scanDomain(env, rec, deadline) {
  const overBudget = () => deadline && Date.now() > deadline;   // per-domain hard cap → skip the heavy enumeration
  // PROFILE decides how much detector a domain gets. "full" is the Oracle VM: real cores, no CPU ceiling, so it
  // runs the reachability ladder and every v2 layer module. "light" is the Cloudflare shards, which live under
  // the free-plan CPU wall that produced error 1102 and froze this engine for 3.3 hours — they keep the original
  // two-fetch detector and act as continuity, while the VM does the deep work.
  const FULL = String((env && env.SCAN_PROFILE) || "light") === "full";
  const d = (rec.domain || "").trim().toLowerCase();
  const reg = d.replace(/^www\./, "");
  const sigs = [];
  const emit = (bucket, layer, match, url = "") => sigs.push({ bucket, layer, match: String(match).slice(0, 200), url });

  // THE RECHABILITY LADDER. https-only is why 68,568 domains — 43% of the corpus — carry dead=1 without ever
  // having been scanned: an http-only site, an expired certificate or a hostname mismatch all fail the connect
  // and look identical to "this domain does not exist". Neglected and already-compromised sites are exactly the
  // population with broken TLS, so that flag was hiding the most hack-dense slice of the database.
  let B, base;
  if (FULL) {
    const R = await F.resolveBase(d, { ua: UA_BR, overBudget, knownBase: rec.base || "" });
    if (!R.status) return { error: "unreachable" };
    base = R.base;
    B = { status: R.status, finalUrl: R.finalUrl, text: R.text, headers: R.headers, chain: R.chain };
  } else {
    // The shards cannot afford the full ladder under the free-plan CPU wall, but condemning a domain on ONE
    // un-retried https attempt is what put 71,939 rows (37% of the corpus) behind dead=1. A fresh 50-row probe
    // found 52% of them answering today, and 3 of the 20 that returned 200 did so ONLY over http:// —
    // hnhs.edu.bd, jhapuaaidmad.edu.bd, shkhs.edu.bd. Sites with expired or absent TLS are precisely the
    // neglected ones most likely to be compromised, so this single extra fetch is the cheapest recall we have.
    base = "https://" + d;
    B = await fetchPage(base, UA_BR, null);
    if (B.status === 0 && !overBudget()) { base = "http://" + d; B = await fetchPage(base, UA_BR, null); }
    if (B.status === 0) return { error: "unreachable" };
  }
  const G = await fetchPage(base, UA_GB, REF_G);

  const visB = stripHtml(B.text);
  const visG = stripHtml(G.text);
  if (S.RE.WAF.test(B.text)) emit("control", "L18CHALLENGE", "waf", base + "/");

  const kwS = distinct(visB, S.REG.ALL_STRONG.source);
  if (kwS.length) emit("homepage-content", "L1KW_STRONG", kwS.join(";"), base + "/");
  const kwW = distinct(visB, S.REG.ALL_WEAK.source);
  if (kwW.length) emit("homepage-content", "L1KW_WEAK", kwW.join(";"), base + "/");

  // L2 UA cloak — strong kw shown to googlebot but not browser
  const setB = new Set(kwS);
  const kgS = distinct(visG, S.REG.ALL_STRONG.source).filter((x) => !setB.has(x));
  if (kgS.length) emit("cloak-diff", "L2UACLOAK", kgS.join(";"), base + "/");

  // L9 redirect off-domain
  const bh = hostOf(B.finalUrl);
  if (bh && !sameHost(bh, reg)) emit("redirect", "L9REDIR", bh, B.finalUrl);

  // L10 foreign title / deface
  const ttl = getTitle(B.text) || getTitle(G.text);
  if (ttl && S.RE.FOREIGN.test(ttl)) emit("homepage-content", "L10LANG", ttl, base + "/");
  const defm = distinct(B.text + G.text, S.RE.DEFACE.source);
  if (defm.length) emit("deface", "L10DEFACE", defm.join(";"), base + "/");

  // L14 malware-js
  const bad = distinct(B.text + G.text, S.RE.MALJS.source);
  if (bad.length) emit("malware-js", "L14CAMPAIGN", bad.slice(0, 3).join(";"), base + "/");

  // L17 hidden-link spam (lean: a display:none/offscreen block with a strong kw)
  const hid = /<(div|span|p|section|footer|ul|a)\b[^>]*style="[^"]*(display\s*:\s*none|visibility\s*:\s*hidden|text-indent\s*:\s*-\s*\d{3,}|position\s*:\s*absolute[^"]*(left|top)\s*:\s*-\s*\d{3,})[^"]*"[^>]*>([\s\S]{0,1500}?)<\/\1>/i.exec(B.text);
  if (hid && S.ALL_STRONG.test(stripHtml(hid[0]))) emit("homepage-content", "L17HIDDEN", "hidden:" + stripHtml(hid[0]).slice(0, 120), base + "/");

  // L8 — gambling iframe/script injection (no extra fetch)
  const ifr = (B.text + G.text).match(/<(?:iframe|script)[^>]+src="https?:\/\/[^"]*(?:casino|slot|judi|togel|xbet|melbet|bet[0-9]|gacor|sbobet)[^"]*"/i);
  if (ifr) emit("malware-js", "L8IFRAME", ifr[0].slice(0, 140), base + "/");

  // L16HDR — server header redirect to gambling / junk TLD (no extra fetch)
  if (G.headers) {
    const loc = G.headers.get("location") || G.headers.get("refresh") || "";
    const lh = hostOf((loc.match(/https?:\/\/[^\s"']+/) || [""])[0]);
    if (lh && !sameHost(lh, reg) && (S.RE.GAMB_STRONG.test(loc) || S.RE.JUNKTLD.test(loc))) emit("redirect", "L16HDR", loc.slice(0, 140), base + "/");
  }

  // L20RELAY — off-domain canonical/alternate to a non-CDN/non-platform host (from googlebot body)
  const relaySkip = /cloudflare|cloudfront|akamai|fastly|jsdelivr|gstatic|googleusercontent|bunny|wp\.com|w\.org|gravatar|youtube|facebook|googleapis|lovable|webflow|wixsite|weebly|netlify|vercel|github\.io|blogspot|myshopify/i;
  const relays = [];
  // `[^/"]+` did not stop at `?` or `#`, so a canonical carrying a query yielded "hosts" like
  // `borendroonline.net?post_type=…` which can never equal `reg` — an automatic L20RELAY on the site's own domain.
  const relayRx = /<link[^>]+rel="(?:alternate|canonical)"[^>]+href="https?:\/\/([^/"?#]+)/gi;
  let rm, rg = 0;
  while ((rm = relayRx.exec(G.text)) && rg++ < 10) {
    const h = rm[1].toLowerCase();
    if (h && !sameHost(h, reg) && !relaySkip.test(h)) relays.push(h);
  }
  if (relays.length) emit("redirect", "L20RELAY", [...new Set(relays)].slice(0, 2).join(";"), base + "/");

  let fired = sigs.length > 0;

  // L11REST — WordPress REST enumeration (the crown jewel for doorway/injected posts).
  // Skipped once the per-domain budget is blown — this multi-fetch + JSON.parse loop is the #1 CPU/wall hog
  // that used to 1102 a shard on a big WP site. Homepage signals above still stand.
  if (!overBudget()) try {
    const probe = await fetchPage(base + "/wp-json/wp/v2/posts?per_page=1", UA_GB, null, 9000);
    const wptot = probe.headers ? probe.headers.get("x-wp-total") : null;
    if (wptot && /^\d+$/.test(wptot)) {
      const pages = Number(wptot) <= 100 ? 1 : Math.min(Math.ceil(Number(wptot) / 100), 3);
      let foreign = 0, total = 0;
      for (const typ of ["posts", "pages"]) {
        const tp = typ === "posts" ? pages : 1;
        for (let pg = 1; pg <= tp; pg++) {
          const rr = await fetchPage(`${base}/wp-json/wp/v2/${typ}?per_page=100&page=${pg}&_fields=slug,title,link`, UA_GB, null, 10000);
          if (!rr.text || !rr.text.includes('"slug"')) break;
          let arr;
          try { arr = JSON.parse(rr.text); } catch (e) { break; }
          if (!Array.isArray(arr)) break;
          for (const p of arr) {
            const slug = (p && p.slug || "").trim();
            let title = (p && p.title && (p.title.rendered ?? p.title)) || "";
            title = String(title).replace(RE_WS, " ").trim();
            total++;
            if (S.RE.FOREIGN.test(title)) foreign++;
            if ((slug && S.RE.SLUG_SPAM.test(slug)) || (title && S.ALL_STRONG.test(title))) {
              emit("content-enum", "L11REST", `slug=${slug.slice(0, 60)}::${title.slice(0, 90)}`, (p.link || "").slice(0, 130));
            }
          }
        }
      }
      if (foreign >= 4 && total && foreign * 100 < total * 30)
        emit("content-enum", "L20SCRIPT", `foreign=${foreign}/${total}`, base + "/wp-json/wp/v2/posts");
    }
  } catch (e) { /* not WP / blocked — fine */ }

  // L11SITEMAP / L20SHAPE — sitemap doorway discovery.
  // The `sigs.length > 0` gate is the second-biggest false-negative in the old detector: the canonical modern
  // SEO-spam hack (Japanese-keyword, Indonesian slot doorways) leaves the homepage byte-for-byte untouched and
  // injects thousands of doorway URLs reachable only through the sitemap. Those sites produce no homepage signal,
  // so the gate holds and the sitemap is never fetched — the highest-value hack class was structurally invisible.
  // On the VM the gate is therefore removed; the shards keep it, because there the extra fetches cost CPU budget.
  // The ungating applies only when the homepage actually served us a page. A WAF that answers 403 answers 403
  // to /robots.txt and /sitemap_index.xml too, and in a traced scan those rejections were 2.3s each — pure cost
  // for a guaranteed-empty result. A site with a real signal still gets the sitemap pass regardless, as before.
  let sitemapN = 0;
  const answered = B.status >= 200 && B.status < 300;
  // `sigs.length > 0` was the original gate and it has the same control-signal flaw as the deep gate did:
  // L18CHALLENGE fires on every WAF-fronted site, so this pass was already running against hosts that answer
  // 403 to robots.txt and every sitemap URL. Count scoring signals only.
  const smells = sigs.some((s) => s.bucket !== "control");
  if (((FULL && answered) || smells) && !overBudget()) {
    try {
      const rob = await fetchPage(base + "/robots.txt", UA_GB, null, 8000);
      let smaps = [...(rob.text || "").matchAll(/sitemap:\s*(https?:\/\/\S+)/gi)].map((m) => m[1]);
      if (!smaps.length) smaps = [base + "/sitemap_index.xml", base + "/wp-sitemap.xml", base + "/sitemap.xml"];
      let sm = "";
      for (const u of smaps.slice(0, 2)) {
        if (!u.includes(reg)) continue;
        const r = await fetchPage(u, UA_GB, null, 8000);
        sm += r.text || "";
        const children = [...new Set([...(r.text || "").matchAll(/https?:\/\/[^<\s"]+\.xml/gi)].map((m) => m[0]))].slice(0, 3);
        for (const child of children) { if (child.includes(reg)) { const c = await fetchPage(child, UA_GB, null, 7000); sm += c.text || ""; } }
        if (sm.length > 220000) break;
      }
      if (sm) {
        const su = [...new Set([...sm.matchAll(/https?:\/\/[^<\s"]+/gi)].map((m) => m[0]))].filter((u) => u.includes(reg) && !u.toLowerCase().endsWith(".xml") && S.RE.SLUG_SPAM.test(u)).slice(0, 3);
        if (su.length) emit("sitemap-doorway", "L11SITEMAP", su.join(";"), su[0]);
        const locs = [...sm.matchAll(/<loc>\s*([^<\s]+)/gi)].map((m) => m[1]);
        sitemapN = locs.length;   // handed to dnsfp: a sitemap that triples between scans is mass injection
        let gib = 0;
        for (const u of locs) {
          if (!u.includes(reg)) continue;
          const seg = (u.replace(/\.html?$/, "").split("/").filter(Boolean).pop() || "").toLowerCase();
          if (seg.length > 9) { const v = (seg.match(/[aeiou]/g) || []).length; if (v / seg.length < 0.22 && /[bcdfghjklmnpqrstvwxz]{6,}/.test(seg)) gib++; }
        }
        if (gib >= 10) emit("sitemap-doorway", "L20SHAPE", "gibberish=" + gib, base + "/");
      }
    } catch (e) { /* sitemap missing/blocked — fine */ }
  }

  // ---- detector v2 layer modules ----
  // Full profile only. Each module owns one evidence family, declares its own weights, and cannot decide a
  // verdict — the genuine-vs-hacked gate below still has the last word. A module that throws is skipped, never
  // fatal: one bad regex must not cost the whole scan.
  let fpNow = null;
  if (FULL && !overBudget()) {
    // Tier 2 (web-shell probes, uploads listing, exposed .git, AMP, TLS forensics) costs several extra requests
    // per domain, so it is spent only where something already smells. On a clean corpus that is a few percent
    // of domains, which is what keeps a 300k re-scan affordable on one OCPU.
    //
    // Two conditions, both learned by tracing a real scan rather than by reasoning about it:
    //  1. `control` signals do not count. L18CHALLENGE fires on every WAF-protected site, so a raw
    //     `sigs.length > 0` promoted every Cloudflare-fronted site to the deep tier — measured on bracu.ac.bd:
    //     28 requests, 36s, verdict clean. The fuser has always excluded `control` from scoring; this gate
    //     simply has to agree with it.
    //  2. The homepage must have actually answered 2xx. Against a 403/401/429 every probe returns the same
    //     403 from the WAF, so the whole tier is guaranteed to learn nothing — and those rejections were the
    //     slowest requests in the trace, 1-6s each.
    const deep = answered && sigs.some((s) => s.bucket !== "control");
    // A truncated read means the footer was cut off — and footer link injection is the single most common
    // WordPress spam placement, so it is worth one Range request to go get the tail we threw away.
    const tail = (B.text || "").length >= 96000 && !overBudget() ? await F.fetchTail(base, UA_BR).catch(() => "") : "";
    const ctx = {
      reg, base, B, G, visB, visG, tail, S,
      fetchPage: F.fetchPage, fetchManual: F.fetchManual, followChain: F.followChain, fetchTail: F.fetchTail,
      doh: dohAll, stripHtml, distinct, hostOf, sameHost,
      UA_BR, UA_GB, UA_MOB: F.UA_MOB, REF_G,
      overBudget, deep, sitemapN,
      budget: { fetches: deep ? 14 : 6 },
      spamHosts: spamHosts(env),
      urlhausHosts: await urlhaus(),
      prevFp: parseFp(rec.fp),
      // doorway URLs discovered by the sitemap and content-enumeration layers, so the per-URL cloak check has
      // somewhere to look. Populated as modules run — cloak.js is ordered last for exactly this reason.
      doorways: [],
    };
    for (const m of MODULES) {
      if ((m.TIER || "t1") === "t2" && !ctx.deep) continue;
      if (overBudget()) break;
      try {
        const out = await m.run(ctx);
        if (Array.isArray(out)) for (const s of out) if (s && s.layer && s.bucket) sigs.push(s);
      } catch (e) { /* a module failure is never fatal to the scan */ }
      // A module that produced the first real signal promotes the rest of the run to the deep tier — but by
      // the same rule as above: scoring signals only, and only on a site that actually served us a page.
      ctx.deep = ctx.deep || (answered && sigs.some((s) => s.bucket !== "control"));
      ctx.doorways = sigs.filter((s) => s.bucket === "sitemap-doorway" || s.bucket === "content-enum").map((s) => s.url).filter(Boolean).slice(0, 12);
    }
    fpNow = ctx.fpNow || null;
  }

  const sc = score(sigs, {
    domainSpammy: S.domainSpammy(reg),
    bdSignal: S.bdSignal(reg, visB),
    selfSpam: isSelfSpam(ttl, visB),
  });
  sc.fp = fpNow ? JSON.stringify(fpNow).slice(0, 1200) : "";
  sc.base = base;
  sc.title = ttl;
  sc.excerpt = visB.slice(0, 1800);
  sc.httpStatus = B.status;
  // PARKED — a domain-parking / expired-domain monetization page. This is neither a hack nor a customer: there is
  // no owner behind it to sell a cleanup to. It is computed here, on the RAW body (the marker usually lives in a
  // <script>, so the visible text cannot see it), because BOTH decision paths — scanSlice and scanOneVerified —
  // must apply it, and the 2026-07-16 lesson was that a gate living in only one of them is not a gate.
  // Measured impact: 971 of 973 confirmed `malware` leads were this one network (l.cdn-fileserver), 778 foreign.
  sc.parked = S.RE.PARKED.test(B.text) || (S.RE.PARK_BOUNCE.test(B.text) && (B.text || "").length < 2000);
  // Resolve the hosting IP ONCE for flagged sites — feeds the accurate BD-by-IP test AND is stored on
  // the finding (so the dashboard's server-cluster view works from scan-time, no separate backfill).
  let hostingIp = "";
  if (sc.flagged) { const ip = await dohA(reg); if (ip && !CDN_IP.test(ip)) hostingIp = ip; }
  sc.ip = hostingIp;
  sc.isBd = await computeIsBd(reg, visB, rec.source || "", hostingIp);
  sc.bizType = S.bizType(reg, ttl, visB);
  const _ct = extractContact(B.text, visB);
  // flagged but no plain address on the homepage → follow the nav's contact/about link (1 extra fetch, ZERO LLM)
  if (sc.flagged && !_ct.address) {
    const cu = findContactUrl(B.text, base);
    if (cu) { try { const P = await fetchPage(cu, UA_BR, base, 8000); if (P.status && P.text) { const c2 = extractContact(P.text, stripHtml(P.text)); if (c2.address) { _ct.address = c2.address; _ct.district = c2.district; _ct.area = c2.area; } if (!_ct.phone) _ct.phone = c2.phone; if (!_ct.email) _ct.email = c2.email; } } catch (e) {} }
  }
  sc.address = _ct.address; sc.district = _ct.district; sc.area = _ct.area; sc.contactPhone = _ct.phone; sc.email = _ct.email;
  return sc;
}

// ---- Groq Stage-2 (gambling/adult only; keeps the lead list clean) ----
const GROQ_SYS = `You triage website-security scan hits for a Bangladesh cleanup service. Classify the flagged site:
- "hacked_client": a LEGITIMATE business/org site HACKED with injected gambling/adult/foreign spam (doorway/cloaked/hidden/inner pages) while a real business still exists. KEEP.
- "genuine_spam": the site ITSELF is a gambling/casino/betting/adult brand by design. DROP.
- "false_positive": actually clean; the keyword was incidental/legitimate. DROP.
Rule: spam hidden in inner/cloaked/doorway pages behind a normal homepage = hacked_client; whole site openly gambling = genuine_spam.
Return STRICT JSON only: {"classification":"hacked_client|genuine_spam|false_positive","business_type":"healthcare|education|ecommerce|garments|realestate|food|finance|it|ngo|travel|news|government|agro|pharma|automobile|professional|general-business","confidence":0-100,"reason":"<=12 words"}`;

// Ordered key rotation (global Groq key-pool §22): ascending cursor — start key #1, on
// 429/rate-limit jump to the NEXT key immediately (never re-hammer an exhausted key), on
// 401/403 mark the key dead for this isolate, on 200 keep using the current key until it 429s.
// Cursor persists across calls in the same isolate so it walks #1→#16 and wraps. Mirrors
// geminiVerify exactly; Groq is the fallback when Gemini's whole pool is exhausted.
let GROQ_IDX = 0;
const GROQ_DEAD = new Set();
export async function groqVerify(env, domain, title, excerpt, evidence) {
  const keys = (env.GROQ_API_KEY || "").split(",").map((k) => k.trim()).filter(Boolean);
  if (!keys.length) return null;
  const model = env.GROQ_MODEL || "llama-3.1-8b-instant";
  const user = `domain: ${domain}\ntitle: ${title}\nhomepage excerpt: ${excerpt.slice(0, 1500)}\n\nDETECTED SPAM EVIDENCE:\n${evidence.slice(0, 1100)}`;
  for (let tries = 0; tries < keys.length; tries++) {
    if (GROQ_DEAD.size >= keys.length) break;
    let guard = 0;
    while (GROQ_DEAD.has(GROQ_IDX % keys.length) && guard++ < keys.length) GROQ_IDX++;
    const idx = GROQ_IDX % keys.length;
    try {
      const r = await fetch("https://api.groq.com/openai/v1/chat/completions", {
        method: "POST",
        headers: { authorization: "Bearer " + keys[idx], "content-type": "application/json", "user-agent": UA_BR },
        body: JSON.stringify({ model, temperature: 0, max_tokens: 170, response_format: { type: "json_object" }, messages: [{ role: "system", content: GROQ_SYS }, { role: "user", content: user }] }),
      });
      if (r.status === 429) { GROQ_IDX++; continue; }                                       // rate-limited → next key
      if (r.status === 401 || r.status === 403) { GROQ_DEAD.add(idx); GROQ_IDX++; continue; } // invalid/denied → dead key
      if (!r.ok) { GROQ_IDX++; continue; }
      const j = await r.json();
      const obj = JSON.parse(j.choices[0].message.content);
      const cls = String(obj.classification || "").toLowerCase();
      if (!["hacked_client", "genuine_spam", "false_positive"].includes(cls)) return null;
      return { classification: cls, business_type: (obj.business_type || "").toLowerCase(), reason: (obj.reason || "").slice(0, 200) };
    } catch (e) { GROQ_IDX++; continue; }
  }
  return null;
}

// ---- Gemini Stage-2 (primary verifier; 17-key ordered rotation per global key-pool) ----
// Ordered rotation: start at key #1, on 429/RESOURCE_EXHAUSTED jump to the NEXT key
// immediately (never re-hammer an exhausted key), on 400/403 mark the key dead for this
// isolate, on 200 keep using the current key until it 429s. State persists across calls
// in the same Worker isolate, so the cursor walks #1→#17 and wraps. Groq stays as fallback.
let GEM_IDX = 0;
const GEM_DEAD = new Set();
const geminiEp = (model, key) => `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${encodeURIComponent(key)}`;

export async function geminiVerify(env, domain, title, excerpt, evidence) {
  const keys = (env.GEMINI_API_KEYS || "").split(",").map((k) => k.trim()).filter(Boolean);
  if (!keys.length) return null;
  const model = env.GEMINI_MODEL || "gemini-2.5-flash";
  const user = `domain: ${domain}\ntitle: ${title}\nhomepage excerpt: ${excerpt.slice(0, 1500)}\n\nDETECTED SPAM EVIDENCE:\n${evidence.slice(0, 1100)}`;
  const body = JSON.stringify({
    systemInstruction: { parts: [{ text: GROQ_SYS }] },
    contents: [{ role: "user", parts: [{ text: user }] }],
    generationConfig: { temperature: 0, maxOutputTokens: 250, responseMimeType: "application/json", thinkingConfig: { thinkingBudget: 0 } },
  });
  for (let tries = 0; tries < keys.length; tries++) {
    if (GEM_DEAD.size >= keys.length) break;
    let guard = 0;
    while (GEM_DEAD.has(GEM_IDX % keys.length) && guard++ < keys.length) GEM_IDX++;
    const idx = GEM_IDX % keys.length;
    try {
      const r = await fetch(geminiEp(model, keys[idx]), { method: "POST", headers: { "content-type": "application/json" }, body });
      if (r.status === 429) { GEM_IDX++; continue; }                       // quota exhausted → next key
      if (r.status === 400 || r.status === 403) { GEM_DEAD.add(idx); GEM_IDX++; continue; } // invalid/denied → dead key
      if (!r.ok) { GEM_IDX++; continue; }
      const j = await r.json();
      const txt = (j && j.candidates && j.candidates[0] && j.candidates[0].content && j.candidates[0].content.parts && j.candidates[0].content.parts[0] && j.candidates[0].content.parts[0].text) || "";
      if (!txt) return null;
      const obj = JSON.parse(txt);
      const cls = String(obj.classification || "").toLowerCase();
      if (!["hacked_client", "genuine_spam", "false_positive"].includes(cls)) return null;
      return { classification: cls, business_type: (obj.business_type || "").toLowerCase(), reason: (obj.reason || "").slice(0, 200) };
    } catch (e) { GEM_IDX++; continue; }
  }
  return null;
}

const DHAKA = 6 * 3600;
const dDay = (ts) => new Date((ts + DHAKA) * 1000).toISOString().slice(0, 10);
const dHour = (ts) => new Date((ts + DHAKA) * 1000).toISOString().slice(0, 13).replace("T", "-");
const CATS = ["gambling", "pharma", "adult", "deface", "cloak", "foreign_lang", "malware", "redirect"];

// scanSlice — read this shard's slice of the queue and SCAN it. Returns results WITHOUT
// touching D1 (besides the read). The sibling shard Workers run this and return the JSON to
// the main Worker, which is the SINGLE writer (ingestResults) — so 8 parallel shards never
// collide on D1 writes (that collision was silently losing ~75% of scans). Pure read+compute.
export async function scanSlice(env, n) {
  const N = n || Number(env.SCAN_PER_TICK || 5);
  const SHARDS = Math.max(1, Number(env.SCAN_SHARDS || 1));
  const SHARD = Math.max(0, Number(env.SCAN_SHARD || 0)) % SHARDS;
  let rows = (await env.DB.prepare(
    "SELECT rowid,domain,business,phone,bd_score,source FROM domains WHERE pass_no=0 AND (rowid % ?)=? ORDER BY bd_score DESC, rowid LIMIT ?"
  ).bind(SHARDS, SHARD, N).all()).results || [];
  // CONTINUITY: if the fresh queue is thin for this slice, top up by RE-SCANNING the least-recently
  // scanned domains (pass_no ASC). Sites get hacked over time so re-scanning finds NEW hacks, and it
  // guarantees scanners are never idle — no hour is ever 0-scan even when new-domain harvest is slow.
  if (rows.length < N) {
    // RE-SCAN only CLEAN + flagged sites — NEVER confirmed-hacked ones. Those are already caught; re-scanning
    // them just burns scan budget on known leads AND spams the feed with duplicate "confirmed" events (the
    // exact thing the user saw). A clean/flagged site can get hacked later, so re-scanning the not-yet-hacked
    // set is precisely where NEW hacks are found — and the fresh pass_no=0 queue is always drained first above.
    const extra = (await env.DB.prepare(
      "SELECT rowid,domain,business,phone,bd_score,source FROM domains WHERE pass_no>0 AND pass_no<9000 AND (rowid % ?)=? AND domain NOT IN (SELECT domain FROM findings WHERE confirmed=1) ORDER BY pass_no ASC, rowid LIMIT ?"
    ).bind(SHARDS, SHARD, N - rows.length).all()).results || [];
    rows = rows.concat(extra);
  }
  // OPTIMISTIC PRE-MARK (the real deadlock-breaker). Advance pass_no for this WHOLE slice NOW, BEFORE the heavy
  // scan. The 3.3h stall was: a cron/shard invocation (stricter free-plan budget than a fetch) hit a heavy site,
  // got killed mid-scan, so its rowids were never marked done → that domain stayed at the head of the pass_no=0
  // slice and killed the invocation every single tick (permanent deadlock). By claiming the slice up-front, a
  // scanDomain that 1102s/times-out can no longer pin a poison domain — next tick always gets fresh rows, so the
  // queue drains deadlock-free. Disjoint per shard (rowid % SHARDS == SHARD) → zero write-contention. Any row we
  // don't reach this tick simply re-surfaces later via the pass_no-ASC continuity re-scan.
  for (let i = 0; i < rows.length; i += 90) {
    const c = rows.slice(i, i + 90).map((r) => r.rowid);
    try { await env.DB.prepare(`UPDATE domains SET pass_no=pass_no+1 WHERE rowid IN (${c.map(() => "?").join(",")})`).bind(...c).run(); } catch (e) {}
  }
  const findings = [], rowids = [], dead = [], parked = [], cleared = [];
  let errors = 0;
  // A re-scan that finds a previously-confirmed site CLEAN must be able to retract the lead — otherwise a lead
  // confirmed by a buggy detector is permanent, which is how genuine porn brands ended up in the sales list and
  // stayed there. `cleared` carries only DEFINITE negatives: the site answered, and the current gate says it is
  // not a hacked victim. An unreachable site, a timeout, or a gambling/adult hit we could not put to the AI is
  // never cleared — losing a real lead because the server blipped during one re-scan is the worse error.
  // The 2xx test is what makes "the site answered" true rather than merely intended. `unreachable` is only
  // returned when the TRANSPORT fails, so a WAF 403, a rate-limit 429 (this engine runs 400-way concurrency
  // against shared BD hosting, so 429 is routine), a 503 or a captcha interstitial all reach the gate as a
  // normal scan — and produce nothing but the L18CHALLENGE control signal, which score() strips, giving
  // verdict CLEAN. Without this test one WAF-blocked re-scan retracts a genuinely hacked lead.
  const clear = (r, sc) => { const s = sc && sc.httpStatus; if (s >= 200 && s < 300) cleared.push(r.domain); };
  // BUDGETS (the anti-1102 / anti-deadlock guard). A single heavy WordPress site (big sitemap + hundreds of
  // REST posts) used to burn the whole invocation's CPU/wall budget → the shard 1102'd BEFORE returning, so
  // its rowids were never marked done and that poison domain sat at the head of the slice forever, 1102-ing
  // the shard every tick (permanent deadlock). Now: (a) SLICE_MS stops taking NEW domains once we're near the
  // budget — whatever was already scanned still returns + gets marked done, so the queue always advances;
  // (b) each scanDomain gets a hard DOMAIN_MS deadline that skips the expensive WP/sitemap enumeration once
  // exceeded, so no single domain can blow the limit.
  const SLICE_MS = Number(env.SLICE_BUDGET_MS || 22000);
  const DOMAIN_MS = Number(env.DOMAIN_BUDGET_MS || 14000);
  const t0 = Date.now();
  for (const r of rows) {
    if (Date.now() - t0 > SLICE_MS) break;   // near budget → return what we have (unscanned rows stay pass_no=0, retry next tick)
    rowids.push(r.rowid);   // every ATTEMPTED row gets marked done by ingestResults (even on error → leaves the queue, no deadlock)
    let sc;
    try { sc = await scanDomain(env, r, Date.now() + DOMAIN_MS); } catch (e) { errors++; continue; }
    if (sc.error) { errors++; if (sc.error === "unreachable") dead.push(r.rowid); continue; }  // dead/unreachable → flag, exclude from the "clean/sellable" list
    const reg = r.domain.replace(/^www\./, "");
    // A restricted BD institutional TLD (.gov/.edu/.ac/.mil.bd) is registrar-locked to real govt/school bodies, so
    // gambling/adult/foreign takeover on one is ALWAYS a hacked victim — the highest-value lead. Confirm it (no AI
    // call) whether the gate called it flagged OR "spam_site" (homepage fully replaced by spam, all Bengali gone —
    // which the normal !flagged path below would otherwise DROP, silently losing a hacked-government lead).
    if (BD_INST_TLD.test(reg) && ["gambling", "adult", "foreign_lang"].includes(sc.category) && (sc.flagged || sc.status === "spam_site")) {
      findings.push({ domain: r.domain, business: r.business, phone: r.phone || sc.contactPhone, category: sc.category, layers: sc.layers.join(","), proof: sc.proof, proofUrl: sc.proofUrl, httpStatus: sc.httpStatus, nbuckets: sc.nbuckets, verdict: "inst-hacked", reason: "restricted BD institutional TLD + injected " + sc.category + " = hacked victim", confirmed: 1, evidence: sc.evidence, isBd: 1, bizType: sc.bizType, status: "lead", address: sc.address, district: sc.district, area: sc.area, ip: sc.ip });
      continue;
    }
    // Not flagged: only PARK when the domain NAME itself is a gambling/adult brand (100% safe — no legit business is
    // named "iceporn"/"netbet"). A merely openly-spam foreign homepage stays droppable (re-scans later, never lost).
    if (!sc.flagged) {
      const nameSpam = S.domainSpammy(reg);
      if (sc.status === "spam_site" && nameSpam) parked.push(r.rowid);
      // RETRACT only on verdict `clean`. A `spam_site` verdict is NOT a negative: score() assigns it whenever the
      // homepage is openly spammy and no BD/Bangla identity survives — which is exactly what a previously-partial
      // injection looks like once the attacker replaces the WHOLE homepage and the Bengali content is gone. Clearing
      // there would retract the lead at the moment the compromise became total. The one safe exception is a
      // gambling/adult BRAND in the domain NAME (domainSpammy), which no real BD business ever carries.
      if (sc.status === "clean" || nameSpam) clear(r, sc);
      continue;
    }
    let status = sc.status, confirmed = sc.confirmed, verdict = sc.verdict, reason = `posterior=${sc.posterior} buckets=${sc.nbuckets}${sc.hard ? " HARD" : ""}`, biz = sc.bizType;
    // PARKING GATE — before the AI, so a parked domain costs zero Gemini. Applies to EVERY category: `malware`
    // never reached the AI at all, which is how 971 parked domains became "malware leads".
    if (sc.parked) { parked.push(r.rowid); clear(r, sc); continue; }
    if (["gambling", "adult", "foreign_lang"].includes(sc.category)) {
      // 1) gambling/adult BRAND in the domain NAME → genuine spam → park, spend NO Gemini.
      if (S.domainSpammy(reg)) { parked.push(r.rowid); clear(r, sc); continue; }
      else {
        const _ev = sc.evidence.map((e) => e.url + " " + e.match).join("; ");
        const v = (await geminiVerify(env, r.domain, sc.title, sc.excerpt, _ev)) || (await groqVerify(env, r.domain, sc.title, sc.excerpt, _ev));
        if (v) {
          // The AI saying "hacked_client" is necessary but NOT sufficient. It answered exactly that for all 26
          // porn sites that reached the sales list. A lead has to have someone to sell to.
          if (v.classification === "hacked_client" && !hasCustomer(reg, sc)) { clear(r, sc); continue; }
          if (v.classification === "hacked_client") {
            biz = v.business_type || biz; verdict = "ai-" + v.classification; reason = "ai:" + v.classification + " — " + v.reason;
            if (adultNeedsReview(reg, sc.category)) { status = "review"; confirmed = 0; reason = "adult on a non-.bd domain — needs human approval before it becomes a lead"; }
            else { status = "lead"; confirmed = 1; }
          }
          else { clear(r, sc); continue; }   // genuine_spam / false_positive → drop, allow a fresh re-scan. NOT parked: a BD business often
                            // uses a .com and the AI can misjudge it as genuine_spam — parking would lose a real hacked
                            // BD lead forever. Only a gambling/adult BRAND in the NAME (domainSpammy, above) is parked.
        } else {
          // AI POOL EXHAUSTED. gambling/adult is INDISTINGUISHABLE from a hacked victim by signals alone, so a positive
          // AI "hacked_client" verdict is REQUIRED to confirm. Without it we must NOT auto-confirm — that fallthrough
          // leaked ~331 genuine porn/betting sites into the leads. Drop this scan; the domain stays in the queue and
          // gets a proper AI verdict on a later re-scan once the Gemini/Groq pool has refilled.
          continue;
        }
      }
    }
    // SAFETY GATE (2026-07-19) — a gambling/adult BRAND in the domain NAME is genuine spam and must NEVER be
    // confirmed, whatever category the fuse resolved. Non-GA categories (malware/deface/cloak/redirect) used to
    // reach the push below having seen NEITHER this name test NOR the AI — and a genuine porn tube ALWAYS carries
    // ad-malware/popunder/redirect layers, so its category resolves to malware/redirect and that was the exact door
    // it walked through into the lead list. Reuses the SAME narrow high-precision brand list as the GA branch above,
    // so it adds ZERO new false-positive surface for real BD businesses (no Bangla/leet tokens are involved here).
    if (S.domainSpammy(reg)) { parked.push(r.rowid); clear(r, sc); continue; }
    // WEAK-TOKEN GATE — deliberately the LAST word, after the AI branch above has had its say. A positive
    // `hacked_client` must not be able to promote a lone generic English word: the AI approved 239 of these,
    // including the national HSC admission portal and a Ministry of Health API. Demote to review, never drop —
    // a genuinely injected site can still be confirmed by a human from the review tab.
    if (confirmed && weakOnly(sc)) {
      status = "review"; confirmed = 0; verdict = "weak-only";
      reason = `only generic English vocabulary matched (${sc.proof || ""}) — needs human confirmation`;
    }
    // (non-GA categories — malware/deface/cloak/redirect — reach here and push directly; they need no AI. A spam_site
    // is always flagged=false and was already handled by the !sc.flagged guard above, so no branch is needed here.)
    findings.push({ domain: r.domain, business: r.business, phone: r.phone || sc.contactPhone, category: sc.category, layers: sc.layers.join(","), proof: sc.proof, proofUrl: sc.proofUrl, httpStatus: sc.httpStatus, nbuckets: sc.nbuckets, verdict, reason, confirmed, evidence: sc.evidence, isBd: sc.isBd, bizType: biz, status, address: sc.address, district: sc.district, area: sc.area, ip: sc.ip });
  }
  // No `gen` here on purpose. scanSlice is what the Cloudflare shards run, and they run the LIGHT profile under
  // the free-plan CPU wall. Claiming v2-qualification for a cheap scan would rob the domain of the deep pass it
  // is queued for. Only the VM, which runs the full detector, sends gen (see scanner/run.mjs).
  return { rowids, findings, scanned: rows.length, errors, dead, parked, cleared };
}

// ingestResults — the SINGLE writer. Marks all scanned rowids done + writes findings + stats
// in ONE batch. If it fails, the rowids stay pass_no=0 and simply retry next tick (no loss).
export async function ingestResults(env, agg) {
  const now = Math.floor(Date.now() / 1000);
  const rowids = agg.rowids || [];
  // SAFETY: cap findings/tick so a 16-shard re-scan burst can't build a giant/slow D1 batch (the transient
  // error that froze the engine). rowids are still ALL marked done; any capped finding re-surfaces next pass.
  const findings = (agg.findings || []).slice(0, 200);
  const scanned = agg.scanned || 0, errors = agg.errors || 0;
  const stmts = [];
  // pass_no was ALREADY advanced optimistically in scanSlice (the deadlock-breaker) — do NOT re-increment here
  // or every row would count twice. We only set the dead flag: unreachable → dead=1 (kept OUT of the clean/
  // sellable list), reached → dead=0 (self-heals if a previously-dead site comes back up).
  const deadSet = new Set(agg.dead || []);
  const reached = rowids.filter((id) => !deadSet.has(id));
  const deadRows = [...deadSet];
  // gen is stamped ONLY by a scanner that actually ran the full detector — the VM sends its DETECTOR_GEN on
  // /vm-push; the Cloudflare shards, which run the light profile under the free-plan CPU wall, send nothing and
  // therefore never claim a row as v2-qualified. Without that asymmetry a shard's cheap scan would stamp gen=2
  // and quietly rob the domain of the deep pass it was queued for.
  // When it IS stamped, it goes on every attempted row, reachable or not: a domain the v2 reachability ladder
  // still cannot reach HAS been re-qualified by v2, and leaving it behind would pin it at the head of the
  // re-scan queue forever and starve the rows that can actually be scanned.
  const gen = Number(agg.gen) || 0;
  const setGen = gen ? ", gen=" + gen : "";
  // Persist each domain's fingerprint and working origin. This is what makes the NEXT scan able to ask the
  // single most discriminating free question there is — "what changed since last time?" — and it is written for
  // every scanned domain, not just the flagged ones, because the whole value is catching a CLEAN site the day
  // it turns dirty. One statement per 45 rows, only for domains whose fingerprint actually moved.
  for (const f of (agg.fps || []).slice(0, 600)) {
    if (!f || !f.rowid) continue;
    stmts.push(env.DB.prepare("UPDATE domains SET fp=?, base=? WHERE rowid=?")
      .bind(String(f.fp || "").slice(0, 1200), String(f.base || "").slice(0, 120), f.rowid));
  }
  for (let i = 0; i < reached.length; i += 90) {
    const chunk = reached.slice(i, i + 90);
    stmts.push(env.DB.prepare(`UPDATE domains SET dead=0${setGen} WHERE rowid IN (${chunk.map(() => "?").join(",")})`).bind(...chunk));
  }
  for (let i = 0; i < deadRows.length; i += 90) {
    const chunk = deadRows.slice(i, i + 90);
    stmts.push(env.DB.prepare(`UPDATE domains SET dead=1${setGen} WHERE rowid IN (${chunk.map(() => "?").join(",")})`).bind(...chunk));
  }
  // PARK genuine gambling/adult brands (pass_no=9000, a sentinel far above any real pass count). This drops them
  // out of the re-scan rotation (ORDER BY pass_no ASC never reaches them) AND out of the clean/safe-site list
  // (its query is pass_no<9000), so a genuine porn/betting site is scanned once, dropped, and never re-verified —
  // it can never re-pollute the leads and never burns Gemini again. Confirmed hacked victims are NEVER parked.
  const parkRows = agg.parked || [];
  for (let i = 0; i < parkRows.length; i += 90) {
    const chunk = parkRows.slice(i, i + 90);
    stmts.push(env.DB.prepare(`UPDATE domains SET pass_no=9000 WHERE rowid IN (${chunk.map(() => "?").join(",")})`).bind(...chunk));
  }
  // RETRACTION. A domain the current detector scanned successfully and judged NOT a hacked victim gives up any
  // confirmed finding it still carries. The row is demoted rather than deleted — status='cleared' keeps the
  // history visible, so a lead that vanishes can be explained instead of just disappearing from the dashboard.
  // Only domains that carry a confirmed finding are touched; for the overwhelming majority of a batch this
  // matches nothing and costs one indexed lookup.
  const clearedRows = (agg.cleared || []).filter(Boolean);
  for (let i = 0; i < clearedRows.length; i += 90) {
    const chunk = clearedRows.slice(i, i + 90);
    stmts.push(env.DB.prepare(
      `UPDATE findings SET confirmed=0, status='cleared', stage2_reason='re-scan under detector gen ${gen || "?"}: no longer a hacked victim', ts=? WHERE confirmed=1 AND domain IN (${chunk.map(() => "?").join(",")})`
    ).bind(now, ...chunk));
  }
  const catc = Object.fromEntries(CATS.map((c) => [c, 0]));
  let flagged = 0, confirmed = 0;
  for (const f of findings) {
    flagged++;
    const conf = f.confirmed ? 1 : 0;
    if (conf) { confirmed++; if (catc[f.category] !== undefined) catc[f.category]++; }
    // Upsert on the unique domain index rather than DELETE-then-INSERT. Two reasons: the delete/insert pair was
    // not atomic and had left 38 duplicate rows behind, and it reset first_ts on every pass — so a lead found in
    // June looked like it was found today, which is exactly the field the outreach copy leans on. COALESCE keeps
    // the original discovery time and only the current-state columns move.
    stmts.push(env.DB.prepare(
      "INSERT INTO findings (domain,business,phone,category,layers,proof_snippet,proof_url,http_status,stage1_score,stage2_verdict,stage2_reason,stage2_category,confirmed,pass_no,first_ts,ts,evidence,is_bd,biz_type,status,address,district,area,ip,apex) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) " +
      "ON CONFLICT(domain) DO UPDATE SET apex=excluded.apex, business=excluded.business, phone=excluded.phone, category=excluded.category, layers=excluded.layers, proof_snippet=excluded.proof_snippet, proof_url=excluded.proof_url, http_status=excluded.http_status, stage1_score=excluded.stage1_score, stage2_verdict=excluded.stage2_verdict, stage2_reason=excluded.stage2_reason, stage2_category=excluded.stage2_category, confirmed=excluded.confirmed, ts=excluded.ts, evidence=excluded.evidence, is_bd=excluded.is_bd, biz_type=excluded.biz_type, status=excluded.status, address=excluded.address, district=excluded.district, area=excluded.area, ip=excluded.ip, first_ts=COALESCE(findings.first_ts, excluded.first_ts)"
    ).bind(f.domain, (f.business || "").slice(0, 200), (f.phone || "").slice(0, 40), f.category, (f.layers || "").slice(0, 200), (f.proof || "").slice(0, 600), (f.proofUrl || "").slice(0, 300), f.httpStatus || 0, f.nbuckets || 0, (f.verdict || "").slice(0, 20), (f.reason || "").slice(0, 400), f.category, conf, 1, now, now, JSON.stringify(f.evidence || []).slice(0, 4000), f.isBd ? 1 : 0, (f.bizType || "").slice(0, 30), (f.status || "lead").slice(0, 16), (f.address || "").slice(0, 200), (f.district || "").slice(0, 40), (f.area || "").slice(0, 40), (f.ip || "").slice(0, 45),
      // derived here, in the single writer, rather than at every call site — a finding that reaches D1 without
      // an organisation would silently reappear as its own lead card and undo the whole rollup
      S.registrableOf(f.domain)));
    // Only announce a FIRST confirmation. Re-scanning the confirmed set (which detector v2 now does, so a bad
    // lead can be retracted) would otherwise republish the same lead into the live feed on every pass — the
    // duplicate-"confirmed"-event noise the owner already reported once.
    if (conf) stmts.push(env.DB.prepare(
      "INSERT INTO events (kind,domain,detail,ts) SELECT 'confirmed',?,?,? WHERE NOT EXISTS (SELECT 1 FROM events WHERE kind='confirmed' AND domain=?)"
    ).bind(f.domain, (f.category + " | " + (f.proof || "")).slice(0, 200), now, f.domain));
  }
  const day = dDay(now), hour = dHour(now);
  const catSet = CATS.map((c) => `${c}=${c}+${catc[c]}`).join(",");
  stmts.push(env.DB.prepare(
    `INSERT INTO daily_stats (day,scanned,flagged,confirmed,errors,${CATS.join(",")}) VALUES (?,?,?,?,?,${CATS.map(() => "?").join(",")}) ON CONFLICT(day) DO UPDATE SET scanned=scanned+?,flagged=flagged+?,confirmed=confirmed+?,errors=errors+?,${catSet}`
  ).bind(day, scanned, flagged, confirmed, errors, ...CATS.map((c) => catc[c]), scanned, flagged, confirmed, errors));
  stmts.push(env.DB.prepare("INSERT INTO hourly_stats (hour,scanned,flagged,confirmed,errors) VALUES (?,?,?,?,?) ON CONFLICT(hour) DO UPDATE SET scanned=scanned+?,flagged=flagged+?,confirmed=confirmed+?,errors=errors+?").bind(hour, scanned, flagged, confirmed, errors, scanned, flagged, confirmed, errors));
  stmts.push(env.DB.prepare("UPDATE counters SET value=value+? WHERE metric='total_scanned'").bind(scanned));
  stmts.push(env.DB.prepare("UPDATE counters SET value=value+? WHERE metric='total_flagged'").bind(flagged));
  stmts.push(env.DB.prepare("UPDATE counters SET value=value+? WHERE metric='total_confirmed'").bind(confirmed));
  stmts.push(env.DB.prepare("UPDATE counters SET value=value+? WHERE metric='total_errors'").bind(errors));
  // Execute in chunks rather than as one giant batch. A 300-domain VM push now carries up to 300 fingerprint
  // UPDATEs on top of the row-marking, finding and stats statements, and a batch that size fails as a whole —
  // which cost a real outage: every push returned ok:true while NOTHING was written, because vmPush swallowed
  // the throw. Chunking keeps each batch inside D1's limits, and a chunk that does fail now propagates.
  for (let i = 0; i < stmts.length; i += 80) await env.DB.batch(stmts.slice(i, i + 80));
  return { scanned, flagged, confirmed };
}

// single-worker convenience (used by POST /scan_tick and main shard-0 fallback)
export async function scanTick(env, n) {
  return await ingestResults(env, await scanSlice(env, n));
}

// scanOneVerified — full deep scan of ONE domain + the SAME Gemini/Groq Stage-2 verify the
// queue uses (no steps skipped). Used by the dashboard's manual on-demand scan. Returns a
// finding-shaped object whether the site is hacked OR clean (so the user sees every result).
export async function scanOneVerified(env, domain) {
  const sc = await scanDomain(env, { domain });
  if (sc.error) return { domain, error: sc.error };
  let status = sc.status, confirmed = sc.confirmed, verdict = sc.verdict, biz = sc.bizType;
  let reason = `posterior=${sc.posterior} buckets=${sc.nbuckets}${sc.hard ? " HARD" : ""}`;
  const reg = String(domain).replace(/^www\./, "");
  const isGA = ["gambling", "adult", "foreign_lang"].includes(sc.category);
  // PARKING GATE — same as scanSlice, and it has to be the FIRST arm of this chain: as a standalone `if` it would
  // be overwritten by the institutional/GA arms below.
  if (sc.parked) {
    status = "parked"; confirmed = 0; verdict = "parked-domain";
    reason = "domain-parking / expired-domain monetization page — no owner to sell a cleanup to";
  }
  // restricted BD institutional TLD (.gov/.edu/.ac/.mil.bd) + spam = always a hacked victim (flagged OR fully-defaced spam_site).
  else if (isGA && BD_INST_TLD.test(reg) && (sc.flagged || sc.status === "spam_site")) {
    status = "lead"; confirmed = 1; verdict = "inst-hacked"; reason = "restricted BD institutional TLD + injected " + sc.category + " = hacked victim";
  } else if (sc.flagged && isGA) {
    if (S.domainSpammy(reg)) { status = "genuine_spam"; confirmed = 0; verdict = "spam-domain"; reason = "gambling/adult brand in the domain name — genuine spam, not a hacked victim"; }
    else {
      const ev = sc.evidence.map((e) => e.url + " " + e.match).join("; ");
      const v = (await geminiVerify(env, domain, sc.title, sc.excerpt, ev)) || (await groqVerify(env, domain, sc.title, sc.excerpt, ev));
      if (v) {
        // Same two gates as scanSlice. This path (POST /scan_manual and the dashboard's on-demand scan) had
        // NEITHER, which is how jamsgroupbd.net and alaskancrowncruise.com re-confirmed themselves minutes
        // after being moved to the review queue. Every path that can set confirmed=1 has to agree.
        if (v.classification === "hacked_client" && !hasCustomer(reg, sc)) { status = "genuine_spam"; confirmed = 0; verdict = "no-customer"; reason = "no business identity found — nothing here to sell a cleanup to"; }
        else if (v.classification === "hacked_client" && adultNeedsReview(reg, sc.category)) { status = "review"; confirmed = 0; verdict = "needs-review"; reason = "adult on a non-.bd domain — needs human approval before it becomes a lead"; }
        else if (v.classification === "hacked_client") { status = "lead"; confirmed = 1; }
        else { status = v.classification; confirmed = 0; }
        biz = v.business_type || biz; verdict = "ai-" + v.classification; reason = "ai:" + v.classification + " — " + v.reason;
      } else {
        // AI pool exhausted → gambling/adult cannot be confirmed without a positive verdict (would leak genuine spam).
        status = "review"; confirmed = 0; verdict = "needs-ai"; reason = "gambling/adult flagged — AI pool exhausted, pending verify";
      }
    }
  }
  // WEAK-TOKEN GATE — last word here too, for the same reason as in scanSlice.
  if (confirmed && weakOnly(sc)) {
    status = "review"; confirmed = 0; verdict = "weak-only";
    reason = `only generic English vocabulary matched (${sc.proof || ""}) — needs human confirmation`;
  }
  return {
    domain, flagged: sc.flagged ? 1 : 0, confirmed: confirmed ? 1 : 0, category: sc.category || "",
    verdict, reason, proof: sc.proof || "", proofUrl: sc.proofUrl || "", layers: (sc.layers || []).join(","),
    title: sc.title || "", httpStatus: sc.httpStatus || 0, isBd: sc.isBd ? 1 : 0, bizType: biz || "",
    status, evidence: sc.evidence || [], address: sc.address || "", district: sc.district || "", area: sc.area || "", phone: sc.contactPhone || "", ip: sc.ip || "",
  };
}

// findContactUrl — pull the nav's contact/about link (absolute) so we can fetch it for an address. zero LLM.
function findContactUrl(html, base) {
  const re = /<a\b[^>]*href=["']([^"'#]+)["'][^>]*>([\s\S]{0,60}?)<\/a>/gi;
  let m, about = "";
  while ((m = re.exec(html)) && re.lastIndex < 90000) {
    const href = (m[1] || "").trim(); if (!href || /^(mailto:|tel:|javascript:|data:)/i.test(href)) continue;
    const txt = (m[2] || "").replace(/<[^>]+>/g, " ").toLowerCase();
    const hl = href.toLowerCase();
    const isContact = /contact|যোগাযোগ/i.test(hl) || /contact|যোগাযোগ/.test(txt);
    const isAbout = /about|আমাদের/i.test(hl) || /about\s*us|about|আমাদের/.test(txt);
    if (!isContact && !isAbout) continue;
    let abs; try { abs = new URL(href, base).href; } catch (e) { continue; }
    if (!/^https?:\/\//.test(abs)) continue;
    if (isContact) return abs;          // contact page is the best source — take it immediately
    if (!about) about = abs;            // keep an about page as fallback
  }
  return about;
}

// fetchContact — homepage (then contact/about page if needed) + regex address extraction (ZERO LLM).
// Used to back-fill address/district/area on already-confirmed leads.
export async function fetchContact(domain) {
  const base = "https://" + String(domain || "").trim().toLowerCase().replace(/^www\./, "");
  const B = await fetchPage(base, UA_BR, null, 9000);
  if (B.status === 0 || !B.text) return null;
  let ct = extractContact(B.text, stripHtml(B.text));
  if (!ct.address) {   // homepage had no plain address → follow contact/about link
    const cu = findContactUrl(B.text, base);
    if (cu) { try { const P = await fetchPage(cu, UA_BR, base, 8000); if (P.status && P.text) { const c2 = extractContact(P.text, stripHtml(P.text)); if (c2.address) { ct.address = c2.address; ct.district = c2.district; ct.area = c2.area; } if (!ct.phone) ct.phone = c2.phone; if (!ct.email) ct.email = c2.email; } } catch (e) {} }
  }
  return ct;
}
