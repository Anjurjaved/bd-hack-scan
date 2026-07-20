// vocab.js — signature-library EXTENSIONS (P45 · P46 · P47).
//
// WHY THIS MODULE EXISTS: signatures.js is shared and frozen, but three vocabulary gaps in it are
// costing real recall:
//
//   P45  SLUG_SPAM (signatures.js:23) knows ~15 tokens while GAMB_STRONG (signatures.js:5) knows 100+.
//        A sitemap full of /1xbet-bangladesh-login/ therefore produces NO hit at all, because the
//        doorway layers test the SLUG, not the body. This module rebuilds that list to brand parity.
//   P46  The lexicon has zero Bengali gambling vocabulary, which is absurd for a BD-focused scanner:
//        spam injected onto a Bengali-language school site is routinely localised for BD search traffic.
//   P47  Whole active injection families — essay mills, replica goods, payday loans, wallet drainers,
//        streaming piracy — have no coverage whatsoever.
//
// It reads only bytes scan.js already fetched: ZERO extra HTTP requests, tier-1 safe.
//
// ---------------------------------------------------------------------------------------------
// THE FIRST RULE OF THIS FILE: a token is not "tuned", it is kept or it is rejected.
// ---------------------------------------------------------------------------------------------
// Every token below was dry-run as a regex over the FULL 160,682-domain live queue corpus and every
// hit eyeballed. The corpus killed five tokens that looked completely safe on paper, and they are
// documented in the REJECTED block rather than deleted, because the next person will be tempted by
// exactly the same five:
//
//   `bahis`  → bahis.dls.gov.bd — the Bangladesh Animal Health Information System, a real .gov.bd
//              site of the Department of Livestock Services. See the FP_GUARD note below: this one
//              is not merely a token we declined to add, it is a LIVE landmine already sitting in
//              GAMB_STRONG, and on a restricted institutional TLD it auto-confirms without any AI.
//   `nagad`  → nagad.com.bd is Bangladesh's second-largest mobile financial service, and
//              nagadislamic.gov.bd / nagad.edu.bd / nagad.ac.bd are real institutions. Only nagad88
//              (the casino brand riding the payment brand's name) is safe.
//   `baji`   → bajitpurpaurashava.gov.bd — Bajitpur Municipality. Also bajitpurnet.com, addabaji.com.bd
//              ("আড্ডাবাজি" = chatting), ambajient.com. Safe ONLY glued to live/88/999/bet/bd/9.
//   `toto`   → toto.com.bd — the Japanese sanitaryware brand's BD distributor.
//   `slot`   → BD school and clinic sites are full of "slot booking" / "admission slot" / "time slot".
//              Safe only glued to gacor/online/88/777/deposit/dana/pulsa/thailand/demo/hoki.
//   `pin-up` → bluebirdpinups.com. "Pin-up" is a hairstyle and makeup term; a BD salon or photography
//              studio has /pin-up-makeup/. Safe only glued to casino/bet/india/bangladesh/bd.
//   `casino` → 120 corpus hits were all gambling, but the corpus is DOMAINS. In a URL path or in body
//              text a BD news site legitimately writes about the 2019 Dhaka casino raids, so bare
//              casino stays where signatures.js already put it: the WEAK tier, never confirming alone.
//
// And the Bengali trap, which is worse than the Latin one because it cannot be corpus-tested at all
// (the corpus is ASCII domains) — see the BN_ block for the per-word reasoning.

export const TIER = "t1";

// ---------------------------------------------------------------------------------------------
// P45 — SLUG_SPAM at brand parity with GAMB_STRONG.
// ---------------------------------------------------------------------------------------------
// Slug form: spaces in the brand become `[-_]?` so "gates of olympus" matches /gates-of-olympus/,
// /gates_of_olympus/ and /gatesofolympus/. Non-Latin alternatives are dropped — a CJK or Cyrillic
// brand never survives into a URL slug, and carrying them here only costs regex.
//
// Boundary discipline is the whole game, exactly as SPAMMY_DOMAIN (signatures.js:29) already does it:
// `bet` NEVER appears unanchored, so /sylhet-branch/, /cabinet-decision/ and /betterment/ cannot match.
// Every short token is either glued to a digit, glued to a second spam word, or \b-anchored on both ends.
// The leading \b on baji and jaya is not decoration. আড্ডাবাজি ("addabaji", chatting) and বাজিতপুর
// (Bajitpur) are ordinary Bangla words, so /addabaji-bd/ would match an unanchored `baji[-_]?bd`
// and hand us a false lead on somebody's blog. Same reasoning for \bjaya (vijaya) and \bmaxbet.
//
// 9wickets, 1win, 22win and 22bet are matched SOLID — no `[-_]?` — and this was not a judgement call.
// The first dry run over 221 live sites produced exactly one false positive, and it was this slug:
//   /nz-vs-wi-...-west-indies-by-9-wickets-in-the-second-test/
// "by 9 wickets" is how every cricket result in Bangladesh is written. A separator-tolerant 9wickets
// turns the national sport into gambling evidence. "1-win", "22-wins" collide the same way in match
// reports, so all four brands only match the way the brand itself is actually spelled.
// `jeet[-_]?win` was SOLIDIFIED to \bjeetwin\b for the 1win/22win/9wickets reason, one entry too late:
// জিত ("jeet") is the everyday Bengali word for VICTORY and a common given name, so /jeet-win-story/ on a
// Bengali motivational or sports blog matched the separator-tolerant form. The brand itself is spelled
// solid everywhere it appears (jeetwinfun.com, jeetwinply.com, jeetwinbd.bet, jeetwinbdt.com are all
// in the corpus), and the separated form is kept where it is glued to a digit — jeet-win66.com and
// jeet-win88.com are real — which "jeet win" in Bengali prose never is.
// jeetbuzz keeps its separator: "buzz" carries the pattern on its own.
const SLUG_BRAND = String.raw`1[-_]?xbet|melbet|\bbetwinner|bet[-_]?visa|parimatch|mostbet|\b4rabet\b|babu[-_]?88|\bbaji[-_]?(?:live|88|888|999|bet|bd|9)|krikya|\bjeet[-_]?buzz|\bjeetwin|jeet[-_]?win[-_]?\d|\bjaya9\b|nagad[-_]?88|glory[-_]?casino|marvel[-_]?bet|mcw[-_]?casino|crickex|\bline[-_]?bet\b|\b9wickets\b|raja[-_]?bets|bet[-_]?365|beto[-_]?bet|vavada|\b1win\b|bbr[-_]?bet|bet[-_]?jili|jili[-_]?bet|dafa[-_]?bet|\bbet[-_]?way\b|\bbet[-_]?fair|\bbet[-_]?ano\b|\b22bet\b|\b22win\b|\bbet[-_]?sson|\buni[-_]?bet\b|\bwin[-_]?bet\b|\bbet[-_]?flix|\bbwin\b|bettilt|bahsegel|pin[-_]?up[-_]?(?:casino|bet|india|bangladesh|bd)\b|\bmax[-_]?bet\b`;

// Indonesian / Turkish / Vietnamese / Iberian campaign vocabulary. These are the slugs the actual
// doorway farms generate, and none of them is a word any Bangladeshi business has ever put in a URL.
//
// The numeric slot arm is `(?!19|20)\d{3,4}`, not `\d{2,4}`, and that lookahead is load-bearing:
// slot88 / slot138 / slot303 / slot777 are brands, but /admission-slot-2025/ and /exam-slot-2024/
// are pages every BD school publishes, and a bare \d{2,4} matches "slot-2025". Two-digit slots are
// dropped for the same reason — /booking/slot-12/ is a time slot. slot88 and slot777 survive because
// they are named explicitly in the alternation above.
//
// SLOT_NB is the guard that makes the REJECTED block above true instead of merely well-intentioned.
// The draft rejected bare `slot` because "BD school and clinic sites are full of slot booking /
// admission slot / time slot" — and then re-admitted those exact pages through the collocation arm:
//   /admission-slot-online-application/   matched  slot-online
//   /appointment-slot-online/             matched  slot-online
//   /serial-slot-online-doctor/           matched  slot-online   (BD doctor-serial booking)
//   /book-slot-demo-class/                matched  slot-demo
//   /time-slot-vip-lounge/                matched  slot-vip
// All five are ordinary Bangladeshi school/clinic URLs and all five fired the first draft of this arm.
// `demo` is dropped outright: it collides with /slot-demo-class/ and dropping it cost ZERO corpus hits
// over all 160,682 domains, so it was never carrying weight. `vip` is kept — bbslotvip.cc and
// ggslotvip.one are in the corpus — because SLOT_NB already handles /time-slot-vip-lounge/.
//
// SLOT_NB is a PREFIX guard, deliberately NOT a `\b`. A `\b` here reads correctly against a URL path
// but wrongly against a HOSTNAME, and SLUG_SPAM2 is exported to sitemapx.js / content.js / obfusc.js,
// which run it over decoded URLs and blobs that contain hosts. Requiring a boundary before `slot`
// dropped kakaslot777.net, adaslot88.org, masterslot138.net, 88slot88.com, danaslot888.com,
// hokislot777.com, bolaslot303.com, menangslot88.com and polaslot138.com — nine live spam hosts —
// because a doorway farm GLUES its prefix. So the guard names the BD booking words instead, with the
// separator optional so that "timeslot-online" is refused along with "time-slot-online".
// The `situs|link|daftar|bandar|judi|mpo|qq|toto|rtp` + slot arms are untouched — their first token
// already carries the pattern, so they need no guard and keep full recall on real slot doorways.
const SLOT_NB = String.raw`(?<!(?:admission|booking|book|time|appointment|serial|exam|test|interview|delivery|pickup|available|open|next|last|reserved|meeting|class|session|visit|vaccine|donation|parking|free)[-_ ]?)`;
// `pragmatic play` is a real casino game studio AND a real speech-and-language / early-childhood
// development term. BD special-needs schools and child therapy centres publish /pragmatic-play-skills/
// and /pragmatic-play-therapy-autism/ in good faith, so the brand is refused in front of that vocabulary.
// A genuine doorway (/pragmatic-play-slot-demo/, /pragmatic-play-login/) is unaffected.
const PRAGMATIC = String.raw`pragmatic[-_]?play(?![-_]?(?:based|therap|skill|learn|develop|activit|area|time|idea|opportunit|session))`;
const SLUG_CAMPAIGN = String.raw`situs[-_]?(?:judi|slot|toto|bola)|judi[-_]?(?:online|bola|slot)|\bjudi\b|${SLOT_NB}slot[-_]?(?:gacor|online|88|777|deposit|dana|pulsa|thailand|hoki|maxwin|jackpot|vip|xo)|${SLOT_NB}slot[-_]?(?!19|20)\d{3,4}\b|mpo[-_]?slot|qq[-_]?slot|\bpkv\b|pkv[-_]?games|togel|toto[-_]?(?:macau|hk|sgp|sdy|4d|togel|slot)|bandar[-_]?(?:togel|judi|bola|slot)|\bgacor\b|maxwin|sbobet|bocoran|taruhan|link[-_]?alternatif|deposit[-_]?pulsa|bonus[-_]?new[-_]?member|scatter[-_]?hitam|daftar[-_]?slot|link[-_]?slot|sabung[-_]?ayam|\bsabong\b|mahjong[-_]?ways|gates[-_]?of[-_]?olympus|${PRAGMATIC}|\bpg[-_]?soft\b|joker[-_]?123|918[-_]?kiss|pussy[-_]?888|mega[-_]?888|rtp[-_]?(?:slot|live)|bahis[-_]?siteleri|casino[-_]?siteleri|apuestas[-_]?deportivas|apostas[-_]?esportivas|tragamonedas|tragaperras|\bnha[-_]?cai\b|\bscommesse\b`;

// The generic-casino slugs are held OUT of SLUG_SPAM2 and applied separately, because they are the
// one arm with a believable innocent owner: an English-language Bangladeshi daily publishes
// /news/online-casino-racket-busted-in-gulshan/. Every other token in this file is a brand or a
// campaign word no newsroom would ever put in a URL. Suppressed on biz_type "news".
const SLUG_CASINO_GENERIC = String.raw`casino[-_]?online|online[-_]?casino|live[-_]?casino|casino[-_]?bonus|casino[-_]?(?:slots?|games?)`;
export const SLUG_CASINO_GENERIC_RE = new RegExp(SLUG_CASINO_GENERIC, "i");

// Pharma slugs. GATED, not free: see PHARMA_SLUG_SAFE_BIZ. A real Bangladeshi online pharmacy
// legitimately has /product/sildenafil-50mg/ — Square and Beximco both make the generic and BD
// pharmacy e-commerce lists it by INN. So these fire only off a pharmacy/clinic site.
const SLUG_PHARMA = String.raw`kamagra|lovegra|\bviagra\b|\bcialis\b|\blevitra\b|sildenafil|tadalafil|vardenafil|(?:buy|cheap|generic|order)[-_]?(?:viagra|cialis|levitra)|viagra[-_]?(?:online|bangladesh|price)|farmacia[-_]?online`;

// Adult slugs. `porn`/`porno` are \b-anchored on BOTH sides, which is what keeps "pornography" out —
// there is no word boundary between the o and the g, so an NGO's /pornography-awareness/ cannot match.
// They are nonetheless bound to a second porn-only word, because /porn-addiction-counselling/ is a
// page a Bangladeshi NGO or madrasah genuinely publishes.
const SLUG_ADULT = String.raw`\bbokep\b|\bhentai\b|\bxnxx\b|xvideos|pornhub|xhamster|\bredtube\b|youporn|brazzers|onlyfans|\bporn[o]?[-_]?(?:video|movie|hd|tube|xxx|sex|site|star|bangla)|(?:bangla|desi|indian)[-_]?porn|\bsikis\b|\bsikiş\b|bangla[-_]?choti|choti[-_]?golpo|chuda[-_]?chudi|choda[-_]?chudi|\bxxx[-_]?(?:video|movie|hd|bd|bangla)`;

/** P45 payload: strong on-domain slug spam. Superset of signatures.js RE.SLUG_SPAM. */
export const SLUG_SPAM2 = new RegExp(`(?:${SLUG_BRAND})|(?:${SLUG_CAMPAIGN})|(?:${SLUG_ADULT})`, "i");
export const SLUG_SPAM2_G = new RegExp(`(?:${SLUG_BRAND})|(?:${SLUG_CAMPAIGN})|(?:${SLUG_ADULT})`, "gi");
export const SLUG_PHARMA_RE = new RegExp(SLUG_PHARMA, "i");
export const SLUG_PHARMA_G = new RegExp(SLUG_PHARMA, "gi");
// Business types whose own product pages legitimately carry a pharma slug.
const PHARMA_SLUG_SAFE_BIZ = new Set(["pharma", "healthcare"]);

// ---------------------------------------------------------------------------------------------
// P46 — Bengali-script gambling vocabulary.
// ---------------------------------------------------------------------------------------------
// Bengali is the hardest surface in this system and the corpus cannot help: it contains only ASCII
// hostnames, so there is no dry-run that proves a Bengali token safe. The rule adopted here is
// therefore stricter than for Latin — NO bare Bengali noun is ever admitted, only multi-word
// spam collocations:
//
//   বাজি   = bet, but আতশবাজি = FIREWORKS and বাজিতপুর = Bajitpur, a real upazila that appears in the
//            harvest below as "কিশোরগঞ্জ জেলার বাজিতপুর উপজেলার". Bare বাজি fires on both.
//   বেটিং  = betting, and this is the worst one in the file: the harvest below found
//            "ডিবেটিং সোসাইটি" — a school DEBATING society — and "ডায়াবেটিস" (diabetes). Both contain
//            বেটিং. A bare বেটিং token would have accused BD colleges of running a sportsbook because
//            they have a debate club.
//   জুয়া   = gambling. BD news and religious/waz content discusses জুয়া constantly — it is a standard
//            khutbah topic. Admitted only as অনলাইন জুয়া / জুয়ার সাইট / জুয়া খেলুন.
//   ক্যাসিনো = casino. The harvest found "ক্যাসিনো মামলার আসামী ইয়াবাসহ গ্রেফতার" on three separate BD
//            news sites — the 2019 Dhaka casino raids are still in every news archive in the country.
//   লটারি   = lottery. REJECTED entirely, even bound: BD has state-run and NGO lotteries, and ভর্তি
//            লটারি (admission lottery) is how schools nationwide allocate seats. Nothing here is safe.
//
// Every stem therefore carries a (?<![ঀ-৿]) guard so it can only match at the START of a Bengali word,
// which is what actually stops ডিবেটিং, ডায়াবেটিস, আতশবাজি and বাজিতপুর — the collocation requirement
// alone would probably have held, but "probably" is not the standard for this file.
//
// Even so, a bound Bengali hit is worth far less than a Latin brand hit, which is why L55BNSPAM
// requires TWO distinct phrases (or one phrase plus a Latin corroborator) before it is emitted at all.
const B0 = String.raw`(?<![ঀ-৿])`;
const BN_GAMB = String.raw`অনলাইন[\s‌]*${B0}ক্যাসিনো|${B0}ক্যাসিনো[\s‌]*(?:গেম|খেল|সাইট|বোনাস|অ্যাপ|লগইন|রিভিউ)|লাইভ[\s‌]*${B0}ক্যাসিনো|অনলাইন[\s‌]*${B0}বাজি|${B0}বাজি[\s‌]*ধর(?:ুন|বেন|তে|ার|া)|${B0}বাজির[\s‌]*(?:সাইট|অ্যাপ|ওয়েবসাইট)|ক্রিকেট[\s‌]*${B0}বাজি|অনলাইন[\s‌]*${B0}জুয়া|${B0}জুয়া[\s‌]*খেল(?:ুন|তে|ার)|${B0}জুয়ার[\s‌]*(?:সাইট|অ্যাপ|আসর)|${B0}বেটিং[\s‌]*(?:সাইট|অ্যাপ|আইডি|এক্সচেঞ্জ|কোম্পানি)|অনলাইন[\s‌]*${B0}বেটিং|সেরা[\s‌]*${B0}বেটিং|${B0}স্লট[\s‌]*(?:গেম|মেশিন|খেলুন)|${B0}বুকমেকার|টাকা[\s‌]*(?:জিতুন|ইনকাম করুন)[\s‌]*(?:অনলাইন|গেম)|রিয়েল[\s‌]*ক্যাশ[\s‌]*গেম|ডিপোজিট[\s‌]*বোনাস`;
export const BN_GAMB_RE = new RegExp(BN_GAMB, "i");
export const BN_GAMB_G = new RegExp(BN_GAMB, "gi");

// Bengali pharma. EXPORTED FOR REUSE BUT DELIBERATELY NOT SELF-CONFIRMING — see run().
// "যৌন উত্তেজক" and "লিঙ্গ বড় করার ঔষধ" are not spam vocabulary in Bangladesh, they are the ordinary
// product copy of the entire হারবাল / ইউনানী retail sector, which is a large, legal and very online
// BD business category. Firing on it would mean cold-calling a herbal shop to tell it that its own
// catalogue is an injection. So this set only ever corroborates a Latin PHARMA_STRONG hit.
const BN_PHARMA = String.raw`ভায়াগ্রা|কামাগ্রা|সিয়ালিস|সিলডেনাফিল|টাডালাফিল`;
export const BN_PHARMA_RE = new RegExp(BN_PHARMA, "i");

// ---------------------------------------------------------------------------------------------
// P47 — spam families with zero current coverage.
// ---------------------------------------------------------------------------------------------
// All five are multi-word commercial boilerplate, which is what makes them cheap: no single word here
// carries the pattern, so there is no bare-token trap to fall into.
//
// Each family names the thing that nearly went in and did not:
//   essay  — "assignment help online" REJECTED: BD coaching centres and tutoring marketplaces
//            advertise exactly that phrase in good faith.
//   loan   — "instant cash advance" REJECTED: BD NBFIs and mobile-financial services use it for a
//            real regulated product.
//   crypto — "connect wallet" REJECTED outright (P47 flags this itself): the corpus has ewallet.com.bd,
//            sblwallet.com.bd (Sonali Bank), instantwallet.com.bd. It is a button on legitimate BD
//            fintech. Only wallet-PHISHING shapes survive, and they still need corroboration.
//   iptv   — "iptv subscription" and "free iptv" REJECTED: iptv.com.bd, radiantiptv.com.bd, bdiptv.net
//            are real BD ISPs, and IPTV bundling is a normal BD broadband product. Only named piracy
//            brands survive.
const FAM_ESSAY = String.raw`essay writing service|write my essay|buy essay online|order essay online|cheap essay writing|essay writers? (?:for hire|online)|paper writing service|dissertation writing service|thesis writing service|research paper writing service|coursework writing service|custom (?:essay|term paper) writing|do my (?:assignment|homework) for me`;
const FAM_REPLICA = String.raw`replica (?:watch(?:es)?|rolex|handbags?|bags?|jewel(?:le)?ry|designer)|fake rolex|swiss replica|1:1 replica|aaa replica`;
const FAM_LOAN = String.raw`payday loans? online|payday loan lenders?|no credit check loans?|loans? with no credit check|instant payday loan|cash advance loans? online|title loans? online`;
// CRYPTO is SPLIT, because half the original list was ordinary crypto-TUTORIAL vocabulary and the
// layer's own emit rule ("two distinct phrases") could be satisfied entirely out of it. A Bengali
// crypto-explainer blog writes, in one paragraph, "restore your wallet ... import your seed phrase"
// — two distinct phrases, i.e. an automatic L57DRAINER on a clean site. That matters more than a
// normal FP: L57DRAINER's category is "malware", and per this project's own 2026-07-19 post-mortem
// the non-gambling/adult categories route AROUND the AI gate, so it would confirm with no second look.
// The phrases a tutorial never writes are the ones that IMPERSONATE wallet infrastructure. Those are
// HARD, and run() now requires at least one of them before the layer may speak.
const FAM_CRYPTO_HARD = String.raw`wallet drainer|claim (?:your )?airdrop|airdrop claim|metamask (?:validation|sync|support|recovery)|walletconnect (?:validation|sync)|validate (?:your )?wallet|sync (?:your )?wallet`;
const FAM_CRYPTO_SOFT = String.raw`restore (?:your )?wallet|import (?:your )?(?:seed|recovery) phrase|enter (?:your )?(?:seed|recovery|secret) phrase`;
const FAM_CRYPTO = `(?:${FAM_CRYPTO_HARD})|(?:${FAM_CRYPTO_SOFT})`;
const CRYPTO_HARD_RE = new RegExp(FAM_CRYPTO_HARD, "i");
// PIRACY is split for the same class of reason. Bangladeshi Bengali tech and entertainment blogs
// publish "filmyzilla theke movie download korben na" explainers constantly — naming the brands IS
// the article. Brand names therefore never fire alone; an operational phrase or a doorway slug must
// be present, which is CONTRACT rule 6 ("bind to a second spam-only token") applied to a family the
// draft exempted from it.
// `free iptv playlist` and `m3u playlist download` are DELETED, not demoted: the draft rejected
// "iptv subscription" and "free iptv" because iptv.com.bd / radiantiptv.com.bd / bdiptv.net are real
// BD ISPs, then kept two phrases from the same BD broadband-tutorial genre. `iptv reseller panel`
// survives — that one is a piracy business, not a customer-facing product.
const PIR_BRAND = String.raw`123movies|putlocker|fmovies|soap2day|yesmovies|gomovies|movierulz|tamilrockers|filmyzilla|9xmovies|khatrimaza`;
const PIR_OPS = String.raw`watch (?:free )?movies online free|free movie streaming site|iptv reseller panel`;
const FAM_PIRACY = `(?:${PIR_BRAND})|(?:${PIR_OPS})`;
const PIR_OPS_RE = new RegExp(PIR_OPS, "i");
// The essay arm's "two distinct phrases" rule is satisfied by the ordinary homepage of a Dhaka
// academic-services firm, which advertises "thesis writing service" AND "dissertation writing service"
// side by side. Those four -writing-service phrases are what a legitimate BD business says; the mill
// phrases below are what nobody says about a service they actually render. One is now required.
const ESSAY_MILL_RE = new RegExp(String.raw`write my essay|buy essay online|order essay online|cheap essay writing|essay writers? (?:for hire|online)|custom (?:essay|term paper) writing|do my (?:assignment|homework) for me`, "i");

export const FAMILY = {
  essay: new RegExp(FAM_ESSAY, "i"),
  replica: new RegExp(FAM_REPLICA, "i"),
  loan: new RegExp(FAM_LOAN, "i"),
  crypto: new RegExp(FAM_CRYPTO, "i"),
  piracy: new RegExp(FAM_PIRACY, "i"),
};
export const FAMILY_G = {
  essay: new RegExp(FAM_ESSAY, "gi"),
  replica: new RegExp(FAM_REPLICA, "gi"),
  loan: new RegExp(FAM_LOAN, "gi"),
  crypto: new RegExp(FAM_CRYPTO, "gi"),
  piracy: new RegExp(FAM_PIRACY, "gi"),
};
export const ALL_FAMILY = new RegExp(`(?:${FAM_ESSAY})|(?:${FAM_REPLICA})|(?:${FAM_LOAN})|(?:${FAM_PIRACY})`, "i");
// Slug forms of the families that actually generate doorway URLs. Crypto and loan are excluded:
// their injections are body/overlay payloads, not doorway page trees.
const FAM_SLUG = String.raw`essay[-_]?writing[-_]?service|write[-_]?my[-_]?essay|buy[-_]?essay|paper[-_]?writing[-_]?service|dissertation[-_]?writing|replica[-_]?(?:watches|rolex|handbags|bags)|fake[-_]?rolex|swiss[-_]?replica|payday[-_]?loans?|no[-_]?credit[-_]?check[-_]?loans?|123movies|putlocker|fmovies|soap2day|movierulz|filmyzilla|9xmovies|khatrimaza`;
export const FAM_SLUG_RE = new RegExp(FAM_SLUG, "i");

// One union for the other layer modules. Every arm in it is boundary-anchored, so unlike a raw
// keyword list it is safe to run over PLAIN TEXT as well as over slugs — which is what sitemapx.js,
// content.js and obfusc.js actually need when they decode a base64 blob or an HTML comment.
// Generic-casino and pharma are deliberately excluded: both are biz_type-gated above and a caller
// reaching for a one-line union will not remember that.
export const EXTRA_STRONG = new RegExp(
  `(?:${SLUG_BRAND})|(?:${SLUG_CAMPAIGN})|(?:${SLUG_ADULT})|(?:${FAM_ESSAY})|(?:${FAM_REPLICA})|(?:${FAM_LOAN})|(?:${FAM_PIRACY})`, "i");
export const EXTRA_STRONG_G = new RegExp(EXTRA_STRONG.source, "gi");

// ---------------------------------------------------------------------------------------------
// FP_GUARD — the ambiguity that is ALREADY LIVE in signatures.js.
// ---------------------------------------------------------------------------------------------
// GAMB_STRONG contains `\bbahis\b`. bahis.dls.gov.bd is the Bangladesh Animal Health Information
// System and the word BAHIS appears throughout its own pages. Because .gov.bd is a restricted
// institutional TLD, scan.js confirms gambling on it as "hacked victim" WITHOUT spending an AI call
// (scan.js BD_INST_TLD path) — i.e. the single highest-confidence, lowest-scrutiny lead path in the
// system would tell a Bangladeshi government livestock directorate that it is running a casino.
//
// The fix belongs in signatures.js, which this module may not touch. It is exported here so the
// integrator can apply it, and run() applies it to its own signals:
//   a spam verdict must NOT stand when EVERY distinct match is an ambiguous BD-real token.
export const AMBIGUOUS_TOKEN = /^(?:bahis|toto|baji|nagad|slot|slots|casino|betting|poker|jackpot|pin[-\s]?up)$/i;
/** true when a match list is entirely made of tokens that a real BD entity plausibly owns. */
export function allMatchesAmbiguous(list) {
  const a = (Array.isArray(list) ? list : String(list || "").split(";")).map((x) => String(x).trim()).filter(Boolean);
  return a.length > 0 && a.every((x) => AMBIGUOUS_TOKEN.test(x));
}

// ---------------------------------------------------------------------------------------------
// WEIGHTS — Bayesian [P(fires | hacked), P(fires | clean)].
// ---------------------------------------------------------------------------------------------
// MEASURED 2026-07-20 by fetching live homepages, not estimated:
//   hacked  = 236 reachable of a 260-domain spread across confirmed.tsv
//             → L54SLUGSPAM 5 · L55BNSPAM 1 · L56FAMILY 0 · L57DRAINER 0
//   clean   = 780 reachable real BD sites, in three separate control groups:
//             547 from clean-bd.txt + ctrl-bd3k.txt swept with the regexes RAW — no biz_type gate,
//                 no corroboration rule, just "does the pattern ever touch a real BD page" (175 of
//                 them Bengali-heavy, which is the population BN_GAMB actually has to survive)
//             102 from clean-bd.txt through the full module
//             131 BD news/media domains through the full module — the worst case for both the
//                 casino vocabulary and the Bengali vocabulary
//             → 0 hits on every layer and every exported regex. The only two hits anywhere in the
//               control groups were /linebet-casino-offers…/ and /migliori-casino-online-aams…/,
//               both genuine injected doorway posts on sites that are in fact compromised.
//
// The hacked hit rate is low (5/236) BY DESIGN and is not the measure of this module's worth: run()
// can only see hrefs on the homepage, while doorway trees live in the sitemap. The real P45 payload
// is SLUG_SPAM2 itself, exported for sitemapx.js and content.js, which walk those trees.
//
// D below therefore expresses the DIAGNOSTICITY of the evidence, matching the convention already in
// W (scan.js) and links.js, not the raw fire rate. Every clean column is set far above the measured
// zero: 780 samples cannot distinguish 0 from 1-in-260, and an over-confident denominator silently
// manufactures leads (CONTRACT.md rule 4).
export const WEIGHTS = {
  // The site's OWN URL tree contains a gambling/adult brand slug. Strong: nobody accidentally
  // publishes /1xbet-bangladesh-login/ on a college site. Held at 0.012 rather than 0 because the
  // generic-casino arm has real theoretical surface even with the news suppression in place.
  L54SLUGSPAM: [0.80, 0.012],
  // Bengali collocations. Deliberately the weakest layer in the file — it is one bad idiom away from
  // firing on a news article ABOUT gambling, and the emit rule below already demands two distinct
  // phrases before it speaks at all. 0.035 is roughly 25x the measured 0/780; that pessimism is the
  // price of a vocabulary no corpus dry-run can validate.
  L55BNSPAM: [0.55, 0.035],
  // Essay / replica / loan / piracy boilerplate in visible text. Not gambling or adult, so these
  // route around the Gemini gate entirely — which is exactly why the phrase list is multi-word only.
  L56FAMILY: [0.75, 0.020],
  // Wallet-phishing payload. Near-unambiguous once the seed-phrase shape is present, but it fired on
  // NEITHER sample, so this pair is a prior, not a measurement, and is kept modest to say so.
  L57DRAINER: [0.80, 0.020],
};

// L54/L55/L56 are intentionally absent: their evidence IS the spam vocabulary, so the keyword-derived
// category (gambling / pharma / adult) is more accurate than any label pinned here.
// NOTE FOR THE INTEGRATOR: scan.js category() falls back to "gambling" when categoryOf() returns "",
// so an essay-mill or replica injection currently lands in the gambling bucket and inherits the AI
// gate it does not need. A "spam_seo" category would fix that; it is out of this module's scope.
export const CATS = {
  L57DRAINER: "malware",
};

// ---------------------------------------------------------------------------------------------
// Stateful /g regexes are built per call, never shared. scan.js may run several domains concurrently
// inside one isolate, and a module-level /g regex carries lastIndex across those calls — which does
// not crash, it just silently skips matches on whichever domain lost the race.
const RE_HREF_SRC = String.raw`(?:href|src)\s*=\s*["']([^"'#][^"']{0,300})["']`;

function hostOfUrl(u) {
  const m = /^https?:\/\/([^/?#]+)/i.exec(u);
  return m ? m[1].toLowerCase().replace(/^www\./, "") : "";
}

/** Same-registrable URLs found in the already-fetched HTML, path+query only, de-duplicated. */
function ownPaths(html, reg, cap) {
  const out = new Set();
  if (!html) return out;
  const re = new RegExp(RE_HREF_SRC, "gi");
  let m;
  while ((m = re.exec(html)) && out.size < cap) {
    const raw = m[1].trim();
    if (/^(?:mailto|tel|javascript|data):/i.test(raw)) continue;
    let path;
    if (/^https?:\/\//i.test(raw)) {
      const h = hostOfUrl(raw);
      // Off-domain links are links.js's evidence, not ours. Sharing them would double-count the
      // same bytes into two buckets and inflate the posterior.
      if (!h || !(h === reg || h.endsWith("." + reg))) continue;
      path = raw.replace(/^https?:\/\/[^/?#]+/i, "") || "/";
    } else if (raw.startsWith("/")) {
      path = raw;
    } else continue;
    if (path.length > 1) out.add(path.slice(0, 300));
  }
  return out;
}

function distinctOf(text, gre, cap) {
  const seen = new Set();
  if (!text) return [];
  const re = new RegExp(gre.source, "gi");   // fresh object: see the lastIndex note above
  let m;
  while ((m = re.exec(text)) && seen.size < cap) {
    const v = m[0].trim().toLowerCase();
    if (v) seen.add(v);
    if (m.index === re.lastIndex) re.lastIndex++;   // zero-length guard
  }
  return [...seen];
}

export async function run(ctx) {
  const out = [];
  try {
    if (!ctx) return out;
    // Zero fetches, but not zero CPU: up to 400 decodeURIComponent calls plus several passes of a
    // ~4KB alternation over the full visible body. The shards run under the free-plan CPU wall that
    // has 1102'd this engine before, so the module yields the same way content.js does.
    if (typeof ctx.overBudget === "function" && ctx.overBudget()) return out;
    const reg = String(ctx.reg || "").toLowerCase().replace(/^www\./, "");
    const base = ctx.base || ("https://" + reg);
    const html = (ctx.B && ctx.B.text) || "";
    const vis = ctx.visB || "";
    const visG = ctx.visG || "";
    if (!html && !vis) return out;

    const title = (/<title[^>]*>([\s\S]{0,300}?)<\/title>/i.exec(html) || [, ""])[1];
    let biz = "";
    try { biz = ctx.S && ctx.S.bizType ? ctx.S.bizType(reg, title, vis) : ""; } catch { biz = ""; }

    // ---- P45 · L54SLUGSPAM — brand slugs inside the site's OWN URL tree -----------------------
    // 400 hrefs is the whole point: a doorway injection writes dozens of them into one footer or one
    // sitemap-ish index page, so the cap only ever bites on genuinely enormous menus.
    const paths = ownPaths(html, reg, 400);
    const slugHits = [];
    for (const p of paths) {
      const dec = safeDecode(p);
      const m = SLUG_SPAM2.exec(dec) || FAM_SLUG_RE.exec(dec) ||
        (biz === "news" ? null : SLUG_CASINO_GENERIC_RE.exec(dec)) ||
        (PHARMA_SLUG_SAFE_BIZ.has(biz) ? null : SLUG_PHARMA_RE.exec(dec));
      if (m) slugHits.push({ tok: m[0].toLowerCase(), path: dec });
      if (slugHits.length >= 6) break;
    }
    if (slugHits.length && !allMatchesAmbiguous(slugHits.map((h) => h.tok))) {
      const proof = slugHits.slice(0, 3).map((h) => h.path).join("  ");
      out.push({ bucket: "slug-spam", layer: "L54SLUGSPAM", match: proof.slice(0, 200), url: base + slugHits[0].path });
    }

    // ---- P46 · L55BNSPAM — Bengali gambling collocations --------------------------------------
    // Two distinct phrases, or one phrase corroborated by a Latin strong keyword. A single Bengali
    // phrase on its own is exactly the "news article ABOUT gambling" case and is never emitted.
    // A news site is excluded outright: reporting on the casino raids is its job.
    if (biz !== "news") {
      const bnAll = distinctOf(vis + " " + visG, BN_GAMB_G, 6);
      const latin = (() => { try { return ctx.S && ctx.S.ALL_STRONG ? ctx.S.ALL_STRONG.test(vis) : false; } catch { return false; } })();
      if (bnAll.length >= 2 || (bnAll.length === 1 && latin)) {
        out.push({ bucket: "bn-vocab", layer: "L55BNSPAM", match: bnAll.join(" · ").slice(0, 200), url: base + "/" });
      }
    }

    // ---- P47 · L56FAMILY / L57DRAINER ---------------------------------------------------------
    const fam = [];
    for (const k of ["essay", "replica", "loan", "piracy"]) {
      const hits = distinctOf(vis, FAMILY_G[k], 4);
      if (hits.length) fam.push({ k, hits });
    }
    if (fam.length) {
      // One boilerplate phrase is enough for replica/loan — no Bangladeshi business writes "swiss
      // replica" or "no credit check loans" by accident. Essay and piracy are the two families a
      // CLEAN BD site writes in good faith (academic-services firm; Bengali "don't use filmyzilla"
      // explainer), and for both, phrase COUNT does not separate them from a hack — a listicle names
      // three brands and a services firm lists two services. Each needs its own mill/ops marker, or
      // a doorway slug in the site's own URL tree.
      const kinds = new Set(fam.map((f) => f.k));
      let enough = kinds.has("replica") || kinds.has("loan") || FAM_SLUG_RE.test([...paths].join(" "));
      if (!enough && kinds.has("essay")) enough = ESSAY_MILL_RE.test(vis);
      if (!enough && kinds.has("piracy")) enough = PIR_OPS_RE.test(vis);
      if (enough) {
        const proof = fam.map((f) => f.k + ": " + f.hits.join(", ")).join(" | ");
        out.push({ bucket: "family-vocab", layer: "L56FAMILY", match: proof.slice(0, 200), url: base + "/" });
      }
    }

    // Wallet drainer. Two independent conditions, because "claim your airdrop" alone is something a
    // legitimate BD crypto community page writes, and biz_type it/finance is excluded on top —
    // the FP here is a real fintech startup, which is a customer, not a lead.
    if (biz !== "it" && biz !== "finance") {
      const dr = distinctOf(vis + " " + html.slice(0, 60000), FAMILY_G.crypto, 4);
      // At least one wallet-INFRASTRUCTURE-impersonating phrase. Without this, "restore your wallet"
      // + "import your seed phrase" — one paragraph of a Bengali wallet-recovery tutorial — is two
      // distinct phrases and confirms a malware finding with no AI review. See FAM_CRYPTO_HARD.
      const hardDr = dr.some((x) => CRYPTO_HARD_RE.test(x));
      const phrase = /\b(?:seed|recovery|secret) phrase\b|\bprivate key\b/i.test(vis);
      if (hardDr && (dr.length >= 2 || phrase)) {
        out.push({ bucket: "family-vocab", layer: "L57DRAINER", match: dr.join(" · ").slice(0, 200), url: base + "/" });
      }
    }
  } catch {
    return out;   // CONTRACT rule 1: degrade to whatever we already have, never throw.
  }
  return out;
}

function safeDecode(s) {
  try { return decodeURIComponent(s); } catch { return s; }
}
