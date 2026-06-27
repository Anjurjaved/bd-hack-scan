// signatures.js — JS port of the Python scanner's signature library (signatures.py + classify.py).
// ONE source of truth for the Cloudflare-Worker scanner. STRONG = unambiguous spam,
// WEAK = generic English (needs corroboration). Case-insensitive over decoded text.

const GAMB_STRONG = String.raw`kasino|kasyno|kasyna|cazino|cassino|casin[oò]|kazino|казино|ставки на спорт|赌场|赌博|博彩|网赌|娱乐城|百家乐|太阳城|菠菜|六合彩|彩票|카지노|바카라|먹튀|토토사이트|토토|슬롯|คาสิโน|บาคาร่า|สล็อต|เว็บพนัน|แทงบอล|カジノ|オンラインカジノ|パチンコ|ブックメーカー|\bjudi\b|judi online|judi bola|situs judi|situs slot|situs toto|slot online|slot gacor|slot-gacor|slot88|slot777|slot deposit|mpo slot|qq ?slot|pkv games|\bpkv\b|togel|toto macau|toto hk|toto sgp|toto sdy|toto 4d|bandar togel|bandar judi|bandar bola|\bgacor\b|maxwin|rtp slot|rtp live|sbobet|bocoran|taruhan|link alternatif|deposit pulsa|bonus new member|scatter hitam|daftar slot|link slot|sabung ayam|\bsabong\b|mahjong ways|gates of olympus|pragmatic play|pg ?soft|joker123|918kiss|pussy888|mega888|maxbet|\bbahis\b|bahsegel|bahis siteleri|bahis giriş|casino siteleri|\bbettilt\b|apuestas deportivas|apostas esportivas|tragamonedas|tragaperras|caça-níqueis|scommesse|nhà cái|nha cai|nổ hũ|\bno hu\b|đá gà|\bda ga\b|cá cược|\bca cuoc\b|सट्टा|कैसीनो|जुआ|1xbet|melbet|betwinner|betvisa|\bpin-?up\b|parimatch|mostbet|4rabet|babu ?88|baji ?(live|88|999|bet|bd)|bajilive|krikya|jeetbuzz|jeetwin|jaya9|nagad88|glory casino|marvelbet|mcw casino|crickex|linebet|9wickets|rajabets|bet365|betobet|vavada|1win|bbrbet`;
const GAMB_WEAK = String.raw`\bcasino\b|\bpoker\b|\bbetting\b|\bslots\b|gambling|jackpot|\bbaccarat\b|\broulette\b|sportsbook|wagering|sweepstakes|\bbet now\b`;
const PHARMA_STRONG = String.raw`kamagra|sildenafil|tadalafil|vardenafil|lovegra|\bviagra\b|\bcialis\b|\blevitra\b|伟哥|comprar viagra|generic viagra|buy viagra|cheap cialis|farmacia online`;
const PHARMA_WEAK = String.raw`erectile dysfunction|\bed pills\b|penis enlargement`;
const ADULT_STRONG = String.raw`\bbokep\b|\bhentai\b|av女优|福利视频|情色片|\bporn\b|pornhub|xvideos|\bxnxx\b|\bsikiş\b|\bsikis\b`;
const ADULT_WEAK = String.raw`\bescort\b|\bxxx\b|sex video|sex tube|escort service`;

export const RE = {
  GAMB_STRONG: new RegExp(GAMB_STRONG, "i"),
  GAMB_WEAK: new RegExp(GAMB_WEAK, "i"),
  PHARMA_STRONG: new RegExp(PHARMA_STRONG, "i"),
  ADULT_STRONG: new RegExp(ADULT_STRONG, "i"),
  DEFACE: /hacked by|defaced by|h4cked|\bhak3d\b|pwned by|owned by .{0,20}team|greetz to|defacer\.id|gantengers|was here by/i,
  // L14CAMPAIGN — ONLY near-zero-FP malware infra/campaign markers (benign currentScript.remove
  // + bare eval() removed; those false-confirmed clean sites like proshikkhon.com).
  MALJS: /defacer\.id|cdn-fileserver\.com|l\.cdn-fileserver|jso\.[a-z0-9.]+\.id|if\(ndsw|[;{ ]ndsw[ =.:]|\bndsx\b|\bndsj\b|COOKIE_ANNOT/i,
  WAF: /Just a moment\.\.\.|Checking your browser before|challenges\.cloudflare\.com|cf-browser-verification|_cf_chl_opt|Verifying you are human|Enable JavaScript and cookies to continue|sucuri_cloudproxy|Incapsula incident ID|ddos-guard/i,
  JUNKTLD: /\.(ru|cn|tk|ml|ga|cf|gq|top|xyz|icu|club|cyou|sbs|monster|men|loan)([/:?#]|$)/i,
  SLUG_SPAM: /situs|\bjudi\b|togel|\bgacor\b|maxwin|sbobet|\bpkv\b|slot-?(gacor|online|88|777|deposit)|sabung-?ayam|918kiss|pussy888|mega888|mahjong-?ways|pragmatic-?play|joker123|toto-?(macau|hk|sgp|4d|sdy)/i,
  FOREIGN: /[぀-ヿ㐀-鿿Ѐ-ӿ฀-๿가-힣]/,
  // classify: gambling/adult brand IN the registrable domain (genuine spam site, exclude)
  SPAMMY_DOMAIN: /casino|cassino|kasino|kasyno|kazino|cazino|slot|togel|toto|judi|gacor|maxwin|sbobet|bocoran|1xbet|melbet|betwinner|mostbet|parimatch|4rabet|jeetbuzz|jeetwin|bajilive|baji999|betvisa|bettilt|glorycasino|marvelbet|crickex|linebet|pussy888|mega888|joker123|918kiss|bandartogel|pornhub|xvideos|xnxx|sexcam/i,
  SPAMMY_TLD: /\.(bet|casino|poker|porn|sex|xxx|adult)$/i,
  BD_PHONE: /(?:\+?880|\b0)1[3-9]\d{8}\b/,
  BENGALI: /[ঀ-৿]/g,
};

// global (g+i) versions for distinct-match enumeration
export const REG = {
  GAMB_STRONG: new RegExp(GAMB_STRONG, "gi"),
  GAMB_WEAK: new RegExp(GAMB_WEAK, "gi"),
  ALL_STRONG: new RegExp(`(?:${GAMB_STRONG})|(?:${PHARMA_STRONG})|(?:${ADULT_STRONG})`, "gi"),
  ALL_WEAK: new RegExp(`(?:${GAMB_WEAK})|(?:${PHARMA_WEAK})|(?:${ADULT_WEAK})`, "gi"),
};
export const ALL_STRONG = new RegExp(`(?:${GAMB_STRONG})|(?:${PHARMA_STRONG})|(?:${ADULT_STRONG})`, "i");

export function categoryOf(text) {
  if (RE.GAMB_STRONG.test(text) || RE.GAMB_WEAK.test(text)) return "gambling";
  if (RE.PHARMA_STRONG.test(text)) return "pharma";
  if (RE.ADULT_STRONG.test(text)) return "adult";
  return "";
}

export function domainSpammy(reg) {
  return RE.SPAMMY_DOMAIN.test(reg || "") || RE.SPAMMY_TLD.test(reg || "");
}

export function bdSignal(reg, body) {
  if ((reg || "").endsWith(".bd")) return true;
  body = body || "";
  if (RE.BD_PHONE.test(body)) return true;
  const m = body.match(RE.BENGALI);
  return !!(m && m.length >= 15);
}

// 16-category business taxonomy (domain weight 5 / title 3 / body 1)
const CATS = [
  ["healthcare", /\b(hospital|clinic|medical|healthcare|health|diagnostic|dental|dentist|ortho|cardiac|surgeon|doctor|physiotherapy|laborator|pathology|maternity|homeo|nursing home|gyna?e)\b|হাসপাতাল|ক্লিনিক|চিকিৎসা|ডায়াগনস্টিক|ডেন্টাল|স্বাস্থ্য/i],
  ["education", /\b(school|college|university|institute|academy|madrasah?|coaching|kindergarten|polytechnic|tutorial|education|e-learning|admission|syllabus|scholarship)\b|স্কুল|কলেজ|বিশ্ববিদ্যালয়|মাদ্রাসা|কোচিং|শিক্ষা|একাডেমি/i],
  ["ecommerce", /\b(shop|store|mart|bazar|bazaar|online shopping|checkout|deals|order now|free delivery|cash on delivery|wholesale|retail|gadget|fashion|lifestyle)\b|দোকান|কেনাকাটা|অনলাইন শপ|বাজার|অর্ডার|ডেলিভারি|পাইকারি/i],
  ["garments", /\b(garments|textile|apparel|knit|knitwear|woven|sweater|denim|fabric|spinning|dyeing|rmg|buying house|mills|industries|manufacturer)\b|গার্মেন্টস|টেক্সটাইল|পোশাক|কারখানা|শিল্প/i],
  ["realestate", /\b(real ?estate|property|properties|developers?|apartment|flat|housing|plot|builders|construction|infrastructure|holdings)\b|রিয়েল এস্টেট|আবাসন|ফ্ল্যাট|প্লট|জমি|নির্মাণ/i],
  ["food", /\b(restaurant|cafe|kitchen|biryani|biriyani|kabab|kebab|fast food|catering|bakery|sweets|hotel|resort|motel|guest house|banquet|buffet|cuisine)\b|রেস্টুরেন্ট|খাবার|বিরিয়ানি|বেকারি|হোটেল|রিসোর্ট/i],
  ["finance", /\b(bank|banking|finance|financial|insurance|micro(?:finance|credit)|nbfi|leasing|investment|capital|securities|brokerage|mutual fund|remittance)\b|ব্যাংক|অর্থায়ন|বীমা|ঋণ|বিনিয়োগ/i],
  ["it", /\b(software|technolog|web development|app development|digital agency|saas|cloud|hosting|erp|cyber|fintech|developers?|solutions|systems)\b|সফটওয়্যার|প্রযুক্তি|ওয়েব|অ্যাপ|ডিজিটাল/i],
  ["ngo", /\b(ngo|foundation|charity|charitable|trust|welfare|relief|humanitarian|non-?profit|orphanage|zakat|samit[iy])\b|ফাউন্ডেশন|কল্যাণ|সমিতি|সংস্থা|ট্রাস্ট/i],
  ["travel", /\b(travels?|tours?|tourism|holiday|air ticket|ticketing|visa|hajj|umrah|pilgrimage|tour operator|iata|manpower)\b|ট্রাভেল|ভ্রমণ|পর্যটন|হজ|ওমরাহ|ভিসা/i],
  ["news", /\b(news|news24|daily|bulletin|times|tribune|press|media|magazine|journal|television|channel|broadcast|breaking news|editorial)\b|সংবাদ|খবর|দৈনিক|পত্রিকা|মিডিয়া|চ্যানেল/i],
  ["government", /\b(government|govt|ministry|directorate|municipality|city corporation|union parishad|upazila|commission|authority|bureau)\b|সরকার|মন্ত্রণালয়|অধিদপ্তর|পৌরসভা/i],
  ["agro", /\b(agro|agricultur|farms?|nursery|seeds?|fertilizer|pesticide|poultry|dairy|fisheries|hatchery|livestock|shrimp)\b|কৃষি|এগ্রো|খামার|বীজ|পোল্ট্রি|মৎস্য/i],
  ["pharma", /\b(pharmaceuticals?|pharma|pharmacy|medicine|drugs?|laboratories|formulation|gmp|vaccine)\b|ফার্মা|ঔষধ|ওষুধ|ফার্মেসি/i],
  ["automobile", /\b(automobiles?|motors|vehicles?|motorcycle|truck|transport|logistics|courier|rent-?a-?car|spare parts|garage|dealership|automotive)\b|অটোমোবাইল|মোটরস|গাড়ি|পরিবহন/i],
  ["professional", /\b(consult(?:ing|ancy|ants)?|law firm|advocate|chambers|legal|audit|chartered accountant|advisory|marketing|advertising|branding|architects|interior|recruitment|traders?|import|export|enterprise|corporation|group)\b|কনসালট্যান্ট|অডিট/i],
];
const PRIORITY = ["government", "education", "ngo", "finance", "pharma", "healthcare", "news", "travel", "garments", "agro", "automobile", "realestate", "food", "ecommerce", "it", "professional"];

function countMatches(rx, s) {
  if (!s) return 0;
  const m = s.match(new RegExp(rx.source, "gi"));
  return m ? m.length : 0;
}

export function bizType(reg, title, body) {
  reg = (reg || "").toLowerCase();
  if (reg.endsWith(".gov.bd") || reg.endsWith(".mil.bd")) return "government";
  if (reg.endsWith(".edu.bd") || reg.endsWith(".ac.bd")) return "education";
  title = (title || "").toLowerCase();
  body = (body || "").slice(0, 2500);
  const scores = {};
  for (const [name, rx] of CATS) {
    const s = countMatches(rx, reg) * 5 + countMatches(rx, title) * 3 + countMatches(rx, body) * 1;
    if (s) scores[name] = s;
  }
  const keys = Object.keys(scores);
  if (!keys.length) return "general-business";
  const best = Math.max(...keys.map((k) => scores[k]));
  if (best < 2) return "general-business";
  const winners = keys.filter((k) => scores[k] === best);
  if (winners.length > 1) {
    for (const p of PRIORITY) if (winners.includes(p)) return p;
  }
  return winners[0];
}
