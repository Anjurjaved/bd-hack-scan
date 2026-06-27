# -*- coding: utf-8 -*-
"""
signatures.py — the keyword library, ported verbatim from the website-hack-audit
skill's lib.sh (ONE source of truth). Two precision tiers per category:
  STRONG = unambiguous spam (compounds, brands, foreign-script) — low false-positive.
  WEAK   = generic ambiguous English (casino/poker/betting) — needs >=2 buckets + verbatim.
Matching is case-insensitive over decoded (utf-8) text so CJK/Thai/Cyrillic/Korean
literals (赌场 / казино / 먹튀 / คาสิโน) match directly.
"""
import re

RX_GAMB_STRONG = (r'kasino|kasyno|kasyna|cazino|cassino|casinò|kazino|казино|ставки на спорт|赌场|赌博|博彩|网赌|娱乐城|百家乐|太阳城|菠菜|六合彩|彩票|'
    r'카지노|바카라|먹튀|토토사이트|토토|슬롯|คาสิโน|บาคาร่า|สล็อต|เว็บพนัน|แทงบอล|カジノ|オンラインカジノ|パチンコ|ブックメーカー|'
    r'\bjudi\b|judi online|judi bola|situs judi|situs slot|situs toto|slot online|slot gacor|slot-gacor|slot88|slot777|slot deposit|mpo slot|qq ?slot|pkv games|\bpkv\b|'
    r'togel|toto macau|toto hk|toto sgp|toto sdy|toto 4d|bandar togel|bandar judi|bandar bola|\bgacor\b|maxwin|rtp slot|rtp live|sbobet|bocoran|taruhan|link alternatif|'
    r'deposit pulsa|bonus new member|scatter hitam|daftar slot|link slot|sabung ayam|\bsabong\b|mahjong ways|gates of olympus|pragmatic play|pg ?soft|joker123|918kiss|'
    r'pussy888|mega888|maxbet|\bbahis\b|bahsegel|bahis siteleri|bahis giriş|casino siteleri|\bbettilt\b|apuestas deportivas|apostas esportivas|tragamonedas|tragaperras|'
    r'caça-níqueis|scommesse|nhà cái|nha cai|nổ hũ|\bno hu\b|đá gà|\bda ga\b|cá cược|\bca cuoc\b|सट्टा|कैसीनो|जुआ|1xbet|melbet|betwinner|betvisa|\bpin-?up\b|parimatch|'
    r'mostbet|4rabet|babu ?88|baji ?(live|88|999|bet|bd)|bajilive|krikya|jeetbuzz|jeetwin|jaya9|nagad88|glory casino|marvelbet|mcw casino|crickex|linebet|9wickets|'
    r'rajabets|bet365|betobet|vavada|1win|bbrbet')
RX_GAMB_WEAK = r'\bcasino\b|\bpoker\b|\bbetting\b|\bslots\b|gambling|jackpot|\bbaccarat\b|\broulette\b|sportsbook|wagering|sweepstakes|\bbet now\b'

RX_PHARMA_STRONG = r'kamagra|sildenafil|tadalafil|vardenafil|lovegra|\bviagra\b|\bcialis\b|\blevitra\b|伟哥|comprar viagra|generic viagra|buy viagra|cheap cialis|farmacia online'
RX_PHARMA_WEAK = r'erectile dysfunction|\bed pills\b|penis enlargement'

RX_ADULT_STRONG = r'\bbokep\b|\bhentai\b|av女优|福利视频|情色片|秘密福利视频|\bporn\b|pornhub|xvideos|\bxnxx\b|\bsikiş\b|\bsikis\b'
RX_ADULT_WEAK = r'\bescort\b|\bxxx\b|sex video|sex tube|escort service'

RX_DEFACE = r'hacked by|defaced by|h4cked|\bhak3d\b|pwned by|owned by .{0,20}team|greetz to|defacer\.id|gantengers|\bg4nteng\b|was here by|\bmr\.?[a-z0-9]+ team\b'

# L14CAMPAIGN is a HARD auto-confirm, so MALJS must contain ONLY near-zero-false-positive
# malware infrastructure / campaign markers. Benign or dual-use patterns were REMOVED
# (2026-06-27) because they HARD-confirmed clean sites: `document.currentScript.remove`
# is a routine script-self-cleanup used by Lovable/analytics/many frameworks, and a bare
# `eval(atob(` / `eval(unescape(` appears in legit minified code. Real multi-signal
# obfuscation is still caught by detect.py's L14OBFUS (score>=4, NOT hard).
RX_MALJS = r'defacer\.id|cdn-fileserver\.com|l\.cdn-fileserver|jso\.[a-z0-9.]+\.id|if\(ndsw|[;{ ]ndsw[ =.:]|\bndsx\b|\bndsj\b|COOKIE_ANNOT'

RX_SHELL = r'base64_decode|gzinflate|str_rot13|FilesMan|c99shell|\bb374k\b|WSO [0-9]|preg_replace\(.*/e|\$_(POST|GET|REQUEST|COOKIE)\['

RX_WAF = (r'Just a moment\.\.\.|Checking your browser before|challenges\.cloudflare\.com|cf-browser-verification|_cf_chl_opt|Verifying you are human|'
    r'Enable JavaScript and cookies to continue|sucuri_cloudproxy|Sucuri WebSite Firewall|Incapsula incident ID|ddos-guard|StackPath')

RX_JUNKTLD = r'\.(ru|cn|tk|ml|ga|cf|gq|top|xyz|icu|club|live|cyou|sbs|online|shop|fun|monster|click|rest|quest|bet|casino|vip|cc|buzz|work|men|loan)([/:?#]|$)'

RX_SLUG_SPAM = (r'situs|\bjudi\b|togel|\bgacor\b|maxwin|sbobet|\bpkv\b|slot-?(gacor|online|88|777|deposit)|sabung-?ayam|bahis(siteleri|giris)?|918kiss|pussy888|mega888|'
    r'mahjong-?ways|pragmatic-?play|joker123|toto-?(macau|hk|sgp|4d|sdy)')

ALL_STRONG = "(?:%s)|(?:%s)|(?:%s)" % (RX_GAMB_STRONG, RX_PHARMA_STRONG, RX_ADULT_STRONG)
ALL_WEAK = "(?:%s)|(?:%s)|(?:%s)" % (RX_GAMB_WEAK, RX_PHARMA_WEAK, RX_ADULT_WEAK)

# compiled
GAMB_STRONG = re.compile(RX_GAMB_STRONG, re.I)
GAMB_WEAK = re.compile(RX_GAMB_WEAK, re.I)
PHARMA_STRONG = re.compile(RX_PHARMA_STRONG, re.I)
PHARMA_WEAK = re.compile(RX_PHARMA_WEAK, re.I)
ADULT_STRONG = re.compile(RX_ADULT_STRONG, re.I)
ADULT_WEAK = re.compile(RX_ADULT_WEAK, re.I)
DEFACE = re.compile(RX_DEFACE, re.I)
MALJS = re.compile(RX_MALJS, re.I)
SHELL = re.compile(RX_SHELL, re.I)
WAF = re.compile(RX_WAF, re.I)
JUNKTLD = re.compile(RX_JUNKTLD, re.I)
SLUG_SPAM = re.compile(RX_SLUG_SPAM, re.I)
C_ALL_STRONG = re.compile(ALL_STRONG, re.I)
C_ALL_WEAK = re.compile(ALL_WEAK, re.I)
FOREIGN = re.compile(r'[぀-ヿ㐀-鿿Ѐ-ӿ฀-๿가-힣]')


def category_of(text):
    """Best-guess spam category for a matched string (for the dashboard breakdown)."""
    if GAMB_STRONG.search(text) or GAMB_WEAK.search(text):
        return "gambling"
    if PHARMA_STRONG.search(text) or PHARMA_WEAK.search(text):
        return "pharma"
    if ADULT_STRONG.search(text) or ADULT_WEAK.search(text):
        return "adult"
    return ""
