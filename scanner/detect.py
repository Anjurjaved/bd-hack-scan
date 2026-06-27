"""
detect.py — Stage-1 HTTP detection, a faithful async port of the proven
website-hack-audit `scan_one.sh` (10 layers + false-positive discipline).

For each domain it fetches the homepage under several identities and looks for
injected gambling / pharma / adult / defacement / cloaking signals. NO LLM here —
this is the cheap, high-recall pre-filter. Only flagged domains go to Stage-2.

Layers:
  L1  visible keywords (normal browser)
  L2  UA cloaking      (extra spam shown only to Googlebot)
  L3  referer cloaking (extra spam shown only to Google referrals)
  L4  mobile redirect  (off-domain redirect for mobile UA)
  L5  WP search-density(/?s=casino ... injected result flood)   [escalated]
  L6  sitemap doorway  (gambling URLs in sitemap.xml)           [escalated]
  L7  malicious JS host
  L8  gambling iframe/script src
  L9  off-domain redirect (desktop)
  L10 foreign-script title / defacement string
"""
import re
import asyncio
import httpx

UA_BROWSER = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
UA_GOOGLE = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
UA_MOBILE = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
REF_GOOGLE = "https://www.google.com/"

# ---- keyword sets (ported verbatim from scan_one.sh; \b guards kill the classic FPs) ----
GAMB = (r"casino|kasino|kasyno|cazino|cassino|casin[oò]|kazino|казино|赌场|博彩|娱乐城|"
        r"\bjudi\b|togel|toto (macau|togel|4d|online|gelap|slot|hk)|gacor|maxwin|sbobet|bocoran|slot online|slot gacor|situs slot|"
        r"judi bola|taruhan|bandar togel|\bbahis\b|apuestas deportivas|apostas esportivas|tragamonedas|tragaperras|scommesse|"
        r"1xbet|melbet|betwinner|betvisa|\bpin-?up\b|parimatch|mostbet|4rabet|baji ?(live|casino|999|bet|bd)|glory casino|"
        r"marvelbet|krikya|jeetbuzz|nagad88|mahjong ways|gates of olympus|pragmatic play|pg ?soft|joker123|freispiele|"
        r"caça-níqueis|\brulet\b|\bbahsegel\b|online casino|slot88|slot777|daftar slot|link slot|bettilt")
PHARMA = r"\bviagra\b|\bcialis\b|kamagra|sildenafil|tadalafil|vardenafil|\blevitra\b|lovegra|erectile dysfunction|\bed pills\b|伟哥"
ADULT = r"\bporn\b|\bxxx\b|\bescort\b|\beskorte\b|\bbokep\b|\bhentai\b|sex video|sex tube|av女优|福利视频|情色片"
DEFACE = r"hacked by|defaced by|h4cked|\bhak3d\b|pwned by|owned by .{0,20}team|greetz to|defacer\.id|gantengers|\bg4nteng\b"
BADHOST = r"defacer\.id|cdn-fileserver\.com|jso\.[a-z0-9.]+\.id|l\.cdn-fileserver"

# strong, near-zero-FP gambling tokens (the academic "no observable false positives" set)
STRONG = r"gacor|maxwin|togel|slot gacor|judi bola|sbobet|situs slot|bocoran|joker123|1xbet|melbet|betvisa|parimatch|mostbet|glory casino|marvelbet|krikya|jeetbuzz|nagad88|bettilt|baji ?(live|999|bet)"

RE_GAMB = re.compile(GAMB, re.I)
RE_PHARMA = re.compile(PHARMA, re.I)
RE_ADULT = re.compile(ADULT, re.I)
RE_DEFACE = re.compile(DEFACE, re.I)
RE_BADHOST = re.compile(BADHOST, re.I)
RE_STRONG = re.compile(STRONG, re.I)
RE_ALL = re.compile("(" + GAMB + ")|(" + PHARMA + ")|(" + ADULT + ")", re.I)

RE_IFRAME = re.compile(r'<(iframe|script)[^>]+src="https?://[^"]*(casino|slot|judi|togel|xbet|melbet|bet[0-9])[^"]*"', re.I)
RE_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
RE_FOREIGN = re.compile(r"[一-鿿぀-ヿ฀-๿Ѐ-ӿ가-힣]")
RE_SITEMAP_SPAM = re.compile(r"slot-|/slot/|casino|judi|togel|gacor|maxwin|sbobet|bocoran|rtp-slot|pragmatic|joker123|tragam|apuesta|bahis|eskort|escort|viagra|cialis|kamagra", re.I)


def strip_html(html: str) -> str:
    html = re.sub(r"<(script|style|noscript)\b.*?</\1>", " ", html, flags=re.I | re.S)
    html = re.sub(r"<[^>]+>", " ", html)
    html = re.sub(r"&[a-z#0-9]+;", " ", html, flags=re.I)
    return re.sub(r"\s+", " ", html)


def hits(text: str, rx: re.Pattern) -> list:
    return sorted({m.group(0).lower() for m in rx.finditer(text)})


def host_of(url: str) -> str:
    return re.sub(r":.*$", "", re.sub(r"/.*$", "", re.sub(r"^[a-z]+://", "", url or "", flags=re.I), flags=re.S))


async def fetch(client: httpx.AsyncClient, ua: str, referer, url: str):
    """Return (status:int, final_url:str, text:str). Falls back https->http on hard failure."""
    headers = {"user-agent": ua}
    if referer:
        headers["referer"] = referer
    for u in (url, url.replace("https://", "http://", 1)):
        try:
            r = await client.get(u, headers=headers, follow_redirects=True, timeout=18.0)
            return r.status_code, str(r.url), (r.text or "")
        except Exception:
            continue
    return 0, "", ""


async def scan_domain(client: httpx.AsyncClient, domain: str) -> dict:
    """Run all layers. Returns a result dict; result['flagged'] tells you to escalate to Stage-2."""
    d = domain.strip().lower()
    res = {"domain": d, "http_status": 0, "layers": [], "score": 0, "category": "", "proof": "", "proof_url": "", "title": "", "error": None}
    base = "https://" + d

    sb, urlB, tB = await fetch(client, UA_BROWSER, None, base)
    if sb == 0:
        res["error"] = "unreachable"
        return res
    res["http_status"] = sb
    # parallel identity fetches (cloaking diff)
    (sg, urlG, tG), (sr, urlR, tR), (sm, urlM, tM) = await asyncio.gather(
        fetch(client, UA_GOOGLE, REF_GOOGLE, base),
        fetch(client, UA_BROWSER, REF_GOOGLE, base),
        fetch(client, UA_MOBILE, REF_GOOGLE, base),
    )

    visB, visG, visR = strip_html(tB), strip_html(tG), strip_html(tR)
    layers, cats = [], set()

    # L1 — visible keywords (browser)
    kwB = hits(visB, RE_ALL)
    g1 = hits(visB, RE_GAMB); p1 = hits(visB, RE_PHARMA); a1 = hits(visB, RE_ADULT)
    if kwB:
        layers.append("L1KW:" + ";".join(kwB)[:160])
        if g1: cats.add("gambling")
        if p1: cats.add("pharma")
        if a1: cats.add("adult")
        if not res["proof"]:
            res["proof"] = (";".join(kwB))[:300]; res["proof_url"] = urlB

    # L2 — UA cloak: keywords for Googlebot that the browser did NOT see
    kwG = set(hits(visG, RE_ALL))
    extraG = sorted(kwG - set(kwB))
    if extraG:
        layers.append("L2CLOAK:" + ";".join(extraG)[:160]); cats.add("cloak")
        res["proof"] = ("googlebot-only: " + ";".join(extraG))[:300]; res["proof_url"] = urlG

    # L3 — referer cloak
    kwR = set(hits(visR, RE_ALL))
    extraR = sorted(kwR - set(kwB))
    if extraR:
        layers.append("L3REFCLOAK:" + ";".join(extraR)[:160]); cats.add("cloak")

    # L4 — mobile off-domain redirect
    mh = host_of(urlM)
    if mh and d not in mh:
        layers.append("L4MOBILE:" + urlM[:120]); cats.add("redirect")

    # L7 — malicious JS host
    bad = hits(tB + tG, RE_BADHOST)
    if bad:
        layers.append("L7BADJS:" + ";".join(bad)[:120]); cats.add("malware")

    # L8 — gambling iframe/script src
    ifr = [m.group(0) for m in RE_IFRAME.finditer(tB + tG)][:2]
    if ifr:
        layers.append("L8IFRAME:" + ";".join(ifr)[:160]); cats.add("gambling")

    # L9 — desktop off-domain redirect
    bh = host_of(urlB)
    if bh and d not in bh:
        layers.append("L9REDIR:" + urlB[:120]); cats.add("redirect")

    # L10 — title foreign-script / defacement
    mt = RE_TITLE.search(tB) or RE_TITLE.search(tG)
    title = re.sub(r"\s+", " ", mt.group(1)).strip()[:110] if mt else ""
    res["title"] = title
    if title and RE_FOREIGN.search(title):
        layers.append("L10LANG:" + title[:110]); cats.add("foreign_lang")
    dfc = hits(tB + tG, RE_DEFACE)
    if dfc:
        layers.append("L10DEFACE:" + ";".join(dfc)[:120]); cats.add("deface")

    # ---- escalation: only run the expensive L5/L6 if something already smells ----
    weak = bool(layers)
    if weak:
        # L5 — WordPress search-density doorway
        best, durl = 0, ""
        for q in ("casino", "bahis", "apuestas", "judi"):
            s5, u5, t5 = await fetch(client, UA_GOOGLE, None, base + "/?s=" + q)
            n = len(RE_ALL.findall(strip_html(t5)))
            if n > best:
                best = n
                for m in re.finditer(r"https?://[a-z0-9.\-]*" + re.escape(d) + r"/[a-z0-9%][^\"' <>]+", t5, re.I):
                    if RE_SITEMAP_SPAM.search(m.group(0)):
                        durl = m.group(0); break
        if best >= 12:
            layers.append("L5DENSITY:%d:%s" % (best, durl[:120])); cats.add("gambling")
            if durl: res["proof_url"] = durl

        # L6 — sitemap doorway
        s6, u6, t6 = await fetch(client, UA_GOOGLE, None, base + "/sitemap.xml")
        spam_urls = []
        for m in re.finditer(r"https?://[^<\"' ]+", t6):
            u = m.group(0)
            if d in u and not u.lower().endswith(".xml") and RE_SITEMAP_SPAM.search(u):
                spam_urls.append(u)
                if len(spam_urls) >= 2:
                    break
        if spam_urls:
            layers.append("L6SITEMAP:" + ",".join(spam_urls)[:200]); cats.add("gambling")
            if not res["proof_url"]: res["proof_url"] = spam_urls[0]

    res["layers"] = layers

    # ---- Stage-1 flag decision (precise enough to keep Gemini quota sane) ----
    strong_signals = any(x.startswith(("L2", "L3", "L4", "L5", "L6", "L7", "L8", "L9", "L10DEFACE")) for x in layers)
    strong_kw = bool(RE_STRONG.search(visB) or (extraG and RE_STRONG.search(" ".join(extraG))))
    multi_kw = (len(g1) + len(p1) + len(a1)) >= 2
    res["category"] = _primary_category(cats)
    res["score"] = len(layers) + (2 if strong_signals else 0) + (2 if strong_kw else 0)
    res["flagged"] = bool(strong_signals or strong_kw or multi_kw)
    # auto_confirm: layers whose proof is conclusive on its own (no human/LLM needed).
    # Cloaking, gambling iframe, sitemap doorway, search-density flood, defacement, malware host.
    res["auto_confirm"] = any(x.startswith((
        "L2CLOAK", "L3REFCLOAK", "L5DENSITY", "L6SITEMAP", "L7BADJS", "L8IFRAME", "L10DEFACE"
    )) for x in layers)
    res["cats"] = sorted(cats)
    # keep a trimmed evidence excerpt for Stage-2
    res["excerpt"] = (visG if extraG else visB)[:4000]
    return res


def _primary_category(cats: set) -> str:
    for c in ("gambling", "malware", "deface", "pharma", "adult", "cloak", "redirect", "foreign_lang"):
        if c in cats:
            return c
    return ""
