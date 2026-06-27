# -*- coding: utf-8 -*-
"""
detect.py — Stage-1 multi-layer HTTP detection, an async port of the proven
website-hack-audit v2 scanner (scan_one.sh + rest_enum/doorway/hidden_links).

It only EMITS signals (no verdict). score.py fuses them with a Bayesian log-odds
model into CONFIRM_CANDIDATE / SUSPECT / CLEAN.

Main-pass layers ported:
  L18 WAF-challenge · L1 visible keywords (strong/weak) · L2 UA-cloak · L3 referer-cloak
  L4 mobile-redirect · L9 browser-redirect · L10 title-lang / L10 defacement
  L14 malware-JS campaign + obfuscation · L8 gambling iframe · L17 hidden-link CSS
  L11REST WordPress REST enumeration · L20SCRIPT foreign-script posts · L20MASS big post count
  L11SITEMAP sitemap doorway · L20SHAPE random-dir/gibberish farm · L20RELAY off-domain canonical
  L16FEED RSS-injected titles · L16HDR header redirect · L5 WP-search density
(Deep/intrusive layers L12 translate.goog, L13 inner-crawl, L15 DNSBL, L19 shell-probe,
 L15CT are intentionally omitted from the mass cloud pass — CT is harvested separately.)
"""
import re
import html
import asyncio
import httpx
from urllib.parse import urlparse
import signatures as S
import classify

UA_BR = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
UA_GB = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
UA_IPH = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
REF_G = "https://www.google.com/"

RE_TAGSTRIP = re.compile(r"<(script|style|noscript|template)\b.*?</\1>", re.I | re.S)
RE_TAGS = re.compile(r"<[^>]+>")
RE_ENT = re.compile(r"&[a-z#0-9]+;", re.I)
RE_WS = re.compile(r"\s+")
RE_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
RE_IFRAME = re.compile(r'<(iframe|script)[^>]+src="https?://[^"]*(casino|slot|judi|togel|xbet|melbet|bet[0-9]|gacor|sbobet)[^"]*"', re.I)
RE_IFRAME_URL = re.compile(r'https?://[^"]+', re.I)
RE_RELAY = re.compile(r'<link[^>]+rel="(?:alternate|canonical)"[^>]+href="https?://([^/"]+)', re.I)
RE_RELAY_SKIP = re.compile(r'cloudflare|cloudfront|akamai|fastly|jsdelivr|gstatic|googleusercontent|bunny|wp\.com|w\.org|gravatar|youtube|facebook|googleapis', re.I)
RE_HTMLLANG = re.compile(r'<html[^>]*\blang="([a-zA-Z]{2})', re.I)
RE_LOC = re.compile(r'<loc>\s*([^<\s]+)\s*</loc>', re.I)
RE_XMLURL = re.compile(r'https?://[^<\s"]+', re.I)

# hidden-link (L17) regexes (port of hidden_links.py)
HID_ALLOW = re.compile(r'sr-only|screen-reader-text|visually-hidden|elementor-screen-only|wp-block-|skip-link|assistive|aria-hidden|googlemaps|gmap', re.I)
HID_STYLE = re.compile(r'(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|text-indent\s*:\s*-\s*\d{3,}|(?:left|top)\s*:\s*-\s*\d{3,}\s*px|height\s*:\s*0(?:px|;|\s)|opacity\s*:\s*0\b|clip\s*:\s*rect\(0)', re.I)
HID_BLOCK = re.compile(r'<(div|span|p|section|footer|ul|a)\b([^>]*style="[^"]*")[^>]*>(.*?)</\1>', re.I | re.S)
# obfuscation heuristics (L14OBFUS)
OB_EVAL = re.compile(r'eval\(\s*(atob|unescape|decodeURIComponent|String\.fromCharCode)', re.I)
OB_HEX = re.compile(r'(\\x[0-9a-fA-F]{2}){12,}')
OB_DOCW = re.compile(r'document\.write\([^)]{0,40}<scr', re.I)
OB_CHAR = re.compile(r'String\.fromCharCode\([0-9]+(,[0-9]+){8,}')
# doorway shape (L20SHAPE)
SH_EXCL = re.compile(r'/wp-content/|/wp-includes/|/cdn-cgi/|/wp-json/|[0-9a-f]{8,}', re.I)
SH_RD = re.compile(r'/[a-z]{5,}/[0-9]{1,4}\.html?($|[?#])', re.I)
SH_CONS = re.compile(r'[bcdfghjklmnpqrstvwxz]{6,}')


def strip_html(h):
    h = RE_TAGSTRIP.sub(" ", h)
    h = RE_TAGS.sub(" ", h)
    h = RE_ENT.sub(" ", h)
    return RE_WS.sub(" ", h)


def distinct(text, rx):
    return sorted({m.group(0).lower() for m in rx.finditer(text)})


def hostof(url):
    if not url:
        return ""
    s = re.sub(r'^[a-z]+://', '', url.lower())
    s = re.sub(r'/.*$', '', s)
    return re.sub(r':.*$', '', s)


def samehost(host, reg):
    return host == reg or host.endswith("." + reg)


def gettitle(h):
    m = RE_TITLE.search(h)
    if not m:
        return ""
    return RE_WS.sub(" ", m.group(1)).strip()[:120]


async def fetch(client, ua, referer, url, timeout=18.0):
    headers = {"user-agent": ua}
    if referer:
        headers["referer"] = referer
    for u in (url, url.replace("https://", "http://", 1)):
        try:
            r = await client.get(u, headers=headers, timeout=timeout)
            return r.status_code, str(r.url), (r.text or ""), r.headers
        except Exception:
            continue
    return 0, "", "", {}


def _hidden_links(htmltext, reg):
    """L17 — off-screen / invisible spam-anchor block with a STRONG kw or >=5 off-domain anchors."""
    for m in HID_BLOCK.finditer(htmltext):
        opentag = m.group(2)
        if not HID_STYLE.search(opentag):
            continue
        block = m.group(0)
        if HID_ALLOW.search(block):
            continue
        inner = m.group(3)
        text = RE_WS.sub(" ", html.unescape(RE_TAGS.sub(" ", inner))).strip()
        off = len(re.findall(r'href="https?://(?!(?:[^"/]*\.)?' + re.escape(reg) + r')[^"]+"', inner, re.I))
        kw = S.C_ALL_STRONG.search(text) or S.GAMB_WEAK.search(text) if text else None
        if kw or off >= 5:
            tag = kw.group(0) if kw else ("%d-offdomain-anchors" % off)
            return ("hidden[%s]: %s" % (tag, (text or block)[:160]))[:200]
    return None


async def scan_domain(client, domain):
    d = domain.strip().lower()
    reg = re.sub(r'^www\.', '', d)
    base = "https://" + d
    sigs = []
    res = {"domain": d, "http_status": 0, "signals": sigs, "title": "", "error": None}

    def emit(bucket, layer, match, url=""):
        sigs.append({"bucket": bucket, "layer": layer, "match": str(match)[:200], "url": url})

    # ---- core homepage fetches ----
    cb, urlB, tB, hB = await fetch(client, UA_BR, None, base)
    if cb == 0:
        res["error"] = "unreachable"
        return res
    res["http_status"] = cb
    (cg, urlG, tG, hG), (cr, urlR, tR, hR), (cm, urlM, tM, hM) = await asyncio.gather(
        fetch(client, UA_GB, REF_G, base),
        fetch(client, UA_BR, REF_G, base),
        fetch(client, UA_IPH, REF_G, base, timeout=15.0),
    )
    bh, gh_, mh = hostof(urlB), hostof(urlG), hostof(urlM)

    # L18 WAF/challenge (modifier, not a verdict)
    if S.WAF.search(tB):
        m = S.WAF.search(tB)
        emit("control", "L18CHALLENGE", m.group(0), base + "/")

    visB, visG, visR = strip_html(tB), strip_html(tG), strip_html(tR)

    # L1 visible keywords (strong + weak)
    kwS = distinct(visB, S.C_ALL_STRONG)
    if kwS:
        emit("homepage-content", "L1KW_STRONG", ";".join(kwS), base + "/")
    kwW = distinct(visB, S.C_ALL_WEAK)
    if kwW:
        emit("homepage-content", "L1KW_WEAK", ";".join(kwW), base + "/")

    # L2 UA cloak, L3 referer cloak (strong kw to bot/referer but not to browser)
    setS = set(kwS)
    kgS = set(distinct(visG, S.C_ALL_STRONG))
    ex = sorted(kgS - setS)
    if ex:
        emit("cloak-diff", "L2UACLOAK", ";".join(ex), base + "/")
    krS = set(distinct(visR, S.C_ALL_STRONG))
    exr = sorted(krS - setS)
    if exr:
        emit("cloak-diff", "L3REFCLOAK", ";".join(exr), base + "/")

    # L4 mobile / L9 browser off-domain redirect
    if mh and not samehost(mh, reg):
        emit("redirect", "L4MOBILE", mh, urlM)
    if bh and not samehost(bh, reg):
        emit("redirect", "L9REDIR", bh, urlB)

    # L10 title foreign-script / defacement
    ttl = gettitle(tB) or gettitle(tG)
    res["title"] = ttl
    if ttl and S.FOREIGN.search(ttl):
        emit("homepage-content", "L10LANG", ttl, base + "/")
    defm = distinct(tB + tG, S.DEFACE)
    if defm:
        emit("deface", "L10DEFACE", ";".join(defm), base + "/")

    # L14 malware-JS campaign + obfuscation, L8 iframe
    bad = distinct(tB + tG, S.MALJS)
    if bad:
        emit("malware-js", "L14CAMPAIGN", ";".join(bad[:3]), base + "/")
    ob, obr = 0, []
    if OB_EVAL.search(tB):
        ob += 3; obr.append("eval-decoder")
    if OB_HEX.search(tB):
        ob += 2; obr.append("hexrun")
    if OB_DOCW.search(tB):
        ob += 2; obr.append("docwrite-script")
    if OB_CHAR.search(tB):
        ob += 2; obr.append("charcode-run")
    if ob >= 4:
        emit("malware-js", "L14OBFUS", "score=%d:%s" % (ob, ",".join(obr)), base + "/")
    ifr = []
    for m in RE_IFRAME.finditer(tB + tG):
        u = RE_IFRAME_URL.search(m.group(0))
        if u:
            ifr.append(u.group(0))
    if ifr:
        emit("malware-js", "L8IFRAME", ";".join(sorted(set(ifr))[:2]), base + "/")

    # L17 hidden-link CSS spam
    hid = _hidden_links(tB, reg)
    if hid:
        emit("homepage-content", "L17HIDDEN", hid, base + "/")

    # L20RELAY off-domain canonical/alternate (from googlebot body)
    relays = []
    for m in RE_RELAY.finditer(tG):
        h = m.group(1).lower()
        if h and not samehost(h, reg) and not RE_RELAY_SKIP.search(h):
            relays.append(h)
    if relays:
        emit("redirect", "L20RELAY", ";".join(sorted(set(relays))[:2]), base + "/")

    fired = len(sigs) > 0

    # ---- WordPress REST enumeration (the crown jewel) ----
    isWP = False
    try:
        cw, urlw, tw, hw = await fetch(client, UA_GB, None, base + "/wp-json/wp/v2/posts?per_page=1", timeout=14.0)
        wptot = hw.get("x-wp-total") if hw else None
        if wptot and str(wptot).isdigit():
            isWP = True
            await _rest_enum(client, base, reg, int(wptot), emit)
    except Exception:
        pass

    # ---- sitemap / robots doorway + shape (if WP or something already smells) ----
    if isWP or fired:
        try:
            await _sitemap(client, base, reg, emit)
        except Exception:
            pass
        # L16FEED
        try:
            for fu in ("/feed/", "/?feed=rss2"):
                cf, uf, tf, hf = await fetch(client, UA_GB, None, base + fu, timeout=12.0)
                if not tf:
                    continue
                feedkw = distinct(" ".join(re.findall(r'<(?:title|description)>[^<]*</(?:title|description)>', tf, re.I)), S.C_ALL_STRONG)
                if feedkw:
                    emit("content-enum", "L16FEED", ";".join(feedkw), base + fu)
                    break
        except Exception:
            pass

    # ---- L16HDR header redirect to spam/junk ----
    try:
        loc = (hG.get("location") or hG.get("refresh") or "") if hG else ""
        if loc:
            u = RE_XMLURL.search(loc)
            loc = u.group(0) if u else loc
            lh = hostof(loc)
            if lh and not samehost(lh, reg) and (S.GAMB_STRONG.search(loc) or S.JUNKTLD.search(loc)):
                emit("redirect", "L16HDR", loc, base + "/")
    except Exception:
        pass

    # ---- L5 WP-search density (WP only) ----
    if isWP:
        try:
            best = 0
            for q in ("casino", "judi"):
                cs, us, ts, hs = await fetch(client, UA_GB, None, base + "/?s=" + q, timeout=12.0)
                n = len(S.C_ALL_STRONG.findall(strip_html(ts)))
                if n > best:
                    best = n
            if best >= 4:
                emit("search-index", "L5DENSITY", "count=%d" % best, base + "/?s=casino")
        except Exception:
            pass

    # classify only flagged candidates (cheap; used to keep the lead list clean)
    if sigs:
        res["domain_spammy"] = classify.domain_spammy(reg)
        res["bd_signal"] = classify.bd_signal(reg, visB)
        res["biz_type"] = classify.biz_type(reg, res.get("title", ""), visB)
        res["excerpt"] = visB[:3000]
    return res


async def _rest_enum(client, base, reg, wptot, emit):
    pages = 1 if wptot <= 100 else min((wptot + 99) // 100, 5)
    foreign = total = 0
    fsamp = []
    for typ in ("posts", "pages"):
        tp = pages if typ == "posts" else 1
        for pg in range(1, tp + 1):
            cf, uf, tf, hf = await fetch(client, UA_GB, None,
                                         "%s/wp-json/wp/v2/%s?per_page=100&page=%d&_fields=slug,title,link,date" % (base, typ, pg), timeout=16.0)
            if not tf or '"slug"' not in tf:
                break
            import json as _json
            try:
                arr = _json.loads(tf)
            except Exception:
                break
            if not isinstance(arr, list):
                break
            seen = set()
            for p in arr:
                if not isinstance(p, dict):
                    continue
                slug = (p.get("slug") or "").strip()
                t = p.get("title") or {}
                title = (t.get("rendered") if isinstance(t, dict) else t) or ""
                title = RE_WS.sub(" ", html.unescape(str(title))).strip()
                link = (p.get("link") or "").strip()
                total += 1
                if S.FOREIGN.search(title):
                    foreign += 1
                    if len(fsamp) < 3:
                        fsamp.append(title[:40])
                key = slug or title[:40]
                if not key or key in seen:
                    continue
                if (slug and S.SLUG_SPAM.search(slug)) or (title and S.C_ALL_STRONG.search(title)):
                    seen.add(key)
                    emit("content-enum", "L11REST", "slug=%s::%s" % (slug[:60], title[:90]), link[:130])
    # L20SCRIPT — foreign-script post cluster on an otherwise en/bn site
    if foreign >= 4 and total and foreign * 100 < total * 30:
        emit("content-enum", "L20SCRIPT", "foreign=%d/%d:%s" % (foreign, total, " | ".join(fsamp)), base + "/wp-json/wp/v2/posts")
    # L20MASS — big post count, gated behind an already-fired content-enum hit (checked in score)
    if wptot >= 300:
        emit("content-enum", "L20MASS_CAND", "x-wp-total=%d" % wptot, base + "/wp-json/wp/v2/posts")


async def _sitemap(client, base, reg, emit):
    cr, ur, tr0, hr = await fetch(client, UA_GB, None, base + "/robots.txt", timeout=10.0)
    smaps = re.findall(r'sitemap:\s*(https?://\S+)', tr0 or "", re.I)
    if not smaps:
        smaps = [base + "/sitemap_index.xml", base + "/wp-sitemap.xml", base + "/sitemap.xml"]
    smtext = ""
    nchild = 0
    for u in smaps[:3]:
        if reg not in u:
            continue
        cx, ux, tx, hx = await fetch(client, UA_GB, None, u, timeout=10.0)
        if not tx:
            continue
        smtext += tx
        for child in sorted(set(re.findall(r'https?://[^<\s"]+\.xml', tx, re.I)))[:6]:
            if reg not in child or nchild >= 6:
                continue
            nchild += 1
            cc, uc, tc, hc = await fetch(client, UA_GB, None, child, timeout=9.0)
            smtext += tc
    if not smtext:
        return
    # L11SITEMAP — spam slug inside a same-site <loc> path
    su = []
    for u in RE_XMLURL.findall(smtext):
        if reg in u and not u.lower().endswith(".xml") and S.SLUG_SPAM.search(u):
            su.append(u)
            if len(su) >= 3:
                break
    if su:
        emit("sitemap-doorway", "L11SITEMAP", ";".join(su), su[0])
    # L20SHAPE — random-dir farm / gibberish-slug cluster (Japanese keyword hack)
    locs = RE_LOC.findall(smtext) or RE_XMLURL.findall(smtext)
    randomdir, gib = {}, {}
    for u in locs:
        if reg not in u or SH_EXCL.search(u):
            continue
        try:
            path = urlparse(u).path
        except Exception:
            continue
        parent = "/".join(path.rstrip("/").split("/")[:-1]) or "/"
        if SH_RD.search(u):
            randomdir[parent] = randomdir.get(parent, 0) + 1
        seg = re.sub(r'\.html?$', '', path.rstrip("/").split("/")[-1]).lower()
        if len(seg) > 9:
            v = sum(seg.count(c) for c in "aeiou")
            if v / max(len(seg), 1) < 0.22 and SH_CONS.search(seg):
                gib[parent] = gib.get(parent, 0) + 1
    rdmax = max(randomdir.values()) if randomdir else 0
    gibmax = max(gib.values()) if gib else 0
    if rdmax >= 6 or gibmax >= 10:
        parent = max(randomdir, key=randomdir.get) if (randomdir and rdmax >= gibmax) else (max(gib, key=gib.get) if gib else "")
        emit("sitemap-doorway", "L20SHAPE", "randomdir=%d gibberish=%d parent=%s" % (rdmax, gibmax, parent), base + (parent or "") + "/")
