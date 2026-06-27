"""
lib.py — shared harvester utilities: domain normalization (registrable domain via
the Public Suffix List, so com.bd/net.bd/etc. collapse correctly), a Bangladesh
confidence score, and a batched POST client to the Worker /harvest endpoint
(with the browser User-Agent the Cloudflare edge requires).

Every harvester (crt.sh, directories, Common Crawl, reverse-IP, OSM, …) imports
this so there is ONE normalization + posting path.
"""
import os
import re
import json
import time
import urllib.request

try:
    import tldextract
    _EXTRACT = tldextract.TLDExtract(suffix_list_urls=())  # offline (bundled PSL snapshot)
except Exception:
    _EXTRACT = None

API = os.environ.get("API_BASE", "https://bd-hack-audit-api.javed-it.workers.dev").rstrip("/")
UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"

# noise hosts we never want to scan (social, CDNs, platforms, infra)
BLOCK = set("""facebook.com fb.com fb.me google.com gmail.com googleusercontent.com youtube.com youtu.be
instagram.com linkedin.com twitter.com x.com wa.me whatsapp.com t.me telegram.me telegram.org bit.ly
tinyurl.com goo.gl maps.google.com play.google.com apple.com microsoft.com yahoo.com hotmail.com
outlook.com live.com w3.org schema.org gravatar.com wordpress.org wordpress.com gstatic.com
googleapis.com google-analytics.com cloudflare.com jsdelivr.net jquery.com bootstrapcdn.com
fontawesome.com example.com domain.com wixsite.com blogspot.com pinterest.com tiktok.com
mail.google.com drive.google.com sites.google.com googletagmanager.com gmpg.org amazonaws.com
cloudfront.net akamai.net fastly.net bunny.net daraz.com.bd bikroy.com""".split())

_HOST_RE = re.compile(r'^[a-z0-9][a-z0-9.\-]+\.[a-z]{2,}$')


def token():
    t = os.environ.get("SHARED_TOKEN", "")
    if not t:
        p = os.path.expanduser("~/.secrets/bd_hack_audit.env")
        if os.path.exists(p):
            for line in open(p):
                if line.strip().startswith("SHARED_TOKEN="):
                    t = line.split("=", 1)[1].strip()
    return t


def registrable(raw):
    """Return the lowercased registrable domain (handles .com.bd via PSL), or None."""
    if not raw:
        return None
    h = str(raw).strip().lower().rstrip('.')
    h = re.sub(r'^[a-z]+://', '', h)
    h = re.sub(r'/.*$', '', h)
    h = re.sub(r':.*$', '', h)
    h = h.lstrip('*.').lstrip('.')
    h = re.sub(r'^www\.', '', h)
    if not _HOST_RE.match(h) or '..' in h:
        return None
    if re.search(r'\.(png|jpe?g|gif|svg|css|js|ico|woff2?|ttf|pdf|zip)$', h):
        return None
    if _EXTRACT:
        e = _EXTRACT(h)
        if not e.domain or not e.suffix:
            return None
        h = (e.domain + "." + e.suffix).lower()
    if h in BLOCK:
        return None
    return h


def bd_score(domain, source_bd=False, ip_bd=False, bengali=False):
    """0-100 Bangladesh-business confidence (research weights)."""
    s = 0
    if domain.endswith('.bd'):
        s += 40
    if ip_bd:
        s += 25
    if bengali:
        s += 15
    if source_bd:
        s += 30
    return min(s, 100)


def post_batch(source, domains, max_retry=4):
    """POST a list of {'domain','business?','phone?','bd_score?'} (or bare domain strings) to /harvest."""
    norm = []
    seen = set()
    for d in domains:
        rec = d if isinstance(d, dict) else {"domain": d}
        rd = registrable(rec.get("domain") or rec.get("host") or rec.get("url"))
        if not rd or rd in seen:
            continue
        seen.add(rd)
        rec["domain"] = rd
        norm.append(rec)
    if not norm:
        return {"found": 0, "inserted": 0}
    body = json.dumps({"source": source, "domains": norm}).encode()
    req = urllib.request.Request(API + "/harvest", body,
                                 {"authorization": "Bearer " + token(), "content-type": "application/json", "user-agent": UA})
    last = None
    for i in range(max_retry):
        try:
            with urllib.request.urlopen(req, timeout=90) as r:
                return json.loads(r.read())
        except Exception as e:
            last = e
            time.sleep(2 * (i + 1))
    print("  post_batch failed:", last)
    return {"found": len(norm), "inserted": 0, "error": str(last)}


def harvest(source, domains, chunk=1000):
    """Normalize + dedup + post in chunks. Returns total inserted."""
    seen, total, found = set(), 0, 0
    clean = []
    for d in domains:
        rec = d if isinstance(d, dict) else {"domain": d}
        rd = registrable(rec.get("domain") or rec.get("host") or rec.get("url"))
        if not rd or rd in seen:
            continue
        seen.add(rd)
        rec["domain"] = rd
        clean.append(rec)
    found = len(clean)
    for i in range(0, len(clean), chunk):
        res = post_batch(source, clean[i:i + chunk])
        total += res.get("inserted", 0)
    print(f"[{source}] found {found} unique, inserted {total} new")
    return total


def http_get(url, timeout=30, headers=None):
    h = {"user-agent": UA}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, headers=h)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()
