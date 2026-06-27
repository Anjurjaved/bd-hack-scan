#!/usr/bin/env python3
"""
seed_existing.py — load the user's already-harvested BD domain lists into the
queue via the Worker /harvest endpoint. One-time (or repeatable; D1 dedups).

Usage: python seed_existing.py [file1 file2 ...]
Reads SHARED_TOKEN from env or ~/.secrets/bd_hack_audit.env; API from API_BASE env.
"""
import os
import re
import sys
import json
import time
import urllib.request

API = os.environ.get("API_BASE", "https://bd-hack-audit-api.javed-it.workers.dev").rstrip("/")
TOKEN = os.environ.get("SHARED_TOKEN", "")
if not TOKEN:
    p = os.path.expanduser("~/.secrets/bd_hack_audit.env")
    if os.path.exists(p):
        for line in open(p):
            if line.strip().startswith("SHARED_TOKEN="):
                TOKEN = line.split("=", 1)[1].strip()

DEFAULT_FILES = [
    "/Users/javed/all-domain/FBCCI_MASTER_ALL_DOMAINS.csv",
    "/Users/javed/fbcci-chamber-associaiotn/website-hack-audit/ALL_DOMAINS_MASTER.csv",
    "/Users/javed/map-scrapper/leads_master.csv",
    "/Users/javed/map-scrapper/scan_input700.csv",
    "/Users/javed/all-domain/scan_input.csv",
    "/Users/javed/mhm-deco-seo/forensics/bd-universe.txt",
    "/Users/javed/mhm-deco-seo/forensics/bd-census/domains.txt",
    "/Users/javed/mhm-deco-seo/forensics/other-hosts/bd_allhosts_sites.txt",
]

BLOCK = set("""facebook.com fb.com fb.me google.com gmail.com googleusercontent.com youtube.com youtu.be
instagram.com linkedin.com twitter.com x.com wa.me whatsapp.com t.me telegram.me telegram.org bit.ly
tinyurl.com goo.gl maps.google.com play.google.com apple.com microsoft.com yahoo.com hotmail.com
outlook.com live.com w3.org schema.org gravatar.com wordpress.org wordpress.com gstatic.com
googleapis.com google-analytics.com cloudflare.com jsdelivr.net jquery.com bootstrapcdn.com
fontawesome.com example.com domain.com wixsite.com blogspot.com pinterest.com tiktok.com
mail.google.com drive.google.com sites.google.com googletagmanager.com gmpg.org""".split())

DOM = re.compile(r'(?:https?://)?(?:www\.)?([a-z0-9][a-z0-9\-]{0,62}(?:\.[a-z0-9\-]{1,63})+)', re.I)


def norm(h):
    h = h.strip().lower().rstrip('.')
    h = re.sub(r'^https?://', '', h)
    h = re.sub(r'/.*$', '', h)
    h = re.sub(r':.*$', '', h)
    h = re.sub(r'^www\.', '', h)
    if not re.match(r'^[a-z0-9][a-z0-9.\-]+\.[a-z]{2,}$', h):
        return None
    if '..' in h or h in BLOCK:
        return None
    # drop image/asset/static hosts
    if re.search(r'\.(png|jpg|jpeg|gif|svg|css|js|ico|woff2?)$', h):
        return None
    return h


# Cloudflare's edge 403s bot User-Agents (Python-urllib/httpx); send a browser UA.
UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"


def post(chunk, src):
    body = json.dumps({"source": src, "domains": [{"domain": d} for d in chunk]}).encode()
    req = urllib.request.Request(API + "/harvest", body,
                                 {"authorization": "Bearer " + TOKEN, "content-type": "application/json", "user-agent": UA})
    with urllib.request.urlopen(req, timeout=90) as r:
        return json.loads(r.read())


def main():
    if not TOKEN:
        print("FATAL: no SHARED_TOKEN", file=sys.stderr); sys.exit(1)
    files = sys.argv[1:] or DEFAULT_FILES
    seen = set()
    for f in files:
        if not os.path.exists(f):
            print("  (skip, not found)", f); continue
        n0 = len(seen)
        txt = open(f, encoding='utf-8', errors='ignore').read()
        for m in DOM.finditer(txt):
            d = norm(m.group(1))
            if d:
                seen.add(d)
        print(f"  {f}: +{len(seen)-n0} (running total {len(seen)})")
    doms = sorted(seen)
    print(f"\nTotal unique domains: {len(doms)}\nPosting to {API}/harvest ...")
    total = 0
    for i in range(0, len(doms), 1000):
        chunk = doms[i:i+1000]
        for attempt in range(4):
            try:
                res = post(chunk, "existing-bulk")
                total += res.get("inserted", 0)
                print(f"  {i+len(chunk):>7}/{len(doms)}  new+={res.get('inserted')}  open_batch={res.get('open_batch')}")
                break
            except Exception as e:
                print("  retry:", e); time.sleep(3 * (attempt + 1))
    print(f"\nDONE — {total} new domains inserted into the queue.")


if __name__ == "__main__":
    main()
