#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
harvester/lead_coip.py — SHARED-IP lead multiplier (co-hosted neighbours of confirmed hacks).

WHY: almost every Bangladeshi SMB sits on LOCAL SHARED HOSTING (cPanel/LiteSpeed boxes at
Namecheap, Dhakacom, ExonHost, Hostever, WebHostBD, …). When ONE site on such a box is
compromised, its NEIGHBOURS on the same IP are high-probability victims too — same vulnerable
host, same attacker, frequent cross-account infection. So the richest scan targets in the
world are the OTHER domains sharing an IP with a site we have ALREADY confirmed hacked.

PIPELINE (all free, bounded, idempotent):
  1. Pull confirmed-hacked lead domains from the Worker (/api/leads).
  2. Resolve each to its A-record IP (skip Cloudflare/CDN ranges — origin is hidden there).
  3. Group leads by IP → "hotspot" servers (an IP carrying >=1 confirmed lead).
  4. Reverse-IP each hotspot (rapiddns.io free, HackerTarget fallback) → every co-hosted host.
  5. registrable + dedup; drop the leads themselves + hosting-provider domains.
  6. harvest('lead-coip', …) with a high bd_score so the scanner prioritises them.
A per-run state file remembers IPs already enumerated, so consecutive runs cover NEW hotspots.

Env (runtime): API_BASE, SHARED_TOKEN
Optional: COIP_REGION (bd|intl|all, default bd), COIP_MAX_LEADS (default 800),
          COIP_MAX_IPS (reverse-IP calls/run, default 60), COIP_RESOLVE_TIMEOUT (default 4)
"""
from __future__ import annotations

import json
import os
import re
import socket
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))
from lib import API, UA, bd_score, harvest, http_get, registrable, token  # noqa: E402

REGION = os.environ.get("COIP_REGION", "bd")
MAX_LEADS = int(os.environ.get("COIP_MAX_LEADS", "800"))
MAX_IPS = int(os.environ.get("COIP_MAX_IPS", "60"))
RESOLVE_TIMEOUT = float(os.environ.get("COIP_RESOLVE_TIMEOUT", "4"))
STATE_FILE = os.path.join(os.path.dirname(__file__), ".lead_coip_state.json")

# Cloudflare / CDN A-record prefixes — reverse-IP on these is useless (origin hidden).
CDN_PREFIXES = ("104.21.", "172.67.", "104.16.", "104.17.", "104.18.", "104.19.",
                "172.64.", "172.65.", "172.66.", "188.114.", "162.159.", "104.26.",
                "104.27.", "104.28.", "151.101.", "199.232.")  # +Fastly

# Hosting / network providers' OWN domains — never a customer business.
HOST_PROVIDERS = {
    "dhakacom.com", "link3.net", "exonhost.com", "webhostbd.com", "hostever.com",
    "bdwebservices.com", "alpha.net.bd", "aamranetworks.com", "bdcom.com", "adnsl.net",
    "cloudflare.com", "hostinger.com", "namecheap.com", "godaddy.com", "bluehost.com",
    "amazonaws.com", "digitalocean.com", "googleusercontent.com", "hostgator.com",
    "siteground.com", "cpanel.net", "litespeedtech.com", "hostnetbd.com", "sslwireless.com",
    "web-hosting.com", "websitewelcome.com", "registrar-servers.com", "hostgator.com.bd",
}

_HOST_IN_HTML = re.compile(r'>\s*([a-z0-9][a-z0-9\-]*(?:\.[a-z0-9\-]+)+\.[a-z]{2,})\s*<', re.I)


def load_state() -> dict:
    try:
        with open(STATE_FILE, encoding="utf-8") as fh:
            d = json.load(fh)
            return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def save_state(s: dict) -> None:
    try:
        with open(STATE_FILE, "w", encoding="utf-8") as fh:
            json.dump(s, fh)
    except Exception:
        pass


def fetch_leads(region: str, limit: int):
    """Confirmed-hacked lead domains from the Worker."""
    try:
        blob = http_get(f"{API}/api/leads?limit={limit}&region={region}", timeout=60)
        d = json.loads(blob.decode("utf-8", "replace"))
        return [l["domain"].strip().lower() for l in d.get("leads", [])
                if l.get("domain") and int(l.get("confirmed", 0) or 0) == 1]
    except Exception as e:
        print(f"[lead-coip] lead fetch failed: {e}", file=sys.stderr)
        return []


def resolve_ip(domain: str):
    try:
        ip = socket.gethostbyname(domain)
    except Exception:
        return None
    if ip.startswith(CDN_PREFIXES):
        return None
    return ip


def reverse_ip_rapiddns(ip: str):
    """All hostnames on *ip* via rapiddns.io (free, no key). None on hard error."""
    try:
        html = http_get(f"https://rapiddns.io/sameip/{ip}?full=1", timeout=35).decode("utf-8", "replace")
    except Exception:
        return None
    hosts = set()
    for m in _HOST_IN_HTML.finditer(html):
        h = m.group(1).lower()
        if "." in h and " " not in h:
            hosts.add(h)
    return list(hosts)


def reverse_ip_hackertarget(ip: str):
    """Fallback: HackerTarget free reverse-IP. None if rate-limited."""
    try:
        txt = http_get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}", timeout=30).decode("utf-8", "replace")
    except Exception:
        return None
    low = txt.lower()
    if "api count exceeded" in low or "too many" in low or "rate limit" in low:
        return None
    if "no dns a records" in low:
        return []
    return [ln.strip() for ln in txt.splitlines() if ln.strip() and "." in ln and " " not in ln.strip()]


def reverse_ip(ip: str):
    """Best-effort co-hosted hostnames: rapiddns first, HackerTarget fallback."""
    hosts = reverse_ip_rapiddns(ip)
    if hosts:
        return hosts
    ht = reverse_ip_hackertarget(ip)
    return ht if ht is not None else (hosts or [])


def main() -> int:
    if not token():
        print("[lead-coip] no SHARED_TOKEN — aborting", file=sys.stderr)
        return 0

    leads = fetch_leads(REGION, MAX_LEADS)
    if not leads:
        print("[lead-coip] no confirmed leads to seed from", file=sys.stderr)
        return 0
    lead_set = set(leads)
    print(f"[lead-coip] {len(leads)} confirmed leads (region={REGION})", file=sys.stderr)

    # resolve leads → IP; group leads per IP (hotspots)
    socket.setdefaulttimeout(RESOLVE_TIMEOUT)
    ip_leads: dict[str, list[str]] = {}
    cdn = 0
    for d in leads:
        ip = resolve_ip(d)
        if not ip:
            cdn += 1
            continue
        ip_leads.setdefault(ip, []).append(d)
    print(f"[lead-coip] {len(ip_leads)} distinct hosting IPs ({cdn} behind CDN/unresolved, skipped)", file=sys.stderr)

    # rank hotspots: IPs carrying the MOST confirmed leads first (densest infections)
    st = load_state()
    done_ips = set(st.get("done_ips", []))
    ranked = sorted(ip_leads.items(), key=lambda kv: -len(kv[1]))
    todo = [(ip, ls) for ip, ls in ranked if ip not in done_ips][:MAX_IPS]
    if not todo:  # everything seen — reset and start over
        done_ips = set()
        todo = ranked[:MAX_IPS]
    print(f"[lead-coip] reverse-IP on {len(todo)} hotspot IPs this run", file=sys.stderr)

    found: dict[str, dict] = {}
    hotspots = []
    for i, (ip, ls) in enumerate(todo, 1):
        hosts = reverse_ip(ip)
        co = 0
        for h in hosts:
            dom = registrable(h)
            if not dom or dom in lead_set or dom in HOST_PROVIDERS or dom in found:
                continue
            found[dom] = {"domain": dom, "bd_score": bd_score(dom, ip_bd=True)}
            co += 1
        hotspots.append((ip, len(ls), len(hosts), co))
        print(f"[lead-coip]   {ip}: {len(ls)} known-hacked + {len(hosts)} co-hosted → {co} new neighbours", file=sys.stderr)
        done_ips.add(ip)
        time.sleep(1.0)  # polite

    st["done_ips"] = list(done_ips)[-4000:]
    save_state(st)

    # hotspot summary (densest infected servers — useful for the dashboard later)
    hotspots.sort(key=lambda x: -x[1])
    print("[lead-coip] TOP infected shared servers (ip | known-hacked | total-cohosted | new):", file=sys.stderr)
    for ip, k, t, n in hotspots[:12]:
        print(f"[lead-coip]   {ip}  hacked={k}  cohosted={t}  new={n}", file=sys.stderr)

    rows = list(found.values())
    print(f"[lead-coip] {len(rows)} unique co-hosted neighbour domains discovered", file=sys.stderr)
    if rows:
        try:
            inserted = harvest("lead-coip", rows)
            print(f"[lead-coip] done: {len(rows)} unique, {inserted} new queued for scan", file=sys.stderr)
        except Exception as e:
            print(f"[lead-coip] harvest failed: {e}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print(f"[lead-coip] fatal (handled): {e}", file=sys.stderr)
        sys.exit(0)
