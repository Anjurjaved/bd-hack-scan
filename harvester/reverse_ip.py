#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
harvester/reverse_ip.py — discover BD-hosted businesses via REVERSE-IP (co-hosted neighbours).

Most Bangladeshi businesses don't run .bd domains — they run .com / .com.bd sites on
LOCAL SHARED HOSTING (Dhakacom, Link3, ExonHost, WebHostBD, Hostever, BDIX members…).
They never appear in the .bd zone or CT-identity queries, but they SHARE an IP with
dozens-to-hundreds of other BD businesses.

PTR reverse-DNS does NOT work here: a shared IP has ONE PTR (the server's own name),
not the customer virtual-hosts — so the old PTR sweep found 0. The right tool is a
REVERSE-IP service that returns ALL domains seen on an IP. We use HackerTarget's free
reverse-IP endpoint (each GitHub-Actions run has a fresh runner IP, so the per-IP free
quota effectively resets per run).

SNOWBALL strategy (all free, bounded, idempotent):
  1. Pull a ROTATING slice of known .bd domains from the Worker (/api/seed) — these are
     guaranteed-live BD sites, so their IPs are guaranteed BD shared-hosting IPs.
  2. Resolve each seed to its A-record IP → a set of real BD hosting IPs.
  3. Reverse-IP each IP (capped per run) → every co-hosted hostname.
  4. registrable() collapses www./mail./cpanel.… to the business apex; dedup; drop the
     hosting providers' own domains. harvest('reverse-ip', …) → the Worker dedups.
Each run advances the seed offset (state file) so consecutive runs cover fresh IPs and
the queue keeps filling with NEW BD businesses 24/7.

Env (runtime): API_BASE, SHARED_TOKEN
Optional: RIP_MAX_IPS (reverse-IP calls/run, default 28), RIP_SEED (.bd seeds resolved, default 220)
"""
from __future__ import annotations

import json
import os
import socket
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))
from lib import API, UA, bd_score, harvest, http_get, registrable  # noqa: E402

SOURCE = "reverse-ip"
MAX_IPS = int(os.environ.get("RIP_MAX_IPS", "28"))        # reverse-IP API calls per run (quota-bounded)
SEED_COUNT = int(os.environ.get("RIP_SEED", "220"))       # .bd domains resolved for seed IPs
RESOLVE_TIMEOUT = float(os.environ.get("RIP_RESOLVE_TIMEOUT", "4"))
STATE_FILE = os.path.join(os.path.dirname(__file__), ".reverse_ip_state.json")
HT_URL = "https://api.hackertarget.com/reverseiplookup/?q="

# Hosting / network providers' OWN domains — skip (they're not customer businesses).
HOST_PROVIDERS = {
    "dhakacom.com", "link3.net", "exonhost.com", "webhostbd.com", "hostever.com",
    "bdwebservices.com", "alpha.net.bd", "aamranetworks.com", "bdcom.com", "adnsl.net",
    "cloudflare.com", "hostinger.com", "namecheap.com", "godaddy.com", "bluehost.com",
    "amazonaws.com", "digitalocean.com", "googleusercontent.com", "hostgator.com",
    "siteground.com", "cpanel.net", "litespeedtech.com", "hostnetbd.com", "sslwireless.com",
}


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


def fetch_seeds(offset: int, n: int):
    """Rotating slice of known .bd domains from the Worker. Returns (domains, total)."""
    try:
        blob = http_get(f"{API}/api/seed?limit={n}&offset={offset}", timeout=45)
        d = json.loads(blob.decode("utf-8", "replace"))
        return d.get("domains", []), int(d.get("total", 0) or 0)
    except Exception as e:
        print(f"[reverse-ip] seed fetch failed: {e}", file=sys.stderr)
        return [], 0


def resolve_ips(domains):
    """domain -> A-record IP; return {ip: a_seed_domain} (unique IPs)."""
    socket.setdefaulttimeout(RESOLVE_TIMEOUT)
    ips = {}
    for d in domains:
        try:
            ip = socket.gethostbyname(d)
        except Exception:
            continue
        # skip Cloudflare / obvious CDN ranges (reverse-IP there is useless)
        if ip.startswith(("104.21.", "172.67.", "104.16.", "172.64.", "188.114.", "162.159.")):
            continue
        ips.setdefault(ip, d)
    return ips


def reverse_ip(ip):
    """All hostnames sharing *ip*. Returns list, or None if rate-limited/error."""
    try:
        txt = http_get(HT_URL + ip, timeout=30).decode("utf-8", "replace")
    except Exception:
        return []
    low = txt.lower()
    if "api count exceeded" in low or "too many" in low or "rate limit" in low:
        return None
    if "no dns a records" in low or "error" in low and "." not in txt:
        return []
    return [ln.strip() for ln in txt.splitlines() if ln.strip() and "." in ln and " " not in ln.strip()]


def main() -> int:
    st = load_state()
    offset = int(st.get("seed_offset", 0))
    seeds, total = fetch_seeds(offset, SEED_COUNT)
    if not seeds:
        # ran off the end (or empty) → wrap to the start next time
        if total:
            st["seed_offset"] = 0
            save_state(st)
        print("[reverse-ip] no seed domains this run", file=sys.stderr)
        return 0
    # advance + wrap the seed cursor
    nxt = offset + len(seeds)
    st["seed_offset"] = 0 if (total and nxt >= total) else nxt
    print(f"[reverse-ip] {len(seeds)} seed .bd domains (offset {offset}/{total})", file=sys.stderr)

    ip_map = resolve_ips(seeds)
    ips = list(ip_map.keys())[:MAX_IPS]
    print(f"[reverse-ip] resolved {len(ip_map)} unique hosting IPs; reverse-IP on {len(ips)}", file=sys.stderr)

    found = {}
    for i, ip in enumerate(ips, 1):
        hosts = reverse_ip(ip)
        if hosts is None:
            print(f"[reverse-ip] reverse-IP quota hit after {i - 1} IPs — stopping", file=sys.stderr)
            break
        for h in hosts:
            dom = registrable(h)
            if not dom or dom in found or dom in HOST_PROVIDERS:
                continue
            found[dom] = {"domain": dom, "bd_score": bd_score(dom, ip_bd=True)}
        time.sleep(1.2)   # polite + spread the free quota

    save_state(st)
    rows = list(found.values())
    print(f"[reverse-ip] {len(rows)} co-hosted domains discovered from {len(ips)} IPs", file=sys.stderr)
    if rows:
        try:
            inserted = harvest(SOURCE, rows)
            print(f"[reverse-ip] done: {len(rows)} unique, {inserted} new", file=sys.stderr)
        except Exception as e:
            print(f"[reverse-ip] harvest failed: {e}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print(f"[reverse-ip] fatal (handled): {e}", file=sys.stderr)
        sys.exit(0)
