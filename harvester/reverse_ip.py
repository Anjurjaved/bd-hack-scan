#!/usr/bin/env python3
"""
harvester/reverse_ip.py — reverse-DNS sweep over Bangladesh hosting IP space.

Most BD businesses don't run on .bd domains — they sit on .com/.net/.org sites
hosted on *local shared hosting* (Dhakacom, Link3, BDIX members, ExonHost,
WebHostBD, Hostever, ...). Those never show up in .bd-zone or CT-identity
queries. But they DO share an IP block with hundreds of other BD sites, and
most local hosts publish PTR (reverse-DNS) records for the customer hostnames
on each IP. So we sweep BD-allocated IP space and read the PTRs back.

Strategy (all free, all bounded, all best-effort):
  1. Discover BD-allocated prefixes: ask bgpview.io for BD's ASNs
     (https://api.bgpview.io/countries/bd), then pull each ASN's announced
     prefixes (https://api.bgpview.io/asn/<n>/prefixes). If the API is down we
     fall back to a hardcoded list of well-known BD hosting CIDRs.
  2. Rotate through the discovered prefixes a slice at a time (state file), so
     repeated runs cover fresh address space instead of re-scanning one /24.
     Cap ~40 prefixes/run.
  3. For each prefix, sample IPs and do a reverse-DNS PTR lookup
     (socket.gethostbyaddr) in a thread pool (~50 workers, 3s per-lookup
     timeout via socket.setdefaulttimeout). registrable() every hostname; drop
     the host's own infra PTRs (server*, vps*, static*, mail*, ns*, ...).
  4. Collect uniques, harvest('reverse-ip', domains).

Any prefix / lookup that errors is skipped — one failure never kills the run.
Total IPs probed is capped (~6000/run) so the whole thing finishes in minutes.

Env (provided at runtime): API_BASE, SHARED_TOKEN   (consumed by lib.harvest)
Optional env:
  RIP_MAX_PREFIXES   prefixes to scan per run         (default 40)
  RIP_MAX_IPS        hard cap on IPs probed per run   (default 6000)
  RIP_WORKERS        reverse-DNS thread-pool size      (default 50)
  RIP_LOOKUP_TIMEOUT per-lookup socket timeout (sec)   (default 3)
  RIP_SAMPLE_PER24   IPs sampled from each /24          (default 64)
  RIP_MAX_ASNS       BD ASNs expanded into prefixes/run (default 30)
  RIP_STATE_FILE     rotation cursor file (default <dir>/.reverse_ip_state.json)
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
import json
import os
import random
import socket
import sys
import time

# Make `import lib` work no matter what the caller's CWD is.
sys.path.insert(0, os.path.dirname(__file__))

from lib import bd_score, harvest, http_get, registrable  # noqa: E402

SOURCE = "reverse-ip"

# --- tunables (env-overridable) -------------------------------------------
MAX_PREFIXES = int(os.environ.get("RIP_MAX_PREFIXES", "40"))
MAX_IPS = int(os.environ.get("RIP_MAX_IPS", "6000"))
WORKERS = int(os.environ.get("RIP_WORKERS", "50"))
LOOKUP_TIMEOUT = float(os.environ.get("RIP_LOOKUP_TIMEOUT", "3"))
SAMPLE_PER_24 = int(os.environ.get("RIP_SAMPLE_PER24", "64"))
MAX_ASNS_EXPANDED = int(os.environ.get("RIP_MAX_ASNS", "30"))
STATE_FILE = os.environ.get(
    "RIP_STATE_FILE",
    os.path.join(os.path.dirname(__file__), ".reverse_ip_state.json"),
)

BGPVIEW_COUNTRY = "https://api.bgpview.io/countries/bd"
BGPVIEW_ASN_PREFIXES = "https://api.bgpview.io/asn/{asn}/prefixes"

# PTRs that are the *host's own* infrastructure rather than a customer site.
# These hostnames belong to the hosting/network provider, not a BD business,
# so registrable() of them just yields the host's own domain — noise we skip.
# Matched against the FIRST label of the PTR (exact or prefix).
_INFRA_PREFIXES = (
    "server", "srv", "vps", "vz", "cpanel", "whm", "host", "hosting",
    "static", "dynamic", "dyn", "pool", "ip-", "ip.", "unassigned",
    "unused", "reverse", "rdns", "no-rdns", "nordns", "ptr",
    "mail", "smtp", "mx", "webmail", "relay",
    "ns", "ns1", "ns2", "dns", "resolver",
    "gw", "gateway", "router", "rtr", "core", "edge", "bng", "bras",
    "lo0", "lo-", "ae0", "ae-", "xe-", "ge-", "et-", "bundle",
    "node", "client", "customer", "cust", "subscriber", "sub-",
    "broadband", "bb-", "fttx", "ftth", "gpon", "olt", "leased",
    "cache", "proxy", "cdn", "lb-", "loadbalancer", "vlan",
)

# Substrings that mark the PTR as provider infra even mid-string.
_INFRA_SUBSTR = (
    "in-addr.arpa", "ip6.arpa", ".rdns.", "broadband",
    "leasedline", "leased-line", "dedicated", "colo.", "-colo",
)

# Fallback prefixes: well-known Bangladeshi hosting / BDIX-member network
# blocks (Dhakacom, Link3, ADN, Aamra, BDCOM, ExonHost upstreams, ...).
# Used only when bgpview.io is unreachable. These are real BD allocations;
# even if a few age out, sampling them is harmless and bounded.
_FALLBACK_PREFIXES = [
    "103.4.144.0/22",    # Dhakacom
    "103.4.146.0/24",
    "103.7.148.0/22",    # Link3 Technologies
    "103.230.104.0/22",  # Link3
    "103.15.248.0/22",   # ADN Telecom
    "103.108.140.0/22",  # Aamra Networks
    "103.69.148.0/22",   # BDCOM Online
    "103.230.84.0/22",   # ExonHost / upstream BD
    "103.108.92.0/22",   # WebHostBD upstream
    "103.79.72.0/22",    # IS Pros / BD hosting
    "103.16.72.0/22",    # Cyber Internet (BD)
    "103.83.84.0/22",    # Skytel / BD
    "103.221.246.0/24",  # BD hosting
    "103.146.190.0/24",  # BD hosting
    "114.130.54.0/24",   # Fiber@Home / BD
    "114.31.32.0/22",    # Mango Teleservices (BD)
    "180.211.128.0/22",  # Telnet Communication (BD)
    "27.147.128.0/18",   # BTCL / national BD (broad — sampled lightly)
    "118.179.0.0/18",    # Grameen Cybernet / BD
    "203.76.96.0/20",    # BD national allocation
    "43.224.124.0/22",   # BD hosting
    "45.249.100.0/22",   # BD hosting
    "163.47.0.0/22",     # BD allocation
    "202.5.48.0/22",     # BD allocation
]


# ---------------------------------------------------------------------------
# Rotation state (so the queue keeps getting fresh address space)
# ---------------------------------------------------------------------------

def _load_state() -> dict:
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_state_field(key, value) -> None:
    state = _load_state()
    state[key] = value
    try:
        with open(STATE_FILE, "w", encoding="utf-8") as fh:
            json.dump(state, fh)
    except Exception as e:  # noqa: BLE001 - state is an optimization, not critical
        print(f"[reverse-ip] could not save state: {e}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Prefix discovery (bgpview.io, with hardcoded fallback)
# ---------------------------------------------------------------------------

def _get_json(url, timeout=40):
    """GET *url* and parse JSON. Returns the object or None (never raises)."""
    try:
        blob = http_get(url, timeout=timeout)
        return json.loads(blob.decode("utf-8", "replace"))
    except Exception as e:  # noqa: BLE001 - any failure → treat as "unavailable"
        print(f"[reverse-ip] fetch failed {url}: {e}", file=sys.stderr)
        return None


def _bd_asns() -> list[int]:
    """Return a list of BD ASNs (ints) from bgpview, best-effort."""
    data = _get_json(BGPVIEW_COUNTRY)
    if not isinstance(data, dict):
        return []
    payload = data.get("data") or {}
    asns = payload.get("asns") or []
    out = []
    for row in asns:
        if isinstance(row, dict) and isinstance(row.get("asn"), int):
            out.append(row["asn"])
    return out


def _asn_prefixes(asn) -> list[str]:
    """Return IPv4 prefix strings announced by *asn*, best-effort."""
    data = _get_json(BGPVIEW_ASN_PREFIXES.format(asn=asn))
    if not isinstance(data, dict):
        return []
    payload = data.get("data") or {}
    v4 = payload.get("ipv4_prefixes") or []
    out = []
    for row in v4:
        if isinstance(row, dict):
            p = row.get("prefix")
            if isinstance(p, str) and "/" in p:
                out.append(p)
    return out


def discover_prefixes() -> list[str]:
    """Discover BD prefixes via bgpview; fall back to the hardcoded list.

    Returns a de-duplicated, deterministically-ordered list of CIDR strings.
    Order is stable (sorted) so the rotation cursor in the state file maps to
    the same slice across runs.
    """
    prefixes: list[str] = []
    asns = _bd_asns()
    if asns:
        # Rotate which ASNs we expand each run so, over time, every BD ASN's
        # space gets covered without expanding hundreds of ASNs in one run.
        start = _load_state().get("asn_cursor", 0) % max(1, len(asns))
        rotated = asns[start:] + asns[:start]
        for asn in rotated[:MAX_ASNS_EXPANDED]:
            prefixes.extend(_asn_prefixes(asn))
            if len(set(prefixes)) >= MAX_PREFIXES * 4:
                # plenty to rotate through; stop hitting the API
                break
            time.sleep(0.4)  # be polite to the free bgpview endpoint
        # advance the ASN cursor for next run
        _save_state_field("asn_cursor", start + MAX_ASNS_EXPANDED)

    if not prefixes:
        print("[reverse-ip] bgpview unavailable — using fallback prefixes",
              file=sys.stderr)
        prefixes = list(_FALLBACK_PREFIXES)

    # validate + de-dup + stable order
    valid = set()
    for p in prefixes:
        try:
            net = ipaddress.ip_network(p, strict=False)
            if net.version == 4 and not (net.is_private or net.is_loopback
                                         or net.is_reserved):
                valid.add(str(net))
        except Exception:
            continue
    return sorted(
        valid,
        key=lambda c: (int(ipaddress.ip_network(c).network_address),
                       ipaddress.ip_network(c).prefixlen),
    )


def select_prefixes(all_prefixes) -> list[str]:
    """Take the next MAX_PREFIXES slice (rotating cursor), advance the cursor."""
    if not all_prefixes:
        return []
    n = len(all_prefixes)
    cursor = _load_state().get("prefix_cursor", 0) % n
    rotated = all_prefixes[cursor:] + all_prefixes[:cursor]
    chosen = rotated[:MAX_PREFIXES]
    _save_state_field("prefix_cursor", (cursor + len(chosen)) % n)
    return chosen


# ---------------------------------------------------------------------------
# IP sampling + reverse DNS
# ---------------------------------------------------------------------------

def sample_ips(prefixes, budget) -> list[str]:
    """Build a bounded, shuffled list of host IPs to probe across *prefixes*.

    Each /24-equivalent contributes up to SAMPLE_PER_24 sampled hosts so a
    huge /16 doesn't eat the whole budget. Total is capped at *budget*.
    """
    ips: list[str] = []
    for cidr in prefixes:
        if len(ips) >= budget:
            break
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except Exception:
            continue
        if net.version != 4:
            continue
        # split into /24s and sample within each
        try:
            if net.prefixlen >= 24:
                subnets = [net]
            else:
                subnets = list(net.subnets(new_prefix=24))
        except Exception:
            subnets = [net]

        # don't let a single mega-prefix expand into thousands of /24s
        random.shuffle(subnets)
        subnets = subnets[:64]

        for sub in subnets:
            if len(ips) >= budget:
                break
            try:
                hosts = list(sub.hosts())
            except Exception:
                continue
            if not hosts:
                continue
            k = min(SAMPLE_PER_24, len(hosts))
            for ip in random.sample(hosts, k):
                ips.append(str(ip))
                if len(ips) >= budget:
                    break
    random.shuffle(ips)
    return ips[:budget]


def _is_infra(host) -> bool:
    """True if PTR *host* looks like the provider's own infra (skip it)."""
    h = host.lower().strip(".")
    label = h.split(".", 1)[0]
    for sub in _INFRA_SUBSTR:
        if sub in h:
            return True
    for pre in _INFRA_PREFIXES:
        if label == pre or label.startswith(pre):
            return True
    # PTRs that are literally the dotted IP encoded as labels (e.g.
    # 1-2-3-4.host.net or 1.2.3.4.host.net) are infra/default rDNS — the first
    # label is all digits (and dashes/dots).
    stripped = label.replace("-", "").replace(".", "")
    if stripped.isdigit():
        return True
    return False


def _ptr(ip) -> str | None:
    """Reverse-DNS one IP. Returns hostname or None. Never raises."""
    try:
        host, _aliases, _addrs = socket.gethostbyaddr(ip)
        return host
    except (socket.herror, socket.gaierror, socket.timeout, OSError):
        return None
    except Exception:  # noqa: BLE001 - belt & suspenders, keep the pool alive
        return None


def reverse_sweep(ips) -> dict:
    """Reverse-DNS every IP in *ips* via a thread pool; return a dict of
    registrable-domain -> harvest-row for hosts that aren't provider infra."""
    socket.setdefaulttimeout(LOOKUP_TIMEOUT)
    domains: dict[str, dict] = {}
    if not ips:
        return domains

    workers = max(1, min(WORKERS, len(ips)))
    done = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_ptr, ip): ip for ip in ips}
        for fut in concurrent.futures.as_completed(futures):
            done += 1
            try:
                host = fut.result()
            except Exception:  # noqa: BLE001
                host = None
            if not host:
                continue
            if _is_infra(host):
                continue
            try:
                dom = registrable(host)
            except Exception:
                dom = None
            if not dom or dom in domains:
                continue
            # the domain resolved on a BD-hosted IP → ip_bd=True is the strong
            # signal this source contributes.
            domains[dom] = {
                "domain": dom,
                "bd_score": bd_score(dom, ip_bd=True),
            }
            if done % 500 == 0:
                print(f"[reverse-ip] probed {done}/{len(ips)}, "
                      f"{len(domains)} domains so far", file=sys.stderr)
    return domains


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main() -> int:
    all_prefixes = discover_prefixes()
    if not all_prefixes:
        print("[reverse-ip] no prefixes discovered — exiting cleanly",
              file=sys.stderr)
        return 0
    print(f"[reverse-ip] {len(all_prefixes)} BD prefixes available",
          file=sys.stderr)

    prefixes = select_prefixes(all_prefixes)
    print(f"[reverse-ip] scanning {len(prefixes)} prefixes this run",
          file=sys.stderr)

    ips = sample_ips(prefixes, MAX_IPS)
    print(f"[reverse-ip] sampled {len(ips)} IPs to probe", file=sys.stderr)
    if not ips:
        print("[reverse-ip] nothing to probe — exiting", file=sys.stderr)
        return 0

    t0 = time.time()
    domains = reverse_sweep(ips)
    dt = time.time() - t0
    print(f"[reverse-ip] reverse-DNS done in {dt:.0f}s — "
          f"{len(domains)} unique customer domains", file=sys.stderr)

    rows = list(domains.values())
    if not rows:
        print("[reverse-ip] no customer domains found this run", file=sys.stderr)
        return 0

    try:
        inserted = harvest(SOURCE, rows)
        print(f"[reverse-ip] done: {len(rows)} unique domains, "
              f"{inserted} inserted", file=sys.stderr)
    except Exception as e:  # noqa: BLE001
        print(f"[reverse-ip] harvest failed: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:  # noqa: BLE001 - top-level guard, exit clean
        print(f"[reverse-ip] fatal (handled): {e}", file=sys.stderr)
        sys.exit(0)
