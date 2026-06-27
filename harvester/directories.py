#!/usr/bin/env python3
"""
harvester/directories.py — Bangladesh business-DIRECTORY sitemap harvester (FREE).

BD yellow-pages / business-directory sites publish a sitemap that lists every
company's profile/listing page, and each of those pages exposes the business's
OWN external website. That means we get a real business domain with ZERO
name->domain guessing — the directory already did the mapping for us.

Sources (all verified to expose listing URLs via XML sitemaps):
  (1) bdtradeinfo.com          — /sitemap-yellow-pages.xml -> ~21,555 /company/ profiles
  (2) businessdirectory.com.bd — /wp-sitemap.xml -> ait-item sub-sitemaps -> /item/ (~19,027)
  (3) bdbusinessdirectory.com  — /sitemap_index.xml -> at_biz_dir listings (~5,400)
  (4) kagoz.com                — /sitemap/business/1.xml & 2.xml (~1,338)

Per run we:
  - fetch the sitemap(s) for each source (regex out <loc>...</loc>),
  - take a BOUNDED, ROUND-ROBIN slice of listing URLs (different runs cover
    different listings via a persisted offset, so the queue keeps filling),
  - fetch each listing page in parallel and regex out the business's own
    website (JSON-LD `url`, a "Web:" / "Website" field, or an outbound <a href>),
  - registrable() it (which already returns None for the directory's own host,
    socials and CDNs, so we just skip None),
  - hand everything to lib.harvest('directories', [...]).

Each directory is an isolated try/except island: one source failing never
aborts the others, and one bad page never aborts a source. Re-running is cheap
and idempotent — the Worker dedups — so the only job here is to keep feeding it.

Pure standard library + tldextract (the latter only via lib.registrable()).
All the heavy lifting (PSL / .com.bd handling, dedup, POSTing) lives in lib.py.

Env (provided at runtime, consumed inside lib.harvest): API_BASE, SHARED_TOKEN
Optional env:
  DIRECTORIES_MAX_LISTINGS   total listing pages fetched per run (default 1500)
  DIRECTORIES_WORKERS        parallel fetch threads (default 16)
"""

from __future__ import annotations

import html
import json
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(__file__))  # make `import lib` work in CI

from lib import bd_score, harvest, http_get, registrable  # noqa: E402

SOURCE = "directories"

# ---------------------------------------------------------------------------
# Tunables (every run stays BOUNDED so it finishes fast and is idempotent)
# ---------------------------------------------------------------------------

# Hard cap on TOTAL listing pages fetched across all four sources per run.
MAX_LISTINGS = int(os.environ.get("DIRECTORIES_MAX_LISTINGS", "1500"))

# Parallel page fetches. The work is network-bound, so threads help a lot;
# kept modest to stay polite to these small directory hosts.
WORKERS = max(1, int(os.environ.get("DIRECTORIES_WORKERS", "16")))

# Per-request timeouts.
SITEMAP_TIMEOUT = 45      # sitemap XML can be a few MB
PAGE_TIMEOUT = 20         # individual listing page

# Cap on sitemap bytes we bother to parse (defensive against a giant index).
MAX_SITEMAP_BYTES = 16 * 1024 * 1024

# Where we persist the round-robin offset per source so consecutive runs walk
# through DIFFERENT listings instead of re-fetching the same first N each time.
STATE_FILE = os.path.join(os.path.dirname(__file__), ".directories_state.json")


# ---------------------------------------------------------------------------
# Regexes (compiled once)
# ---------------------------------------------------------------------------

_LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.I)

# JSON-LD "url":"https://business.example/..." (LocalBusiness/Organization etc.)
_JSONLD_URL_RE = re.compile(r'"url"\s*:\s*"([^"]+)"', re.I)

# A labelled website field on the profile page: "Web:", "Website:", "Web site:".
_WEB_FIELD_RE = re.compile(
    r"(?:web(?:\s*site)?|website|url)\s*[:\-]?\s*"
    r"(?:</[^>]+>\s*)*"                       # allow a closing tag between label & value
    r"(?:<a[^>]+href=['\"])?"                 # optional anchor
    r"\s*((?:https?://)?[a-z0-9.\-]+\.[a-z]{2,}[^\s'\"<>]*)",
    re.I,
)

# Generic outbound link.
_HREF_RE = re.compile(r"<a\b[^>]*\bhref\s*=\s*['\"]([^'\"]+)['\"]", re.I)

# Optional business name from JSON-LD / og:title / <title>.
_OG_TITLE_RE = re.compile(
    r'<meta[^>]+property=["\']og:title["\'][^>]+content=["\']([^"\']+)["\']', re.I
)
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_JSONLD_NAME_RE = re.compile(r'"name"\s*:\s*"([^"]+)"', re.I)


# ---------------------------------------------------------------------------
# Host blocklist (skip the directory's own host + obvious non-business hosts).
# registrable() already returns None for many of these, but matching on the
# raw host first saves a normalize call and is explicit about intent.
# ---------------------------------------------------------------------------

# Social / CDN / aggregator hosts whose registrable domain is NOT a customer
# website. Tested by substring against the raw host.
_BLOCK_HOST_SUBSTR = (
    "facebook.", "fb.com", "fb.me", "instagram.", "twitter.", "x.com",
    "linkedin.", "youtube.", "youtu.be", "wa.me", "whatsapp.", "t.me",
    "telegram.", "pinterest.", "tiktok.", "google.", "goo.gl", "maps.app",
    "g.page", "bit.ly", "tinyurl.", "gravatar.", "wp.com", "w.org",
    "wordpress.org", "gstatic.", "googleapis.", "doubleclick.",
    "schema.org", "example.com", "cloudflare", "jsdelivr.", "unpkg.",
    "fontawesome.", "bootstrapcdn.", "jquery.", "gmpg.org", "yoast.com",
    "cdninstagram.", "fbcdn.", "ggpht.",
)


def _host_of(url: str) -> str:
    """Lowercase host portion of a URL/href (no scheme, no path/port)."""
    s = (url or "").strip().lower()
    s = re.sub(r"^[a-z][a-z0-9+.\-]*://", "", s)
    s = s.split("/")[0].split("?")[0].split("#")[0]
    s = s.split("@")[-1].split(":")[0]
    return s.strip().strip(".")


def _is_blocked_host(host: str) -> bool:
    return any(b in host for b in _BLOCK_HOST_SUBSTR)


# ---------------------------------------------------------------------------
# Round-robin state
# ---------------------------------------------------------------------------

def _load_state() -> dict:
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_state(state: dict) -> None:
    # Best-effort: a read-only sandbox simply skips this and falls back to a
    # time-derived offset on the next run.
    try:
        with open(STATE_FILE, "w", encoding="utf-8") as fh:
            json.dump(state, fh)
    except Exception:
        pass


def _rotate(urls: list, source_key: str, take: int, state: dict) -> list:
    """Return `take` URLs starting at the persisted offset for *source_key*,
    wrapping around. Advance the stored offset so the next run continues where
    this one stopped. Falls back to a time-derived offset if no state exists.
    """
    n = len(urls)
    if n == 0 or take <= 0:
        return []
    if take >= n:
        # Small directory — just take everything; offset is irrelevant.
        state[source_key] = 0
        return list(urls)
    start = state.get(source_key)
    if not isinstance(start, int) or start < 0:
        # No usable saved offset (e.g. read-only FS) -> spread by wall clock.
        start = int(time.time() // 60) % n
    start %= n
    end = start + take
    if end <= n:
        out = urls[start:end]
    else:
        out = urls[start:] + urls[: end - n]
    state[source_key] = end % n
    return out


# ---------------------------------------------------------------------------
# Sitemap helpers
# ---------------------------------------------------------------------------

def _fetch_locs(url: str, timeout: int = SITEMAP_TIMEOUT) -> list:
    """Fetch a sitemap (or sitemap index) and return every <loc> URL.

    Never raises — returns [] on any failure.
    """
    try:
        blob = http_get(url, timeout=timeout)
    except Exception as e:  # noqa: BLE001
        print(f"[directories]   sitemap fetch failed {url}: {e}", file=sys.stderr)
        return []
    if not blob:
        return []
    if len(blob) > MAX_SITEMAP_BYTES:
        blob = blob[:MAX_SITEMAP_BYTES]
    text = blob.decode("utf-8", "ignore")
    out = []
    for m in _LOC_RE.findall(text):
        loc = html.unescape(m).strip()
        if loc:
            out.append(loc)
    return out


def _expand_index(index_url: str, child_filter, max_children: int = 80) -> list:
    """Given a sitemap-INDEX URL, fetch child sub-sitemaps that match
    *child_filter* (a predicate on the child URL) and return all their <loc>s.

    Bounded by *max_children* sub-sitemaps so a huge index can't blow the run.
    If no child matches the filter, the index was actually a flat listing
    sitemap, so its own <loc>s are returned.
    """
    children = _fetch_locs(index_url)
    if not children:
        return []
    picked = [c for c in children if child_filter(c)]
    if not picked:
        return children
    picked = picked[:max_children]
    locs = []
    for child in picked:
        locs.extend(_fetch_locs(child))
    return locs


# ---------------------------------------------------------------------------
# Listing-page parsing
# ---------------------------------------------------------------------------

def _business_name(text: str) -> str:
    """Best-effort business name (JSON-LD name > og:title > <title>)."""
    m = _JSONLD_NAME_RE.search(text)
    if m:
        name = html.unescape(m.group(1)).strip()
        if name:
            return name[:200]
    m = _OG_TITLE_RE.search(text)
    if m:
        name = html.unescape(m.group(1)).strip()
        if name:
            return name[:200]
    m = _TITLE_RE.search(text)
    if m:
        name = re.sub(r"\s+", " ", html.unescape(m.group(1))).strip()
        # trim common " | Directory Name" / " - Directory Name" suffixes
        name = re.split(r"\s+[|\-–—]\s+", name)[0].strip()
        if name:
            return name[:200]
    return ""


def _extract_website(text: str, directory_apex: str):
    """Return the business's own registrable domain from listing-page *text*,
    or None. *directory_apex* is the directory's own registrable domain so we
    never harvest the directory back onto itself.

    Candidate sources, in confidence order:
      1. JSON-LD `"url": ...`   (structured, usually the business site)
      2. a labelled "Web:" / "Website:" field on the profile
      3. any outbound <a href> to a non-blocked, off-directory registrable domain
    """
    candidates = []
    candidates.extend(_JSONLD_URL_RE.findall(text))
    candidates.extend(_WEB_FIELD_RE.findall(text))
    # hrefs come last (noisiest) and are capped so a link-farm page is cheap.
    candidates.extend(_HREF_RE.findall(text)[:400])

    for raw in candidates:
        raw = html.unescape((raw or "").strip())
        if not raw or raw.startswith(("#", "mailto:", "tel:", "javascript:")):
            continue
        host = _host_of(raw)
        if not host or "." not in host:
            continue
        if _is_blocked_host(host):
            continue
        # Skip self-links back to the directory (and its subdomains).
        if directory_apex and (host == directory_apex
                               or host.endswith("." + directory_apex)):
            continue
        dom = registrable(raw)
        if not dom:
            continue
        # registrable() may still hand back the directory's own apex.
        if directory_apex and dom == directory_apex:
            continue
        if _is_blocked_host(dom):
            continue
        return dom

    return None


def _fetch_listing(url: str, directory_apex: str):
    """Fetch one listing page and pull out (domain, business). Never raises."""
    try:
        blob = http_get(url, timeout=PAGE_TIMEOUT)
    except Exception:
        return None
    if not blob:
        return None
    text = blob.decode("utf-8", "ignore")
    dom = _extract_website(text, directory_apex)
    if not dom:
        return None
    return dom, _business_name(text)


# ---------------------------------------------------------------------------
# Source definitions — each returns the full list of listing-page URLs
# ---------------------------------------------------------------------------

def _listing_urls_bdtradeinfo() -> list:
    """bdtradeinfo.com — flat yellow-pages sitemap of /company/ profiles."""
    locs = _fetch_locs("https://bdtradeinfo.com/sitemap-yellow-pages.xml")
    keep = [u for u in locs if "/company/" in u]
    return keep or locs


def _listing_urls_businessdirectory() -> list:
    """businessdirectory.com.bd — WP sitemap index -> ait-item -> /item/ listings."""
    def is_item_child(u: str) -> bool:
        lu = u.lower()
        return "ait-item" in lu or "ait_item" in lu or "item" in lu
    locs = _expand_index(
        "https://businessdirectory.com.bd/wp-sitemap.xml", is_item_child
    )
    keep = [u for u in locs if "/item/" in u]
    return keep or locs


def _listing_urls_bdbusinessdirectory() -> list:
    """bdbusinessdirectory.com — Yoast-style index -> at_biz_dir listings."""
    def is_biz_child(u: str) -> bool:
        lu = u.lower()
        return ("at_biz_dir" in lu or "biz_dir" in lu
                or "directory" in lu or "listing" in lu)
    locs = _expand_index(
        "https://bdbusinessdirectory.com/sitemap_index.xml", is_biz_child
    )
    keep = [u for u in locs
            if "at_biz_dir" in u.lower() or "/directory/" in u.lower()]
    return keep or locs


def _listing_urls_kagoz() -> list:
    """kagoz.com — two static business sub-sitemaps (needs the browser UA)."""
    locs = []
    for n in (1, 2):
        locs.extend(_fetch_locs(f"https://kagoz.com/sitemap/business/{n}.xml"))
    return locs


# (source-key, sitemap-loader, directory host, per-source listing-page budget)
SOURCES = [
    ("bdtradeinfo",         _listing_urls_bdtradeinfo,         "bdtradeinfo.com",          450),
    ("businessdirectory",   _listing_urls_businessdirectory,   "businessdirectory.com.bd", 450),
    ("bdbusinessdirectory", _listing_urls_bdbusinessdirectory, "bdbusinessdirectory.com",  350),
    ("kagoz",               _listing_urls_kagoz,               "kagoz.com",                350),
]


# ---------------------------------------------------------------------------
# Per-source harvest (isolated island)
# ---------------------------------------------------------------------------

def _process_source(key, loader, dir_host, budget, state, remaining):
    """Collect {domain: row} for one directory. Never raises.

    *remaining* caps how many listing pages this source may still consume from
    the global MAX_LISTINGS budget. Returns (rows_dict, pages_fetched).
    """
    take = min(budget, remaining)
    if take <= 0:
        return {}, 0

    try:
        all_urls = loader()
    except Exception as e:  # noqa: BLE001
        print(f"[directories] {key}: sitemap step failed: {e}", file=sys.stderr)
        return {}, 0

    if not all_urls:
        print(f"[directories] {key}: no listing URLs found", file=sys.stderr)
        return {}, 0

    # De-dup while preserving order, then take a rotating slice.
    seen_u, ordered = set(), []
    for u in all_urls:
        if u not in seen_u:
            seen_u.add(u)
            ordered.append(u)

    batch = _rotate(ordered, key, take, state)
    print(f"[directories] {key}: {len(ordered)} listings in sitemap; "
          f"fetching {len(batch)} this run", file=sys.stderr)

    dir_apex = registrable(dir_host) or dir_host
    found: dict[str, dict] = {}

    try:
        with ThreadPoolExecutor(max_workers=WORKERS) as pool:
            futs = {pool.submit(_fetch_listing, u, dir_apex): u for u in batch}
            for fut in as_completed(futs):
                try:
                    res = fut.result()
                except Exception:
                    res = None
                if not res:
                    continue
                dom, name = res
                if dom in found:
                    continue
                try:
                    score = bd_score(dom, source_bd=True)
                except Exception:
                    score = 0
                row = {"domain": dom, "bd_score": score}
                if name:
                    row["business"] = name
                found[dom] = row
    except Exception as e:  # noqa: BLE001 — pool-level guard
        print(f"[directories] {key}: fetch pool error: {e}", file=sys.stderr)

    print(f"[directories] {key}: +{len(found)} business domains "
          f"from {len(batch)} pages", file=sys.stderr)
    return found, len(batch)


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main() -> int:
    state = _load_state()
    collected: dict[str, dict] = {}
    used = 0  # listing pages consumed so far this run

    for key, loader, dir_host, budget in SOURCES:
        remaining = MAX_LISTINGS - used
        if remaining <= 0:
            print(f"[directories] global listing budget exhausted, "
                  f"skipping {key}", file=sys.stderr)
            break
        rows, fetched = _process_source(
            key, loader, dir_host, budget, state, remaining
        )
        used += fetched
        for dom, row in rows.items():
            collected.setdefault(dom, row)

    _save_state(state)

    rows = list(collected.values())
    if not rows:
        print("[directories] nothing collected this run", file=sys.stderr)
        return 0

    print(f"[directories] collected {len(rows)} unique business domains "
          f"from {used} pages, handing to harvest()", file=sys.stderr)
    try:
        inserted = harvest(SOURCE, rows)
    except Exception as e:  # noqa: BLE001
        print(f"[directories] harvest failed: {e}", file=sys.stderr)
        return 1
    print(f"[directories] done: {len(rows)} unique, {inserted} inserted",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    try:
        main()
    except Exception as e:  # noqa: BLE001 — top-level guard, exit clean
        print(f"[directories] fatal (handled): {e}", file=sys.stderr)
        sys.exit(0)
