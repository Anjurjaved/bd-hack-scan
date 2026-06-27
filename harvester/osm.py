#!/usr/bin/env python3
"""
osm.py — OpenStreetMap Overpass harvester for the Bangladesh-business
domain queue (legally the cleanest, highest-precision source).

It asks the Overpass API for every OSM element inside Bangladesh that
carries a `website` (or `contact:website`) tag, normalises each one to a
registrable domain, keeps the business name from `tags.name` when present,
and hands the result to lib.harvest('osm', ...).

Pure standard library only — all the heavy lifting (PSL / .com.bd handling,
dedup, POSTing to the Worker) lives in lib.py, which we import.

Env (provided at runtime): API_BASE, SHARED_TOKEN  (consumed by lib.harvest).
"""

import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

# Make `import lib` work no matter what the caller's CWD is.
sys.path.insert(0, os.path.dirname(__file__))

from lib import registrable, harvest, bd_score  # noqa: E402

SOURCE = "osm"

# Overpass mirrors, tried in order. The first is the canonical instance;
# the second is a fast independent mirror we fall back to on failure.
MIRRORS = [
    "https://overpass-api.de/api/interpreter",
    "https://overpass.kumi.systems/api/interpreter",
]

# Overpass QL: select the BD national area (admin_level=2, ISO3166-1=BD),
# then every node/way/relation inside it that has a website-ish tag, and
# emit only the tags (we don't need geometry).
OVERPASS_QL = (
    '[out:json][timeout:180];'
    'area["ISO3166-1"="BD"][admin_level=2]->.bd;'
    '('
    'nwr["website"](area.bd);'
    'nwr["contact:website"](area.bd);'
    ');'
    'out tags;'
)

# Safety cap so each run is BOUNDED and finishes fast. The Worker dedups,
# so re-running is cheap and idempotent — we never need everything at once.
MAX_ITEMS = 20000

# A generous overall budget for a single Overpass response (large body).
HTTP_TIMEOUT = 240

# Browser UA — some Overpass front-ends / CDNs 403 obvious bots.
UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)


def _query_overpass(url):
    """POST the QL to one Overpass mirror; return parsed JSON or None.

    Raises nothing — on any failure returns None so the caller can retry /
    move to the next mirror. Distinguishes "busy" HTTP codes (429/504/503/502)
    which are worth retrying.
    """
    body = urllib.parse.urlencode({"data": OVERPASS_QL}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "User-Agent": UA,
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            raw = resp.read()
        return json.loads(raw.decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        # 429 = rate limited, 504/503/502 = gateway busy → retryable.
        print(f"[osm] HTTP {e.code} from {url}", file=sys.stderr)
        return None
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        print(f"[osm] network error from {url}: {e}", file=sys.stderr)
        return None
    except (ValueError, json.JSONDecodeError) as e:
        print(f"[osm] bad JSON from {url}: {e}", file=sys.stderr)
        return None


def fetch_elements():
    """Hit Overpass with backoff (up to 3x per mirror, then next mirror).

    Returns the list of `elements` from the first successful response, or [].
    """
    for url in MIRRORS:
        for attempt in range(1, 4):  # up to 3 tries per mirror
            data = _query_overpass(url)
            if data and isinstance(data.get("elements"), list):
                els = data["elements"]
                print(f"[osm] {len(els)} elements from {url}", file=sys.stderr)
                return els
            # Exponential-ish backoff before retrying this mirror.
            wait = min(60, 5 * (2 ** (attempt - 1)))  # 5, 10, 20
            print(
                f"[osm] retry {attempt}/3 on {url} after {wait}s",
                file=sys.stderr,
            )
            time.sleep(wait)
    print("[osm] all mirrors failed", file=sys.stderr)
    return []


def collect(elements):
    """Turn Overpass elements into harvest items.

    Each item: {'domain': d, 'business': name, 'bd_score': n}.
    Dedup by domain locally (first business name wins); lib.harvest also
    dedups globally, but local dedup keeps the payload tight.
    """
    seen = {}
    for el in elements:
        if not isinstance(el, dict):
            continue
        tags = el.get("tags")
        if not isinstance(tags, dict):
            continue

        raw_url = tags.get("website") or tags.get("contact:website")
        if not raw_url:
            continue

        try:
            dom = registrable(raw_url)
        except Exception:
            dom = None
        if not dom:
            continue
        if dom in seen:
            continue

        name = tags.get("name") or ""
        if isinstance(name, str):
            name = name.strip()
        else:
            name = ""

        # OSM-tagged BD element → source is geographically BD. Mark it so
        # bd_score reflects the high confidence of this source.
        try:
            score = bd_score(dom, source_bd=True)
        except Exception:
            score = 0

        item = {"domain": dom, "business": name, "bd_score": score}
        seen[dom] = item

        if len(seen) >= MAX_ITEMS:
            break

    return list(seen.values())


def main():
    elements = fetch_elements()
    if not elements:
        print("[osm] nothing fetched — exiting cleanly", file=sys.stderr)
        return 0

    items = collect(elements)
    if not items:
        print("[osm] no registrable domains found", file=sys.stderr)
        return 0

    print(f"[osm] collected {len(items)} domains, handing to harvest()",
          file=sys.stderr)
    try:
        inserted = harvest(SOURCE, items)
        print(f"[osm] harvest inserted {inserted}", file=sys.stderr)
    except Exception as e:
        print(f"[osm] harvest failed: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())