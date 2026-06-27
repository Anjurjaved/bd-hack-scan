#!/usr/bin/env python3
"""
harvester/crtsh.py — Certificate-Transparency harvester (FREE, no key).

crt.sh exposes the public Certificate Transparency logs as JSON. Every TLS
certificate ever issued for a hostname is logged there, so a single wildcard
query for a Bangladesh ccTLD label (e.g. `%.com.bd`) returns thousands of
Bangladeshi business domains at once. This is the single biggest .bd firehose
available for free, so it's the workhorse that keeps the scanner queue full.

Strategy (all free, all bounded):
  Query EACH Bangladesh ccTLD second-level label separately so we miss none:
      com.bd  net.bd  org.bd  edu.bd  ac.bd  gov.bd  mil.bd
  plus the bare `bd` zone (catches any other / unusual .bd hostnames).
  For each query we hit:
      https://crt.sh/?q=%25.<label>&output=json
  (%25 is the URL-encoded `%` SQL wildcard crt.sh expects.)

For every row in the JSON response we split `name_value` on newlines (it holds
the cert's SANs, one host per line), run each host through lib.registrable()
(PSL-aware, so `*.com.bd` collapses correctly), and collect the uniques.

crt.sh is SLOW and FLAKY, so every query gets a long (60s) timeout and 2-3
retries; if a label still times out we just skip it and keep going — one bad
label never aborts the run. Results are deduped across all labels, then handed
to lib.harvest('crtsh', ...) which normalizes/dedups again and POSTs to the
Worker in chunks. The Worker dedups globally, so re-running is cheap and
idempotent. The run is capped at ~50k domains so it finishes fast.

Env (provided at runtime): API_BASE, SHARED_TOKEN  (consumed by lib.harvest).
Optional env:
  CRTSH_MAX_DOMAINS   cap on domains collected per run (default 50000)
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.parse

# Make `import lib` work no matter what the caller's CWD is.
sys.path.insert(0, os.path.dirname(__file__))

from lib import bd_score, harvest, http_get, registrable  # noqa: E402

SOURCE = "crtsh"

# crt.sh JSON endpoint. We pre-build the URL with an already-URL-encoded query
# so the literal `%` SQL wildcard arrives as `%25`.
CRTSH_URL = "https://crt.sh/?q={q}&output=json"

# Every Bangladesh ccTLD second-level label, queried one at a time so we never
# miss a zone. The bare `bd` zone is queried as `%.bd` too — that also sweeps
# up the second-level zones, but querying each label explicitly is far more
# reliable against crt.sh's flaky paging than one giant `%.bd` query.
BD_LABELS = [
    "com.bd",
    "net.bd",
    "org.bd",
    "edu.bd",
    "ac.bd",
    "gov.bd",
    "mil.bd",
    "bd",          # bare zone — catches anything not under the labels above
]

# Per-query network budget. crt.sh is slow; give it room and retry a few times.
HTTP_TIMEOUT = 60          # seconds per attempt (long — crt.sh is slow)
RETRIES = 3                # attempts per label before we skip it
RETRY_BASE_WAIT = 5        # seconds; grows 5, 10, 15 between attempts
POLITE_PAUSE = 2           # seconds between labels (be kind to the free API)

# Safety cap so each run is BOUNDED and finishes fast. The Worker dedups, so we
# never need everything at once.
DEFAULT_MAX_DOMAINS = 50000


def _query_url(label: str) -> str:
    """Build the crt.sh URL for one ccTLD label: q=%25.<label> (or %25.bd)."""
    # We want the raw query string `%.<label>`; quote() turns `%` into `%25`.
    raw_q = f"%.{label}"
    return CRTSH_URL.format(q=urllib.parse.quote(raw_q, safe=""))


def _names_from_json(blob: bytes) -> list[str]:
    """Pull every hostname out of a crt.sh JSON response.

    crt.sh returns a JSON array of rows; each row's `name_value` holds the
    cert's Subject Alternative Names, newline-separated. We also read
    `common_name` for good measure. Never raises — on a malformed/truncated
    body we salvage what we can and return whatever we got.
    """
    names: list[str] = []
    if not blob:
        return names
    try:
        data = json.loads(blob)
    except Exception:
        return names
    if not isinstance(data, list):
        return names
    for row in data:
        if not isinstance(row, dict):
            continue
        val = row.get("name_value")
        if val:
            # name_value is newline-separated SANs — split on newlines.
            names.extend(str(val).splitlines())
        cn = row.get("common_name")
        if cn:
            names.append(str(cn))
    return names


def _fetch_label(label: str) -> list[str]:
    """Fetch one crt.sh label query with retries; returns raw hostnames.

    Never raises: on repeated failure / timeout it logs and returns [] so the
    overall run continues to the next label.
    """
    url = _query_url(label)
    for attempt in range(1, RETRIES + 1):
        try:
            blob = http_get(url, timeout=HTTP_TIMEOUT)
            names = _names_from_json(blob)
            return names
        except Exception as e:  # noqa: BLE001 — never crash the whole run
            if attempt < RETRIES:
                wait = RETRY_BASE_WAIT * attempt  # 5, 10, 15
                print(
                    f"[crtsh] label {label!r} attempt {attempt}/{RETRIES} "
                    f"failed: {e} — retry in {wait}s",
                    file=sys.stderr,
                )
                time.sleep(wait)
            else:
                print(
                    f"[crtsh] label {label!r} gave up after {RETRIES} tries "
                    f"({e}) — skipping",
                    file=sys.stderr,
                )
    return []


def main() -> int:
    max_domains = int(os.environ.get("CRTSH_MAX_DOMAINS", str(DEFAULT_MAX_DOMAINS)))

    collected: dict[str, dict] = {}   # registrable domain -> harvest row

    for label in BD_LABELS:
        if len(collected) >= max_domains:
            print(f"[crtsh] cap {max_domains} reached — stopping label sweep",
                  file=sys.stderr)
            break

        raw_names = _fetch_label(label)
        added = 0
        for raw in raw_names:
            try:
                dom = registrable(raw)
            except Exception:
                dom = None
            if not dom or dom in collected:
                continue
            # Every host pulled from a .bd-label cert is a BD-zone domain, so
            # mark the source as BD and (for .bd registrables) flag the strong
            # ccTLD signal so bd_score reflects high confidence.
            is_bd_zone = dom.endswith(".bd")
            try:
                score = bd_score(dom, source_bd=True, ip_bd=is_bd_zone)
            except Exception:
                score = 0
            collected[dom] = {"domain": dom, "bd_score": score}
            added += 1
            if len(collected) >= max_domains:
                break

        print(f"[crtsh] {('%.' + label)!r}: +{added} new "
              f"(total {len(collected)})", file=sys.stderr)

        # Be polite to the free crt.sh endpoint between labels.
        time.sleep(POLITE_PAUSE)

    rows = list(collected.values())
    if not rows:
        print("[crtsh] nothing collected this run — exiting cleanly",
              file=sys.stderr)
        return 0

    print(f"[crtsh] collected {len(rows)} unique domains, handing to harvest()",
          file=sys.stderr)
    try:
        inserted = harvest(SOURCE, rows)
        print(f"[crtsh] done: {len(rows)} unique, {inserted} inserted",
              file=sys.stderr)
    except Exception as e:  # noqa: BLE001
        print(f"[crtsh] harvest failed: {e}", file=sys.stderr)
        return 0
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:  # noqa: BLE001 — top-level guard, exit clean
        print(f"[crtsh] fatal (handled): {e}", file=sys.stderr)
        sys.exit(0)
