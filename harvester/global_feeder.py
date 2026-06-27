#!/usr/bin/env python3
"""
global_feeder.py — paced feed of the TOP-RANKED GLOBAL domain list into the queue,
to run AFTER the Bangladesh sources have filled the BD slice. Walks
harvester/data/global_ranked_top1m.txt.gz with a server-side cursor (Worker /cursor)
so each run feeds only a bounded chunk — this respects D1's 100k-rows-written/day
free cap. Top-ranked first = the most important real businesses get scanned first.
"""
import os
import sys
import gzip
import json
import urllib.request

sys.path.insert(0, os.path.dirname(__file__))
import lib

SOURCE = "global-ranked"
DATA = os.path.join(os.path.dirname(__file__), "data", "global_ranked_top1m.txt.gz")
CHUNK = int(os.environ.get("GLOBAL_CHUNK", "25000"))


def _cursor(payload):
    body = json.dumps(payload).encode()
    req = urllib.request.Request(lib.API + "/cursor", body,
                                 {"authorization": "Bearer " + lib.token(), "content-type": "application/json", "user-agent": lib.UA})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read()).get("cursor")
    except Exception as e:
        print("cursor call failed:", e)
        return None


def main():
    if not os.path.exists(DATA):
        print("[global] no data file:", DATA)
        return
    c = _cursor({"source": SOURCE})
    offset = int(c) if c and str(c).isdigit() else 0
    print(f"[global] cursor at {offset}, feeding next {CHUNK}")

    chunk = []
    with gzip.open(DATA, "rt", encoding="utf-8", errors="ignore") as f:
        for i, line in enumerate(f):
            if i < offset:
                continue
            if i >= offset + CHUNK:
                break
            d = line.strip()
            if d:
                chunk.append(d)

    if not chunk:
        print("[global] reached end of list — looping cursor back to 0")
        _cursor({"source": SOURCE, "cursor": "0"})
        return

    lib.harvest(SOURCE, chunk)
    _cursor({"source": SOURCE, "cursor": str(offset + CHUNK)})
    print(f"[global] advanced cursor to {offset + CHUNK}")


if __name__ == "__main__":
    main()
