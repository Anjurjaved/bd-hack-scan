#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
reclassify_existing.py — one-time cleanup of the leads already in D1.

The existing findings were produced by an OLDER scan that ran Stage-1 only (no
genuine-vs-hacked gate, no Groq Stage-2, no is_bd/biz_type). This re-runs JUST the
missing Stage-2 on each already-flagged domain:

  re-fetch homepage -> classify (domain_spammy / bd_signal / biz_type)
                    -> Groq verify (hacked_client | genuine_spam | false_positive)

Then it UPDATEs each finding in D1:
  genuine_spam / false_positive / domain-name-gambling -> status='rejected', confirmed=0  (dropped)
  hacked_client (or Groq down + heuristic-keep)        -> status='lead', confirmed=1,
                                                          is_bd + biz_type populated       (clean lead)

This instantly de-pollutes the live lead list (drops purpose-built gambling sites,
splits BD vs International, tags business type) without a multi-hour full re-scan.

Run:  GROQ_API_KEY=<comma-keys> python3 tools/reclassify_existing.py [--apply]
      (without --apply = dry-run summary only)
"""
import os
import re
import sys
import json
import html
import asyncio
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
WORKERS = os.path.join(ROOT, "workers")
sys.path.insert(0, os.path.join(ROOT, "scanner"))

import httpx                       # noqa: E402
import classify                    # noqa: E402
import verify as verifier          # noqa: E402

DB = "bd-hack-audit"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
CONC = int(os.environ.get("RECLASS_CONC", "12"))
APPLY = "--apply" in sys.argv

RE_TAGSTRIP = re.compile(r"(?is)<(script|style|noscript|template)\b.*?</\1>")
RE_TAGS = re.compile(r"(?s)<[^>]+>")
RE_WS = re.compile(r"\s+")
RE_TITLE = re.compile(r"(?is)<title[^>]*>(.*?)</title>")

# verify.py returns short business types ("general", "it", ...); normalize to the
# 16-category taxonomy + the two terminal buckets the dashboard expects.
BIZ_FIX = {"general": "general-business", "general-business": "general-business",
           "gambling": "gambling-site", "gambling-site": "gambling-site"}
VALID_BIZ = set(classify.PRIORITY) | {"general-business", "gambling-site"}

# A homepage-only LLM can wrongly call a doorway/cloaked hack a "false_positive"
# (the spam hides in inner pages it never saw). When the scanner fired a STRONG
# stealth/injection signal, trust the scanner and KEEP — only drop a false_positive
# when the original detection was weak (an incidental keyword). genuine_spam always drops.
STRONG_LAYERS = ("L11REST", "L11SITEMAP", "L2UACLOAK", "L3REFCLOAK", "L12IPCLOAK", "L13INNERCLOAK",
                 "L17HIDDEN", "L10DEFACE", "L14CAMPAIGN", "L8IFRAME", "L19SHELL", "L5DENSITY",
                 "L16FEED", "L20SCRIPT", "L20SHAPE", "L16HDR", "L20RELAY")


def strip_html(h):
    h = RE_TAGSTRIP.sub(" ", h)
    h = RE_TAGS.sub(" ", h)
    return RE_WS.sub(" ", html.unescape(h)).strip()


def d1(sql, as_json=True, file=None):
    cmd = ["npx", "--yes", "wrangler", "d1", "execute", DB, "--remote"]
    if as_json:
        cmd.append("--json")
    if file:
        cmd += ["--file", file]
    else:
        cmd += ["--command", sql]
    r = subprocess.run(cmd, cwd=WORKERS, capture_output=True, text=True)
    if r.returncode != 0:
        sys.stderr.write(r.stderr[-2000:] + "\n")
        raise SystemExit("wrangler d1 failed")
    if not as_json:
        return r.stdout
    # wrangler prints a JSON array: [ { results:[...], success, meta } ]
    txt = r.stdout
    s = txt.find("[")
    data = json.loads(txt[s:])
    return data[0]["results"]


async def fetch(client, domain):
    for u in ("https://" + domain, "http://" + domain):
        try:
            r = await client.get(u, headers={"user-agent": UA}, timeout=14.0)
            return r.text or ""
        except Exception:
            continue
    return ""


def sqlstr(s):
    return "'" + str(s or "").replace("'", "''") + "'"


async def process(client, pool, f, sem):
    async with sem:
        dom = f["domain"]
        reg = re.sub(r"^www\.", "", dom.lower())
        body = await fetch(client, dom)
        alive = bool(body)
        vis = strip_html(body)[:3000] if body else ""
        m = RE_TITLE.search(body or "")
        title = RE_WS.sub(" ", m.group(1)).strip()[:120] if m else ""

        spammy = classify.domain_spammy(reg)
        is_bd = 1 if classify.bd_signal(reg, vis) else 0
        biz = classify.biz_type(reg, title, vis)

        decision, reason, conf = None, "", 0
        if spammy:
            decision, reason = "reject", "domain-name is a gambling/adult brand"
        else:
            v = None
            if pool and pool.keys and alive:
                v = await verifier.verify(pool, client, {
                    "domain": dom, "business": f.get("business", ""),
                    "layers": f.get("layers", ""), "proof": f.get("proof_snippet", ""),
                    "evidence": f.get("proof_url", ""),
                    "excerpt": vis,
                })
            if v:
                cls = v.get("classification", "")
                conf = v.get("confidence") or 0
                reason = v.get("reason", "")
                gbiz = (v.get("business_type") or "").strip().lower()
                gbiz = BIZ_FIX.get(gbiz, gbiz)
                if gbiz in VALID_BIZ:
                    biz = gbiz
                has_strong = any(L in (f.get("layers") or "") for L in STRONG_LAYERS)
                if cls == "genuine_spam":
                    decision, reason = "reject", "groq:genuine_spam — %s" % reason
                elif cls == "false_positive" and not has_strong:
                    decision, reason = "reject", "groq:false_positive (weak signal) — %s" % reason
                elif cls == "false_positive":
                    decision, reason = "keep", "groq:fp but strong scanner signal kept — %s" % reason
                else:
                    decision = "keep"           # hacked_client / unknown -> keep
            elif not alive:
                decision, reason = "keep", "offline at re-scan (kept as-is)"
            else:
                decision, reason = "keep", "groq unavailable (heuristic keep)"

        biz = biz if biz in VALID_BIZ else "general-business"
        return {"id": f["id"], "domain": dom, "decision": decision, "is_bd": is_bd,
                "biz": biz, "reason": reason[:180], "conf": conf, "alive": alive}


async def main():
    keys = os.environ.get("GROQ_API_KEY", "")
    pool = verifier.Pool()
    print("Groq keys loaded: %d  model=%s" % (len(pool.keys), verifier.MODEL))
    if not pool.keys:
        print("WARNING: no Groq keys -> heuristic-only reclassify")

    rows = d1("SELECT id,domain,business,phone,category,layers,proof_snippet,proof_url FROM findings WHERE confirmed=1")
    print("fetched %d confirmed findings from D1" % len(rows))

    sem = asyncio.Semaphore(CONC)
    limits = httpx.Limits(max_connections=CONC * 3 + 10, max_keepalive_connections=20)
    async with httpx.AsyncClient(limits=limits, verify=False, follow_redirects=True) as client:
        results = []
        tasks = [process(client, pool, f, sem) for f in rows]
        done = 0
        for fut in asyncio.as_completed(tasks):
            r = await fut
            results.append(r)
            done += 1
            if done % 50 == 0:
                print("  ...%d/%d" % (done, len(rows)))

    keep = [r for r in results if r["decision"] == "keep"]
    drop = [r for r in results if r["decision"] == "reject"]
    bd = [r for r in keep if r["is_bd"]]
    intl = [r for r in keep if not r["is_bd"]]
    from collections import Counter
    bizc = Counter(r["biz"] for r in keep)
    print("\n==== RECLASSIFY SUMMARY ====")
    print("kept (clean leads): %d   (BD %d · International %d)" % (len(keep), len(bd), len(intl)))
    print("dropped (genuine gambling / false positive): %d" % len(drop))
    print("business types:", dict(bizc.most_common()))
    print("\nsample drops:")
    for r in drop[:20]:
        print("  DROP %-38s %s" % (r["domain"], r["reason"]))
    print("\nsample BD leads:")
    for r in bd[:12]:
        print("  KEEP %-38s biz=%s" % (r["domain"], r["biz"]))

    if not APPLY:
        print("\n(dry-run — re-run with --apply to write these to D1)")
        return

    # ---- write updates to D1 in chunked SQL files ----
    stmts = []
    for r in results:
        if r["decision"] == "reject":
            stmts.append("UPDATE findings SET status='rejected', confirmed=0 WHERE id=%d;" % r["id"])
        else:
            stmts.append("UPDATE findings SET status='lead', confirmed=1, is_bd=%d, biz_type=%s WHERE id=%d;"
                         % (r["is_bd"], sqlstr(r["biz"]), r["id"]))
    os.makedirs("/tmp/reclass", exist_ok=True)
    CH = 80
    nf = 0
    for i in range(0, len(stmts), CH):
        nf += 1
        fp = "/tmp/reclass/chunk_%03d.sql" % nf
        with open(fp, "w") as fh:
            fh.write("\n".join(stmts[i:i + CH]) + "\n")
        d1(None, as_json=False, file=fp)
        print("applied chunk %d (%d stmts)" % (nf, len(stmts[i:i + CH])))
    # recompute the headline confirmed counter from the cleaned table
    d1("UPDATE counters SET value=(SELECT COUNT(*) FROM findings WHERE confirmed=1 AND status!='rejected') WHERE metric='total_confirmed'", as_json=False)
    print("\nDONE — D1 updated. total_confirmed counter recomputed.")


if __name__ == "__main__":
    asyncio.run(main())
