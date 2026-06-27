#!/usr/bin/env python3
"""
scan.py — the scan engine that runs inside every GitHub-Actions job.

Stage-1 (detect.py, async, high concurrency) flags candidates -> Bayesian fuse +
genuine-vs-hacked heuristic (score.py) -> Stage-2 LLM verify (verify.py / Groq,
free, keeps the Gemini pool for voice) classifies each candidate:
  hacked_client  -> confirmed lead   |   genuine_spam / false_positive -> dropped
-> ingest -> heartbeat -> repeat until the queue is empty or the time budget ends.

Env: API_BASE, SHARED_TOKEN, GROQ_API_KEY, WORKER_ID, JOB_MINUTES(=300),
     SCAN_CONC(=50), VERIFY_CONC(=8), VERIFY_PROVIDER(=groq), DOMAIN_TIMEOUT(=90)
"""
import os
import sys
import json
import time
import asyncio
import httpx

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import detect
import score as scoring
import verify as verifier

API_BASE = os.environ.get("API_BASE", "").rstrip("/")
TOKEN = os.environ.get("SHARED_TOKEN", "")
WORKER_ID = os.environ.get("WORKER_ID", "job-" + str(os.getpid()))
JOB_SECONDS = int(os.environ.get("JOB_MINUTES", "300")) * 60
SCAN_CONC = int(os.environ.get("SCAN_CONC", "50"))
VERIFY_CONC = int(os.environ.get("VERIFY_CONC", "8"))
PROVIDER = os.environ.get("VERIFY_PROVIDER", "groq").lower()
DOMAIN_TIMEOUT = float(os.environ.get("DOMAIN_TIMEOUT", "90"))

_UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
AUTH = {"authorization": "Bearer " + TOKEN, "content-type": "application/json", "user-agent": _UA}


async def api(client, path, payload, tries=4):
    for i in range(tries):
        try:
            r = await client.post(API_BASE + path, json=payload, headers=AUTH, timeout=45.0)
            if r.status_code == 200:
                return r.json()
        except Exception:
            pass
        await asyncio.sleep(2 * (i + 1))
    return None


async def scan_batch(scan_client, llm_client, groq_pool, domains):
    sem = asyncio.Semaphore(SCAN_CONC)
    candidates = []   # (rec, res, sc) — Stage-1 flagged, domain-spammy already dropped
    errors = 0

    async def stage1(rec):
        nonlocal errors
        async with sem:
            try:
                res = await asyncio.wait_for(detect.scan_domain(scan_client, rec["domain"]), timeout=DOMAIN_TIMEOUT)
            except Exception:
                errors += 1
                return
            if res.get("error"):
                errors += 1
                return
            sigs = res.get("signals", [])
            if not sigs:
                return
            ctx = {"domain_spammy": res.get("domain_spammy"), "bd_signal": res.get("bd_signal")}
            sc = scoring.score(sigs, ctx)
            if sc["status"] == "clean":
                return
            if res.get("domain_spammy"):      # gambling brand IN the domain name = genuine spam, no LLM needed
                return
            candidates.append((rec, res, sc))

    await asyncio.gather(*(stage1(r) for r in domains))

    findings = []
    vsem = asyncio.Semaphore(VERIFY_CONC)
    use_groq = bool(PROVIDER == "groq" and groq_pool and groq_pool.keys)

    async def stage2(rec, res, sc):
        status, confirmed = sc["status"], sc["confirmed"]
        biz = res.get("biz_type", "")
        verdict = sc["verdict"]
        reason = "posterior=%.3f buckets=%d%s" % (sc["posterior"], sc["nbuckets"], " HARD" if sc["hard"] else "")
        if use_groq:
            async with vsem:
                v = await verifier.verify(groq_pool, llm_client, {
                    "domain": res["domain"], "business": rec.get("business", ""),
                    "layers": ",".join(sc["layers"]), "proof": sc["proof"],
                    "evidence": "; ".join(e.get("url", "") for e in sc.get("evidence", [])),
                    "excerpt": res.get("excerpt", ""),
                })
            if v:
                cls = v["classification"]
                if cls == "hacked_client":
                    status, confirmed = "lead", 1
                else:
                    return   # genuine_spam / false_positive -> not a sellable lead
                biz = v.get("business_type") or biz
                verdict = "groq-" + cls
                reason = "groq:%s — %s" % (cls, v.get("reason", ""))
            else:
                # Groq unavailable (rate-limited). Never promote an UNVERIFIED non-BD
                # gambling/adult hit to a confirmed lead — a genuine casino on WordPress
                # has the same doorway/REST signals as a hacked business. Park it for review.
                if sc["status"] == "spam_site":
                    return   # heuristic already dropped it
                if sc["category"] in ("gambling", "adult") and not res.get("bd_signal"):
                    status, confirmed, verdict = "review", 0, "unverified-" + sc["category"]
                    reason = "groq unavailable; non-BD %s parked for review" % sc["category"]
        elif sc["status"] == "spam_site":
            return

        findings.append({
            "domain": res["domain"], "business": rec.get("business", ""), "phone": rec.get("phone", ""),
            "category": sc["category"], "layers": ",".join(sc["layers"])[:200],
            "proof_snippet": sc["proof"], "proof_url": sc["proof_url"][:300],
            "http_status": res.get("http_status", 0), "stage1_score": sc["nbuckets"],
            "stage2_verdict": verdict[:20], "stage2_reason": reason[:400], "stage2_category": sc["category"],
            "confirmed": confirmed,
            "evidence": json.dumps(sc.get("evidence", []), ensure_ascii=False)[:4000],
            "is_bd": 1 if res.get("bd_signal") else 0, "biz_type": (biz or "")[:30], "status": status,
        })

    await asyncio.gather(*(stage2(*c) for c in candidates))
    return findings, errors


async def main():
    if not API_BASE or not TOKEN:
        print("FATAL: API_BASE and SHARED_TOKEN are required", file=sys.stderr)
        sys.exit(1)
    deadline = time.time() + JOB_SECONDS
    groq_pool = verifier.Pool() if PROVIDER == "groq" else None
    if groq_pool and groq_pool.keys:
        print(f"[{WORKER_ID}] Stage-2 = Groq ({len(groq_pool.keys)} keys, {verifier.MODEL})")
    else:
        print(f"[{WORKER_ID}] Stage-2 = heuristic only (no Groq keys)")
    scanned_total, empty_strikes = 0, 0

    limits = httpx.Limits(max_connections=SCAN_CONC * 6 + 20, max_keepalive_connections=40)
    async with httpx.AsyncClient(limits=limits, verify=False, follow_redirects=True) as scan_client, \
               httpx.AsyncClient() as llm_client, \
               httpx.AsyncClient() as ctl:
        while time.time() < deadline:
            claim = await api(ctl, "/claim", {"worker_id": WORKER_ID})
            if not claim or not claim.get("batch_id"):
                empty_strikes += 1
                print(f"[{WORKER_ID}] queue empty (strike {empty_strikes})")
                if empty_strikes >= 5:
                    break
                await asyncio.sleep(30)
                continue
            empty_strikes = 0
            bid, domains = claim["batch_id"], claim.get("domains", [])
            t0 = time.time()
            findings, errors = await scan_batch(scan_client, llm_client, groq_pool, domains)
            scanned = len(domains)
            scanned_total += scanned
            confirmed = sum(f["confirmed"] for f in findings)
            await api(ctl, "/ingest", {"batch_id": bid, "worker_id": WORKER_ID, "scanned": scanned,
                                       "errors": errors, "findings": findings, "pass_no": 1})
            await api(ctl, "/heartbeat", {"worker_id": WORKER_ID, "scanned_total": scanned_total,
                                          "current_batch": bid, "state": "running"})
            print(f"[{WORKER_ID}] batch {bid}: {scanned} scanned, {len(findings)} leads, "
                  f"{confirmed} confirmed, {errors} err, {time.time()-t0:.0f}s")

        async with httpx.AsyncClient() as c:
            await api(c, "/heartbeat", {"worker_id": WORKER_ID, "scanned_total": scanned_total, "state": "finished"})


if __name__ == "__main__":
    asyncio.run(main())
