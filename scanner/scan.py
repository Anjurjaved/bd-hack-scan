#!/usr/bin/env python3
"""
scan.py — the scan engine that runs inside every GitHub-Actions job.

Loop: claim a batch -> Stage-1 multi-layer scan each domain (detect.py, async,
high concurrency) -> Bayesian fuse to a verdict (score.py) -> ingest findings ->
heartbeat -> repeat until the queue is empty or the time budget ends.

Verdict mapping (NO external LLM; Gemini pool stays free for the user's voice work):
  CONFIRM_CANDIDATE -> confirmed=1   (hard signal, or posterior>=0.97 + 2 buckets)
  SUSPECT           -> needs-review  (surfaced on the dashboard, confirmed=0)
  CLEAN / NEEDS_BROWSER -> not flagged

Stateless: all state lives in Cloudflare D1 behind the Worker API. Many of these
run in parallel (the GitHub Actions matrix); each claims different batches.

Env: API_BASE, SHARED_TOKEN, WORKER_ID, JOB_MINUTES(=300), SCAN_CONC(=50), DOMAIN_TIMEOUT(=75)
"""
import os
import sys
import time
import asyncio
import httpx

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import detect
import score as scoring

API_BASE = os.environ.get("API_BASE", "").rstrip("/")
TOKEN = os.environ.get("SHARED_TOKEN", "")
WORKER_ID = os.environ.get("WORKER_ID", "job-" + str(os.getpid()))
JOB_SECONDS = int(os.environ.get("JOB_MINUTES", "300")) * 60
SCAN_CONC = int(os.environ.get("SCAN_CONC", "50"))
DOMAIN_TIMEOUT = float(os.environ.get("DOMAIN_TIMEOUT", "75"))

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


async def scan_batch(scan_client, domains):
    sem = asyncio.Semaphore(SCAN_CONC)
    findings = []
    errors = 0

    async def one(rec):
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
            sc = scoring.score(res.get("signals", []))
            if not sc["flagged"]:
                return
            findings.append({
                "domain": res["domain"], "business": rec.get("business", ""), "phone": rec.get("phone", ""),
                "category": sc["category"],
                "layers": ",".join(sc["layers"])[:200],
                "proof_snippet": sc["proof"],
                "proof_url": sc["proof_url"][:300],
                "http_status": res.get("http_status", 0),
                "stage1_score": sc["nbuckets"],
                "stage2_verdict": sc["verdict"],
                "stage2_reason": "posterior=%.3f buckets=%d%s" % (sc["posterior"], sc["nbuckets"], " HARD" if sc["hard"] else ""),
                "stage2_category": sc["category"],
                "confirmed": sc["confirmed"],
            })

    await asyncio.gather(*(one(r) for r in domains))
    return findings, errors


async def main():
    if not API_BASE or not TOKEN:
        print("FATAL: API_BASE and SHARED_TOKEN are required", file=sys.stderr)
        sys.exit(1)
    deadline = time.time() + JOB_SECONDS
    scanned_total, empty_strikes = 0, 0

    limits = httpx.Limits(max_connections=SCAN_CONC * 6 + 20, max_keepalive_connections=40)
    async with httpx.AsyncClient(limits=limits, verify=False, follow_redirects=True, http2=False) as scan_client, \
               httpx.AsyncClient() as ctl:
        while time.time() < deadline:
            claim = await api(ctl, "/claim", {"worker_id": WORKER_ID})
            if not claim or not claim.get("batch_id"):
                empty_strikes += 1
                print(f"[{WORKER_ID}] queue empty (strike {empty_strikes})")
                if empty_strikes >= 5:
                    print(f"[{WORKER_ID}] no work after retries, exiting")
                    break
                await asyncio.sleep(30)
                continue
            empty_strikes = 0
            bid, domains = claim["batch_id"], claim.get("domains", [])
            t0 = time.time()
            findings, errors = await scan_batch(scan_client, domains)
            scanned = len(domains)
            scanned_total += scanned
            confirmed = sum(f["confirmed"] for f in findings)
            await api(ctl, "/ingest", {"batch_id": bid, "worker_id": WORKER_ID, "scanned": scanned,
                                       "errors": errors, "findings": findings, "pass_no": 1})
            await api(ctl, "/heartbeat", {"worker_id": WORKER_ID, "scanned_total": scanned_total,
                                          "current_batch": bid, "state": "running"})
            print(f"[{WORKER_ID}] batch {bid}: {scanned} scanned, {len(findings)} flagged, "
                  f"{confirmed} confirmed, {errors} err, {time.time()-t0:.0f}s")

        async with httpx.AsyncClient() as c:
            await api(c, "/heartbeat", {"worker_id": WORKER_ID, "scanned_total": scanned_total, "state": "finished"})


if __name__ == "__main__":
    asyncio.run(main())
