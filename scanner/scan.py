#!/usr/bin/env python3
"""
scan.py — the scan engine that runs inside every GitHub-Actions job.

Loop:  claim a batch -> Stage-1 scan all its domains (async, high concurrency)
       -> classify flagged -> ingest results -> heartbeat -> repeat until the
       queue is empty or the time budget ends.

Stage-2 verdict (NO external LLM by default, so the Gemini pool stays free for
the user's voice work):
  * STRONG layers (cloaking, gambling iframe, sitemap doorway, search-density,
    defacement, malware host) -> AUTO-CONFIRMED (verbatim proof is conclusive).
  * WEAK keyword-only / foreign-title / plain redirect -> "needs-review" (shown
    on the dashboard for a human glance), confirmed=0.
  * Optional: set VERIFY_PROVIDER=groq (+GROQ_API_KEY) to LLM-verify the weak
    bucket via verify.py — never touches Gemini.

Stateless: all state lives in Cloudflare D1 behind the Worker API. Many of these
run in parallel (the GitHub Actions matrix); each claims different batches.

Env: API_BASE, SHARED_TOKEN, WORKER_ID, JOB_MINUTES(=300), SCAN_CONC(=120),
     VERIFY_CONC(=6), VERIFY_PROVIDER(=none|groq|cerebras|openrouter)
"""
import os
import sys
import time
import asyncio
import httpx

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import detect

API_BASE = os.environ.get("API_BASE", "").rstrip("/")
TOKEN = os.environ.get("SHARED_TOKEN", "")
WORKER_ID = os.environ.get("WORKER_ID", "job-" + str(os.getpid()))
JOB_SECONDS = int(os.environ.get("JOB_MINUTES", "300")) * 60
SCAN_CONC = int(os.environ.get("SCAN_CONC", "120"))
VERIFY_CONC = int(os.environ.get("VERIFY_CONC", "6"))
PROVIDER = os.environ.get("VERIFY_PROVIDER", "none").lower()

# Cloudflare's edge 403s bot User-Agents; present a browser UA on Worker API calls.
_UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
AUTH = {"authorization": "Bearer " + TOKEN, "content-type": "application/json", "user-agent": _UA}

# optional LLM verifier (only if a provider+key is configured)
verifier = None
if PROVIDER not in ("none", ""):
    try:
        import verify as verifier
    except Exception:
        verifier = None


def mk_finding(sig, confirmed, verdict, reason, proof=None, category=None):
    return {
        "domain": sig["domain"], "business": sig.get("business", ""), "phone": sig.get("phone", ""),
        "category": category or sig.get("category", ""),
        "layers": ",".join(sig.get("layers", []))[:200],
        "proof_snippet": (proof if proof is not None else sig.get("proof", "")),
        "proof_url": sig.get("proof_url", ""),
        "http_status": sig.get("http_status", 0),
        "stage1_score": sig.get("score", 0),
        "stage2_verdict": verdict,
        "stage2_reason": reason,
        "stage2_category": category or sig.get("category", ""),
        "confirmed": confirmed,
    }


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


async def scan_batch(scan_client, llm_pool, llm_client, domains):
    sem = asyncio.Semaphore(SCAN_CONC)
    flagged, errors = [], 0

    async def one(rec):
        nonlocal errors
        async with sem:
            try:
                sig = await detect.scan_domain(scan_client, rec["domain"])
            except Exception:
                errors += 1
                return
            if sig.get("error"):
                errors += 1
                return
            if sig.get("flagged"):
                sig["business"] = rec.get("business", "")
                sig["phone"] = rec.get("phone", "")
                flagged.append(sig)

    await asyncio.gather(*(one(r) for r in domains))

    findings, weak = [], []
    for sig in flagged:
        if sig.get("auto_confirm"):
            findings.append(mk_finding(sig, 1, "auto-confirmed",
                                       "conclusive injection signal (cloaking / iframe / sitemap / density / defacement / malware)"))
        else:
            weak.append(sig)

    if verifier and llm_pool and getattr(llm_pool, "keys", None):
        vsem = asyncio.Semaphore(VERIFY_CONC)

        async def vone(sig):
            async with vsem:
                v = await verifier.verify(llm_pool, llm_client, sig)
            findings.append(mk_finding(sig, v["confirmed"], v["verdict"], v["reason"],
                                       proof=v.get("proof"), category=v.get("category")))
        await asyncio.gather(*(vone(s) for s in weak))
    else:
        for sig in weak:
            findings.append(mk_finding(sig, 0, "needs-review", "keyword/weak signal — manual review"))

    return findings, errors


async def main():
    if not API_BASE or not TOKEN:
        print("FATAL: API_BASE and SHARED_TOKEN are required", file=sys.stderr)
        sys.exit(1)
    deadline = time.time() + JOB_SECONDS
    llm_pool = verifier.Pool(PROVIDER) if verifier else None
    scanned_total, empty_strikes = 0, 0

    limits = httpx.Limits(max_connections=SCAN_CONC + 20, max_keepalive_connections=40)
    async with httpx.AsyncClient(limits=limits, verify=False) as scan_client, \
               httpx.AsyncClient() as llm_client, \
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
            findings, errors = await scan_batch(scan_client, llm_pool, llm_client, domains)
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
