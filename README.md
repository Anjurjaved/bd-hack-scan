# BD Hack-Audit — free always-on cloud scanner

Scans hundreds of thousands of Bangladesh-based business websites for **current
hacks** (gambling/casino SEO-spam injection, cloaking, malicious redirects,
defacement, pharma/adult spam) and surfaces the confirmed list on a **live
dashboard** — running 24/7 on free infrastructure, independent of any local machine.

## Architecture (100% free, $0)

```
 GitHub Actions (engine)            Cloudflare (state + dashboard)
 16 parallel scanner jobs   ──►   Worker API  ──►  D1 (queue + findings + stats)
 Stage-1: 10+ layer detect  ◄──   /claim /ingest /harvest /build
 Stage-2: rules-based confirm                     Pages dashboard ◄─ /api/stats
 + continuous harvester     ──►   /harvest
```

- **scanner/** — async Stage-1 detection (`detect.py`) + orchestrator (`scan.py`). No external LLM by default; strong injection signals auto-confirm, weak ones go to a review bucket.
- **workers/** — the Cloudflare Worker API + live dashboard (served as static assets).
- **harvester/** — domain harvesters (existing-list seed, crt.sh CT, directory sitemaps, …).
- **db/** — D1 schema.
- **.github/workflows/** — `scan.yml` (16-wide scan wave every 30 min) and harvesting.

Live dashboard: served by the Worker at its `workers.dev` URL.

Built by [Javed IT Solution](https://javeditsolution.com).
