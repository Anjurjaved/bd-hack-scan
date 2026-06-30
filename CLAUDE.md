# BD Hack-Audit — project workspace (Claude Code)

This folder (`/Users/javed/bd-hack-scan/`) is the **dedicated workspace** for the
**BD Hack-Audit** system — a 100% free, always-on cloud system that scans Bangladeshi
business websites for hacks (gambling/casino SEO-spam, pharma/adult, cloaking, redirect,
defacement, malware) and turns confirmed hacks into security-cleanup sales leads on a live
dashboard. Built by **Javed IT Solution**.

> The unrelated SEO / research work lives in `/Users/javed/mhm-deco-seo/`. Do hack-audit
> work HERE. Full project history is in this project's memory — read
> `memory/MEMORY.md` and especially `memory/bd-hack-audit-cloud-system.md` first.

## Token discipline (IMPORTANT)
- The project's **free Gemini API tokens are limited**. Keep Gemini usage minimal:
  Stage-2 verify only fires on flagged gambling/adult/foreign hits; harvesting, address
  extraction, screenshots, dashboard = **zero Gemini** (regex / fetch / hotlink). Prefer
  programmatic (regex/heuristic) solutions over LLM calls everywhere possible.
- Claude conversation tokens are NOT a concern to the user — be thorough.

## Live system
- **Dashboard + API (main Worker):** https://bd-hack-audit-api.javed-it.workers.dev/
- **Cloudflare account:** mdanjurjaved@gmail.com · **D1 database id:** `5a01635e-b9fe-4b28-a684-ba7007118f2a` (name `bd-hack-audit`, region ENAM)
- **GitHub repo:** https://github.com/Anjurjaved/bd-hack-scan (default branch `master`)
- **⚠️ GitHub Actions is DISABLED on this account** (HTTP 422 "Actions has been disabled for this user", since 2026-06-27). So `harvest.yml`/`scan.yml` do NOT run. ALL scanning + harvesting runs on **Cloudflare Worker crons**. Don't rely on Actions.

## Architecture
- **Main Worker** `bd-hack-audit-api` (`workers/src/index.js`, `wrangler.toml`): API + dashboard assets + cron orchestrator + the SINGLE D1 writer.
- **7 shard Workers** `bd-scan-1..7` (`workers/src/scan-worker.js`, `scanner.wrangler.toml`): run `scanSlice` (scan only, no writes) on `/run`; main fans out via service bindings `SHARD1..7` every minute, then writes once (`ingestResults`) — zero D1 write-contention.
- **Detector** `workers/src/scan.js`: ~20-layer detector + Bayesian fuse + genuine-vs-hacked gate. **Stage-2 verify = Gemini** (`geminiVerify`, model `gemini-2.5-flash` with `thinkingConfig.thinkingBudget=0`, JSON mode, **17-key ordered rotation** from secret `GEMINI_API_KEYS`), **Groq fallback** (`groqVerify`, secret `GROQ_API_KEY`). NOTE: `gemini-2.0-flash` has free-tier limit 0 on these keys — must use 2.5-flash.
- **Harvesters** `workers/src/harvest.js` (Worker-native, free):
  - `harvestCommonCrawl` (*/20) — CDX *.bd (now mostly "0 new" = exhausted, expected)
  - `harvestReverseIp` (*/20) — rapiddns reverse-IP snowball, seeds bd_score>=25 domains
  - `harvestDirectories` (37 */2) — BD business directories (bdtradeinfo etc.)
  - `harvestCrtsh` (13 */6) — crt.sh .bd identities
  - `harvestBdIpSweep` (13 */6) — ipdeny BD CIDR list (2311 blocks) reverse-IP
  - `harvestLeadCoip` (*/15, after housekeeping) — **shared-IP lead multiplier**: confirmed leads → hosting IP → co-hosted neighbours (prime victims). The main new-lead engine.
  - Python equivalents in `harvester/*.py` (run manually / local booster; `.venv` = python3.12 + tldextract). `lead_coip.py` also posts lead→IP to `/lead-ips` for the cluster view.
- **Dashboard** `dashboard/index.html` (single file, served as Worker static asset): tabs = Overview · BD Leads · International · Sources · System · Live Feed · **Manual Scan** · **আক্রান্ত সাইট (Screenshots)**. Features: server-cluster (shared-IP) grouping, export TXT/Excel/PDF, full mobile-responsive, fullscreen modal, manual on-demand scan (public `/scan_manual`, batches, delete), live thum.io screenshot gallery (no storage, no Gemini).

## findings table columns added over time
`ip` (hosting IP, for clusters), `is_manual` + `mbatch` (manual-scan batches), `address` + `district` (scan-time contact extraction — geographic).

## Deploy (wrangler is authed as mdanjurjaved@gmail.com)
```bash
cd workers
# main worker (also uploads dashboard/ assets):
npx wrangler deploy
# all 7 shards (when scan.js changes):
for i in 1 2 3 4 5 6 7; do npx wrangler deploy -c scanner.wrangler.toml --name "bd-scan-$i" --var "SCAN_SHARD:$i" --var "SCAN_SHARDS:8"; done
# secrets (already set): GEMINI_API_KEYS, GROQ_API_KEY, SHARED_TOKEN on main + each shard
```
- **SHARED_TOKEN** for authed writes: `~/.secrets/bd_hack_audit.env`. Gemini keys: `~/.secrets/gemini_api_keys` (lines 1-17 live; line 18 dead). Groq: `~/.secrets/groq_keys.env`.
- Manual harvest/scan: `POST /harvest_now {source:leadcoip|reverse|directories|bdipsweep|crtsh}` (Bearer SHARED_TOKEN); `POST /scan_manual {domains,name}` (public). D1: use the Cloudflare MCP `d1_database_query` with the id above.

## Rules of engagement
- Live system — deploy is fine (user authorized deploy-as-you-go) but test before/after; cron jobs run via `ctx.waitUntil` so slow harvesters (rapiddns ~12s/IP) complete in background even though a curl to `/harvest_now` may time out — verify via `source_state`/D1, not curl.
- Keep solutions practical + self-sustaining (must not stop after a few hours). Minimize Gemini.
