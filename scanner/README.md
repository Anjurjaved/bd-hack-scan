# BD Hack-Audit — VM Scanner (the throughput unlock)

The heavy **fetch + detect** engine, moved off Cloudflare Workers (Free-plan 10 ms CPU wall → constant `1102`)
onto a real always-on box. It reuses `workers/src/scan.js` **verbatim** (same ~20-layer detector, same
Gemini/Groq Stage-2), so results are identical — just **25×–400× faster** and never CPU-throttled.

```
Oracle A1 VM (systemd, Restart=always)          Cloudflare (unchanged, single D1 writer)
  run.mjs: pull → scan (400 concurrent) → push  ──►  /vm-pull  (hand out + pre-mark a batch)
  imports scan.js (scanDomain+gemini+groq)      ◄──  /vm-push  (write findings + counters + dead flags)
                                                     D1 · dashboard · Worker-native harvesters · CF shard engine
```

Measured: at concurrency **25** from a laptop → **~11,000 domains/hr**. At concurrency **400** on the A1 VM →
**tens of thousands/hr** (network-bound, not CPU). The 28k backlog drains in well under an hour; then it
continuously re-scans + eats new harvest.

---

## A. Run it RIGHT NOW on your Mac (instant booster, zero signup)

No Oracle account needed to start helping. From the repo root:

```bash
GEMINI=$(sed -n '1,17p' ~/.secrets/gemini_api_keys | paste -sd, -)
GROQ=$(grep -oE 'gsk_[A-Za-z0-9_]+' ~/.secrets/groq_keys.env | paste -sd, -)
TOKEN=$(grep -oE 'SHARED_TOKEN=.*' ~/.secrets/bd_hack_audit.env | cut -d= -f2)

SCAN_JS=../workers/src/scan.js \
API_BASE=https://bd-hack-audit-api.javed-it.workers.dev \
SHARED_TOKEN=$TOKEN GEMINI_API_KEYS=$GEMINI GROQ_API_KEY=$GROQ \
CONCURRENCY=100 BATCH=300 \
node scanner/run.mjs
```

Ctrl-C to stop. (Keep the Mac awake: `caffeinate -i node scanner/run.mjs …`.) This is a stopgap — the VM is the
permanent, always-on home.

---

## B. The permanent home — Oracle Cloud Always-Free VM (0 BDT forever)

### B1. Create the account (YOUR hands-on part — Claude can guide in the browser but cannot enter card / sign in)
1. Go to <https://signup.oracle.com/> → pick **Bangladesh** as country.
2. Verify email, set a password. **A debit/credit card is required for identity verification only** — a small
   temporary hold (~$1), refunded; **Always Free stays $0**. bKash/virtual cards usually don't work — use a real
   Visa/Mastercard.
3. Home region: pick a **quiet** one (home region is permanent). Singapore / Hyderabad / Mumbai are close to BD
   but busy for free A1; if A1 capacity fails, a less-busy region helps.

### B2. Create the VM instance
- Compute → Instances → **Create instance**.
- Image: **Canonical Ubuntu 22.04**. Shape: **Ampere A1 (Always Free-eligible)** — 1–2 OCPU / 6–12 GB.
  - A1 often says *"Out of host capacity"*. Either retry every few minutes / different AD, or start on the
    always-available **VM.Standard.E2.1.Micro** (AMD, 1 OCPU / 1 GB — still fine for a fetch-bound scanner) and
    move to A1 later.
- Add your **SSH public key** (`cat ~/.ssh/id_*.pub`; or let Oracle generate one and download it).
- Create. Note the **public IP**.
- Networking → the instance's subnet **security list** → allow egress (default allows all outbound — that's all
  the scanner needs; no inbound ports required).
- **Tip:** convert the tenancy to **Pay-As-You-Go** (still $0 within Always-Free limits) so the idle-reclaim
  policy never touches this box.

### B3. One-command deploy (from the Mac)
```bash
chmod +x scanner/*.sh
./scanner/deploy-to-vm.sh ubuntu@<VM_PUBLIC_IP>            # or opc@<ip> on Oracle Linux, add key.pem if needed
```
This copies `run.mjs` + the current `scan.js`/`signatures.js` + a `scanner.env` built from `~/.secrets`, installs
Node 20, and starts the `bd-scanner` systemd service (`Restart=always`). Done.

### B4. Verify / operate
```bash
ssh ubuntu@<ip> 'sudo journalctl -u bd-scanner -f'    # live: "+500 in 9s · ~180000/hr"
```
Dashboard → Workers/System shows an **`oracle-vm`** worker with a climbing scan count.

Tune throughput: edit `/opt/bd-scanner/scanner.env` (`CONCURRENCY`, `BATCH`) → `sudo systemctl restart bd-scanner`.
Start at 400; raise until CPU on the box stays < 80% (`htop`).

### B5. Update the detector later (when `scan.js` changes)
Re-run `./scanner/deploy-to-vm.sh ubuntu@<ip>` — it recopies the current detector and restarts the service.

---

## Notes
- The VM **never touches D1** — it only calls `/vm-pull` + `/vm-push` with the `SHARED_TOKEN`, preserving the
  single-writer design (zero write-contention). If Oracle ever reclaims the box, swap it and lose nothing — all
  data lives on Cloudflare.
- The Cloudflare shard engine keeps running as a **warm failover**; both feed the same D1. You can also run the
  Mac booster and the VM simultaneously — they pull disjoint batches safely (each `/vm-pull` pre-marks its rows).
- Egress used ≈ 2–5 GB/day (tiny JSON POSTs); page fetches are **ingress** = free. Nowhere near the 10 TB/mo free
  cap.
