# Oracle Cloud (always-free) — 24/7 scanner setup

GitHub Actions disabled our account (mass scanning violates their Acceptable Use Policy).
So the **scan + harvest compute** moves to a free Oracle VM. The cloud parts
(Cloudflare Worker + D1 + dashboard) stay live and unchanged.

This VM runs **24/7 even when your Mac is off**, free forever, no charge (a card is only
used to verify identity at signup).

---

## 1. Create the Oracle account
1. Go to **https://www.oracle.com/cloud/free/** → *Start for free*.
2. Pick a **Home Region** near Bangladesh (e.g. **Singapore** or **Hyderabad/Mumbai**).
   (You can't change it later — pick one with ARM capacity.)
3. Verify email + a card (₹0 charged — identity only).

## 2. Launch the always-free ARM VM
1. Console → **Compute → Instances → Create instance**.
2. **Image:** Canonical **Ubuntu 22.04** (or 24.04).
3. **Shape:** *Change shape* → **Ampere (ARM)** → **VM.Standard.A1.Flex** →
   set **1–4 OCPU / 6–24 GB** (all within Always-Free).
4. **SSH key:** on your Mac run `ssh-keygen -t ed25519` (Enter through), then paste
   `~/.ssh/id_ed25519.pub` into *Add SSH keys → Paste public key*.
5. Create. Note the **Public IP**.
   - ⚠️ ARM is popular → if you see **"Out of capacity"**, retry, change Availability
     Domain, or try another region. Keep retrying — it frees up.
6. Outbound internet works by default; **no ingress rules needed** (the scanner only
   makes outbound requests).

## 3. SSH in
```bash
ssh ubuntu@<PUBLIC_IP> -i ~/.ssh/id_ed25519
```

## 4. Install (one time)
```bash
git clone https://github.com/Anjurjaved/bd-hack-scan
cd bd-hack-scan
cp deploy/scanner.env.example deploy/scanner.env
nano deploy/scanner.env       # paste SHARED_TOKEN + GROQ_API_KEY (see below), Ctrl-O, Enter, Ctrl-X
bash deploy/setup_oracle.sh
```

**Where the secrets are** (on your Mac):
- `SHARED_TOKEN` → `~/.secrets/bd_hack_audit.env`
- `GROQ_API_KEY` → `~/.secrets/groq_keys.env` (join the 3 keys with commas)

## 5. Verify it's running
```bash
systemctl status bdscan            # should say "active (running)"
journalctl -u bdscan -f            # live scan log (batch X: N scanned, M leads...)
```
Then open the dashboard — workers appear under **Workers / System**, leads grow:
**https://bd-hack-audit-api.javed-it.workers.dev/**

---

## What it does
- **`bdscan.service`** — always-on; runs `SCAN_WORKERS` (default 6) parallel scanners,
  each claiming batches from the Worker, scanning, Groq Stage-2, ingesting. Auto-restarts.
- **`bdscan-harvest.timer`** — every 2h runs the BD harvesters (crt.sh, directories,
  reverse-IP, OSM) then builds new scan batches.

## Update later (after code changes)
```bash
cd ~/bd-hack-scan && git pull && sudo systemctl restart bdscan
```

## Tune
Edit `deploy/scanner.env` (e.g. `SCAN_WORKERS=8`), then `sudo systemctl restart bdscan`.
A 4-OCPU / 24 GB A1 comfortably runs 8–10 workers (the work is network-bound).
