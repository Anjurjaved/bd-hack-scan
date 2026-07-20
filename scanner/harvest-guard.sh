#!/usr/bin/env bash
# harvest-guard.sh — run ON the VM. Makes the harvest timers mutually exclusive and keeps them off the
# scanner's back.
#
# WHY: 12 harvest timers were scheduled with only RandomizedDelaySec separating them, and nothing stopped
# several from running at once. tls-san opens raw TLS to thousands of addresses, pdns-iptree issues thousands
# of DoH queries, commoncrawl streams a 45MB range, crux-full spends a 20,000-call DNS gate budget — any two
# of those together with the scanner exhausts a 1-OCPU / 946MB box. It wedged twice: sshd stopped completing
# its banner exchange while OCI still reported the instance RUNNING, and recovery needed an API reset.
#
# THE FIX: every harvester acquires one shared lock, non-blocking. A second harvester that fires while another
# is running exits immediately (flock -n returns 1) and simply waits for its next timer rather than piling on.
# Skipping a run costs nothing — each harvester persists a cursor, so the next run resumes where it left off.
#
# Also caps each harvester's CPU and memory through systemd, so a runaway one cannot take the box with it.
set -euo pipefail

LOCK=/var/lock/bd-harvest.lock
UNITS=$(systemctl list-unit-files 'bd-*.service' --no-legend | awk '{print $1}' | grep -vE 'bd-scanner|bd-a1-catcher')

echo "[guard] serialising: $(echo "$UNITS" | tr '\n' ' ')"
for u in $UNITS; do
  f="/etc/systemd/system/$u"
  [ -f "$f" ] || continue
  grep -q 'flock' "$f" && { echo "[guard] $u already guarded"; continue; }
  # -n = fail rather than queue: a harvester that cannot get the lock right now skips this run entirely.
  sudo sed -i "s#^ExecStart=/usr/bin/node #ExecStart=/usr/bin/flock -n $LOCK /usr/bin/node #" "$f"
  # The scanner is the revenue path; harvesting is background work and must lose every contest for the core.
  sudo grep -q '^CPUWeight=' "$f" || sudo sed -i '/^Nice=/a CPUWeight=20\nIOWeight=20\nMemoryMax=320M' "$f"
  echo "[guard] guarded $u"
done

sudo systemctl daemon-reload
echo "[guard] done. Verify with:  systemctl cat bd-cc.service | grep ExecStart"
