# 🖥️ Oracle Cloud Always-Free VM — ধাপে ধাপে সেটআপ গাইড (বাংলা)

> **লক্ষ্য:** heavy scan-engine (`run.mjs`) আপনার Mac থেকে সরিয়ে একটা **সবসময়-চালু, ১০০% ফ্রি Oracle VM**-এ বসানো — যাতে Mac বন্ধ থাকলেও, sleep-এ গেলেও scanning কখনো থামে না।
>
> এখন যা চলছে: `node scanner/run.mjs` আপনার Mac-এ (Mac জাগানো থাকলে চলে, ঘুমালে বন্ধ)।
> এই গাইডের পরে যা হবে: একই কোড Oracle VM-এ `systemd` service হিসেবে — reboot/crash-এও নিজে নিজে চালু (`Restart=always`)।
>
> **গুরুত্বপূর্ণ:** account বানানো, Google/email sign-in, আর card বসানো — এই তিনটা **আপনাকে নিজ হাতে** করতে হবে (নিরাপত্তার নিয়মে Claude এগুলো করতে পারে না)। VM তৈরি হয়ে গেলে **server setup-এর ১০০% আমি (এক কমান্ডে) করে দেব**।

---

## ⚡ ধাপ ০ — আপাতত Mac-এই চালু রাখুন (Oracle বসানোর আগ পর্যন্ত)

Oracle বসাতে যতক্ষণ, ততক্ষণ কাজ যেন না থামে — Mac booster জাগিয়ে রেখে চালান। repo root (`/Users/javed/bd-hack-scan`) থেকে:

```bash
cd /Users/javed/bd-hack-scan
GEMINI=$(sed -n '1,17p' ~/.secrets/gemini_api_keys | paste -sd, -)
GROQ=$(grep -oE 'gsk_[A-Za-z0-9_]+' ~/.secrets/groq_keys.env | paste -sd, -)
TOKEN=$(grep -oE 'SHARED_TOKEN=.*' ~/.secrets/bd_hack_audit.env | cut -d= -f2)

SCAN_JS=../workers/src/scan.js \
API_BASE=https://bd-hack-audit-api.javed-it.workers.dev \
SHARED_TOKEN=$TOKEN GEMINI_API_KEYS=$GEMINI GROQ_API_KEY=$GROQ \
CONCURRENCY=100 BATCH=300 \
caffeinate -i node scanner/run.mjs
```

`caffeinate -i` = কমান্ড চলাকালীন Mac ঘুমাবে না। বন্ধ করতে **Ctrl-C**। এটা সাময়িক — Oracle VM-ই স্থায়ী ঘর।

---

## 🟥 ধাপ ১ — Oracle Cloud account (আপনার হাতে)

1. ব্রাউজারে যান → **https://signup.oracle.com/**
2. **Country/Territory** = **Bangladesh** সিলেক্ট করুন। নাম, email দিন → email-এ আসা কোড দিয়ে verify করুন → password সেট করুন।
3. **Account type:** Personal. Address = আপনার ঠিকানা, mobile = **+880** নম্বর (OTP আসবে)।
4. **Payment / card যাচাই (স্ক্রিনে "Add payment verification method" আসবে):**
   - একটা **আসল Visa/Mastercard** (debit/credit) দিতে হবে — **শুধু পরিচয় যাচাইয়ের জন্য**। ~$১ সাময়িক hold হয়, ফেরত আসে। **Always Free-তে $0-ই থাকে, কোনো charge হয় না।**
   - ⚠️ bKash/Nagad/virtual card সাধারণত কাজ করে না — real Visa/Mastercard লাগবে।
   - 🔒 **card নম্বর আমি (Claude) বসাতে পারব না — আপনি নিজে বসাবেন।** এটা নিরাপত্তার নিয়ম।
5. **Home Region (স্থায়ী — পরে বদলানো যায় না):** BD-র কাছে **Singapore** বা **India (Hyderabad/Mumbai)** ভালো। তবে এগুলোতে ফ্রি A1 প্রায়ই "capacity নেই" দেখায় — সমস্যা হলে ধাপ ২-এর টিপস দেখুন।
6. Agreement টিক দিয়ে **Start my free trial** → account তৈরি হবে (২-৫ মিনিট), তারপর **OCI Console** (dashboard) খুলবে।

---

## 🟩 ধাপ ২ — VM instance তৈরি (আপনার হাতে, আমি পাশে গাইড করব)

OCI Console খোলার পর:

1. উপরে-বাঁয়ে **☰ হ্যামবার্গার মেনু** → **Compute** → **Instances** → নীল **Create instance** বাটন।
2. **Name:** `bd-scanner` (যা খুশি)।
3. **Placement:** default AD রাখুন (capacity error হলে AD-1/AD-2/AD-3 পাল্টে দেখবেন)।
4. **Image and shape** (এই অংশটাই আসল):
   - **Image:** **Edit** → **Canonical Ubuntu** → **22.04** সিলেক্ট করুন।
   - **Shape:** **Edit** → **Ampere** ট্যাব → **VM.Standard.A1.Flex** (এতে **"Always Free-eligible"** সবুজ লেখা থাকবে) → **OCPU = 2**, **Memory = 12 GB** (ফ্রি সীমা: মোট ৪ OCPU / ২৪GB — একটা VM-এ ২/১২ ভালো)।
   - 🟠 যদি **"Out of host capacity"** লাল error দেখায় (A1-এ খুব common):
     - কয়েক মিনিট পর আবার **Create** চাপুন, বা placement-এ **অন্য AD** সিলেক্ট করুন।
     - কাজ না হলে সাময়িকভাবে **VM.Standard.E2.1.Micro** (AMD, 1 OCPU/1GB — এটাও Always-Free, সবসময় available) দিয়ে শুরু করুন; scanner তো fetch-নির্ভর, ছোট box-এও চলে। পরে A1 পেলে migrate করবেন।
5. **Networking:** default রাখুন (নতুন VCN + subnet নিজেই বানাবে)। **কোনো inbound port লাগবে না** — scanner শুধু বাইরে যায় (outbound), যেটা default-এ খোলা।
6. **Add SSH keys** (server-এ ঢোকার চাবি — গুরুত্বপূর্ণ):
   - সবচেয়ে সহজ: **Generate a key pair for me** সিলেক্ট → **Save private key** চাপে `.key` ফাইল download করে **নিরাপদে রাখুন** (এটা দিয়েই server-এ ঢুকব)।
   - অথবা আপনার Mac-এ আগেই key থাকলে: টার্মিনালে `cat ~/.ssh/id_ed25519.pub` (বা `id_rsa.pub`) চালিয়ে পুরো লেখাটা copy করে **Paste public keys** বক্সে দিন। (না থাকলে `ssh-keygen -t ed25519` চালিয়ে বানিয়ে নিন।)
7. নিচে **Create** চাপুন। ১-২ মিনিটে instance **RUNNING** (সবুজ) হবে।
8. **Public IP address** নোট করুন — instance ডিটেইল পেজে **"Public IP address"** ফিল্ডে সংখ্যাটা (যেমন `140.238.x.x`) থাকবে। **এই IP-টা আমাকে দেবেন।**

> 💡 টিপ: বাঁ-মেনু → **Billing** → **Upgrade to Pay As You Go**-তে গেলে (তবু $0-ই থাকে Always-Free সীমায়) Oracle idle VM reclaim করে না — box কখনো হারাবেন না।

---

## 🟦 ধাপ ৩ — এক কমান্ডে scanner বসানো (এটা আমি করব)

VM-এর **Public IP** (আর "generate for me" করলে সেই **private key ফাইলের path**) আমাকে দিলেই, আমি Mac থেকে এই কমান্ডটা চালাব:

```bash
cd /Users/javed/bd-hack-scan
chmod +x scanner/*.sh
# generate করা key থাকলে:  ./scanner/deploy-to-vm.sh ubuntu@<PUBLIC_IP> ~/Downloads/ssh-key-xxxx.key
./scanner/deploy-to-vm.sh ubuntu@<PUBLIC_IP>
```

এই এক কমান্ড যা করে (`deploy-to-vm.sh`):
1. `run.mjs` + **এখনকার fixed `scan.js`/`signatures.js`** (আজকের real-vs-fake সংশোধন সহ) VM-এ copy করে,
2. `~/.secrets` থেকে Gemini(১৭)/Groq/SHARED_TOKEN নিয়ে VM-এ `scanner.env` বানায়,
3. VM-এ Node 20 বসায়,
4. `bd-scanner` নামে **systemd service** চালু করে (`Restart=always` — crash/reboot-এও নিজে চালু হয়)।

ব্যস — এরপর scanner ২৪/৭ চলবে, Mac লাগবে না।

---

## 🟨 ধাপ ৪ — চলছে কিনা যাচাই

1. **live log** (আমি দেখাব, চাইলে আপনিও):
   ```bash
   ssh ubuntu@<PUBLIC_IP> 'sudo journalctl -u bd-scanner -f'
   ```
   `[bd-scanner] +500 in 9s · total=... confirmed=... · ~180000/hr` — এমন লাইন মানে কাজ করছে।
2. **Dashboard-এ প্রমাণ:** https://bd-hack-audit-api.javed-it.workers.dev/ → **System** ট্যাব → workers তালিকায় **`oracle-vm`** নামে একটা worker দেখবেন, scan count বাড়ছে।

---

## ⚙️ ধাপ ৫ — গতি বাড়ানো / কোড আপডেট (পরে দরকার হলে)

- **গতি টিউন:** `ssh ubuntu@<ip>` → `sudo nano /opt/bd-scanner/scanner.env` → `CONCURRENCY` (৪০০ থেকে শুরু, box-এর CPU ৮০%-এর নিচে থাকা পর্যন্ত বাড়ান) → `sudo systemctl restart bd-scanner`।
- **detector আপডেট হলে** (`scan.js` বদলালে): Mac থেকে আবার `./scanner/deploy-to-vm.sh ubuntu@<ip>` — নতুন কোড copy করে service restart করে দেয়।
- **থামাতে / চালু করতে:** `sudo systemctl stop bd-scanner` / `start` / `status bd-scanner`।

---

## ❓ সাধারণ সমস্যা

| স্ক্রিনে যা দেখবেন | কী করবেন |
|---|---|
| **"Out of host capacity"** (A1 বানাতে গেলে) | কয়েক মিনিট পর retry / অন্য AD / সাময়িকভাবে E2.1.Micro দিয়ে শুরু |
| **card decline** | real Visa/Mastercard লাগবে; bKash/virtual চলে না |
| **`Permission denied (publickey)`** (deploy-এ) | ভুল key; `deploy-to-vm.sh ubuntu@<ip> <সঠিক-key-path>` দিন, অথবা Oracle-এ Ubuntu login user `ubuntu` (Oracle Linux হলে `opc`) নিশ্চিত করুন |
| A1 কিছুতেই পাচ্ছেন না | E2.1.Micro-তে চালান — একটু ধীর কিন্তু ২৪/৭ ফ্রি, কাজ চলবে |

---

## 🔑 এক নজরে দরকারি তথ্য

- **Signup:** https://signup.oracle.com/ (Country = Bangladesh)
- **Image:** Canonical Ubuntu 22.04 · **Shape:** VM.Standard.A1.Flex (2 OCPU/12GB, Always-Free) · fallback E2.1.Micro
- **Login user:** `ubuntu` · **Deploy কমান্ড:** `./scanner/deploy-to-vm.sh ubuntu@<PUBLIC_IP> [key.key]`
- **Dashboard:** https://bd-hack-audit-api.javed-it.workers.dev/ → System → worker `oracle-vm`
- **আপনার যা লাগবে আমাকে দিতে:** VM-এর **Public IP** (আর generate-করা হলে **private key ফাইল**)

> Developed by **Javed IT Solution** — javeditsolution.com
