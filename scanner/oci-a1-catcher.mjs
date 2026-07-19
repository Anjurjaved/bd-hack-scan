#!/usr/bin/env node
// OCI Ampere A1 capacity catcher — retries LaunchInstance until Oracle frees capacity, then stops.
//
// Singapore has a single AD, so the usual "try another availability domain" advice does not apply:
// the only workable strategy is to keep asking until capacity appears. Runs on the existing scanner VM
// as a systemd service so it survives reboots and does not depend on the Mac being awake.
//
// Zero dependencies — signs OCI REST requests directly (draft-cavage-http-signatures-08) with node:crypto,
// so the 946MB E2.1.Micro never has to run a pip/dnf install (those OOM the box).
//
// Config comes from env (see oci-catcher.env):
//   OCI_TENANCY, OCI_USER, OCI_FINGERPRINT, OCI_KEY_FILE, OCI_REGION, SSH_PUBKEY
//   OCPUS (2), MEMORY_GB (12), BOOT_GB (50), DISPLAY_NAME, RETRY_MS (45000)
import crypto from "node:crypto";
import fs from "node:fs";
import https from "node:https";

const TENANCY = req("OCI_TENANCY");
const USER = req("OCI_USER");
const FINGERPRINT = req("OCI_FINGERPRINT");
const REGION = process.env.OCI_REGION || "ap-singapore-1";
const KEY = fs.readFileSync(process.env.OCI_KEY_FILE || `${process.env.HOME}/.oci/oci_api_key.pem`, "utf8");
const SSH_PUBKEY = req("SSH_PUBKEY").trim();
const OCPUS = Number(process.env.OCPUS || 2);
const MEMORY_GB = Number(process.env.MEMORY_GB || 12);
const BOOT_GB = Number(process.env.BOOT_GB || 50);
const DISPLAY_NAME = process.env.DISPLAY_NAME || "bd-scanner-a1";
const RETRY_MS = Number(process.env.RETRY_MS || 45000);
const SHAPE = "VM.Standard.A1.Flex";

function req(k) { const v = process.env[k]; if (!v) { console.error(`[catcher] missing env ${k}`); process.exit(1); } return v; }
const log = (...a) => console.log(new Date().toISOString(), ...a);

// --- request signing -------------------------------------------------------
// Oracle rejects requests whose clock is >5 min off, and requires x-content-sha256/content-length/
// content-type in the signing string for anything with a body.
async function oci(method, host, path, body) {
  const date = new Date().toUTCString();
  const headers = { date, host };
  let signed = ["date", "(request-target)", "host"];
  let payload;
  if (body !== undefined) {
    payload = JSON.stringify(body);
    const sha = crypto.createHash("sha256").update(payload).digest("base64");
    headers["x-content-sha256"] = sha;
    headers["content-type"] = "application/json";
    headers["content-length"] = String(Buffer.byteLength(payload));
    signed = signed.concat(["content-length", "content-type", "x-content-sha256"]);
  }
  const target = `${method.toLowerCase()} ${path}`;
  const signingString = signed
    .map((h) => (h === "(request-target)" ? `(request-target): ${target}` : `${h}: ${headers[h]}`))
    .join("\n");
  const sig = crypto.createSign("RSA-SHA256").update(signingString).sign(KEY, "base64");
  headers.authorization =
    `Signature version="1",keyId="${TENANCY}/${USER}/${FINGERPRINT}",algorithm="rsa-sha256",` +
    `headers="${signed.join(" ")}",signature="${sig}"`;

  // node:https, not fetch — the Fetch spec forbids setting date/host/content-length, and OCI signs
  // exactly those headers, so fetch silently drops them and every request comes back 401.
  return new Promise((resolve, reject) => {
    const rq = https.request(
      { host, path, method, headers, timeout: 60000 },
      (res) => {
        let text = "";
        res.on("data", (c) => (text += c));
        res.on("end", () => {
          let json = null;
          try { json = text ? JSON.parse(text) : null; } catch {}
          resolve({ status: res.statusCode, json, text });
        });
      }
    );
    rq.on("error", reject);
    rq.on("timeout", () => { rq.destroy(new Error("timeout")); });
    if (payload) rq.write(payload);
    rq.end();
  });
}
const iaas = (m, p, b) => oci(m, `iaas.${REGION}.oraclecloud.com`, p, b);
const identity = (m, p, b) => oci(m, `identity.${REGION}.oraclecloud.com`, p, b);

// --- discovery -------------------------------------------------------------
// OCI intermittently answers a perfectly valid signed request with 401 NotAuthenticated (seen on ~1 in 5
// calls right after an API key is added). Retry instead of dying — this process is meant to run for days.
async function getRetry(fn, label, tries = 6) {
  let last;
  for (let i = 1; i <= tries; i++) {
    last = await fn();
    if (last.status === 200) return last;
    log(`[discover] ${label} → ${last.status} (attempt ${i}/${tries})`);
    await new Promise((r) => setTimeout(r, 3000 * i));
  }
  throw new Error(`${label} ${last.status}: ${last.text.slice(0, 300)}`);
}

async function discover() {
  const ad = await getRetry(() => identity("GET", `/20160918/availabilityDomains?compartmentId=${encodeURIComponent(TENANCY)}`), "availabilityDomains");
  const adName = ad.json[0].name;

  // filter images by shape — that is what guarantees an aarch64 build (an x86 image is simply not listed
  // for A1.Flex, which is exactly the incompatibility the Console reports as a greyed-out shape)
  const img = await getRetry(() => iaas("GET",
    `/20160918/images?compartmentId=${encodeURIComponent(TENANCY)}&operatingSystem=${encodeURIComponent("Oracle Linux")}` +
    `&operatingSystemVersion=9&shape=${encodeURIComponent(SHAPE)}&sortBy=TIMECREATED&sortOrder=DESC&limit=5`), "images");
  if (!img.json?.length) throw new Error("no Oracle Linux 9 image is listed for this shape");
  const image = img.json[0];

  const sn = await getRetry(() => iaas("GET", `/20160918/subnets?compartmentId=${encodeURIComponent(TENANCY)}&limit=50`), "subnets");
  if (!sn.json?.length) throw new Error("no subnet found");
  // prefer the public subnet the existing scanner VM already uses — its ingress rules are proven
  const subnet = sn.json.find((s) => !s.prohibitPublicIpOnVnic) || sn.json[0];

  return { adName, imageId: image.id, imageName: image.displayName, subnetId: subnet.id, subnetName: subnet.displayName };
}

// --- launch ----------------------------------------------------------------
async function launch(d) {
  return iaas("POST", "/20160918/instances", {
    availabilityDomain: d.adName,
    compartmentId: TENANCY,
    displayName: DISPLAY_NAME,
    shape: SHAPE,
    shapeConfig: { ocpus: OCPUS, memoryInGBs: MEMORY_GB },
    sourceDetails: { sourceType: "image", imageId: d.imageId, bootVolumeSizeInGBs: BOOT_GB },
    createVnicDetails: { subnetId: d.subnetId, assignPublicIp: true },
    metadata: { ssh_authorized_keys: SSH_PUBKEY },
    // no faultDomain on purpose — Oracle's own guidance is that letting it choose maximises the
    // chance of landing on a host that has room
  });
}

async function publicIpOf(instanceId) {
  for (let i = 0; i < 40; i++) {
    const va = await iaas("GET", `/20160918/vnicAttachments?compartmentId=${encodeURIComponent(TENANCY)}&instanceId=${encodeURIComponent(instanceId)}`);
    const vnicId = va.json?.[0]?.vnicId;
    if (vnicId) {
      const v = await iaas("GET", `/20160918/vnics/${vnicId}`);
      if (v.json?.publicIp) return v.json.publicIp;
    }
    await new Promise((r) => setTimeout(r, 15000));
  }
  return null;
}

// --- main ------------------------------------------------------------------
const d = await discover();
log(`[catcher] AD=${d.adName}`);
log(`[catcher] image=${d.imageName}`);
log(`[catcher] subnet=${d.subnetName}`);
log(`[catcher] hunting ${SHAPE} ${OCPUS}ocpu/${MEMORY_GB}GB every ${Math.round(RETRY_MS / 1000)}s …`);

let n = 0, backoff = RETRY_MS, auth401 = 0;
for (;;) {
  n++;
  let r;
  try { r = await launch(d); } catch (e) { log(`[${n}] network error: ${e.message}`); await sleep(backoff); continue; }

  if (r.status === 200) {
    const id = r.json.id;
    log(`[${n}] 🎉 CAUGHT IT — instance ${id}`);
    const ip = await publicIpOf(id);
    log(`[${n}] PUBLIC IP: ${ip || "(pending — check the Console)"}`);
    fs.writeFileSync("/tmp/a1-caught.txt", `${id}\n${ip || ""}\n`);
    process.exit(0);
  }

  const code = r.json?.code || "";
  const msg = (r.json?.message || r.text || "").slice(0, 160);
  if (code === "TooManyRequests" || r.status === 429) {
    backoff = Math.min(backoff * 2, 300000); // rate-limited — back off hard, Oracle counts attempts
    log(`[${n}] 429 rate-limited → backing off to ${Math.round(backoff / 1000)}s`);
  } else if (r.status === 500 && /[Oo]ut of (host )?capacity/.test(msg)) {
    backoff = RETRY_MS;
    if (n % 20 === 1) log(`[${n}] still out of capacity — continuing`); // keep the log readable over days
  } else if (r.status === 401) {
    // transient far more often than real — only give up once it is clearly not a blip
    auth401++;
    backoff = RETRY_MS;
    if (auth401 >= 15) { log("[catcher] 401 persisted 15× — the API key looks wrong. Stopping."); process.exit(1); }
  } else {
    // a real misconfiguration (bad OCID, quota) would otherwise loop silently forever
    log(`[${n}] ⚠️ ${r.status} ${code}: ${msg}`);
    if (r.status === 404 || code === "LimitExceeded" || code === "QuotaExceeded") {
      log("[catcher] not a capacity problem — stopping so it gets fixed rather than retried blindly.");
      process.exit(1);
    }
    backoff = RETRY_MS;
  }
  if (r.status !== 401) auth401 = 0;
  await sleep(backoff);
}

function sleep(ms) { return new Promise((r) => setTimeout(r, ms + Math.floor(Math.random() * 5000))); }
