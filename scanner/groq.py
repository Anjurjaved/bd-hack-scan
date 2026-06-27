# -*- coding: utf-8 -*-
"""
groq.py — Stage-2 LLM verifier (Groq, free tier) that makes the lead list clean.

The heuristic gate in score.py is fast but blunt. This module is the precise
tiebreaker for the ONE decision the user cares about most:

    Is a flagged gambling/adult/foreign hit a LEGITIMATE business that was HACKED
    (a real owner we can sell cleanup to → KEEP as a lead), or is the site ITSELF
    a gambling/casino/betting/adult brand by design (no innocent owner → DROP)?

It also returns an accurate business_type and an is_bangladesh flag, so the
dashboard can split BD vs International and group leads by business category.

Design:
  * 3-key rotation (GROQ_KEY_1..N or GROQ_API_KEYS=comma-list). A key that hits
    429/permission errors is put on a short cooldown; the next key is tried.
  * Model tiers: a fast high-throughput primary (llama-3.1-8b-instant) for bulk,
    optional escalation to a stronger model (llama-3.3-70b-versatile) on 'uncertain'.
  * NEVER blocks the pipeline: if every key is cooled down / the call fails, it
    returns None and the caller falls back to the heuristic verdict.
  * Strict-JSON output (response_format=json_object) so no fragile parsing.

Groq's edge 403s the default urllib/httpx UA on some PoPs → we send a browser UA.
"""
import os
import json
import time
import asyncio

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"

PRIMARY = os.environ.get("GROQ_MODEL", "llama-3.1-8b-instant")
ESCALATE = os.environ.get("GROQ_MODEL_HI", "llama-3.3-70b-versatile")

# 16 business categories (aligned with classify.py) + the two terminal buckets.
BIZ_TYPES = ("healthcare", "education", "ecommerce", "garments", "realestate", "food",
             "finance", "it", "ngo", "travel", "news", "government", "agro", "pharma",
             "automobile", "professional", "general-business", "gambling-site")

SYSTEM = (
    "You triage website-security scan hits for a Bangladesh cleanup service. "
    "A scanner flagged spam (gambling/casino/betting/slots/pharma/adult/foreign-language) on a site. "
    "Decide which of these the site is:\n"
    "- \"hacked\": a LEGITIMATE business / organization site (clinic, school, shop, company, "
    "factory, govt, news, NGO, restaurant, travel agency, ...) that was HACKED — the spam was "
    "INJECTED into a real owner's site. The owner is an innocent victim we can sell cleanup to. "
    "THESE ARE LEADS.\n"
    "- \"genuine_spam\": the site is ITSELF a gambling / casino / betting / slots / lottery / adult "
    "brand by design — its whole purpose is that. There is NO innocent owner. EXCLUDE these.\n"
    "- \"uncertain\": not enough signal to tell.\n\n"
    "Decision rule:\n"
    "* If the HOMEPAGE itself openly sells casino/betting/slots/lottery/adult (that IS its business) "
    "→ genuine_spam.\n"
    "* If the homepage is a normal, unrelated business in its own branding/language, but the spam "
    "shows up only in inner pages / injected posts / cloaked-to-Google content / hidden links / a "
    "defacement → hacked.\n"
    "* A real business whose homepage was fully defaced or replaced by spam is still \"hacked\".\n\n"
    "Also give the underlying business_type (one of: " + ", ".join(BIZ_TYPES) + "; use "
    "\"gambling-site\" only when verdict is genuine_spam) and whether it is a Bangladesh business "
    "(.bd domain, Bengali text, +880 phone, BD address, or a known BD brand).\n\n"
    "Return STRICT JSON ONLY, no prose:\n"
    "{\"verdict\":\"hacked|genuine_spam|uncertain\",\"confidence\":0-100,"
    "\"business_type\":\"<one of the list>\",\"is_bangladesh\":true|false,\"reason\":\"<=12 words\"}"
)


def load_keys():
    """GROQ_KEY_1, GROQ_KEY_2, ... and/or GROQ_API_KEYS=comma-separated. De-duped, order kept."""
    keys, seen = [], set()
    multi = os.environ.get("GROQ_API_KEYS", "")
    for k in multi.split(","):
        k = k.strip()
        if k and k not in seen:
            seen.add(k); keys.append(k)
    i = 1
    while True:
        k = os.environ.get("GROQ_KEY_%d" % i, "").strip()
        if not k and i > 1 and not os.environ.get("GROQ_KEY_%d" % (i + 1), "").strip():
            break
        if k and k not in seen:
            seen.add(k); keys.append(k)
        i += 1
        if i > 40:
            break
    single = os.environ.get("GROQ_API_KEY", "").strip()
    if single and single not in seen:
        keys.append(single)
    return keys


class KeyPool:
    """Round-robin Groq keys with a per-key cooldown after a rate-limit/permission error."""
    def __init__(self, keys):
        self.keys = list(keys)
        self.idx = 0
        self.cooldown = {}          # key -> epoch when usable again
        self.usage = {}             # key_id -> {requests, successes, rate_limited}

    def available(self):
        return bool(self.keys)

    def _kid(self, key):
        return key[-6:] if key else "?"

    def next_key(self):
        now = time.time()
        n = len(self.keys)
        for _ in range(n):
            key = self.keys[self.idx % n]
            self.idx += 1
            if self.cooldown.get(key, 0) <= now:
                return key
        return None                 # everything cooling down

    def mark(self, key, success, rate_limited=False, secs=60):
        kid = self._kid(key)
        u = self.usage.setdefault(kid, {"key_id": kid, "requests": 0, "successes": 0, "rate_limited": 0})
        u["requests"] += 1
        if success:
            u["successes"] += 1
        if rate_limited:
            u["rate_limited"] += 1
            self.cooldown[key] = time.time() + secs

    def usage_report(self):
        return list(self.usage.values())


def _coerce(obj):
    """Validate / normalize the model's JSON into our schema."""
    if not isinstance(obj, dict):
        return None
    v = str(obj.get("verdict", "")).lower().strip()
    if v not in ("hacked", "genuine_spam", "uncertain"):
        # tolerate near-misses
        if "genuine" in v or "spam_site" in v or v == "spam":
            v = "genuine_spam"
        elif "hack" in v or "inject" in v or "compromis" in v:
            v = "hacked"
        else:
            v = "uncertain"
    bt = str(obj.get("business_type", "")).lower().strip().replace(" ", "-")
    if bt not in BIZ_TYPES:
        bt = "gambling-site" if v == "genuine_spam" else "general-business"
    try:
        conf = int(float(obj.get("confidence", 0)))
    except Exception:
        conf = 0
    conf = max(0, min(100, conf))
    is_bd = obj.get("is_bangladesh")
    is_bd = bool(is_bd) if isinstance(is_bd, bool) else str(is_bd).lower() in ("true", "1", "yes")
    return {"verdict": v, "confidence": conf, "business_type": bt,
            "is_bangladesh": is_bd, "reason": str(obj.get("reason", ""))[:120]}


def build_user_msg(domain, title, homepage_text, evidence):
    return (
        "domain: %s\n"
        "homepage <title>: %s\n"
        "homepage visible text (excerpt):\n%s\n\n"
        "DETECTED SPAM EVIDENCE (where/what the scanner found):\n%s"
        % (domain, (title or "")[:160], (homepage_text or "")[:1700], (evidence or "")[:1300])
    )


async def _call(client, key, model, messages, timeout=40.0):
    """One Groq chat call. Returns (dict|None, rate_limited:bool)."""
    payload = {
        "model": model, "temperature": 0, "max_tokens": 170,
        "response_format": {"type": "json_object"}, "messages": messages,
    }
    headers = {"Authorization": "Bearer " + key, "Content-Type": "application/json", "User-Agent": UA}
    try:
        r = await client.post(GROQ_URL, json=payload, headers=headers, timeout=timeout)
    except Exception:
        return None, False
    if r.status_code == 200:
        try:
            txt = r.json()["choices"][0]["message"]["content"]
            return _coerce(json.loads(txt)), False
        except Exception:
            return None, False
    if r.status_code in (429, 403, 401, 402):
        return None, True          # cool this key down, try the next
    return None, False


async def verify(client, pool, domain, title, homepage_text, evidence, escalate=True):
    """
    Classify one flagged site. Returns the coerced dict, or None if no key could
    answer (caller must then fall back to the heuristic verdict — never blocks).
    """
    if not pool or not pool.available():
        return None
    messages = [{"role": "system", "content": SYSTEM},
                {"role": "user", "content": build_user_msg(domain, title, homepage_text, evidence)}]
    tried = 0
    out = None
    while tried < max(len(pool.keys), 1) + 1:
        key = pool.next_key()
        if key is None:
            break                  # all keys cooling down
        tried += 1
        res, rl = await _call(client, key, PRIMARY, messages)
        pool.mark(key, success=bool(res), rate_limited=rl)
        if res:
            out = res
            break
        if not rl:
            # genuine failure (timeout/parse) — one more key, then give up
            continue
    # escalate only when the cheap model was unsure and a stronger model exists
    if out and out["verdict"] == "uncertain" and escalate and ESCALATE and ESCALATE != PRIMARY:
        key = pool.next_key()
        if key is not None:
            res, rl = await _call(client, key, ESCALATE, messages)
            pool.mark(key, success=bool(res), rate_limited=rl)
            if res:
                out = res
    return out
