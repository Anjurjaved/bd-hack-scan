# -*- coding: utf-8 -*-
"""
verify.py — Stage-2 LLM verification via Groq (free, OpenAI-compatible, FAST).
Keeps the Gemini key pool 100% free for the user's voice/TTS work.

For each Stage-1-flagged site it asks the model to classify:
  hacked_client  — a legit business/org HACKED with injected gambling/spam (sellable cleanup client) -> KEEP
  genuine_spam   — the site itself IS a gambling/adult/spam site, or an expired-domain casino        -> DROP
  false_positive — actually clean; the keyword was incidental/legitimate                              -> DROP

Keys rotate on HTTP 429. Model: llama-3.1-8b-instant (high RPD, plenty for the flagged subset).
"""
import os
import json
import re
import asyncio

MODEL = os.environ.get("GROQ_MODEL", "llama-3.1-8b-instant")
ENDPOINT = "https://api.groq.com/openai/v1/chat/completions"

PROMPT = """You are a website-security analyst for a Bangladeshi website-cleanup service.
A scanner flagged this site for gambling/casino/betting/pharma/adult spam. Classify it into ONE:

A) "hacked_client": a LEGITIMATE business/organization site (clinic, school, shop, company, factory,
   NGO, govt, news, etc.) that has been HACKED — spam injected into doorway/inner pages, cloaked so
   only Google sees it, hidden off-screen links, or defacement — while the real business still exists.
   This owner is a sellable cleanup client. KEEP.
B) "genuine_spam": the site ITSELF is a gambling/casino/betting/adult site, OR an expired domain turned
   into a casino-spam site. There is no real business owner to sell a cleanup to. DROP.
C) "false_positive": actually clean — the keyword was incidental or legitimate (a real pharmacy listing
   medicines, a news article mentioning a casino, a law firm with "judicial", a hotel). DROP.

DECISIVE RULE: cloaking, hidden links, or doorway pages behind an otherwise-normal homepage = hacked_client.
A whole site that is openly gambling to everyone with no real business identity = genuine_spam.

DATA
domain: {domain}
business_name_guess: {business}
detection_layers: {layers}
  (L2UACLOAK/L3REFCLOAK = cloaking; L11REST/L11SITEMAP/L5DENSITY/L16FEED/L20* = doorway pages;
   L17HIDDEN = hidden links; L10DEFACE = defacement; L1KW_STRONG = gambling on the visible homepage)
spam_proof: {proof}
attacked_pages: {evidence}
homepage_text_excerpt: \"\"\"{excerpt}\"\"\"

Return STRICT JSON only:
{{"classification":"hacked_client|genuine_spam|false_positive","business_type":"healthcare|education|ecommerce|garments|realestate|food|finance|it|ngo|travel|news|government|agro|pharma|automobile|professional|general","confidence":0.0,"reason":"one short sentence"}}"""


class Pool:
    def __init__(self, provider="groq"):
        keys = os.environ.get("GROQ_API_KEY", "")
        self.keys = [k.strip() for k in keys.replace("\n", ",").split(",") if k.strip()]
        self.i = 0
        self.calls = 0

    async def chat(self, client, prompt):
        n = len(self.keys)
        if not n:
            return None
        for step in range(n):
            k = self.keys[(self.i + step) % n]
            self.calls += 1
            try:
                r = await client.post(
                    ENDPOINT,
                    headers={"authorization": "Bearer " + k, "content-type": "application/json"},
                    json={"model": MODEL, "messages": [{"role": "user", "content": prompt}],
                          "response_format": {"type": "json_object"}, "temperature": 0, "max_tokens": 220},
                    timeout=35.0,
                )
            except Exception:
                continue
            if r.status_code == 429 or "rate_limit" in r.text:
                self.i = (self.i + step + 1) % n
                await asyncio.sleep(0.4)
                continue
            if r.status_code != 200:
                continue
            self.i = (self.i + step) % n
            try:
                return _parse(r.json()["choices"][0]["message"]["content"])
            except Exception:
                return None
        return None


def _parse(txt):
    txt = (txt or "").strip()
    m = re.search(r"\{.*\}", txt, re.S)
    if m:
        txt = m.group(0)
    try:
        return json.loads(txt)
    except Exception:
        return None


async def verify(pool, client, sig):
    prompt = PROMPT.format(
        domain=sig.get("domain", ""),
        business=(sig.get("business") or "?")[:120],
        layers=(sig.get("layers") or "")[:300],
        proof=(sig.get("proof") or "")[:300],
        evidence=(sig.get("evidence") or "")[:400],
        excerpt=(sig.get("excerpt") or "")[:2500],
    )
    out = await pool.chat(client, prompt)
    if not out or not out.get("classification"):
        return None
    return {
        "classification": str(out.get("classification", "")).lower(),
        "business_type": (out.get("business_type") or "").lower(),
        "confidence": out.get("confidence"),
        "reason": (out.get("reason") or "")[:300],
    }
