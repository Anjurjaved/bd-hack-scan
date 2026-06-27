"""
gemini.py — Stage-2 deep verification with the free Gemini key pool.

Only flagged (Stage-1) domains reach here. The model is asked, with strict
zero-false-positive discipline, whether the page is a Bangladeshi SMB website
that has actually been HACKED with injected gambling/pharma/adult/spam content,
versus a clean site that merely mentions a word, or a legitimately
foreign-language / gambling business.

Keys are rotated in fixed pool order; on HTTP 429 / RESOURCE_EXHAUSTED we jump
to the next key immediately (never hammer an exhausted key), per the user's
standing key-rotation rule.
"""
import os
import json
import re
import asyncio
import httpx

MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash-lite")
ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={key}"

PROMPT = """You are a website-security auditor with ZERO tolerance for false positives.

A cheap pre-filter flagged this website as possibly HACKED with injected spam
(gambling/casino/betting, pharma ED-pills, adult, or defacement). Your job: decide
if it is GENUINELY hacked right now, or a false positive.

A site is HACKED only if it serves spam content that is clearly UNRELATED to the
real business — e.g. casino/slot/"gacor"/"maxwin"/betting-brand text or links on a
clinic, school, factory, law firm, or shop; spam shown only to Googlebot (cloaking);
a redirect to a gambling domain; or a defacement message.

NOT hacked (false positive): a real gambling/betting company's own site; a pharmacy's
legitimate product page; words like "specialist" (contains cialis), "judicial/Judith"
(contains judi), "slotted/parking slot", "TOTO" toilet brand, "Ford Escort"; a real
foreign-language business serving its own brand in its own language.

DATA
domain: {domain}
stage1_layers: {layers}
keyword_hits: {proof}
visible_text_excerpt (first ~4000 chars):
\"\"\"{excerpt}\"\"\"

Return STRICT JSON only, no prose:
{{"hacked": true|false, "category": "gambling|pharma|adult|deface|cloak|redirect|malware|none",
"verbatim_proof": "the exact injected spam string you saw, or empty",
"offending_domain": "spam domain if any, else empty",
"confidence": 0.0-1.0, "reason": "one short sentence"}}"""


class KeyPool:
    def __init__(self, keys):
        self.keys = [k.strip() for k in keys if k.strip()]
        self.i = 0
        self.usage = {}  # key_id -> {requests, successes, rate_limited}

    def _uid(self, k):
        return k[:8] + "…" + k[-4:]

    def _bump(self, k, field):
        u = self.usage.setdefault(self._uid(k), {"requests": 0, "successes": 0, "rate_limited": 0})
        u[field] += 1

    def usage_report(self):
        return [{"key_id": kid, **v} for kid, v in self.usage.items()]

    async def generate(self, client, prompt):
        """Try keys in order starting at the current cursor; advance past exhausted ones."""
        n = len(self.keys)
        for step in range(n):
            k = self.keys[(self.i + step) % n]
            self._bump(k, "requests")
            try:
                r = await client.post(
                    ENDPOINT.format(model=MODEL, key=k),
                    json={
                        "contents": [{"parts": [{"text": prompt}]}],
                        "generationConfig": {"temperature": 0, "responseMimeType": "application/json"},
                    },
                    timeout=40.0,
                )
            except Exception:
                continue
            if r.status_code == 429 or "RESOURCE_EXHAUSTED" in r.text:
                self._bump(k, "rate_limited")
                self.i = (self.i + step + 1) % n  # park cursor past the exhausted key
                continue
            if r.status_code == 400 and "API key not valid" in r.text:
                continue
            if r.status_code != 200:
                continue
            self._bump(k, "successes")
            self.i = (self.i + step) % n
            try:
                txt = r.json()["candidates"][0]["content"]["parts"][0]["text"]
                return _parse_json(txt)
            except Exception:
                return None
        return None  # whole pool exhausted this round


def _parse_json(txt):
    txt = txt.strip()
    m = re.search(r"\{.*\}", txt, re.S)
    if m:
        txt = m.group(0)
    try:
        return json.loads(txt)
    except Exception:
        return None


async def verify(pool: KeyPool, client: httpx.AsyncClient, sig: dict) -> dict:
    """Take a Stage-1 result, ask Gemini, return verdict fields."""
    prompt = PROMPT.format(
        domain=sig["domain"],
        layers=", ".join(sig.get("layers", []))[:400],
        proof=(sig.get("proof") or "")[:300],
        excerpt=(sig.get("excerpt") or "")[:4000],
    )
    out = await pool.generate(client, prompt)
    if not out:
        # pool exhausted or unparseable -> keep as flagged-unconfirmed (never auto-confirm)
        return {"verdict": "uncertain", "confirmed": 0, "category": sig.get("category", ""), "reason": "stage2 unavailable", "proof": sig.get("proof", "")}
    hacked = bool(out.get("hacked")) and float(out.get("confidence") or 0) >= 0.7
    return {
        "verdict": "confirmed" if hacked else ("benign" if out.get("hacked") is False else "uncertain"),
        "confirmed": 1 if hacked else 0,
        "category": (out.get("category") or sig.get("category") or "").lower(),
        "reason": (out.get("reason") or "")[:300],
        "proof": (out.get("verbatim_proof") or sig.get("proof") or "")[:500],
        "offending_domain": (out.get("offending_domain") or "")[:120],
        "confidence": out.get("confidence"),
    }
