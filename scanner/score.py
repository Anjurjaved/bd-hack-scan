# -*- coding: utf-8 -*-
"""
score.py — Bayesian log-odds fusion of the per-domain signals from detect.py,
ported from the website-hack-audit v2 scorer.

INDEPENDENCE BUCKETS: at most one signal counts per bucket, so two layers catching
the same injection can't double-count. External blocklist sources each get their own
pseudo-bucket (capped at 2). HARD layers shortcut straight to CONFIRM_CANDIDATE.

Verdict:
  CONFIRM_CANDIDATE  hard signal OR (posterior >= 0.97 AND >= 2 distinct buckets)  -> confirmed
  SUSPECT            posterior >= 0.50 OR >= 1 bucket                              -> needs-review
  NEEDS_BROWSER      WAF/JS challenge wall, no spam seen                           -> needs-review
  CLEAN              nothing                                                       -> not flagged
"""
import math
import signatures as S

PRIOR = 0.12
W = {
    "L1KW_STRONG": (0.80, 0.030), "L1KW_WEAK": (0.55, 0.120), "L10LANG": (0.45, 0.080),
    "L17HIDDEN": (0.85, 0.010),
    "L2UACLOAK": (0.92, 0.020), "L3REFCLOAK": (0.90, 0.020),
    "L12IPCLOAK": (0.95, 0.005), "L13INNERCLOAK": (0.93, 0.005),
    "L11REST": (0.88, 0.010), "L16FEED": (0.80, 0.020), "L20SCRIPT": (0.82, 0.020),
    "L20MASS": (0.40, 0.050),
    "L11SITEMAP": (0.78, 0.020), "L20SHAPE": (0.80, 0.020),
    "L5DENSITY": (0.70, 0.050),
    "L4MOBILE": (0.75, 0.040), "L9REDIR": (0.70, 0.060), "L16HDR": (0.80, 0.030),
    "L20RELAY": (0.50, 0.050),
    "L14CAMPAIGN": (0.97, 0.002), "L14OBFUS": (0.60, 0.030), "L8IFRAME": (0.85, 0.010),
    "L19SHELL": (0.95, 0.003),
    "L15SURBL": (0.85, 0.020), "L15DBL": (0.88, 0.020), "L15URLHAUS": (0.95, 0.003),
    "L15CT": (0.60, 0.030), "L15GSB": (0.95, 0.003),
    "L10DEFACE": (0.97, 0.002),
}
HARD = {"L14CAMPAIGN", "L19SHELL", "L15URLHAUS", "L15GSB", "L10DEFACE"}
EXT = {"L15SURBL", "L15DBL", "L15URLHAUS", "L15CT", "L15GSB"}

LAYER_CAT = {
    "L2UACLOAK": "cloak", "L3REFCLOAK": "cloak", "L12IPCLOAK": "cloak", "L13INNERCLOAK": "cloak",
    "L4MOBILE": "redirect", "L9REDIR": "redirect", "L16HDR": "redirect", "L20RELAY": "redirect",
    "L10DEFACE": "deface",
    "L14CAMPAIGN": "malware", "L14OBFUS": "malware", "L8IFRAME": "malware", "L19SHELL": "malware",
    "L10LANG": "foreign_lang", "L20SCRIPT": "foreign_lang",
}


def _category(eff):
    # prefer the concrete spam-content category (gambling/pharma/adult) from any match
    for s in eff:
        c = S.category_of(s["match"])
        if c:
            return c
    for pref in ("deface", "malware", "cloak", "redirect", "foreign_lang"):
        for s in eff:
            if LAYER_CAT.get(s["layer"]) == pref:
                return pref
    return "gambling"


def score(signals):
    spam = [s for s in signals if s.get("bucket") != "control"]
    challenge = any(s["layer"].startswith("L18") for s in signals)

    layers_present = {s["layer"] for s in spam}
    has_content_enum = ("L11REST" in layers_present) or ("L20SCRIPT" in layers_present)
    eff = []
    for s in spam:
        lay = s["layer"]
        if lay == "L20MASS_CAND":
            if not has_content_enum:
                continue
            lay = "L20MASS"
        eff.append({**s, "layer": lay})

    best = {}   # bucket -> (ratio, signal)
    hard = False
    for s in eff:
        lay = s["layer"]
        if lay in HARD:
            hard = True
        D, F = W.get(lay, (0.55, 0.10))
        ratio = D / F
        bkey = ("ext:" + lay) if lay in EXT else s["bucket"]
        if bkey not in best or ratio > best[bkey][0]:
            best[bkey] = (ratio, s)
    ext_buckets = [k for k in best if k.startswith("ext:")]
    if len(ext_buckets) > 2:
        keep = sorted(ext_buckets, key=lambda k: -best[k][0])[:2]
        for k in ext_buckets:
            if k not in keep:
                del best[k]

    lo = math.log(PRIOR / (1 - PRIOR))
    for bkey, (ratio, s) in best.items():
        lo += math.log(ratio)
    posterior = 1.0 / (1.0 + math.exp(-lo))
    nbuckets = len(best)

    if not eff:
        verdict = "NEEDS_BROWSER" if challenge else "CLEAN"
    elif hard or (posterior >= 0.97 and nbuckets >= 2):
        verdict = "CONFIRM_CANDIDATE"
    elif posterior >= 0.50 or nbuckets >= 1:
        verdict = "SUSPECT"
    else:
        verdict = "CLEAN"
    if challenge and verdict == "SUSPECT" and nbuckets == 0:
        verdict = "NEEDS_BROWSER"

    # lead signal (highest ratio) for proof + url
    lead = None
    if best:
        lead = max(best.values(), key=lambda v: v[0])[1]
    category = _category(eff) if eff else ""
    layers = sorted(layers_present)
    # evidence = the exact attacked pages (distinct URLs) + what was found on each
    seen_u, evidence = set(), []
    for s in eff:
        u = s.get("url", "")
        if u and u not in seen_u:
            seen_u.add(u)
            evidence.append({"layer": s["layer"], "url": u[:300], "match": s["match"][:160]})
        if len(evidence) >= 12:
            break
    return {
        "verdict": verdict,
        "posterior": round(posterior, 4),
        "nbuckets": nbuckets,
        "hard": hard,
        "category": category,
        "proof": (lead["match"] if lead else "")[:500],
        "proof_url": (lead["url"] if lead else ""),
        "layers": layers,
        "evidence": evidence,
        "confirmed": 1 if verdict == "CONFIRM_CANDIDATE" else 0,
        "flagged": verdict in ("CONFIRM_CANDIDATE", "SUSPECT"),
    }
