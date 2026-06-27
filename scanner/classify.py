# -*- coding: utf-8 -*-
"""
classify.py — three API-free classifiers used to keep the lead list clean:
  domain_spammy(reg)        -> True if the registrable DOMAIN itself is a gambling/adult brand
                               (genuine spam site, NOT a hacked client — EXCLUDE).
  bd_signal(reg, body)      -> True if the site carries a Bangladesh identity (.bd / +880 / Bengali).
  biz_type(reg,title,body)  -> one of 16 BD business categories (or 'general-business').

The genuine-vs-hacked DECISION lives in score.py and combines these with the cloaking /
doorway / malware signals: cloaking-delta or doorway-behind-a-clean-homepage = HACKED (keep);
gambling in the domain name, or openly-gambling-to-everyone with no BD identity = genuine (drop).
"""
import re

# ---- EXCLUDE signal: gambling/adult brand IN THE REGISTRABLE DOMAIN (never the path) ----
SPAMMY_DOMAIN = re.compile(
    r'casino|cassino|kasino|kasyno|kazino|cazino|slot|togel|toto|judi|gacor|maxwin|sbobet|bocoran|'
    r'1xbet|melbet|betwinner|mostbet|parimatch|4rabet|jeetbuzz|jeetwin|bajilive|baji999|betvisa|bettilt|'
    r'glorycasino|marvelbet|crickex|linebet|pussy888|mega888|joker123|918kiss|bandartogel|'
    r'pornhub|xvideos|xnxx|sexcam|escortservice', re.I)
SPAMMY_TLD = re.compile(r'\.(bet|casino|poker|porn|sex|xxx|adult)$', re.I)


def domain_spammy(reg):
    return bool(SPAMMY_DOMAIN.search(reg or "") or SPAMMY_TLD.search(reg or ""))


# ---- Bangladesh identity ----
BENGALI = re.compile(r'[ঀ-৿]')
BD_PHONE = re.compile(r'(?:\+?880|\b0)1[3-9]\d{8}\b')


def bd_signal(reg, body):
    if (reg or "").endswith(".bd"):
        return True
    body = body or ""
    if BD_PHONE.search(body):
        return True
    if len(BENGALI.findall(body)) >= 15:
        return True
    return False


# ---- 16-category business-type taxonomy (EN + key BN), domain=5 / title=3 / body=1 ----
CATS = [
    ("healthcare", r'\b(hospital|clinic|medical|healthcare|health|diagnostic|dental|dentist|ortho|cardiac|surgeon|doctor|physiotherapy|laborator|pathology|maternity|homeo|nursing home|gyna?e)\b|হাসপাতাল|ক্লিনিক|চিকিৎসা|ডায়াগনস্টিক|ডেন্টাল|স্বাস্থ্য'),
    ("education", r'\b(school|college|university|institute|academy|madrasah?|coaching|kindergarten|polytechnic|tutorial|education|e-learning|admission|syllabus|scholarship)\b|স্কুল|কলেজ|বিশ্ববিদ্যালয়|মাদ্রাসা|কোচিং|শিক্ষা|একাডেমি'),
    ("ecommerce", r'\b(shop|store|mart|bazar|bazaar|online shopping|checkout|deals|order now|free delivery|cash on delivery|wholesale|retail|gadget|fashion|lifestyle)\b|দোকান|কেনাকাটা|অনলাইন শপ|বাজার|অর্ডার|ডেলিভারি|পাইকারি'),
    ("garments", r'\b(garments|textile|apparel|knit|knitwear|woven|sweater|denim|fabric|spinning|dyeing|rmg|buying house|mills|industries|manufacturer)\b|গার্মেন্টস|টেক্সটাইল|পোশাক|কারখানা|শিল্প'),
    ("realestate", r'\b(real ?estate|property|properties|developers?|apartment|flat|housing|plot|builders|construction|infrastructure|holdings)\b|রিয়েল এস্টেট|আবাসন|ফ্ল্যাট|প্লট|জমি|নির্মাণ'),
    ("food", r'\b(restaurant|cafe|kitchen|biryani|biriyani|kabab|kebab|fast food|catering|bakery|sweets|hotel|resort|motel|guest house|banquet|buffet|cuisine)\b|রেস্টুরেন্ট|খাবার|বিরিয়ানি|বেকারি|হোটেল|রিসোর্ট'),
    ("finance", r'\b(bank|banking|finance|financial|insurance|micro(?:finance|credit)|nbfi|leasing|investment|capital|securities|brokerage|mutual fund|remittance)\b|ব্যাংক|অর্থায়ন|বীমা|ঋণ|বিনিয়োগ'),
    ("it", r'\b(software|technolog|web development|app development|digital agency|saas|cloud|hosting|erp|cyber|fintech|developers?|solutions|systems)\b|সফটওয়্যার|প্রযুক্তি|ওয়েব|অ্যাপ|ডিজিটাল'),
    ("ngo", r'\b(ngo|foundation|charity|charitable|trust|welfare|relief|humanitarian|non-?profit|orphanage|zakat|samit[iy])\b|ফাউন্ডেশন|কল্যাণ|সমিতি|সংস্থা|ট্রাস্ট'),
    ("travel", r'\b(travels?|tours?|tourism|holiday|air ticket|ticketing|visa|hajj|umrah|pilgrimage|tour operator|iata|manpower)\b|ট্রাভেল|ভ্রমণ|পর্যটন|হজ|ওমরাহ|ভিসা'),
    ("news", r'\b(news|news24|daily|bulletin|times|tribune|press|media|magazine|journal|television|channel|broadcast|breaking news|editorial)\b|সংবাদ|খবর|দৈনিক|পত্রিকা|মিডিয়া|চ্যানেল'),
    ("government", r'\b(government|govt|ministry|directorate|municipality|city corporation|union parishad|upazila|commission|authority|bureau)\b|সরকার|মন্ত্রণালয়|অধিদপ্তর|পৌরসভা'),
    ("agro", r'\b(agro|agricultur|farms?|nursery|seeds?|fertilizer|pesticide|poultry|dairy|fisheries|hatchery|livestock|shrimp)\b|কৃষি|এগ্রো|খামার|বীজ|পোল্ট্রি|মৎস্য'),
    ("pharma", r'\b(pharmaceuticals?|pharma|pharmacy|medicine|drugs?|laboratories|formulation|gmp|vaccine)\b|ফার্মা|ঔষধ|ওষুধ|ফার্মেসি'),
    ("automobile", r'\b(automobiles?|motors|vehicles?|motorcycle|truck|transport|logistics|courier|rent-?a-?car|spare parts|garage|dealership|automotive)\b|অটোমোবাইল|মোটরস|গাড়ি|পরিবহন'),
    ("professional", r'\b(consult(?:ing|ancy|ants)?|law firm|advocate|chambers|legal|audit|chartered accountant|advisory|marketing|advertising|branding|architects|interior|recruitment|traders?|import|export|enterprise|corporation|group)\b|কনসালট্যান্ট|অডিট'),
]
CATS = [(n, re.compile(p, re.I)) for n, p in CATS]
PRIORITY = ["government", "education", "ngo", "finance", "pharma", "healthcare", "news", "travel",
            "garments", "agro", "automobile", "realestate", "food", "ecommerce", "it", "professional"]


def biz_type(reg, title, body):
    reg = (reg or "").lower()
    if reg.endswith((".gov.bd", ".mil.bd")):
        return "government"
    if reg.endswith((".edu.bd", ".ac.bd")):
        return "education"
    title = (title or "").lower()
    body = (body or "")[:2500]
    scores = {}
    for name, rx in CATS:
        s = len(rx.findall(reg)) * 5 + len(rx.findall(title)) * 3 + len(rx.findall(body)) * 1
        if s:
            scores[name] = s
    if not scores:
        return "general-business"
    best = max(scores.values())
    if best < 2:
        return "general-business"
    winners = [n for n, v in scores.items() if v == best]
    if len(winners) > 1:
        for p in PRIORITY:
            if p in winners:
                return p
    return max(scores, key=scores.get)
