import json
import os
from collections import Counter
from django.conf import settings

MAPPING_PATH = os.path.join(settings.BASE_DIR, "hexaShiftApp", "mitre_mapping.json")

try:
    with open(MAPPING_PATH, "r", encoding="utf-8") as f:
        MITRE_MAP = json.load(f)
except Exception:
    MITRE_MAP = {}

def classify_log(raw_text):
    """
    Sadə keyword-based classifier.
    raw_text: str və ya None
    qaytarır: {"mitre_id":..., "attack_family":..., "confidence":...}
    """
    text = (raw_text or "").lower()
    scores = Counter()

    for mitre_id, keywords in MITRE_MAP.items():
        if not isinstance(keywords, (list, tuple)):
            continue
        for kw in keywords:
            try:
                if kw and kw.lower() in text:
                    scores[mitre_id] += 1
            except Exception:
                continue

    if not scores:
        return {"mitre_id": None, "attack_family": "unknown", "confidence": 0.0}

    mitre_id, count = scores.most_common(1)[0]
    confidence = min(1.0, count / 3.0)
    attack_family = mitre_id  
    return {"mitre_id": mitre_id, "attack_family": attack_family, "confidence": confidence}
