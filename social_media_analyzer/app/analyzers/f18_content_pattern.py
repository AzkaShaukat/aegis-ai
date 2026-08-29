"""F-18: Content pattern analysis — copy-paste templates, repetitive posts (no key). Max 20 pts."""
import re, logging, math
from typing import List, Dict, Any
from app.models import ContentPatternResult

logger = logging.getLogger(__name__)
TEMPLATE_PATTERNS = [
    re.compile(r"(dm|message|contact)\s+(me|us)\s+for\s+(price|info|details|investment)", re.I),
    re.compile(r"(send|transfer)\s+[\d.]+\s*(btc|eth|usdt|crypto)", re.I),
    re.compile(r"(guaranteed|100%)\s+(profit|returns|income)", re.I),
    re.compile(r"(join|subscribe)\s+(my|our)\s+(channel|group|telegram|whatsapp)", re.I),
    re.compile(r"(i\s+made|earned|received)\s+\$[\d,]+\s+in\s+\d+\s+(days?|hours?|weeks?)", re.I),
    re.compile(r"(limited\s+slots?|only\s+\d+\s+spots?\s+left)", re.I),
    re.compile(r"(click|tap)\s+(the\s+)?(link\s+in\s+(my|the)\s+bio)", re.I),
]

def _similarity(a: str, b: str) -> float:
    """Jaccard similarity of word sets."""
    wa = set(re.findall(r'\w+', a.lower()))
    wb = set(re.findall(r'\w+', b.lower()))
    if not wa or not wb: return 0.0
    return len(wa & wb) / len(wa | wb)

def analyze_content_pattern(posts: List[Dict[str,Any]], bio: str = "") -> Dict[str,Any]:
    pts = 0; flags = []; template_detected = False
    # 1. Template patterns in bio
    for pat in TEMPLATE_PATTERNS:
        if pat.search(bio or ""):
            pts += 8; flags.append(f"template_in_bio"); template_detected = True; break
    # 2. Copy-paste posts (very similar to each other)
    captions = [p.get("text","") or p.get("caption","") or "" for p in posts if p.get("text") or p.get("caption")]
    if len(captions) >= 4:
        similarities = []
        for i in range(min(len(captions)-1, 10)):
            sim = _similarity(captions[i], captions[i+1])
            similarities.append(sim)
        if similarities:
            avg_sim = sum(similarities)/len(similarities)
            if avg_sim > 0.8: pts += 20; flags.append(f"copy_paste_posts:avg_sim={avg_sim:.2f}"); template_detected = True
            elif avg_sim > 0.6: pts += 12; flags.append(f"very_similar_posts:avg_sim={avg_sim:.2f}")
            elif avg_sim > 0.4: pts += 6; flags.append(f"similar_posts:avg_sim={avg_sim:.2f}")
    # 3. Repetitive hashtag blocks
    all_text = " ".join(captions[:20])
    hashtags = re.findall(r'#\w+', all_text.lower())
    if len(hashtags) > 50: pts += 8; flags.append(f"hashtag_spam:{len(hashtags)}")
    pts = min(pts, 20)
    logger.info(f"[F-18] content: template={template_detected} pts={pts}")
    return {"suspicion_points":pts,"template_detected":template_detected,"flags":flags,
            "details":{"posts_analyzed":len(posts),"captions_found":len(captions)}}
