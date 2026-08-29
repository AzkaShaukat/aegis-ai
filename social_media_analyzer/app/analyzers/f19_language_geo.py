"""F-19: Language + geo mismatch detection (no key). Max 15 pts."""
import re, logging
from typing import Optional, List, Dict, Any
from app.models import LanguageGeoResult

logger = logging.getLogger(__name__)

# Language detection by script/character sets
ARABIC_RE  = re.compile(r'[\u0600-\u06FF\u0750-\u077F]')
CHINESE_RE = re.compile(r'[\u4e00-\u9fff]')
CYRILLIC_RE = re.compile(r'[\u0400-\u04FF]')
DEVANAGARI_RE = re.compile(r'[\u0900-\u097F]')
KOREAN_RE  = re.compile(r'[\uAC00-\uD7AF]')
JAPANESE_RE = re.compile(r'[\u3040-\u30FF]')
LATIN_RE   = re.compile(r'[a-zA-Z]')

# Location → expected language/script
GEO_LANG_MAP = {
    "pakistan": "arabic_or_latin", "pk": "arabic_or_latin",
    "india": "devanagari_or_latin", "in": "devanagari_or_latin",
    "china": "chinese", "cn": "chinese",
    "russia": "cyrillic", "ru": "cyrillic",
    "korea": "korean", "kr": "korean",
    "japan": "japanese", "jp": "japanese",
    "saudi": "arabic", "uae": "arabic", "egypt": "arabic", "arab": "arabic",
    "usa": "latin", "uk": "latin", "us": "latin", "canada": "latin",
    "france": "latin", "germany": "latin", "spain": "latin", "italy": "latin",
}

def _detect_script(text: str) -> str:
    if not text: return "unknown"
    counts = {
        "arabic":    len(ARABIC_RE.findall(text)),
        "chinese":   len(CHINESE_RE.findall(text)),
        "cyrillic":  len(CYRILLIC_RE.findall(text)),
        "devanagari": len(DEVANAGARI_RE.findall(text)),
        "korean":    len(KOREAN_RE.findall(text)),
        "japanese":  len(JAPANESE_RE.findall(text)),
        "latin":     len(LATIN_RE.findall(text)),
    }
    dominant = max(counts, key=counts.get)
    return dominant if counts[dominant] > 3 else "unknown"

def analyze_language_geo(bio: Optional[str], location: Optional[str],
                          posts: Optional[List[Dict[str,Any]]] = None) -> Dict[str,Any]:
    pts = 0; flags = []; mismatch = False
    bio_text = bio or ""
    post_text = " ".join(p.get("text","") or p.get("caption","") or "" for p in (posts or [])[:10])
    all_text = f"{bio_text} {post_text}".strip()
    detected = _detect_script(all_text)
    # Check claimed location vs detected language
    claimed = None
    if location:
        loc_lower = location.lower()
        for geo, expected_lang in GEO_LANG_MAP.items():
            if geo in loc_lower:
                claimed = geo; expected = expected_lang; break
        else: expected = None
        if claimed and expected and detected not in ("unknown","latin"):
            if detected not in expected:
                pts += 10; mismatch = True
                flags.append(f"lang_mismatch:claimed={claimed} detected={detected}")
    # Unusually many languages in a single profile (bot content farm)
    scripts_found = sum(1 for pat in [ARABIC_RE,CHINESE_RE,CYRILLIC_RE,DEVANAGARI_RE,KOREAN_RE]
                        if len(pat.findall(all_text)) > 5)
    if scripts_found >= 3: pts += 8; flags.append(f"multilang_content_farm:{scripts_found}_scripts")
    pts = min(pts, 15)
    logger.info(f"[F-19] detected={detected} claimed_loc={location} mismatch={mismatch} pts={pts}")
    return {"suspicion_points":pts,"detected_language":detected,"claimed_location":location,
            "language_mismatch":mismatch,"flags":flags,
            "details":{"all_text_chars":len(all_text),"scripts_found":scripts_found}}
