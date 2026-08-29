"""
Block 2 — Content & Language Intelligence
All checks consolidated.
"""
import re, statistics, asyncio, logging
from typing import Any, Dict, List, Optional, Tuple
import httpx

from app.config import get_settings
from app.models import BioResult, PostsResult, LinksResult, LinkResult, LanguageResult, PostSample
from data.patterns import (
    BIO_SCAM_CATEGORIES, PK_SCAM_PATTERNS, POST_TEMPLATE_PATTERNS,
    ENGAGEMENT_BAIT_PATTERNS, SCHEDULER_APPS, SUSPICIOUS_LINK_SERVICES,
    HIGH_RISK_LINK_SERVICES, LOOKALIKE_BRANDS, PHISHING_PATH_KEYWORDS,
    GEO_LANG_MAP, SCRIPT_RANGES, CRYPTO_WALLET_RE, PHONE_RE,
    EMOJI_RE, URL_RE, ROMAN_URDU_MARKERS,
)

logger   = logging.getLogger(__name__)
settings = get_settings()
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"


# ─────────────────────────────────────────────────────────────────────────────
#  BIO NLP
# ─────────────────────────────────────────────────────────────────────────────
def analyze_bio(bio: str, claimed_location: Optional[str] = None,
                ollama_result: Optional[Dict] = None) -> BioResult:
    r = BioResult(bio_length=len(bio))
    pts, flags = 0, []
    bio_l = bio.lower()

    # BIO-01..05: Keyword categories
    for cat, kws in BIO_SCAM_CATEGORIES.items():
        hits = sum(1 for kw in kws if kw in bio_l)
        if hits > 0:
            r.scam_category_hits[cat] = hits
            cat_pts = min(hits * 4, 16)
            pts += cat_pts
            flags.append(f"bio_scam_category:{cat}:{hits}hits")

    # BIO-06: Suspicious link services in bio
    bio_urls = URL_RE.findall(bio)
    for url in bio_urls:
        u_lower = url.lower()
        for svc in SUSPICIOUS_LINK_SERVICES:
            if svc in u_lower:
                r.has_suspicious_links = True
                pts += 8; flags.append(f"suspicious_link_in_bio:{svc}")
                break

    # BIO-07: Emoji density
    emojis = EMOJI_RE.findall(bio)
    words  = bio.split()
    r.emoji_density = round(len(emojis) / max(len(words), 1), 3)
    if len(emojis) >= 8:
        pts += 10; flags.append(f"very_high_emoji_density:{len(emojis)}")
    elif len(emojis) >= 4:
        pts += 5; flags.append(f"high_emoji_density:{len(emojis)}")

    # BIO-08: Phone number in bio
    if PHONE_RE.search(bio):
        r.has_phone_in_bio = True
        pts += 8; flags.append("phone_number_in_bio")

    # BIO-09: Excessive ALL CAPS
    cap_words = [w for w in words if len(w) >= 3 and w.isupper() and w.isalpha()]
    if len(cap_words) >= 3:
        r.excessive_caps = True
        pts += 8; flags.append(f"excessive_caps:{len(cap_words)}words")

    # BIO-11: PK-specific
    for cat, kws in PK_SCAM_PATTERNS.items():
        hits = sum(1 for kw in kws if kw in bio_l)
        if hits > 0:
            pts += min(hits * 5, 18)
            flags.append(f"pk_scam_pattern:{cat}:{hits}hits")

    # BONUS: Crypto wallet in bio
    if CRYPTO_WALLET_RE.search(bio):
        r.has_crypto_wallet = True
        pts += 20; flags.append("crypto_wallet_address_in_bio")

    # BIO-13: Script vs claimed location
    if claimed_location:
        detected = _detect_scripts(bio)
        expected = GEO_LANG_MAP.get(claimed_location.lower(), set())
        if expected and not any(s in expected for s in detected) and len(detected) > 0:
            pts += 10; flags.append(f"script_mismatch:detected={detected},expected={expected}")

    # BIO-10/12: Ollama enrichment (if pre-computed)
    if ollama_result:
        r.ollama_scam_score   = ollama_result.get("scam_score")
        r.ai_generated_bio    = ollama_result.get("is_ai_generated")
        if r.ollama_scam_score and r.ollama_scam_score > 60:
            pts += 15; flags.append(f"ollama_bio_scam_score:{r.ollama_scam_score}")
        if r.ai_generated_bio:
            pts += 10; flags.append("ollama_ai_generated_bio_detected")

    r.suspicion_score = pts; r.flags = flags
    return r.finalize()


def _detect_scripts(text: str) -> set:
    detected = set()
    for char in text:
        cp = ord(char)
        for name, (lo, hi) in SCRIPT_RANGES.items():
            if lo <= cp <= hi:
                detected.add(name)
    return detected


# ─────────────────────────────────────────────────────────────────────────────
#  POST ANALYSIS
# ─────────────────────────────────────────────────────────────────────────────
def analyze_posts(posts: List[PostSample]) -> PostsResult:
    r = PostsResult(post_count=len(posts))
    if not posts:
        return r
    pts, flags = 0, []

    texts     = [p.text for p in posts if p.text]
    timestamps = [p.timestamp for p in posts if p.timestamp]
    sources    = [p.source_app for p in posts if p.source_app]
    reposts    = sum(1 for p in posts if p.is_repost)

    # POST-01: Interval CV
    if len(timestamps) >= 4:
        try:
            from datetime import datetime
            dts = sorted(datetime.fromisoformat(t.replace("Z", "+00:00")) for t in timestamps)
            gaps = [(dts[i+1]-dts[i]).total_seconds() for i in range(len(dts)-1)]
            if gaps:
                mean_gap = statistics.mean(gaps)
                std_gap  = statistics.stdev(gaps) if len(gaps) > 1 else 0
                cv = std_gap / mean_gap if mean_gap > 0 else 0
                r.interval_cv = round(cv, 4)
                if cv < 0.15:
                    r.bot_posting_pattern = True
                    pts += 20; flags.append(f"bot_posting_interval:cv={cv:.3f}")
        except Exception:
            pass

    # POST-02: 24/7 posting
    if len(timestamps) >= 12:
        try:
            from datetime import datetime, timezone
            hours = set()
            for t in timestamps:
                dt = datetime.fromisoformat(t.replace("Z", "+00:00"))
                hours.add(dt.hour)
            dead_hours = 24 - len(hours)
            if dead_hours <= 3:
                r.no_sleep_hours = True
                pts += 15; flags.append(f"no_sleep_posting:only_{dead_hours}_dead_hours")
        except Exception:
            pass

    # POST-04: Copy-paste detection
    if len(texts) >= 3:
        sims = []
        sets = [set(t.lower().split()) for t in texts]
        for i in range(len(sets)):
            for j in range(i+1, min(i+6, len(sets))):
                a, b = sets[i], sets[j]
                if a | b:
                    sims.append(len(a & b) / len(a | b))
        if sims:
            avg_sim = statistics.mean(sims)
            r.copy_paste_score = round(avg_sim, 3)
            if avg_sim > 0.7:
                pts += 18; flags.append(f"copy_paste_posts:avg_jaccard={avg_sim:.2f}")
            elif avg_sim > 0.5:
                pts += 8; flags.append(f"similar_posts:avg_jaccard={avg_sim:.2f}")

    # POST-05: Hashtag spam
    total_hashtags = sum(len(p.hashtags) for p in posts)
    r.hashtag_count = total_hashtags
    if total_hashtags > 50:
        pts += 10; flags.append(f"hashtag_spam:{total_hashtags}_total_hashtags")

    # POST-06: Template patterns
    template_hits = 0
    for text in texts:
        for pat in POST_TEMPLATE_PATTERNS:
            if pat.search(text):
                template_hits += 1
                break
    r.template_hits = template_hits
    if template_hits >= 3:
        pts += 15; flags.append(f"scam_template_posts:{template_hits}hits")
    elif template_hits >= 1:
        pts += 8

    # POST-07: Repost ratio
    if posts:
        ratio = reposts / len(posts)
        r.repost_ratio = round(ratio, 3)
        if ratio > 0.9:
            pts += 10; flags.append(f"high_repost_ratio:{ratio:.0%}")

    # POST-08: Scheduler
    sched_found = {s.lower() for s in sources if any(app in s.lower() for app in SCHEDULER_APPS)}
    if sched_found:
        r.scheduler_detected = True
        r.scheduler_apps = list(sched_found)
        pts += 8; flags.append(f"scheduler_tool:{','.join(sched_found)}")

    # POST-09: Engagement bait
    for text in texts:
        for pat in ENGAGEMENT_BAIT_PATTERNS:
            if pat.search(text):
                r.engagement_bait = True
                pts += 5; flags.append("engagement_bait_detected")
                break
        if r.engagement_bait:
            break

    r.suspicion_score = pts; r.flags = flags
    return r.finalize()


# ─────────────────────────────────────────────────────────────────────────────
#  LINK SAFETY
# ─────────────────────────────────────────────────────────────────────────────
async def _vt_check(url: str, session: httpx.AsyncClient) -> Tuple[bool, int]:
    if not settings.virustotal_api_key:
        return False, 0
    try:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        r = await session.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={"x-apikey": settings.virustotal_api_key},
            timeout=10,
        )
        if r.status_code == 200:
            stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            mal = stats.get("malicious", 0)
            return mal > 0, mal
    except Exception:
        pass
    return False, 0


async def _unshorten(url: str, session: httpx.AsyncClient) -> Optional[str]:
    try:
        r = await session.head(url, follow_redirects=True, timeout=8)
        final = str(r.url)
        return final if final != url else None
    except Exception:
        return None


def _levenshtein(a: str, b: str) -> int:
    if len(a) < len(b): a, b = b, a
    if not b: return len(a)
    prev = list(range(len(b)+1))
    for i, ca in enumerate(a):
        curr = [i+1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j+1]+1, curr[j]+1, prev[j]+(ca != cb)))
        prev = curr
    return prev[-1]


def _check_lookalike(domain: str) -> Optional[str]:
    d = re.sub(r"\.(com|net|org|io|pk|co|me|info|biz)$", "", domain.lower())
    for brand in LOOKALIKE_BRANDS:
        if d == brand:
            return None  # exact match = real
        if _levenshtein(d, brand) <= 2:
            return brand
        if d.startswith(brand) and len(d) > len(brand):
            return brand
    return None


async def analyze_links(urls: List[str]) -> LinksResult:
    r = LinksResult(links_analyzed=len(urls))
    pts, flags = 0, []

    async with httpx.AsyncClient(
        headers={"User-Agent": UA}, follow_redirects=False, timeout=10
    ) as session:
        tasks = [_analyze_single_link(u, session) for u in urls[:20]]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    for res in results:
        if isinstance(res, LinkResult):
            r.link_details.append(res)
            pts += res.score
            if res.is_malicious:
                r.malicious_count += 1
                flags.append(f"malicious_url:{res.url[:60]}")
            if res.is_shortener:
                r.shortener_count += 1
            if res.is_lookalike:
                r.lookalike_count += 1
                flags.append(f"lookalike_domain:{res.lookalike_brand}")

    if r.malicious_count > 0:
        flags.insert(0, f"{r.malicious_count}_malicious_urls_detected")
    r.suspicion_score = pts; r.flags = flags
    return r.finalize()


async def _analyze_single_link(url: str, session: httpx.AsyncClient) -> LinkResult:
    lr = LinkResult(url=url)
    s  = 0
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url if "://" in url else "https://" + url)
        domain = parsed.netloc.lower().lstrip("www.")
        path   = parsed.path.lower()

        lr.is_https = parsed.scheme == "https"
        if not lr.is_https: s += 5

        # Shortener + redirect chain
        for svc in SUSPICIOUS_LINK_SERVICES:
            if svc in domain:
                lr.is_shortener = True
                s += 8; break
        if lr.is_shortener:
            final = await _unshorten(url, session)
            lr.final_url = final

        # Lookalike domain
        brand = _check_lookalike(domain)
        if brand:
            lr.is_lookalike   = True
            lr.lookalike_brand = brand
            s += 25

        # Phishing path
        for kw in PHISHING_PATH_KEYWORDS:
            if kw in path:
                lr.is_phishing_path = True
                s += 20; break

        # High-risk service
        for svc in HIGH_RISK_LINK_SERVICES:
            if svc in domain:
                lr.is_high_risk_service = True
                s += 12; break

        # VirusTotal
        is_mal, mal_count = await _vt_check(url, session)
        lr.is_malicious = is_mal
        lr.vt_malicious = mal_count
        if is_mal: s += 30

    except Exception as e:
        logger.debug(f"[link] {e}")

    lr.score = min(s, 50)
    return lr


# ─────────────────────────────────────────────────────────────────────────────
#  LANGUAGE & GEO
# ─────────────────────────────────────────────────────────────────────────────
def analyze_language(
    bio:              Optional[str],
    posts:            Optional[List[PostSample]],
    claimed_location: Optional[str],
    claimed_timezone: Optional[str],
    exif_gps_lat:     Optional[float],
    exif_gps_lon:     Optional[float],
) -> LanguageResult:
    r = LanguageResult(claimed_location=claimed_location)
    pts, flags = 0, []

    all_texts = []
    if bio: all_texts.append(bio)
    if posts:
        all_texts.extend(p.text for p in posts if p.text)

    combined = " ".join(all_texts)

    # Detect scripts
    detected_scripts = list(_detect_scripts(combined))
    r.detected_scripts = detected_scripts

    # GEO-01: Script vs location mismatch
    if claimed_location and detected_scripts:
        expected = GEO_LANG_MAP.get(claimed_location.lower(), set())
        if expected and not any(s in expected for s in detected_scripts):
            r.script_mismatch = True
            pts += 15; flags.append(f"script_mismatch:location={claimed_location},detected={detected_scripts}")

    # GEO-02: Multilanguage content farm (3+ scripts)
    if len(detected_scripts) >= 3:
        r.multilang_farm = True
        pts += 12; flags.append(f"multilang_content_farm:{len(detected_scripts)}_scripts")

    # GEO-03: Timezone inference
    if posts and len(posts) >= 8:
        try:
            from datetime import datetime
            hours = []
            for p in posts:
                if p.timestamp:
                    dt = datetime.fromisoformat(p.timestamp.replace("Z", "+00:00"))
                    hours.append(dt.hour)
            if hours:
                avg_h = statistics.mean(hours)
                utc_offset = round((avg_h - 13) % 24 - 12)
                tz_labels = {5: "Asia/Karachi (PKT)", 0: "UTC", -5: "America/New_York"}
                r.inferred_timezone = tz_labels.get(utc_offset, f"UTC{utc_offset:+d}")
                if claimed_timezone and abs(utc_offset - 5) > 3:
                    r.timezone_mismatch = True
                    pts += 10; flags.append(f"timezone_mismatch:inferred={r.inferred_timezone}")
        except Exception:
            pass

    # GEO-06: Per-post language detection
    if posts:
        try:
            from langdetect import detect
            langs = []
            for p in posts[:10]:
                if p.text and len(p.text) > 20:
                    try:
                        langs.append(detect(p.text))
                    except Exception:
                        pass
            r.per_post_languages = langs
        except ImportError:
            pass

    r.suspicion_score = pts; r.flags = flags
    return r.finalize()
