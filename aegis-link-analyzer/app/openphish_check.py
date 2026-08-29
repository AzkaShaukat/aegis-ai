"""
openphish_check.py
Aegis Link Analyzer

OpenPhish community phishing feed checker.
Replaces PhishTank (registration permanently disabled by Cisco Talos).

Feed is cached in Redis with a 6-hour TTL to avoid fetching on every scan.
Includes retry logic and a fallback mirror URL.
"""

import httpx
import redis.asyncio as redis
from typing import Dict, List
from urllib.parse import urlparse

REDIS_URL        = "redis://redis:6379"
FEED_CACHE_KEY   = "openphish:feed"
FEED_TTL_SECONDS = 6 * 60 * 60  # 6 hours

# Primary + fallback feed URLs
FEED_URLS = [
    "https://openphish.com/feed.txt",
    "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt",
]


async def _fetch_feed() -> List[str]:
    """Fetches the OpenPhish feed, trying each URL in order."""
    for feed_url in FEED_URLS:
        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                resp = await client.get(
                    feed_url,
                    headers={"User-Agent": "AegisLinkAnalyzer/4.0 (security-research)"},
                    follow_redirects=True,
                )
                if resp.status_code == 200 and resp.text.strip():
                    urls = [ln.strip() for ln in resp.text.splitlines() if ln.strip()]
                    if urls:
                        try:
                            r = redis.from_url(REDIS_URL, encoding="utf-8", decode_responses=True)
                            await r.set(FEED_CACHE_KEY, "\n".join(urls), ex=FEED_TTL_SECONDS)
                        except Exception:
                            pass
                        return urls
        except Exception:
            continue
    return []


async def _get_feed() -> List[str]:
    """Returns feed from Redis cache, or fetches fresh if expired."""
    try:
        r = redis.from_url(REDIS_URL, encoding="utf-8", decode_responses=True)
        cached = await r.get(FEED_CACHE_KEY)
        if cached:
            return [ln for ln in cached.splitlines() if ln.strip()]
    except Exception:
        pass
    return await _fetch_feed()


def _normalize(url: str) -> str:
    url = url.lower().strip().rstrip("/")
    url = url.replace("://www.", "://")
    return url


def _domain(url: str) -> str:
    try:
        h = urlparse(url).netloc.lower()
        return h.lstrip("www.").split(":")[0]
    except Exception:
        return ""


async def run_openphish_check(url: str) -> Dict:
    flags: List[str] = []

    try:
        feed = await _get_feed()

        if not feed:
            return {
                "found": False, "match_type": None, "matched_entry": None,
                "feed_size": 0, "source": "openphish",
                "flags": ["OpenPhish feed unavailable — check skipped"],
                "phishtank_score": 0, "is_suspicious": False,
            }

        norm_url    = _normalize(url)
        url_domain  = _domain(url)

        # Level 1: exact URL match
        for entry in feed:
            if _normalize(entry) == norm_url:
                return {
                    "found": True, "match_type": "exact_url",
                    "matched_entry": entry, "feed_size": len(feed),
                    "source": "openphish",
                    "flags": ["🚨 CONFIRMED PHISHING: URL found in OpenPhish live phishing feed"],
                    "phishtank_score": 100, "is_suspicious": True,
                }

        # Level 2: domain match
        if url_domain:
            for entry in feed:
                if _domain(entry) == url_domain:
                    return {
                        "found": True, "match_type": "domain",
                        "matched_entry": entry, "feed_size": len(feed),
                        "source": "openphish",
                        "flags": [
                            f"⚠️ Domain '{url_domain}' is associated with phishing "
                            "entries in OpenPhish feed"
                        ],
                        "phishtank_score": 75, "is_suspicious": True,
                    }

        return {
            "found": False, "match_type": None, "matched_entry": None,
            "feed_size": len(feed), "source": "openphish",
            "flags": [], "phishtank_score": 0, "is_suspicious": False,
        }

    except Exception as e:
        return {
            "found": False, "match_type": None, "matched_entry": None,
            "feed_size": 0, "source": "openphish",
            "flags": [f"OpenPhish check failed: {str(e)}"],
            "phishtank_score": 0, "is_suspicious": False,
        }
