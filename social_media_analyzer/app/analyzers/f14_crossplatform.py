"""F-14: Cross-platform username existence check (free, no key). Max 15 pts."""
import asyncio, logging, httpx
from typing import Dict, List
from app.models import Platform

logger = logging.getLogger(__name__)
TARGETS: Dict[str, str] = {
    "twitter":   "https://twitter.com/{u}",
    "instagram": "https://www.instagram.com/{u}/",
    "tiktok":    "https://www.tiktok.com/@{u}",
    "youtube":   "https://www.youtube.com/@{u}",
    "github":    "https://github.com/{u}",
    "reddit":    "https://www.reddit.com/user/{u}",
    "pinterest": "https://www.pinterest.com/{u}/",
}
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36"

async def _exists(client: httpx.AsyncClient, platform: str, url: str):
    try:
        r = await client.head(url, timeout=8, follow_redirects=True)
        return platform, r.status_code == 200
    except: return platform, False

async def analyze_crossplatform(username: str, current_platform: str) -> dict:
    targets = {p:u.format(u=username) for p,u in TARGETS.items() if p != current_platform.lower()}
    async with httpx.AsyncClient(headers={"User-Agent":UA}, follow_redirects=True) as c:
        results = await asyncio.gather(*[_exists(c,p,u) for p,u in targets.items()], return_exceptions=True)
    found = [p for r in results if isinstance(r,tuple) and r[1] for p,_ in [r]]
    pts = 0; flags = []
    if len(found) >= 5: pts = 15; flags.append("registered_5+_platforms")
    elif len(found) >= 3: pts = 8; flags.append(f"registered_{len(found)}_platforms")
    logger.info(f"[F-14] @{username}: found={found} pts={pts}")
    return {"found_on_platforms":found,"platforms_checked":list(targets.keys()),
            "suspicion_points":pts,"flags":flags,
            "details":{"note":"Multi-platform only suspicious combined with other signals"}}
