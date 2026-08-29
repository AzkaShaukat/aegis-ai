"""F-12: SerpAPI Google Images reverse search. 100/month free."""
import logging, httpx
from typing import Optional
from urllib.parse import urlparse
from app.models import SerpApiResult
from app.config import get_settings

logger   = logging.getLogger(__name__)
settings = get_settings()

async def analyze_serpapi_image(pic_url: Optional[str]) -> SerpApiResult:
    if not pic_url: return SerpApiResult(available=False,details={"skipped":"No image URL"})
    if not settings.serpapi_key: return SerpApiResult(available=False,details={"skipped":"Set SERPAPI_KEY in .env (free: serpapi.com)"})
    try:
        async with httpx.AsyncClient(timeout=20) as c:
            r = await c.get("https://serpapi.com/search",
                params={"engine":"google_images_reverse","image_url":pic_url,"api_key":settings.serpapi_key})
        if r.status_code != 200: return SerpApiResult(available=False,details={"error":f"HTTP {r.status_code}"})
        data    = r.json()
        results = data.get("image_results",[])
        domains = list({urlparse(i.get("link","")).netloc for i in results if i.get("link","")})
        count   = len(results); udom = len(domains)
        pts     = 15 if count>10 else 8 if count>4 else 3 if count>1 else 0
        logger.info(f"[F-12] SerpAPI images: count={count} domains={udom} pts={pts}")
        return SerpApiResult(available=True,match_count=count,unique_domains=udom,
            suspicion_points=pts,details={"top_domains":domains[:8]})
    except Exception as e:
        return SerpApiResult(available=False,details={"error":str(e)})
