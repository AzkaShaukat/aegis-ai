"""F-10: Free reverse image — Yandex (no key) + SerpAPI Lens (optional). Replaces TinEye (paid)."""
import re, logging, httpx, asyncio
from typing import Optional, List, Tuple
from urllib.parse import urlparse
from app.models import ReverseImageResult
from app.config import get_settings

logger   = logging.getLogger(__name__)
settings = get_settings()
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36"

async def _yandex(img_url: str) -> Tuple[int, List[str]]:
    try:
        async with httpx.AsyncClient(timeout=15, follow_redirects=True,
                                      headers={"User-Agent":UA,"Accept-Language":"en-US,en;q=0.9"}) as c:
            r = await c.get("https://yandex.com/images/search",
                params={"rpt":"imageview","url":img_url,"cbir_page":"similar"})
        if r.status_code not in (200,302): return 0, []
        domains = re.findall(r'"site"\s*:\s*"([a-zA-Z0-9.\-]+\.[a-z]{2,})"', r.text)
        hrefs   = re.findall(r'href="https?://([a-zA-Z0-9.\-]+\.[a-z]{2,})/', r.text)
        clean   = list({d for d in set(domains+hrefs) if "yandex" not in d and "ya.ru" not in d})
        return len(clean), clean[:12]
    except Exception as e:
        logger.debug(f"[F-10] Yandex: {e}"); return 0, []

async def _serpapi(img_url: str) -> Tuple[int, List[str]]:
    if not settings.serpapi_key: return 0, []
    try:
        async with httpx.AsyncClient(timeout=20) as c:
            r = await c.get("https://serpapi.com/search",
                params={"engine":"google_lens","url":img_url,"api_key":settings.serpapi_key})
        if r.status_code != 200: return 0, []
        data    = r.json()
        results = data.get("visual_matches",[]) + data.get("image_results",[])
        domains = list({urlparse(i.get("link","")).netloc for i in results if i.get("link","")})
        return len(results), [d for d in domains if d][:12]
    except Exception as e:
        logger.debug(f"[F-10] SerpAPI: {e}"); return 0, []

SKIP = ["localhost","127.0.0.1","default_profile","blank.png","placeholder","twimg.com/sticky"]

async def analyze_reverse_image(pic_url: Optional[str]) -> ReverseImageResult:
    if not pic_url or any(s in pic_url for s in SKIP):
        return ReverseImageResult(available=False,details={"skipped":"No usable image URL"})
    (sc, sd), (yc, yd) = await asyncio.gather(_serpapi(pic_url), _yandex(pic_url))
    count, domains, source = (sc,sd,"SerpAPI") if sc >= yc else (yc,yd,"Yandex")
    pts    = 20 if count>15 else 15 if count>5 else 5 if count>1 else 0
    stolen = 5 < count <= 15; stock = count > 15
    logger.info(f"[F-10] {source}: {count} matches → pts={pts}")
    return ReverseImageResult(available=True,match_count=count,stolen_identity=stolen,
        is_stock_photo=stock,suspicion_points=pts,
        details={"source":source,"domains":domains,"yandex_count":yc,"serpapi_count":sc,
                 "note":"TinEye is paid — using free Yandex+SerpAPI"})
