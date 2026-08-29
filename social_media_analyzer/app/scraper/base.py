"""URL builder + HTTP base for all scrapers."""
import re, httpx, asyncio, logging
from abc import ABC, abstractmethod
from app.models import ProfileData, Platform
from app.config import get_settings

logger   = logging.getLogger(__name__)
settings = get_settings()

HEADERS = {
    "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                   "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"),
    "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "DNT": "1",
}

URL_TEMPLATES = {
    Platform.TWITTER:   "https://twitter.com/{u}",
    Platform.INSTAGRAM: "https://www.instagram.com/{u}/",
    Platform.TIKTOK:    "https://www.tiktok.com/@{u}",
    Platform.FACEBOOK:  "https://www.facebook.com/{u}",
    Platform.LINKEDIN:  "https://www.linkedin.com/in/{u}/",
    Platform.YOUTUBE:   "https://www.youtube.com/@{u}",
    Platform.WHATSAPP:  "https://wa.me/{u}",
}

def build_url(username: str, platform: Platform) -> str:
    tpl = URL_TEMPLATES.get(platform)
    if not tpl: raise ValueError(f"No template for {platform}")
    if platform == Platform.WHATSAPP:
        return tpl.format(u=re.sub(r"[^\d]", "", username))
    return tpl.format(u=username)

class BaseScraper(ABC):
    async def _get(self, url: str, extra: dict = None) -> httpx.Response:
        h = {**HEADERS, **(extra or {})}
        async with httpx.AsyncClient(follow_redirects=True, timeout=settings.scraper_timeout) as c:
            await asyncio.sleep(settings.scraper_delay)
            return await c.get(url, headers=h)

    @abstractmethod
    async def scrape(self, url: str, username: str) -> ProfileData: ...

    def _fail(self, url: str, platform: Platform, username: str, err: str) -> ProfileData:
        return ProfileData(username=username, platform=platform, profile_url=url,
                           scrape_successful=False, scrape_error=err)
