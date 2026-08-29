"""
ScraperRouter — dispatches username+platform to the right scraper.
Also includes lightweight scrapers for Facebook, LinkedIn, YouTube, WhatsApp.
THIS is the single import that main.py needs.
"""
import re, logging
from bs4 import BeautifulSoup
from app.scraper.base import BaseScraper, build_url
from app.scraper.twitter   import TwitterScraper
from app.scraper.instagram  import InstagramScraper
from app.scraper.tiktok    import TikTokScraper
from app.models import ProfileData, Platform

logger = logging.getLogger(__name__)

# ─── Facebook (meta-only, JS wall) ───────────────────────────────
class FacebookScraper(BaseScraper):
    async def scrape(self, url: str, username: str) -> ProfileData:
        try:
            r = await self._get(url)
            if r.status_code == 404: return self._fail(url, Platform.FACEBOOK, username, "Not found")
            soup  = BeautifulSoup(r.text, "lxml")
            title = soup.find("meta", property="og:title")
            desc  = soup.find("meta", property="og:description")
            image = soup.find("meta", property="og:image")
            dn = title.get("content","").strip() if title else None
            bio = desc.get("content","").strip() if desc else None
            pic = image.get("content") if image else None
            if not dn: return self._fail(url, Platform.FACEBOOK, username, "Login wall — meta only")
            logger.info(f"[Facebook] {username} via meta")
            return ProfileData(username=username, display_name=dn, bio=bio,
                platform=Platform.FACEBOOK, profile_url=url,
                profile_picture_url=pic, scrape_successful=True,
                scrape_error="Limited: Facebook meta-only (JS wall)")
        except Exception as e:
            return self._fail(url, Platform.FACEBOOK, username, str(e))

# ─── LinkedIn ────────────────────────────────────────────────────
class LinkedInScraper(BaseScraper):
    async def scrape(self, url: str, username: str) -> ProfileData:
        try:
            r = await self._get(url)
            if r.status_code == 404: return self._fail(url, Platform.LINKEDIN, username, "Not found")
            soup  = BeautifulSoup(r.text, "lxml")
            title = soup.find("meta", property="og:title")
            desc  = soup.find("meta", property="og:description")
            image = soup.find("meta", property="og:image")
            dn  = title.get("content","").split("|")[0].strip() if title else None
            bio = desc.get("content","").strip() if desc else None
            pic = image.get("content") if image else None
            if not dn: return self._fail(url, Platform.LINKEDIN, username, "Login wall")
            logger.info(f"[LinkedIn] {username} via meta")
            return ProfileData(username=username, display_name=dn, bio=bio,
                platform=Platform.LINKEDIN, profile_url=url,
                profile_picture_url=pic, scrape_successful=True,
                scrape_error="Limited: LinkedIn meta-only (login wall)")
        except Exception as e:
            return self._fail(url, Platform.LINKEDIN, username, str(e))

# ─── YouTube ─────────────────────────────────────────────────────
class YouTubeScraper(BaseScraper):
    async def scrape(self, url: str, username: str) -> ProfileData:
        try:
            r = await self._get(url)
            if r.status_code == 404: return self._fail(url, Platform.YOUTUBE, username, "Not found")
            soup = BeautifulSoup(r.text, "lxml")
            title = soup.find("meta", property="og:title")
            desc  = soup.find("meta", property="og:description")
            image = soup.find("meta", property="og:image")
            dn  = title.get("content","").strip() if title else None
            bio = desc.get("content","").strip() if desc else None
            pic = image.get("content") if image else None
            # Try to extract subscriber count
            sub = None
            m = re.search(r'"subscriberCountText":\{"simpleText":"([\d,.KkMm]+)\s*subscribers?"', r.text, re.I)
            if m:
                t = m.group(1).replace(",","").strip()
                try:
                    if t.lower().endswith("k"): sub = int(float(t[:-1])*1000)
                    elif t.lower().endswith("m"): sub = int(float(t[:-1])*1000000)
                    else: sub = int(float(t))
                except: pass
            if not dn: return self._fail(url, Platform.YOUTUBE, username, "Could not parse")
            logger.info(f"[YouTube] @{username}")
            return ProfileData(username=username, display_name=dn, bio=bio,
                platform=Platform.YOUTUBE, profile_url=url,
                follower_count=sub, profile_picture_url=pic, scrape_successful=True)
        except Exception as e:
            return self._fail(url, Platform.YOUTUBE, username, str(e))

# ─── WhatsApp ─────────────────────────────────────────────────────
class WhatsAppScraper(BaseScraper):
    async def scrape(self, url: str, username: str) -> ProfileData:
        digits = re.sub(r"[^\d]", "", username)
        wa_url = f"https://wa.me/{digits}"
        return ProfileData(username=digits, display_name=None,
            platform=Platform.WHATSAPP, profile_url=wa_url,
            scrape_successful=True,
            scrape_error="WhatsApp: profile data not publicly available — phone analysis only")

# ─── Router ───────────────────────────────────────────────────────
class ScraperRouter:
    def __init__(self):
        self._scrapers = {
            Platform.TWITTER:   TwitterScraper(),
            Platform.INSTAGRAM: InstagramScraper(),
            Platform.TIKTOK:    TikTokScraper(),
            Platform.FACEBOOK:  FacebookScraper(),
            Platform.LINKEDIN:  LinkedInScraper(),
            Platform.YOUTUBE:   YouTubeScraper(),
            Platform.WHATSAPP:  WhatsAppScraper(),
        }

    async def scrape(self, username: str, platform: Platform) -> ProfileData:
        url     = build_url(username, platform)
        scraper = self._scrapers.get(platform)
        if not scraper:
            return ProfileData(username=username, platform=platform, profile_url=url,
                scrape_successful=False, scrape_error=f"No scraper for {platform}")
        return await scraper.scrape(url, username)
