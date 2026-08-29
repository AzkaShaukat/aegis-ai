"""TikTok public profile scraper (SIGI_STATE JSON + OG meta fallback)."""
import re, json, logging
from datetime import datetime
from typing import Optional, Any
from bs4 import BeautifulSoup
from app.scraper.base import BaseScraper
from app.models import ProfileData, Platform

logger = logging.getLogger(__name__)
TT_H = {"User-Agent":"Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
        "Referer":"https://www.tiktok.com/"}

def _n(v: Any) -> Optional[int]:
    if v is None: return None
    try:
        s = str(v).replace(",","").strip()
        if s.lower().endswith("k"): return int(float(s[:-1])*1000)
        if s.lower().endswith("m"): return int(float(s[:-1])*1000000)
        return int(float(s))
    except: return None

class TikTokScraper(BaseScraper):
    async def scrape(self, url: str, username: str) -> ProfileData:
        canonical = f"https://www.tiktok.com/@{username}"
        try:
            r = await self._get(canonical, extra=TT_H)
            if r.status_code == 404: return self._fail(url, Platform.TIKTOK, username, "Not found")
            if r.status_code != 200: return self._fail(url, Platform.TIKTOK, username, f"HTTP {r.status_code}")
            p = self._from_sigi(r.text, username, canonical)
            if p: logger.info(f"[TikTok] @{username} via SIGI_STATE"); return p
            p = self._from_meta(r.text, username, canonical)
            if p: logger.info(f"[TikTok] @{username} via meta"); return p
            return self._fail(url, Platform.TIKTOK, username, "Could not parse TikTok page")
        except Exception as e:
            return self._fail(url, Platform.TIKTOK, username, str(e))

    def _from_sigi(self, html: str, username: str, url: str) -> Optional[ProfileData]:
        for pattern in [r'<script id="SIGI_STATE"[^>]*>(.*?)</script>',
                        r'<script id="__UNIVERSAL_DATA_FOR_REHYDRATION__"[^>]*>(.*?)</script>']:
            m = re.search(pattern, html, re.DOTALL)
            if not m: continue
            try:
                data = json.loads(m.group(1))
                u = self._find_user_tt(data, username.lower())
                if u: return self._build_tt(u, username, url)
            except: continue
        return None

    def _find_user_tt(self, data: Any, username: str) -> Optional[dict]:
        if isinstance(data, dict):
            # TikTok stores user under various keys
            for key in ["UserModule","userInfo","user"]:
                if key in data:
                    sub = data[key]
                    if isinstance(sub, dict):
                        # UserModule has users dict
                        users = sub.get("users", sub)
                        if isinstance(users, dict):
                            for k, v in users.items():
                                if isinstance(v, dict) and v.get("uniqueId","").lower() == username:
                                    return v
                        elif isinstance(sub, dict) and sub.get("uniqueId","").lower() == username:
                            return sub
            for v in data.values():
                r = self._find_user_tt(v, username)
                if r: return r
        elif isinstance(data, list):
            for item in data:
                r = self._find_user_tt(item, username)
                if r: return r
        return None

    def _build_tt(self, u: dict, username: str, url: str) -> ProfileData:
        stats = u.get("stats", {})
        return ProfileData(username=u.get("uniqueId", username),
            display_name=u.get("nickname"),
            platform=Platform.TIKTOK, profile_url=url,
            follower_count=stats.get("followerCount"),
            following_count=stats.get("followingCount"),
            post_count=stats.get("videoCount"),
            is_verified=u.get("verified", False),
            is_private=u.get("privateAccount", False),
            bio=u.get("signature"),
            profile_picture_url=u.get("avatarLarger") or u.get("avatarMedium"),
            scrape_successful=True)

    def _from_meta(self, html: str, username: str, url: str) -> Optional[ProfileData]:
        soup = BeautifulSoup(html, "lxml")
        desc  = soup.find("meta", property="og:description") or soup.find("meta", attrs={"name":"description"})
        title = soup.find("meta", property="og:title")
        image = soup.find("meta", property="og:image")
        if not desc: return None
        d = desc.get("content","")
        fl = fo = lk = None
        m = re.search(r"([\d,.KkMm]+)\s*Followers?,?\s*([\d,.KkMm]+)\s*Following,?\s*([\d,.KkMm]+)\s*Likes?", d, re.I)
        if m: fl, fo, lk = _n(m.group(1)), _n(m.group(2)), _n(m.group(3))
        dn = None
        if title:
            t = title.get("content","")
            dn = t.split("(@")[0].strip() if "(@" in t else t.split("-")[0].strip()
        return ProfileData(username=username, display_name=dn,
            platform=Platform.TIKTOK, profile_url=url,
            follower_count=fl, following_count=fo,
            profile_picture_url=image.get("content") if image else None,
            scrape_successful=True, scrape_error="Limited: meta tags only")
