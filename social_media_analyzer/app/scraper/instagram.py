"""Instagram public profile scraper (JSON + meta fallback)."""
import re, json, logging
from datetime import datetime
from typing import Optional, Any
from bs4 import BeautifulSoup
from app.scraper.base import BaseScraper
from app.models import ProfileData, Platform

logger = logging.getLogger(__name__)
IG_H = {"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
        "Accept-Language":"en-US,en;q=0.5","Referer":"https://www.instagram.com/"}

def _n(v: Any) -> Optional[int]:
    if v is None: return None
    try:
        s = str(v).replace(",","").strip()
        if s.lower().endswith("k"): return int(float(s[:-1])*1000)
        if s.lower().endswith("m"): return int(float(s[:-1])*1000000)
        return int(float(s))
    except: return None

class InstagramScraper(BaseScraper):
    async def scrape(self, url: str, username: str) -> ProfileData:
        canonical = f"https://www.instagram.com/{username}/"
        try:
            r = await self._get(canonical, extra=IG_H)
            if r.status_code == 404: return self._fail(url, Platform.INSTAGRAM, username, "Not found")
            if "login" in str(r.url) or r.status_code in (302,401):
                return self._fail(url, Platform.INSTAGRAM, username, "Login required")
            if r.status_code != 200: return self._fail(url, Platform.INSTAGRAM, username, f"HTTP {r.status_code}")
            p = self._from_json(r.text, username, canonical)
            if p: logger.info(f"[Instagram] @{username} via JSON"); return p
            p = self._from_meta(r.text, username, canonical)
            if p: logger.info(f"[Instagram] @{username} via meta"); return p
            return self._fail(url, Platform.INSTAGRAM, username, "Could not parse page")
        except Exception as e:
            return self._fail(url, Platform.INSTAGRAM, username, str(e))

    def _from_json(self, html: str, username: str, url: str) -> Optional[ProfileData]:
        m = re.search(r"window\._sharedData\s*=\s*({.*?});</script>", html, re.DOTALL)
        if m:
            try:
                d = json.loads(m.group(1))
                u = d.get("entry_data",{}).get("ProfilePage",[{}])[0].get("graphql",{}).get("user",{})
                if u: return self._build(u, username, url)
            except: pass
        soup = BeautifulSoup(html, "lxml")
        for tag in soup.find_all("script", type="application/json"):
            try:
                u = self._find_user(json.loads(tag.string or "{}"), username)
                if u: return self._build(u, username, url)
            except: continue
        return None

    def _find_user(self, data: Any, username: str) -> Optional[dict]:
        if isinstance(data, dict):
            if data.get("username") == username and "edge_followed_by" in data: return data
            for v in data.values():
                r = self._find_user(v, username)
                if r: return r
        elif isinstance(data, list):
            for item in data:
                r = self._find_user(item, username)
                if r: return r
        return None

    def _build(self, u: dict, username: str, url: str) -> ProfileData:
        posts = []
        for edge in u.get("edge_owner_to_timeline_media",{}).get("edges",[])[:50]:
            node = edge.get("node",{})
            ts = node.get("taken_at_timestamp")
            if ts: posts.append({"timestamp":datetime.utcfromtimestamp(ts).isoformat(),
                "likes":node.get("edge_liked_by",{}).get("count",0),
                "comments":node.get("edge_media_to_comment",{}).get("count",0)})
        return ProfileData(username=username, display_name=u.get("full_name"),
            platform=Platform.INSTAGRAM, profile_url=url,
            follower_count=u.get("edge_followed_by",{}).get("count"),
            following_count=u.get("edge_follow",{}).get("count"),
            post_count=u.get("edge_owner_to_timeline_media",{}).get("count"),
            is_verified=u.get("is_verified",False), is_private=u.get("is_private",False),
            bio=u.get("biography"),
            profile_picture_url=u.get("profile_pic_url_hd") or u.get("profile_pic_url"),
            website_url=u.get("external_url"), recent_posts=posts, scrape_successful=True)

    def _from_meta(self, html: str, username: str, url: str) -> Optional[ProfileData]:
        soup = BeautifulSoup(html, "lxml")
        desc  = soup.find("meta", attrs={"name":"description"}) or soup.find("meta", property="og:description")
        title = soup.find("meta", property="og:title")
        image = soup.find("meta", property="og:image")
        if not desc: return None
        d = desc.get("content","")
        m = re.search(r"([\d,.KkMm]+)\s*Followers?,\s*([\d,.KkMm]+)\s*Following,\s*([\d,.KkMm]+)", d, re.I)
        fl = fo = po = None
        if m: fl, fo, po = _n(m.group(1)), _n(m.group(2)), _n(m.group(3))
        dn = title.get("content","").split("•")[0].strip() if title else None
        return ProfileData(username=username, display_name=dn,
            platform=Platform.INSTAGRAM, profile_url=url,
            follower_count=fl, following_count=fo, post_count=po,
            profile_picture_url=image.get("content") if image else None,
            scrape_successful=True, scrape_error="Limited: meta tags only")
