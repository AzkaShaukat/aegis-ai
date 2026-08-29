"""Twitter/X — Nitter instances (no API key needed)."""
import re, logging
from datetime import datetime
from typing import Optional
from bs4 import BeautifulSoup
from app.scraper.base import BaseScraper
from app.models import ProfileData, Platform

logger = logging.getLogger(__name__)
NITTER = ["https://nitter.privacydev.net","https://nitter.poast.org","https://nitter.net"]

def _n(t: str) -> Optional[int]:
    if not t: return None
    t = t.strip().replace(",","")
    try:
        if t.lower().endswith("k"): return int(float(t[:-1])*1000)
        if t.lower().endswith("m"): return int(float(t[:-1])*1000000)
        return int(float(t))
    except: return None

class TwitterScraper(BaseScraper):
    async def scrape(self, url: str, username: str) -> ProfileData:
        for host in NITTER:
            try:
                r = await self._get(f"{host}/{username}")
                if r.status_code == 404:
                    return self._fail(url, Platform.TWITTER, username, "Not found")
                if r.status_code == 200:
                    p = self._parse(r.text, username, url)
                    if p.scrape_successful:
                        logger.info(f"[Twitter] @{username} ← {host}")
                        return p
            except Exception as e:
                logger.debug(f"[Twitter] {host}: {e}")
        return self._fail(url, Platform.TWITTER, username, "All Nitter instances failed")

    def _parse(self, html: str, username: str, url: str) -> ProfileData:
        soup = BeautifulSoup(html, "lxml")
        stats = {}
        for el in soup.select(".profile-stat"):
            lbl = el.select_one(".profile-stat-header")
            val = el.select_one(".profile-stat-num")
            if lbl and val: stats[lbl.get_text(strip=True).lower()] = _n(val.get_text(strip=True))
        dn = soup.select_one(".profile-card-fullname")
        bio = soup.select_one(".profile-bio")
        jd = soup.select_one(".profile-joindate")
        pic = soup.select_one(".profile-card-avatar img")
        verif = soup.select_one(".icon-ok.verified-icon")
        display_name = re.sub(r"\s*✓\s*","", dn.get_text(strip=True)).strip() if dn else None
        created_at = None
        if jd:
            raw = re.sub(r"Joined\s*","", jd.get_text(strip=True), flags=re.I).strip()
            for fmt in ["%b %d, %Y","%B %d, %Y"]:
                try: created_at = datetime.strptime(raw, fmt); break
                except: pass
        pic_url = None
        if pic and pic.get("src"):
            s = pic["src"]
            pic_url = ("https://"+s.replace("/pic/","").replace("%2F","/")) if s.startswith("/pic/") else s
        posts = []
        for el in soup.select(".timeline-item .tweet-date a")[:50]:
            title = el.get("title","")
            if not title: continue
            try:
                dt = datetime.strptime(title.split("·")[0].strip(), "%b %d, %Y")
                box = el.find_parent(".timeline-item")
                lk = cm = 0
                if box:
                    le = box.select_one(".icon-heart + .tweet-stat")
                    ce = box.select_one(".icon-comment + .tweet-stat")
                    if le: lk = _n(le.get_text(strip=True)) or 0
                    if ce: cm = _n(ce.get_text(strip=True)) or 0
                posts.append({"timestamp": dt.isoformat(), "likes": lk, "comments": cm})
            except: pass
        if not display_name and not stats:
            return self._fail(url, Platform.TWITTER, username, "Could not parse Nitter page")
        return ProfileData(username=username, display_name=display_name,
            platform=Platform.TWITTER, profile_url=url,
            follower_count=stats.get("followers"), following_count=stats.get("following"),
            post_count=stats.get("tweets"), account_created_at=created_at,
            is_verified=verif is not None,
            bio=bio.get_text(strip=True) if bio else None,
            profile_picture_url=pic_url, recent_posts=posts, scrape_successful=True)
