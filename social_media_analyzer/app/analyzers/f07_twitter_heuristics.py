"""F-07: Twitter API v2 heuristics — replaces BotSentinel (down May 2026). Max 40 pts."""
import logging, httpx
from datetime import datetime, timezone
from app.models import TwitterHeuristicsResult, Platform
from app.config import get_settings

logger   = logging.getLogger(__name__)
settings = get_settings()

async def analyze_twitter_heuristics(username: str, platform: Platform) -> TwitterHeuristicsResult:
    if platform != Platform.TWITTER:
        return TwitterHeuristicsResult(available=False, details={"skipped":f"Twitter only, got {platform}"})
    if not settings.twitter_bearer_token:
        return TwitterHeuristicsResult(available=False,
            details={"skipped":"Set TWITTER_BEARER_TOKEN in .env (free: developer.twitter.com → Bearer Token)",
                     "note":"BotSentinel v3 launches May 2026 — will integrate then"})
    try:
        async with httpx.AsyncClient(timeout=12) as c:
            r = await c.get("https://api.twitter.com/2/users/by/username/"+username,
                params={"user.fields":"created_at,description,profile_image_url,public_metrics,verified"},
                headers={"Authorization":f"Bearer {settings.twitter_bearer_token}"})
        if r.status_code == 404: return TwitterHeuristicsResult(available=True,classification="NotFound",details={"note":"Account not found"})
        if r.status_code == 429: return TwitterHeuristicsResult(available=False,details={"error":"Rate limited. Wait 15min."})
        if r.status_code == 401: return TwitterHeuristicsResult(available=False,details={"error":"Bearer token invalid. Regenerate at developer.twitter.com"})
        if r.status_code != 200: return TwitterHeuristicsResult(available=False,details={"error":f"HTTP {r.status_code}"})
        data = r.json().get("data",{})
        if not data: return TwitterHeuristicsResult(available=False,details={"error":"Empty response"})
        pm = data.get("public_metrics",{})
        fl = pm.get("followers_count",0) or 0
        fw = pm.get("following_count",0) or 0
        tw = pm.get("tweet_count",0) or 0
        li = pm.get("listed_count",0) or 0
        pts = 0; flags = []
        # Age
        created = data.get("created_at","")
        if created:
            try:
                dt = datetime.fromisoformat(created.replace("Z","+00:00"))
                age = (datetime.now(timezone.utc)-dt).days
                if age < 7: pts += 15; flags.append("under_7_days_old")
                elif age < 30 and fl > 5000: pts += 20; flags.append("new_account_high_followers")
                elif age < 90 and fl > 20000: pts += 12; flags.append("young_very_high_followers")
            except: pass
        # Default avatar
        if "default_profile" in (data.get("profile_image_url","")): pts += 10; flags.append("default_avatar")
        # No bio
        if not data.get("description","").strip(): pts += 8; flags.append("no_bio")
        # FF ratio
        if fl > 0:
            ffw = fw/max(fl,1)
            if ffw > 50: pts += 15; flags.append(f"extreme_ff_ratio:{ffw:.0f}x")
            elif ffw > 10: pts += 8; flags.append(f"high_ff_ratio:{ffw:.1f}x")
        # Zero tweets many followers
        if tw == 0 and fl > 1000: pts += 15; flags.append("zero_tweets_many_followers")
        elif tw < 5 and fl > 10000: pts += 10; flags.append("almost_no_tweets_many_followers")
        # Low listed
        if fl > 10000 and li < 5: pts += 8; flags.append(f"low_listed:{li}")
        pts = min(pts, 40)
        clf = ("Disruptive" if pts>=30 else "Problematic" if pts>=15 else "Acceptable" if pts>=5 else "Trustworthy")
        logger.info(f"[F-07] @{username}: {clf} pts={pts}")
        return TwitterHeuristicsResult(available=True,bot_score=round(pts/40*100,1),
            classification=clf,suspicion_points=pts,
            details={"flags":flags,"public_metrics":pm,"created_at":created})
    except Exception as e:
        return TwitterHeuristicsResult(available=False,details={"error":str(e)})
