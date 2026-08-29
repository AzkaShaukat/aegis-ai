"""F-08: Social Blade growth history. Max 20 pts."""
import logging, httpx
from app.models import SocialBladeResult, Platform
from app.config import get_settings

logger   = logging.getLogger(__name__)
settings = get_settings()
PLATFORMS = {Platform.TWITTER:"twitter",Platform.INSTAGRAM:"instagram",
             Platform.YOUTUBE:"youtube",Platform.TIKTOK:"tiktok"}

async def analyze_socialblade(username: str, platform: Platform) -> SocialBladeResult:
    if platform not in PLATFORMS:
        return SocialBladeResult(available=False,details={"skipped":f"SocialBlade supports twitter/instagram/youtube/tiktok"})
    if not (settings.socialblade_client_id and settings.socialblade_token):
        return SocialBladeResult(available=False,details={"skipped":"Set SOCIALBLADE_CLIENT_ID + SOCIALBLADE_TOKEN in .env (free: socialblade.com/api)"})
    try:
        plat = PLATFORMS[platform]
        async with httpx.AsyncClient(timeout=12) as c:
            r = await c.get(f"https://matrix.socialblade.com/api/v2/{plat}/statistics",
                params={"query":username},
                headers={"clientid":settings.socialblade_client_id,"token":settings.socialblade_token})
        if r.status_code == 404: return SocialBladeResult(available=True,details={"note":"Not found on SocialBlade"})
        if r.status_code != 200: return SocialBladeResult(available=False,details={"error":f"HTTP {r.status_code}"})
        data = r.json()
        tables = data.get("data",{}).get("table",[]) or []
        gains  = [{"month":row.get("date",""),"followers_gained":row.get("followers_gained",0)} for row in tables[:12]]
        spike_detected = False; spike_month = None; spike_mag = None; pts = 0
        for row in tables:
            gained = row.get("followers_gained",0) or 0
            if gained > 100000:
                spike_detected = True; spike_month = row.get("date"); spike_mag = gained
                pts = min(20, 10 + gained//100000); break
        logger.info(f"[F-08] @{username} spike={spike_detected} pts={pts}")
        return SocialBladeResult(available=True,monthly_gains=gains,spike_detected=spike_detected,
            spike_month=spike_month,spike_magnitude=spike_mag,suspicion_points=pts,details={})
    except Exception as e:
        return SocialBladeResult(available=False,details={"error":str(e)})
