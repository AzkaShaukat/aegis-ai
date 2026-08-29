"""F-09: Botometer academic score via RapidAPI. Twitter only. Max 30 pts."""
import logging, httpx
from app.models import BotometerResult, Platform
from app.config import get_settings

logger   = logging.getLogger(__name__)
settings = get_settings()

async def analyze_botometer(username: str, platform: Platform) -> BotometerResult:
    if platform != Platform.TWITTER:
        return BotometerResult(available=False,details={"skipped":"Botometer: Twitter only"})
    if not (settings.rapidapi_key and settings.twitter_bearer_token):
        return BotometerResult(available=False,details={"skipped":"Set RAPIDAPI_KEY + TWITTER_BEARER_TOKEN in .env (free 500/month at rapidapi.com → Botometer Pro)"})
    try:
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.get("https://botometer-pro.p.rapidapi.com/4/check_account",
                params={"username":username},
                headers={"x-rapidapi-key":settings.rapidapi_key,
                         "x-rapidapi-host":"botometer-pro.p.rapidapi.com",
                         "Authorization":f"Bearer {settings.twitter_bearer_token}"})
        if r.status_code == 404: return BotometerResult(available=True,details={"note":"Account not found"})
        if r.status_code == 429: return BotometerResult(available=False,details={"error":"Rate limit. 500/month free."})
        if r.status_code != 200: return BotometerResult(available=False,details={"error":f"HTTP {r.status_code}"})
        data = r.json()
        cap  = data.get("cap",{}).get("universal",0) or 0
        raw  = data.get("display_scores",{}).get("universal",{}).get("overall",0) or 0
        pts  = int(cap*30)
        logger.info(f"[F-09] @{username}: cap={cap:.2f} pts={pts}")
        return BotometerResult(available=True,cap_score=round(cap,3),suspicion_points=pts,
            details={"raw_score":raw,"cap_score":cap})
    except Exception as e:
        return BotometerResult(available=False,details={"error":str(e)})
