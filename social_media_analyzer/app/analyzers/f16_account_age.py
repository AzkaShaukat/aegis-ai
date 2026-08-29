"""F-16: Account age + follower velocity analysis. Max 20 pts."""
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any

logger = logging.getLogger(__name__)
VELOCITY = {"twitter":1000,"instagram":2000,"tiktok":5000,"youtube":500,"facebook":300}

def analyze_account_age(created_at: Optional[datetime], followers: Optional[int],
                         posts: Optional[int], platform: str,
                         recent_posts: Optional[List[Dict]] = None) -> Dict[str, Any]:
    if not created_at:
        return {"suspicion_points":3,"flags":["creation_date_hidden"],"details":{"note":"no date"}}
    now = datetime.now(timezone.utc)
    if created_at.tzinfo is None: created_at = created_at.replace(tzinfo=timezone.utc)
    age = (now - created_at).days
    pts = 0; flags = []
    if age < 7:   pts += 18; flags.append("account_under_7_days")
    elif age < 30: pts += 12; flags.append("account_under_30_days")
    elif age < 90: pts += 5;  flags.append("account_under_90_days")
    if followers and age > 0:
        vel = followers / age
        thresh = VELOCITY.get(platform.lower(), 1000)
        if vel > thresh*5: pts += 20; flags.append(f"extreme_velocity:{vel:.0f}/day")
        elif vel > thresh: pts += 10; flags.append(f"high_velocity:{vel:.0f}/day")
    if posts and age > 0:
        ppd = posts / age
        if ppd > 50: pts += 15; flags.append(f"extreme_post_rate:{ppd:.0f}/day")
        elif ppd > 20: pts += 8; flags.append(f"high_post_rate:{ppd:.0f}/day")
    # Dormant revival
    if recent_posts and len(recent_posts) >= 3 and age > 365:
        try:
            times = []
            for p in recent_posts:
                ts = p.get("timestamp","")
                if ts:
                    try:
                        dt = datetime.fromisoformat(ts.replace("Z","+00:00"))
                        if dt.tzinfo is None: dt = dt.replace(tzinfo=timezone.utc)
                        times.append(dt)
                    except: pass
            if times and (now - max(times)).days < 30 and age > 365:
                oldest_post_days = (now - min(times)).days
                if oldest_post_days < 60: pts += 12; flags.append("dormant_revival")
        except: pass
    pts = min(pts, 20)
    logger.info(f"[F-16] age={age}d pts={pts}")
    return {"suspicion_points":pts,"flags":flags,
            "details":{"account_age_days":age,"created_at":created_at.isoformat()}}
