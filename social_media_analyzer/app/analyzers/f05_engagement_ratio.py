"""F-05: Engagement ratio anomaly detection. Max 20 pts."""
import logging
from typing import Optional, List, Dict, Any
from app.models import EngagementRatioResult, Platform

logger = logging.getLogger(__name__)
BASELINES = {Platform.TWITTER:0.005,Platform.INSTAGRAM:0.03,Platform.TIKTOK:0.05,
             Platform.FACEBOOK:0.005,Platform.LINKEDIN:0.02,Platform.YOUTUBE:0.01,Platform.WHATSAPP:0.01}

def analyze_engagement_ratio(followers: Optional[int], following: Optional[int],
                              posts: List[Dict[str,Any]], platform: Platform) -> EngagementRatioResult:
    if not followers or followers < 50 or not posts:
        return EngagementRatioResult(engagement_rate=0,platform_baseline=BASELINES.get(platform,0.01),
            deviation_multiplier=0,anomaly_type="insufficient_data",suspicion_points=0,
            details={"note":"insufficient data"})
    total_lk = sum(p.get("likes",0) or 0 for p in posts)
    total_cm = sum(p.get("comments",0) or 0 for p in posts)
    avg_eng  = (total_lk + total_cm) / max(len(posts),1)
    rate     = avg_eng / followers
    baseline = BASELINES.get(platform, 0.01)
    mult     = rate / baseline if baseline > 0 else 0
    pts = 0; atype = "normal"
    if rate < baseline * 0.02: pts = 20; atype = "ghost_followers"
    elif rate < baseline * 0.1: pts = 12; atype = "low_engagement"
    elif rate > baseline * 100: pts = 20; atype = "like_farming"
    elif rate > baseline * 20: pts = 10; atype = "suspiciously_high"
    logger.info(f"[F-05] rate={rate:.4f} baseline={baseline} mult={mult:.1f} type={atype} pts={pts}")
    return EngagementRatioResult(engagement_rate=round(rate,5),platform_baseline=baseline,
        deviation_multiplier=round(mult,2),anomaly_type=atype,suspicion_points=pts,
        details={"avg_engagement":round(avg_eng,1),"posts_sampled":len(posts),"followers":followers})
