"""F-03: Profile completeness penalty. Max 15 pts."""
import logging
from datetime import datetime, timezone, timedelta
from app.models import ProfileCompletenessResult, ProfileData

logger = logging.getLogger(__name__)
FIELDS = [("bio",5),("profile_picture_url",4),("display_name",3),
          ("website_url",2),("location",2),("account_created_at",2),
          ("follower_count",1),("post_count",1)]

def analyze_profile_completeness(p: ProfileData) -> ProfileCompletenessResult:
    total_w = sum(w for _,w in FIELDS)
    present = []; missing = []; score_w = 0
    for field, w in FIELDS:
        val = getattr(p, field, None)
        if val not in (None, "", 0): present.append(field); score_w += w
        else: missing.append(field)
    score = round(score_w / total_w * 100, 1)
    penalty = 0
    if score < 40: penalty += 10
    elif score < 60: penalty += 6
    elif score < 80: penalty += 3
    # Very new account
    if p.account_created_at:
        tz = p.account_created_at
        if tz.tzinfo is None: tz = tz.replace(tzinfo=timezone.utc)
        age = (datetime.now(timezone.utc) - tz).days
        if age < 7: penalty += 8
        elif age < 30: penalty += 5
        elif age < 90: penalty += 2
    if p.is_private: penalty += 3
    penalty = min(penalty, 15)
    logger.info(f"[F-03] completeness={score}% penalty={penalty}")
    return ProfileCompletenessResult(completeness_score=score, completeness_penalty=penalty,
        missing_fields=missing, present_fields=present, details={"score_weight":score_w,"total_weight":total_w})
