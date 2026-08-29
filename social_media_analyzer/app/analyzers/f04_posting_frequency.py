"""F-04: Posting frequency regularity (CV + Shannon entropy). Max 25 pts."""
import math, logging
from typing import List, Dict, Any
from datetime import datetime, timezone
from app.models import PostingFrequencyResult

logger = logging.getLogger(__name__)

def _intervals(posts: List[Dict[str,Any]]) -> List[float]:
    times = []
    for p in posts:
        ts = p.get("timestamp","")
        if not ts: continue
        try:
            dt = datetime.fromisoformat(ts.replace("Z","+00:00"))
            if dt.tzinfo is None: dt = dt.replace(tzinfo=timezone.utc)
            times.append(dt.timestamp())
        except: pass
    times.sort()
    return [times[i+1]-times[i] for i in range(len(times)-1) if times[i+1]-times[i]>0]

def _entropy(vals: List[float]) -> float:
    if not vals: return 0.0
    buckets = {}
    for v in vals:
        b = int(v/3600)
        buckets[b] = buckets.get(b,0)+1
    n = len(vals)
    return -sum((c/n)*math.log2(c/n) for c in buckets.values())

def analyze_posting_frequency(posts: List[Dict[str,Any]]) -> PostingFrequencyResult:
    gaps = _intervals(posts)
    if len(gaps) < 3:
        return PostingFrequencyResult(coefficient_of_variation=0,posting_entropy=0,
            mean_interval_hours=0,std_interval_hours=0,is_bot_regular=False,
            suspicion_points=0,posts_analyzed=len(posts),details={"note":"insufficient posts"})
    import numpy as np
    arr  = np.array(gaps)
    mean = float(arr.mean()); std = float(arr.std())
    cv   = std/mean if mean > 0 else 0
    ent  = _entropy(gaps)
    pts  = 0
    is_bot = cv < 0.15
    if cv < 0.10: pts += 25
    elif cv < 0.15: pts += 20
    elif cv < 0.25: pts += 12
    if ent < 1.0 and len(gaps) >= 10: pts += 8
    pts = min(pts, 25)
    logger.info(f"[F-04] posts={len(posts)} cv={cv:.3f} ent={ent:.2f} bot={is_bot} pts={pts}")
    return PostingFrequencyResult(coefficient_of_variation=round(cv,4),posting_entropy=round(ent,3),
        mean_interval_hours=round(mean/3600,2),std_interval_hours=round(std/3600,2),
        is_bot_regular=is_bot,suspicion_points=pts,posts_analyzed=len(posts),
        details={"intervals_analyzed":len(gaps)})
