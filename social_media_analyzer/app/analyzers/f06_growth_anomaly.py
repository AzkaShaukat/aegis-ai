"""F-06: Wayback Machine follower growth spike detection. Max 20 pts."""
import re, logging, httpx
from typing import List, Dict, Any
from app.models import GrowthAnomalyResult

logger = logging.getLogger(__name__)
CDX = "https://web.archive.org/cdx/search/cdx"

async def analyze_growth_anomaly(profile_url: str) -> GrowthAnomalyResult:
    empty = GrowthAnomalyResult(wayback_snapshots_found=0,growth_timeline=[],
        spike_detected=False,spike_date=None,spike_magnitude=None,suspicion_points=0,details={})
    try:
        async with httpx.AsyncClient(timeout=20) as c:
            r = await c.get(CDX,params={"url":profile_url,"output":"json","limit":"40",
                                         "fl":"timestamp,statuscode","filter":"statuscode:200"})
        if r.status_code != 200: return empty
        rows = r.json()
        if not rows or len(rows) < 2: return empty
        snapshots = rows[1:]  # skip header
        if len(snapshots) < 3:
            return GrowthAnomalyResult(**{**empty.dict(),"wayback_snapshots_found":len(snapshots),
                "details":{"note":"too few snapshots for analysis"}})
        # Fetch a few snapshots to compare follower counts
        timeline: List[Dict[str,Any]] = []
        prev_count = None; spike_detected = False; spike_date = None; spike_mag = None; pts = 0
        for row in snapshots[:8]:
            ts = row[0]
            snap_url = f"https://web.archive.org/web/{ts}/{profile_url}"
            try:
                async with httpx.AsyncClient(timeout=10) as c:
                    sr = await c.get(snap_url, follow_redirects=True,
                                      headers={"User-Agent":"Mozilla/5.0"})
                text = sr.text
                # Try to extract follower count from archived HTML
                count = None
                for pat in [r'"followers_count"\s*:\s*(\d+)',
                             r'"edge_followed_by".*?"count"\s*:\s*(\d+)',
                             r'"follower_count"\s*:\s*(\d+)',
                             r'([\d,]+)\s*[Ff]ollowers?']:
                    m = re.search(pat, text)
                    if m:
                        try: count = int(m.group(1).replace(",",""))
                        except: pass
                        if count: break
                if count:
                    entry = {"timestamp":ts,"followers":count}
                    if prev_count and count > prev_count * 3 and count - prev_count > 10000:
                        spike_detected = True; spike_date = ts
                        spike_mag = count - prev_count
                        pts = min(20, 10 + min(10, spike_mag//10000))
                        entry["spike"] = True
                    timeline.append(entry)
                    prev_count = count
            except: pass
        logger.info(f"[F-06] {profile_url}: {len(snapshots)} snaps spike={spike_detected} pts={pts}")
        return GrowthAnomalyResult(wayback_snapshots_found=len(snapshots),growth_timeline=timeline,
            spike_detected=spike_detected,spike_date=spike_date,spike_magnitude=spike_mag,
            suspicion_points=pts,details={"snapshots_checked":min(len(snapshots),8)})
    except Exception as e:
        logger.debug(f"[F-06] {e}")
        return empty
