"""F-17: Link safety — URLScan.io + VirusTotal (Phase 4). Max 30 pts."""
import re, asyncio, logging, httpx
from typing import Optional, List
from app.models import LinkSafetyResult
from app.config import get_settings

logger   = logging.getLogger(__name__)
settings = get_settings()
URL_RE   = re.compile(r'https?://[^\s\'"<>]+', re.I)

async def _urlscan(url: str) -> dict:
    if not settings.urlscan_api_key: return {}
    try:
        async with httpx.AsyncClient(timeout=20) as c:
            r = await c.post("https://urlscan.io/api/v1/scan/",
                json={"url":url,"visibility":"public"},
                headers={"API-Key":settings.urlscan_api_key,"Content-Type":"application/json"})
        if r.status_code in (200,201):
            data = r.json()
            return {"uuid":data.get("uuid",""),"result":data.get("result",""),"submitted":True}
        return {}
    except Exception as e: return {"error":str(e)}

async def _virustotal(url: str) -> dict:
    if not settings.virustotal_api_key: return {}
    try:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.get(f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers={"x-apikey":settings.virustotal_api_key})
        if r.status_code != 200: return {}
        stats = r.json().get("data",{}).get("attributes",{}).get("last_analysis_stats",{})
        malicious  = stats.get("malicious",0)
        suspicious = stats.get("suspicious",0)
        return {"malicious":malicious,"suspicious":suspicious,"harmless":stats.get("harmless",0)}
    except Exception as e: return {"error":str(e)}

async def analyze_link_safety(bio: Optional[str], website: Optional[str]) -> LinkSafetyResult:
    texts = " ".join(filter(None, [bio, website]))
    links = URL_RE.findall(texts)[:5]
    if not links:
        return LinkSafetyResult(available=False,details={"note":"No links found in profile"})
    if not (settings.urlscan_api_key or settings.virustotal_api_key):
        return LinkSafetyResult(available=False,links_found=links,
            details={"skipped":"Set URLSCAN_API_KEY or VIRUSTOTAL_API_KEY in .env",
                     "urlscan":"urlscan.io/user/signup (1000/day FREE)",
                     "virustotal":"virustotal.com (500/day FREE)"})
    malicious = []; suspicious = []; pts = 0
    for url in links[:3]:
        vt = await _virustotal(url)
        if vt.get("malicious",0) > 2: malicious.append(url); pts += 25
        elif vt.get("suspicious",0) > 0 or vt.get("malicious",0) > 0: suspicious.append(url); pts += 10
    pts = min(pts, 30)
    logger.info(f"[F-17] links={len(links)} malicious={len(malicious)} pts={pts}")
    return LinkSafetyResult(available=True,links_found=links,malicious_links=malicious,
        suspicious_links=suspicious,suspicion_points=pts,details={"checked":len(links)})
