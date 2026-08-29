"""F-15: OSINT breach check — LeakCheck (free) + HudsonRock (free) + IntelX (optional). Max 30 pts."""
import asyncio, logging, httpx
from typing import Dict, Any
from app.config import get_settings

logger   = logging.getLogger(__name__)
settings = get_settings()

async def _leakcheck(query: str) -> Dict[str,Any]:
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get("https://leakcheck.io/api/public",params={"check":query},
                            headers={"User-Agent":"Aegis-AI-v4"})
        if r.status_code == 429: return {"available":False,"error":"Daily limit reached"}
        if r.status_code != 200: return {"available":False,"error":f"HTTP {r.status_code}"}
        data = r.json()
        return {"available":True,"found":data.get("found",False),"sources":data.get("sources",[])[:10],
                "count":len(data.get("sources",[]))}
    except Exception as e: return {"available":False,"error":str(e)}

async def _hudsonrock(email: str) -> Dict[str,Any]:
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get("https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email",
                params={"email":email}, headers={"User-Agent":"Aegis-AI-v4"})
        if r.status_code == 404: return {"available":True,"found":False,"compromised":False}
        if r.status_code != 200: return {"available":False,"error":f"HTTP {r.status_code}"}
        data     = r.json()
        stealers = data.get("stealers",[])
        return {"available":True,"found":len(stealers)>0,"compromised":len(stealers)>0,
                "stealer_count":len(stealers),"stealers":[s.get("computer_name","unknown") for s in stealers[:5]]}
    except Exception as e: return {"available":False,"error":str(e)}

async def _intelx(query: str) -> Dict[str,Any]:
    if not settings.intelx_api_key:
        return {"available":False,"skipped":"Set INTELX_API_KEY in .env (free academic: intelx.io/account#api)"}
    try:
        async with httpx.AsyncClient(timeout=15) as c:
            r1 = await c.post("https://2.intelx.io/intelligent/search",
                json={"term":query,"buckets":[],"lookuplevel":0,"maxresults":5,"timeout":0,
                      "datefrom":"","dateto":"","sort":4,"media":0,"terminate":[]},
                headers={"x-key":settings.intelx_api_key,"Content-Type":"application/json"})
            if r1.status_code != 200: return {"available":False,"error":f"HTTP {r1.status_code}"}
            sid = r1.json().get("id","")
            if not sid: return {"available":False,"error":"No search ID"}
            r2 = await c.get("https://2.intelx.io/intelligent/search/result",
                params={"id":sid,"limit":5,"offset":0},
                headers={"x-key":settings.intelx_api_key})
        if r2.status_code != 200: return {"available":False,"error":f"Results HTTP {r2.status_code}"}
        records = r2.json().get("records",[])
        return {"available":True,"found":len(records)>0,"record_count":len(records),
                "buckets":list({r.get("bucket","") for r in records if r.get("bucket")})}
    except Exception as e: return {"available":False,"error":str(e)}

async def analyze_osint(query: str, query_type: str = "email") -> Dict[str,Any]:
    lc, hr, ix = await asyncio.gather(
        _leakcheck(query),
        _hudsonrock(query) if query_type == "email" else asyncio.coroutine(lambda: {"available":False,"skipped":"emails only"})(),
        _intelx(query),
    )
    pts = 0; flags = []
    if lc.get("found"): n = lc.get("count",1); pts += min(20,n*4); flags.append(f"leakcheck:{n}_sources")
    if hr.get("compromised"): pts += 25; flags.append(f"infostealer:{hr.get('stealer_count',0)}_infections")
    if ix.get("found"): pts += 15; flags.append(f"intelx:{ix.get('record_count',0)}_records")
    pts = min(pts, 30)
    logger.info(f"[F-15] OSINT {query}: pts={pts} flags={flags}")
    return {"suspicion_points":pts,"flags":flags,"leakcheck":lc,"hudsonrock":hr,"intelx":ix,
            "details":{"query":query,"query_type":query_type}}
