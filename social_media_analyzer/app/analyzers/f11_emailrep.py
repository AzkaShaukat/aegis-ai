"""F-11: EmailRep.io check on email found in profile bio/website. 100/day free."""
import re, logging, httpx
from typing import Optional
from app.models import EmailRepResult
from app.config import get_settings

logger   = logging.getLogger(__name__)
settings = get_settings()
EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")

def _extract_email(bio: Optional[str], website: Optional[str], email: Optional[str]) -> Optional[str]:
    if email: return email.lower()
    for text in [bio, website]:
        if text:
            m = EMAIL_RE.search(text)
            if m: return m.group(0).lower()
    return None

async def analyze_emailrep_from_profile(bio: Optional[str], website: Optional[str], email: Optional[str]) -> EmailRepResult:
    addr = _extract_email(bio, website, email)
    if not addr:
        return EmailRepResult(available=False,details={"skipped":"No email found in profile"})
    headers = {"User-Agent":"Aegis-AI-v4"}
    if settings.emailrep_api_key: headers["Key"] = settings.emailrep_api_key
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(f"https://emailrep.io/{addr}",headers=headers)
        if r.status_code == 429: return EmailRepResult(available=False,details={"error":"Rate limited (100/day free)"})
        if r.status_code != 200: return EmailRepResult(available=False,details={"error":f"HTTP {r.status_code}"})
        data = r.json()
        rep  = data.get("reputation","unknown")
        susp = data.get("suspicious",False)
        spam = data.get("details",{}).get("spam",False)
        pts  = 0
        if rep == "none": pts += 8
        if susp: pts += 10
        if spam: pts += 12
        logger.info(f"[F-11] {addr}: rep={rep} susp={susp} pts={pts}")
        return EmailRepResult(available=True,email_checked=addr,reputation=rep,
            suspicious=susp,spam_flag=spam,suspicion_points=min(pts,20),details=data)
    except Exception as e:
        return EmailRepResult(available=False,details={"error":str(e)})
