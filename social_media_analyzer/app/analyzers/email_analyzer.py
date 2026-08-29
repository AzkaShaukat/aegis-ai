"""
Email analysis: FE-1 format+DNS, FE-2 disposable, FE-3 breach check, FE-4 EmailRep

FE-3 Breach check — three free sources (no paid key needed):
  1. LeakCheck.io     — 1000/day FREE, no key needed
  2. HudsonRock       — FREE infostealer DB, no key needed
  3. BreachDirectory  — FREE via RapidAPI (free tier), optional
  4. HIBP             — optional if you have a key ($3.50/mo) or test key

NOTE: HIBP test key 00000000000000000000000000000000 only works on
      test addresses (test@example.com etc). Use LeakCheck for real checks.
"""
import re, asyncio, logging, httpx
from datetime import datetime
from typing import Optional, List
try:
    import dns.resolver
    DNS_OK = True
except ImportError:
    DNS_OK = False

from app.models import (EmailFormatResult, DisposableEmailResult, EmailBreachResult,
                         EmailReputationResult, OsintResult, EmailAnalysisResult, SuspicionLevel)
from app.config import get_settings

logger   = logging.getLogger(__name__)
settings = get_settings()

EMAIL_RE = re.compile(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$')

FREE_PROVIDERS = {
    "gmail.com","yahoo.com","hotmail.com","outlook.com","icloud.com","protonmail.com",
    "live.com","msn.com","aol.com","mail.com","zoho.com","ymail.com","me.com",
    "yahoo.co.uk","yahoo.co.in","googlemail.com","pm.me","tutanota.com","tutamail.com",
}

DISPOSABLE_DOMAINS = {
    "mailinator.com","guerrillamail.com","10minutemail.com","temp-mail.org","throwaway.email",
    "yopmail.com","fakeinbox.com","dispostable.com","sharklasers.com","guerrillamailblock.com",
    "grr.la","guerrillamail.info","guerrillamail.biz","guerrillamail.de","guerrillamail.net",
    "guerrillamail.org","spam4.me","trashmail.com","trashmail.me","trashmail.net","trashmail.org",
    "trashmail.io","mailnull.com","maildrop.cc","discard.email","tempr.email","spamgourmet.com",
    "spamgourmet.net","mailnesia.com","spamgob.com","mailexpire.com","spamex.com","tempemail.net",
    "mailzilla.com","throwam.com","crazymailing.com","filzmail.com","mailscrap.com",
    "incognitomail.com","nobulk.com","pookmail.com","spaml.de","tempail.com","tempmail.us",
    "tempomail.fr","thankyou2010.com","trashdevil.com","deadaddress.com","getairmail.com",
    "mailnew.com","mt2015.com","mt2016.com","mt2017.com","nwldx.com","spamgourmet.org",
    "spamfree24.org","spamfree24.de","spamfree24.net","guerrillamail.biz","2prong.com",
    "mvrht.com","e4ward.com","trashmail.at","trashmail.io","trashmail.me","trashmail.net",
    "yopmail.fr","cool.fr.nf","jetable.fr.nf","nospam.ze.tc","nomail.xl.cx","mega.zik.dj",
    "speed.1s.fr","courriel.fr.nf","moncourrier.fr.nf","monemail.fr.nf","monmail.fr.nf",
    "tempinbox.com","tmpmail.net","tmpmail.org","yopmail.pp.ua","guerrillamail.com",
}


# ─── FE-1: Format + DNS ──────────────────────────────────────────
def check_email_format(email: str) -> EmailFormatResult:
    if not email or not EMAIL_RE.match(email.strip()):
        return EmailFormatResult(is_valid_format=False, suspicion_points=20,
            details={"error": "Invalid email format"})
    domain = email.split("@")[1].lower()
    has_mx = False; dom_exists = False
    if DNS_OK:
        try: dns.resolver.resolve(domain, "MX"); has_mx = True; dom_exists = True
        except Exception:
            try: dns.resolver.resolve(domain, "A"); dom_exists = True
            except Exception: pass
    pts = 0
    if not dom_exists: pts += 15
    elif not has_mx:   pts += 8
    return EmailFormatResult(is_valid_format=True, domain=domain,
        has_mx_record=has_mx, domain_exists=dom_exists,
        is_free_provider=(domain in FREE_PROVIDERS),
        suspicion_points=pts, details={"dns_checked": DNS_OK})


# ─── FE-2: Disposable email ──────────────────────────────────────
def check_disposable_email(email: str) -> DisposableEmailResult:
    domain = email.split("@")[1].lower() if "@" in email else ""
    if domain in DISPOSABLE_DOMAINS:
        return DisposableEmailResult(is_disposable=True, provider=domain,
            suspicion_points=25, details={"match": "known_disposable_domain"})
    PATTERNS = ["temp","mailinator","yopmail","throwaway","trash","spam","fake",
                "disposable","guerrilla","10minute","burner","junk","dump","discard"]
    for pat in PATTERNS:
        if pat in domain:
            return DisposableEmailResult(is_disposable=True, provider=domain,
                suspicion_points=20, details={"match": f"pattern:{pat}"})
    return DisposableEmailResult(is_disposable=False, suspicion_points=0, details={})


# ─── FE-3: Breach check (3 free sources) ─────────────────────────

async def _leakcheck(email: str) -> dict:
    """
    LeakCheck.io — 1000 FREE requests/day, no API key needed.
    Best free alternative to HIBP.
    """
    try:
        async with httpx.AsyncClient(timeout=12) as c:
            r = await c.get("https://leakcheck.io/api/public",
                            params={"check": email},
                            headers={"User-Agent": "Aegis-AI-v4"})
        if r.status_code == 429:
            return {"ok": False, "error": "LeakCheck daily limit (1000/day) reached"}
        if r.status_code == 200:
            d = r.json()
            found   = d.get("found", False)
            sources = d.get("sources", [])
            return {"ok": True, "found": found,
                    "count": len(sources),
                    "sources": [s.get("name", str(s)) for s in sources[:10]]}
        return {"ok": False, "error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


async def _hudsonrock(email: str) -> dict:
    """
    HudsonRock Cavalier — FREE infostealer intelligence DB.
    Checks if email was compromised by malware/stealer infections.
    No key needed.
    """
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(
                "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email",
                params={"email": email},
                headers={"User-Agent": "Aegis-AI-v4"})
        if r.status_code == 404:
            return {"ok": True, "found": False, "compromised": False, "count": 0}
        if r.status_code != 200:
            return {"ok": False, "error": f"HTTP {r.status_code}"}
        data     = r.json()
        stealers = data.get("stealers", [])
        return {"ok": True, "found": len(stealers) > 0,
                "compromised": len(stealers) > 0,
                "count": len(stealers),
                "stealers": [s.get("computer_name", "unknown") for s in stealers[:5]]}
    except Exception as e:
        return {"ok": False, "error": str(e)}


async def _hibp(email: str) -> dict:
    """
    HIBP — optional. Needs paid key ($3.50/mo).
    Test key 00000000000000000000000000000000 only works on test@example.com etc.
    If no key → skipped gracefully. Use LeakCheck instead.
    """
    key = settings.hibp_api_key
    # Skip invalid/test keys silently
    if not key or key == "00000000000000000000000000000000":
        return {"ok": False,
                "skipped": "HIBP key not set or is test key — using LeakCheck instead",
                "upgrade": "haveibeenpwned.com/API/Key ($3.50/month)"}
    try:
        async with httpx.AsyncClient(timeout=12) as c:
            r = await c.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                headers={"hibp-api-key": key,
                         "User-Agent": "Aegis-AI-v4"},
                params={"truncateResponse": "true"})
        if r.status_code == 404:
            return {"ok": True, "found": False, "count": 0, "breaches": []}
        if r.status_code == 401:
            return {"ok": False, "error": "HIBP key rejected (test key only works on test@example.com)"}
        if r.status_code == 429:
            return {"ok": False, "error": "HIBP rate limited"}
        if r.status_code == 200:
            data = r.json()
            return {"ok": True, "found": True,
                    "count": len(data),
                    "breaches": [b.get("Name", "") for b in data[:10]]}
        return {"ok": False, "error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


async def check_breach(email: str) -> EmailBreachResult:
    """
    Combined breach check: LeakCheck + HudsonRock + HIBP (optional).
    Works with zero API keys.
    """
    lc, hr, hibp = await asyncio.gather(
        _leakcheck(email),
        _hudsonrock(email),
        _hibp(email),
    )

    pts     = 0
    breaches: List[str] = []
    sources_used: List[str] = []

    # LeakCheck results
    if lc.get("ok") and lc.get("found"):
        n = lc.get("count", 1)
        pts += min(20, n * 4)
        breaches += lc.get("sources", [])
        sources_used.append(f"LeakCheck:{n}_sources")

    # HudsonRock infostealer results (much more serious)
    if hr.get("ok") and hr.get("compromised"):
        n = hr.get("count", 1)
        pts += min(25, n * 10)
        breaches.append(f"[Infostealer] {n} device infection(s)")
        sources_used.append(f"HudsonRock:{n}_stealers")

    # HIBP results (if key is real)
    if hibp.get("ok") and hibp.get("found"):
        n = hibp.get("count", 1)
        pts += min(15, n * 3)
        breaches += hibp.get("breaches", [])
        sources_used.append(f"HIBP:{n}_breaches")

    pts = min(pts, 30)
    total_count = (lc.get("count", 0) if lc.get("found") else 0) + \
                  (hr.get("count", 0) if hr.get("compromised") else 0) + \
                  (hibp.get("count", 0) if hibp.get("found") else 0)

    available = any(x.get("ok") for x in [lc, hr, hibp])

    logger.info(f"[FE-3] {email}: {sources_used} pts={pts}")
    return EmailBreachResult(
        available=available,
        breach_count=total_count,
        breaches=list(dict.fromkeys(breaches))[:12],
        suspicion_points=pts,
        details={
            "sources_queried": sources_used,
            "leakcheck":  lc,
            "hudsonrock": hr,
            "hibp":       hibp,
            "note": "Using LeakCheck+HudsonRock (free). HIBP optional ($3.50/mo key).",
        }
    )


# ─── FE-4: EmailRep reputation ───────────────────────────────────
async def check_emailrep(email: str) -> EmailReputationResult:
    headers = {"User-Agent": "Aegis-AI-v4"}
    if settings.emailrep_api_key:
        headers["Key"] = settings.emailrep_api_key
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(f"https://emailrep.io/{email}", headers=headers)
        if r.status_code == 429:
            return EmailReputationResult(available=False,
                details={"error": "Rate limited (100/day free without key)"})
        if r.status_code != 200:
            return EmailReputationResult(available=False,
                details={"error": f"HTTP {r.status_code}"})
        data = r.json()
        rep  = data.get("reputation", "unknown")
        susp = data.get("suspicious", False)
        spam = data.get("details", {}).get("spam", False)
        cred = data.get("details", {}).get("credentials_leaked", False)
        pts  = 0
        if rep == "none": pts += 8
        if susp:          pts += 10
        if spam:          pts += 12
        if cred:          pts += 15
        return EmailReputationResult(available=True, reputation=rep,
            suspicious=susp, spam=spam, credentials_leaked=cred,
            suspicion_points=min(pts, 25), details={"raw": data})
    except Exception as e:
        return EmailReputationResult(available=False, details={"error": str(e)})


# ─── Combined email analysis ─────────────────────────────────────
def _classify(score: int) -> SuspicionLevel:
    if score >= 60: return SuspicionLevel.HIGH
    if score >= 30: return SuspicionLevel.MEDIUM
    return SuspicionLevel.LOW


def _verdict(score: int, fe1, fe2, fe3, fe4) -> str:
    if fe2 and fe2.is_disposable:
        return "Fraudulent — disposable/temporary email"
    if fe1 and not fe1.is_valid_format:
        return "Invalid — bad email format"
    if fe1 and not fe1.domain_exists:
        return "Invalid — domain doesn't exist"
    if fe3 and fe3.breach_count > 5:
        return f"Breached — found in {fe3.breach_count} data sources"
    if fe3 and fe3.breach_count > 0:
        return "Breached — found in data breach"
    if fe4 and fe4.suspicious:
        return "Suspicious — poor email reputation"
    if score >= 60: return "High risk"
    if score >= 30: return "Suspicious — investigate further"
    return "Legitimate"


async def analyze_email(email: str) -> EmailAnalysisResult:
    start = datetime.utcnow()
    email = email.strip().lower()

    fe1 = check_email_format(email)
    fe2 = check_disposable_email(email)
    fe3, fe4 = await asyncio.gather(check_breach(email), check_emailrep(email))

    score = min(100, fe1.suspicion_points + fe2.suspicion_points +
                     fe3.suspicion_points + fe4.suspicion_points)

    flags = []
    if not fe1.is_valid_format:       flags.append("[FE-1] Invalid email format")
    if not fe1.domain_exists:         flags.append("[FE-1] Domain does not exist")
    if fe2.is_disposable:             flags.append(f"[FE-2] Disposable: {fe2.provider}")
    if fe3.breach_count > 0:          flags.append(f"[FE-3] {fe3.breach_count} breach source(s): {', '.join(fe3.breaches[:3])}")
    if fe4.suspicious:                flags.append(f"[FE-4] EmailRep: suspicious={fe4.suspicious} spam={fe4.spam}")
    if fe4.credentials_leaked:        flags.append("[FE-4] Credentials previously leaked")

    dur = (datetime.utcnow() - start).total_seconds()
    return EmailAnalysisResult(
        email=email, suspicion_score=score,
        suspicion_level=_classify(score), confidence=0.9,
        verdict=_verdict(score, fe1, fe2, fe3, fe4),
        fe1_format=fe1, fe2_disposable=fe2, fe3_breach=fe3, fe4_reputation=fe4,
        flags_raised=flags,
        score_breakdown={"fe1": fe1.suspicion_points, "fe2": fe2.suspicion_points,
                         "fe3": fe3.suspicion_points, "fe4": fe4.suspicion_points},
        analysis_duration_seconds=round(dur, 2))
