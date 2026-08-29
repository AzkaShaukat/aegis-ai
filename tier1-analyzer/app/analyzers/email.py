"""
Email Analyzer — All 9 checklist features:
  E-01  Syntax + RFC validation
  E-02  Normalization (dots, plus, case, Unicode NFKC)
  E-03  Homoglyph detection (Cyrillic / Greek lookalikes)
  E-04  Disposable provider check (600+ domains)
  E-05  MX DNS record validation
  E-06  HIBP breach history
  E-07  Paste site search (psbdmp.ws)
  E-08  Email reputation (EmailRep.io)
  E-09  Domain age via WHOIS
"""
import asyncio
import hashlib
import json
import logging
import re
import unicodedata
from datetime import datetime, timezone
from typing import Any

import httpx

from app.config import settings
from app.data.disposable_domains import (
    DISPOSABLE_DOMAINS, get_service_name
)
from app.data.password_data import HOMOGLYPH_MAP
from app.redis_client import cache_get, cache_set

logger = logging.getLogger(__name__)

# ── E-01: RFC 5322 syntax check ───────────────────────────────────────────────
_EMAIL_RE = re.compile(
    r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+"
    r"@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*"
    r"\.[a-zA-Z]{2,}$"
)


def check_syntax(email: str) -> dict:
    """RFC 5322-compliant syntax validation."""
    email = email.strip()
    flags = []

    if len(email) > 320:
        flags.append("Email exceeds maximum length of 320 characters")

    if email.count("@") != 1:
        return {"valid": False, "reason": "Must contain exactly one @ symbol", "flags": flags}

    local, domain = email.rsplit("@", 1)

    if len(local) > 64:
        flags.append("Local part exceeds 64 characters (RFC limit)")
    if len(local) == 0:
        return {"valid": False, "reason": "Local part is empty", "flags": flags}
    if local.startswith(".") or local.endswith("."):
        flags.append("Local part starts or ends with a dot")
    if ".." in local:
        flags.append("Local part contains consecutive dots")
    if not _EMAIL_RE.match(email.lower()):
        return {"valid": False, "reason": "Does not match RFC 5322 pattern", "flags": flags}

    return {"valid": True, "local": local, "domain": domain.lower(), "flags": flags}


# ── E-02: Normalization ───────────────────────────────────────────────────────
def normalize_email(email: str) -> dict:
    """
    Normalize email:
    - Unicode NFKC normalization
    - Lowercase
    - Gmail: remove dots from local, strip +tag
    - Googlemail → gmail
    - Detect subaddressing
    """
    email = unicodedata.normalize("NFKC", email).strip().lower()

    if "@" not in email:
        return {"normalized": email, "is_subaddressed": False, "sub_address_tag": None,
                "is_gmail_normalized": False, "changes_made": []}

    local, domain = email.rsplit("@", 1)
    changes = []

    # Googlemail → gmail
    if domain == "googlemail.com":
        domain = "gmail.com"
        changes.append("googlemail.com → gmail.com")

    # Sub-addressing (+tag)
    is_subaddressed = "+" in local
    sub_tag = None
    if is_subaddressed:
        local, sub_tag = local.split("+", 1)
        changes.append(f"Removed sub-address tag '+{sub_tag}'")

    # Gmail dot normalization
    is_gmail = domain in ("gmail.com", "googlemail.com")
    original_local = local
    if is_gmail:
        nodots = local.replace(".", "")
        if nodots != local:
            changes.append(f"Removed dots from Gmail local part ({local} → {nodots})")
            local = nodots

    normalized = f"{local}@{domain}"

    return {
        "normalized": normalized,
        "original": email,
        "is_subaddressed": is_subaddressed,
        "sub_address_tag": sub_tag,
        "is_gmail_normalized": is_gmail and "." in original_local,
        "changes_made": changes,
    }


# ── E-03: Homoglyph detection ─────────────────────────────────────────────────
def detect_homoglyphs(email: str) -> dict:
    """
    Detect Unicode characters that look like ASCII but are different scripts.
    Returns which characters were found and their ASCII equivalents.
    """
    found = {}
    for char in email:
        if char in HOMOGLYPH_MAP and HOMOGLYPH_MAP[char]:  # skip zero-width
            found[char] = {
                "looks_like": HOMOGLYPH_MAP[char],
                "unicode_name": unicodedata.name(char, "UNKNOWN"),
                "code_point": f"U+{ord(char):04X}",
            }

    # Check for mixed scripts in local part
    if "@" in email:
        local = email.split("@")[0]
        scripts = set()
        for char in local:
            try:
                name = unicodedata.name(char)
                if "LATIN" in name:
                    scripts.add("Latin")
                elif "CYRILLIC" in name:
                    scripts.add("Cyrillic")
                elif "GREEK" in name:
                    scripts.add("Greek")
                elif "ARABIC" in name:
                    scripts.add("Arabic")
            except ValueError:
                pass
        mixed_script = len(scripts) > 1
    else:
        mixed_script = False
        scripts = set()

    return {
        "detected": len(found) > 0,
        "homoglyph_chars": found,
        "count": len(found),
        "mixed_script": mixed_script,
        "scripts_found": list(scripts),
        "risk": "High" if (found or mixed_script) else "None",
    }


# ── E-04: Disposable domain check ────────────────────────────────────────────
def check_disposable(email: str) -> dict:
    """Check against 600+ disposable email service domains."""
    if "@" not in email:
        return {"is_disposable": False}

    domain = email.rsplit("@", 1)[1].lower().strip()
    is_disposable = domain in DISPOSABLE_DOMAINS
    service = get_service_name(domain) if is_disposable else None

    return {
        "is_disposable": is_disposable,
        "domain": domain,
        "service_name": service,
        "risk_contribution": 20 if is_disposable else 0,
    }


# ── E-05: MX DNS record check ─────────────────────────────────────────────────
async def check_mx(domain: str) -> dict:
    """
    Check whether the domain has valid MX records.
    Uses dnspython for async DNS resolution.
    No MX record = cannot receive email = likely fake.
    """
    try:
        import dns.asyncresolver
        import dns.exception
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 8
        answers = await resolver.resolve(domain, "MX")
        mx_records = sorted(
            [{"priority": r.preference, "exchange": str(r.exchange).rstrip(".")}
             for r in answers],
            key=lambda x: x["priority"]
        )
        return {
            "has_mx": True,
            "mx_records": mx_records,
            "primary_mx": mx_records[0]["exchange"] if mx_records else None,
            "mx_count": len(mx_records),
        }
    except Exception as e:
        return {
            "has_mx": False,
            "error": str(e)[:100],
            "mx_records": [],
            "risk": "Medium — domain cannot receive email",
        }


# ── E-06: HIBP breach history ─────────────────────────────────────────────────
async def check_hibp(email: str) -> dict:
    """
    Query HaveIBeenPwned API for breach history.
    Returns breach names, dates, data classes, severity.
    Uses Redis cache with 24h TTL.
    """
    if not settings.HIBP_API_KEY:
        return {"available": False, "reason": "HIBP_API_KEY not configured"}

    cache_key = f"hibp:email:{hashlib.sha256(email.lower().encode()).hexdigest()[:16]}"
    cached = await cache_get(cache_key)
    if cached:
        return json.loads(cached)

    try:
        async with httpx.AsyncClient(timeout=settings.HTTP_TIMEOUT) as c:
            r = await c.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                headers={
                    "hibp-api-key": settings.HIBP_API_KEY,
                    "User-Agent": "Aegis-Tier1-Checker",
                },
                params={"truncateResponse": "false"},
            )

        if r.status_code == 404:
            result = {"available": True, "found": False, "breach_count": 0, "breaches": []}
        elif r.status_code == 200:
            breaches = r.json()
            # Score severity
            sensitive_classes = {"Passwords", "PlaintextPasswords", "CreditCards",
                                  "BankAccountNumbers", "SocialSecurityNumbers",
                                  "BiometricData", "MedicalRecords"}
            has_plaintext = any(
                dc in sensitive_classes
                for b in breaches for dc in b.get("DataClasses", [])
                if "Password" in dc
            )
            has_financial = any(
                "Credit" in dc or "Bank" in dc or "Financial" in dc
                for b in breaches for dc in b.get("DataClasses", [])
            )
            # Most recent breach
            dates = []
            for b in breaches:
                try:
                    dates.append(datetime.strptime(b["BreachDate"], "%Y-%m-%d").replace(tzinfo=timezone.utc))
                except Exception:
                    pass
            most_recent = max(dates).strftime("%Y-%m-%d") if dates else None
            days_since = (datetime.now(timezone.utc) - max(dates)).days if dates else None
            is_recent = days_since is not None and days_since < 365

            severity = min(len(breaches) * 8 + (30 if has_plaintext else 0) + (20 if has_financial else 0), 100)

            result = {
                "available": True,
                "found": True,
                "breach_count": len(breaches),
                "breaches": [
                    {
                        "name": b.get("Name"),
                        "domain": b.get("Domain"),
                        "date": b.get("BreachDate"),
                        "pwned_count": b.get("PwnCount"),
                        "data_classes": b.get("DataClasses", []),
                        "is_sensitive": b.get("IsSensitive", False),
                        "is_fabricated": b.get("IsFabricated", False),
                    }
                    for b in breaches
                ],
                "has_plaintext_passwords": has_plaintext,
                "has_financial_data": has_financial,
                "most_recent_breach": most_recent,
                "days_since_most_recent": days_since,
                "is_recently_breached": is_recent,
                "severity_score": severity,
            }
        elif r.status_code == 401:
            return {"available": False, "reason": "Invalid HIBP API key"}
        elif r.status_code == 429:
            return {"available": False, "reason": "HIBP rate limit — try again in 60s"}
        else:
            return {"available": False, "reason": f"HIBP returned HTTP {r.status_code}"}

        await cache_set(cache_key, json.dumps(result), ttl=86400)
        return result

    except Exception as e:
        logger.warning(f"HIBP error: {e}")
        return {"available": False, "reason": str(e)[:100]}


# ── E-07: Paste site search (psbdmp.ws) ───────────────────────────────────────
async def check_pastes(email: str) -> dict:
    """
    Search psbdmp.ws for email appearances in public pastes.
    Free, no API key required.
    """
    cache_key = f"paste:{hashlib.sha256(email.lower().encode()).hexdigest()[:16]}"
    cached = await cache_get(cache_key)
    if cached:
        return json.loads(cached)

    try:
        async with httpx.AsyncClient(timeout=settings.HTTP_TIMEOUT) as c:
            r = await c.get(
                "https://psbdmp.ws/api/v3/search",
                params={"query": email},
                headers={"User-Agent": "Aegis-Tier1-Checker"},
            )

        if r.status_code == 200:
            data = r.json()
            pastes = data.get("data", [])
            result = {
                "available": True,
                "found": len(pastes) > 0,
                "paste_count": len(pastes),
                "pastes": [
                    {
                        "id": p.get("id"),
                        "tags": p.get("tags", ""),
                        "time": p.get("time"),
                        "url": f"https://psbdmp.ws/{p.get('id', '')}",
                    }
                    for p in pastes[:10]
                ],
                "source": "psbdmp.ws",
            }
        else:
            result = {"available": False, "reason": f"psbdmp returned HTTP {r.status_code}"}

        await cache_set(cache_key, json.dumps(result), ttl=3600)
        return result

    except Exception as e:
        logger.warning(f"Paste search error: {e}")
        return {"available": False, "reason": str(e)[:100], "source": "psbdmp.ws"}


# ── E-08: EmailRep.io reputation ──────────────────────────────────────────────
async def check_reputation(email: str) -> dict:
    """
    Query EmailRep.io for email reputation signals.
    Free at 10 requests/hour without key.
    Returns: suspicious flag, spam reports, deliverability, domain age bucket.
    """
    cache_key = f"emailrep:{hashlib.sha256(email.lower().encode()).hexdigest()[:16]}"
    cached = await cache_get(cache_key)
    if cached:
        result = json.loads(cached)
        # Backward-compat: old cache entries may lack source field
        result.setdefault("source", "emailrep.io")
        return result

    try:
        headers = {"User-Agent": "Aegis-Tier1-Checker"}
        async with httpx.AsyncClient(timeout=settings.HTTP_TIMEOUT) as c:
            r = await c.get(f"https://emailrep.io/{email}", headers=headers)

        if r.status_code == 200:
            data = r.json()
            details = data.get("details", {})
            result = {
                "available": True,
                "reputation": data.get("reputation", "unknown"),
                "suspicious": data.get("suspicious", False),
                "references": data.get("references", 0),
                "blacklisted": details.get("blacklisted", False),
                "malicious_activity": details.get("malicious_activity", False),
                "malicious_activity_recent": details.get("malicious_activity_recent", False),
                "credential_leak": details.get("credential_leak", False),
                "data_breach": details.get("data_breach", False),
                "spam": details.get("spam", False),
                "spam_lists": details.get("spam_lists", 0),
                "days_since_domain_creation": details.get("days_since_domain_creation"),
                "deliverability": details.get("deliverability", "unknown"),
                "free_provider": details.get("free_provider", False),
                "disposable": details.get("disposable", False),
                "source": "emailrep.io",
            }
        elif r.status_code == 429:
            result = {"available": False, "reason": "EmailRep rate limit (10/hr)", "source": "emailrep.io"}
        else:
            result = {"available": False, "reason": f"EmailRep HTTP {r.status_code}", "source": "emailrep.io"}

        await cache_set(cache_key, json.dumps(result), ttl=7200)
        return result

    except Exception as e:
        logger.warning(f"EmailRep error: {e}")
        return {"available": False, "reason": str(e)[:100], "source": "emailrep.io"}


# ── E-09: Domain age via WHOIS ────────────────────────────────────────────────
async def check_domain_age(domain: str) -> dict:
    """
    Look up domain registration age via WHOIS.
    New domains (< 30 days) = high risk indicator.
    """
    cache_key = f"whois:{domain}"
    cached = await cache_get(cache_key)
    if cached:
        return json.loads(cached)

    try:
        import whois as pythonwhois

        def _sync_whois():
            return pythonwhois.whois(domain)

        loop = asyncio.get_event_loop()
        w = await loop.run_in_executor(None, _sync_whois)

        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]

        if creation:
            if hasattr(creation, 'tzinfo') and creation.tzinfo is None:
                creation = creation.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            age_days = (now - creation).days

            if age_days < 7:
                risk = "Critical"
            elif age_days < 30:
                risk = "High"
            elif age_days < 180:
                risk = "Medium"
            elif age_days < 365:
                risk = "Low"
            else:
                risk = "None"

            result = {
                "available": True,
                "creation_date": str(creation.date()),
                "age_days": age_days,
                "age_years": round(age_days / 365, 1),
                "registrar": str(w.registrar or "Unknown"),
                "country": str(w.country or "Unknown"),
                "risk_level": risk,
                "is_newly_registered": age_days < 90,
            }
        else:
            result = {"available": True, "creation_date": None,
                      "reason": "No creation date in WHOIS record"}

        await cache_set(cache_key, json.dumps(result), ttl=86400)
        return result

    except Exception as e:
        logger.debug(f"WHOIS error for {domain}: {e}")
        return {"available": False, "reason": str(e)[:100]}


# ── Master email scanner ───────────────────────────────────────────────────────
async def analyze_email(email: str) -> dict[str, Any]:
    """
    Run all 9 email analysis features concurrently.
    Returns comprehensive result with overall risk score.
    """
    email = email.strip()

    # ── Synchronous checks first ──────────────────────────────────────────────
    syntax     = check_syntax(email)
    normalized = normalize_email(email)
    homoglyphs = detect_homoglyphs(email)
    disposable = check_disposable(email)

    if not syntax["valid"]:
        # Still return homoglyph + disposable — they ran before syntax check
        # so Cyrillic/homoglyph emails still show detection on syntax fail
        extra_flags = [f"Invalid email syntax: {syntax.get('reason', '')}"]
        extra_score = 80
        if homoglyphs["detected"]:
            extra_flags.append(f"Homoglyph characters detected: {list(homoglyphs['homoglyph_chars'].keys())}")
            extra_score = min(extra_score + 15, 100)
        if homoglyphs.get("mixed_script"):
            extra_flags.append(f"Mixed Unicode scripts: {homoglyphs['scripts_found']}")
        if disposable.get("is_disposable"):
            extra_flags.append(f"Disposable provider: {disposable.get('service_name') or disposable.get('domain')}")
        return {
            "credential_type": "email",
            "input": email,
            "syntax": syntax,
            "homoglyphs": homoglyphs,
            "disposable": disposable,
            "overall_risk_score": extra_score,
            "overall_risk_level": "Critical" if extra_score >= 76 else "High",
            "all_flags": extra_flags,
            "error": "Invalid email format — contains non-ASCII/homoglyph characters",
        }

    domain = syntax["domain"]

    # ── Async checks concurrently ─────────────────────────────────────────────
    mx_task         = asyncio.create_task(check_mx(domain))
    hibp_task       = asyncio.create_task(check_hibp(email))
    paste_task      = asyncio.create_task(check_pastes(email))
    reputation_task = asyncio.create_task(check_reputation(email))
    age_task        = asyncio.create_task(check_domain_age(domain))

    mx, hibp, pastes, reputation, domain_age = await asyncio.gather(
        mx_task, hibp_task, paste_task, reputation_task, age_task,
        return_exceptions=True
    )

    # Handle exceptions from gather
    def safe(r, name):
        if isinstance(r, Exception):
            logger.warning(f"{name} exception: {r}")
            return {"available": False, "reason": str(r)[:80]}
        return r

    mx         = safe(mx, "MX")
    hibp       = safe(hibp, "HIBP")
    pastes     = safe(pastes, "Pastes")
    reputation = safe(reputation, "EmailRep")
    domain_age = safe(domain_age, "WHOIS")

    # ── Score aggregation ─────────────────────────────────────────────────────
    score = 0
    flags = list(syntax.get("flags", []))

    # Homoglyphs
    if homoglyphs["detected"]:
        score += 35
        flags.append(f"Homoglyph characters detected: {list(homoglyphs['homoglyph_chars'].keys())}")
    if homoglyphs.get("mixed_script"):
        score += 15
        flags.append(f"Mixed Unicode scripts in local part: {homoglyphs['scripts_found']}")

    # Disposable
    if disposable["is_disposable"]:
        score += 20
        svc = disposable.get("service_name") or disposable["domain"]
        flags.append(f"Disposable/temporary email provider: {svc}")

    # MX
    if not mx.get("has_mx"):
        score += 25
        flags.append("Domain has no MX records — cannot receive email")

    # HIBP
    if hibp.get("found"):
        bc = hibp.get("breach_count", 0)
        score += min(bc * 7, 40)
        flags.append(f"Found in {bc} known data breach(es)")
        if hibp.get("has_plaintext_passwords"):
            score += 15
            flags.append("Plaintext passwords exposed in breach data")
        if hibp.get("has_financial_data"):
            score += 10
            flags.append("Financial data exposed in breach")
        if hibp.get("is_recently_breached"):
            score += 5
            flags.append(f"Breached recently (within last year)")

    # Pastes
    if pastes.get("found"):
        pc = pastes.get("paste_count", 0)
        score += min(pc * 5, 20)
        flags.append(f"Email found in {pc} public paste dump(s)")

    # Reputation
    if reputation.get("suspicious"):
        score += 15
        flags.append("Email flagged as suspicious by EmailRep")
    if reputation.get("malicious_activity_recent"):
        score += 20
        flags.append("Recent malicious activity associated with this email")
    if reputation.get("blacklisted"):
        score += 25
        flags.append("Email on known blacklists")
    if reputation.get("spam"):
        score += 10
        flags.append("Email associated with spam activity")
    if reputation.get("disposable") and not disposable["is_disposable"]:
        score += 10
        flags.append("EmailRep classifies domain as disposable")

    # Domain age
    if domain_age.get("available") and domain_age.get("is_newly_registered"):
        age = domain_age.get("age_days", 0)
        if age < 30:
            score += 20
            flags.append(f"Domain registered only {age} days ago — very new")
        else:
            score += 10
            flags.append(f"Domain registered {age} days ago — relatively new")

    score = min(score, 100)

    if score < 16:     level = "Clean"
    elif score < 36:   level = "Low"
    elif score < 56:   level = "Medium"
    elif score < 76:   level = "High"
    else:              level = "Critical"

    return {
        "credential_type": "email",
        "input": email,
        "syntax": syntax,
        "normalization": normalized,
        "homoglyphs": homoglyphs,
        "disposable": disposable,
        "mx_check": mx,
        "hibp": hibp,
        "pastes": pastes,
        "reputation": reputation,
        "domain_age": domain_age,
        "overall_risk_score": score,
        "overall_risk_level": level,
        "all_flags": flags,
    }
