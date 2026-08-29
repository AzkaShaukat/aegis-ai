"""
whois_check.py
Aegis Link Analyzer

WHOIS domain intelligence analysis.
Strips VeriSign legal boilerplate from error flags so API responses
contain clean 1-line messages instead of 200+ lines of legal text.
"""

import whois
import re
from datetime import datetime, timezone
from typing import Dict, List, Optional


ABUSIVE_REGISTRARS = [
    "namecheap", "publicdomainregistry", "pdr ltd", "reg.ru",
    "internet.bs", "1api gmbh", "beget", "reg2c.com", "eranet", "bizcn",
    "hosting concepts", "todaynic", "west263", "alibaba cloud",
]


def _clean_whois_error(raw: str, domain: str) -> str:
    """
    Extract only the meaningful 1-line message from a raw WHOIS error.
    Strips VeriSign legal notice, IANA boilerplate, and other noise.

    Examples:
      "No match for DOMAIN.COM.\r\n>>> Last update ... NOTICE: The expiration..."
      → "Domain 'domain.com' not found in WHOIS registry"

      "Socket timed out: ... [host]"
      → "WHOIS lookup timed out"
    """
    s = str(raw).strip()

    # Pattern 1: No match / domain doesn't exist
    if re.search(r"No match for", s, re.IGNORECASE) or \
       re.search(r"NOT FOUND", s) or \
       re.search(r"no entries found", s, re.IGNORECASE) or \
       re.search(r"No data found", s, re.IGNORECASE) or \
       re.search(r"Object does not exist", s, re.IGNORECASE):
        return (
            f"Domain '{domain}' not found in WHOIS — "
            "unregistered or recently deleted"
        )

    # Pattern 2: Legal boilerplate from VeriSign or IANA
    if "NOTICE:" in s or "VeriSign" in s or "TERMS OF USE" in s or \
       "VeriSign Global Registry" in s or "expiration date" in s.lower()[:200]:
        # The boilerplate always starts after the actual error on line 1
        first_line = s.split("\n")[0].strip()
        # Strip leading wrapper text
        for prefix in ["WHOIS lookup failed (", "WHOIS error: "]:
            if first_line.startswith(prefix):
                first_line = first_line[len(prefix):].rstrip(")")
        # If still has boilerplate on first line, just show domain not found
        if "NOTICE" in first_line or len(first_line) > 150:
            return (
                f"Domain '{domain}' not found in WHOIS — "
                "unregistered or recently deleted"
            )
        return first_line if first_line else (
            f"WHOIS data unavailable for '{domain}'"
        )

    # Pattern 3: Timeout
    if "timed out" in s.lower() or "timeout" in s.lower():
        return "WHOIS lookup timed out — registry may be rate-limiting"

    # Pattern 4: Rate limited
    if "rate limit" in s.lower() or "too many" in s.lower() or \
       "quota exceeded" in s.lower():
        return "WHOIS lookup rate-limited — try again in a few minutes"

    # Pattern 5: Connection error
    if "connection" in s.lower() and ("refused" in s.lower() or
                                       "failed" in s.lower()):
        return "WHOIS lookup failed — could not connect to registry"

    # Default: truncate to 120 chars
    if len(s) > 120:
        return s[:120].rstrip() + "..."
    return s


def _parse_date(raw) -> Optional[str]:
    """Safely parse WHOIS date to YYYY-MM-DD string."""
    if raw is None:
        return None
    if isinstance(raw, list):
        raw = raw[0]
    if isinstance(raw, datetime):
        return raw.strftime("%Y-%m-%d")
    if isinstance(raw, str):
        for fmt in ("%Y-%m-%d", "%d-%b-%Y", "%Y-%m-%dT%H:%M:%S", "%d/%m/%Y"):
            try:
                return datetime.strptime(raw[:10], fmt[:len(fmt)]).strftime("%Y-%m-%d")
            except ValueError:
                continue
    return None


def _domain_age_days(creation_str: Optional[str]) -> Optional[int]:
    if not creation_str:
        return None
    try:
        created = datetime.strptime(creation_str, "%Y-%m-%d")
        return (datetime.now() - created).days
    except Exception:
        return None


async def run_whois_check(url: str) -> Dict:
    flags: List[str] = []

    from urllib.parse import urlparse
    try:
        parsed   = urlparse(url)
        hostname = parsed.netloc.lower().split(":")[0]
        # Strip @ trick: google.com@evil.com → actual domain is after @
        if "@" in hostname:
            hostname = hostname.split("@")[-1]
        # Strip www.
        domain = hostname.lstrip("www.") if hostname.startswith("www.") else hostname
    except Exception:
        domain = ""

    if not domain:
        return {
            "domain": None,
            "domain_age_days": None,
            "registrar": "Unknown",
            "creation_date": None,
            "expiration_date": None,
            "country": None,
            "flags": ["Could not extract domain from URL"],
            "whois_score": 5,
            "is_suspicious": False,
        }

    try:
        w = whois.whois(domain)
    except Exception as e:
        clean_msg = _clean_whois_error(str(e), domain)
        # Determine score based on error type
        if "not found" in clean_msg.lower() or "unregistered" in clean_msg.lower():
            score = 15
            flags.append(
                f"Domain '{domain}' not found in WHOIS — "
                "unregistered or recently deleted"
            )
        elif "timed out" in clean_msg.lower():
            score = 5
            flags.append("WHOIS lookup timed out — results may be incomplete")
        else:
            score = 15
            flags.append(
                f"WHOIS data unavailable — {clean_msg}"
            )
        return {
            "domain": domain,
            "domain_age_days": None,
            "registrar": "Unknown",
            "creation_date": None,
            "expiration_date": None,
            "country": None,
            "flags": flags,
            "whois_score": score,
            "is_suspicious": False,
        }

    # ── Parse WHOIS fields ──────────────────────────────────────────────────
    creation_str   = _parse_date(getattr(w, "creation_date", None))
    expiration_str = _parse_date(getattr(w, "expiration_date", None))
    registrar_raw  = getattr(w, "registrar", None)
    registrar      = str(registrar_raw).strip() if registrar_raw else "Unknown"
    country        = getattr(w, "country", None)
    if isinstance(country, list):
        country = country[0] if country else None

    age_days = _domain_age_days(creation_str)

    # ── Check for empty/failed WHOIS (domain exists but no data) ───────────
    if not creation_str and not registrar_raw:
        flags.append(
            "Domain creation date not available in WHOIS — "
            "may indicate privacy shielding or new gTLD"
        )
        return {
            "domain": domain,
            "domain_age_days": None,
            "registrar": "Unknown",
            "creation_date": None,
            "expiration_date": None,
            "country": None,
            "flags": flags,
            "whois_score": 15,
            "is_suspicious": False,
        }

    # ── Score: domain age ───────────────────────────────────────────────────
    score = 0

    if age_days is not None:
        if age_days < 30:
            score += 40
            flags.append(
                f"Very new domain (registered {age_days} days ago) — "
                "phishing campaigns typically use freshly-registered domains"
            )
        elif age_days < 90:
            score += 20
            flags.append(
                f"Recently registered domain ({age_days} days old) — "
                "most phishing domains are < 90 days old"
            )
        elif age_days < 180:
            score += 10
            flags.append(
                f"Domain is {age_days} days old — newer domain, moderate risk"
            )
    elif not creation_str:
        score += 15
        flags.append(
            "Domain creation date not available in WHOIS — "
            "may indicate privacy shielding"
        )

    # ── Score: registration period ─────────────────────────────────────────
    if creation_str and expiration_str:
        try:
            c = datetime.strptime(creation_str, "%Y-%m-%d")
            e = datetime.strptime(expiration_str, "%Y-%m-%d")
            reg_period = (e - c).days
            if reg_period < 365:
                score += 10
                flags.append(
                    f"Short registration period ({reg_period} days) — "
                    "legitimate organizations register domains for multiple years"
                )
        except Exception:
            pass

    # ── Score: abusive registrar ───────────────────────────────────────────
    if registrar and any(
        a in registrar.lower() for a in ABUSIVE_REGISTRARS
    ):
        score += 10
        flags.append(
            f"Registrar '{registrar}' is frequently associated with "
            "abusive domain registrations"
        )

    return {
        "domain": domain,
        "domain_age_days": age_days,
        "registrar": registrar,
        "creation_date": creation_str,
        "expiration_date": expiration_str,
        "country": str(country) if country else None,
        "flags": flags,
        "whois_score": min(score, 100),
        "is_suspicious": score >= 30,
    }
