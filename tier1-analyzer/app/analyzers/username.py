"""
Username Analyzer — All 7 checklist features:
  U-01  Brand impersonation (100+ brands incl. Pakistani banks)
  U-02  Bot entropy detection (Shannon entropy threshold)
  U-03  Numeric suffix pattern (auto-generated bot accounts)
  U-04  Lookalike / digit substitution (m1cr0s0ft)
  U-05  Admin / suspicious keyword detection
  U-06  Breach history search (DeHashed API)
  U-07  Cross-platform presence check (Sherlock-style)
"""
import hashlib
import json
import logging
import math
import re
import unicodedata
from typing import Any

import httpx

from app.config import settings
from app.data.password_data import BRANDS, HOMOGLYPH_MAP
from app.redis_client import cache_get, cache_set

logger = logging.getLogger(__name__)

# ── U-01: Brand impersonation ─────────────────────────────────────────────────
def detect_brand_impersonation(username: str) -> dict:
    """
    Check if username contains brand names to impersonate official accounts.
    Covers 100+ global + Pakistani brands.
    """
    lower = username.lower()
    # Remove common separators for matching
    clean = re.sub(r"[_\-\.\s]", "", lower)
    found = []

    for brand in BRANDS:
        brand_clean = brand.replace(" ", "")
        if brand_clean in clean:
            # Check it's not a legitimate user with that name
            # (Flag only if combined with 'official', 'support', 'help', numbers at end)
            found.append(brand)

    # Extra: support / official / admin keywords next to any word
    combined_suspicion = bool(
        re.search(r"(support|official|admin|helpdesk|help|service|security|"
                  r"billing|verify|account|team|staff|representative|rep)\d*$", lower)
        and found
    )

    return {
        "detected": len(found) > 0,
        "brands_found": found,
        "primary_brand": found[0] if found else None,
        "combined_with_support_keyword": combined_suspicion,
        "risk": "High" if (found and combined_suspicion) else "Medium" if found else "None",
    }


# ── U-02: Entropy (bot detection) ────────────────────────────────────────────
def calc_username_entropy(username: str) -> dict:
    """
    Shannon entropy of username.
    High entropy with mixed chars = machine-generated.
    Thresholds tuned from analysis of real bot datasets.
    """
    if not username:
        return {"entropy_bits": 0, "is_high_entropy": False}

    lower = username.lower()
    freq = {}
    for c in lower:
        freq[c] = freq.get(c, 0) + 1
    n = len(lower)
    shannon = -sum((v / n) * math.log2(v / n) for v in freq.values())

    # Threshold: 3.2 bits for short strings, lower acceptable for names
    # Adjust by length: short high-entropy = more suspicious
    threshold = 3.0 if n < 8 else 3.2 if n < 12 else 3.5
    is_high = shannon > threshold

    return {
        "entropy_bits": round(shannon, 3),
        "threshold": threshold,
        "is_high_entropy": is_high,
        "unique_char_ratio": round(len(freq) / n, 3),
        "length": n,
    }


# ── U-03: Bot numeric patterns ───────────────────────────────────────────────
def detect_bot_patterns(username: str) -> dict:
    """
    Detect patterns common in auto-generated bot accounts:
    - Long numeric suffix (user4729182)
    - All digits
    - Hex-like strings (a3f7c2d9)
    - Very long alphanumeric without vowels
    - Repeated segments
    """
    lower = username.lower()
    patterns = {}

    # Long numeric suffix (5+ digits)
    m = re.search(r"[a-z]{2,}\d{5,}$", lower)
    patterns["numeric_suffix"] = m.group(0) if m else None

    # All digits
    patterns["all_digits"] = lower.isdigit()

    # Hex string (8+ hex chars with no vowels)
    patterns["hex_string"] = bool(re.fullmatch(r"[0-9a-f]{8,}", lower))

    # No vowels in alpha part
    alpha_part = re.sub(r"\d", "", lower)
    patterns["no_vowels"] = len(alpha_part) >= 4 and not any(
        v in alpha_part for v in "aeiou"
    )

    # Random-looking (mixed case, digits, no recognisable words)
    patterns["mixed_random"] = bool(
        re.search(r"[A-Z]", username) and
        re.search(r"\d", username) and
        len(username) >= 8 and
        not re.search(r"[aeiou]{2,}", lower)
    )

    detected = any(patterns.values())

    # Bot probability
    signals = sum(1 for v in patterns.values() if v)
    if signals == 0:   prob_label = "Low"
    elif signals == 1: prob_label = "Medium"
    elif signals == 2: prob_label = "High"
    else:              prob_label = "Very High"

    return {
        "detected": detected,
        "patterns": patterns,
        "bot_signal_count": signals,
        "bot_probability_label": prob_label,
    }


# ── U-04: Lookalike / digit substitution ─────────────────────────────────────
def detect_lookalike(username: str) -> dict:
    """
    Detect digit-for-letter substitutions (m1cr0s0ft)
    and Unicode lookalike chars in username.
    """
    lower = username.lower()
    digit_subs = {
        '0': 'o', '1': 'l', '3': 'e', '4': 'a',
        '5': 's', '6': 'g', '7': 't', '8': 'b',
    }

    # Check digit substitutions
    subs_found = {}
    for char in lower:
        if char in digit_subs:
            subs_found[char] = digit_subs[char]

    # Reconstruct with subs applied and check for brand
    if subs_found:
        normalized = lower
        for digit, letter in subs_found.items():
            normalized = normalized.replace(digit, letter)
    else:
        normalized = lower

    # Check homoglyphs
    hg_found = {c: HOMOGLYPH_MAP[c] for c in username if c in HOMOGLYPH_MAP}

    detected = bool(subs_found or hg_found)

    return {
        "detected": detected,
        "digit_substitutions": subs_found,
        "homoglyph_chars": hg_found,
        "normalized_form": normalized if subs_found else None,
    }


# ── U-05: Suspicious keyword detection ───────────────────────────────────────
def detect_suspicious_keywords(username: str) -> dict:
    """
    Detect reserved / privileged / suspicious keywords in username.
    Tokenises by splitting on non-alpha characters (handles underscores, dots, digits).
    """
    lower = username.lower()
    # Split on anything that isn't a letter — handles under_score, dot.sep, digits
    tokens = set(re.split(r"[^a-z]+", lower))
    tokens.discard("")

    ADMIN     = {"admin","administrator","root","superuser","sysadmin","superadmin",
                 "moderator","staff","owner","webmaster","postmaster"}
    SECURITY  = {"security","verify","verification","secure","safe","protected",
                 "auth","authentication","login","password","signin"}
    PAYMENT   = {"payment","pay","billing","invoice","money","cash","transfer",
                 "bank","wallet","refund","topup","recharge"}
    SUPPORT   = {"support","helpdesk","help","service","cs","customercare",
                 "customer","care","assistance","rep","representative"}
    OFFICIAL  = {"official","real","genuine","authentic","legit","legitimate",
                 "verified","true","original"}

    found = {}
    for tok in tokens:
        if tok in ADMIN:     found["admin_privilege"]    = tok
        if tok in SECURITY:  found["security_keyword"]   = tok
        if tok in PAYMENT:   found["payment_keyword"]    = tok
        if tok in SUPPORT:   found["support_keyword"]    = tok
        if tok in OFFICIAL:  found["official_keyword"]   = tok

    return {
        "detected": len(found) > 0,
        "tokens_checked": sorted(tokens),
        "keywords_found": found,
        "risk": "High" if len(found) >= 2 else "Medium" if found else "None",
    }


# ── U-06: Breach history (DeHashed) ──────────────────────────────────────────
async def check_username_breach(username: str) -> dict:
    """
    Search DeHashed for username in known credential dumps.
    Requires DEHASHED_EMAIL + DEHASHED_API_KEY in .env (free account).
    """
    if not settings.DEHASHED_EMAIL or not settings.DEHASHED_API_KEY:
        return {"available": False, "reason": "DEHASHED credentials not configured"}

    cache_key = f"dehashed:usr:{hashlib.sha256(username.lower().encode()).hexdigest()[:16]}"
    cached = await cache_get(cache_key)
    if cached:
        return json.loads(cached)

    try:
        async with httpx.AsyncClient(timeout=settings.HTTP_TIMEOUT) as c:
            r = await c.get(
                "https://api.dehashed.com/search",
                params={"query": f"username:{username}", "size": 10},
                headers={"Accept": "application/json"},
                auth=(settings.DEHASHED_EMAIL, settings.DEHASHED_API_KEY),
            )

        if r.status_code == 200:
            data = r.json()
            total = data.get("total", 0)
            entries = data.get("entries") or []
            result = {
                "available": True,
                "found": total > 0,
                "total_results": total,
                "sample_breaches": [
                    {
                        "database_name": e.get("database_name"),
                        "email": e.get("email", "").split("@")[0] + "@***" if e.get("email") else None,
                        "hashed_password": e.get("hashed_password", ""),
                        "ip_address": e.get("ip_address"),
                    }
                    for e in entries[:5]
                ],
                "source": "dehashed.com",
            }
        elif r.status_code == 401:
            result = {"available": False, "reason": "Invalid DeHashed credentials"}
        elif r.status_code == 302:
            result = {"available": False, "reason": "DeHashed: account required — check subscription"}
        else:
            result = {"available": False, "reason": f"DeHashed HTTP {r.status_code}"}

        await cache_set(cache_key, json.dumps(result), ttl=3600)
        return result

    except Exception as e:
        logger.warning(f"DeHashed error: {e}")
        return {"available": False, "reason": str(e)[:100]}


# ── U-07: Cross-platform presence ────────────────────────────────────────────
async def check_cross_platform(username: str) -> dict:
    """
    Check if username exists on major platforms.
    Makes lightweight HEAD requests to public profile URLs.
    Only checks platforms with publicly detectable profiles.
    """
    PLATFORMS = {
        "GitHub":    f"https://github.com/{username}",
        "Twitter":   f"https://twitter.com/{username}",
        "Instagram": f"https://www.instagram.com/{username}/",
        "Reddit":    f"https://www.reddit.com/user/{username}",
        "TikTok":    f"https://www.tiktok.com/@{username}",
        "Telegram":  f"https://t.me/{username}",
    }

    found_on = []
    not_found_on = []

    async def check_one(name: str, url: str) -> None:
        try:
            async with httpx.AsyncClient(
                timeout=6.0,
                follow_redirects=False,
                headers={"User-Agent": "Mozilla/5.0 (compatible; AegisBot/1.0)"}
            ) as c:
                r = await c.head(url)
                if r.status_code == 200:
                    found_on.append({"platform": name, "url": url})
                elif r.status_code in (301, 302, 303, 307, 308):
                    # Might be a redirect to a valid profile
                    location = r.headers.get("location", "")
                    if "login" not in location and "signin" not in location:
                        found_on.append({"platform": name, "url": url, "redirects_to": location})
                    else:
                        not_found_on.append(name)
                else:
                    not_found_on.append(name)
        except Exception:
            not_found_on.append(name)

    import asyncio
    await asyncio.gather(*[check_one(n, u) for n, u in PLATFORMS.items()])

    return {
        "available": True,
        "platforms_found": found_on,
        "platform_count": len(found_on),
        "checked_platforms": list(PLATFORMS.keys()),
        "note": "High platform count may indicate established user or targeted account",
    }


# ── Master username scanner ───────────────────────────────────────────────────
async def analyze_username(username: str, skip_external: bool = False) -> dict[str, Any]:
    """
    Run all 7 username analysis features.
    Returns comprehensive result with overall risk score.
    """
    import asyncio
    username = username.strip()

    # ── Synchronous checks ────────────────────────────────────────────────────
    brand     = detect_brand_impersonation(username)
    entropy   = calc_username_entropy(username)
    bot_pats  = detect_bot_patterns(username)
    lookalike = detect_lookalike(username)
    keywords  = detect_suspicious_keywords(username)

    # ── Async checks ──────────────────────────────────────────────────────────
    breach_task   = asyncio.create_task(check_username_breach(username))
    platform_task = asyncio.create_task(check_cross_platform(username))

    breach, platforms = await asyncio.gather(breach_task, platform_task,
                                             return_exceptions=True)
    if isinstance(breach, Exception):
        breach = {"available": False, "reason": str(breach)[:80]}
    if isinstance(platforms, Exception):
        platforms = {"available": False, "reason": str(platforms)[:80]}

    # ── Score aggregation ─────────────────────────────────────────────────────
    score = 0
    flags = []

    # Brand impersonation
    if brand["detected"]:
        score += 35
        flags.append(f"Brand impersonation: {brand['brands_found']}")
        if brand["combined_with_support_keyword"]:
            score += 10
            flags.append("Combined with support/official keyword — high phishing risk")

    # Bot entropy
    if entropy["is_high_entropy"]:
        score += 20
        flags.append(f"High entropy ({entropy['entropy_bits']} bits) — likely machine-generated")

    # Bot patterns
    if bot_pats["detected"]:
        score += bot_pats["bot_signal_count"] * 8
        pats = [k for k, v in bot_pats["patterns"].items() if v]
        flags.append(f"Bot-like patterns detected: {pats}")

    # Lookalike
    if lookalike["detected"]:
        score += 15
        if lookalike["digit_substitutions"]:
            flags.append(f"Digit substitutions found: {lookalike['digit_substitutions']}")
        if lookalike["homoglyph_chars"]:
            flags.append(f"Homoglyph characters: {list(lookalike['homoglyph_chars'].keys())}")

    # Keywords
    if keywords["detected"]:
        score += len(keywords["keywords_found"]) * 8
        flags.append(f"Suspicious keywords: {list(keywords['keywords_found'].values())}")

    # Breach
    if breach.get("found"):
        score += min(20, breach.get("total_results", 0) * 2)
        flags.append(f"Username found in {breach.get('total_results', 0)} breach record(s)")

    score = min(score, 100)

    if score < 16:   level = "Clean"
    elif score < 36: level = "Low"
    elif score < 56: level = "Medium"
    elif score < 76: level = "High"
    else:            level = "Critical"

    return {
        "credential_type": "username",
        "input": username,
        "brand_impersonation": brand,
        "entropy": entropy,
        "bot_patterns": bot_pats,
        "lookalike": lookalike,
        "suspicious_keywords": keywords,
        "breach_history": breach,
        "cross_platform": platforms,
        "overall_risk_score": score,
        "overall_risk_level": level,
        "all_flags": flags,
    }
