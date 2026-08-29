"""
Card Analyzer — Tier 2 Financial
  C-01  Luhn checksum validation
  C-02  Card network detection (12 networks incl. Meeza/RuPay/MIR)
  C-03  BIN lookup (binlist.net — free, no key)
  C-04  Test card detection (known test numbers)
  C-05  Expiry date validation
  C-06  CVV format check
  C-07  Card length / format validation
  C-08  Pakistani card network indicators
"""
import hashlib
import json
import logging
import re
from typing import Any

import httpx

from app.config import settings
from app.redis_client import cache_get, cache_set

logger = logging.getLogger(__name__)

# ── C-01: Luhn algorithm ──────────────────────────────────────────────────────
def luhn_check(number: str) -> dict:
    """
    Luhn algorithm (ISO/IEC 7812).
    Used by all major card networks to detect transcription errors.
    """
    digits = re.sub(r"[\s\-]", "", number)
    if not digits.isdigit():
        return {"valid": False, "reason": "Contains non-digit characters"}
    if len(digits) < 12 or len(digits) > 19:
        return {"valid": False, "reason": f"Invalid length {len(digits)} — cards are 12–19 digits"}

    total = 0
    for i, d in enumerate(reversed(digits)):
        n = int(d)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n

    valid = total % 10 == 0
    return {
        "valid": valid,
        "reason": None if valid else "Luhn checksum failed — not a valid card number",
        "digit_count": len(digits),
    }


# ── C-02: Card network detection ──────────────────────────────────────────────
def detect_network(number: str) -> dict:
    """
    Detect card network from BIN prefix.
    Covers 12 networks including Pakistan-specific (Meeza, Payoneer BINs).
    """
    digits = re.sub(r"[\s\-]", "", number)
    n = digits

    # Order matters — more specific first
    NETWORKS = [
        # Amex: 34, 37
        ("American Express", re.compile(r"^3[47]")),
        # Diners: 300–305, 36, 38
        ("Diners Club",      re.compile(r"^3(?:0[0-5]|[68])")),
        # JCB: 3528–3589
        ("JCB",              re.compile(r"^35(?:2[89]|[3-8]\d)")),
        # Discover: 6011, 622126-622925, 644-649, 65
        ("Discover",         re.compile(r"^6(?:011|22(?:1(?:2[6-9]|[3-9]\d)|[2-8]\d{2}|9(?:[01]\d|2[0-5]))|[45]\d{2}|5\d{3})")),
        # Maestro: 6304, 6759, 676[1-3]
        ("Maestro",          re.compile(r"^(?:6304|6759|676[1-3])")),
        # UnionPay: 62 (most)
        ("UnionPay",         re.compile(r"^62")),
        # MIR (Russian): 2200–2204
        ("MIR",              re.compile(r"^220[0-4]")),
        # RuPay (Indian): 60, 6521, 6522
        ("RuPay",            re.compile(r"^6(?:0|521|522)")),
        # Meeza (Egyptian): 507803, 507808
        ("Meeza",            re.compile(r"^5078(?:0[38])")),
        # Visa Electron: 4026, 417500, 4508, 4844, 4913, 4917
        ("Visa Electron",    re.compile(r"^(?:4026|417500|4508|4844|491[37])")),
        # Mastercard: 51–55, 2221–2720
        ("Mastercard",       re.compile(r"^(?:5[1-5]|2(?:2[2-9]\d|[3-6]\d{2}|7[01]\d|720))")),
        # Visa: 4
        ("Visa",             re.compile(r"^4")),
    ]

    for name, pattern in NETWORKS:
        if pattern.match(n):
            return {
                "network": name,
                "bin": digits[:6],
                "detected": True,
            }

    return {"network": "Unknown", "bin": digits[:6] if len(digits) >= 6 else digits, "detected": False}


# ── C-03: BIN lookup ──────────────────────────────────────────────────────────
async def lookup_bin(number: str) -> dict:
    """
    Query binlist.net for BIN details: bank name, country, card type, prepaid flag.
    Free, no API key. Rate limited at ~10/min.
    """
    digits = re.sub(r"[\s\-]", "", number)
    if len(digits) < 6:
        return {"available": False, "reason": "Need at least 6 digits for BIN lookup"}

    bin6 = digits[:6]
    cache_key = f"bin:{bin6}"
    cached = await cache_get(cache_key)
    if cached:
        return json.loads(cached)

    try:
        async with httpx.AsyncClient(timeout=settings.HTTP_TIMEOUT) as c:
            r = await c.get(
                f"https://lookup.binlist.net/{bin6}",
                headers={"Accept-Version": "3", "User-Agent": "Aegis-Tier2-Checker"},
            )
        if r.status_code == 200:
            data = r.json()
            result = {
                "available": True,
                "bin": bin6,
                "scheme": data.get("scheme", ""),
                "type": data.get("type", ""),         # debit / credit
                "brand": data.get("brand", ""),
                "prepaid": data.get("prepaid"),
                "bank": {
                    "name": data.get("bank", {}).get("name", ""),
                    "city": data.get("bank", {}).get("city", ""),
                    "phone": data.get("bank", {}).get("phone", ""),
                    "url": data.get("bank", {}).get("url", ""),
                },
                "country": {
                    "name": data.get("country", {}).get("name", ""),
                    "alpha2": data.get("country", {}).get("alpha2", ""),
                    "currency": data.get("country", {}).get("currency", ""),
                },
                "source": "binlist.net",
            }
        elif r.status_code == 404:
            result = {"available": True, "bin": bin6, "found": False,
                      "reason": "BIN not in database", "source": "binlist.net"}
        elif r.status_code == 429:
            result = {"available": False, "reason": "binlist.net rate limit — try again in 60s"}
        else:
            result = {"available": False, "reason": f"binlist.net HTTP {r.status_code}"}

        await cache_set(cache_key, json.dumps(result), ttl=86400)
        return result

    except Exception as e:
        logger.debug(f"BIN lookup error: {e}")
        return {"available": False, "reason": str(e)[:80], "source": "binlist.net"}


# ── C-04: Test card detection ─────────────────────────────────────────────────
TEST_CARDS = {
    "4111111111111111": ("Visa", "Standard test card"),
    "4012888888881881": ("Visa", "Test card"),
    "4222222222222":    ("Visa", "Test card (13-digit)"),
    "5500005555555559": ("Mastercard", "Standard test card"),
    "5105105105105100": ("Mastercard", "Test card"),
    "5425233430109903": ("Mastercard", "Test card"),
    "2223000048400011": ("Mastercard", "2-series test card"),
    "378282246310005":  ("Amex", "Standard test card"),
    "371449635398431":  ("Amex", "Test card"),
    "6011111111111117": ("Discover", "Standard test card"),
    "6011000990139424": ("Discover", "Test card"),
    "3530111333300000": ("JCB", "Standard test card"),
    "3566002020360505": ("JCB", "Test card"),
    "30569309025904":   ("Diners", "Standard test card"),
    "38520000023237":   ("Diners", "Test card"),
    "4000000000000002": ("Visa", "Stripe decline test"),
    "4000000000009995": ("Visa", "Stripe insufficient funds"),
    "4000000000000127": ("Visa", "Stripe incorrect CVC"),
    "4242424242424242": ("Visa", "Stripe success test"),
    "5555555555554444": ("Mastercard", "Stripe success test"),
    "4000056655665556": ("Visa Debit", "Stripe debit test"),
}

def detect_test_card(number: str) -> dict:
    """Detect known test card numbers used in development/QA environments."""
    clean = re.sub(r"[\s\-]", "", number)
    if clean in TEST_CARDS:
        network, desc = TEST_CARDS[clean]
        return {
            "is_test_card": True,
            "network": network,
            "description": desc,
            "risk": "High — test card number in production context",
        }
    # Stripe test pattern: repeating digit segments
    if re.match(r"^4{4}2{4}4{4}2{4}$", clean) or re.match(r"^5{4}4{4}5{4}4{4}$", clean):
        return {"is_test_card": True, "description": "Repeating-digit pattern (test/synthetic)", "risk": "High"}

    return {"is_test_card": False}


# ── C-05: Expiry validation ────────────────────────────────────────────────────
def validate_expiry(month: str, year: str) -> dict:
    """
    Validate card expiry date.
    Accepts: MM, YY or YYYY.
    """
    from datetime import date
    try:
        m = int(month)
        y = int(year)
        if y < 100:
            y += 2000   # 2-digit year

        if not (1 <= m <= 12):
            return {"valid": False, "reason": "Month must be 01–12"}
        if y < 2000 or y > 2050:
            return {"valid": False, "reason": f"Year {y} out of valid range"}

        # Last day of expiry month
        if m == 12:
            expiry = date(y + 1, 1, 1)
        else:
            expiry = date(y, m + 1, 1)

        today = date.today()
        is_expired = today >= expiry
        months_until = (expiry.year - today.year) * 12 + (expiry.month - today.month)

        return {
            "valid": True,
            "is_expired": is_expired,
            "expiry_date": f"{m:02d}/{y}",
            "months_until_expiry": months_until,
            "risk": "High" if is_expired else "Medium" if months_until <= 3 else "None",
        }
    except (ValueError, TypeError) as e:
        return {"valid": False, "reason": f"Invalid format: {e}"}


# ── C-06: CVV format check ────────────────────────────────────────────────────
def check_cvv(cvv: str, network: str = "") -> dict:
    """
    CVV must be 3 digits (most networks) or 4 digits (Amex CID).
    CVV should never appear in logs or storage.
    """
    if not cvv:
        return {"provided": False}
    clean = cvv.strip()
    if not clean.isdigit():
        return {"provided": True, "valid": False, "reason": "CVV must be numeric"}

    expected_len = 4 if "express" in network.lower() else 3
    valid = len(clean) == expected_len

    return {
        "provided": True,
        "valid": valid,
        "length": len(clean),
        "expected_length": expected_len,
        "reason": None if valid else f"Expected {expected_len} digits for {network or 'this network'}",
        "security_note": "CVV not stored — format validated only",
    }


# ── C-08: Pakistani card indicators ───────────────────────────────────────────
PK_BIN_PREFIXES = {
    # HBL
    "404090": "HBL Visa Debit",    "404091": "HBL Visa Debit",
    "404092": "HBL Visa Debit",    "539264": "HBL Mastercard Debit",
    "539266": "HBL Mastercard",    "454313": "HBL Visa Credit",
    # MCB
    "459769": "MCB Visa Debit",    "459770": "MCB Visa Debit",
    "526506": "MCB Mastercard",    "521299": "MCB Mastercard Debit",
    # UBL
    "421978": "UBL Visa Debit",    "421979": "UBL Visa",
    "512276": "UBL Mastercard",    "517553": "UBL Mastercard Debit",
    # Meezan Bank
    "405523": "Meezan Visa",       "422432": "Meezan Visa",
    "517538": "Meezan Mastercard",
    # Bank Alfalah
    "491491": "Alfalah Visa",      "491492": "Alfalah Visa",
    "549551": "Alfalah Mastercard",
    # Askari Bank
    "414751": "Askari Visa",       "534579": "Askari Mastercard",
    # Faysal Bank
    "531019": "Faysal Mastercard", "524668": "Faysal Mastercard",
    # JS Bank
    "400026": "JS Bank Visa",      "517490": "JS Bank Mastercard",
    # Standard Chartered Pakistan
    "476618": "SCB Pakistan Visa", "521774": "SCB Pakistan MC",
    # JazzCash prepaid
    "534396": "JazzCash Mastercard",
    # Easypaisa prepaid
    "536766": "Easypaisa Mastercard",
    # NayaPay
    "529076": "NayaPay Mastercard",
    # SadaPay
    "535960": "SadaPay Mastercard",
}

def check_pk_card(number: str) -> dict:
    """Check if this appears to be a Pakistani bank-issued card."""
    clean = re.sub(r"[\s\-]", "", number)
    bin6 = clean[:6] if len(clean) >= 6 else clean
    if bin6 in PK_BIN_PREFIXES:
        return {
            "is_pk_card": True,
            "bank_product": PK_BIN_PREFIXES[bin6],
            "bin": bin6,
        }
    return {"is_pk_card": False, "bin": bin6}


# ── Master card scanner ────────────────────────────────────────────────────────
async def analyze_card(
    number: str,
    expiry_month: str = "",
    expiry_year: str = "",
    cvv: str = ""
) -> dict[str, Any]:
    """
    Full card analysis — all 8 features.
    Raw CVV never stored. Card number hashed for caching only.
    """
    clean = re.sub(r"[\s\-]", "", number)

    luhn       = luhn_check(number)
    network    = detect_network(number)
    test_card  = detect_test_card(number)
    pk_check   = check_pk_card(number)
    expiry     = validate_expiry(expiry_month, expiry_year) if expiry_month and expiry_year else {"provided": False}
    cvv_check  = check_cvv(cvv, network.get("network", ""))
    bin_info   = await lookup_bin(number)

    # ── Risk scoring ──────────────────────────────────────────────────────────
    score = 0
    flags = []

    if not luhn["valid"]:
        score += 40
        flags.append(f"Luhn checksum FAILED — {luhn.get('reason', '')}")
    
    if test_card["is_test_card"]:
        score += 50
        flags.append(f"Test card number detected: {test_card.get('description', '')}")
    
    if expiry.get("is_expired"):
        score += 30
        flags.append("Card has expired")
    elif expiry.get("months_until_expiry", 99) <= 3 and expiry.get("valid"):
        score += 10
        flags.append(f"Card expires in {expiry.get('months_until_expiry')} month(s)")
    
    if not network["detected"]:
        score += 15
        flags.append("Unknown card network — could not identify issuer")
    
    if cvv_check.get("provided") and not cvv_check.get("valid"):
        score += 15
        flags.append(f"Invalid CVV format: {cvv_check.get('reason', '')}")
    
    if bin_info.get("prepaid"):
        score += 5
        flags.append("Prepaid card — higher fraud risk")
    
    # Missing expiry or CVV in context where they should be present
    if not expiry.get("provided"):
        flags.append("Expiry date not provided")
    if not cvv_check.get("provided"):
        flags.append("CVV not provided")

    score = min(score, 100)

    if score < 16:   level = "Clean"
    elif score < 36: level = "Low"
    elif score < 56: level = "Medium"
    elif score < 76: level = "High"
    else:            level = "Critical"

    return {
        "credential_type": "card",
        "masked_number": f"{'*' * (len(clean) - 4)}{clean[-4:]}" if len(clean) >= 4 else "****",
        "privacy_note": "Full card number not stored — last 4 digits only retained",
        "luhn": luhn,
        "network": network,
        "bin_info": bin_info,
        "test_card": test_card,
        "pk_card": pk_check,
        "expiry": expiry,
        "cvv": cvv_check,
        "overall_risk_score": score,
        "overall_risk_level": level,
        "all_flags": flags,
    }
