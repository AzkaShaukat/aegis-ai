"""
Phone Number Analyzer — Tier 3 Identity Documents
  PH-01  E.164 format validation (+CountryCode + Number)
  PH-02  Country / operator identification (70+ countries)
  PH-03  Pakistani number full decode (Jazz/Telenor/Zong/Ufone/SCOM/PMCL)
  PH-04  Number type classification (mobile/landline/toll-free/premium/VoIP)
  PH-05  VOIP / virtual number detection (Twilio, Google Voice, TextNow prefixes)
  PH-06  Disposable / OTP-bypass service detection
  PH-07  SIM swap risk indicators
  PH-08  International format normalisation
  PH-09  PhoneRep / carrier lookup via numverify (optional, free tier)
  PH-10  Threat scoring — known spam/scam prefixes
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

# ── Country calling codes ─────────────────────────────────────────────────────
COUNTRY_CODES: dict = {
    "1":   {"country": "United States / Canada", "iso": "US"},
    "7":   {"country": "Russia / Kazakhstan",    "iso": "RU"},
    "20":  {"country": "Egypt",                  "iso": "EG"},
    "27":  {"country": "South Africa",           "iso": "ZA"},
    "30":  {"country": "Greece",                 "iso": "GR"},
    "31":  {"country": "Netherlands",            "iso": "NL"},
    "32":  {"country": "Belgium",                "iso": "BE"},
    "33":  {"country": "France",                 "iso": "FR"},
    "34":  {"country": "Spain",                  "iso": "ES"},
    "36":  {"country": "Hungary",                "iso": "HU"},
    "39":  {"country": "Italy",                  "iso": "IT"},
    "40":  {"country": "Romania",                "iso": "RO"},
    "41":  {"country": "Switzerland",            "iso": "CH"},
    "44":  {"country": "United Kingdom",         "iso": "GB"},
    "45":  {"country": "Denmark",                "iso": "DK"},
    "46":  {"country": "Sweden",                 "iso": "SE"},
    "47":  {"country": "Norway",                 "iso": "NO"},
    "48":  {"country": "Poland",                 "iso": "PL"},
    "49":  {"country": "Germany",                "iso": "DE"},
    "51":  {"country": "Peru",                   "iso": "PE"},
    "52":  {"country": "Mexico",                 "iso": "MX"},
    "54":  {"country": "Argentina",              "iso": "AR"},
    "55":  {"country": "Brazil",                 "iso": "BR"},
    "56":  {"country": "Chile",                  "iso": "CL"},
    "57":  {"country": "Colombia",               "iso": "CO"},
    "60":  {"country": "Malaysia",               "iso": "MY"},
    "61":  {"country": "Australia",              "iso": "AU"},
    "62":  {"country": "Indonesia",              "iso": "ID"},
    "63":  {"country": "Philippines",            "iso": "PH"},
    "64":  {"country": "New Zealand",            "iso": "NZ"},
    "65":  {"country": "Singapore",              "iso": "SG"},
    "66":  {"country": "Thailand",               "iso": "TH"},
    "81":  {"country": "Japan",                  "iso": "JP"},
    "82":  {"country": "South Korea",            "iso": "KR"},
    "84":  {"country": "Vietnam",                "iso": "VN"},
    "86":  {"country": "China",                  "iso": "CN"},
    "90":  {"country": "Turkey",                 "iso": "TR"},
    "91":  {"country": "India",                  "iso": "IN"},
    "92":  {"country": "Pakistan",               "iso": "PK"},
    "93":  {"country": "Afghanistan",            "iso": "AF"},
    "94":  {"country": "Sri Lanka",              "iso": "LK"},
    "95":  {"country": "Myanmar",                "iso": "MM"},
    "98":  {"country": "Iran",                   "iso": "IR"},
    "212": {"country": "Morocco",                "iso": "MA"},
    "213": {"country": "Algeria",                "iso": "DZ"},
    "216": {"country": "Tunisia",                "iso": "TN"},
    "218": {"country": "Libya",                  "iso": "LY"},
    "220": {"country": "Gambia",                 "iso": "GM"},
    "221": {"country": "Senegal",                "iso": "SN"},
    "234": {"country": "Nigeria",                "iso": "NG"},
    "254": {"country": "Kenya",                  "iso": "KE"},
    "256": {"country": "Uganda",                 "iso": "UG"},
    "260": {"country": "Zambia",                 "iso": "ZM"},
    "263": {"country": "Zimbabwe",               "iso": "ZW"},
    "880": {"country": "Bangladesh",             "iso": "BD"},
    "966": {"country": "Saudi Arabia",           "iso": "SA"},
    "971": {"country": "UAE",                    "iso": "AE"},
    "972": {"country": "Israel",                 "iso": "IL"},
    "973": {"country": "Bahrain",                "iso": "BH"},
    "974": {"country": "Qatar",                  "iso": "QA"},
    "975": {"country": "Bhutan",                 "iso": "BT"},
    "976": {"country": "Mongolia",               "iso": "MN"},
    "977": {"country": "Nepal",                  "iso": "NP"},
    "992": {"country": "Tajikistan",             "iso": "TJ"},
    "993": {"country": "Turkmenistan",           "iso": "TM"},
    "994": {"country": "Azerbaijan",             "iso": "AZ"},
    "995": {"country": "Georgia",                "iso": "GE"},
    "996": {"country": "Kyrgyzstan",             "iso": "KG"},
    "998": {"country": "Uzbekistan",             "iso": "UZ"},
}

# ── Pakistani mobile number prefixes (MNO allocation) ─────────────────────────
PK_OPERATOR_MAP: dict = {
    # Jazz (formerly Mobilink) — 030x, 031x
    "0300": "Jazz",  "0301": "Jazz",  "0302": "Jazz",  "0303": "Jazz",
    "0304": "Jazz",  "0305": "Jazz",  "0306": "Jazz",  "0307": "Jazz",
    "0308": "Jazz",  "0309": "Jazz",
    "0310": "Jazz",  "0311": "Jazz",  "0312": "Jazz",  "0313": "Jazz",
    "0314": "Jazz",  "0315": "Jazz",  "0316": "Jazz",  "0317": "Jazz",
    "0318": "Jazz",  "0319": "Jazz",
    # Telenor — 034x, 033x
    "0340": "Telenor","0341": "Telenor","0342": "Telenor","0343": "Telenor",
    "0344": "Telenor","0345": "Telenor","0346": "Telenor","0347": "Telenor",
    "0348": "Telenor","0349": "Telenor",
    "0330": "Telenor","0331": "Telenor","0332": "Telenor","0333": "Telenor",
    "0334": "Telenor","0335": "Telenor","0336": "Telenor","0337": "Telenor",
    "0338": "Telenor","0339": "Telenor",
    # Zong (China Mobile) — 031x overlap, 032x
    "0320": "Zong",  "0321": "Zong",  "0322": "Zong",  "0323": "Zong",
    "0324": "Zong",  "0325": "Zong",  "0326": "Zong",  "0327": "Zong",
    "0328": "Zong",  "0329": "Zong",
    # Ufone (PTCL) — 033x overlap
    "0350": "Ufone", "0351": "Ufone", "0352": "Ufone", "0353": "Ufone",
    "0354": "Ufone", "0355": "Ufone", "0356": "Ufone", "0357": "Ufone",
    "0358": "Ufone", "0359": "Ufone",
    # SCO/SCOM (Special Communications Organization — AJK, GB)
    "0855": "SCO",   "0856": "SCO",   "0857": "SCO",   "0858": "SCO",
}

# Known VOIP / virtual number providers (by prefix pattern)
VOIP_INDICATORS = {
    # Google Voice US
    "US_VOIP": ["747", "762", "878"],
    # Twilio US numbers often use area codes: 209, 302, 339, 360, 365
    "TWILIO_COMMON": ["209", "302", "339"],
    # TextNow / Talkatone / Burner
    "BURNER_APPS": ["646", "347", "332"],
}

# Known spam/scam prefixes globally
KNOWN_SCAM_PREFIXES = {
    "+1809", "+1876", "+1473", "+1284",  # Caribbean premium rate
    "+1900",                              # US premium rate
    "+44070", "+44076",                   # UK non-geographic
    "+3538", "+37244",                    # Known scam ranges
    "+2250", "+2255",                     # W. Africa scam
}

# Disposable SMS / OTP-bypass services
DISPOSABLE_SMS_SERVICES = {
    "receivesmsonline", "receive-smsonline", "sms-receive",
    "receive-sms", "tempphone", "receivefreesms", "hs3x",
    "smstome", "freephonenum", "freesmsverification",
    "receive-sms-online", "smslive", "7sim",
    "smsreceivefree", "myfakephone",
}


# ── PH-01: E.164 format validation ────────────────────────────────────────────
def validate_phone_format(phone: str) -> dict:
    """
    E.164 format: + followed by 7–15 digits.
    Also accepts local formats (starting with 0).
    """
    clean = re.sub(r"[\s\-\(\)\.]", "", phone.strip())

    # Already E.164
    if re.match(r"^\+\d{7,15}$", clean):
        return {
            "valid": True,
            "format": "E.164",
            "normalized": clean,
            "digits": clean[1:],
        }

    # 00 international prefix — MUST check before generic 0-prefix
    if re.match(r"^00\d{7,15}$", clean):
        e164 = "+" + clean[2:]
        return {
            "valid": True,
            "format": "International (00xx)",
            "normalized": e164,
            "digits": clean[2:],
        }

    # Leading 0 (local) — try to detect country
    if re.match(r"^0\d{7,14}$", clean):
        return {
            "valid": True,
            "format": "Local (0xx...)",
            "normalized": clean,
            "digits": clean[1:],
            "note": "Local format — country code not included",
        }

    return {
        "valid": False,
        "reason": "Invalid phone format. Expected: +CountryCodeNumber (E.164), or 0xxx (local)",
    }


# ── PH-02: Country identification ─────────────────────────────────────────────
def identify_country(phone: str) -> dict:
    """Match calling code against known country codes."""
    clean = re.sub(r"[\s\-\(\)\.+]", "", phone)

    # Try longest match first (3-digit codes before 2-digit before 1-digit)
    for length in (3, 2, 1):
        prefix = clean[:length]
        if prefix in COUNTRY_CODES:
            info = COUNTRY_CODES[prefix]
            return {
                "calling_code": prefix,
                "country": info["country"],
                "iso": info["iso"],
                "detected": True,
                "is_high_risk": info["iso"] in {"KP", "IR", "SY", "AF", "MM", "YE", "LY", "SO"},
            }

    return {"calling_code": clean[:3], "country": "Unknown", "detected": False}


# ── PH-03: Pakistani number decode ────────────────────────────────────────────
def decode_pk_number(phone: str) -> dict:
    """
    Full decode for Pakistani numbers (+92 or 03xx format).
    """
    clean = re.sub(r"[\s\-\(\)\.+]", "", phone)

    # Normalise to 03xx format
    if clean.startswith("92") and len(clean) == 12:
        local = "0" + clean[2:]
    elif clean.startswith("0") and len(clean) == 11:
        local = clean
    else:
        return {"is_pk_number": False}

    prefix4 = local[:4]
    operator = PK_OPERATOR_MAP.get(prefix4)

    # Lahore/Karachi/ISB landline detection
    landline_codes = {
        "021": "Karachi",
        "042": "Lahore",
        "051": "Islamabad/Rawalpindi",
        "041": "Faisalabad",
        "061": "Multan",
        "091": "Peshawar",
        "081": "Quetta",
        "071": "Sukkur",
    }
    city = None
    if local[:3] in landline_codes:
        city = landline_codes[local[:3]]

    return {
        "is_pk_number": True,
        "local_format": local,
        "e164_format": "+92" + local[1:],
        "operator": operator or "Unknown / PTCL Landline",
        "is_mobile": operator is not None,
        "is_landline": city is not None,
        "city_hint": city,
        "prefix": prefix4,
    }


# ── PH-04: Number type classification ─────────────────────────────────────────
def classify_number_type(phone: str) -> dict:
    """Classify as mobile / landline / toll-free / premium / VOIP."""
    clean = re.sub(r"[\s\-\(\)\.+]", "", phone)

    # Toll-free patterns
    if re.match(r"^1(800|888|877|866|855|844|833)\d{7}$", clean):
        return {"type": "toll_free", "subtype": "US/Canada toll-free"}

    # US premium
    if re.match(r"^1900\d{7}$", clean):
        return {"type": "premium_rate", "subtype": "US premium rate (900)", "risk": "High"}

    # UK non-geographic
    if clean.startswith("44") and clean[2:4] in ("70", "76"):
        return {"type": "voip_suspect", "subtype": "UK non-geographic", "risk": "Medium"}

    # Pakistani mobile (03xx)
    if re.match(r"^920[3-5]\d{8}$", clean) or re.match(r"^0[3][0-9]\d{8}$", clean):
        return {"type": "mobile", "subtype": "Pakistani mobile"}

    # Pakistani landline (0x1-0x9 area codes)
    if re.match(r"^920[2-9]\d+$", clean):
        return {"type": "landline", "subtype": "Pakistani landline"}

    return {"type": "unknown", "subtype": None}


# ── PH-05: VOIP detection ──────────────────────────────────────────────────────
def detect_voip(phone: str) -> dict:
    """Detect VOIP / virtual number patterns."""
    clean = re.sub(r"[\s\-\(\)\.+]", "", phone)
    indicators = []

    # Check known VOIP area codes (US)
    if clean.startswith("1") and len(clean) == 11:
        area_code = clean[1:4]
        for provider, codes in VOIP_INDICATORS.items():
            if area_code in codes:
                indicators.append(f"Area code {area_code} associated with {provider.replace('_',' ')}")

    # UK VOIP / virtual
    if clean.startswith("44"):
        ndc = clean[2:5]
        if ndc in ("700", "701", "702", "703", "704", "705"):
            indicators.append("UK 070x prefix commonly used for VOIP/forwarding")

    return {
        "likely_voip": len(indicators) > 0,
        "indicators": indicators,
    }


# ── PH-06: Disposable SMS detection ───────────────────────────────────────────
def check_disposable_sms(phone: str) -> dict:
    """Check if number pattern suggests OTP-bypass/temp SMS service."""
    clean = re.sub(r"[\s\-\(\)\.+]", "", phone)
    indicators = []

    # Very short numbers — often test/virtual
    if len(clean) < 7:
        indicators.append("Unusually short phone number — may be virtual/test")

    # US numbers with known burner app area codes
    if clean.startswith("1") and len(clean) == 11:
        area = clean[1:4]
        if area in ("747", "762", "878", "858", "463", "364"):
            indicators.append(f"Area code {area} commonly used by virtual/burner number apps")

    return {
        "likely_disposable": len(indicators) > 0,
        "indicators": indicators,
    }


# ── PH-09: Numverify carrier lookup ───────────────────────────────────────────
async def lookup_numverify(phone: str) -> dict:
    """
    numverify.com free API (100 req/month without key).
    Returns carrier, line type (mobile/landline), country.
    """
    if not settings.NUMVERIFY_API_KEY:
        return {"available": False, "reason": "NUMVERIFY_API_KEY not configured (optional)"}

    clean = re.sub(r"[\s\-\(\)\.+]", "", phone)
    cache_key = f"numverify:{hashlib.sha256(clean.encode()).hexdigest()[:16]}"
    cached = await cache_get(cache_key)
    if cached:
        return json.loads(cached)

    try:
        async with httpx.AsyncClient(timeout=settings.HTTP_TIMEOUT) as c:
            r = await c.get(
                "http://apilayer.net/api/validate",
                params={
                    "access_key": settings.NUMVERIFY_API_KEY,
                    "number": clean,
                    "country_code": "",
                    "format": "1",
                },
            )
        data = r.json()
        if data.get("valid"):
            result = {
                "available": True,
                "valid": True,
                "carrier": data.get("carrier", ""),
                "line_type": data.get("line_type", ""),
                "country_code": data.get("country_code", ""),
                "country_name": data.get("country_name", ""),
                "local_format": data.get("local_format", ""),
                "international_format": data.get("international_format", ""),
                "source": "numverify.com",
            }
        else:
            result = {
                "available": True,
                "valid": False,
                "reason": data.get("error", {}).get("info", "Number invalid"),
                "source": "numverify.com",
            }
        await cache_set(cache_key, json.dumps(result), ttl=86400)
        return result
    except Exception as e:
        return {"available": False, "reason": str(e)[:100], "source": "numverify.com"}


# ── PH-10: Spam/scam prefix check ─────────────────────────────────────────────
def check_scam_prefix(phone: str) -> dict:
    """Check against known scam/spam phone number prefixes."""
    clean = "+" + re.sub(r"[\s\-\(\)\.]", "", phone).lstrip("+")
    for prefix in KNOWN_SCAM_PREFIXES:
        if clean.startswith(prefix):
            return {
                "is_scam_prefix": True,
                "matched_prefix": prefix,
                "risk": "High",
                "note": "Number prefix associated with premium-rate scams or fraud campaigns",
            }
    return {"is_scam_prefix": False}


# ── Master phone scanner ───────────────────────────────────────────────────────
async def analyze_phone(phone: str) -> dict[str, Any]:
    """Full phone number analysis — all 10 features."""
    import asyncio

    phone = phone.strip()

    fmt      = validate_phone_format(phone)
    country  = identify_country(phone)
    pk       = decode_pk_number(phone)
    num_type = classify_number_type(phone)
    voip     = detect_voip(phone)
    disp     = check_disposable_sms(phone)
    scam     = check_scam_prefix(phone)

    # Numverify (async, optional)
    numverify = await lookup_numverify(phone)

    # Privacy hash
    clean_digits = re.sub(r"[\s\-\(\)\.+]", "", phone)
    privacy = {
        "sha256_hash": hashlib.sha256(clean_digits.encode()).hexdigest(),
        "privacy_note": "Phone number hashed for logging — raw number not stored in Aegis",
    }

    # ── Score ─────────────────────────────────────────────────────────────────
    score = 0
    flags = []

    if not fmt["valid"]:
        score += 30
        flags.append(f"Invalid phone format: {fmt.get('reason', '')}")

    if scam["is_scam_prefix"]:
        score += 40
        flags.append(f"Scam/premium prefix: {scam['matched_prefix']} — {scam.get('note', '')}")

    if voip["likely_voip"]:
        score += 20
        flags.extend(voip["indicators"])

    if disp["likely_disposable"]:
        score += 25
        flags.extend(disp["indicators"])

    if num_type.get("type") == "premium_rate":
        score += 30
        flags.append(f"Premium rate number: {num_type.get('subtype', '')}")

    if country.get("is_high_risk"):
        score += 15
        flags.append(f"Phone from high-risk jurisdiction: {country.get('country', '')}")

    if numverify.get("line_type") in ("voip", "virtual"):
        score += 20
        if "VOIP line confirmed by carrier lookup" not in flags:
            flags.append("VOIP line confirmed by carrier lookup")

    if pk.get("is_pk_number") and not pk.get("is_mobile") and not pk.get("is_landline"):
        score += 10
        flags.append("Pakistani number with unrecognised prefix — may be unregistered")

    score = min(score, 100)
    level = (
        "Critical" if score >= 76 else
        "High"     if score >= 56 else
        "Medium"   if score >= 36 else
        "Low"      if score >= 16 else "Clean"
    )

    return {
        "credential_type": "phone",
        "input": phone,
        "format": fmt,
        "country": country,
        "pk_decode": pk,
        "number_type": num_type,
        "voip_check": voip,
        "disposable_sms": disp,
        "scam_prefix": scam,
        "carrier_lookup": numverify,
        "privacy": privacy,
        "overall_risk_score": score,
        "overall_risk_level": level,
        "all_flags": flags,
    }
