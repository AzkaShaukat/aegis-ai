"""
IBAN / Bank Account Analyzer — Tier 2 Financial
  I-01  IBAN format validation (structure + length per country)
  I-02  MOD-97 checksum (ISO 7064)
  I-03  Country code identification (77 countries)
  I-04  BBAN decode (bank + branch + account number)
  I-05  Pakistani IBAN full decode (bank name, city hint)
  I-06  SWIFT/BIC format validation
  I-07  Suspicious patterns (all same digits, zeros, sequential)
  I-08  OFAC-like high-risk country flag
"""
import re
from typing import Any

# ── Country IBAN length table (ISO 13616) ─────────────────────────────────────
IBAN_LENGTHS: dict = {
    "AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16,
    "BG": 22, "BH": 22, "BR": 29, "BY": 28, "CH": 21, "CR": 22, "CY": 28,
    "CZ": 24, "DE": 22, "DJ": 27, "DK": 18, "DO": 28, "DZ": 26, "EE": 20,
    "EG": 29, "ES": 24, "FI": 18, "FK": 18, "FO": 18, "FR": 27, "GB": 22,
    "GE": 22, "GI": 23, "GL": 18, "GR": 27, "GT": 28, "HR": 21, "HU": 28,
    "IE": 22, "IL": 23, "IQ": 23, "IS": 26, "IT": 27, "JO": 30, "KW": 30,
    "KZ": 20, "LB": 28, "LC": 32, "LI": 21, "LT": 20, "LU": 20, "LV": 21,
    "LY": 25, "MC": 27, "MD": 24, "ME": 22, "MK": 19, "MN": 20, "MR": 27,
    "MT": 31, "MU": 30, "NI": 28, "NL": 18, "NO": 15, "OM": 23, "PK": 24,
    "PL": 28, "PS": 29, "PT": 25, "QA": 29, "RO": 24, "RS": 22, "RU": 33,
    "SA": 24, "SC": 31, "SD": 18, "SE": 24, "SI": 19, "SK": 24, "SM": 27,
    "SO": 23, "ST": 25, "SV": 28, "TL": 23, "TN": 24, "TR": 26, "UA": 29,
    "VA": 22, "VG": 24, "XK": 20,
}

# ── Pakistani bank codes (4-char BIC prefix in IBAN BBAN) ────────────────────
PK_BANKS: dict = {
    "HABB": "Habib Bank Limited (HBL)",
    "MUCB": "MCB Bank Limited",
    "UNIL": "United Bank Limited (UBL)",
    "NBPA": "National Bank of Pakistan (NBP)",
    "ALFH": "Bank Alfalah",
    "MEBL": "Meezan Bank",
    "JSBL": "JS Bank",
    "FASB": "Faysal Bank",
    "BAHL": "Bank AL Habib",
    "ASKH": "Askari Bank",
    "SILK": "Silk Bank",
    "SABB": "Samba Bank",
    "ALBB": "Al Baraka Bank Pakistan",
    "BISL": "BankIslami Pakistan",
    "FYST": "First Women Bank",
    "SMBL": "Summit Bank",
    "SNBL": "Soneri Bank",
    "ZSBL": "Zarai Taraqiati Bank",
    "PMCB": "Punjab & Sind Bank",
    "BKIP": "Bank of Khyber",
    "SCBL": "Standard Chartered Pakistan",
    "CITI": "Citibank Pakistan",
    "DUIB": "Dubai Islamic Bank Pakistan",
    "HMBL": "Habib Metropolitan Bank",
    "AINS": "Al Ain Finance",
    "OPAB": "OPIC Pakistan",
    "EMPK": "Emirates NBD Pakistan",
    "INIB": "Industrial & Commercial Bank of China Pakistan",
    "BOCB": "Bank of China Pakistan",
    "KBPK": "KBL Pakistan",
}

# ── High-risk jurisdictions (FATF grey/black list indicators) ─────────────────
HIGH_RISK_COUNTRIES: set = {
    "AF", "MM", "KP", "IR", "SY", "YE", "LY", "SO", "SS", "CF",
    "CD", "CU", "VE", "ET", "KH", "NG", "PH", "PG", "TZ", "VU",
}


# ── I-01: IBAN format check ───────────────────────────────────────────────────
def validate_iban_format(iban: str) -> dict:
    """
    Basic format check: country code, check digits, correct length.
    """
    clean = re.sub(r"[\s\-]", "", iban).upper()

    if len(clean) < 5:
        return {"valid": False, "reason": "Too short to be an IBAN"}

    country = clean[:2]
    check_digits = clean[2:4]
    bban = clean[4:]

    if not country.isalpha():
        return {"valid": False, "reason": "First 2 chars must be country code (letters)"}
    if not check_digits.isdigit():
        return {"valid": False, "reason": "Positions 3–4 must be numeric check digits"}

    expected_len = IBAN_LENGTHS.get(country)
    if expected_len is None:
        return {"valid": False, "reason": f"Country code '{country}' not in IBAN standard",
                "country": country, "known": False}
    if len(clean) != expected_len:
        return {"valid": False,
                "reason": f"Wrong length for {country}: expected {expected_len}, got {len(clean)}",
                "country": country, "expected_length": expected_len}

    return {
        "valid": True,
        "country": country,
        "check_digits": check_digits,
        "bban": bban,
        "length": len(clean),
        "cleaned": clean,
    }


# ── I-02: MOD-97 checksum ─────────────────────────────────────────────────────
def verify_mod97(iban: str) -> dict:
    """
    ISO 7064 MOD-97 checksum.
    Rearrange: BBAN + country + check digits.
    Replace letters with numbers (A=10, B=11 … Z=35).
    Result MOD 97 must equal 1.
    """
    clean = re.sub(r"[\s\-]", "", iban).upper()
    if len(clean) < 5:
        return {"valid": False, "reason": "Too short"}

    # Rearrange: move first 4 chars to end
    rearranged = clean[4:] + clean[:4]

    # Convert letters to digits
    numeric = ""
    for ch in rearranged:
        if ch.isalpha():
            numeric += str(ord(ch) - 55)  # A=10, B=11 …
        else:
            numeric += ch

    try:
        remainder = int(numeric) % 97
        valid = remainder == 1
        return {
            "valid": valid,
            "remainder": remainder,
            "reason": None if valid else f"MOD-97 check failed (remainder={remainder}, expected 1)",
        }
    except ValueError as e:
        return {"valid": False, "reason": f"Numeric conversion failed: {e}"}


# ── I-05: Pakistani IBAN decode ───────────────────────────────────────────────
def decode_pk_iban(iban: str) -> dict:
    """
    Pakistani IBAN format: PK[2 check][4 bank code][16 account number]
    Total 24 characters.
    """
    clean = re.sub(r"[\s\-]", "", iban).upper()
    if not clean.startswith("PK") or len(clean) != 24:
        return {"is_pk_iban": False}

    bank_code = clean[4:8]   # 4 alpha chars
    account   = clean[8:]    # 16 digit account number

    bank_name = PK_BANKS.get(bank_code, f"Unknown bank code: {bank_code}")

    return {
        "is_pk_iban": True,
        "bank_code": bank_code,
        "bank_name": bank_name,
        "account_number": account,
        "bank_known": bank_code in PK_BANKS,
    }


# ── I-06: SWIFT/BIC validation ────────────────────────────────────────────────
def validate_swift(bic: str) -> dict:
    """
    SWIFT BIC format: 4 (bank) + 2 (country) + 2 (location) + optional 3 (branch)
    Total 8 or 11 chars. All alphanumeric.
    """
    clean = re.sub(r"[\s\-]", "", bic).upper()
    if len(clean) not in (8, 11):
        return {"valid": False, "reason": f"BIC must be 8 or 11 chars, got {len(clean)}"}
    if not re.match(r"^[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}([A-Z0-9]{3})?$", clean):
        return {"valid": False, "reason": "Does not match BIC pattern"}

    bank_code    = clean[:4]
    country_code = clean[4:6]
    location     = clean[6:8]
    branch       = clean[8:] if len(clean) == 11 else "XXX"

    return {
        "valid": True,
        "bank_code": bank_code,
        "country_code": country_code,
        "location": location,
        "branch": branch,
        "is_primary": branch == "XXX",
    }


# ── I-07: Suspicious patterns ─────────────────────────────────────────────────
def detect_suspicious_iban(iban: str) -> dict:
    """Detect patterns that suggest test/fabricated IBANs."""
    clean = re.sub(r"[\s\-]", "", iban).upper()
    bban = clean[4:] if len(clean) > 4 else clean
    bban_digits = re.sub(r"[A-Z]", "", bban)

    flags = []

    # All same digit
    if bban_digits and len(set(bban_digits)) == 1:
        flags.append(f"BBAN contains all identical digits ({bban_digits[0]})")

    # Mostly zeros
    if bban_digits and bban_digits.count("0") / len(bban_digits) > 0.6:
        flags.append("BBAN is mostly zeros — possibly a test/placeholder IBAN")

    # Sequential digits
    sequential = False
    if len(bban_digits) >= 6:
        asc = all(int(bban_digits[i+1]) == int(bban_digits[i]) + 1
                  for i in range(min(5, len(bban_digits) - 1)))
        desc = all(int(bban_digits[i+1]) == int(bban_digits[i]) - 1
                   for i in range(min(5, len(bban_digits) - 1)))
        if asc or desc:
            flags.append("Sequential digit pattern in account number")
            sequential = True

    # Check if account digits are all same in PK IBAN
    if clean.startswith("PK") and len(clean) == 24:
        account = clean[8:]
        if len(set(account)) <= 2:
            flags.append("Pakistani account number has very low digit variety")

    return {
        "detected": len(flags) > 0,
        "flags": flags,
    }


# ── I-08: High-risk country check ─────────────────────────────────────────────
def check_iban_country_risk(country: str) -> dict:
    is_high_risk = country.upper() in HIGH_RISK_COUNTRIES
    return {
        "country": country.upper(),
        "is_high_risk": is_high_risk,
        "risk_reason": "FATF grey/black list jurisdiction" if is_high_risk else None,
    }


# ── Master IBAN scanner ────────────────────────────────────────────────────────
async def analyze_iban(iban: str, swift: str = "") -> dict[str, Any]:
    """Full IBAN + optional SWIFT/BIC analysis."""
    iban = iban.strip()

    fmt    = validate_iban_format(iban)
    mod97  = verify_mod97(iban) if fmt["valid"] else {"valid": False, "reason": "Format invalid"}
    pk     = decode_pk_iban(iban)
    susp   = detect_suspicious_iban(iban)
    country_risk = check_iban_country_risk(fmt.get("country", "")) if fmt.get("country") else {}
    swift_r = validate_swift(swift) if swift else {"provided": False}

    # ── Score ─────────────────────────────────────────────────────────────────
    score = 0
    flags = []

    if not fmt["valid"]:
        score += 50
        flags.append(f"Invalid IBAN format: {fmt.get('reason', '')}")
    elif not mod97["valid"]:
        score += 40
        flags.append(f"MOD-97 checksum FAILED: {mod97.get('reason', '')}")

    if susp["detected"]:
        score += 20
        flags.extend(susp["flags"])

    if country_risk.get("is_high_risk"):
        score += 25
        flags.append(f"IBAN from high-risk jurisdiction ({country_risk.get('country')}): {country_risk.get('risk_reason')}")

    if swift_r.get("provided") is not False and not swift_r.get("valid"):
        score += 15
        flags.append(f"Invalid SWIFT/BIC: {swift_r.get('reason', '')}")

    if pk.get("is_pk_iban") and not pk.get("bank_known"):
        score += 10
        flags.append(f"Pakistani IBAN with unrecognised bank code: {pk.get('bank_code')}")

    score = min(score, 100)
    level = (
        "Critical" if score >= 76 else
        "High"     if score >= 56 else
        "Medium"   if score >= 36 else
        "Low"      if score >= 16 else "Clean"
    )

    return {
        "credential_type": "iban",
        "input": iban.upper().replace(" ", ""),
        "format": fmt,
        "mod97_checksum": mod97,
        "pk_iban": pk,
        "suspicious_patterns": susp,
        "country_risk": country_risk,
        "swift": swift_r,
        "overall_risk_score": score,
        "overall_risk_level": level,
        "all_flags": flags,
    }
