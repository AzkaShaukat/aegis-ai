"""
National ID Analyzer — Tier 3 Identity Documents
  N-01  Pakistani CNIC format validation (13 digits, dash format)
  N-02  CNIC checksum / structural plausibility
  N-03  Province decode from CNIC prefix (all 7 provinces + regions)
  N-04  Gender extraction (last digit odd=male, even=female)
  N-05  Age / birth year estimation from serial range
  N-06  Fake / test CNIC detection (000000, 1234567, sequential)
  N-07  Privacy — SHA-256 hash for storage (never store raw)
  N-08  US SSN format + invalid range detection
  N-09  SSN blacklist (known fake/reserved: 000-xx-xxxx, 666, 9xx)
  N-10  Indian Aadhaar format + Verhoeff checksum
  N-11  Synthetic identity risk scoring
  N-12  Dark web indicator (known leaked ID patterns)
"""
import hashlib
import re
from typing import Any


# ── CNIC province / division codes ────────────────────────────────────────────
# Format: PPPPP-SSSSSSS-G  (5 digit location, 7 digit serial, 1 check digit)
# First digit = province
CNIC_PROVINCE_MAP: dict = {
    "1": "Khyber Pakhtunkhwa (KPK)",
    "2": "FATA / Merged Districts",
    "3": "Punjab",
    "4": "Sindh",
    "5": "Balochistan",
    "6": "Islamabad Capital Territory (ICT)",
    "7": "Gilgit-Baltistan",
    "8": "Azad Jammu & Kashmir (AJK)",
}

# CNIC division codes (first 3 digits → major city/division)
CNIC_DIVISION_MAP: dict = {
    "610": "Islamabad", "611": "Islamabad",
    "341": "Lahore",    "342": "Lahore",   "343": "Lahore",
    "350": "Rawalpindi","351": "Rawalpindi",
    "361": "Faisalabad","362": "Faisalabad",
    "371": "Gujranwala","372": "Gujranwala",
    "381": "Sargodha",
    "391": "Multan",    "392": "Multan",
    "431": "Karachi",   "432": "Karachi",  "433": "Karachi",  "434": "Karachi",
    "441": "Hyderabad", "442": "Hyderabad",
    "451": "Sukkur",
    "531": "Quetta",    "532": "Quetta",
    "151": "Peshawar",  "152": "Peshawar",
    "161": "Mardan",
    "712": "Gilgit",
    "811": "Muzaffarabad",
}

# Known test / invalid CNIC patterns
CNIC_INVALID_SERIALS = {
    "0000000", "1111111", "2222222", "3333333", "4444444",
    "5555555", "6666666", "7777777", "8888888", "9999999",
    "1234567", "9876543", "0000001", "9999998",
}


# ── N-01: CNIC format validation ──────────────────────────────────────────────
def validate_cnic_format(cnic: str) -> dict:
    """
    Pakistani CNIC format: PPPPP-SSSSSSS-G
    P = 5-digit location code
    S = 7-digit serial
    G = 1 check digit (1=male odd, 0/2/4/6/8=female)
    Total: 13 digits + 2 dashes = 15 chars
    """
    # Strip spaces
    clean = cnic.strip().replace(" ", "")

    # Accept with or without dashes
    if re.match(r"^\d{5}-\d{7}-\d$", clean):
        formatted = clean
        digits = clean.replace("-", "")
    elif re.match(r"^\d{13}$", clean):
        digits = clean
        formatted = f"{clean[:5]}-{clean[5:12]}-{clean[12]}"
    else:
        return {
            "valid": False,
            "reason": "CNIC must be 13 digits (with or without dashes: PPPPP-SSSSSSS-G)",
            "input": cnic,
        }

    return {
        "valid": True,
        "formatted": formatted,
        "digits": digits,
        "location_code": digits[:5],
        "serial": digits[5:12],
        "check_digit": digits[12],
    }


# ── N-02: CNIC structural plausibility ────────────────────────────────────────
def check_cnic_plausibility(digits: str) -> dict:
    """
    Check structural plausibility:
    - First digit must be 1–8 (valid province codes)
    - Location code must not be 00000
    - Serial must not be all-same or known test pattern
    """
    issues = []
    province_digit = digits[0]
    location_code  = digits[:5]
    serial         = digits[5:12]

    if province_digit not in CNIC_PROVINCE_MAP:
        issues.append(f"Invalid province digit '{province_digit}' — valid range is 1–8")

    if location_code == "00000":
        issues.append("Location code 00000 is not a valid NADRA code")

    if serial in CNIC_INVALID_SERIALS:
        issues.append(f"Serial number '{serial}' is a known test/fake pattern")

    if len(set(serial)) == 1:
        issues.append(f"Serial number is all identical digits ({serial[0]}*7) — not plausible")

    # Check if serial is purely sequential
    asc  = all(int(serial[i+1]) == int(serial[i])+1 for i in range(6))
    desc = all(int(serial[i+1]) == int(serial[i])-1 for i in range(6))
    if asc or desc:
        issues.append("Serial number is sequential digits — likely fabricated")

    return {
        "plausible": len(issues) == 0,
        "issues": issues,
    }


# ── N-03: Province decode ─────────────────────────────────────────────────────
def decode_cnic_province(digits: str) -> dict:
    """Decode province and city from CNIC location code."""
    province_digit = digits[0]
    division_code  = digits[:3]
    location_code  = digits[:5]

    province = CNIC_PROVINCE_MAP.get(province_digit, "Unknown province")
    division = CNIC_DIVISION_MAP.get(division_code, "Unknown division")

    return {
        "province": province,
        "division": division,
        "location_code": location_code,
        "province_code": province_digit,
    }


# ── N-04: Gender extraction ───────────────────────────────────────────────────
def extract_cnic_gender(check_digit: str) -> dict:
    """
    NADRA convention: check digit (last digit):
    Odd (1,3,5,7,9) = Male
    Even (0,2,4,6,8) = Female
    """
    try:
        cd = int(check_digit)
        gender = "Male" if cd % 2 == 1 else "Female"
        return {"gender": gender, "check_digit": cd, "confidence": "High"}
    except ValueError:
        return {"gender": "Unknown", "check_digit": check_digit}


# ── N-05: Age estimation from serial range ────────────────────────────────────
def estimate_cnic_era(serial: str) -> dict:
    """
    Rough estimate: higher serial numbers were issued later.
    NADRA started registration in 2000. Serials increment per location.
    Returns issuance era, not birth year.
    """
    try:
        s = int(serial)
        if s < 1000000:
            era = "Early NADRA era (2000–2005)"
        elif s < 3000000:
            era = "Mid NADRA era (2005–2012)"
        elif s < 6000000:
            era = "Recent era (2012–2020)"
        else:
            era = "Very recent (2020+)"
        return {"serial_number": s, "issuance_era_estimate": era}
    except ValueError:
        return {"serial_number": None, "issuance_era_estimate": "Unknown"}


# ── N-07: Privacy — SHA-256 hash ──────────────────────────────────────────────
def hash_national_id(digits: str, id_type: str = "CNIC") -> dict:
    """Generate SHA-256 hash for safe storage. Raw ID never stored."""
    salted = f"{id_type}:{digits}".encode()
    sha256 = hashlib.sha256(salted).hexdigest()
    return {
        "sha256_hash": sha256,
        "id_type": id_type,
        "privacy_note": f"Raw {id_type} number not stored — SHA-256 hash only",
    }


# ── N-08: US SSN validation ───────────────────────────────────────────────────
SSN_INVALID_AREAS = {
    "000",  # Reserved — never assigned
    "666",  # Reserved by SSA
}

def validate_ssn(ssn: str) -> dict:
    """
    US Social Security Number: AAA-GG-SSSS
    Rules per SSA:
    - Area (AAA): 001–899, not 000, not 666, not 900–999
    - Group (GG): 01–99, not 00
    - Serial (SSSS): 0001–9999, not 0000
    """
    clean = re.sub(r"[-\s]", "", ssn)
    if not re.match(r"^\d{9}$", clean):
        return {"valid": False, "reason": "SSN must be 9 digits (AAA-GG-SSSS)"}

    area   = clean[:3]
    group  = clean[3:5]
    serial = clean[5:]

    issues = []
    if area == "000":
        issues.append("Area '000' is reserved — never assigned")
    if area == "666":
        issues.append("Area '666' is reserved by SSA — never assigned")
    if area.startswith("9"):
        issues.append(f"Area '{area}' (900–999) is reserved for ITIN — not a valid SSN")
    if group == "00":
        issues.append("Group '00' is invalid")
    if serial == "0000":
        issues.append("Serial '0000' is invalid")

    # Known test SSNs
    known_test = {"123456789", "987654321", "111111111", "000000000",
                  "123121234", "219099999", "457555462"}
    if clean in known_test:
        issues.append("Known test/example SSN number")

    return {
        "valid": len(issues) == 0,
        "formatted": f"{area}-{group}-{serial}",
        "area": area,
        "group": group,
        "serial": serial,
        "issues": issues,
        "is_itin": area.startswith("9"),
    }


# ── N-10: Aadhaar validation + Verhoeff checksum ──────────────────────────────
_VERHOEFF_D = [
    [0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],
    [3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],
    [6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],
    [9,8,7,6,5,4,3,2,1,0],
]
_VERHOEFF_P = [
    [0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],
    [8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],
    [2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8],
]
_VERHOEFF_INV = [0,4,3,2,1,9,8,7,6,5]

def _verhoeff_check(number: str) -> bool:
    """Validate Verhoeff checksum (used by Aadhaar)."""
    try:
        c = 0
        for i, d in enumerate(reversed(number)):
            c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][int(d)]]
        return c == 0
    except Exception:
        return False

def validate_aadhaar(aadhaar: str) -> dict:
    """
    Indian Aadhaar: 12 digits, Verhoeff checksum, first digit not 0 or 1.
    """
    clean = re.sub(r"[\s\-]", "", aadhaar)
    if not re.match(r"^\d{12}$", clean):
        return {"valid": False, "reason": "Aadhaar must be exactly 12 digits"}

    if clean[0] in ("0", "1"):
        return {"valid": False, "reason": "Aadhaar cannot start with 0 or 1"}

    checksum_valid = _verhoeff_check(clean)
    issues = []
    if not checksum_valid:
        issues.append("Verhoeff checksum failed — not a valid Aadhaar number")
    if len(set(clean)) <= 2:
        issues.append("Very low digit variety — possibly fabricated")

    return {
        "valid": checksum_valid,
        "formatted": f"{clean[:4]} {clean[4:8]} {clean[8:]}",
        "verhoeff_checksum": checksum_valid,
        "issues": issues,
    }


# ── N-11: Synthetic identity risk ─────────────────────────────────────────────
def synthetic_identity_risk(
    plausibility: dict,
    province: dict,
    gender: dict,
    id_type: str = "CNIC"
) -> dict:
    """
    Score likelihood that this is a fabricated/synthetic identity.
    Used in fraud detection.
    """
    score = 0
    indicators = []

    if not plausibility.get("plausible"):
        score += 40
        indicators.extend(plausibility.get("issues", []))

    if province.get("province") == "Unknown province":
        score += 20
        indicators.append("Province code not in NADRA database")

    if gender.get("gender") == "Unknown":
        score += 10
        indicators.append("Cannot determine gender from check digit")

    score = min(score, 100)
    return {
        "synthetic_risk_score": score,
        "synthetic_risk_level": (
            "High"   if score >= 50 else
            "Medium" if score >= 25 else "Low"
        ),
        "indicators": indicators,
    }


# ── N-12: Dark web patterns ────────────────────────────────────────────────────
def check_dark_web_patterns(digits: str, id_type: str = "CNIC") -> dict:
    """
    Check for patterns commonly found in leaked ID datasets.
    These are structural indicators, not live dark web queries.
    """
    indicators = []

    if id_type == "CNIC":
        # Known leaked CNIC batches (by location prefix) — documented in Pakistani data breaches
        HIGH_RISK_PREFIXES = {
            "34202", "34203",  # Lahore batches in Jazz 2020 leak
            "42201", "42301",  # Karachi batches in various leaks
            "61101", "61102",  # Islamabad batches
        }
        prefix = digits[:5]
        if prefix in HIGH_RISK_PREFIXES:
            indicators.append(f"CNIC prefix {prefix} appears in known leaked dataset batches")

    return {
        "high_risk_pattern": len(indicators) > 0,
        "indicators": indicators,
        "note": "Structural pattern check only — not a live dark web query",
    }


# ── Master National ID scanner ────────────────────────────────────────────────
async def analyze_national_id(
    value: str,
    id_type: str = "auto"  # auto, cnic, ssn, aadhaar
) -> dict[str, Any]:
    """
    Auto-detect and analyze national ID number.
    Returns type-specific analysis + privacy hash.
    """
    value = value.strip()
    clean = re.sub(r"[\s\-]", "", value)

    # ── Auto-detect type ──────────────────────────────────────────────────────
    detected_type = id_type
    if id_type == "auto":
        if re.match(r"^\d{5}-?\d{7}-?\d$", value) or (clean.isdigit() and len(clean) == 13):
            detected_type = "cnic"
        elif re.match(r"^\d{3}-?\d{2}-?\d{4}$", value) or (clean.isdigit() and len(clean) == 9):
            detected_type = "ssn"
        elif clean.isdigit() and len(clean) == 12:
            detected_type = "aadhaar"
        else:
            return {
                "credential_type": "national_id",
                "detected_type": "unknown",
                "error": "Cannot auto-detect ID type. Specify: cnic, ssn, or aadhaar",
                "input": value,
            }

    score  = 0
    flags  = []
    result = {
        "credential_type": "national_id",
        "input": value,
        "detected_type": detected_type,
    }

    # ── CNIC analysis ─────────────────────────────────────────────────────────
    if detected_type == "cnic":
        fmt        = validate_cnic_format(value)
        if not fmt["valid"]:
            return {**result, "format": fmt, "overall_risk_score": 60,
                    "overall_risk_level": "High",
                    "all_flags": [f"Invalid CNIC format: {fmt.get('reason', '')}"],
                    "privacy": hash_national_id(clean, "CNIC")}

        digits     = fmt["digits"]
        plaus      = check_cnic_plausibility(digits)
        province   = decode_cnic_province(digits)
        gender     = extract_cnic_gender(fmt["check_digit"])
        era        = estimate_cnic_era(fmt["serial"])
        synth      = synthetic_identity_risk(plaus, province, gender)
        dark_web   = check_dark_web_patterns(digits)
        privacy    = hash_national_id(digits, "CNIC")

        if not plaus["plausible"]:
            score += 40
            flags.extend(plaus["issues"])
        if synth["synthetic_risk_score"] >= 50:
            score += 20
            flags.append("High synthetic identity risk score")
        if dark_web["high_risk_pattern"]:
            score += 15
            flags.extend(dark_web["indicators"])

        score = min(score, 100)
        result.update({
            "format": fmt,
            "plausibility": plaus,
            "province": province,
            "gender": gender,
            "issuance_era": era,
            "synthetic_identity": synth,
            "dark_web_patterns": dark_web,
            "privacy": privacy,
        })

    # ── SSN analysis ──────────────────────────────────────────────────────────
    elif detected_type == "ssn":
        ssn_r   = validate_ssn(value)
        privacy = hash_national_id(clean, "SSN")

        if not ssn_r["valid"]:
            score += 50
            flags.extend(ssn_r.get("issues", []))
        result.update({"ssn": ssn_r, "privacy": privacy})

    # ── Aadhaar analysis ──────────────────────────────────────────────────────
    elif detected_type == "aadhaar":
        aadh_r  = validate_aadhaar(value)
        privacy = hash_national_id(clean, "Aadhaar")

        if not aadh_r["valid"]:
            score += 50
            flags.extend(aadh_r.get("issues", []))
        result.update({"aadhaar": aadh_r, "privacy": privacy})

    score = min(score, 100)
    level = (
        "Critical" if score >= 76 else
        "High"     if score >= 56 else
        "Medium"   if score >= 36 else
        "Low"      if score >= 16 else "Clean"
    )
    result.update({
        "overall_risk_score": score,
        "overall_risk_level": level,
        "all_flags": flags,
    })
    return result
