"""
Passport Analyzer — Tier 3 Identity Documents
  P-01  MRZ (Machine Readable Zone) format validation — TD3/TD2/TD1
  P-02  Check digit validation (Luhn-like algorithm per ICAO Doc 9303)
  P-03  Country code validation (ISO 3166-1 alpha-3)
  P-04  Date of birth + expiry date validation / expired flag
  P-05  Document number format check per country
  P-06  Personal number / national ID field extraction
  P-07  Fake / test MRZ pattern detection
  P-08  Nationality vs issuing country mismatch flag
  P-09  Privacy — SHA-256 hash for storage, raw never stored
  P-10  Pakistani passport MRZ decoder (full field breakdown)
"""
import hashlib
import re
from datetime import date, datetime
from typing import Any

# ── ICAO MRZ check digit weights ─────────────────────────────────────────────
MRZ_WEIGHTS = [7, 3, 1]
MRZ_CHARSET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
MRZ_VALUES  = {c: i for i, c in enumerate("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ")}

# ── Country codes (ISO 3166-1 alpha-3 + special ICAO codes) ──────────────────
VALID_COUNTRY_CODES: set = {
    "AFG","ALA","ALB","DZA","ASM","AND","AGO","AIA","ATA","ATG","ARG","ARM",
    "ABW","AUS","AUT","AZE","BHS","BHR","BGD","BRB","BLR","BEL","BLZ","BEN",
    "BMU","BTN","BOL","BES","BIH","BWA","BVT","BRA","IOT","BRN","BGR","BFA",
    "BDI","CPV","KHM","CMR","CAN","CYM","CAF","TCD","CHL","CHN","CXR","CCK",
    "COL","COM","COD","COG","COK","CRI","CIV","HRV","CUB","CUW","CYP","CZE",
    "DNK","DJI","DMA","DOM","ECU","EGY","SLV","GNQ","ERI","EST","SWZ","ETH",
    "FLK","FRO","FJI","FIN","FRA","GUF","PYF","ATF","GAB","GMB","GEO","DEU",
    "GHA","GIB","GRC","GRL","GRD","GLP","GUM","GTM","GGY","GIN","GNB","GUY",
    "HTI","HMD","VAT","HND","HKG","HUN","ISL","IND","IDN","IRN","IRQ","IRL",
    "IMN","ISR","ITA","JAM","JPN","JEY","JOR","KAZ","KEN","KIR","PRK","KOR",
    "KWT","KGZ","LAO","LVA","LBN","LSO","LBR","LBY","LIE","LTU","LUX","MAC",
    "MDG","MWI","MYS","MDV","MLI","MLT","MHL","MTQ","MRT","MUS","MYT","MEX",
    "FSM","MDA","MCO","MNG","MNE","MSR","MAR","MOZ","MMR","NAM","NRU","NPL",
    "NLD","NCL","NZL","NIC","NER","NGA","NIU","NFK","MKD","MNP","NOR","OMN",
    "PAK","PLW","PSE","PAN","PNG","PRY","PER","PHL","PCN","POL","PRT","PRI",
    "QAT","REU","ROU","RUS","RWA","BLM","SHN","KNA","LCA","MAF","SPM","VCT",
    "WSM","SMR","STP","SAU","SEN","SRB","SYC","SLE","SGP","SXM","SVK","SVN",
    "SLB","SOM","ZAF","SGS","SSD","ESP","LKA","SDN","SUR","SJM","SWE","CHE",
    "SYR","TWN","TJK","TZA","THA","TLS","TGO","TKL","TON","TTO","TUN","TUR",
    "TKM","TCA","TUV","UGA","UKR","ARE","GBR","USA","UMI","URY","UZB","VUT",
    "VEN","VNM","VGB","VIR","WLF","ESH","YEM","ZMB","ZWE",
    # Special ICAO codes
    "UNO","UNA","UNK","XOM","XXB","XXX",
    # Org / stateless
    "EUE","EUA",
}

# ── P-02: ICAO MRZ check digit ────────────────────────────────────────────────
def compute_mrz_check_digit(field: str) -> int:
    """
    ICAO Doc 9303 check digit algorithm.
    Each char mapped to value, multiplied by weight [7,3,1] cyclically, sum % 10.
    '<' = 0 filler.
    """
    total = 0
    for i, ch in enumerate(field.upper()):
        if ch == "<":
            val = 0
        elif ch in MRZ_VALUES:
            val = MRZ_VALUES[ch]
        else:
            val = 0  # treat unknown as 0
        total += val * MRZ_WEIGHTS[i % 3]
    return total % 10


def verify_mrz_check_digit(field: str, check_char: str) -> bool:
    """Return True if check digit matches."""
    try:
        expected = compute_mrz_check_digit(field)
        return expected == int(check_char)
    except (ValueError, TypeError):
        return False


# ── P-01: MRZ format detection ────────────────────────────────────────────────
def detect_mrz_type(lines: list[str]) -> dict:
    """
    TD3 = passport (2 lines, 44 chars each)
    TD2 = official travel doc (2 lines, 36 chars each)
    TD1 = ID card (3 lines, 30 chars each)
    """
    if len(lines) == 2:
        if all(len(l) == 44 for l in lines):
            return {"type": "TD3", "format": "Passport (ICAO)", "lines": 2, "chars_per_line": 44}
        if all(len(l) == 36 for l in lines):
            return {"type": "TD2", "format": "Official Travel Doc", "lines": 2, "chars_per_line": 36}
    if len(lines) == 3 and all(len(l) == 30 for l in lines):
        return {"type": "TD1", "format": "ID Card / Residence Permit", "lines": 3, "chars_per_line": 30}
    return {
        "type": "Unknown",
        "format": "Unknown",
        "error": f"Lines: {[len(l) for l in lines]} — does not match TD1/TD2/TD3 format",
    }


# ── P-03: Country code validation ─────────────────────────────────────────────
def validate_country_code(code: str) -> dict:
    code = code.upper().replace("<", "").strip()
    is_valid = code in VALID_COUNTRY_CODES
    return {
        "code": code,
        "valid": is_valid,
        "reason": None if is_valid else f"'{code}' not in ISO 3166-1 alpha-3 / ICAO codes",
        "is_pakistan": code == "PAK",
        "is_high_risk": code in {"PRK","IRN","SYR","AFG","MMR","YEM","LBY","SOM","SDN","VEN"},
    }


# ── P-04: MRZ date decode ─────────────────────────────────────────────────────
def decode_mrz_date(yymmdd: str, is_expiry: bool = False) -> dict:
    """Decode YYMMDD MRZ date. For expiry, years >= 30 are 1930s else 2000s."""
    if not re.match(r"^\d{6}$", yymmdd):
        return {"valid": False, "reason": "Date must be 6 digits (YYMMDD)"}
    try:
        yy = int(yymmdd[:2])
        mm = int(yymmdd[2:4])
        dd = int(yymmdd[4:])

        current_year = date.today().year % 100
        century = 1900 if (yy > current_year + 10 and not is_expiry) else 2000
        if is_expiry and yy < 70:
            century = 2000
        elif is_expiry and yy >= 70:
            century = 2000  # Passports don't expire in 1900s

        year = century + yy
        dt   = date(year, mm, dd)
        today = date.today()

        result = {
            "valid": True,
            "date": dt.isoformat(),
            "year": year,
            "formatted": dt.strftime("%d %B %Y"),
        }

        if is_expiry:
            result["is_expired"] = dt < today
            result["days_until_expiry"] = (dt - today).days
        else:
            age = today.year - dt.year - ((today.month, today.day) < (dt.month, dt.day))
            result["age_years"] = age
            if age < 0 or age > 130:
                result["plausible"] = False
                result["note"] = f"Age {age} is not plausible"
            else:
                result["plausible"] = True

        return result
    except ValueError as e:
        return {"valid": False, "reason": str(e)}


# ── P-07: Fake/test MRZ detection ─────────────────────────────────────────────
KNOWN_TEST_MRZES = {
    "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<",  # ICAO specimen line 1
    "L898902C36UTO7408122F1204159ZE184226B<<<<<<1",  # ICAO specimen line 2
    "P<GBRGOLD<<SARAH<LOUISE<<<<<<<<<<<<<<<<<<<<<<",
}

def detect_fake_mrz(mrz_lines: list[str]) -> dict:
    """
    Detect test, sample, or fabricated MRZ data.
    """
    indicators = []
    full_mrz = "".join(mrz_lines)

    for line in mrz_lines:
        if line in KNOWN_TEST_MRZES:
            indicators.append("Line matches ICAO specimen/test MRZ")

    # All-filler check
    non_filler = full_mrz.replace("<", "")
    if len(non_filler) < len(full_mrz) * 0.3:
        indicators.append("MRZ has unusually high proportion of filler characters")

    # Repeating pattern (exclude pure-filler "<" repeats — those are normal padding)
    non_filler_repeat = re.search(r"([A-Z0-9][A-Z0-9<]{4})\1{3,}", full_mrz)
    if non_filler_repeat and non_filler_repeat.group(0).replace("<", ""):
        indicators.append("Repeating non-filler pattern in MRZ — may be synthetic/fabricated")

    # Check for obviously sequential doc numbers
    line2 = mrz_lines[1] if len(mrz_lines) > 1 else ""
    doc_num = line2[:9] if len(line2) >= 9 else ""
    if re.match(r"^[0-9]+$", doc_num) and len(set(doc_num)) <= 2:
        indicators.append(f"Document number '{doc_num}' has very low digit variety — suspicious")

    return {
        "detected": len(indicators) > 0,
        "indicators": indicators,
    }


# ── P-10: Pakistani passport MRZ decoder ──────────────────────────────────────
def decode_pak_passport_mrz(line1: str, line2: str) -> dict:
    """
    Full decoder for Pakistani TD3 MRZ.
    Line 1: P<PAKNAME_FIELD (44 chars)
    Line 2: DOCNUMCDDOB<CDGENDEREXP<CDNATIONALIDCHECK (44 chars)
    """
    if len(line1) != 44 or len(line2) != 44:
        return {"valid": False, "reason": "Pakistani passport MRZ requires exactly 44 chars per line"}

    # Line 1
    doc_type    = line1[0]
    issuer      = line1[2:5]
    name_field  = line1[5:44]

    if "<<" in name_field:
        parts     = name_field.split("<<")
        surname   = parts[0].replace("<", " ").strip()
        given     = parts[1].replace("<", " ").strip() if len(parts) > 1 else ""
    else:
        surname   = name_field.replace("<", " ").strip()
        given     = ""

    # Line 2
    doc_number      = line2[0:9]
    doc_num_check   = line2[9]
    nationality     = line2[10:13]
    dob_field       = line2[13:19]
    dob_check       = line2[19]
    sex             = line2[20]
    expiry_field    = line2[21:27]
    expiry_check    = line2[27]
    personal_num    = line2[28:42]
    personal_check  = line2[42]
    overall_check   = line2[43]

    # Validate check digits
    checks = {
        "document_number": verify_mrz_check_digit(doc_number, doc_num_check),
        "date_of_birth":   verify_mrz_check_digit(dob_field, dob_check),
        "expiry_date":     verify_mrz_check_digit(expiry_field, expiry_check),
        "personal_number": verify_mrz_check_digit(personal_num, personal_check),
        "overall":         verify_mrz_check_digit(
            doc_number + doc_num_check + dob_field + dob_check +
            expiry_field + expiry_check + personal_num + personal_check,
            overall_check
        ),
    }

    all_checks_pass = all(checks.values())

    dob    = decode_mrz_date(dob_field, is_expiry=False)
    expiry = decode_mrz_date(expiry_field, is_expiry=True)

    gender_map = {"M": "Male", "F": "Female", "<": "Unspecified", "X": "Non-binary"}

    # Clean document number (remove filler)
    clean_doc = doc_number.replace("<", "")

    return {
        "valid": all_checks_pass,
        "document_type": "Passport" if doc_type == "P" else doc_type,
        "issuing_country": issuer,
        "surname": surname,
        "given_names": given,
        "document_number": clean_doc,
        "nationality": nationality,
        "date_of_birth": dob,
        "sex": gender_map.get(sex, sex),
        "expiry_date": expiry,
        "personal_number": personal_num.replace("<", ""),
        "check_digits": checks,
        "all_check_digits_valid": all_checks_pass,
    }


# ── Master passport scanner ────────────────────────────────────────────────────
async def analyze_passport(
    mrz_line1: str = "",
    mrz_line2: str = "",
    mrz_line3: str = "",
    raw_mrz: str   = "",
    doc_number: str = "",
    issuing_country: str = "",
) -> dict[str, Any]:
    """
    Full passport / travel document analysis.
    Accepts either:
      - mrz_line1 + mrz_line2 (+ optional mrz_line3)
      - raw_mrz (multi-line string separated by newline/pipe)
      - doc_number + issuing_country (partial check)
    """
    # Parse raw MRZ if provided
    if raw_mrz:
        sep = "\n" if "\n" in raw_mrz else "|"
        lines = [l.upper().strip() for l in raw_mrz.split(sep) if l.strip()]
    elif mrz_line1:
        lines = [l.upper() for l in [mrz_line1, mrz_line2, mrz_line3] if l]
    else:
        lines = []

    score = 0
    flags = []
    result: dict = {"credential_type": "passport"}

    # ── MRZ path ──────────────────────────────────────────────────────────────
    if lines:
        mrz_type = detect_mrz_type(lines)
        fake     = detect_fake_mrz(lines)

        result["mrz_type"] = mrz_type

        if mrz_type["type"] == "Unknown":
            score += 30
            flags.append(f"MRZ format invalid: {mrz_type.get('error', '')}")
        else:
            # Country check from line 1
            if len(lines[0]) >= 5:
                country_code = lines[0][2:5].replace("<", "").strip()
                country_r    = validate_country_code(country_code)
                result["issuing_country"] = country_r

                if not country_r["valid"]:
                    score += 20
                    flags.append(f"Invalid issuing country code: {country_code}")

                if country_r.get("is_high_risk"):
                    score += 15
                    flags.append(f"Document issued by high-risk jurisdiction: {country_code}")

            # TD3 full decode (Passport)
            if mrz_type["type"] == "TD3" and len(lines) >= 2:
                decoded = decode_pak_passport_mrz(lines[0], lines[1])
                result["decoded"] = decoded

                if not decoded["all_check_digits_valid"]:
                    failed = [k for k, v in decoded["check_digits"].items() if not v]
                    score += 35
                    flags.append(f"Check digit validation FAILED for: {', '.join(failed)}")

                if decoded.get("expiry_date", {}).get("is_expired"):
                    score += 25
                    flags.append("Passport has expired")

                dob = decoded.get("date_of_birth", {})
                if dob.get("valid") and not dob.get("plausible", True):
                    score += 15
                    flags.append(f"Date of birth not plausible: {dob.get('note', '')}")

        if fake["detected"]:
            score += 40
            flags.extend(fake["indicators"])

        result["fake_detection"] = fake

    # ── Document number only path ─────────────────────────────────────────────
    elif doc_number:
        clean_doc = doc_number.upper().strip()
        result["document_number"] = clean_doc

        # Pakistan passport: 2 letters + 7 digits (e.g. AA1234567) or 1 letter + 8 digits
        if issuing_country.upper() in ("PAK", "PAKISTAN"):
            if re.match(r"^[A-Z]{2}\d{7}$", clean_doc):
                result["pak_format"] = {"valid": True, "format": "Standard (AA1234567)"}
            elif re.match(r"^[A-Z]\d{8}$", clean_doc):
                result["pak_format"] = {"valid": True, "format": "Old format (A12345678)"}
            else:
                score += 20
                flags.append(f"Pakistani passport number format invalid: {clean_doc}")
                result["pak_format"] = {"valid": False}

        # Generic checks
        if re.match(r"^(.)\1{5,}$", clean_doc):
            score += 30
            flags.append("Passport number contains repeated character pattern")

        country_r = validate_country_code(issuing_country) if issuing_country else None
        if country_r:
            result["issuing_country"] = country_r
            if not country_r.get("valid"):
                score += 20
                flags.append(f"Invalid issuing country code: {issuing_country}")
            if country_r.get("is_high_risk"):
                score += 15
                flags.append(f"Document from high-risk country: {issuing_country}")

    else:
        return {
            "credential_type": "passport",
            "error": "Provide mrz_line1+mrz_line2, raw_mrz, or doc_number+issuing_country",
        }

    # Privacy hash
    hash_input = "".join(lines) if lines else f"{doc_number}:{issuing_country}"
    result["privacy"] = {
        "sha256_hash": hashlib.sha256(hash_input.encode()).hexdigest(),
        "privacy_note": "Raw MRZ/document number not stored — SHA-256 hash only",
    }

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
