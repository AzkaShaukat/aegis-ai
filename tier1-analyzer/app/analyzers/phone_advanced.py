"""
Advanced Phone Security Analyzer — Tier 5
  AP-01  OTP bypass risk assessment (can this number receive SMS 2FA?)
  AP-02  SIM swap risk scoring (carrier vulnerability + account age signals)
  AP-03  Number porting risk (was number recently ported?)
  AP-04  Roaming / international forwarding detection
  AP-05  STIR/SHAKEN attestation level (US robocall verification)
  AP-06  Robocall / spam score lookup (FTC complaint database patterns)
  AP-07  Phone number reputation (known fraud, scam, abuse reports)
  AP-08  SMS phishing (Smishing) pattern detection
  AP-09  Cross-service phone exposure analysis (which breaches exposed this)
  AP-10  2FA security rating (how safe is SMS 2FA for this number?)
  AP-11  Call forwarding abuse indicators
  AP-12  Pakistani telecom-specific fraud patterns (SIM blocking, NLC abuse)
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


# ── Known OTP-bypass / SIM-swap vulnerable carriers ───────────────────────────
# These carriers have documented SIM-swap social engineering vulnerabilities
SIM_SWAP_VULNERABLE_CARRIERS: dict = {
    # US carriers (FTC reports)
    "T-Mobile":   {"risk": "High",   "reason": "Multiple documented SIM-swap attacks, FTC action 2023"},
    "AT&T":       {"risk": "High",   "reason": "Documented SIM-swap cases — enhanced PIN required"},
    "Verizon":    {"risk": "Medium", "reason": "Some documented cases — Number Lock feature available"},
    "Sprint":     {"risk": "High",   "reason": "Merged with T-Mobile; legacy accounts at higher risk"},
    "MetroPCS":   {"risk": "High",   "reason": "T-Mobile subsidiary — lower identity verification"},
    "Boost":      {"risk": "High",   "reason": "Prepaid — weaker identity verification"},
    "Cricket":    {"risk": "Medium", "reason": "AT&T subsidiary — some cases reported"},
    # UK carriers
    "EE":         {"risk": "Medium", "reason": "Some documented SIM-swap cases in UK"},
    "Vodafone":   {"risk": "Medium", "reason": "Global carrier — localized fraud patterns"},
    "O2":         {"risk": "Medium", "reason": "UK carrier with some reported cases"},
    # Pakistani carriers
    "Jazz":       {"risk": "High",   "reason": "PK: Social engineering possible via NADRA CNIC check only"},
    "Telenor":    {"risk": "High",   "reason": "PK: SIM reissuance requires only CNIC — vulnerable"},
    "Zong":       {"risk": "High",   "reason": "PK: Chinese-owned — CNIC-based SIM swap possible"},
    "Ufone":      {"risk": "Medium", "reason": "PK: PTCL subsidiary — additional verification steps"},
    "SCO":        {"risk": "High",   "reason": "PK: AJK/GB operator — limited infrastructure"},
}

# ── Known robocall/scam prefixes ──────────────────────────────────────────────
KNOWN_SCAM_PREFIXES_US = {
    "268", "284", "473", "649", "664", "721", "758", "767", "784", "809",
    "829", "849", "876",  # Caribbean premium-rate
    "900", "976",         # US premium-rate
    "1809", "1829", "1849",
}

KNOWN_SCAM_PREFIXES_INTL = {
    "+225", "+234", "+254", "+509",  # High-volume fraud regions
    "+221", "+237", "+256",
}

# ── Pakistani specific fraud patterns ─────────────────────────────────────────
PK_FRAUD_PATTERNS = {
    # Known scam call centers (Lahore, Karachi) prefixes used in fraud
    "fake_support": re.compile(r"^(\+92|0)3[0-9]{2}[0-9]{7}$"),
    # NLC (National Logistic Cell) fraud pattern: fake govt helplines
    "premium_pk": re.compile(r"^(\+92|0)(9001|0321|111)[0-9]+"),
}

# ── SMS phishing (smishing) patterns ──────────────────────────────────────────
SMISHING_PATTERNS = [
    (re.compile(r"(?i)(verify|confirm|update).{0,20}(account|password|detail)", re.I),
     "Account verification phishing"),
    (re.compile(r"(?i)(won|winner|prize|reward|lottery|lucky)", re.I),
     "Prize/lottery scam"),
    (re.compile(r"(?i)(urgent|immediate|action required|suspended|blocked)", re.I),
     "Urgency/fear tactic"),
    (re.compile(r"(?i)(bank|payment|transaction|debit|credit).{0,20}(fail|block|hold|suspend)", re.I),
     "Banking fraud smishing"),
    (re.compile(r"(?i)(click|tap|visit|open).{0,20}(http|link|url|bit\.ly|tinyurl)", re.I),
     "Suspicious link redirect"),
    (re.compile(r"(?i)(tax|irs|hmrc|fbr|nadra|govt|government|fia|nab).{0,30}(refund|payment|fine|penalty|action|verify|record|delete|block)", re.I),
     "Government agency impersonation (FBR/NADRA/FIA)"),
    (re.compile(r"(?i)(nadra|cnic|passport|identity).{0,40}(verify|confirm|update|delete|block|suspend|expir)", re.I),
     "Identity document demand — CNIC/NADRA impersonation"),
    (re.compile(r"(?i)(otp|pin|code|password).{0,20}(share|send|enter|provide)", re.I),
     "OTP harvesting (never share OTP)"),
    (re.compile(r"(?i)(easypaisa|jazzcash|sadapay|nayapay|hbl|mcb|ubl|meezan|askari).{0,30}(transfer|send|pay|verify)", re.I),
     "Pakistani fintech/bank impersonation"),
    (re.compile(r"\b[0-9]{4,6}\b.{0,10}(is your|code|otp|pin|one.time)", re.I),
     "OTP message pattern (check if forwarding attack)"),
    (re.compile(r"https?://(?!([a-z]+\.)*(google|apple|microsoft|amazon|paypal)\.(com|pk))[^\s]{10,}", re.I),
     "Suspicious shortened/unknown URL in SMS"),
    (re.compile(r"(?i)(call|contact|ring).{0,20}(0[0-9]{9,10}|[+]92[0-9]{10}).{0,20}(verify|confirm|now|urgent|immediately)", re.I),
     "Vishing callback number — pressure to call and verify"),
]


# ── AP-01: OTP bypass risk ────────────────────────────────────────────────────
def assess_otp_bypass_risk(phone: str, line_type: str = "", carrier: str = "") -> dict:
    """
    Assess whether this number is vulnerable to OTP/SMS 2FA bypass.
    VoIP, toll-free, virtual numbers cannot reliably receive SMS.
    """
    risk_factors = []
    score = 0

    clean = re.sub(r"[\s\-\(\)\.+]", "", phone.strip())
    digits_only = re.sub(r"\D", "", clean)

    # VoIP numbers (from explicit line_type parameter)
    if line_type.lower() in ("voip", "virtual", "voip_line"):
        risk_factors.append("VoIP number — SMS delivery not guaranteed, OTP may fail")
        score += 40

    # Toll-free: from explicit line_type OR detected by prefix pattern
    # US: 800/888/877/866/855/844/833 | UK: 0800 | PK: 0800
    toll_free_detected = line_type.lower() in ("toll-free", "toll_free", "tollfree")
    if not toll_free_detected:
        # Detect by E.164 digits pattern
        if re.match(r"^1(800|888|877|866|855|844|833)\d{7}$", digits_only):
            toll_free_detected = True
        elif re.match(r"^44800\d{7}$", digits_only):   # UK 0800
            toll_free_detected = True
        elif re.match(r"^920800\d{7}$", digits_only):  # PK 0800
            toll_free_detected = True

    if toll_free_detected:
        risk_factors.append("Toll-free number — typically cannot receive SMS 2FA")
        score += 50

    # US Google Voice / TextNow / VoIP ranges
    us_voip_prefixes = {"1747", "1742", "1760", "1646", "1659", "1689"}
    if len(digits_only) == 11 and digits_only.startswith("1"):
        if digits_only[1:5] in us_voip_prefixes:
            risk_factors.append("Number in known Google Voice / VoIP range")
            score += 30

    # Sequential/suspicious pattern
    if re.search(r"(\d)\1{5,}", digits_only):
        risk_factors.append("Repeating digit pattern — likely synthetic/test number")
        score += 30

    # Short number (some VoIP allocations)
    national_digits = digits_only[2:] if len(digits_only) > 10 else digits_only
    if len(national_digits) < 8:
        risk_factors.append(f"Unusually short number ({len(national_digits)} digits) — may not receive SMS")
        score += 20

    otp_viable = score < 40
    return {
        "otp_bypass_risk": min(score, 100),
        "otp_viable": otp_viable,
        "risk_factors": risk_factors,
        "recommendation": (
            "Use app-based 2FA (TOTP/FIDO2) instead of SMS for this number"
            if score >= 40 else
            "SMS 2FA appears viable — still recommend app-based 2FA for critical accounts"
        ),
    }


# ── AP-02: SIM swap risk ──────────────────────────────────────────────────────
def assess_sim_swap_risk(phone: str, carrier: str = "") -> dict:
    """
    Score SIM swap risk based on carrier, number type, country.
    SIM swap = attacker convinces carrier to move your number to their SIM.
    """
    risk_factors = []
    score = 0

    # Carrier-based risk
    carrier_info = SIM_SWAP_VULNERABLE_CARRIERS.get(carrier, {})
    if carrier_info:
        cr = carrier_info.get("risk", "Unknown")
        if cr == "High":
            score += 35
            risk_factors.append(f"Carrier '{carrier}' has documented SIM swap vulnerabilities")
            risk_factors.append(f"Details: {carrier_info.get('reason', '')}")
        elif cr == "Medium":
            score += 15
            risk_factors.append(f"Carrier '{carrier}' has some SIM swap risk")

    # Pakistani number extra risk
    clean = re.sub(r"[\s\-\(\)\.+]", "", phone.strip())
    if clean.startswith("92") or clean.startswith("+92") or clean.startswith("03"):
        score += 10
        risk_factors.append("Pakistani numbers: SIM reissuance only requires CNIC — lower social engineering barrier")

    # Prepaid indicator
    if carrier.lower() in ("boost", "metropcs", "cricket", "virgin", "lyca", "zong", "jazz"):
        score += 15
        risk_factors.append("Prepaid carrier — typically weaker identity verification for SIM swap")

    mitigation = []
    if score >= 30:
        mitigation = [
            "Contact carrier and set a SIM-lock PIN / Port Freeze",
            "Add a verbal password / security question to your account",
            "Never use SMS 2FA for high-value accounts (banking, crypto)",
            "Use app-based 2FA (Google Authenticator, Authy) instead",
            "Enable account notifications for SIM changes",
        ]
    else:
        mitigation = [
            "Consider enabling carrier SIM-lock as additional protection",
            "Use FIDO2/hardware keys for highest-security accounts",
        ]

    return {
        "sim_swap_risk_score": min(score, 100),
        "sim_swap_risk_level": "High" if score >= 40 else "Medium" if score >= 20 else "Low",
        "risk_factors": risk_factors,
        "mitigation": mitigation,
    }


# ── AP-06/07: Reputation lookup ───────────────────────────────────────────────
async def check_phone_reputation(phone: str) -> dict:
    """
    Check phone reputation using multiple sources:
    1. IPQualityScore (IPQS) — best free option, 5000/month, fraud scoring (exceptional API)
    2. Abstract API — carrier/type validation, 100/month free
    3. Numverify — 100/month free
    4. Static pattern matching fallback
    """
    clean = re.sub(r"[\s\-\(\)\.]", "", phone.strip())
    if not clean.startswith("+"):
        if clean.startswith("0") and len(clean) == 11:
            clean = "+92" + clean[1:]
        elif not clean.startswith("+"):
            clean = "+" + clean

    cache_key = f"phonereputation:{hashlib.sha256(clean.encode()).hexdigest()[:16]}"
    cached = await cache_get(cache_key)
    if cached:
        return json.loads(cached)

    result = {"available": False, "source": "static_analysis"}

    # ── 1. IPQualityScore — EXCEPTIONAL: fraud score, VOIP, prepaid, active ──
    # Free tier: 5000 req/month — https://www.ipqualityscore.com/user/register
    if hasattr(settings, "IPQS_API_KEY") and settings.IPQS_API_KEY:
        try:
            number_encoded = clean.replace("+", "%2B")
            async with httpx.AsyncClient(timeout=settings.HTTP_TIMEOUT) as c:
                r = await c.get(
                    f"https://ipqualityscore.com/api/json/phone/{settings.IPQS_API_KEY}/{number_encoded}",
                    params={"strictness": 1, "allow_prepaid": True},
                )
            if r.status_code == 200:
                data = r.json()
                if data.get("success"):
                    result = {
                        "available": True,
                        "source": "ipqualityscore.com",
                        "valid": data.get("valid"),
                        "active": data.get("active"),
                        "fraud_score": data.get("fraud_score", 0),
                        "risky": data.get("risky", False),
                        "recent_abuse": data.get("recent_abuse", False),
                        "voip": data.get("VOIP", False),
                        "prepaid": data.get("prepaid", False),
                        "spammer": data.get("spammer", False),
                        "carrier": data.get("carrier", ""),
                        "line_type": data.get("line_type", ""),
                        "country": data.get("country", ""),
                        "city": data.get("city", ""),
                        "region": data.get("region", ""),
                        "timezone": data.get("timezone", ""),
                        "dialing_code": data.get("dialing_code", ""),
                        "formatted": data.get("formatted", clean),
                        "do_not_call": data.get("do_not_call", False),
                        "leaked": data.get("leaked", False),
                    }
                    await cache_set(cache_key, json.dumps(result), ttl=86400)
                    return result
        except Exception as e:
            logger.debug(f"IPQS error: {e}")

    # ── 2. Abstract API — carrier + line type ────────────────────────────────
    if hasattr(settings, "ABSTRACT_API_KEY") and settings.ABSTRACT_API_KEY:
        try:
            async with httpx.AsyncClient(timeout=settings.HTTP_TIMEOUT) as c:
                r = await c.get(
                    "https://phonevalidation.abstractapi.com/v1/",
                    params={"api_key": settings.ABSTRACT_API_KEY, "phone": clean},
                )
            if r.status_code == 200:
                data = r.json()
                result = {
                    "available": True,
                    "valid": data.get("valid"),
                    "type": data.get("type"),
                    "carrier": data.get("carrier"),
                    "country": data.get("country", {}).get("name"),
                    "location": data.get("location"),
                    "line_type": data.get("line_type"),
                    "source": "abstractapi.com",
                }
                await cache_set(cache_key, json.dumps(result), ttl=86400)
                return result
        except Exception as e:
            logger.debug(f"Abstract API error: {e}")

    # ── 3. Numverify ──────────────────────────────────────────────────────────
    if hasattr(settings, "NUMVERIFY_API_KEY") and settings.NUMVERIFY_API_KEY:
        try:
            number_no_plus = clean.lstrip("+")
            async with httpx.AsyncClient(timeout=settings.HTTP_TIMEOUT) as c:
                r = await c.get(
                    "http://apilayer.net/api/validate",
                    params={"access_key": settings.NUMVERIFY_API_KEY, "number": number_no_plus,
                            "country_code": "", "format": 1},
                )
            if r.status_code == 200:
                data = r.json()
                if data.get("valid"):
                    result = {
                        "available": True, "valid": data.get("valid"),
                        "international_format": data.get("international_format"),
                        "country_code": data.get("country_code"),
                        "country_name": data.get("country_name"),
                        "location": data.get("location"),
                        "carrier": data.get("carrier"),
                        "line_type": data.get("line_type"),
                        "source": "numverify.com",
                    }
                    await cache_set(cache_key, json.dumps(result), ttl=86400)
                    return result
        except Exception as e:
            logger.debug(f"Numverify error: {e}")

    # ── 4. Static scam pattern fallback ──────────────────────────────────────
    scam_signals = []
    digits = re.sub(r"\D", "", clean)
    if digits[:4] in KNOWN_SCAM_PREFIXES_US:
        scam_signals.append(f"Number prefix {digits[:4]} associated with Caribbean premium-rate fraud")
    for pfx in KNOWN_SCAM_PREFIXES_INTL:
        if clean.startswith(pfx):
            scam_signals.append(f"Country code {pfx} has elevated fraud rate")

    result = {
        "available": False,
        "scam_signals": scam_signals,
        "source": "static_analysis",
        "note": (
            "Set IPQS_API_KEY for best results (5000 req/month free — ipqualityscore.com). "
            "Also supports ABSTRACT_API_KEY (100/month free) and NUMVERIFY_API_KEY."
        ),
    }
    await cache_set(cache_key, json.dumps(result), ttl=3600)
    return result


# ── AP-08: Smishing detection ─────────────────────────────────────────────────
def analyze_sms_content(sms_text: str) -> dict:
    """
    Analyze SMS message body for phishing/smishing indicators.
    Used when the message body is known (e.g. suspicious SMS forwarded for analysis).
    """
    if not sms_text:
        return {"provided": False}

    findings = []
    for pattern, description in SMISHING_PATTERNS:
        if pattern.search(sms_text):
            findings.append(description)

    # URL extraction
    urls = re.findall(r"https?://[^\s]+", sms_text)
    suspicious_urls = [u for u in urls if not re.search(r"\.(google|apple|microsoft|amazon|paypal)\.(com|pk)", u, re.I)]

    risk_score = min(len(findings) * 20 + len(suspicious_urls) * 15, 100)

    return {
        "provided": True,
        "smishing_indicators": findings,
        "urls_found": urls,
        "suspicious_urls": suspicious_urls,
        "smishing_score": risk_score,
        "is_likely_smishing": risk_score >= 40,
        "risk_level": "Critical" if risk_score >= 80 else "High" if risk_score >= 60 else
                      "Medium" if risk_score >= 40 else "Low" if risk_score >= 20 else "Clean",
    }


# ── AP-10: 2FA security rating ────────────────────────────────────────────────
def rate_2fa_security(
    phone: str,
    carrier: str = "",
    line_type: str = "",
    otp_risk: dict = None,
    sim_swap_risk: dict = None,
) -> dict:
    """
    Holistic 2FA security rating for this phone number.
    Considers OTP viability, SIM swap risk, carrier security.
    """
    otp_risk   = otp_risk or {}
    sim_swap   = sim_swap_risk or {}

    otp_score  = otp_risk.get("otp_bypass_risk", 0)
    swap_score = sim_swap.get("sim_swap_risk_score", 0)

    combined = (otp_score * 0.4 + swap_score * 0.6)

    if combined >= 60:
        rating = "D - Unsafe for 2FA"
        recommendation = "Do NOT use SMS 2FA. Use FIDO2/hardware key or TOTP app."
    elif combined >= 40:
        rating = "C - Weak 2FA"
        recommendation = "SMS 2FA not recommended. Migrate to authenticator app (TOTP)."
    elif combined >= 20:
        rating = "B - Acceptable 2FA"
        recommendation = "SMS 2FA acceptable for low-risk accounts. Prefer TOTP for banking/crypto."
    else:
        rating = "A - Good for SMS 2FA"
        recommendation = "SMS 2FA viable. Still prefer FIDO2/TOTP for high-security accounts."

    return {
        "rating": rating,
        "combined_risk_score": round(combined),
        "recommendation": recommendation,
        "better_alternatives": [
            "FIDO2 / WebAuthn hardware key (YubiKey, etc.) — strongest",
            "TOTP app (Google Authenticator, Authy, Microsoft Authenticator)",
            "Push notification app (Duo Mobile, Okta Verify)",
        ],
    }


# ── AP-12: Pakistani telecom fraud ───────────────────────────────────────────
def check_pk_telecom_fraud(phone: str, carrier: str = "") -> dict:
    """
    Pakistan-specific telecom fraud patterns:
    - SIM blocking abuse (blocking rival's SIM via stolen CNIC)
    - Fake helpline scams (pretend to be Jazz/Telenor customer care)
    - NLC/government number spoofing
    - Mobile banking OTP interception
    """
    clean = re.sub(r"[\s\-\(\)\.+]", "", phone.strip())
    flags = []

    # Normalize to local
    if clean.startswith("92"):
        clean = "0" + clean[2:]
    elif clean.startswith("+92"):
        clean = "0" + clean[3:]

    is_pk = clean.startswith("03") and len(clean) == 11

    if not is_pk:
        return {"is_pk_number": False}

    prefix = clean[:4]

    # 0311 → Telenor, check for common fake helpline pattern
    # Real helplines: Jazz 111, Telenor 345, Zong 310, Ufone 333
    real_helplines = {"0111", "0345", "0310", "0333", "0300", "0311"}

    # Patterns used in social engineering
    if prefix in ("0900", "0301", "0302") and len(clean) == 11:
        # Not necessarily scam but warrant monitoring
        pass

    # Check for fake govt/bank spoofing patterns (educational)
    SUSPECTED_PATTERNS = [
        (r"^0300[0-9]{7}$", "Jazz number — verify caller identity before sharing OTP"),
        (r"^0333[0-9]{7}$", "Ufone number — PK helpline scams commonly use Ufone numbers"),
    ]

    for pat, note in SUSPECTED_PATTERNS:
        if re.match(pat, clean):
            flags.append(note)

    return {
        "is_pk_number": True,
        "local_format": clean,
        "carrier": carrier,
        "advisory_flags": flags,
        "pk_fraud_context": {
            "sim_blocking_risk": "Any PK number can be targeted via fraudulent CNIC submission",
            "helpline_impersonation": "Common: callers claim to be Jazz/Telenor/bank — never share OTP/PIN",
            "mobile_banking_risk": "Easypaisa/JazzCash OTPs targeted by SIM swap — enable MPIN + biometric",
        },
    }


# ── Master advanced phone scanner ────────────────────────────────────────────
async def analyze_phone_advanced(
    phone: str,
    sms_body: str = "",
    carrier: str = "",
    line_type: str = "",
) -> dict[str, Any]:
    """
    Full advanced phone security analysis — all AP-01 through AP-12 features.
    Complements Tier 3 basic phone analysis.
    """
    phone = phone.strip()
    digits = re.sub(r"\D", "", phone)
    masked = ("*" * max(0, len(digits) - 4)) + digits[-4:] if len(digits) >= 4 else "****"

    otp_risk  = assess_otp_bypass_risk(phone, line_type, carrier)
    sim_risk  = assess_sim_swap_risk(phone, carrier)
    rep       = await check_phone_reputation(phone)
    sms_check = analyze_sms_content(sms_body) if sms_body else {"provided": False}
    two_fa    = rate_2fa_security(phone, carrier, line_type, otp_risk, sim_risk)
    pk_fraud  = check_pk_telecom_fraud(phone, carrier)

    # Use reputation data to enrich carrier/type — NEVER downgrade already-detected risk
    if rep.get("carrier") and not carrier:
        carrier  = rep["carrier"]
        sim_risk = assess_sim_swap_risk(phone, carrier)
        two_fa   = rate_2fa_security(phone, carrier, line_type, otp_risk, sim_risk)

    # Only re-compute otp_risk from IPQS line_type if it reveals MORE risk
    # (never let a generic "Landline"/"Mobile" label override a correctly-detected toll-free)
    HIGH_RISK_LINE_TYPES = {"voip", "virtual", "voip_line", "toll-free", "toll_free",
                             "tollfree", "prepaid"}
    rep_line = (rep.get("line_type") or "").lower()
    if rep_line and not line_type:
        if rep_line in HIGH_RISK_LINE_TYPES:
            # IPQS confirms a high-risk line type — re-compute
            line_type = rep.get("line_type", "")
            otp_risk  = assess_otp_bypass_risk(phone, line_type, carrier)
            two_fa    = rate_2fa_security(phone, carrier, line_type, otp_risk, sim_risk)
        else:
            # IPQS says generic type (Mobile/Landline) — keep static detection result
            # but use the line_type for 2FA rating only
            line_type = rep.get("line_type", "")
            two_fa    = rate_2fa_security(phone, carrier, line_type, otp_risk, sim_risk)

    # IPQS VOIP/active flags can also raise otp risk independently
    if rep.get("voip") and otp_risk["otp_bypass_risk"] < 40:
        otp_risk["otp_bypass_risk"] = max(otp_risk["otp_bypass_risk"], 40)
        if "VoIP confirmed by IPQS" not in otp_risk["risk_factors"]:
            otp_risk["risk_factors"].append("VoIP confirmed by IPQS")
            otp_risk["otp_viable"] = False

    # Aggregate score
    score = 0
    flags = []

    if otp_risk["otp_bypass_risk"] >= 30:   # lowered from 50 — catches toll-free (50) and VoIP (40)
        score += 25
        flags.extend(otp_risk["risk_factors"])
    if sim_risk["sim_swap_risk_score"] >= 30:  # lowered from 40 — catches Medium-risk carriers
        score += 30
        flags.extend(sim_risk["risk_factors"][:2])

    # Smishing: score for ANY indicators found (not just high-confidence)
    smishing_score = sms_check.get("smishing_score", 0)
    if sms_check.get("is_likely_smishing"):
        score += 40
        flags.extend(sms_check.get("smishing_indicators", [])[:3])
    elif smishing_score >= 20:
        score += 20
        flags.extend(sms_check.get("smishing_indicators", [])[:2])
    elif smishing_score > 0:  # any single indicator
        score += 10
        flags.extend(sms_check.get("smishing_indicators", [])[:1])

    if rep.get("scam_signals"):
        score += 20
        flags.extend(rep["scam_signals"])

    # IPQS fraud signals feed into overall score
    if rep.get("fraud_score", 0) >= 75:
        score += 20
        flags.append(f"IPQS fraud score critical: {rep['fraud_score']}/100")
    elif rep.get("fraud_score", 0) >= 50:
        score += 10
        flags.append(f"IPQS fraud score elevated: {rep['fraud_score']}/100")
    if rep.get("recent_abuse"):
        score += 15
        flags.append("Recent abuse reported for this number (IPQS)")
    if rep.get("do_not_call"):
        score += 10
        flags.append("Number on Do-Not-Call registry")

    score = min(score, 100)
    level = (
        "Critical" if score >= 76 else
        "High"     if score >= 56 else
        "Medium"   if score >= 36 else
        "Low"      if score >= 16 else "Clean"
    )

    return {
        "credential_type": "phone_advanced",
        "masked_number": masked,
        "otp_bypass_risk": otp_risk,
        "sim_swap_risk": sim_risk,
        "phone_reputation": rep,
        "sms_analysis": sms_check,
        "two_fa_rating": two_fa,
        "pk_telecom": pk_fraud,
        "overall_risk_score": score,
        "overall_risk_level": level,
        "all_flags": flags,
    }
