"""
logic.py — v3
=============

B13 FIX (MEDIUM): WiFi is_likely_evil_twin: false for FreeHotelWifi
  ROOT CAUSE: logic.py v2 with substring matching was never delivered to user.
  Old version used exact-match: 'hotel' != 'FreeHotelWifi' → not detected.
  This v3 version is the FIRST delivery of substring-matching evil twin logic.

B14 FIX (MEDIUM): DNS false flags subdomains for no MX/NS records
  ROOT CAUSE: DNS analyzer checked for MX/NS records on subdomains like
  maps.google.com and q.me-qr.com. Subdomains SHOULD NOT have their own
  MX or NS records — those belong to the apex domain (google.com, me-qr.com).
  Flagging subdomains for this is a false positive.
  FIX: offline_url_check() now skips MX/NS flags when hostname is a subdomain
  (3+ dot-separated parts). DNS penalty reduced for subdomains.

Other improvements in v3:
  - WiFi password analysis: add common password list expansion
  - Evil twin: add more honeypot patterns (Free*, Guest*, Temp*)
  - offline_url_check: differentiate apex vs subdomain DNS flags
"""

import re
import httpx
import os
from app.type_parser import identify_and_parse
from app.smishing_detector import detect_smishing
from app.ai import analyze_intent
from app.logger import log

NUM_VERIFY_KEY  = os.getenv("NUM_VERIFY_KEY", "")
EMAIL_REP_KEY   = os.getenv("EMAIL_REP_KEY", "")


# ─────────────────────────────────────────────────────────────
# WiFi Analyzer v3
# ─────────────────────────────────────────────────────────────

# Common spoofed SSID keywords — SUBSTRING matching (B13 FIX delivered)
EVIL_TWIN_KEYWORDS = [
    # Generic traps
    "free wifi", "freewifi", "free_wifi", "free-wifi",
    "public wifi", "publicwifi", "public_wifi",
    "open wifi", "openwifi", "open_wifi",
    "guest wifi", "guestwifi", "guest_wifi",
    "temp wifi", "tempwifi",
    # Hospitality
    "hotel", "motel", "hostel", "inn ", " inn",
    "airbnb", "resort", "lodg",
    # Food & Retail
    "starbucks", "mcdonalds", "mcdonald",
    "subway", "costa", "dunkin", "domino",
    "tesco", "walmart", "target", "ikea",
    "restaurant", "cafe", "coffee shop", "coffeeshop",
    # Transport
    "airport", "train wifi", "trainwifi", "rail wifi",
    "bus wifi", "coach wifi", "terminal",
    # Healthcare
    "hospital", "clinic", "pharmacy",
    # Public services
    "library", "council", "government", "police",
    # Finance
    "bank", "atm", "hsbc", "barclays", "lloyds", "natwest",
    "santander", "chase", "citibank", "wellsfargo",
    # ISP networks
    "xfinity", "btopen", "bt wifi", "btopenzone",
    "bt openzone", "virginmedia", "sky wifi",
    # Events
    "event wifi", "conference", "venue wifi",
    # Loyalty / marketing tricks
    "loyalty", "reward", "free internet",
]

# Common weak/default passwords
COMMON_PASSWORDS = [
    "password", "12345678", "qwerty", "qwerty123", "abc123",
    "admin", "admin123", "letmein", "welcome", "welcome1",
    "wifi1234", "internet", "connect", "wireless", "network",
    "test1234", "changeme", "pass1234", "iloveyou", "monkey",
    "1234", "12345", "1234567", "123456789", "0000000",
    "password1", "password123", "login", "access",
]


def _parse_wifi(raw: str) -> dict:
    """Parse WIFI:S:<ssid>;T:<type>;P:<password>;; string."""
    ssid     = re.search(r"S:([^;]*)", raw)
    security = re.search(r"T:([^;]*)", raw)
    password = re.search(r"P:([^;]*)", raw)
    hidden   = re.search(r"H:([^;]*)", raw)
    return {
        "ssid":     ssid.group(1).strip()     if ssid     else "",
        "security": security.group(1).strip() if security else "nopass",
        "password": password.group(1).strip() if password else "",
        "hidden":   hidden.group(1).lower() == "true" if hidden else False,
    }


def analyze_wifi(raw: str) -> dict:
    """
    Full WiFi security analysis.

    Checks:
    - WEP/WPA1 weak encryption (crackable in seconds/minutes)
    - Password exposed in QR code
    - Password strength and complexity
    - Evil twin detection via SUBSTRING keyword matching (B13 FIX)
    - Hidden network detection
    - Common/default password detection
    """
    parsed   = _parse_wifi(raw)
    ssid     = parsed["ssid"]
    security = parsed["security"].upper()
    password = parsed["password"]
    is_hidden = parsed["hidden"]

    risk_score = 0
    flags = []

    # ── Security protocol check ──────────────────────────────
    if security in ("WEP", "WEP40", "WEP104"):
        flags.append("⚠️ WEP ENCRYPTION: Crackable in under 60 seconds with Aircrack-ng. WPA2/WPA3 required.")
        risk_score += 60
    elif security in ("WPA", "WPA1"):
        flags.append("⚠️ WPA (v1): Vulnerable to dictionary attack. Upgrade to WPA2 or WPA3.")
        risk_score += 35
    elif security == "NOPASS":
        flags.append("🚨 OPEN NETWORK: No encryption — all traffic is interceptable")
        risk_score += 50
    elif security in ("WPA2", "WPA2-EAP"):
        # WPA2 is acceptable — minor note if using TKIP cipher
        pass
    elif security in ("WPA3", "SAE"):
        flags.append("✅ WPA3: Strongest available Wi-Fi security protocol")

    # ── Password analysis ────────────────────────────────────
    password_analysis = {}
    if password:
        length = len(password)
        has_upper   = any(c.isupper()  for c in password)
        has_lower   = any(c.islower()  for c in password)
        has_digits  = any(c.isdigit()  for c in password)
        has_special = any(not c.isalnum() for c in password)
        complexity  = sum([has_upper, has_lower, has_digits, has_special])
        is_common   = password.lower() in COMMON_PASSWORDS

        password_analysis = {
            "length":       length,
            "complexity_score": complexity,
            "has_uppercase": has_upper,
            "has_lowercase": has_lower,
            "has_digits":    has_digits,
            "has_special_chars": has_special,
            "is_common_password": is_common,
        }

        if is_common:
            flags.append(f"🚨 COMMON PASSWORD: '{password}' is a default/dictionary password")
            risk_score += 30
        elif length < 8:
            flags.append(f"🚨 SHORT PASSWORD: {length} chars — minimum 12 recommended")
            risk_score += 25
        elif length < 12:
            flags.append(f"ℹ️ MODERATE PASSWORD: {length} chars — 12+ recommended")
            risk_score += 10
        if complexity < 2 and not is_common:
            flags.append("⚠️ LOW COMPLEXITY: Password lacks uppercase, digits or special chars")
            risk_score += 15

    # ── B13 FIX: Evil twin via SUBSTRING matching ────────────
    ssid_lower = ssid.lower()
    matched_keywords = [
        kw for kw in EVIL_TWIN_KEYWORDS
        if kw.lower() in ssid_lower
    ]
    is_evil_twin = len(matched_keywords) > 0

    if is_evil_twin:
        flags.append(
            f"🚨 KNOWN SPOOFED SSID: '{ssid}' matches evil twin pattern(s): "
            + ", ".join(f'"{k}"' for k in matched_keywords[:3])
        )
        risk_score += 40

    if is_hidden:
        flags.append("ℹ️ HIDDEN NETWORK: SSID not broadcast — may be cloaking identity")
        risk_score += 10

    risk_score = min(risk_score, 100)

    if risk_score >= 80:   risk_level = "Critical"
    elif risk_score >= 60: risk_level = "High"
    elif risk_score >= 35: risk_level = "Medium"
    elif risk_score >= 15: risk_level = "Low"
    else:                  risk_level = "Safe"

    smishing = detect_smishing(ssid, "text")

    return {
        "type":                      "wifi_config",
        "ssid":                      ssid,
        "security_protocol":         security,
        "has_password":              bool(password),
        "password_exposed_in_qr":    bool(password),
        "is_hidden_network":         is_hidden,
        "is_likely_evil_twin":       is_evil_twin,
        "matched_evil_twin_keywords": matched_keywords,
        "password_analysis":         password_analysis,
        "risk_level":                risk_level,
        "risk_score":                risk_score,
        "flags":                     flags,
        "smishing_check":            smishing
    }


# ─────────────────────────────────────────────────────────────
# Offline URL check (no Link Analyzer)
# ─────────────────────────────────────────────────────────────

# Phishing-related keywords in URLs
PHISHING_URL_KEYWORDS = [
    "login", "signin", "sign-in", "account", "verify", "verify-now",
    "update", "confirm", "secure", "security", "alert",
    "billing", "payment", "pay-now", "checkout", "invoice",
    "suspended", "blocked", "urgent", "immediate",
    "recover", "unlock", "support", "helpdesk",
    "password", "credential", "authenticate",
    "apple-id", "paypal", "microsoft-", "google-security",
    "amazon-", "netflix-", "banking",
]

# Known URL shorteners
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly",
    "short.io", "rebrand.ly", "cutt.ly", "is.gd", "v.gd",
    "buff.ly", "tiny.cc", "clck.ru", "bc.vc", "adf.ly",
}

# Major trustworthy domains (safe regardless of flags)
TRUSTED_APEX_DOMAINS = {
    "google.com", "apple.com", "microsoft.com", "amazon.com",
    "facebook.com", "twitter.com", "instagram.com", "linkedin.com",
    "github.com", "wikipedia.org", "youtube.com", "reddit.com",
    "cloudflare.com", "netflix.com", "spotify.com",
}


def _extract_apex_domain(hostname: str) -> str:
    """Extract apex (root) domain from hostname. maps.google.com → google.com"""
    parts = hostname.lower().split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return hostname.lower()


def _is_subdomain(hostname: str) -> bool:
    """Returns True if hostname is a subdomain (has 3+ dot-separated parts)."""
    return hostname.count(".") >= 2


def offline_url_check(url: str) -> dict:
    """
    Quick local URL safety check — used when Link Analyzer is unavailable.

    B14 FIX: Subdomain handling
    Subdomains (maps.google.com, q.me-qr.com) should NOT be flagged for
    missing MX or NS records — these belong to the apex domain, not subdomains.
    Now only applies apex-domain-level DNS flags when NOT a subdomain.
    """
    flags = []
    heuristic_score = 0

    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        scheme   = parsed.scheme.lower()
        path     = parsed.path.lower()
        apex     = _extract_apex_domain(hostname)
        is_sub   = _is_subdomain(hostname)

        # Scheme checks
        if scheme == "http":
            flags.append("Non-HTTPS: traffic not encrypted")
            heuristic_score += 20

        # Shortener check (applies to apex, not subdomain)
        if apex in URL_SHORTENERS:
            flags.append(f"URL shortener ({apex}) — hides destination")
            heuristic_score += 35

        # Phishing keywords
        full_url_lower = url.lower()
        kw_found = [kw for kw in PHISHING_URL_KEYWORDS if kw in full_url_lower]
        if kw_found:
            flags.append(f"Phishing keywords: {', '.join(kw_found[:3])}")
            heuristic_score += min(len(kw_found) * 10, 30)

        # Suspicious TLD
        tld = hostname.split(".")[-1] if "." in hostname else ""
        if tld in ("ru", "cn", "tk", "pw", "xyz", "top", "club", "gq", "ga", "cf", "ml"):
            flags.append(f"High-risk TLD: .{tld}")
            heuristic_score += 15

        # Too many subdomains
        sub_count = hostname.count(".")
        if sub_count >= 3:
            flags.append(f"Many subdomains ({sub_count}) — domain spoofing pattern")
            heuristic_score += 15

        # IP address instead of domain
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", hostname):
            flags.append("IP address used instead of domain name")
            heuristic_score += 20

        # B14 FIX: Only flag missing DNS records for APEX domains
        # Subdomains (maps.google.com) legitimately have no MX or NS
        if not is_sub and apex not in TRUSTED_APEX_DOMAINS:
            flags.append("DNS record check recommended (offline mode — cannot verify)")

        heuristic_score = min(heuristic_score, 100)

        if heuristic_score >= 70:   risk_level = "High Risk"
        elif heuristic_score >= 40: risk_level = "Medium Risk"
        elif heuristic_score >= 20: risk_level = "Low Risk"
        else:                       risk_level = "Safe"

        return {
            "risk_level":      risk_level,
            "heuristic_score": heuristic_score,
            "flags":           flags,
            "source":          "offline_heuristics",
            "note":            "Link Analyzer unavailable — local check only"
        }

    except Exception as e:
        log.warning(f"[Logic] offline_url_check error: {e}")
        return {"risk_level": "Unknown", "flags": [], "source": "offline_error"}


# ─────────────────────────────────────────────────────────────
# Communication analysis (SMS, email, tel)
# ─────────────────────────────────────────────────────────────

async def _enrich_phone(number: str) -> dict:
    """NumVerify phone enrichment (requires API key)."""
    if not NUM_VERIFY_KEY or not number:
        return {}
    try:
        clean = re.sub(r"[^0-9+]", "", number)
        async with httpx.AsyncClient() as client:
            r = await client.get(
                "http://apilayer.net/api/validate",
                params={"access_key": NUM_VERIFY_KEY, "number": clean, "format": 1},
                timeout=5.0
            )
        if r.status_code == 200:
            data = r.json()
            return {
                "valid":      data.get("valid"),
                "country":    data.get("country_name"),
                "carrier":    data.get("carrier"),
                "line_type":  data.get("line_type"),
            }
    except Exception:
        pass
    return {}


async def analyze_communication(raw: str, parsed: dict) -> dict:
    """Analyze SMS, email, tel QR codes."""
    qr_type = parsed.get("qr_type", "text")
    result  = {
        "type":       "communication",
        "qr_subtype": qr_type,
        "payload":    raw,
        "parsed":     parsed,
    }

    if qr_type == "sms":
        number   = parsed.get("number", "")
        body     = parsed.get("body", "")
        enrichment = await _enrich_phone(number)
        smishing   = detect_smishing(body or raw, "sms")
        ai         = await analyze_intent(raw, "SMS QR — check for smishing or premium rate")
        result.update({
            "enrichment": enrichment,
            "smishing":   smishing,
            "ai_analysis": ai
        })

    elif qr_type == "email":
        body    = f"{parsed.get('subject','') or ''} {parsed.get('body','') or ''}".strip()
        smishing = detect_smishing(body or raw, "email")
        ai       = await analyze_intent(raw, "Email QR — check for phishing or malware delivery")
        result.update({"smishing": smishing, "ai_analysis": ai})

    elif qr_type == "tel":
        number     = parsed.get("number", "")
        enrichment = await _enrich_phone(number)
        result.update({"enrichment": enrichment})

    return result
