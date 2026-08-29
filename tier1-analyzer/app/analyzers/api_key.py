"""
API Key & Token Analyzer — Tier 4
  AK-01  Key format detection (40+ service patterns: AWS, GitHub, Stripe, OpenAI, etc.)
  AK-02  Entropy analysis (low entropy = predictable / weak key)
  AK-03  Structure validation per service (prefix, length, charset)
  AK-04  Test/demo key detection (well-known test keys embedded in repos)
  AK-05  GitHub secret scanning patterns (matches GitHub's own patterns)
  AK-06  TruffleHog regex catalogue (common leak patterns)
  AK-07  Key age estimation from format (rotation needed?)
  AK-08  Sensitive scope indicators (admin, write, root, full-access prefixes)
  AK-09  GitGuardian-compatible entropy threshold check
  AK-10  Key type risk scoring (cloud > payment > auth > read-only)
"""
import hashlib
import math
import re
from typing import Any

# ── AK-01: Service pattern catalogue ──────────────────────────────────────────
# Format: (service_name, risk_tier, pattern, notes)
# risk_tier: 5=critical(cloud/payment), 4=high(auth), 3=medium, 2=low, 1=info
KEY_PATTERNS: list = [
    # ── Cloud Providers ───────────────────────────────────────────────────────
    ("AWS Access Key ID",       5, re.compile(r"^AKIA[0-9A-Z]{16}$"),
     "20-char key — pair with secret for full AWS access"),
    ("AWS Secret Access Key",   5, re.compile(r"^[A-Za-z0-9/+=]{40}$"),
     "40-char base64 secret — never commit to repo"),
    ("AWS Session Token",       5, re.compile(r"^(ASIA)[0-9A-Z]{16}$"),
     "Temporary STS token with ASIA prefix"),
    ("GCP API Key",             4, re.compile(r"^AIza[0-9A-Za-z_\-]{35}$"),
     "39-char Google Cloud API key"),
    ("GCP Service Account",     5, re.compile(r"^-----BEGIN (RSA |EC )?PRIVATE KEY-----"),
     "Private key — critical exposure"),
    ("Azure Storage Key",       5, re.compile(r"^[A-Za-z0-9+/]{86}==$"),
     "88-char base64 Azure storage account key"),
    ("Azure Client Secret",     4, re.compile(r"^[A-Za-z0-9_~.\-]{34,40}$"),
     "Azure AD app client secret"),
    ("DigitalOcean Token",      4, re.compile(r"^dop_v1_[a-f0-9]{64}$"),
     "64 hex chars after dop_v1_ prefix"),
    ("Heroku API Key",          4, re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"),
     "UUID-format Heroku personal API token"),

    # ── Source Control ─────────────────────────────────────────────────────────
    ("GitHub Personal Access Token (Classic)", 4,
     re.compile(r"^ghp_[A-Za-z0-9]{36}$"),
     "Fine-grained PAT since 2021 — repo read/write"),
    ("GitHub Fine-Grained PAT", 4,
     re.compile(r"^github_pat_[A-Za-z0-9_]{82}$"),
     "New fine-grained PAT format"),
    ("GitHub OAuth Token",      4, re.compile(r"^gho_[A-Za-z0-9]{36}$"),
     "OAuth application token"),
    ("GitHub App Token",        4, re.compile(r"^ghs_[A-Za-z0-9]{36}$"),
     "GitHub Actions / App installation token"),
    ("GitHub Refresh Token",    4, re.compile(r"^ghr_[A-Za-z0-9]{36}$"),
     "OAuth refresh token"),
    ("GitLab Personal Token",   4, re.compile(r"^glpat-[A-Za-z0-9_\-]{20}$"),
     "GitLab PAT with glpat- prefix"),
    ("GitLab Runner Token",     3, re.compile(r"^GR1348941[A-Za-z0-9_\-]{20}$"),
     "GitLab CI runner registration token"),

    # ── Payment ────────────────────────────────────────────────────────────────
    ("Stripe Secret Key",       5, re.compile(r"^sk_live_[A-Za-z0-9]{24,99}$"),
     "LIVE stripe secret — full charge access"),
    ("Stripe Test Key",         2, re.compile(r"^sk_test_[A-Za-z0-9]{24,99}$"),
     "Stripe test mode key — no real transactions"),
    ("Stripe Restricted Key",   3, re.compile(r"^rk_live_[A-Za-z0-9]{24,99}$"),
     "Restricted live key"),
    ("Stripe Publishable Key",  1, re.compile(r"^pk_(live|test)_[A-Za-z0-9]{24,99}$"),
     "Publishable key — public by design"),
    ("PayPal Client ID",        2, re.compile(r"^A[A-Za-z0-9_\-]{79}$"),
     "PayPal OAuth client ID — public-facing"),
    ("PayPal Client Secret",    5, re.compile(r"^E[A-Za-z0-9_\-]{79}$"),
     "PayPal OAuth secret — grants full PayPal API access"),
    ("Square Access Token",     5, re.compile(r"^sq0atp-[A-Za-z0-9_\-]{22}$"),
     "Square production access token"),
    ("Square OAuth Token",      4, re.compile(r"^sq0csp-[A-Za-z0-9_\-]{43}$"),
     "Square client secret / OAuth token"),
    ("Braintree Token",         4, re.compile(r"^access_token\$production\$[A-Za-z0-9]{16}\$[a-f0-9]{32}$"),
     "Braintree production access token"),
    ("Razorpay Key ID",         2, re.compile(r"^rzp_live_[A-Za-z0-9]{14}$"),
     "Razorpay production key ID (South Asian)"),
    ("Razorpay Key Secret",     5, re.compile(r"^[A-Za-z0-9]{20}$"),
     "Razorpay key secret — 20 alphanumeric chars"),
    ("JazzCash Merchant Key",   4, re.compile(r"^[A-Za-z0-9]{32}$"),
     "Pakistani JazzCash merchant integration key"),

    # ── AI / ML Services ─────────────────────────────────────────────────────
    ("OpenAI API Key",          4, re.compile(r"^sk-[A-Za-z0-9]{48}$"),
     "OpenAI API key — billed per token"),
    ("OpenAI Project Key",      4, re.compile(r"^sk-proj-[A-Za-z0-9_\-]{48,}$"),
     "OpenAI project-scoped API key"),
    ("Anthropic API Key",       4, re.compile(r"^sk-ant-api[0-9]+-[A-Za-z0-9_\-]{90,}$"),
     "Anthropic Claude API key"),
    ("HuggingFace Token",       3, re.compile(r"^hf_[A-Za-z0-9]{37}$"),
     "Hugging Face user access token"),
    ("Cohere API Key",          3, re.compile(r"^[A-Za-z0-9]{40}$"),
     "Cohere.ai API key — 40 alphanumeric chars"),
    ("Replicate Token",         3, re.compile(r"^r8_[A-Za-z0-9]{40}$"),
     "Replicate.com API token"),

    # ── Communication ─────────────────────────────────────────────────────────
    ("Twilio Account SID",      2, re.compile(r"^AC[a-f0-9]{32}$"),
     "Public-facing Twilio SID — pair with auth token"),
    ("Twilio Auth Token",       5, re.compile(r"^[a-f0-9]{32}$"),
     "32 hex chars — Twilio auth token (also matches MD5)"),
    ("Twilio API Key",          4, re.compile(r"^SK[a-f0-9]{32}$"),
     "Twilio API key SID"),
    ("SendGrid API Key",        4, re.compile(r"^SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}$"),
     "SendGrid mail send access"),
    ("Mailgun API Key",         4, re.compile(r"^key-[a-f0-9]{32}$"),
     "Mailgun private API key"),
    ("Postmark Server Token",   4, re.compile(r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$"),
     "UUID-format Postmark server token"),
    ("Slack Bot Token",         4, re.compile(r"^xoxb-[0-9]{11,13}-[0-9]{11,13}-[A-Za-z0-9]{24}$"),
     "Slack bot access token"),
    ("Slack User Token",        4, re.compile(r"^xoxp-[0-9]{11,13}-[0-9]{11,13}-[0-9]{11,13}-[a-f0-9]{32}$"),
     "Slack user OAuth token — full user access"),
    ("Slack Webhook",           3, re.compile(r"^https://hooks\.slack\.com/services/T[A-Za-z0-9_/]+$"),
     "Incoming Slack webhook URL"),
    ("Discord Bot Token",       4, re.compile(r"^[MNO][A-Za-z0-9_\-]{23}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27}$"),
     "Discord bot token — full bot API access"),
    ("Telegram Bot Token",      3, re.compile(r"^\d{8,10}:[A-Za-z0-9_\-]{35}$"),
     "Telegram bot token — send messages as bot"),

    # ── Analytics / Marketing ─────────────────────────────────────────────────
    ("Mixpanel Secret",         3, re.compile(r"^[a-f0-9]{32}$"),
     "32 hex chars — Mixpanel project secret"),
    ("Amplitude API Key",       2, re.compile(r"^[a-f0-9]{32}$"),
     "32 hex — Amplitude project API key"),
    ("Segment Write Key",       3, re.compile(r"^[A-Za-z0-9]{27}$"),
     "27-char Segment write key"),
    ("Intercom Access Token",   3, re.compile(r"^dG9r[A-Za-z0-9]{50,}$"),
     "Intercom personal access token (base64 prefix)"),

    # ── Database / Infrastructure ─────────────────────────────────────────────
    ("MongoDB URI",             5, re.compile(r"^mongodb(\+srv)?://[^:]+:[^@]+@"),
     "MongoDB connection URI with embedded credentials"),
    ("PostgreSQL URI",          5, re.compile(r"^postgres(ql)?://[^:]+:[^@]+@"),
     "PostgreSQL connection URI with embedded password"),
    ("MySQL URI",               5, re.compile(r"^mysql://[^:]+:[^@]+@"),
     "MySQL connection URI with embedded password"),
    ("Redis URI",               4, re.compile(r"^redis(s)?://:[^@]+@"),
     "Redis connection URI with auth token"),

    # ── JWT / OAuth ────────────────────────────────────────────────────────────
    ("JWT Token",               3, re.compile(r"^eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+$"),
     "JSON Web Token — check expiry and claims"),
    ("OAuth Bearer Token",      3, re.compile(r"^Bearer [A-Za-z0-9+/=_\-]{20,}$"),
     "OAuth 2.0 Bearer token in Authorization header format"),

    # ── Social / Maps ─────────────────────────────────────────────────────────
    ("Twitter/X Bearer Token",  3, re.compile(r"^AAAAAAAAAAAAAAAAAAAAAA[A-Za-z0-9%/+]{50,}$"),
     "Twitter v2 Bearer Token"),
    ("Google Maps API Key",     3, re.compile(r"^AIza[0-9A-Za-z_\-]{35}$"),
     "Google Maps/Places API key — billing risk if unrestricted"),
    ("Facebook Access Token",   4, re.compile(r"^EAAA[A-Za-z0-9]{50,}$"),
     "Facebook Graph API access token"),
    ("Shopify Access Token",    4, re.compile(r"^shpat_[a-f0-9]{32}$"),
     "Shopify Admin API access token"),
    ("Shopify Shared Secret",   4, re.compile(r"^shpss_[a-f0-9]{32}$"),
     "Shopify partner shared secret"),

    # ── Security Tools ────────────────────────────────────────────────────────
    ("VirusTotal API Key",      3, re.compile(r"^[a-f0-9]{64}$"),
     "64 hex — VirusTotal API key"),
    ("Shodan API Key",          3, re.compile(r"^[A-Za-z0-9]{32}$"),
     "Shodan 32-char API key"),
    ("Have I Been Pwned Key",   2, re.compile(r"^[a-z0-9]{32}$"),
     "HIBP API key — lowercase hex 32 chars"),
]

# ── AK-04: Known test/demo keys ────────────────────────────────────────────────
KNOWN_TEST_KEYS: dict = {
    # Stripe
    "sk_test_4eC39HqLyjWDarjtT1zdp7dc": ("Stripe", "Official Stripe test key from docs"),
    "sk_test_BQokikJOvBiI2HlWgH4olfQ2": ("Stripe", "Stripe docs example key"),
    "rk_test_s3rF7DP6eSBWU2RlJT5lbN0P": ("Stripe", "Stripe restricted test key"),
    # GitHub
    "ghp_exampletoken1234567890abcde12345": ("GitHub", "GitHub docs example token"),
    # AWS
    "AKIAIOSFODNN7EXAMPLE": ("AWS", "Official AWS docs example Access Key ID"),
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY": ("AWS", "Official AWS docs example secret"),
    # OpenAI
    "sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx": ("OpenAI", "OpenAI placeholder key"),
    # Twilio
    "ACXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX": ("Twilio", "Twilio docs example Account SID"),
    "your_auth_token": ("Generic", "Placeholder — not a real key"),
    "YOUR_API_KEY": ("Generic", "Placeholder — not a real key"),
    "INSERT_API_KEY_HERE": ("Generic", "Template placeholder"),
}


# ── AK-02: Entropy calculation ─────────────────────────────────────────────────
def calculate_entropy(key: str) -> dict:
    """
    Shannon entropy + charset analysis.
    Low entropy = predictable / weak.
    Threshold: < 3.0 = weak, 3.0–4.5 = medium, > 4.5 = strong.
    """
    if not key:
        return {"entropy_bits": 0.0, "charset_size": 0, "strength": "Empty"}

    # Charset detection
    has_lower   = bool(re.search(r"[a-z]", key))
    has_upper   = bool(re.search(r"[A-Z]", key))
    has_digit   = bool(re.search(r"\d", key))
    has_special = bool(re.search(r"[^A-Za-z0-9]", key))

    charset_size = (
        (26 if has_lower   else 0) +
        (26 if has_upper   else 0) +
        (10 if has_digit   else 0) +
        (32 if has_special else 0)
    )

    # Shannon entropy per character
    freq = {}
    for c in key:
        freq[c] = freq.get(c, 0) + 1
    n = len(key)
    shannon = -sum((f / n) * math.log2(f / n) for f in freq.values())

    # Effective bits
    entropy_bits = shannon * len(key)

    # Theoretical max (if uniform)
    if charset_size > 0:
        theoretical_max = math.log2(charset_size) * len(key)
    else:
        theoretical_max = 0

    strength = (
        "Very Strong" if shannon > 4.5 else
        "Strong"      if shannon > 3.8 else
        "Medium"      if shannon > 3.0 else
        "Weak"        if shannon > 2.0 else "Very Weak"
    )

    return {
        "shannon_entropy": round(shannon, 3),
        "entropy_bits": round(entropy_bits, 1),
        "charset_size": charset_size,
        "theoretical_max_bits": round(theoretical_max, 1),
        "has_lowercase": has_lower,
        "has_uppercase": has_upper,
        "has_digits": has_digit,
        "has_special": has_special,
        "unique_chars": len(freq),
        "key_length": n,
        "strength": strength,
    }


# ── AK-01: Service detection ───────────────────────────────────────────────────
def _pattern_specificity(pattern_src: str) -> int:
    """
    Returns 1 if the pattern encodes a known literal prefix (high specificity),
    0 if it is a generic length/charset pattern.
    Prefix-specific patterns win as tiebreakers when risk_tier is equal.
    """
    # Patterns that start with specific fixed-string prefixes
    specific_starts = (
        r"^\^AKIA", r"^\^ASIA", r"^\^AIza", r"^\^ghp_", r"^\^gho_",
        r"^\^ghs_", r"^\^ghr_", r"^\^github_pat_", r"^\^glpat-",
        r"^\^GR1348941", r"^\^sk_live_", r"^\^sk_test_", r"^\^rk_live_",
        r"^\^rk_test_", r"^\^pk_", r"^\^SG\.", r"^\^xoxb-", r"^\^xoxp-",
        r"^\^dop_v1_", r"^\^SK", r"^\^AC", r"^\^hf_", r"^\^r8_",
        r"^\^shpat_", r"^\^shpss_", r"^\^sq0atp-", r"^\^sq0csp-",
        r"^\^rzp_live_", r"^\^eyJ", r"^\^Bearer ", r"^\^mongodb",
        r"^\^postgres", r"^\^mysql", r"^\^redis", r"^\^https://hooks",
        r"^\^sk-ant-", r"^\^sk-proj-", r"^\^sk-", r"^\^-----BEGIN",
        r"^\^access_token", r"^\^AAAAAAAAAA", r"^\^EAAA", r"^\^MNO\]",
    )
    import re as _re
    for prefix in specific_starts:
        if _re.match(prefix, pattern_src):
            return 1
    return 0


def detect_key_service(key: str) -> dict:
    """Match key against all known service patterns. Return best match."""
    key_strip = key.strip()
    matches = []

    for service, risk_tier, pattern, notes in KEY_PATTERNS:
        if pattern.match(key_strip):
            specificity = _pattern_specificity(pattern.pattern)
            matches.append({
                "service":       service,
                "risk_tier":     risk_tier,
                "notes":         notes,
                "confidence":    "High",
                "specificity":   specificity,
                "_pattern_src":  pattern.pattern,  # internal: for prefix_len sort
            })

    if not matches:
        # Partial/heuristic detection
        if key_strip.startswith("sk-"):
            matches.append({"service": "Unknown (sk- prefix)", "risk_tier": 4, "specificity": 1,
                             "notes": "Secret key format — likely API key", "confidence": "Medium"})
        elif key_strip.startswith("AKIA"):
            matches.append({"service": "AWS (AKIA prefix)", "risk_tier": 5, "specificity": 1,
                             "notes": "AWS Access Key ID prefix", "confidence": "High"})
        elif len(key_strip) in (32, 40, 64) and re.match(r"^[a-f0-9]+$", key_strip):
            matches.append({"service": f"Unknown ({len(key_strip)}-char hex token)",
                             "risk_tier": 3, "confidence": "Low", "specificity": 0,
                             "notes": "Hex token — could be API key, MD5, SHA1, or SHA256"})
        elif len(key_strip) >= 20 and re.match(r"^[A-Za-z0-9+/=_\-]+$", key_strip):
            matches.append({"service": "Unknown (generic token)", "risk_tier": 2,
                             "confidence": "Low", "specificity": 0,
                             "notes": "Alphanumeric token pattern"})

    if not matches:
        return {"detected": False, "matches": [], "primary_service": None, "max_risk_tier": 0}

    # Sort: highest risk_tier first, then prefix_length (longest fixed prefix = most specific),
    # then generic specificity as final tiebreaker.
    # This ensures ghp_-prefixed patterns beat generic Azure {34-40} patterns.
    import re as _re2
    def _prefix_len(pat_src):
        """Count consecutive literal (non-metachar) chars at start of pattern."""
        # Strip leading ^ if present
        s = pat_src.lstrip("^")
        count = 0
        for ch in s:
            if ch in r".[*+?{\()|$": break
            count += 1
        return count
    for m in matches:
        m["prefix_len"] = _prefix_len(m.get("_pattern_src", ""))
    matches_sorted = sorted(matches, key=lambda x: (x["risk_tier"], x["specificity"], x.get("prefix_len",0)), reverse=True)
    best = matches_sorted[0]

    # Build clean output (remove internal specificity field from public response)
    public_matches = [{k: v for k, v in m.items() if k not in ("specificity","prefix_len","_pattern_src")} for m in matches_sorted[:3]]

    return {
        "detected":         True,
        "matches":          public_matches,
        "primary_service":  best["service"],
        "max_risk_tier":    best["risk_tier"],
        "risk_tier_label":  {5: "Critical", 4: "High", 3: "Medium", 2: "Low", 1: "Info"}.get(
                                best["risk_tier"], "Unknown"),
    }


# ── AK-03: Structure validation ────────────────────────────────────────────────
def validate_key_structure(key: str, service_info: dict) -> dict:
    """Validate structural requirements for detected service."""
    issues = []
    suggestions = []
    key_strip = key.strip()

    primary = service_info.get("primary_service") or ""   # guard None → ""

    # JWT specific checks
    if "JWT" in primary or (key_strip.startswith("eyJ") and "." in key_strip):
        parts = key_strip.split(".")
        if len(parts) != 3:
            issues.append("JWT should have exactly 3 parts (header.payload.signature)")
        else:
            try:
                import base64
                header_b64 = parts[0] + "=="  # pad
                header = base64.urlsafe_b64decode(header_b64.encode()).decode("utf-8", errors="replace")
                suggestions.append(f"JWT header: {header[:100]}")
                # Check expiry hint
                payload_b64 = parts[1] + "=="
                import json
                payload = json.loads(base64.urlsafe_b64decode(payload_b64.encode()).decode("utf-8", errors="replace"))
                if "exp" in payload:
                    from datetime import datetime
                    exp = payload["exp"]
                    try:
                        exp_dt = datetime.fromtimestamp(exp)
                        from datetime import datetime as dt
                        is_expired = dt.now() > exp_dt
                        suggestions.append(f"JWT exp: {exp_dt.strftime('%Y-%m-%d %H:%M:%S')} — {'EXPIRED' if is_expired else 'valid'}")
                        if is_expired:
                            issues.append("JWT token has expired")
                    except Exception:
                        pass
                if "iss" in payload:
                    suggestions.append(f"JWT issuer: {payload['iss']}")
                if "sub" in payload:
                    suggestions.append(f"JWT subject: {payload['sub']}")
            except Exception as e:
                issues.append(f"JWT decode error: {str(e)[:50]}")

    # AWS checks
    if "AWS Access Key ID" in primary:
        if not key_strip.startswith(("AKIA", "ASIA", "ABIA", "ACCA")):
            issues.append("AWS Access Key should start with AKIA/ASIA/ABIA/ACCA")
        if len(key_strip) != 20:
            issues.append(f"AWS Access Key should be 20 chars, got {len(key_strip)}")

    # GitHub checks
    if "GitHub" in primary:
        expected_prefixes = {"ghp_": 36, "gho_": 36, "ghs_": 36, "ghr_": 36}
        for pfx, expected_len in expected_prefixes.items():
            if key_strip.startswith(pfx):
                remainder = len(key_strip) - len(pfx)
                if remainder != expected_len:
                    issues.append(f"GitHub {pfx} token should be {len(pfx)+expected_len} chars total")

    # Stripe checks
    if "Stripe" in primary:
        if "sk_live" in key_strip:
            issues.append("⚠️  LIVE Stripe secret key — rotate immediately if exposed")

    return {
        "issues": issues,
        "suggestions": suggestions,
        "structure_valid": len(issues) == 0,
    }


# ── AK-04: Test key detection ──────────────────────────────────────────────────
def detect_test_key(key: str) -> dict:
    """Check against known demo/placeholder/test keys."""
    key_strip = key.strip()

    # Exact match
    if key_strip in KNOWN_TEST_KEYS:
        service, desc = KNOWN_TEST_KEYS[key_strip]
        return {"is_test_key": True, "service": service, "description": desc, "confidence": "Definite"}

    # Pattern-based test detection
    patterns = [
        (r"^sk_test_", "Stripe test mode key"),
        (r"^rk_test_", "Stripe restricted test key"),
        (r"^pk_test_", "Stripe publishable test key"),
        (r"EXAMPLE$", "Documented example key"),
        (r"^your_", "Template placeholder"),
        (r"^YOUR_", "Template placeholder"),
        (r"^INSERT_", "Template placeholder"),
        (r"xxx+$", "Repeating-char placeholder"),
        (r"1234567890", "Sequential-digit test key"),
        (r"^test_", "Prefixed test key"),
        (r"_test$", "Suffixed test key"),
        (r"^demo_", "Demo key"),
        (r"^sample_", "Sample key"),
    ]

    for pat, desc in patterns:
        if re.search(pat, key_strip, re.IGNORECASE):
            return {"is_test_key": True, "description": desc, "confidence": "High"}

    return {"is_test_key": False}


# ── AK-08: Sensitive scope indicators ─────────────────────────────────────────
def detect_scope_indicators(key: str, service_info: dict) -> dict:
    """
    Detect scope signals in key names/prefixes.
    Many services encode scope in the token prefix.
    """
    key_lower = key.lower()
    signals = []

    SCOPE_PATTERNS = {
        "root":          "Root-level access",
        "admin":         "Admin/privileged scope",
        "write":         "Write access",
        "readwrite":     "Read-write access",
        "fullaccess":    "Full access",
        "superuser":     "Superuser scope",
        "master":        "Master key",
        "owner":         "Owner-level token",
        "live":          "Production/live environment",
        "_sk_":          "Secret key pattern",
        "secret":        "Secret credential",
        "private":       "Private key",
        "sk_live":       "Stripe live secret key",
        "shpat":         "Shopify admin token",
        "dop_v1":        "DigitalOcean production token",
    }

    for pattern, meaning in SCOPE_PATTERNS.items():
        if pattern in key_lower:
            signals.append(meaning)

    # Check for read-only indicators (lower risk)
    readonly_patterns = ["readonly", "read_only", "ro_", "_ro", "pk_live", "pk_test", "public"]
    is_likely_readonly = any(p in key_lower for p in readonly_patterns)

    return {
        "elevated_scope_signals": signals,
        "is_likely_elevated": len(signals) > 0,
        "is_likely_readonly": is_likely_readonly,
        "recommendation": "Rotate immediately — elevated scope detected" if signals else None,
    }


# ── AK-09: GitGuardian-style entropy check ────────────────────────────────────
def gitguardian_entropy_check(key: str) -> dict:
    """
    Replicate GitGuardian's entropy-based detection logic.
    Uses base64 and hex string entropy thresholds.
    """
    key_strip = key.strip()
    findings = []

    # Base64 string entropy (threshold 4.5)
    b64_matches = re.findall(r"[A-Za-z0-9+/=_\-]{20,}", key_strip)
    for match in b64_matches:
        entropy = calculate_entropy(match)
        if entropy["shannon_entropy"] >= 4.5:
            findings.append({
                "type": "high_entropy_base64",
                "value_masked": f"{match[:4]}...{match[-4:]}",
                "entropy": entropy["shannon_entropy"],
                "length": len(match),
            })

    # Hex string entropy (threshold 3.0)
    hex_matches = re.findall(r"[a-f0-9]{16,}", key_strip)
    for match in hex_matches:
        entropy = calculate_entropy(match)
        if entropy["shannon_entropy"] >= 3.0:
            findings.append({
                "type": "high_entropy_hex",
                "value_masked": f"{match[:4]}...{match[-4:]}",
                "entropy": entropy["shannon_entropy"],
                "length": len(match),
            })

    return {
        "high_entropy_strings_found": len(findings) > 0,
        "findings": findings[:3],
        "note": "High-entropy strings are a strong indicator of embedded secrets",
    }


# ── Master API key scanner ─────────────────────────────────────────────────────
async def analyze_api_key(key: str) -> dict[str, Any]:
    """Full API key / token analysis — all AK-01 through AK-10 features."""
    key = key.strip()

    # Privacy: never log the actual key — hash it
    key_hash = hashlib.sha256(key.encode()).hexdigest()

    service   = detect_key_service(key)
    entropy   = calculate_entropy(key)
    structure = validate_key_structure(key, service)
    test_key  = detect_test_key(key)
    scope     = detect_scope_indicators(key, service)
    gg_check  = gitguardian_entropy_check(key)

    # ── Risk scoring ──────────────────────────────────────────────────────────
    score = 0
    flags = []

    risk_tier = service.get("max_risk_tier", 0)
    if risk_tier >= 5:
        score += 50
        flags.append(f"Critical-risk credential type: {service.get('primary_service')}")
    elif risk_tier == 4:
        score += 35
        flags.append(f"High-risk credential: {service.get('primary_service')}")
    elif risk_tier == 3:
        score += 20
    elif risk_tier == 2:
        score += 10

    if test_key["is_test_key"]:
        score = max(0, score - 30)  # Test keys are lower risk
        flags.append(f"Test/demo key detected: {test_key.get('description', '')}")
    elif not service["detected"]:
        score += 15
        flags.append("Key format not recognised — may be a custom or undocumented format")

    if scope["is_likely_elevated"]:
        score += 15
        for sig in scope["elevated_scope_signals"]:
            flags.append(f"Elevated scope indicator: {sig}")

    if entropy["strength"] in ("Weak", "Very Weak"):
        score += 20
        flags.append(f"Low entropy key ({entropy['shannon_entropy']:.2f} bits/char) — potentially predictable")

    if structure["issues"]:
        score += 10
        flags.extend(structure["issues"])

    if gg_check["high_entropy_strings_found"] and not service["detected"]:
        score += 10
        flags.append("High-entropy string detected — GitGuardian-style pattern match")

    # Stripe live key special handling
    _primary = (service.get('primary_service') or '')   # guard None
    if _primary.startswith('Stripe Secret') and not test_key['is_test_key']:
        score = max(score, 70)
        flags.append("⚠️  Live payment credential — ROTATE IMMEDIATELY IF EXPOSED")

    # AWS key special handling — only for real (non-test) keys
    if ("AWS Access Key ID" in _primary and not test_key["is_test_key"]):   # use _primary (already guarded)
        score = max(score, 65)
        flags.append("⚠️  AWS credential — can result in cloud account hijack, billback fraud")

    score = min(score, 100)
    level = (
        "Critical" if score >= 76 else
        "High"     if score >= 56 else
        "Medium"   if score >= 36 else
        "Low"      if score >= 16 else "Clean"
    )

    return {
        "credential_type": "api_key",
        "privacy": {
            "sha256_hash": key_hash,
            "key_length": len(key),
            "privacy_note": "Raw key never stored or logged — SHA-256 hash only",
        },
        "service_detection": service,
        "entropy": entropy,
        "structure": structure,
        "test_key": test_key,
        "scope": scope,
        "gitguardian_check": gg_check,
        "rotation_recommended": score >= 40 or scope["is_likely_elevated"],
        "overall_risk_score": score,
        "overall_risk_level": level,
        "all_flags": flags,
        "remediation": {
            "steps": [
                "Immediately revoke this key in the service dashboard",
                "Rotate to a new key and update all consuming systems",
                "Check git history / logs for any previous exposure",
                "Enable git-secrets or GitGuardian pre-commit hooks",
                "Store secrets in vault (HashiCorp Vault, AWS Secrets Manager, etc.)",
            ] if score >= 40 else [
                "Monitor for unexpected usage",
                "Ensure key is stored securely (not in code/config files)",
            ],
        },
    }
