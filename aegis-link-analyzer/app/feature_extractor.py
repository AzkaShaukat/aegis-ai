"""
feature_extractor.py
Aegis Link Analyzer

Converts a complete scan result dictionary into a fixed-length numeric
feature vector suitable for machine learning classification.

Each feature is normalized to a 0–1 range so no single feature
dominates the model due to scale differences.

Feature vector length: 35 features
"""

import math
import re
from typing import Dict, List, Tuple
from urllib.parse import urlparse


# ─────────────────────────────────────────────────────────────────────────────
# FEATURE DEFINITIONS
# ─────────────────────────────────────────────────────────────────────────────
# Each entry: (feature_name, description)
# Order must stay fixed — changing order breaks existing trained models.

FEATURE_NAMES: List[Tuple[str, str]] = [
    # URL Structure (Features 0–7)
    ("url_length",              "Normalized URL length (len/200, capped at 1.0)"),
    ("subdomain_depth",         "Number of subdomains / 5"),
    ("has_ip_address",          "1 if URL uses raw IP instead of domain"),
    ("is_http",                 "1 if URL scheme is HTTP (not HTTPS)"),
    ("suspicious_tld",          "1 if TLD is in known-abusive list"),
    ("entropy",                 "Shannon entropy of domain name / 5"),
    ("has_phishing_keywords",   "Fraction of known phishing keywords present (capped at 1.0)"),
    ("has_at_symbol",           "1 if @ present in URL"),

    # WHOIS Signals (Features 8–11)
    ("domain_age_normalized",   "Inverse domain age — newer = higher score (1 - age/3650, floor 0)"),
    ("whois_unavailable",       "1 if WHOIS lookup returned no data"),
    ("registrar_abusive",       "1 if registrar is in known-abusive list"),
    ("short_registration",      "1 if registration period < 365 days"),

    # DNS Signals (Features 12–17)
    ("dns_no_resolve",          "1 if domain does not resolve (NXDOMAIN)"),
    ("dns_no_mx",               "1 if no MX records"),
    ("dns_no_spf",              "1 if no SPF TXT record"),
    ("dns_cname_depth",         "CNAME chain depth / 5"),
    ("dns_single_ns",           "1 if only one nameserver"),
    ("dns_free_provider",       "1 if using free/dynamic DNS provider"),

    # SSL Signals (Features 18–23)
    ("ssl_invalid",             "1 if SSL cert is invalid or missing"),
    ("ssl_new_cert",            "1 if cert is < 30 days old (from non-major CA)"),
    ("ssl_expiring_soon",       "1 if cert expires in < 30 days"),
    ("ssl_free_ca",             "1 if issued by free CA (Let's Encrypt etc.)"),
    ("ssl_self_signed",         "1 if cert appears self-signed"),
    ("ssl_cn_mismatch",         "1 if CN doesn't match hostname"),

    # Redirect Signals (Features 24–28)
    ("redirect_hops",           "Number of redirect hops / 10"),
    ("has_shortener",           "1 if URL shortener found in chain"),
    ("protocol_downgrade",      "1 if HTTPS→HTTP downgrade in chain"),
    ("destination_changed",     "1 if final domain differs from original (non-www)"),
    ("final_404",               "1 if final redirect destination returns 404"),

    # External API Signals (Features 29–31)
    ("vt_malicious_normalized", "VT malicious count / 10"),
    ("vt_suspicious_normalized","VT suspicious count / 10"),
    ("urlhaus_hit",             "1 if found in URLhaus database"),

    # OpenPhish / GSB Signals (Features 32–34)
    ("openphish_hit",           "1 if found in OpenPhish feed"),
    ("gsb_hit",                 "1 if found in Google Safe Browsing"),
    ("total_flags_normalized",  "Total flag count / 20"),
]

FEATURE_COUNT = len(FEATURE_NAMES)

# Abusive TLDs list (synced with heuristics.py)
SUSPICIOUS_TLDS = {
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".buzz", ".click",
    ".link", ".online", ".site", ".website", ".space", ".club", ".win",
    ".download", ".stream", ".gdn", ".racing", ".loan", ".party", ".trade",
    ".accountant", ".science", ".work", ".date", ".faith", ".review", ".biz"
}

PHISHING_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "verification", "secure", "security",
    "account", "update", "confirm", "password", "credential", "banking", "wallet",
    "support", "helpdesk", "alert", "suspend", "unusual", "unauthorized",
    "recover", "restore", "validate", "billing", "payment", "invoice", "refund"
]

ABUSIVE_REGISTRARS = [
    "namecheap", "publicdomainregistry", "pdr ltd", "reg.ru",
    "internet.bs", "1api gmbh", "beget", "reg2c.com", "eranet", "bizcn"
]

FREE_DNS_PROVIDERS = ["afraid.org", "changeip.com", "no-ip.com", "dyndns"]


# ─────────────────────────────────────────────────────────────────────────────
# HELPER: Shannon Entropy
# ─────────────────────────────────────────────────────────────────────────────

def _entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    n = len(text)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


# ─────────────────────────────────────────────────────────────────────────────
# MAIN EXTRACTOR
# ─────────────────────────────────────────────────────────────────────────────

def extract_features(scan_result: Dict) -> List[float]:
    """
    Converts a scan result dictionary into a 35-element feature vector.

    Args:
        scan_result: The full dictionary returned by scan_url()

    Returns:
        List of 35 floats, each in range [0.0, 1.0]

    Raises:
        ValueError if the result is None or missing required fields
    """
    if not scan_result:
        raise ValueError("scan_result cannot be None or empty")

    url = scan_result.get("url", "")
    heuristics = scan_result.get("heuristics") or {}
    whois = scan_result.get("whois") or {}
    dns = scan_result.get("dns") or {}
    ssl = scan_result.get("ssl") or {}
    redirects = scan_result.get("redirects") or {}
    urlhaus = scan_result.get("urlhaus") or {}
    phishtank = scan_result.get("phishtank") or {}  # also holds openphish data
    gsb = scan_result.get("gsb") or {}
    detection = scan_result.get("detection_counts") or {}

    dns_details = dns.get("details") or {}
    ssl_details = ssl.get("details") or {}
    ssl_flags_text = " ".join(ssl.get("flags", [])).lower()

    try:
        parsed = urlparse(url)
        hostname = parsed.netloc.lower().split(":")[0]
        parts = hostname.split(".")
        tld = "." + parts[-1] if len(parts) >= 2 else ""
        domain_stripped = hostname.replace(".", "")
    except Exception:
        hostname = ""
        tld = ""
        domain_stripped = ""
        parts = []

    features = [
        # ── URL Structure ─────────────────────────────────────────────────
        # 0: url_length
        min(len(url) / 200.0, 1.0),

        # 1: subdomain_depth
        min(hostname.count(".") / 5.0, 1.0),

        # 2: has_ip_address
        1.0 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname) else 0.0,

        # 3: is_http
        1.0 if parsed.scheme == "http" else 0.0,

        # 4: suspicious_tld
        1.0 if tld in SUSPICIOUS_TLDS else 0.0,

        # 5: entropy
        min(_entropy(domain_stripped) / 5.0, 1.0),

        # 6: has_phishing_keywords
        min(sum(1 for kw in PHISHING_KEYWORDS if kw in url.lower()) / 5.0, 1.0),

        # 7: has_at_symbol
        1.0 if "@" in url else 0.0,

        # ── WHOIS ─────────────────────────────────────────────────────────
        # 8: domain_age_normalized (newer = higher risk)
        max(0.0, 1.0 - (whois.get("domain_age_days") or 3650) / 3650.0),

        # 9: whois_unavailable
        1.0 if not whois.get("creation_date") else 0.0,

        # 10: registrar_abusive
        1.0 if any(
            a in (whois.get("registrar") or "").lower()
            for a in ABUSIVE_REGISTRARS
        ) else 0.0,

        # 11: short_registration (reg period < 365 days)
        0.0,  # Filled below after date math

        # ── DNS ───────────────────────────────────────────────────────────
        # 12: dns_no_resolve
        0.0 if dns_details.get("resolves", True) else 1.0,

        # 13: dns_no_mx
        0.0 if dns_details.get("has_mx", True) else 1.0,

        # 14: dns_no_spf
        0.0 if dns_details.get("has_spf", True) else 1.0,

        # 15: dns_cname_depth
        min((dns_details.get("cname_depth") or 0) / 5.0, 1.0),

        # 16: dns_single_ns
        1.0 if len(dns_details.get("nameservers") or []) == 1 else 0.0,

        # 17: dns_free_provider
        1.0 if any(
            p in " ".join(dns_details.get("nameservers") or []).lower()
            for p in FREE_DNS_PROVIDERS
        ) else 0.0,

        # ── SSL ───────────────────────────────────────────────────────────
        # 18: ssl_invalid
        0.0 if ssl_details.get("is_valid", True) else 1.0,

        # 19: ssl_new_cert (< 30 days, non-major CA)
        1.0 if (
            (ssl_details.get("cert_age_days") or 365) < 30
            and not ssl_details.get("is_trusted_major_ca", False)
        ) else 0.0,

        # 20: ssl_expiring_soon (< 30 days until expiry)
        1.0 if 0 < (ssl_details.get("days_until_expiry") or 365) < 30 else 0.0,

        # 21: ssl_free_ca
        1.0 if ssl_details.get("is_free_cert", False) else 0.0,

        # 22: ssl_self_signed
        1.0 if "self-signed" in ssl_flags_text else 0.0,

        # 23: ssl_cn_mismatch
        1.0 if "mismatch" in ssl_flags_text else 0.0,

        # ── Redirects ─────────────────────────────────────────────────────
        # 24: redirect_hops
        min((redirects.get("hop_count") or 0) / 10.0, 1.0),

        # 25: has_shortener
        1.0 if redirects.get("shorteners_found") else 0.0,

        # 26: protocol_downgrade
        1.0 if "protocol downgrade" in " ".join(redirects.get("flags", [])).lower() else 0.0,

        # 27: destination_changed (real domain change, not www)
        1.0 if (
            redirects.get("destination_changed", False)
            and not redirects.get("is_www_normalization", False)
        ) else 0.0,

        # 28: final_404
        1.0 if (redirects.get("final_status_code") == 404 or "404" in " ".join(redirects.get("flags", []))) else 0.0,

        # ── External API ──────────────────────────────────────────────────
        # 29: vt_malicious_normalized
        min((detection.get("malicious") or 0) / 10.0, 1.0),

        # 30: vt_suspicious_normalized
        min((detection.get("suspicious") or 0) / 10.0, 1.0),

        # 31: urlhaus_hit
        1.0 if urlhaus.get("found", False) else 0.0,

        # 32: openphish_hit
        1.0 if phishtank.get("found", False) else 0.0,

        # 33: gsb_hit
        1.0 if gsb.get("found", False) else 0.0,

        # 34: total_flags_normalized
        min((scan_result.get("total_flags") or 0) / 20.0, 1.0),
    ]

    # ── Post-fill: short_registration (index 11) ──────────────────────────
    # Calculated separately because it needs two date fields
    try:
        creation = whois.get("creation_date")
        expiration = whois.get("expiration_date")
        if creation and expiration:
            from datetime import datetime
            c = datetime.strptime(creation, "%Y-%m-%d")
            e = datetime.strptime(expiration, "%Y-%m-%d")
            features[11] = 1.0 if (e - c).days < 365 else 0.0
    except Exception:
        features[11] = 0.0

    # Validate length
    assert len(features) == FEATURE_COUNT, (
        f"Feature extraction produced {len(features)} features, expected {FEATURE_COUNT}"
    )

    # Clamp all values to [0, 1]
    features = [max(0.0, min(1.0, float(f))) for f in features]

    return features


def extract_features_with_names(scan_result: Dict) -> Dict[str, float]:
    """
    Returns features as a named dictionary for debugging and explainability.
    """
    values = extract_features(scan_result)
    return {name: value for (name, _), value in zip(FEATURE_NAMES, values)}
