"""
Feature 1 — URL Heuristic Engine
Aegis Link Analyzer | Phase 1

Runs entirely locally — no API keys, no internet connection required.
Detects suspicious URL patterns using structural analysis.
"""

import re
import math
from urllib.parse import urlparse
from typing import Dict, List, Tuple

# ─────────────────────────────────────────────
# REFERENCE DATA
# ─────────────────────────────────────────────

# Top brands most commonly impersonated in phishing attacks
BRAND_LIST = [
    "paypal", "google", "microsoft", "apple", "amazon", "facebook", "instagram",
    "netflix", "twitter", "linkedin", "dropbox", "adobe", "chase", "wellsfargo",
    "bankofamerica", "citibank", "ebay", "walmart", "steam", "spotify", "youtube",
    "yahoo", "outlook", "office365", "onedrive", "icloud", "coinbase", "binance",
    "blockchain", "dhl", "fedex", "ups", "usps", "irs", "whatsapp", "telegram",
    "discord", "reddit", "github", "gitlab", "shopify", "stripe", "godaddy",
    "namecheap", "robinhood", "cashapp", "venmo", "zelle", "wise", "revolut"
]

# TLDs heavily associated with free/abuse registrations
SUSPICIOUS_TLDS = {
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".buzz", ".click",
    ".link", ".online", ".site", ".website", ".space", ".club", ".win",
    ".download", ".stream", ".gdn", ".racing", ".loan", ".party", ".trade",
    ".accountant", ".science", ".work", ".date", ".faith", ".review", ".biz"
}

# Keywords commonly found in phishing URLs
PHISHING_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "verification", "secure", "security",
    "account", "update", "confirm", "password", "credential", "banking", "wallet",
    "support", "helpdesk", "alert", "suspend", "unusual", "unauthorized",
    "recover", "restore", "validate", "billing", "payment", "invoice", "refund",
    "claim", "reward", "bonus", "prize", "winner", "lucky", "free-gift",
    "urgent", "limited-time", "act-now", "click-here", "ebayisapi", "webscr"
]

# Known URL shortener domains
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "short.io", "tiny.cc", "shorturl.at", "cutt.ly", "rb.gy",
    "bl.ink", "snip.ly", "lnkd.in", "adf.ly", "bc.vc", "x.co"
}


# ─────────────────────────────────────────────
# CORE ALGORITHMS
# ─────────────────────────────────────────────

def shannon_entropy(text: str) -> float:
    """
    Calculates Shannon entropy of a string.
    High entropy (>3.8) suggests randomly-generated/DGA domain names.
    Normal English words have entropy around 3.0-3.5.
    """
    if not text:
        return 0.0
    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    length = len(text)
    entropy = -sum((count / length) * math.log2(count / length)
                   for count in freq.values())
    return round(entropy, 3)


def levenshtein_distance(s1: str, s2: str) -> int:
    """
    Calculates the edit distance between two strings.
    Used to detect typosquatting (e.g., 'paypa1' vs 'paypal').
    """
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    prev_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            curr_row.append(min(
                prev_row[j + 1] + 1,   # deletion
                curr_row[j] + 1,       # insertion
                prev_row[j] + (c1 != c2)  # substitution
            ))
        prev_row = curr_row
    return prev_row[-1]


def detect_typosquatting(domain_base: str) -> Tuple[bool, str]:
    """
    Checks if a domain name is suspiciously close to a known brand.
    Returns (is_typosquat, reason_string).
    """
    domain_lower = domain_base.lower()

    for brand in BRAND_LIST:
        # Exact match → legitimate, skip
        if domain_lower == brand:
            return False, ""

        # Brand embedded in a longer domain name (e.g., "paypal-secure.com")
        if brand in domain_lower and len(domain_lower) > len(brand):
            return True, f"Brand '{brand}' embedded in domain — classic phishing pattern"

        # Edit distance check — catches typos like 'paypa1', 'gooogle'
        if len(domain_lower) >= 5 and len(brand) >= 5:
            dist = levenshtein_distance(domain_lower, brand)
            if 1 <= dist <= 2:
                return True, f"Very similar to '{brand}' (edit distance: {dist})"

    return False, ""


# ─────────────────────────────────────────────
# MAIN HEURISTICS RUNNER
# ─────────────────────────────────────────────

def run_heuristics(url: str) -> Dict:
    """
    Runs all heuristic checks on a URL.

    Returns:
        dict with:
          - flags: list of human-readable warning strings
          - flag_count: number of flags triggered
          - heuristic_score: 0-100 raw risk score from heuristics alone
          - entropy: Shannon entropy of the domain
          - is_suspicious: True if score >= 20
          - checks_performed: list of check names that ran
    """
    flags: List[str] = []
    score: int = 0
    checks_performed: List[str] = []
    entropy: float = 0.0

    try:
        parsed = urlparse(url)
        full_url = url.lower()
        domain = parsed.netloc.lower()
        hostname = domain.split(":")[0]  # strip port
        path = parsed.path.lower()
        query = parsed.query.lower()

        # Split hostname into parts for analysis
        parts = hostname.split(".")
        registrable_domain = parts[-2] if len(parts) >= 2 else hostname
        tld = "." + parts[-1] if len(parts) >= 2 else ""

        # ── Check 1: IP-Based URL ─────────────────────────
        checks_performed.append("ip_url")
        ip_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
        if ip_pattern.match(hostname):
            flags.append("IP-based URL — legitimate sites use domain names, not raw IPs")
            score += 40

        # ── Check 2: Suspicious TLD ───────────────────────
        checks_performed.append("suspicious_tld")
        if tld in SUSPICIOUS_TLDS:
            flags.append(f"Suspicious TLD '{tld}' — commonly used for free/abusive registrations")
            score += 25   # raised from 20 — suspicious TLDs are a reliable signal

        # ── Check 3: Subdomain Depth ──────────────────────
        checks_performed.append("subdomain_depth")
        subdomain_count = hostname.count(".")
        if subdomain_count > 3:
            flags.append(
                f"Excessive subdomain depth ({subdomain_count} levels) — "
                "phishing trick to hide the real domain at the end"
            )
            score += 15

        # ── Check 4: Typosquatting ────────────────────────
        checks_performed.append("typosquatting")
        is_typo, typo_reason = detect_typosquatting(registrable_domain)
        if is_typo:
            flags.append(f"Possible typosquatting detected: {typo_reason}")
            score += 35

        # ── Check 5: Shannon Entropy (DGA Detection) ──────
        checks_performed.append("entropy")
        domain_stripped = hostname.replace(".", "")
        entropy = shannon_entropy(domain_stripped)
        if entropy > 3.8:
            flags.append(
                f"High domain entropy ({entropy}) — "
                "random-looking name typical of malware-generated domains"
            )
            score += 25
        elif entropy > 3.5:
            flags.append(f"Moderately high domain entropy ({entropy})")
            score += 10

        # ── Check 6: Phishing Keywords ────────────────────
        checks_performed.append("phishing_keywords")
        full_path_query = (path + "?" + query).lower()
        matched_keywords = [kw for kw in PHISHING_KEYWORDS if kw in full_url]
        if matched_keywords:
            keyword_score = min(len(matched_keywords) * 8, 30)
            flags.append(
                f"Phishing keywords in URL: [{', '.join(matched_keywords[:6])}]"
            )
            score += keyword_score

        # ── Check 7: Abnormal URL Length ──────────────────
        checks_performed.append("url_length")
        url_len = len(url)
        if url_len > 200:
            flags.append(f"Very long URL ({url_len} chars) — often used to hide true destination")
            score += 20
        elif url_len > 100:
            flags.append(f"Abnormally long URL ({url_len} chars)")
            score += 10

        # ── Check 8: URL Shortener ────────────────────────
        checks_performed.append("url_shortener")
        if hostname in URL_SHORTENERS:
            flags.append(f"URL shortener detected ({hostname}) — hides the real destination")
            score += 15

        # ── Check 9: HTTP (Not HTTPS) ─────────────────────
        checks_performed.append("https_check")
        if parsed.scheme == "http":
            flags.append("Non-secure HTTP protocol — no encryption, data can be intercepted")
            score += 12   # raised from 10

        # ── Check 10: Special Characters in Domain ────────
        checks_performed.append("special_chars")
        if re.search(r"[^a-zA-Z0-9\-\.]", hostname):
            flags.append("Special/encoded characters in domain name — evasion technique")
            score += 20

        # ── Check 11: Numeric-Only Domain ─────────────────
        checks_performed.append("numeric_domain")
        if re.match(r"^\d+\.", hostname):
            flags.append("Domain starts with numbers — unusual for legitimate sites")
            score += 15

        # ── Check 12: Double Slash in Path (Evasion) ──────
        checks_performed.append("double_slash")
        if "//" in path:
            flags.append("Double slash in URL path — possible open redirect evasion")
            score += 15

        # ── Check 13: @ Symbol in URL (User-info trick) ───
        checks_performed.append("at_symbol")
        if "@" in hostname or "@" in path:
            flags.append(
                "@ symbol in URL — can trick browsers into loading a different domain "
                "(e.g., http://legit.com@evil.com)"
            )
            score += 35

        # ── Check 14: Punycode / IDN Homograph ────────────
        checks_performed.append("punycode")
        if "xn--" in hostname:
            flags.append(
                "Punycode/IDN domain detected — may use look-alike Unicode characters "
                "to impersonate legitimate domains"
            )
            score += 30

    except Exception as e:
        flags.append(f"Heuristic engine error: {str(e)}")

    final_score = min(score, 100)

    return {
        "flags": flags,
        "flag_count": len(flags),
        "heuristic_score": final_score,
        "entropy": entropy,
        "checks_performed": checks_performed,
        "checks_count": len(checks_performed),
        "is_suspicious": final_score >= 20
    }
