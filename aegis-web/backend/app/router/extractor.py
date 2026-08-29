"""app/router/extractor.py — Entity extraction from raw WhatsApp message text.

Detects and returns all recognisable entities in a message so the intent
router can decide routing priority and clash resolution.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional


# ── Compiled Regexes ──────────────────────────────────────────────────────────

# URLs (with and without scheme)
_URL_RE = re.compile(
    r"(?:https?://)[^\s<>\"']+|"
    r"(?<!\w)(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)"
    r"(?:com|pk|net|org|io|edu|gov|info|co|xyz|tk|ml|ga|cf|gq|top|live|online|site|store|shop|app|dev|ai|tech|ly|to|cc)"
    r"(?:/[^\s<>\"']*)?",
    re.IGNORECASE,
)

# Social platform URLs (instagram, twitter, tiktok, facebook, linkedin, youtube)
_SOCIAL_URL_RE = re.compile(
    r"https?://(?:www\.)?"
    r"(?:instagram\.com|twitter\.com|x\.com|tiktok\.com|facebook\.com|fb\.com|"
    r"linkedin\.com|youtube\.com|snapchat\.com|threads\.net)"
    r"/([A-Za-z0-9_.%-]+)",
    re.IGNORECASE,
)

# @handle (Twitter/Instagram style)
_HANDLE_RE = re.compile(r"(?<!\w)@([A-Za-z0-9_.]{1,30})(?!\w)")

# Email
_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")

# Pakistani CNIC: XXXXX-XXXXXXX-X
_CNIC_RE = re.compile(r"\b(\d{5}-\d{7}-\d|\d{13})\b")

# IBAN (starts with 2 letters + 2 digits)
_IBAN_RE = re.compile(r"\b([A-Z]{2}\d{2}[A-Z0-9]{4,30})\b")

# Passport MRZ line 1 (P<COUNTRY...)
_MRZ_LINE1_RE = re.compile(r"P<[A-Z]{3}[A-Z<]{39}")
_MRZ_LINE2_RE = re.compile(r"[A-Z0-9<]{9}\d[A-Z]{3}\d{6}[0-9MF<]\d{6}[0-9<]\d{6}[A-Z0-9<]{2}")

# Payment card (13-19 digits, possibly space/dash separated)
_CARD_RE = re.compile(r"\b(?:\d[ \-]?){13,19}\b")

# API keys
_AWS_KEY_RE     = re.compile(r"\b(AKIA[0-9A-Z]{16})\b")
_AWS_SECRET_RE  = re.compile(r"\b([A-Za-z0-9/+]{40})\b")
_STRIPE_LIVE_RE = re.compile(r"\b(sk_live_[A-Za-z0-9]{24,})\b")
_STRIPE_TEST_RE = re.compile(r"\b(sk_test_[A-Za-z0-9]{24,})\b")
_GITHUB_PAT_RE  = re.compile(r"\b(ghp_[A-Za-z0-9]{20,40}|github_pat_[A-Za-z0-9_]{40,90})\b")
_SENDGRID_RE    = re.compile(r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b")
_JWT_RE         = re.compile(r"\b(eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)\b")
_GENERIC_KEY_RE = re.compile(r"\b([A-Za-z0-9]{32,64})\b")

# Crypto addresses
_BTC_LEGACY_RE  = re.compile(r"\b([13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
_BTC_BECH32_RE  = re.compile(r"\b(bc1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{25,90})\b")
_ETH_RE         = re.compile(r"\b(0x[0-9a-fA-F]{40})\b", re.IGNORECASE)
# Crypto private key: 64 hex chars (raw) OR WIF-like base58 starting with 5/K/L
# Using broader charset to catch test/truncated keys
_CRYPTO_PRIVATE_RE = re.compile(r"\b([0-9a-fA-F]{64}|[5KL][A-Za-z0-9]{43,55})\b")

# Pakistani phone numbers
_PK_PHONE_RE = re.compile(
    r"\b(?:\+92|0092|92|0)(3[0-9]{2})[\s\-]?(\d{7})\b"
)
_INTL_PHONE_RE = re.compile(r"\+[1-9]\d{7,14}\b")

# Plain username (no @, 3-30 alphanum/underscore, not a URL/email)
_USERNAME_RE = re.compile(r"(?<![/@\w])([A-Za-z][A-Za-z0-9_.]{2,29})(?![/@\w\.])")

# URL shorteners
_SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "short.io", "rb.gy", "tiny.cc", "cutt.ly",
}

SOCIAL_PLATFORMS = {
    "instagram.com", "twitter.com", "x.com", "tiktok.com",
    "facebook.com", "fb.com", "linkedin.com", "youtube.com",
    "snapchat.com", "threads.net",
}


# ── Extracted entity container ────────────────────────────────────────────────

@dataclass
class ExtractedEntities:
    urls: List[str] = field(default_factory=list)
    social_urls: List[dict] = field(default_factory=list)  # [{url, platform, handle}]
    handles: List[str] = field(default_factory=list)       # @-prefixed
    emails: List[str] = field(default_factory=list)
    cnics: List[str] = field(default_factory=list)
    ibans: List[str] = field(default_factory=list)
    mrz_pairs: List[dict] = field(default_factory=list)    # [{line1, line2}]
    cards: List[str] = field(default_factory=list)
    api_keys: List[dict] = field(default_factory=list)     # [{value, service}]
    crypto_addresses: List[dict] = field(default_factory=list)  # [{value, chain}]
    crypto_private_keys: List[str] = field(default_factory=list)
    phone_numbers: List[str] = field(default_factory=list)
    passwords: List[str] = field(default_factory=list)
    usernames: List[str] = field(default_factory=list)     # plain (no @)
    raw_text_for_smishing: Optional[str] = None
    has_image: bool = False
    has_video: bool = False
    has_audio: bool = False

    def has_any(self) -> bool:
        return any([
            self.urls, self.social_urls, self.handles, self.emails,
            self.cnics, self.ibans, self.mrz_pairs, self.cards,
            self.api_keys, self.crypto_addresses, self.crypto_private_keys,
            self.phone_numbers, self.passwords, self.usernames,
        ])


# ── Main extractor ────────────────────────────────────────────────────────────

def extract(text: str, media_type: Optional[str] = None) -> ExtractedEntities:
    """
    Extract all recognisable entities from a WhatsApp message.
    media_type: 'image' | 'video' | 'audio' | None
    """
    ent = ExtractedEntities()
    if not text:
        text = ""

    # Media flags
    if media_type == "image":
        ent.has_image = True
    elif media_type == "video":
        ent.has_video = True
    elif media_type == "audio":
        ent.has_audio = True

    # ── Explicit /check password: ... ────────────────────────────────────────
    # Match "password: value" or "/check password value" but NOT "is this password saved"
    # Requires either /check prefix OR a colon after "password"
    pwd_match = re.search(
        r"(?:/check\s+password[\s:]+|password[:\s]*:+\s*)([^\n\r]{4,128})",
        text, re.IGNORECASE
    )
    if pwd_match:
        val = pwd_match.group(1).strip()
        # Must be a single token (no spaces) to be a real password value
        if val and " " not in val:
            ent.passwords.append(val)

    # ── MRZ (must be before generic URL/text to avoid false positives) ────────
    l1_matches = _MRZ_LINE1_RE.findall(text)
    l2_matches = _MRZ_LINE2_RE.findall(text)
    if l1_matches and l2_matches:
        ent.mrz_pairs.append({"line1": l1_matches[0], "line2": l2_matches[0]})

    # ── CNIC ─────────────────────────────────────────────────────────────────
    for m in _CNIC_RE.finditer(text):
        val = m.group(1)
        # Normalize 13-digit unformatted CNIC to formatted version
        if re.match(r"^\d{13}$", val):
            val = f"{val[:5]}-{val[5:12]}-{val[12]}"
        ent.cnics.append(val)

    # ── IBAN ─────────────────────────────────────────────────────────────────
    for m in _IBAN_RE.finditer(text):
        val = m.group(1)
        if len(val) >= 15 and val[:2].isalpha():
            ent.ibans.append(val)

    # ── Crypto private keys (before generic API key) ─────────────────────────
    for m in _CRYPTO_PRIVATE_RE.finditer(text):
        val = m.group(1)
        # 64 hex chars = raw private key
        if len(val) == 64 and re.match(r"^[0-9a-fA-F]+$", val):
            ent.crypto_private_keys.append(val)
        # WIF-like format: starts with 5/K/L, mostly base58, 44-55 chars
        # Note: allow slightly invalid base58 (test keys may have 'l','0','O','I')
        elif val[0] in "5KL" and 44 <= len(val) <= 55:
            # At least 85% of chars should be valid base58
            b58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz0lOI"
            valid_ratio = sum(1 for c in val[1:] if c in b58) / (len(val) - 1)
            if valid_ratio >= 0.85:
                ent.crypto_private_keys.append(val)

    # ── API Keys ─────────────────────────────────────────────────────────────
    def _add_key(value: str, service: str):
        if not any(k["value"] == value for k in ent.api_keys):
            ent.api_keys.append({"value": value, "service": service})

    for m in _AWS_KEY_RE.finditer(text):
        _add_key(m.group(1), "aws_access_key")
    for m in _STRIPE_LIVE_RE.finditer(text):
        _add_key(m.group(1), "stripe_live")
    for m in _STRIPE_TEST_RE.finditer(text):
        _add_key(m.group(1), "stripe_test")
    for m in _GITHUB_PAT_RE.finditer(text):
        _add_key(m.group(1), "github_pat")
    for m in _SENDGRID_RE.finditer(text):
        _add_key(m.group(1), "sendgrid")
    for m in _JWT_RE.finditer(text):
        _add_key(m.group(1), "jwt")

    # ── Crypto addresses ─────────────────────────────────────────────────────
    def _add_crypto(value: str, chain: str):
        if not any(c["value"] == value for c in ent.crypto_addresses):
            ent.crypto_addresses.append({"value": value, "chain": chain})

    for m in _BTC_BECH32_RE.finditer(text):
        _add_crypto(m.group(1), "bitcoin_bech32")
    for m in _BTC_LEGACY_RE.finditer(text):
        val = m.group(1)
        if val not in [c["value"] for c in ent.crypto_addresses]:
            chain = "bitcoin_p2sh" if val.startswith("3") else "bitcoin_legacy"
            _add_crypto(val, chain)
    for m in _ETH_RE.finditer(text):
        _add_crypto(m.group(1), "ethereum")

    # ── Payment cards (16-19 digits, NOT CNICs) ──────────────────────────────
    cnic_digit_set = {re.sub(r"\D","",c) for c in ent.cnics}
    for m in _CARD_RE.finditer(text):
        orig_text = m.group(0)
        digits = re.sub(r"[\s\-]", "", orig_text)
        if 13 <= len(digits) <= 19 and digits.isdigit():
            # Skip if original text matches CNIC pattern (5-7-1 with dashes)
            if re.match(r"\d{5}-\d{7}-\d$", orig_text.strip()):
                continue
            # Skip if digits match a CNIC's digit-only form
            if digits in cnic_digit_set or digits[:13] in {d[:13] for d in cnic_digit_set}:
                continue
            ent.cards.append(digits)

    # ── Phone numbers ─────────────────────────────────────────────────────────
    for m in _PK_PHONE_RE.finditer(text):
        num = f"+92{m.group(1)}{m.group(2)}"
        if num not in ent.phone_numbers:
            ent.phone_numbers.append(num)
    for m in _INTL_PHONE_RE.finditer(text):
        num = m.group(0)
        if not num.startswith("+92") and num not in ent.phone_numbers:
            ent.phone_numbers.append(num)

    # ── Password-like strings (3-of-4 criteria) ─────────────────────────────
    # Requires 3 of 4: uppercase + lowercase + digit + special char
    # Catches: azka@123, P@ssw0rd, Admin@123, MyP@ss!
    # Rejects: Hello, cryptoking99, Laeba.rana
    if (not ent.emails and not ent.urls and not ent.api_keys
            and not ent.cnics and not ent.ibans and not ent.cards
            and not ent.passwords and not ent.crypto_private_keys):
        _st = text.strip()
        _hu = bool(re.search(r"[A-Z]", _st))
        _hl = bool(re.search(r"[a-z]", _st))
        _hd = bool(re.search(r"[0-9]", _st))
        _hs = bool(re.search(r"[@#!$%^&*+=]", _st))
        _nc = sum([_hu, _hl, _hd, _hs])
        if (6 <= len(_st) <= 64
                and " " not in _st
                and not _st.startswith("/")
                and not _st.startswith("@")
                and _nc >= 3
                and (_hs or (_hu and _hl and _hd))):
            ent.passwords.append(_st)

    # ── @handles ─────────────────────────────────────────────────────────────
    for m in _HANDLE_RE.finditer(text):
        handle = m.group(1)
        if handle not in ent.handles:
            ent.handles.append(handle)

    # ── Emails ───────────────────────────────────────────────────────────────
    for m in _EMAIL_RE.finditer(text):
        email = m.group(0).lower()
        # Validate: domain must have a dot (azka@123 is NOT an email)
        local, _, domain = email.partition("@")
        if "." in domain and not domain.endswith(".") and email not in ent.emails:
            ent.emails.append(email)
            # Remove from passwords if mistakenly added
            ent.passwords = [p for p in ent.passwords if p.lower() != email]

    # ── URLs ─────────────────────────────────────────────────────────────────
    # First collect email domains to exclude from URL extraction
    email_domains = set()
    for em in ent.emails:
        if "@" in em:
            email_domains.add(em.split("@")[1].lower())

    raw_urls = []
    for m in _URL_RE.finditer(text):
        url = m.group(0)
        # Skip if this "URL" is actually just an email domain
        raw_domain = url.replace("https://","").replace("http://","").split("/")[0].lower()
        if raw_domain in email_domains:
            continue
        if not url.startswith("http"):
            url = "https://" + url
        if url not in raw_urls:
            raw_urls.append(url)

    for url in raw_urls:
        # Check if social platform URL
        sm = _SOCIAL_URL_RE.match(url)
        if sm:
            handle = sm.group(1)
            domain = re.search(r"(?:https?://(?:www\.)?)([\w.]+)", url)
            platform = domain.group(1) if domain else "social"
            ent.social_urls.append({
                "url": url,
                "platform": platform,
                "handle": handle,
            })
        else:
            ent.urls.append(url)

    # ── Smishing — store raw text if short SMS-like message ─────────────────
    if len(text.split()) < 60 and not ent.urls and not ent.has_image:
        ent.raw_text_for_smishing = text

    # ── Plain usernames (only if nothing else found clearly) ─────────────────
    if not any([
        ent.urls, ent.social_urls, ent.handles, ent.emails,
        ent.cnics, ent.ibans, ent.cards, ent.api_keys,
        ent.crypto_addresses, ent.phone_numbers, ent.passwords,
    ]):
        for m in _USERNAME_RE.finditer(text):
            val = m.group(1)
            # Filter out common English words and commands
            if (
                len(val) >= 3
                and not val.lower() in _COMMON_WORDS
                and not val.startswith("/")
                and val not in ent.usernames
            ):
                ent.usernames.append(val)

    return ent


def is_url_shortener(url: str) -> bool:
    try:
        from urllib.parse import urlparse
        domain = urlparse(url).netloc.lower().replace("www.", "")
        return domain in _SHORTENER_DOMAINS
    except Exception:
        return False


def extract_domain(url: str) -> str:
    try:
        from urllib.parse import urlparse
        return urlparse(url).netloc.lower().replace("www.", "")
    except Exception:
        return url


_COMMON_WORDS = {
    "the", "and", "for", "not", "you", "are", "can", "this", "that",
    "with", "have", "from", "they", "will", "your", "but", "what",
    "said", "each", "she", "do", "how", "their", "if", "is", "it",
    "an", "as", "at", "be", "by", "do", "go", "he", "his", "in",
    "me", "my", "no", "of", "on", "or", "so", "to", "up", "us",
    "was", "we", "yes", "yet", "our", "out", "get", "has", "her",
    "him", "its", "let", "may", "new", "old", "see", "set", "try",
    "use", "via", "way", "who", "why", "yes", "scan", "check", "link",
    "please", "help", "thanks", "hello", "hi", "hey",
}
