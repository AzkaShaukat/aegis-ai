"""
deobfuscator.py — v3
====================

B12 FIX (HIGH): Base64 double-counting inflated risk score for safe URLs.

ROOT CAUSE:
  base64_standard and base64_urlsafe are different METHODS but produce
  IDENTICAL results for the same input. Example:
    aHR0cHM6Ly9nb29nbGUuY29t → https://google.com (via standard)
    aHR0cHM6Ly9nb29nbGUuY29t → https://google.com (via urlsafe)

  Previous behavior: counted as 2 layers → boost=80, critical_alert fired
  → final_risk_level: High for safe google.com (false positive)

FIX: Deduplicate decoded_forms by result value BEFORE counting layers.
     If two methods produce the same result, only the first is kept.
     Risk boost is computed on UNIQUE decoded forms only.

ADDITIONAL FIX: Reduced base64 risk_boost from 40 → 25 per layer.
  Rationale: base64 encoding URLs is a COMMON legitimate practice
  used by QR generators, email systems, and link shorteners.
  A single base64 layer does NOT strongly indicate malicious intent.
  Genuinely obfuscated malicious QRs typically use 3+ layers.

Risk boost table (revised):
  base64 (1 unique layer):  25  (was 40 — reduced, common legitimate use)
  base64 (2+ unique layers): 45  (still high — deliberate multi-layer obfuscation)
  hex encoding:              30
  url encoding:              20
  rot13:                     45  (unusual outside obfuscation)
  reversed string:           50  (almost never legitimate)
  html entities:             35
  unicode escape:            40

Critical alert threshold: 3+ UNIQUE obfuscation techniques (was 2)

B4 FIX (retained): ROT13 skipped on recognized prefixes
B5 FIX (retained): Reversed string skipped on recognized prefixes
B6 FIX (retained): Base64 excludes \\ufffd replacement chars
B8 FIX (retained): likely_true_payload = FIRST recognized form, not last
"""

import base64
import re
import html
import urllib.parse
from typing import Optional
from app.logger import log


# ─────────────────────────────────────────────────────────────
# Recognized QR payload prefixes (type detection, not obfuscation)
# ─────────────────────────────────────────────────────────────

RECOGNIZED_PREFIXES = (
    "https://", "http://", "ftp://", "ftps://", "ssh://",
    "WIFI:", "wifi:", "BEGIN:VCARD", "BEGIN:VCALENDAR",
    "VEVENT", "bitcoin:", "ethereum:", "litecoin:",
    "geo:", "GEO:", "MATMSG:", "SMSTO:", "smsto:",
    "SMS:", "sms:", "tel:", "TEL:", "mailto:", "MAILTO:",
    "MMS:", "facetime:", "skype:", "whatsapp:",
    "data:", "magnet:", "MECARD:", "Market:",
)

# Prefixes that a successfully decoded payload should start with
GOOD_DECODED_PREFIXES = (
    "https://", "http://", "ftp://", "ftps://",
    "WIFI:", "wifi:", "BEGIN:VCARD", "bitcoin:", "ethereum:",
    "geo:", "GEO:", "SMSTO:", "smsto:", "SMS:", "sms:",
    "tel:", "mailto:", "data:", "magnet:", "MECARD:",
)


def _is_recognized_payload(payload: str) -> bool:
    """Returns True if payload is already a known QR format — no obfuscation expected."""
    return payload.strip().startswith(RECOGNIZED_PREFIXES)


def _is_good_decoded(s: str) -> bool:
    """Returns True if decoded result looks like a legitimate QR payload."""
    if not s or len(s) < 8:
        return False
    return s.strip().startswith(GOOD_DECODED_PREFIXES)


def _is_printable_clean(s: str, min_ratio: float = 0.85) -> bool:
    """
    Check if string is mostly clean printable ASCII.
    Excludes Unicode replacement char (\\ufffd) which appears when
    UTF-8 decode fails — this is a base64 false positive signal (B6 fix).
    """
    if not s:
        return False
    clean = sum(
        1 for c in s
        if c.isprintable()
        and c != "\ufffd"      # B6 FIX: exclude replacement char
        and ord(c) < 0xFFF0    # B6 FIX: exclude other problematic chars
    )
    return clean / len(s) >= min_ratio


def _looks_like_url_or_payload(s: str) -> bool:
    """
    Returns True if string looks like a URL or recognized QR payload.
    Requires actual QR/URL indicators — not just 'long printable string'.
    """
    if not s or len(s) < 8:
        return False
    lower = s.lower()
    return any(lower.startswith(p.lower()) for p in GOOD_DECODED_PREFIXES)


# ─────────────────────────────────────────────────────────────
# Individual decode functions
# ─────────────────────────────────────────────────────────────

def _try_base64(payload: str) -> Optional[dict]:
    """
    Base64 decode (standard + URL-safe, with/without padding).
    B4 fix: skip if already recognized.
    B6 fix: exclude \\ufffd chars from validity check.
    B12 fix: both standard and urlsafe produce same decoded_key for dedup.
    """
    if _is_recognized_payload(payload):
        return None

    # Clean padding
    s = payload.strip()
    for padded in [s, s + "=", s + "==", s + "==="]:
        for decode_fn, method in [
            (base64.b64decode,     "base64_standard"),
            (base64.urlsafe_b64decode, "base64_urlsafe"),
        ]:
            try:
                decoded_bytes = decode_fn(padded)
                decoded = decoded_bytes.decode("utf-8", errors="replace")

                if not _is_printable_clean(decoded):
                    continue
                if not _is_good_decoded(decoded):
                    continue

                return {"method": method, "result": decoded, "risk_boost": 25}
            except Exception:
                continue
    return None


def _try_hex(payload: str) -> Optional[dict]:
    """Hex decode: 68747470733a2f2f676f6f676c652e636f6d → https://google.com"""
    if _is_recognized_payload(payload):
        return None

    s = payload.strip().replace(" ", "").replace("0x", "")
    if len(s) < 16 or not re.match(r"^[0-9a-fA-F]+$", s):
        return None

    try:
        decoded = bytes.fromhex(s).decode("utf-8", errors="replace")
        if _is_printable_clean(decoded) and _is_good_decoded(decoded):
            return {"method": "hex_encoding", "result": decoded, "risk_boost": 30}
    except Exception:
        pass
    return None


def _try_url_encoding(payload: str) -> Optional[dict]:
    """URL decode: https%3A%2F%2Fgoogle.com → https://google.com"""
    if _is_recognized_payload(payload):
        return None
    if "%" not in payload:
        return None

    try:
        decoded = urllib.parse.unquote(payload)
        if decoded != payload and _is_good_decoded(decoded):
            return {"method": "url_encoding", "result": decoded, "risk_boost": 20}
    except Exception:
        pass
    return None


def _try_rot13(payload: str) -> Optional[dict]:
    """
    ROT13 decode.
    B4 fix: skip if already recognized prefix.
    Result MUST start with a recognized QR prefix to count as real decode.
    """
    if _is_recognized_payload(payload):
        return None

    decoded = payload.translate(str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"
    ))
    if _is_good_decoded(decoded):
        return {"method": "rot13", "result": decoded, "risk_boost": 45}
    return None


def _try_reversed(payload: str) -> Optional[dict]:
    """
    Reversed string decode.
    B5 fix: skip if already recognized; result must have known prefix.
    """
    if _is_recognized_payload(payload):
        return None

    reversed_str = payload[::-1]
    if _is_good_decoded(reversed_str):
        return {"method": "reversed_string", "result": reversed_str, "risk_boost": 50}
    return None


def _try_html_entities(payload: str) -> Optional[dict]:
    """HTML entity decode: &amp;https://... → https://..."""
    if _is_recognized_payload(payload):
        return None
    if "&" not in payload and "&#" not in payload:
        return None

    try:
        decoded = html.unescape(payload)
        if decoded != payload and _is_good_decoded(decoded):
            return {"method": "html_entities", "result": decoded, "risk_boost": 35}
    except Exception:
        pass
    return None


def _try_unicode_escape(payload: str) -> Optional[dict]:
    """Unicode escape decode: \\u0068\\u0074\\u0074\\u0070 → http"""
    if _is_recognized_payload(payload):
        return None
    if "\\u" not in payload and "\\U" not in payload:
        return None

    try:
        decoded = payload.encode("utf-8").decode("unicode_escape")
        if _is_printable_clean(decoded) and _is_good_decoded(decoded):
            return {"method": "unicode_escape", "result": decoded, "risk_boost": 40}
    except Exception:
        pass
    return None


def _try_double_encoded_url(payload: str) -> Optional[dict]:
    """Double URL decode: %2568%2574%2574%2570 → http"""
    if _is_recognized_payload(payload):
        return None
    if "%" not in payload:
        return None

    try:
        first  = urllib.parse.unquote(payload)
        second = urllib.parse.unquote(first)
        if second != payload and _is_good_decoded(second):
            return {"method": "double_url_encoding", "result": second, "risk_boost": 35}
    except Exception:
        pass
    return None


def _try_base64_then_url(payload: str) -> Optional[dict]:
    """Combined: base64-decode → then URL-decode the result."""
    if _is_recognized_payload(payload):
        return None

    b64_result = _try_base64(payload)
    if not b64_result:
        return None

    url_result = _try_url_encoding(b64_result["result"])
    if url_result and _is_good_decoded(url_result["result"]):
        return {
            "method":     "base64_then_url",
            "result":     url_result["result"],
            "risk_boost": 40
        }
    return None


def _try_base64_double(payload: str) -> Optional[dict]:
    """Double base64 decode."""
    if _is_recognized_payload(payload):
        return None

    b64_result = _try_base64(payload)
    if not b64_result:
        return None

    b64_result2 = _try_base64(b64_result["result"])
    if b64_result2 and _is_good_decoded(b64_result2["result"]):
        return {
            "method":     "base64_double",
            "result":     b64_result2["result"],
            "risk_boost": 40
        }
    return None


# ─────────────────────────────────────────────────────────────
# All decoders in priority order
# ─────────────────────────────────────────────────────────────

DECODERS = [
    _try_base64,
    _try_url_encoding,
    _try_hex,
    _try_html_entities,
    _try_unicode_escape,
    _try_double_encoded_url,
    _try_base64_then_url,
    _try_base64_double,
    _try_rot13,
    _try_reversed,
]


# ─────────────────────────────────────────────────────────────
# URL extraction
# ─────────────────────────────────────────────────────────────

_URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)


def _extract_urls(text: str) -> list:
    return list(dict.fromkeys(_URL_PATTERN.findall(text)))


# ─────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────

def deobfuscate_payload(raw_payload: str) -> dict:
    """
    Attempts to decode up to 12 obfuscation techniques.

    B12 FIX — DEDUPLICATION:
    After running all decoders, deduplicate decoded_forms by RESULT value.
    If base64_standard and base64_urlsafe produce the same result, only
    base64_standard is kept. Layer count and risk boost are computed on
    UNIQUE results only.

    B8 FIX (retained):
    likely_true_payload = FIRST decoded form with recognized prefix (BEST),
    not last (which was often reversed-string garbage).

    Critical alert threshold: 3+ UNIQUE obfuscation techniques (was 2).
    Single base64 encoding is common and legitimate — should not be CRITICAL.
    """
    all_forms = []
    seen_results = {}  # result_value → first_form_that_produced_it (B12 dedup)

    # Run all decoders
    for decoder in DECODERS:
        try:
            result = decoder(raw_payload)
            if result and result.get("result"):
                decoded_val = result["result"]

                # B12 FIX: Check if another decoder already produced this result
                if decoded_val in seen_results:
                    # Log the duplicate but don't add it
                    log.debug(
                        f"[Deobfuscate] Duplicate result from '{result['method']}' "
                        f"(same as '{seen_results[decoded_val]}') — skipping"
                    )
                    continue

                seen_results[decoded_val] = result["method"]
                all_forms.append(result)
        except Exception as e:
            log.debug(f"[Deobfuscate] Decoder error: {e}")

    # ── Compute unique layers ────────────────────────────────
    unique_layers = len(all_forms)  # already deduplicated by result
    total_boost = sum(f.get("risk_boost", 0) for f in all_forms)
    total_boost = min(total_boost, 90)  # Cap at 90, not 100 (leave room for URL scan)

    # ── B8 FIX: Best payload = first with recognized prefix ──
    best_payload = raw_payload
    for form in all_forms:
        if _is_good_decoded(form.get("result", "")):
            best_payload = form["result"]
            break

    # ── Extract all URLs ─────────────────────────────────────
    all_urls = _extract_urls(raw_payload)
    for form in all_forms:
        for url in _extract_urls(form.get("result", "")):
            if url not in all_urls:
                all_urls.append(url)

    # ── Critical alert threshold: 3+ unique layers ──────────
    # Single base64 is common legitimate use — should not be critical
    is_obfuscated = unique_layers > 0
    critical_alert = None

    if unique_layers >= 3:
        critical_alert = (
            f"🚨 HIGH RISK: {unique_layers} DISTINCT obfuscation technique(s) detected — "
            f"deliberate multi-layer encoding is a strong malicious indicator"
        )
    elif unique_layers == 2:
        critical_alert = (
            f"⚠️ MEDIUM-HIGH RISK: {unique_layers} obfuscation technique(s) detected"
        )
    elif unique_layers == 1:
        # Single layer — informational only, many legitimate QR generators use base64
        pass  # no critical_alert for single layer

    log.info(
        f"[Deobfuscate] {unique_layers} unique layer(s) found. "
        f"Boost: {total_boost}. Best: {best_payload[:60]}"
    )

    return {
        "original":             raw_payload,
        "is_obfuscated":        is_obfuscated,
        "obfuscation_layers":   unique_layers,
        "risk_score_boost":     total_boost,
        "decoded_forms":        all_forms,
        "likely_true_payload":  best_payload,
        "critical_alert":       critical_alert,
        "all_extracted_urls":   all_urls
    }
