"""
Password Analyzer — All 12 checklist features:
  P-01  HIBP k-Anonymity (password never transmitted)
  P-02  Shannon entropy calculation
  P-03  zxcvbn realistic crack-time estimate
  P-04  Common password list (2000+ passwords)
  P-05  Keyboard walk detection (QWERTY, numpad patterns)
  P-06  Repeating character detection
  P-07  Date pattern detection (years, dd/mm, mm/dd)
  P-08  Dictionary word detection
  P-09  Urdu Roman wordlist check
  P-10  Leetspeak reversal & re-check
  P-11  Policy compliance (NIST SP 800-63B)
  P-12  Similarity to email / username
"""
import hashlib
import logging
import math
import re
import unicodedata
from typing import Any

import httpx

from app.config import settings
from app.data.password_data import (
    COMMON_PASSWORDS, URDU_ROMAN, LEET_MAP,
    QWERTY_ADJACENCY, COMMON_WALKS
)

logger = logging.getLogger(__name__)


# ── P-01: HIBP k-Anonymity ────────────────────────────────────────────────────
async def check_pwned(password: str) -> dict:
    """
    Check password against HIBP Passwords via k-anonymity.
    Only the first 5 characters of SHA-1 hash are sent.
    Password never transmitted. Completely free, no key needed.
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    try:
        async with httpx.AsyncClient(timeout=settings.HTTP_TIMEOUT) as c:
            r = await c.get(
                f"https://api.pwnedpasswords.com/range/{prefix}",
                headers={"User-Agent": "Aegis-Tier1-Checker",
                         "Add-Padding": "true"},
            )

        if r.status_code != 200:
            return {"available": False, "reason": f"HIBP Passwords returned HTTP {r.status_code}"}

        # Parse k-anonymity response
        count = 0
        for line in r.text.splitlines():
            parts = line.split(":")
            if len(parts) == 2 and parts[0].strip() == suffix:
                count = int(parts[1].strip())
                break

        return {
            "available": True,
            "is_compromised": count > 0,
            "pwned_count": count,
            "method": "k_anonymity",
            "privacy_note": "Only SHA-1 prefix (5 chars) sent — raw password never transmitted",
            "risk": "Critical" if count > 100000 else
                    "High"     if count > 10000  else
                    "Medium"   if count > 100    else
                    "Low"      if count > 0      else "None",
        }

    except Exception as e:
        logger.warning(f"HIBP password error: {e}")
        return {"available": False, "reason": str(e)[:100]}


# ── P-02: Shannon entropy ─────────────────────────────────────────────────────
def calc_entropy(password: str) -> dict:
    """
    Shannon entropy + character pool analysis.
    Entropy bits = log2(pool_size) × length — not perfect but standard.
    """
    if not password:
        return {"entropy_bits": 0, "pool_size": 0}

    # Character set analysis
    has_lower   = bool(re.search(r"[a-z]", password))
    has_upper   = bool(re.search(r"[A-Z]", password))
    has_digit   = bool(re.search(r"\d", password))
    has_special = bool(re.search(r"[^a-zA-Z0-9]", password))

    pool = 0
    if has_lower:   pool += 26
    if has_upper:   pool += 26
    if has_digit:   pool += 10
    if has_special: pool += 33

    charset_entropy = math.log2(pool) * len(password) if pool > 0 else 0

    # Shannon entropy (actual character distribution)
    freq = {}
    for c in password:
        freq[c] = freq.get(c, 0) + 1
    n = len(password)
    shannon = -sum((v / n) * math.log2(v / n) for v in freq.values())

    variety = sum([has_lower, has_upper, has_digit, has_special])

    return {
        "entropy_bits": round(charset_entropy, 1),
        "shannon_entropy": round(shannon, 2),
        "character_variety": variety,
        "has_lowercase": has_lower,
        "has_uppercase": has_upper,
        "has_digits": has_digit,
        "has_special": has_special,
        "unique_chars": len(freq),
        "length": n,
    }


# ── P-03: zxcvbn crack time ───────────────────────────────────────────────────
def calc_zxcvbn(password: str) -> dict:
    """
    Use zxcvbn library for realistic crack time estimation.
    Falls back to entropy-based estimate if library unavailable.
    """
    try:
        from zxcvbn import zxcvbn
        result = zxcvbn(password)
        ct = result.get("crack_times_display", {})
        return {
            "score": result.get("score", 0),  # 0–4
            "score_label": ["Very Weak","Weak","Fair","Strong","Very Strong"][result.get("score", 0)],
            "guesses": result.get("guesses", 0),
            "guesses_log10": result.get("guesses_log10", 0),
            "crack_time_online_throttled": ct.get("online_throttling_100_per_hour", ""),
            "crack_time_online": ct.get("online_no_throttling_10_per_second", ""),
            "crack_time_offline_slow": ct.get("offline_slow_hashing_1e4_per_second", ""),
            "crack_time_offline_fast": ct.get("offline_fast_hashing_1e10_per_second", ""),
            "feedback": result.get("feedback", {}),
            "source": "zxcvbn",
        }
    except ImportError:
        # Fallback using entropy
        ent = calc_entropy(password)
        eb = ent["entropy_bits"]
        if eb < 28:   label, score = "Very Weak", 0
        elif eb < 36: label, score = "Weak", 1
        elif eb < 60: label, score = "Fair", 2
        elif eb < 80: label, score = "Strong", 3
        else:          label, score = "Very Strong", 4
        return {
            "score": score,
            "score_label": label,
            "guesses": int(2 ** (eb * 0.7)),
            "source": "entropy_fallback",
        }


# ── P-04: Common password list ────────────────────────────────────────────────
def check_common(password: str) -> dict:
    """Check against 2000+ most-used passwords."""
    lower = password.lower()
    is_common = lower in COMMON_PASSWORDS
    return {"is_common": is_common,
            "risk": "Critical" if is_common else "None"}


# ── P-05: Keyboard walk detection ────────────────────────────────────────────
def detect_keyboard_walk(password: str) -> dict:
    """
    Detect keyboard walk patterns: qwerty, asdf, 1234, numpad diagonals.
    Checks: QWERTY rows, adjacency chains, reversed walks, numpad.
    """
    lower = password.lower()
    found_walks = []

    # Check against known common walks
    for walk in COMMON_WALKS:
        if walk in lower or walk[::-1] in lower:
            found_walks.append(walk if walk in lower else walk[::-1])

    # Detect adjacency chains (3+ chars in sequence on keyboard)
    def find_adjacency_chain(s: str) -> list:
        chains = []
        current = [s[0]] if s else []
        for i in range(1, len(s)):
            if s[i] in QWERTY_ADJACENCY.get(s[i - 1], []):
                current.append(s[i])
            else:
                if len(current) >= 4:
                    chains.append("".join(current))
                current = [s[i]]
        if len(current) >= 4:
            chains.append("".join(current))
        return chains

    adjacency_chains = find_adjacency_chain(lower)

    # Detect number sequences (ascending/descending)
    def has_number_sequence(s: str, min_len: int = 4) -> str | None:
        digits = re.findall(r"\d+", s)
        for d in digits:
            if len(d) >= min_len:
                seq_asc = all(int(d[i + 1]) == int(d[i]) + 1 for i in range(len(d) - 1))
                seq_desc = all(int(d[i + 1]) == int(d[i]) - 1 for i in range(len(d) - 1))
                if seq_asc or seq_desc:
                    return d
        return None

    number_seq = has_number_sequence(lower)
    if number_seq:
        found_walks.append(number_seq)

    detected = bool(found_walks or adjacency_chains)
    return {
        "detected": detected,
        "walk_patterns": list(set(found_walks)),
        "adjacency_chains": adjacency_chains,
        "number_sequence": number_seq,
    }


# ── P-06: Repeating characters ────────────────────────────────────────────────
def detect_repeating(password: str) -> dict:
    """Detect repeating chars, repeated sequences, leet-style repeats."""
    # Single char repeating
    single_rep = re.search(r"(.)\1{3,}", password)
    # Short sequence repeating
    seq_rep = re.search(r"(.{2,4})\1{2,}", password)
    # Alternating (abababab)
    alternating = re.search(r"(..)\1{3,}", password)

    detected = bool(single_rep or seq_rep or alternating)
    return {
        "detected": detected,
        "single_char_repeat": single_rep.group(0) if single_rep else None,
        "sequence_repeat": seq_rep.group(0) if seq_rep else None,
        "alternating": alternating.group(0) if alternating else None,
    }


# ── P-07: Date patterns ───────────────────────────────────────────────────────
def detect_date_patterns(password: str) -> dict:
    """
    Detect embedded dates: years (19xx, 20xx), dd/mm, mm/dd, month names.
    """
    patterns = {
        "year_19xx": re.search(r"19[0-9]{2}", password),
        "year_20xx": re.search(r"20[0-2][0-9]", password),
        "ddmm":      re.search(r"(0[1-9]|[12]\d|3[01])(0[1-9]|1[0-2])", password),
        "mmdd":      re.search(r"(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])", password),
        "month_name":re.search(
            r"\b(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec|"
            r"january|february|march|april|june|july|august|"
            r"september|october|november|december)\b",
            password.lower()
        ),
        "pk_dates": re.search(r"(1947|1971|1973|23mar|14aug|6sep)", password.lower()),
    }

    found = {k: v.group(0) for k, v in patterns.items() if v}
    return {
        "detected": len(found) > 0,
        "patterns_found": found,
    }


# ── P-08 + P-09: Dictionary word detection ────────────────────────────────────
def check_dictionary(password: str) -> dict:
    """
    Check if password contains common English dictionary words
    or Urdu Roman words.
    """
    lower = password.lower()

    # Simple English wordlist (embedded — subset of most common words)
    _english = {
        "sunshine","shadow","dragon","monkey","princess","football","baseball",
        "the","be","to","of","and","a","in","that","have","it","for",
        "not","on","with","he","as","you","do","at","this","but","his",
        "by","from","they","we","say","her","she","or","an","will","my",
        "one","all","would","there","their","what","so","up","out","if",
        "about","who","get","which","go","me","when","make","can","like",
        "time","no","just","him","know","take","people","into","year",
        "your","good","some","could","them","see","other","than","then",
        "now","look","only","come","its","over","think","also","back",
        "after","use","two","how","our","work","first","well","way","even",
        "new","want","because","any","these","give","day","most","us",
        "love","god","sex","money","fire","water","earth","wind","air",
        "sun","moon","star","blue","red","black","white","green","gold",
        "king","queen","angel","devil","life","death","peace","war",
        "home","family","house","mother","father","sister","brother",
        "baby","friend","heart","dream","hope","faith","trust","power",
        "master","shadow","dragon","monkey","princess","football","baseball",
        "summer","winter","spring","batman","superman","spider","tiger",
        "lion","eagle","wolf","ninja","pirate","knight","wizard","hunter",
        "secret","welcome","password","computer","internet","android",
        "apple","orange","banana","mango","coffee","hello","world",
    }

    found_english = None
    for word in sorted(_english, key=len, reverse=True):
        if len(word) >= 4 and word in lower:
            found_english = word
            break

    found_urdu = None
    for word in sorted(URDU_ROMAN, key=len, reverse=True):
        if len(word) >= 4 and word in lower:
            found_urdu = word
            break

    return {
        "dictionary_word_found": found_english,
        "urdu_roman_found": found_urdu,
        "detected": bool(found_english or found_urdu),
    }


# ── P-10: Leetspeak reversal ──────────────────────────────────────────────────
def reverse_leetspeak(password: str) -> dict:
    """
    Replace l33t chars with their letter equivalents, then re-check dictionary.
    e.g. P@ssw0rd → password → in dictionary = weak
    """
    reversed_chars = {}
    normalized = []
    for char in password.lower():
        if char in LEET_MAP:
            normalized.append(LEET_MAP[char])
            reversed_chars[char] = LEET_MAP[char]
        else:
            normalized.append(char)

    normalized_str = "".join(normalized)
    has_leet = len(reversed_chars) > 0

    # Check normalized form against common passwords and dictionary
    dict_check = check_dictionary(normalized_str)
    is_common_after = normalized_str in COMMON_PASSWORDS

    return {
        "has_leet_substitution": has_leet,
        "leet_chars_found": reversed_chars,
        "normalized_form": normalized_str if has_leet else None,
        "is_weak_after_normalization": dict_check["detected"] or is_common_after,
        "common_after_leet_removal": is_common_after,
    }


# ── P-11: NIST SP 800-63B Policy compliance ───────────────────────────────────
def check_policy(password: str) -> dict:
    """
    NIST SP 800-63B recommendations:
    - Minimum 8 characters (suggest 12+)
    - No length maximum below 64
    - Allow all printable ASCII + Unicode
    - No complexity rules required (but entropy matters)
    """
    issues = []
    n = len(password)

    if n < 8:
        issues.append(f"Too short ({n} chars) — minimum 8 per NIST")
    elif n < 12:
        issues.append(f"Short ({n} chars) — 12+ recommended")

    if n > 64:
        issues.append(f"Very long ({n} chars) — check system allows this")

    # Detect null bytes or control chars
    if any(unicodedata.category(c).startswith("C") for c in password):
        issues.append("Contains control characters — may cause issues")

    variety = sum([
        bool(re.search(r"[a-z]", password)),
        bool(re.search(r"[A-Z]", password)),
        bool(re.search(r"\d", password)),
        bool(re.search(r"[^a-zA-Z0-9]", password)),
    ])

    return {
        "length": n,
        "meets_minimum": n >= 8,
        "meets_recommended": n >= 12,
        "character_variety": variety,
        "policy_issues": issues,
        "nist_compliant": n >= 8 and not any(
            unicodedata.category(c).startswith("C") for c in password
        ),
    }


# ── P-12: Similarity to email / username ─────────────────────────────────────
def check_similarity(password: str, email: str = "", username: str = "") -> dict:
    """
    Detect if password is too similar to email or username.
    Uses Levenshtein distance ratio.
    """
    try:
        import Levenshtein
        results = {}

        if email and "@" in email:
            local = email.split("@")[0].lower()
            full_email = email.lower()
            ratio_local = Levenshtein.ratio(password.lower(), local)
            ratio_full  = Levenshtein.ratio(password.lower(), full_email)
            results["email_local_similarity"] = round(ratio_local, 3)
            results["email_full_similarity"]  = round(ratio_full, 3)
            results["too_similar_to_email"]   = max(ratio_local, ratio_full) > 0.6

        if username:
            ratio_user = Levenshtein.ratio(password.lower(), username.lower())
            results["username_similarity"]       = round(ratio_user, 3)
            results["too_similar_to_username"]   = ratio_user > 0.6

        results["available"] = True
        return results
    except ImportError:
        # Fallback: simple substring check
        results = {"available": True, "note": "Levenshtein not installed — using substring check"}
        if email:
            local = email.split("@")[0].lower() if "@" in email else email.lower()
            results["too_similar_to_email"] = local in password.lower() or password.lower() in local
        if username:
            results["too_similar_to_username"] = (username.lower() in password.lower() or
                                                   password.lower() in username.lower())
        return results


# ── Master password scanner ────────────────────────────────────────────────────
async def analyze_password(password: str, email: str = "", username: str = "") -> dict[str, Any]:
    """
    Run all 12 password analysis features.
    Raw password NEVER stored or logged.
    Returns comprehensive result with overall risk score.
    """
    # ── Synchronous checks ────────────────────────────────────────────────────
    entropy    = calc_entropy(password)
    zxcvbn_r   = calc_zxcvbn(password)
    common     = check_common(password)
    kb_walk    = detect_keyboard_walk(password)
    repeating  = detect_repeating(password)
    date_pat   = detect_date_patterns(password)
    dictionary = check_dictionary(password)
    leet       = reverse_leetspeak(password)
    policy     = check_policy(password)
    similarity = check_similarity(password, email, username)

    # ── Async: HIBP k-anonymity ────────────────────────────────────────────────
    pwned = await check_pwned(password)

    # ── Score aggregation ─────────────────────────────────────────────────────
    score = 0
    flags = []

    # HIBP
    if pwned.get("is_compromised"):
        pc = pwned.get("pwned_count", 0)
        score += 40
        flags.append(f"Password found in {pc:,} known data breach records (HIBP)")

    # zxcvbn score (0=very weak → 4=very strong)
    zs = zxcvbn_r.get("score", 0)
    score += max(0, (3 - zs) * 10)  # 0 for score 3+, 30 for score 0

    # Common
    if common["is_common"]:
        score += 30
        flags.append("Password is on the list of most commonly used passwords")

    # Keyboard walk
    if kb_walk["detected"]:
        score += 20
        flags.append(f"Keyboard walk pattern detected: {kb_walk.get('walk_patterns') or kb_walk.get('adjacency_chains')}")

    # Repeating
    if repeating["detected"]:
        score += 15
        if repeating.get("single_char_repeat"):
            flags.append(f"Repeating characters: {repeating['single_char_repeat']!r}")
        if repeating.get("sequence_repeat"):
            flags.append(f"Repeating sequence: {repeating['sequence_repeat']!r}")

    # Date pattern
    if date_pat["detected"]:
        score += 10
        flags.append(f"Date patterns found: {list(date_pat['patterns_found'].values())}")

    # Dictionary
    if dictionary["detected"]:
        score += 15
        if dictionary["dictionary_word_found"]:
            flags.append(f"Contains dictionary word: '{dictionary['dictionary_word_found']}'")
        if dictionary["urdu_roman_found"]:
            flags.append(f"Contains Urdu Roman word: '{dictionary['urdu_roman_found']}'")

    # Leet
    if leet["has_leet_substitution"] and leet["is_weak_after_normalization"]:
        score += 15
        flags.append(f"Leetspeak substitution hiding weak word: '{leet['normalized_form']}'")

    # Policy
    if not policy["meets_minimum"]:
        score += 25
        flags.append(f"Too short ({policy['length']} chars) — minimum 8 required")
    elif not policy["meets_recommended"]:
        score += 5
        flags.append(f"Short ({policy['length']} chars) — 12+ recommended for strong security")

    # Similarity
    if similarity.get("too_similar_to_email"):
        score += 20
        flags.append("Password too similar to email address")
    if similarity.get("too_similar_to_username"):
        score += 20
        flags.append("Password too similar to username")

    # Low entropy
    if entropy["entropy_bits"] < 28:
        score += 20
        flags.append(f"Very low entropy ({entropy['entropy_bits']} bits) — highly guessable")
    elif entropy["entropy_bits"] < 50:
        score += 5

    score = min(score, 100)

    if score < 16:   level = "Clean"
    elif score < 36: level = "Low"
    elif score < 56: level = "Medium"
    elif score < 76: level = "High"
    else:            level = "Critical"

    return {
        "credential_type": "password",
        "privacy_note": "Raw password never stored, logged, or transmitted — SHA-1 prefix only (k-anonymity)",
        "length": policy["length"],
        "entropy": entropy,
        "zxcvbn": zxcvbn_r,
        "hibp_pwned": pwned,
        "common_password": common,
        "keyboard_walk": kb_walk,
        "repeating_chars": repeating,
        "date_patterns": date_pat,
        "dictionary": dictionary,
        "leetspeak": leet,
        "policy": policy,
        "similarity": similarity,
        "overall_risk_score": score,
        "overall_risk_level": level,
        "all_flags": flags,
    }
