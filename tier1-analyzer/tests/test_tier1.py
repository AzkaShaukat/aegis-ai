#!/usr/bin/env python3
"""
================================================================
  Aegis AI — Tier 1 Automated Test Suite
  Sends real HTTP requests to localhost:8003 and verifies
  every expected field/value against the actual response.

  USAGE:
      pip install httpx colorama
      python test_tier1.py                  # run all
      python test_tier1.py --email          # only email tests
      python test_tier1.py --password       # only password tests
      python test_tier1.py --username       # only username tests
      python test_tier1.py --verbose        # show full response on fail

  REQUIREMENTS:
      Docker running:  docker-compose up
      API on:          http://localhost:8003
================================================================
"""

import argparse
import json
import sys
import time
import traceback
from dataclasses import dataclass, field
from typing import Any

try:
    import httpx
except ImportError:
    print("ERROR: httpx not installed — run:  pip install httpx colorama")
    sys.exit(1)

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    GREEN  = Fore.GREEN
    RED    = Fore.RED
    YELLOW = Fore.YELLOW
    CYAN   = Fore.CYAN
    BOLD   = Style.BRIGHT
    RESET  = Style.RESET_ALL
except ImportError:
    GREEN = RED = YELLOW = CYAN = BOLD = RESET = ""

BASE = "http://localhost:8006"
TIMEOUT = 30.0


# ═══════════════════════════════════════════════════════════════════════════════
# TEST ENGINE
# ═══════════════════════════════════════════════════════════════════════════════
@dataclass
class TestResult:
    test_id:   str
    name:      str
    passed:    bool
    skipped:   bool   = False
    skip_reason: str  = ""
    failures:  list   = field(default_factory=list)
    response:  dict   = field(default_factory=dict)
    elapsed_ms: float = 0.0


def _get_nested(obj: Any, path: str) -> Any:
    """Navigate dot-notation path through nested dict/list."""
    keys = path.split(".")
    cur = obj
    for k in keys:
        if cur is None:
            return None
        if isinstance(cur, dict):
            cur = cur.get(k)
        elif isinstance(cur, list) and k.isdigit():
            i = int(k)
            cur = cur[i] if i < len(cur) else None
        else:
            return None
    return cur


def check(response: dict, assertions: dict) -> list[str]:
    """
    assertions format:
      "field.path":     expected_value          # equality
      "field.path__gt": number                  # greater than
      "field.path__gte": number                 # >=
      "field.path__lt": number                  # less than
      "field.path__in": [list]                  # value in list
      "field.path__contains": "string"          # string contains
      "field.path__exists": True/False          # key exists
      "field.path__type": "str"/"int"/"list"    # type check
      "field.path__truthy": True                # bool(value) is True
      "field.path__not": value                  # not equal
    """
    failures = []
    for expr, expected in assertions.items():
        # Split off operator
        if "__" in expr.rsplit(".", 1)[-1]:
            parts = expr.rsplit("__", 1)
            path, op = parts[0], parts[1]
        else:
            path, op = expr, "eq"

        actual = _get_nested(response, path)

        try:
            if op == "eq":
                if actual != expected:
                    failures.append(f"  ✗ {path}: expected {expected!r}, got {actual!r}")
            elif op == "not":
                if actual == expected:
                    failures.append(f"  ✗ {path}: expected NOT {expected!r}, got {actual!r}")
            elif op == "gt":
                if not (isinstance(actual, (int, float)) and actual > expected):
                    failures.append(f"  ✗ {path}: expected > {expected}, got {actual!r}")
            elif op == "gte":
                if not (isinstance(actual, (int, float)) and actual >= expected):
                    failures.append(f"  ✗ {path}: expected >= {expected}, got {actual!r}")
            elif op == "lt":
                if not (isinstance(actual, (int, float)) and actual < expected):
                    failures.append(f"  ✗ {path}: expected < {expected}, got {actual!r}")
            elif op == "in":
                if actual not in expected:
                    failures.append(f"  ✗ {path}: expected one of {expected}, got {actual!r}")
            elif op == "contains":
                if not (isinstance(actual, (str, list)) and expected in actual):
                    failures.append(f"  ✗ {path}: expected to contain {expected!r}, got {actual!r}")
            elif op == "exists":
                exists = actual is not None
                if exists != expected:
                    failures.append(f"  ✗ {path}: expected exists={expected}, got {actual!r}")
            elif op == "type":
                type_map = {"str": str, "int": int, "float": float,
                            "list": list, "dict": dict, "bool": bool, "none": type(None)}
                expected_type = type_map.get(expected)
                if expected_type and not isinstance(actual, expected_type):
                    failures.append(f"  ✗ {path}: expected type {expected}, got {type(actual).__name__} ({actual!r})")
            elif op == "truthy":
                if bool(actual) != expected:
                    failures.append(f"  ✗ {path}: expected truthy={expected}, got {actual!r}")
            elif op == "len_gt":
                if not (isinstance(actual, (str, list, dict)) and len(actual) > expected):
                    failures.append(f"  ✗ {path}: expected len > {expected}, got len={len(actual) if actual else 'N/A'}")
            elif op == "absent":
                # Value should NOT be in the response string (privacy check)
                resp_str = json.dumps(response)
                if expected in resp_str:
                    failures.append(f"  ✗ PRIVACY VIOLATION: '{expected}' found in response — must be absent")
        except Exception as e:
            failures.append(f"  ✗ {path}: assertion error — {e}")

    return failures


def post(endpoint: str, payload: dict, timeout=TIMEOUT) -> tuple[dict, float]:
    t0 = time.perf_counter()
    try:
        r = httpx.post(f"{BASE}{endpoint}", json=payload,headers={"X-API-Key": "1122"}, timeout=timeout)
        elapsed = (time.perf_counter() - t0) * 1000
        if r.status_code not in (200, 201):
            return {"_http_error": r.status_code, "_body": r.text[:300]}, elapsed
        return r.json(), elapsed
    except httpx.ConnectError:
        return {"_connection_error": f"Cannot connect to {BASE} — is Docker running?"}, 0
    except Exception as e:
        return {"_error": str(e)}, 0


def run_test(test_id: str, name: str, endpoint: str, payload: dict,
             assertions: dict, skip_if: str = "") -> TestResult:
    if skip_if:
        return TestResult(test_id=test_id, name=name, passed=True,
                          skipped=True, skip_reason=skip_if)

    response, elapsed = post(endpoint, payload)

    if "_connection_error" in response:
        return TestResult(test_id=test_id, name=name, passed=False,
                          failures=[response["_connection_error"]], elapsed_ms=elapsed)
    if "_http_error" in response:
        return TestResult(test_id=test_id, name=name, passed=False,
                          failures=[f"HTTP {response['_http_error']}: {response.get('_body', '')}"],
                          elapsed_ms=elapsed)

    failures = check(response, assertions)
    return TestResult(test_id=test_id, name=name, passed=len(failures) == 0,
                      failures=failures, response=response, elapsed_ms=round(elapsed, 1))


# ═══════════════════════════════════════════════════════════════════════════════
# EMAIL TESTS — 28 test cases covering all 9 features
# ═══════════════════════════════════════════════════════════════════════════════
EMAIL_TESTS = [

    # ── E-01: Syntax ─────────────────────────────────────────────────────────
    dict(id="E-SYN-001", name="Valid email — syntax passes",
         payload={"value": "valid.user@gmail.com"},
         expect={"syntax.valid": True}),

    dict(id="E-SYN-002", name="Missing @ symbol — syntax fails",
         payload={"value": "notanemail"},
         expect={"syntax.valid": False,
                 "overall_risk_score__gte": 60}),

    dict(id="E-SYN-003", name="Double @ — syntax fails",
         payload={"value": "user@@gmail.com"},
         expect={"syntax.valid": False}),

    dict(id="E-SYN-004", name="Local part starts with dot — flagged",
         payload={"value": ".user@gmail.com"},
         expect={"syntax.flags__len_gt": 0}),

    # ── E-02: Normalization ───────────────────────────────────────────────────
    dict(id="E-NRM-001", name="Gmail dots removed",
         payload={"value": "j.o.h.n@gmail.com"},
         expect={"normalization.normalized": "john@gmail.com",
                 "normalization.is_gmail_normalized": True}),

    dict(id="E-NRM-002", name="Gmail plus tag stripped",
         payload={"value": "john+work@gmail.com"},
         expect={"normalization.is_subaddressed": True,
                 "normalization.sub_address_tag": "work",
                 "normalization.normalized": "john@gmail.com"}),

    dict(id="E-NRM-003", name="Combined dots + plus tag",
         payload={"value": "J.O.H.N+spam@Gmail.com"},
         expect={"normalization.normalized": "john@gmail.com",
                 "normalization.is_subaddressed": True,
                 "normalization.is_gmail_normalized": True}),

    dict(id="E-NRM-004", name="Googlemail normalised to gmail",
         payload={"value": "user@googlemail.com"},
         expect={"normalization.normalized": "user@gmail.com"}),

    dict(id="E-NRM-005", name="Non-Gmail plus tag — still detects subaddress",
         payload={"value": "user+tag@outlook.com"},
         expect={"normalization.is_subaddressed": True,
                 "normalization.sub_address_tag": "tag"}),

    # ── E-03: Homoglyphs ──────────────────────────────────────────────────────
    dict(id="E-HOM-001", name="Cyrillic 'о' in local part detected",
         payload={"value": "j\u043ehn@gmail.com"},
         expect={"homoglyphs.detected": True,
                 "homoglyphs.count__gte": 1,
                 "overall_risk_score__gte": 30}),

    dict(id="E-HOM-002", name="Mixed Latin + Cyrillic script flagged",
         payload={"value": "use\u0440@gmail.com"},
         expect={"homoglyphs.detected": True,
                 "homoglyphs.mixed_script": True}),

    dict(id="E-HOM-003", name="Pure ASCII email — no homoglyphs",
         payload={"value": "cleanuser@gmail.com"},
         expect={"homoglyphs.detected": False,
                 "homoglyphs.count": 0}),

    # ── E-04: Disposable ──────────────────────────────────────────────────────
    dict(id="E-DSP-001", name="Mailinator flagged as disposable",
         payload={"value": "attacker@mailinator.com"},
         expect={"disposable.is_disposable": True,
                 "disposable.service_name": "Mailinator",
                 "overall_risk_score__gte": 15}),

    dict(id="E-DSP-002", name="Guerrilla Mail flagged",
         payload={"value": "test@guerrillamail.com"},
         expect={"disposable.is_disposable": True,
                 "disposable.service_name": "Guerrilla Mail"}),

    dict(id="E-DSP-003", name="10 Minute Mail flagged",
         payload={"value": "noreply@10minutemail.com"},
         expect={"disposable.is_disposable": True}),

    dict(id="E-DSP-004", name="YOPmail flagged",
         payload={"value": "user@yopmail.com"},
         expect={"disposable.is_disposable": True,
                 "disposable.service_name": "YOPmail"}),

    dict(id="E-DSP-005", name="Gmail NOT flagged as disposable",
         payload={"value": "legit@gmail.com"},
         expect={"disposable.is_disposable": False}),

    dict(id="E-DSP-006", name="Outlook NOT flagged as disposable",
         payload={"value": "someone@outlook.com"},
         expect={"disposable.is_disposable": False}),

    # ── E-05: MX check ────────────────────────────────────────────────────────
    dict(id="E-MX-001", name="Gmail has valid MX records",
         payload={"value": "user@gmail.com"},
         expect={"mx_check.has_mx": True,
                 "mx_check.mx_count__gte": 1}),

    dict(id="E-MX-002", name="Non-existent domain has no MX",
         payload={"value": "user@thisdomain-does-not-exist-ever.xyz"},
         expect={"mx_check.has_mx": False,
                 "overall_risk_score__gte": 20}),

    # ── E-06: HIBP ────────────────────────────────────────────────────────────
    dict(id="E-HIBP-001", name="HIBP: returns valid structure (key optional)",
         payload={"value": "test@example.com"},
         expect={"hibp__type": "dict",
                 "hibp.available__type": "bool"}),

    dict(id="E-HIBP-002", name="HIBP: structure present for any email",
         payload={"value": "zqxjwvk99@norealdomain-aegis-test.io"},
         expect={"hibp__type": "dict",
                 "hibp.available__type": "bool"}),

    # ── E-07: Paste search ────────────────────────────────────────────────────
    dict(id="E-PST-001", name="Paste search returns valid structure",
         payload={"value": "test@example.com"},
         expect={"pastes__type": "dict",
                 "pastes.source": "psbdmp.ws"}),

    # ── E-08: Reputation ──────────────────────────────────────────────────────
    dict(id="E-REP-001", name="EmailRep returns valid structure",
         payload={"value": "test@gmail.com"},
         expect={"reputation__type": "dict",
                 "reputation.source": "emailrep.io"}),

    # ── E-09: Domain age ──────────────────────────────────────────────────────
    dict(id="E-AGE-001", name="gmail.com domain age is many years old",
         payload={"value": "user@gmail.com"},
         expect={"domain_age.available": True,
                 "domain_age.age_days__gt": 3000,
                 "domain_age.is_newly_registered": False}),

    # ── End-to-end risk scoring ───────────────────────────────────────────────
    dict(id="E-RSK-001", name="High-risk email: disposable + homoglyph combo",
         payload={"value": "j\u043ehn@mailinator.com"},
         expect={"overall_risk_score__gte": 50,
                 "overall_risk_level__in": ["High", "Critical"],
                 "disposable.is_disposable": True,
                 "homoglyphs.detected": True}),

    dict(id="E-RSK-002", name="Clean email has low risk score",
         payload={"value": "ahmed.khan2024@outlook.com"},
         expect={"overall_risk_score__lt": 30,
                 "disposable.is_disposable": False,
                 "homoglyphs.detected": False,
                 "syntax.valid": True}),

    dict(id="E-RSK-003", name="Risk level field is always present",
         payload={"value": "anyone@anywhere.com"},
         expect={"overall_risk_level__in": ["Clean","Low","Medium","High","Critical"],
                 "all_flags__type": "list",
                 "credential_type": "email"}),
]


# ═══════════════════════════════════════════════════════════════════════════════
# PASSWORD TESTS — 32 test cases covering all 12 features
# ═══════════════════════════════════════════════════════════════════════════════
PASSWORD_TESTS = [

    # ── P-01: HIBP k-anonymity ────────────────────────────────────────────────
    dict(id="P-HIBP-001", name="HIBP: 'password' is in millions of breaches",
         payload={"value": "password"},
         expect={"hibp_pwned.available": True,
                 "hibp_pwned.is_compromised": True,
                 "hibp_pwned.pwned_count__gt": 1000000,
                 "hibp_pwned.method": "k_anonymity"}),

    dict(id="P-HIBP-002", name="HIBP: '123456' is in breaches",
         payload={"value": "123456"},
         expect={"hibp_pwned.is_compromised": True,
                 "hibp_pwned.pwned_count__gt": 500000}),

    dict(id="P-HIBP-003", name="HIBP: Novel password not in breaches",
         payload={"value": "ZxQ9!mP3@kLw#v2yR8&nT7qS"},
         expect={"hibp_pwned.is_compromised": False,
                 "hibp_pwned.pwned_count": 0}),

    dict(id="P-PRV-001", name="PRIVACY: raw password never in response body",
         payload={"value": "MySuperSecret99!"},
         expect={"privacy_note__exists": True,
                 # The actual password must not appear anywhere in JSON
                 "hibp_pwned.method__absent": "MySuperSecret99!"}),

    # ── P-02: Entropy ─────────────────────────────────────────────────────────
    dict(id="P-ENT-001", name="Short all-lowercase: very low entropy",
         payload={"value": "abc"},
         expect={"entropy.entropy_bits__lt": 15,
                 "entropy.character_variety__lt": 3}),

    dict(id="P-ENT-002", name="Long mixed-case with symbols: high entropy",
         payload={"value": "Tr0ub4dor&3!"},
         expect={"entropy.entropy_bits__gt": 40,
                 "entropy.has_uppercase": True,
                 "entropy.has_digits": True,
                 "entropy.has_special": True,
                 "entropy.character_variety": 4}),

    dict(id="P-ENT-003", name="Entropy: all same character = low Shannon",
         payload={"value": "aaaaaaaaaa"},
         expect={"entropy.shannon_entropy__lt": 0.5,
                 "entropy.unique_chars": 1}),

    # ── P-03: zxcvbn ─────────────────────────────────────────────────────────
    dict(id="P-ZXC-001", name="zxcvbn: 'password' scores 0 (Very Weak)",
         payload={"value": "password"},
         expect={"zxcvbn.score": 0,
                 "zxcvbn.score_label": "Very Weak"}),

    dict(id="P-ZXC-002", name="zxcvbn: strong passphrase scores 3 or 4",
         payload={"value": "correct-horse-battery-99!"},
         expect={"zxcvbn.score__gte": 3}),

    dict(id="P-ZXC-003", name="zxcvbn: crack time present for all passwords",
         payload={"value": "test"},
         expect={"zxcvbn.score__exists": True,
                 "zxcvbn.score_label__type": "str"}),

    # ── P-04: Common password list ────────────────────────────────────────────
    dict(id="P-CMN-001", name="Common: 'password123' on list",
         payload={"value": "password123"},
         expect={"common_password.is_common": True}),

    dict(id="P-CMN-002", name="Common: 'pakistan' on list",
         payload={"value": "pakistan"},
         expect={"common_password.is_common": True}),

    dict(id="P-CMN-003", name="Common: novel password NOT on list",
         payload={"value": "Zq9!Tm3@Rk#v"},
         expect={"common_password.is_common": False}),

    # ── P-05: Keyboard walk ───────────────────────────────────────────────────
    dict(id="P-KBD-001", name="Keyboard walk: 'qwerty123' detected",
         payload={"value": "qwerty123"},
         expect={"keyboard_walk.detected": True}),

    dict(id="P-KBD-002", name="Keyboard walk: '1234567890' detected",
         payload={"value": "1234567890"},
         expect={"keyboard_walk.detected": True}),

    dict(id="P-KBD-003", name="Keyboard walk: 'asdfghjkl' detected",
         payload={"value": "asdfghjkl"},
         expect={"keyboard_walk.detected": True}),

    dict(id="P-KBD-004", name="Keyboard walk: random string NOT detected",
         payload={"value": "Zx9Qm!Tp2"},
         expect={"keyboard_walk.detected": False}),

    # ── P-06: Repeating chars ────────────────────────────────────────────────
    dict(id="P-REP-001", name="Repeating: 'aaaa1234' detected",
         payload={"value": "aaaa1234"},
         expect={"repeating_chars.detected": True,
                 "repeating_chars.single_char_repeat__exists": True}),

    dict(id="P-REP-002", name="Repeating: 'abababab' sequence detected",
         payload={"value": "abababab"},
         expect={"repeating_chars.detected": True}),

    dict(id="P-REP-003", name="Repeating: no repeats in strong password",
         payload={"value": "Zq9!Tm3@Rk#v"},
         expect={"repeating_chars.detected": False}),

    # ── P-07: Date patterns ───────────────────────────────────────────────────
    dict(id="P-DAT-001", name="Date: year 1990 detected",
         payload={"value": "Ahmed1990"},
         expect={"date_patterns.detected": True,
                 "date_patterns.patterns_found__type": "dict"}),

    dict(id="P-DAT-002", name="Date: '14aug' Pakistan date detected",
         payload={"value": "14august1947"},
         expect={"date_patterns.detected": True}),

    dict(id="P-DAT-003", name="Date: no date in random password",
         payload={"value": "Zq9!Tm3@Rk"},
         expect={"date_patterns.detected": False}),

    # ── P-08+09: Dictionary ───────────────────────────────────────────────────
    dict(id="P-DCT-001", name="Dictionary: 'sunshine' detected",
         payload={"value": "sunshine"},
         expect={"dictionary.detected": True,
                 "dictionary.dictionary_word_found": "sunshine"}),

    dict(id="P-DCT-002", name="Dictionary Urdu: 'pakistan' word",
         payload={"value": "pakistan123"},
         expect={"dictionary.detected": True}),

    # ── P-10: Leetspeak ───────────────────────────────────────────────────────
    dict(id="P-LET-001", name="Leet: 'p@ssw0rd' reversed to 'password'",
         payload={"value": "p@ssw0rd"},
         expect={"leetspeak.has_leet_substitution": True,
                 "leetspeak.is_weak_after_normalization": True}),

    dict(id="P-LET-002", name="Leet: '4dm1n' reversed to 'admin'",
         payload={"value": "4dm1n"},
         expect={"leetspeak.has_leet_substitution": True}),

    # ── P-11: NIST policy ────────────────────────────────────────────────────
    dict(id="P-POL-001", name="Policy: 4-char password fails minimum",
         payload={"value": "abcd"},
         expect={"policy.meets_minimum": False,
                 "policy.length": 4,
                 "policy.nist_compliant": False}),

    dict(id="P-POL-002", name="Policy: 12-char password meets recommendation",
         payload={"value": "ValidPass12!@"},
         expect={"policy.meets_minimum": True,
                 "policy.meets_recommended": True,
                 "policy.nist_compliant": True}),

    # ── P-12: Similarity ─────────────────────────────────────────────────────
    dict(id="P-SIM-001", name="Similarity: password = email local part",
         payload={"value": "ahmed2024", "email": "ahmed2024@gmail.com"},
         expect={"similarity.too_similar_to_email": True}),

    dict(id="P-SIM-002", name="Similarity: password matches username",
         payload={"value": "john_doe", "username": "john_doe"},
         expect={"similarity.too_similar_to_username": True}),
]


# ═══════════════════════════════════════════════════════════════════════════════
# USERNAME TESTS — 22 test cases covering all 7 features
# ═══════════════════════════════════════════════════════════════════════════════
USERNAME_TESTS = [

    # ── U-01: Brand impersonation ─────────────────────────────────────────────
    dict(id="U-BRD-001", name="Brand: 'paypal_support99' → PayPal",
         payload={"value": "paypal_support99"},
         expect={"brand_impersonation.detected": True,
                 "brand_impersonation.primary_brand__contains": "paypal",
                 "overall_risk_score__gte": 25}),

    dict(id="U-BRD-002", name="Brand: 'microsoft_helpdesk' flagged",
         payload={"value": "microsoft_helpdesk"},
         expect={"brand_impersonation.detected": True}),

    dict(id="U-BRD-003", name="Brand: 'hbl_official' (PK bank) flagged",
         payload={"value": "hbl_official"},
         expect={"brand_impersonation.detected": True,
                 "brand_impersonation.primary_brand__contains": "hbl"}),

    dict(id="U-BRD-004", name="Brand: 'jazzcash_support' (PK fintech) flagged",
         payload={"value": "jazzcash_support"},
         expect={"brand_impersonation.detected": True}),

    dict(id="U-BRD-005", name="Brand: 'google_verify_account' flagged",
         payload={"value": "google_verify_account"},
         expect={"brand_impersonation.detected": True}),

    dict(id="U-BRD-006", name="Brand: clean name 'ahmed_khan' — no impersonation",
         payload={"value": "ahmed_khan"},
         expect={"brand_impersonation.detected": False,
                 "overall_risk_score__lt": 25}),

    # ── U-02: Bot entropy ────────────────────────────────────────────────────
    dict(id="U-ENT-001", name="Entropy: 'xK9mZpQr7wB3' is high entropy",
         payload={"value": "xK9mZpQr7wB3"},
         expect={"entropy.is_high_entropy": True,
                 "entropy.entropy_bits__gt": 3.0}),

    dict(id="U-ENT-002", name="Entropy: 'ahmed_khan' is low entropy (human)",
         payload={"value": "ahmed_khan"},
         expect={"entropy.is_high_entropy": False}),

    dict(id="U-ENT-003", name="Entropy: 'a7Fd2Kz9Mn4X' flagged as machine-like",
         payload={"value": "a7Fd2Kz9Mn4X"},
         expect={"entropy.is_high_entropy": True}),

    # ── U-03: Bot numeric patterns ────────────────────────────────────────────
    dict(id="U-BOT-001", name="Bot pattern: 'user4729182' long numeric suffix",
         payload={"value": "user4729182"},
         expect={"bot_patterns.detected": True,
                 "bot_patterns.patterns.numeric_suffix__exists": True}),

    dict(id="U-BOT-002", name="Bot pattern: '123456789' all digits",
         payload={"value": "123456789"},
         expect={"bot_patterns.detected": True,
                 "bot_patterns.patterns.all_digits": True}),

    dict(id="U-BOT-003", name="Bot pattern: 'a3f7c2d9b1e4' hex string",
         payload={"value": "a3f7c2d9b1e4"},
         expect={"bot_patterns.detected": True,
                 "bot_patterns.patterns.hex_string": True}),

    dict(id="U-BOT-004", name="Bot pattern: 'ali_raza' is human-like",
         payload={"value": "ali_raza"},
         expect={"bot_patterns.bot_probability_label__in": ["Low", "Medium"]}),

    # ── U-04: Lookalike chars ─────────────────────────────────────────────────
    dict(id="U-LKA-001", name="Lookalike: 'm1cr0s0ft' digit subs detected",
         payload={"value": "m1cr0s0ft"},
         expect={"lookalike.detected": True,
                 "lookalike.digit_substitutions__type": "dict",
                 "lookalike.normalized_form__contains": "m"}),

    dict(id="U-LKA-002", name="Lookalike: 'paypa1' — 1 for l",
         payload={"value": "paypa1"},
         expect={"lookalike.detected": True}),

    dict(id="U-LKA-003", name="Lookalike: 'google' — no subs (clean)",
         payload={"value": "google"},
         expect={"lookalike.digit_substitutions": {}}),

    # ── U-05: Suspicious keywords ─────────────────────────────────────────────
    dict(id="U-KWD-001", name="Keyword: 'admin_user_official'",
         payload={"value": "admin_user_official"},
         expect={"suspicious_keywords.detected": True}),

    dict(id="U-KWD-002", name="Keyword: 'payment_verify_secure'",
         payload={"value": "payment_verify_secure"},
         expect={"suspicious_keywords.detected": True,
                 "suspicious_keywords.risk__in": ["High", "Medium"]}),

    dict(id="U-KWD-003", name="Keyword: 'zainab_tariq' — clean, no keywords",
         payload={"value": "zainab_tariq"},
         expect={"suspicious_keywords.detected": False}),

    # ── U-06: Breach history (DeHashed) ──────────────────────────────────────
    dict(id="U-BRH-001", name="DeHashed: returns valid structure (key optional)",
         payload={"value": "admin"},
         expect={"breach_history__type": "dict"}),

    # ── U-07: Cross-platform ──────────────────────────────────────────────────
    dict(id="U-PLT-001", name="Platform: response always has checked_platforms",
         payload={"value": "testuser"},
         expect={"cross_platform.checked_platforms__type": "list",
                 "cross_platform.checked_platforms__len_gt": 3}),

    dict(id="U-PLT-002", name="Platform: platform_count is non-negative int",
         payload={"value": "randomuser12345"},
         expect={"cross_platform.platform_count__gte": 0}),

    # ── End-to-end ────────────────────────────────────────────────────────────
    dict(id="U-RSK-001", name="Full risk: attacker profile username",
         payload={"value": "paypal_official_support99"},
         expect={"brand_impersonation.detected": True,
                 "suspicious_keywords.detected": True,
                 "overall_risk_score__gte": 40,
                 "overall_risk_level__in": ["Medium","High","Critical"]}),
]


# ═══════════════════════════════════════════════════════════════════════════════
# RUNNER
# ═══════════════════════════════════════════════════════════════════════════════
def print_separator(char="═", width=70):
    print(f"{BOLD}{char * width}{RESET}")


def run_suite(suite_name: str, tests: list, endpoint: str, verbose: bool) -> tuple[int, int, int]:
    passed = failed = skipped = 0
    print_separator()
    print(f"{BOLD}{CYAN}  {suite_name}{RESET}")
    print_separator()

    for t in tests:
        result = run_test(
            test_id=t["id"],
            name=t["name"],
            endpoint=endpoint,
            payload=t["payload"],
            assertions=t["expect"],
        )

        tag_id   = f"{BOLD}[{t['id']:>12}]{RESET}"
        elapsed  = f"{YELLOW}({result.elapsed_ms:.0f}ms){RESET}" if result.elapsed_ms else ""

        if result.skipped:
            skipped += 1
            print(f"  {tag_id} {YELLOW}SKIP{RESET}  {t['name']}  — {result.skip_reason}")
        elif result.passed:
            passed += 1
            print(f"  {tag_id} {GREEN}PASS{RESET}  {t['name']}  {elapsed}")
        else:
            failed += 1
            print(f"  {tag_id} {RED}FAIL{RESET}  {t['name']}  {elapsed}")
            for f in result.failures:
                print(f"         {RED}{f}{RESET}")
            if verbose and result.response:
                print(f"         {YELLOW}Response snippet:{RESET}")
                snippet = json.dumps(result.response, indent=2)[:800]
                print("         " + snippet.replace("\n", "\n         "))

    return passed, failed, skipped


def main():
    parser = argparse.ArgumentParser(description="Aegis Tier-1 Test Suite")
    parser.add_argument("--email",    action="store_true", help="Only email tests")
    parser.add_argument("--password", action="store_true", help="Only password tests")
    parser.add_argument("--username", action="store_true", help="Only username tests")
    parser.add_argument("--verbose",  action="store_true", help="Show response on fail")
    args = parser.parse_args()

    run_all = not (args.email or args.password or args.username)

    # ── Check server is up ────────────────────────────────────────────────────
    print(f"\n{BOLD}Aegis AI — Tier 1 Automated Test Suite{RESET}")
    print(f"Target: {CYAN}{BASE}{RESET}\n")
    try:
        r = httpx.get(f"{BASE}/health", timeout=5)
        h = r.json()
        print(f"{GREEN}✓ Server healthy{RESET} — version {h.get('version')} | redis: {h.get('redis')}\n")
    except Exception as e:
        print(f"{RED}✗ Cannot reach {BASE} — {e}{RESET}")
        print(f"{YELLOW}  Make sure Docker is running:  docker-compose up{RESET}\n")
        sys.exit(1)

    total_pass = total_fail = total_skip = 0

    suites = []
    if run_all or args.email:
        suites.append(("EMAIL ANALYSIS (9 features)", EMAIL_TESTS, "/analyze/email"))
    if run_all or args.password:
        suites.append(("PASSWORD ANALYSIS (12 features)", PASSWORD_TESTS, "/analyze/password"))
    if run_all or args.username:
        suites.append(("USERNAME ANALYSIS (7 features)", USERNAME_TESTS, "/analyze/username"))

    for name, tests, ep in suites:
        p, f, s = run_suite(name, tests, ep, args.verbose)
        total_pass += p
        total_fail += f
        total_skip += s

    # ── Summary ───────────────────────────────────────────────────────────────
    total = total_pass + total_fail + total_skip
    print_separator()
    print(f"\n{BOLD}  SUMMARY{RESET}")
    print_separator("─")
    print(f"  Total:   {total}")
    print(f"  {GREEN}Passed:  {total_pass}{RESET}")
    print(f"  {RED}Failed:  {total_fail}{RESET}")
    print(f"  {YELLOW}Skipped: {total_skip}{RESET}")
    pct = (total_pass / (total - total_skip) * 100) if (total - total_skip) > 0 else 0
    print(f"\n  Pass rate: {BOLD}{pct:.1f}%{RESET}")
    print_separator()

    if total_fail > 0:
        print(f"\n{RED}  {total_fail} test(s) failed.{RESET}")
        print(f"  Run with --verbose to see full responses.\n")
        sys.exit(1)
    else:
        print(f"\n{GREEN}  All tests passed!{RESET}\n")
        sys.exit(0)


if __name__ == "__main__":
    main()
