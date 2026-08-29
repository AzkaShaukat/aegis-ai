#!/usr/bin/env python3
"""
================================================================
  Aegis AI — Tier 2 Automated Test Suite
  Tests: Card (18) · IBAN (16) · Crypto (18) · Social Media (12)
  Total: 64 tests

  USAGE:
      python test_tier2.py                  # all
      python test_tier2.py --card           # card only
      python test_tier2.py --iban           # IBAN only
      python test_tier2.py --crypto         # crypto only
      python test_tier2.py --social         # social media only
      python test_tier2.py --verbose        # show response on fail

  REQUIRES: docker-compose up + pip install httpx colorama
================================================================
"""
import argparse
import json
import sys
import time
from dataclasses import dataclass, field
from typing import Any

try:
    import httpx
except ImportError:
    print("ERROR: run  pip install httpx colorama"); sys.exit(1)

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    GREEN=Fore.GREEN; RED=Fore.RED; YELLOW=Fore.YELLOW
    CYAN=Fore.CYAN; BOLD=Style.BRIGHT; RESET=Style.RESET_ALL
except ImportError:
    GREEN=RED=YELLOW=CYAN=BOLD=RESET=""

BASE    = "http://localhost:8006"
TIMEOUT = 30.0


# ═══ TEST ENGINE (same as tier1 suite) ════════════════════════════════════════
@dataclass
class TestResult:
    test_id: str; name: str; passed: bool
    skipped: bool=False; skip_reason: str=""
    failures: list=field(default_factory=list)
    response: dict=field(default_factory=dict)
    elapsed_ms: float=0.0

def _get(obj, path):
    for k in path.split("."):
        if obj is None: return None
        obj = obj.get(k) if isinstance(obj, dict) else (obj[int(k)] if k.isdigit() and isinstance(obj,list) else None)
    return obj

def check(response, assertions):
    failures = []
    for expr, expected in assertions.items():
        if "__" in expr.rsplit(".",1)[-1]:
            path, op = expr.rsplit("__",1)
        else:
            path, op = expr, "eq"
        actual = _get(response, path)
        try:
            if op=="eq"      and actual!=expected:       failures.append(f"  ✗ {path}: expected {expected!r}, got {actual!r}")
            elif op=="not"   and actual==expected:       failures.append(f"  ✗ {path}: expected NOT {expected!r}")
            elif op=="gt"    and not(isinstance(actual,(int,float)) and actual>expected):  failures.append(f"  ✗ {path}: expected > {expected}, got {actual!r}")
            elif op=="gte"   and not(isinstance(actual,(int,float)) and actual>=expected): failures.append(f"  ✗ {path}: expected >= {expected}, got {actual!r}")
            elif op=="lt"    and not(isinstance(actual,(int,float)) and actual<expected):  failures.append(f"  ✗ {path}: expected < {expected}, got {actual!r}")
            elif op=="in"    and actual not in expected: failures.append(f"  ✗ {path}: expected one of {expected}, got {actual!r}")
            elif op=="contains" and not(isinstance(actual,(str,list)) and expected in actual): failures.append(f"  ✗ {path}: expected to contain {expected!r}")
            elif op=="exists":
                if (actual is not None)!=expected:       failures.append(f"  ✗ {path}: exists={expected}, got {actual!r}")
            elif op=="type":
                tm={"str":str,"int":int,"float":float,"list":list,"dict":dict,"bool":bool}
                if not isinstance(actual, tm.get(expected, object)): failures.append(f"  ✗ {path}: expected type {expected}, got {type(actual).__name__}")
            elif op=="truthy" and bool(actual)!=expected: failures.append(f"  ✗ {path}: truthy={expected}, got {actual!r}")
            elif op=="len_gt" and not(isinstance(actual,(str,list,dict)) and len(actual)>expected): failures.append(f"  ✗ {path}: expected len>{expected}")
        except Exception as e:
            failures.append(f"  ✗ {path}: error — {e}")
    return failures

def post(endpoint, payload, timeout=TIMEOUT):
    t0=time.perf_counter()
    try:
        r=httpx.post(f"{BASE}{endpoint}",json=payload,headers={"X-API-Key": "1122"},timeout=timeout)
        el=(time.perf_counter()-t0)*1000
        if r.status_code not in (200,201): return {"_http_error":r.status_code,"_body":r.text[:300]},el
        return r.json(),el
    except httpx.ConnectError: return {"_connection_error":f"Cannot connect to {BASE}"},0
    except Exception as e:    return {"_error":str(e)},0

def run_test(test_id,name,endpoint,payload,assertions):
    response,elapsed=post(endpoint,payload)
    if "_connection_error" in response:
        return TestResult(test_id=test_id,name=name,passed=False,failures=[response["_connection_error"]])
    if "_http_error" in response:
        return TestResult(test_id=test_id,name=name,passed=False,
                          failures=[f"HTTP {response['_http_error']}: {response.get('_body','')}"])
    failures=check(response,assertions)
    return TestResult(test_id=test_id,name=name,passed=len(failures)==0,
                      failures=failures,response=response,elapsed_ms=round(elapsed,1))


# ═══════════════════════════════════════════════════════════════════════════════
# CARD TESTS — 18 tests
# ═══════════════════════════════════════════════════════════════════════════════
CARD_TESTS = [
    # ── C-01: Luhn ────────────────────────────────────────────────────────────
    dict(id="C-LHN-001", name="Luhn PASS: valid Visa number",
         payload={"number":"4532015112830366"},
         expect={"luhn.valid":True, "luhn.digit_count":16}),

    dict(id="C-LHN-002", name="Luhn FAIL: invalid number",
         payload={"number":"4532015112830367"},
         expect={"luhn.valid":False,
                 "overall_risk_score__gte":35}),

    dict(id="C-LHN-003", name="Luhn PASS: valid Mastercard",
         payload={"number":"5425233430109903"},
         expect={"luhn.valid":True}),

    dict(id="C-LHN-004", name="Luhn PASS: valid Amex (15 digits)",
         payload={"number":"378282246310005"},
         expect={"luhn.valid":True, "luhn.digit_count":15}),

    dict(id="C-LHN-005", name="Luhn: spaces in input accepted",
         payload={"number":"4532 0151 1283 0366"},
         expect={"luhn.valid":True}),

    # ── C-02: Network detection ────────────────────────────────────────────────
    dict(id="C-NET-001", name="Network: Visa detected from prefix 4",
         payload={"number":"4111111111111111"},
         expect={"network.network":"Visa", "network.detected":True}),

    dict(id="C-NET-002", name="Network: Mastercard 5x prefix",
         payload={"number":"5500005555555559"},
         expect={"network.network":"Mastercard"}),

    dict(id="C-NET-003", name="Network: Amex 37 prefix",
         payload={"number":"378282246310005"},
         expect={"network.network":"American Express"}),

    dict(id="C-NET-004", name="Network: Discover 6011 prefix",
         payload={"number":"6011111111111117"},
         expect={"network.network":"Discover"}),

    dict(id="C-NET-005", name="Network: Mastercard 2-series (2221–2720)",
         payload={"number":"2223000048400011"},
         expect={"network.network":"Mastercard"}),

    # ── C-03: BIN lookup ──────────────────────────────────────────────────────
    dict(id="C-BIN-001", name="BIN: lookup returns dict structure",
         payload={"number":"4532015112830366"},
         expect={"bin_info__type":"dict",
                 "bin_info.bin":"453201"}),

    # ── C-04: Test card detection ──────────────────────────────────────────────
    dict(id="C-TST-001", name="Test card: Stripe 4242... detected",
         payload={"number":"4242424242424242"},
         expect={"test_card.is_test_card":True,
                 "overall_risk_score__gte":40}),

    dict(id="C-TST-002", name="Test card: classic Visa 4111... detected",
         payload={"number":"4111111111111111"},
         expect={"test_card.is_test_card":True}),

    dict(id="C-TST-003", name="Test card: real-world number NOT flagged",
         payload={"number":"4532015112830366"},
         expect={"test_card.is_test_card":False}),

    # ── C-05: Expiry ──────────────────────────────────────────────────────────
    dict(id="C-EXP-001", name="Expiry: valid future date",
         payload={"number":"4532015112830366","expiry_month":"12","expiry_year":"27"},
         expect={"expiry.valid":True, "expiry.is_expired":False}),

    dict(id="C-EXP-002", name="Expiry: expired date flagged",
         payload={"number":"4532015112830366","expiry_month":"01","expiry_year":"20"},
         expect={"expiry.valid":True, "expiry.is_expired":True,
                 "overall_risk_score__gte":25}),

    # ── C-06: CVV ─────────────────────────────────────────────────────────────
    dict(id="C-CVV-001", name="CVV: 3-digit valid for Visa",
         payload={"number":"4532015112830366","cvv":"123"},
         expect={"cvv.valid":True, "cvv.length":3}),

    dict(id="C-CVV-002", name="CVV: 4-digit valid for Amex",
         payload={"number":"378282246310005","cvv":"1234"},
         expect={"cvv.valid":True, "cvv.length":4, "cvv.expected_length":4}),
]


# ═══════════════════════════════════════════════════════════════════════════════
# IBAN TESTS — 16 tests
# ═══════════════════════════════════════════════════════════════════════════════
IBAN_TESTS = [
    # ── I-01: Format ──────────────────────────────────────────────────────────
    dict(id="I-FMT-001", name="Format: valid PK IBAN passes",
         payload={"iban":"PK36ALFA0064001025009774"},
         expect={"format.valid":True,
                 "format.country":"PK",
                 "format.length":24}),

    dict(id="I-FMT-002", name="Format: valid GB IBAN passes",
         payload={"iban":"GB82WEST12345698765432"},
         expect={"format.valid":True, "format.country":"GB"}),

    dict(id="I-FMT-003", name="Format: wrong length fails",
         payload={"iban":"PK36ALFA006400"},
         expect={"format.valid":False,
                 "overall_risk_score__gte":40}),

    dict(id="I-FMT-004", name="Format: invalid country code fails",
         payload={"iban":"XX36ALFA0064001025009774"},
         expect={"format.valid":False}),

    dict(id="I-FMT-005", name="Format: spaces stripped and validated",
         payload={"iban":"PK36 ALFA 0064 0010 2500 9774"},
         expect={"format.valid":True, "format.country":"PK"}),

    # ── I-02: MOD-97 ──────────────────────────────────────────────────────────
    dict(id="I-MOD-001", name="MOD-97: valid GB IBAN passes checksum",
         payload={"iban":"GB82WEST12345698765432"},
         expect={"mod97_checksum.valid":True, "mod97_checksum.remainder":1}),

    dict(id="I-MOD-002", name="MOD-97: tampered IBAN fails checksum",
         payload={"iban":"GB83WEST12345698765432"},
         expect={"mod97_checksum.valid":False,
                 "overall_risk_score__gte":35}),

    dict(id="I-MOD-003", name="MOD-97: valid DE IBAN passes",
         payload={"iban":"DE89370400440532013000"},
         expect={"mod97_checksum.valid":True}),

    # ── I-05: PK decode ───────────────────────────────────────────────────────
    dict(id="I-PK-001", name="PK: HBL IBAN decoded correctly",
         payload={"iban":"PK07HABB0000001123456702"},
         expect={"pk_iban.is_pk_iban":True,
                 "pk_iban.bank_code":"HABB",
                 "pk_iban.bank_name__contains":"Habib"}),

    dict(id="I-PK-002", name="PK: MCB IBAN decoded",
         payload={"iban":"PK70MUCB0001001234567890"},
         expect={"pk_iban.is_pk_iban":True,
                 "pk_iban.bank_code":"MUCB"}),

    dict(id="I-PK-003", name="PK: account number extracted",
         payload={"iban":"PK36ALFA0064001025009774"},
         expect={"pk_iban.is_pk_iban":True,
                 "pk_iban.account_number__len_gt":8}),

    dict(id="I-PK-004", name="PK: non-PK IBAN not flagged as PK",
         payload={"iban":"GB82WEST12345698765432"},
         expect={"pk_iban.is_pk_iban":False}),

    # ── I-07: Suspicious patterns ──────────────────────────────────────────────
    dict(id="I-SUS-001", name="Suspicious: all-zero account flagged",
         payload={"iban":"PK36ALFA0000000000000000"},
         expect={"suspicious_patterns.detected":True}),

    # ── I-06: SWIFT ───────────────────────────────────────────────────────────
    dict(id="I-SWT-001", name="SWIFT: valid 8-char BIC",
         payload={"iban":"GB82WEST12345698765432","swift":"BARCGB22"},
         expect={"swift.valid":True, "swift.bank_code":"BARC",
                 "swift.country_code":"GB"}),

    dict(id="I-SWT-002", name="SWIFT: valid 11-char BIC with branch",
         payload={"iban":"PK36ALFA0064001025009774","swift":"ALFHPKKA001"},
         expect={"swift.valid":True, "swift.branch":"001"}),

    dict(id="I-SWT-003", name="SWIFT: invalid BIC rejected",
         payload={"iban":"PK36ALFA0064001025009774","swift":"INVALID"},
         expect={"swift.valid":False}),
]


# ═══════════════════════════════════════════════════════════════════════════════
# CRYPTO TESTS — 18 tests
# ═══════════════════════════════════════════════════════════════════════════════
CRYPTO_TESTS = [
    # ── CR-01: Network detection ───────────────────────────────────────────────
    dict(id="CR-NET-001", name="Crypto: Bitcoin P2PKH (starts with 1)",
         payload={"value":"1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"},
         expect={"network.network":"Bitcoin",
                 "network.address_type":"P2PKH (Legacy)",
                 "network.detected":True}),

    dict(id="CR-NET-002", name="Crypto: Bitcoin P2SH (starts with 3)",
         payload={"value":"3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"},
         expect={"network.network":"Bitcoin",
                 "network.address_type":"P2SH"}),

    dict(id="CR-NET-003", name="Crypto: Bitcoin Bech32 SegWit (bc1...)",
         payload={"value":"bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"},
         expect={"network.network":"Bitcoin",
                 "network.address_type__contains":"Bech32"}),

    dict(id="CR-NET-004", name="Crypto: Ethereum address (0x...)",
         payload={"value":"0x742d35Cc6634C0532925a3b844Bc454e4438f44e"},
         expect={"network.network":"Ethereum",
                 "network.detected":True}),

    dict(id="CR-NET-005", name="Crypto: Litecoin (starts with L)",
         payload={"value":"LaMT348PWRnrqeeWArpwQPbuanpXDZGEUz"},
         expect={"network.network":"Litecoin"}),

    dict(id="CR-NET-006", name="Crypto: Dogecoin (starts with D)",
         payload={"value":"D7Y55M5sBX1zHoiHGLQsMZqHUC3Bm5e5oi"},
         expect={"network.network":"Dogecoin"}),

    dict(id="CR-NET-007", name="Crypto: Tron (starts with T)",
         payload={"value":"TQn9Y2khDD9oEqkSUBenHvCFQtJG8YMJV2"},
         expect={"network.network":"Tron"}),

    dict(id="CR-NET-008", name="Crypto: invalid/unknown address flagged",
         payload={"value":"NOTACRYPTOADDRESS123"},
         expect={"network.detected":False,
                 "overall_risk_score__gte":35}),

    # ── CR-02: Bitcoin Base58Check ─────────────────────────────────────────────
    dict(id="CR-CHK-001", name="Checksum: valid BTC address passes Base58Check",
         payload={"value":"1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"},
         expect={"checksum.valid":True,
                 "checksum.method":"base58check"}),

    dict(id="CR-CHK-002", name="Checksum: Bech32 uses bech32 method",
         payload={"value":"bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"},
         expect={"checksum.method":"bech32"}),

    # ── CR-03: Ethereum EIP-55 ────────────────────────────────────────────────
    dict(id="CR-ETH-001", name="ETH: checksummed address validates",
         payload={"value":"0x742d35Cc6634C0532925a3b844Bc454e4438f44e"},
         expect={"checksum__type":"dict",
                 "network.network":"Ethereum"}),

    dict(id="CR-ETH-002", name="ETH: all-lowercase address — no checksum present note",
         payload={"value":"0x742d35cc6634c0532925a3b844bc454e4438f44e"},
         expect={"checksum.valid":True,
                 "checksum.checksum_present":False}),

    # ── CR-05: Scam address ────────────────────────────────────────────────────
    dict(id="CR-SCM-001", name="Scam: clean address not in scam list",
         payload={"value":"1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"},
         expect={"scam_check.in_scam_list":False}),

    # ── CR-06: Clipboard risk ─────────────────────────────────────────────────
    dict(id="CR-CLB-001", name="Clipboard: clean ASCII address no risk",
         payload={"value":"1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"},
         expect={"clipboard_risk.risk_detected":False}),

    # ── End to end ────────────────────────────────────────────────────────────
    dict(id="CR-RSK-001", name="Risk level always present in response",
         payload={"value":"1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"},
         expect={"overall_risk_level__in":["Clean","Low","Medium","High","Critical"],
                 "credential_type":"crypto_wallet",
                 "all_flags__type":"list"}),

    dict(id="CR-RSK-002", name="Clean valid BTC address = low risk",
         payload={"value":"1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"},
         expect={"overall_risk_score__lt":40}),

    dict(id="CR-RSK-003", name="Invalid address gets high risk score",
         payload={"value":"THISISNOTAVALIDADDRESS000"},
         expect={"overall_risk_score__gte":35,
                 "network.detected":False}),

    dict(id="CR-RSK-004", name="Monero address flagged with note",
         payload={"value":"44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A"},
         expect={"network.network":"Monero",
                 "all_flags__len_gt":0}),
]


# ═══════════════════════════════════════════════════════════════════════════════
# SOCIAL MEDIA TESTS — 12 tests
# ═══════════════════════════════════════════════════════════════════════════════
SOCIAL_TESTS = [
    # ── SM-01: Platform identification ────────────────────────────────────────
    dict(id="SM-PLT-001", name="Platform: 'twitter' identified",
         payload={"username":"testuser","platform":"twitter"},
         expect={"platform_info.platform":"twitter",
                 "platform_info.known":True}),

    dict(id="SM-PLT-002", name="Platform: 'ig' alias → instagram",
         payload={"username":"testuser","platform":"ig"},
         expect={"platform_info.platform":"instagram"}),

    dict(id="SM-PLT-003", name="Platform: 'linkedin' identified",
         payload={"username":"testuser","platform":"linkedin"},
         expect={"platform_info.platform":"linkedin",
                 "platform_info.known":True}),

    # ── SM-02: Platform breach database ───────────────────────────────────────
    dict(id="SM-BRH-001", name="LinkedIn has major breaches in database",
         payload={"username":"testuser","platform":"linkedin"},
         expect={"platform_breaches.found":True,
                 "platform_breaches.breach_count__gte":2,
                 "platform_breaches.has_password_exposure":True}),

    dict(id="SM-BRH-002", name="LinkedIn 2021 breach has 700M records",
         payload={"username":"testuser","platform":"linkedin"},
         expect={"platform_breaches.total_records_exposed__gt":700_000_000}),

    dict(id="SM-BRH-003", name="Facebook breaches: has phone in exposed data",
         payload={"username":"testuser","platform":"facebook"},
         expect={"platform_breaches.found":True,
                 "platform_breaches.breaches__type":"list"}),

    dict(id="SM-BRH-004", name="VK has plaintext password breach",
         payload={"username":"testuser","platform":"vk"},
         expect={"platform_breaches.has_plaintext_passwords":True,
                 "platform_breaches.max_severity":5}),

    dict(id="SM-BRH-005", name="Unknown platform: no breach found gracefully",
         payload={"username":"testuser","platform":"unknownplatform999"},
         expect={"platform_breaches.found":False,
                 "platform_breaches.breach_count":0}),

    # ── SM-04: Cross-platform existence ───────────────────────────────────────
    dict(id="SM-EXT-001", name="Existence check returns checked_count",
         payload={"username":"testuser"},
         expect={"platform_existence.checked_count__gte":1,
                 "platform_existence.found_on__type":"list"}),

    # ── SM-07: Data exposure ──────────────────────────────────────────────────
    dict(id="SM-EXP-001", name="LinkedIn exposes email, phone, job data",
         payload={"username":"testuser","platform":"linkedin"},
         expect={"data_types_exposed__contains":"email"}),

    # ── End to end ────────────────────────────────────────────────────────────
    dict(id="SM-RSK-001", name="Risk level always present",
         payload={"username":"testuser","platform":"twitter"},
         expect={"overall_risk_level__in":["Clean","Low","Medium","High","Critical"],
                 "credential_type":"social_media",
                 "all_flags__type":"list"}),

    dict(id="SM-RSK-002", name="VK platform gets higher risk due to severity 5",
         payload={"username":"testuser","platform":"vk"},
         expect={"overall_risk_score__gt":10,
                 "platform_breaches.max_severity":5}),
]


# ═══════════════════════════════════════════════════════════════════════════════
# RUNNER
# ═══════════════════════════════════════════════════════════════════════════════
def sep(char="═", w=70): print(f"{BOLD}{char*w}{RESET}")

def run_suite(name, tests, endpoint, verbose):
    p=f=0; sep()
    print(f"{BOLD}{CYAN}  {name}{RESET}"); sep()
    for t in tests:
        r=run_test(t["id"],t["name"],endpoint,t["payload"],t["expect"])
        tag=f"{BOLD}[{t['id']:>12}]{RESET}"
        ms=f"{YELLOW}({r.elapsed_ms:.0f}ms){RESET}" if r.elapsed_ms else ""
        if r.passed:
            p+=1; print(f"  {tag} {GREEN}PASS{RESET}  {t['name']}  {ms}")
        else:
            f+=1; print(f"  {tag} {RED}FAIL{RESET}  {t['name']}  {ms}")
            for fx in r.failures: print(f"         {RED}{fx}{RESET}")
            if verbose and r.response:
                print(f"         {YELLOW}Response:{RESET}")
                print("         "+json.dumps(r.response,indent=2)[:600].replace("\n","\n         "))
    return p,f

def main():
    ap=argparse.ArgumentParser(); 
    ap.add_argument("--card",   action="store_true")
    ap.add_argument("--iban",   action="store_true")
    ap.add_argument("--crypto", action="store_true")
    ap.add_argument("--social", action="store_true")
    ap.add_argument("--verbose",action="store_true")
    args=ap.parse_args(); run_all=not(args.card or args.iban or args.crypto or args.social)

    print(f"\n{BOLD}Aegis AI — Tier 2 Automated Test Suite{RESET}")
    print(f"Target: {CYAN}{BASE}{RESET}\n")
    try:
        r=httpx.get(f"{BASE}/health",timeout=5); h=r.json()
        print(f"{GREEN}✓ Server healthy{RESET} — version {h.get('version')} | redis: {h.get('redis')}\n")
    except Exception as e:
        print(f"{RED}✗ Cannot reach {BASE} — {e}{RESET}\n  Make sure: docker-compose up\n"); sys.exit(1)

    tp=tf=0
    suites=[]
    if run_all or args.card:   suites.append(("CARD ANALYSIS (8 features)",      CARD_TESTS,   "/analyze/card"))
    if run_all or args.iban:   suites.append(("IBAN ANALYSIS (8 features)",      IBAN_TESTS,   "/analyze/iban"))
    if run_all or args.crypto: suites.append(("CRYPTO ANALYSIS (8 features)",    CRYPTO_TESTS, "/analyze/crypto"))
    if run_all or args.social: suites.append(("SOCIAL MEDIA ANALYSIS (7 features)", SOCIAL_TESTS, "/analyze/social"))

    for name,tests,ep in suites:
        p,f=run_suite(name,tests,ep,args.verbose); tp+=p; tf+=f

    total=tp+tf; sep()
    print(f"\n{BOLD}  SUMMARY{RESET}"); sep("─")
    print(f"  Total:  {total}")
    print(f"  {GREEN}Passed: {tp}{RESET}")
    print(f"  {RED}Failed: {tf}{RESET}")
    pct=(tp/total*100) if total else 0
    print(f"\n  Pass rate: {BOLD}{pct:.1f}%{RESET}"); sep()
    if tf: print(f"\n{RED}  {tf} test(s) failed. Run with --verbose to see responses.{RESET}\n"); sys.exit(1)
    else:  print(f"\n{GREEN}  All tests passed!{RESET}\n"); sys.exit(0)

if __name__=="__main__": main()
