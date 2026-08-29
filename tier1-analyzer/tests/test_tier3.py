#!/usr/bin/env python3
"""
================================================================
  Aegis AI — Tier 3 Automated Test Suite
  Tests: National ID (20) · Passport (18) · Phone (20)
  Total: 58 tests

  USAGE:
      python test_tier3.py                     # all
      python test_tier3.py --national-id       # CNIC/SSN/Aadhaar
      python test_tier3.py --passport          # Passport MRZ
      python test_tier3.py --phone             # Phone numbers
      python test_tier3.py --verbose           # show response on fail
================================================================
"""
import argparse
import json
import sys
import time
from dataclasses import dataclass, field

try:
    import httpx
except ImportError:
    print("ERROR: pip install httpx colorama"); sys.exit(1)

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    GREEN=Fore.GREEN; RED=Fore.RED; YELLOW=Fore.YELLOW
    CYAN=Fore.CYAN; BOLD=Style.BRIGHT; RESET=Style.RESET_ALL
except ImportError:
    GREEN=RED=YELLOW=CYAN=BOLD=RESET=""

BASE    = "http://localhost:8006"
TIMEOUT = 30.0


# ═══ TEST ENGINE ══════════════════════════════════════════════════════════════
@dataclass
class TestResult:
    test_id: str; name: str; passed: bool
    failures: list = field(default_factory=list)
    response: dict = field(default_factory=dict)
    elapsed_ms: float = 0.0

def _get(obj, path):
    for k in path.split("."):
        if obj is None: return None
        if isinstance(obj, dict): obj = obj.get(k)
        elif k.isdigit() and isinstance(obj, list): obj = obj[int(k)]
        else: return None
    return obj

def check(response, assertions):
    failures = []
    for expr, expected in assertions.items():
        if "__" in expr.rsplit(".", 1)[-1]:
            path, op = expr.rsplit("__", 1)
        else:
            path, op = expr, "eq"
        actual = _get(response, path)
        try:
            if   op == "eq"       and actual != expected:
                failures.append(f"  ✗ {path}: expected {expected!r}, got {actual!r}")
            elif op == "not"      and actual == expected:
                failures.append(f"  ✗ {path}: expected NOT {expected!r}")
            elif op == "gt"       and not (isinstance(actual,(int,float)) and actual > expected):
                failures.append(f"  ✗ {path}: expected > {expected}, got {actual!r}")
            elif op == "gte"      and not (isinstance(actual,(int,float)) and actual >= expected):
                failures.append(f"  ✗ {path}: expected >= {expected}, got {actual!r}")
            elif op == "lt"       and not (isinstance(actual,(int,float)) and actual < expected):
                failures.append(f"  ✗ {path}: expected < {expected}, got {actual!r}")
            elif op == "in"       and actual not in expected:
                failures.append(f"  ✗ {path}: expected one of {expected}, got {actual!r}")
            elif op == "contains" and not (isinstance(actual,(str,list)) and expected in actual):
                failures.append(f"  ✗ {path}: expected to contain {expected!r}")
            elif op == "type":
                tm = {"str":str,"int":int,"float":float,"list":list,"dict":dict,"bool":bool}
                if not isinstance(actual, tm.get(expected, object)):
                    failures.append(f"  ✗ {path}: expected type {expected}, got {type(actual).__name__} ({actual!r})")
            elif op == "truthy"   and bool(actual) != expected:
                failures.append(f"  ✗ {path}: truthy={expected}, got {actual!r}")
            elif op == "exists":
                if (actual is not None) != expected:
                    failures.append(f"  ✗ {path}: exists={expected}, got {actual!r}")
            elif op == "len_gt"   and not (isinstance(actual,(str,list,dict)) and len(actual) > expected):
                failures.append(f"  ✗ {path}: expected len>{expected}, got {actual!r}")
        except Exception as e:
            failures.append(f"  ✗ {path}: assertion error — {e}")
    return failures

def post(endpoint, payload, timeout=TIMEOUT):
    t0 = time.perf_counter()
    try:
        r = httpx.post(f"{BASE}{endpoint}", json=payload, headers={"X-API-Key": "1122"},timeout=timeout)
        el = (time.perf_counter() - t0) * 1000
        if r.status_code not in (200, 201):
            return {"_http_error": r.status_code, "_body": r.text[:400]}, el
        return r.json(), el
    except httpx.ConnectError:
        return {"_connection_error": f"Cannot connect to {BASE}"}, 0
    except Exception as e:
        return {"_error": str(e)}, 0

def run_test(test_id, name, endpoint, payload, assertions):
    response, elapsed = post(endpoint, payload)
    if "_connection_error" in response:
        return TestResult(test_id=test_id, name=name, passed=False,
                          failures=[response["_connection_error"]])
    if "_http_error" in response:
        return TestResult(test_id=test_id, name=name, passed=False,
                          failures=[f"HTTP {response['_http_error']}: {response.get('_body','')}"])
    failures = check(response, assertions)
    return TestResult(test_id=test_id, name=name, passed=len(failures)==0,
                      failures=failures, response=response, elapsed_ms=round(elapsed,1))


# ═══════════════════════════════════════════════════════════════════════════════
# NATIONAL ID TESTS — 20 tests (CNIC + SSN + Aadhaar)
# ═══════════════════════════════════════════════════════════════════════════════
NATIONAL_ID_TESTS = [

    # ── CNIC format ───────────────────────────────────────────────────────────
    dict(id="NID-CNIC-001", name="CNIC: valid format with dashes",
         payload={"value": "35202-7491823-1"},
         expect={"detected_type": "cnic",
                 "format.valid": True,
                 "format.formatted": "35202-7491823-1"}),

    dict(id="NID-CNIC-002", name="CNIC: valid 13-digit no dashes",
         payload={"value": "3520274918231"},
         expect={"detected_type": "cnic",
                 "format.valid": True,
                 "format.digits": "3520274918231"}),

    dict(id="NID-CNIC-003", name="CNIC: wrong digit count fails",
         payload={"value": "3520-123456-1", "id_type": "cnic"},
         expect={"format.valid": False,
                 "overall_risk_score__gte": 50}),

    dict(id="NID-CNIC-004", name="CNIC: province 3 → Punjab",
         payload={"value": "35202-7491823-1"},
         expect={"province.province__contains": "Punjab",
                 "province.province_code": "3"}),

    dict(id="NID-CNIC-005", name="CNIC: province 4 → Sindh",
         payload={"value": "42301-1234567-2"},
         expect={"province.province__contains": "Sindh"}),

    dict(id="NID-CNIC-006", name="CNIC: province 6 → Islamabad ICT",
         payload={"value": "61101-1234567-3"},
         expect={"province.province__contains": "Islamabad"}),

    dict(id="NID-CNIC-007", name="CNIC: check digit odd → Male",
         payload={"value": "35202-7491823-1"},
         expect={"gender.gender": "Male"}),

    dict(id="NID-CNIC-008", name="CNIC: check digit even → Female",
         payload={"value": "35202-7491823-2"},
         expect={"gender.gender": "Female"}),

    dict(id="NID-CNIC-009", name="CNIC: all-same serial flagged",
         payload={"value": "35202-1111111-1"},
         expect={"plausibility.plausible": False,
                 "overall_risk_score__gte": 35}),

    dict(id="NID-CNIC-010", name="CNIC: privacy hash always present",
         payload={"value": "35202-7491823-1"},
         expect={"privacy.sha256_hash__type": "str",
                 "privacy.sha256_hash__len_gt": 30,
                 "credential_type": "national_id"}),

    # ── SSN tests ─────────────────────────────────────────────────────────────
    dict(id="NID-SSN-001", name="SSN: valid number passes",
         payload={"value": "524-23-4567", "id_type": "ssn"},
         expect={"detected_type": "ssn",
                 "ssn.valid": True,
                 "ssn.area": "524"}),

    dict(id="NID-SSN-002", name="SSN: area 000 rejected",
         payload={"value": "000-12-3456", "id_type": "ssn"},
         expect={"ssn.valid": False,
                 "overall_risk_score__gte": 40}),

    dict(id="NID-SSN-003", name="SSN: area 666 reserved → invalid",
         payload={"value": "666-12-3456", "id_type": "ssn"},
         expect={"ssn.valid": False}),

    dict(id="NID-SSN-004", name="SSN: 9xx ITIN range flagged",
         payload={"value": "912-34-5678", "id_type": "ssn"},
         expect={"ssn.is_itin": True}),

    dict(id="NID-SSN-005", name="SSN: group 00 invalid",
         payload={"value": "123-00-4567", "id_type": "ssn"},
         expect={"ssn.valid": False}),

    # ── Aadhaar tests ─────────────────────────────────────────────────────────
    dict(id="NID-ADB-001", name="Aadhaar: valid 12-digit with Verhoeff checksum",
         payload={"value": "234123412346", "id_type": "aadhaar"},
         expect={"detected_type": "aadhaar",
                 "aadhaar__type": "dict"}),

    dict(id="NID-ADB-002", name="Aadhaar: starts with 0 → invalid",
         payload={"value": "012345678901", "id_type": "aadhaar"},
         expect={"aadhaar.valid": False,
                 "overall_risk_score__gte": 40}),

    dict(id="NID-ADB-003", name="Aadhaar: starts with 1 → invalid",
         payload={"value": "123456789012", "id_type": "aadhaar"},
         expect={"aadhaar.valid": False}),

    # ── Auto-detection ─────────────────────────────────────────────────────────
    dict(id="NID-AUTO-001", name="Auto: 13 digits → detects as CNIC",
         payload={"value": "3520274918231"},
         expect={"detected_type": "cnic"}),

    dict(id="NID-AUTO-002", name="Auto: 9 digits → detects as SSN",
         payload={"value": "123456789"},
         expect={"detected_type": "ssn"}),
]


# ═══════════════════════════════════════════════════════════════════════════════
# PASSPORT TESTS — 18 tests
# ═══════════════════════════════════════════════════════════════════════════════
# ICAO specimen passport MRZ (public test data)
PAK_MRZ_LINE1 = "P<PAKAHMED<<ALI<RAZA<<<<<<<<<<<<<<<<<<<<<<<<"
PAK_MRZ_LINE2 = "AA12345678PAK8001014M2501017<<<<<<<<<<<<<<08"
# ICAO standard test passport
ICAO_LINE1 = "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<"
ICAO_LINE2 = "L898902C36UTO7408122F1204159ZE184226B<<<<<<1"

PASSPORT_TESTS = [

    # ── P-01: MRZ type detection ──────────────────────────────────────────────
    dict(id="PSP-MRZ-001", name="MRZ: TD3 format (44×2) detected",
         payload={"mrz_line1": PAK_MRZ_LINE1, "mrz_line2": PAK_MRZ_LINE2},
         expect={"mrz_type.type": "TD3",
                 "credential_type": "passport"}),

    dict(id="PSP-MRZ-002", name="MRZ: wrong length returns error",
         payload={"mrz_line1": "P<PAKTEST<<<", "mrz_line2": "123456789"},
         expect={"mrz_type.type": "Unknown",
                 "overall_risk_score__gte": 25}),

    # ── P-03: Country code ────────────────────────────────────────────────────
    dict(id="PSP-CTY-001", name="Country: PAK is valid ICAO code",
         payload={"mrz_line1": PAK_MRZ_LINE1, "mrz_line2": PAK_MRZ_LINE2},
         expect={"issuing_country.valid": True,
                 "issuing_country.is_pakistan": True}),

    dict(id="PSP-CTY-002", name="Country: GBR is valid",
         payload={"doc_number": "123456789", "issuing_country": "GBR"},
         expect={"issuing_country.valid": True,
                 "issuing_country.code": "GBR"}),

    dict(id="PSP-CTY-003", name="Country: invalid code XX fails",
         payload={"doc_number": "123456789", "issuing_country": "XXZ"},
         expect={"issuing_country.valid": False,
                 "overall_risk_score__gte": 15}),

    # ── P-10: Full Pakistani MRZ decode ───────────────────────────────────────
    dict(id="PSP-PAK-001", name="PAK: surname decoded from MRZ line 1",
         payload={"mrz_line1": PAK_MRZ_LINE1, "mrz_line2": PAK_MRZ_LINE2},
         expect={"decoded.surname__contains": "AHMED",
                 "decoded.issuing_country": "PAK"}),

    dict(id="PSP-PAK-002", name="PAK: document number extracted",
         payload={"mrz_line1": PAK_MRZ_LINE1, "mrz_line2": PAK_MRZ_LINE2},
         expect={"decoded.document_number__len_gt": 5}),

    dict(id="PSP-PAK-003", name="PAK: gender decoded (M → Male)",
         payload={"mrz_line1": PAK_MRZ_LINE1, "mrz_line2": PAK_MRZ_LINE2},
         expect={"decoded.sex": "Male"}),

    dict(id="PSP-PAK-004", name="PAK: nationality field present",
         payload={"mrz_line1": PAK_MRZ_LINE1, "mrz_line2": PAK_MRZ_LINE2},
         expect={"decoded.nationality": "PAK"}),

    dict(id="PSP-PAK-005", name="PAK: DOB decoded as valid date",
         payload={"mrz_line1": PAK_MRZ_LINE1, "mrz_line2": PAK_MRZ_LINE2},
         expect={"decoded.date_of_birth.valid": True,
                 "decoded.date_of_birth.age_years__gt": 20}),

    dict(id="PSP-PAK-006", name="PAK: check digits structure present",
         payload={"mrz_line1": PAK_MRZ_LINE1, "mrz_line2": PAK_MRZ_LINE2},
         expect={"decoded.check_digits__type": "dict",
                 "decoded.all_check_digits_valid__type": "bool"}),

    # ── P-07: Fake MRZ detection ──────────────────────────────────────────────
    dict(id="PSP-FAK-001", name="Fake: ICAO specimen detected as test MRZ",
         payload={"mrz_line1": ICAO_LINE1, "mrz_line2": ICAO_LINE2},
         expect={"fake_detection.detected": True}),

    dict(id="PSP-FAK-002", name="Fake: real PAK MRZ not flagged as specimen",
         payload={"mrz_line1": PAK_MRZ_LINE1, "mrz_line2": PAK_MRZ_LINE2},
         expect={"fake_detection.detected": False}),

    # ── P-05: Document number format ──────────────────────────────────────────
    dict(id="PSP-DOC-001", name="Doc: valid Pakistani passport number (AA1234567)",
         payload={"doc_number": "AA1234567", "issuing_country": "PAK"},
         expect={"pak_format.valid": True}),

    dict(id="PSP-DOC-002", name="Doc: invalid PAK format flagged",
         payload={"doc_number": "12345", "issuing_country": "PAK"},
         expect={"pak_format.valid": False,
                 "overall_risk_score__gte": 15}),

    # ── P-09: Privacy ─────────────────────────────────────────────────────────
    dict(id="PSP-PRV-001", name="Privacy: SHA-256 hash always present",
         payload={"mrz_line1": PAK_MRZ_LINE1, "mrz_line2": PAK_MRZ_LINE2},
         expect={"privacy.sha256_hash__type": "str",
                 "privacy.sha256_hash__len_gt": 30}),

    dict(id="PSP-PRV-002", name="Privacy: doc_number route also hashed",
         payload={"doc_number": "AA1234567", "issuing_country": "PAK"},
         expect={"privacy.sha256_hash__type": "str"}),

    # ── Risk scoring ──────────────────────────────────────────────────────────
    dict(id="PSP-RSK-001", name="Risk: clean PAK MRZ has low risk",
         payload={"mrz_line1": PAK_MRZ_LINE1, "mrz_line2": PAK_MRZ_LINE2},
         expect={"overall_risk_level__in": ["Clean","Low","Medium","High","Critical"],
                 "all_flags__type": "list"}),
]


# ═══════════════════════════════════════════════════════════════════════════════
# PHONE TESTS — 20 tests
# ═══════════════════════════════════════════════════════════════════════════════
PHONE_TESTS = [

    # ── PH-01: Format validation ──────────────────────────────────────────────
    dict(id="PHN-FMT-001", name="Format: E.164 Pakistani mobile valid",
         payload={"value": "+923001234567"},
         expect={"format.valid": True,
                 "format.format": "E.164",
                 "credential_type": "phone"}),

    dict(id="PHN-FMT-002", name="Format: local 03xx format accepted",
         payload={"value": "03001234567"},
         expect={"format.valid": True,
                 "format.format__contains": "Local"}),

    dict(id="PHN-FMT-003", name="Format: 00 international prefix normalised",
         payload={"value": "00923001234567"},
         expect={"format.valid": True,
                 "format.normalized__contains": "+92"}),

    dict(id="PHN-FMT-004", name="Format: too short number rejected",
         payload={"value": "123"},
         expect={"format.valid": False,
                 "overall_risk_score__gte": 25}),

    # ── PH-02: Country identification ─────────────────────────────────────────
    dict(id="PHN-CTY-001", name="Country: +92 → Pakistan",
         payload={"value": "+923001234567"},
         expect={"country.calling_code": "92",
                 "country.country__contains": "Pakistan",
                 "country.detected": True}),

    dict(id="PHN-CTY-002", name="Country: +44 → United Kingdom",
         payload={"value": "+447911123456"},
         expect={"country.calling_code": "44",
                 "country.country__contains": "United Kingdom"}),

    dict(id="PHN-CTY-003", name="Country: +1 → US/Canada",
         payload={"value": "+12125551234"},
         expect={"country.calling_code": "1"}),

    dict(id="PHN-CTY-004", name="Country: +971 → UAE",
         payload={"value": "+971501234567"},
         expect={"country.country__contains": "UAE"}),

    # ── PH-03: Pakistani decode ────────────────────────────────────────────────
    dict(id="PHN-PK-001", name="PK: 0300 prefix → Jazz operator",
         payload={"value": "03001234567"},
         expect={"pk_decode.is_pk_number": True,
                 "pk_decode.operator": "Jazz",
                 "pk_decode.is_mobile": True}),

    dict(id="PHN-PK-002", name="PK: 0345 prefix → Telenor",
         payload={"value": "03451234567"},
         expect={"pk_decode.operator": "Telenor"}),

    dict(id="PHN-PK-003", name="PK: 0321 prefix → Zong",
         payload={"value": "03211234567"},
         expect={"pk_decode.operator": "Zong"}),

    dict(id="PHN-PK-004", name="PK: 0351 prefix → Ufone",
         payload={"value": "03511234567"},
         expect={"pk_decode.operator": "Ufone"}),

    dict(id="PHN-PK-005", name="PK: +92 E.164 also decoded",
         payload={"value": "+923001234567"},
         expect={"pk_decode.is_pk_number": True,
                 "pk_decode.e164_format": "+923001234567"}),

    # ── PH-04: Number type ────────────────────────────────────────────────────
    dict(id="PHN-TYP-001", name="Type: US toll-free 1-800 detected",
         payload={"value": "+18001234567"},
         expect={"number_type.type": "toll_free"}),

    dict(id="PHN-TYP-002", name="Type: PK mobile classified correctly",
         payload={"value": "03001234567"},
         expect={"number_type.type": "mobile"}),

    # ── PH-10: Scam prefix ────────────────────────────────────────────────────
    dict(id="PHN-SCM-001", name="Scam: +1809 Caribbean premium flagged",
         payload={"value": "+18091234567"},
         expect={"scam_prefix.is_scam_prefix": True,
                 "overall_risk_score__gte": 35}),

    dict(id="PHN-SCM-002", name="Scam: regular PK number not flagged",
         payload={"value": "+923001234567"},
         expect={"scam_prefix.is_scam_prefix": False}),

    # ── Privacy + structure ────────────────────────────────────────────────────
    dict(id="PHN-PRV-001", name="Privacy: hash always present",
         payload={"value": "+923001234567"},
         expect={"privacy.sha256_hash__type": "str",
                 "privacy.sha256_hash__len_gt": 30}),

    dict(id="PHN-RSK-001", name="Risk: level always present",
         payload={"value": "+923001234567"},
         expect={"overall_risk_level__in": ["Clean","Low","Medium","High","Critical"],
                 "all_flags__type": "list",
                 "credential_type": "phone"}),

    dict(id="PHN-RSK-002", name="Risk: carrier lookup structure present",
         payload={"value": "+923001234567"},
         expect={"carrier_lookup__type": "dict",
                 "carrier_lookup.available__type": "bool"}),
]


# ═══════════════════════════════════════════════════════════════════════════════
# RUNNER
# ═══════════════════════════════════════════════════════════════════════════════
def sep(char="═", w=70): print(f"{BOLD}{char*w}{RESET}")

def run_suite(name, tests, endpoint, verbose):
    p=f=0; sep()
    print(f"{BOLD}{CYAN}  {name}{RESET}"); sep()
    for t in tests:
        r = run_test(t["id"], t["name"], endpoint, t["payload"], t["expect"])
        tag = f"{BOLD}[{t['id']:>14}]{RESET}"
        ms  = f"{YELLOW}({r.elapsed_ms:.0f}ms){RESET}" if r.elapsed_ms else ""
        if r.passed:
            p += 1
            print(f"  {tag} {GREEN}PASS{RESET}  {t['name']}  {ms}")
        else:
            f += 1
            print(f"  {tag} {RED}FAIL{RESET}  {t['name']}  {ms}")
            for fx in r.failures:
                print(f"         {RED}{fx}{RESET}")
            if verbose and r.response:
                snippet = json.dumps(r.response, indent=2)[:600]
                print(f"         {YELLOW}Response:{RESET}")
                print("         " + snippet.replace("\n", "\n         "))
    return p, f

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--national-id", action="store_true")
    ap.add_argument("--passport",    action="store_true")
    ap.add_argument("--phone",       action="store_true")
    ap.add_argument("--verbose",     action="store_true")
    args = ap.parse_args()
    run_all = not (args.national_id or args.passport or args.phone)

    print(f"\n{BOLD}Aegis AI — Tier 3 Automated Test Suite{RESET}")
    print(f"Target: {CYAN}{BASE}{RESET}\n")
    try:
        r = httpx.get(f"{BASE}/health", timeout=5)
        h = r.json()
        print(f"{GREEN}✓ Server healthy{RESET} — version {h.get('version')} | redis: {h.get('redis')}\n")
    except Exception as e:
        print(f"{RED}✗ Cannot reach {BASE} — {e}{RESET}\n  Make sure: docker-compose up\n")
        sys.exit(1)

    tp = tf = 0
    suites = []
    if run_all or args.national_id:
        suites.append(("NATIONAL ID ANALYSIS (CNIC · SSN · Aadhaar)", NATIONAL_ID_TESTS, "/analyze/national-id"))
    if run_all or args.passport:
        suites.append(("PASSPORT / TRAVEL DOC ANALYSIS", PASSPORT_TESTS, "/analyze/passport"))
    if run_all or args.phone:
        suites.append(("PHONE NUMBER ANALYSIS", PHONE_TESTS, "/analyze/phone"))

    for name, tests, ep in suites:
        p, f = run_suite(name, tests, ep, args.verbose)
        tp += p; tf += f

    total = tp + tf
    sep(); print(f"\n{BOLD}  SUMMARY{RESET}"); sep("─")
    print(f"  Total:  {total}")
    print(f"  {GREEN}Passed: {tp}{RESET}")
    print(f"  {RED}Failed: {tf}{RESET}")
    pct = (tp / total * 100) if total else 0
    print(f"\n  Pass rate: {BOLD}{pct:.1f}%{RESET}"); sep()

    if tf:
        print(f"\n{RED}  {tf} test(s) failed.{RESET}\n")
        sys.exit(1)
    else:
        print(f"\n{GREEN}  All tests passed!{RESET}\n")
        sys.exit(0)

if __name__ == "__main__":
    main()
