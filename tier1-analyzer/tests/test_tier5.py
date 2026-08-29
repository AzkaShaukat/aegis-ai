#!/usr/bin/env python3
"""
================================================================
  Aegis AI — Tier 5 Test Suite: Advanced Phone Security
  20 tests | AP-01 through AP-12

  USAGE:
      python tests/test_tier5.py              # all
      python tests/test_tier5.py --verbose    # show full responses on fail
================================================================
"""
import argparse, json, sys, time
from dataclasses import dataclass, field

try:
    import httpx
    from colorama import Fore, Style, init as ci; ci(autoreset=True)
    G=Fore.GREEN; R=Fore.RED; Y=Fore.YELLOW; C=Fore.CYAN; B=Style.BRIGHT; Z=Style.RESET_ALL
except ImportError:
    print("pip install httpx colorama"); sys.exit(1)

BASE = "http://localhost:8006"

@dataclass
class TR:
    test_id: str; name: str; passed: bool
    failures: list = field(default_factory=list)
    response: dict = field(default_factory=dict)
    elapsed_ms: float = 0.0

def _get(obj, path):
    for k in path.split("."):
        if obj is None: return None
        obj = obj.get(k) if isinstance(obj, dict) else None
    return obj

def check(resp, assertions):
    fails = []
    for expr, expected in assertions.items():
        path, op = (expr.rsplit("__",1) if "__" in expr.rsplit(".",1)[-1] else (expr,"eq"))
        actual = _get(resp, path)
        try:
            if   op=="eq"       and actual != expected:  fails.append(f"  ✗ {path}: expected {expected!r}, got {actual!r}")
            elif op=="not"      and actual == expected:  fails.append(f"  ✗ {path}: expected NOT {expected!r}")
            elif op=="gt"       and not (isinstance(actual,(int,float)) and actual>expected): fails.append(f"  ✗ {path}: expected >{expected}, got {actual!r}")
            elif op=="gte"      and not (isinstance(actual,(int,float)) and actual>=expected):fails.append(f"  ✗ {path}: expected >={expected}, got {actual!r}")
            elif op=="lt"       and not (isinstance(actual,(int,float)) and actual<expected): fails.append(f"  ✗ {path}: expected <{expected}, got {actual!r}")
            elif op=="in"       and actual not in expected: fails.append(f"  ✗ {path}: expected one of {expected}, got {actual!r}")
            elif op=="contains" and not (isinstance(actual,(str,list)) and expected in actual): fails.append(f"  ✗ {path}: expected to contain {expected!r}, got {actual!r}")
            elif op=="type":
                tm={"str":str,"int":int,"float":float,"list":list,"dict":dict,"bool":bool}
                if not isinstance(actual,tm.get(expected,object)): fails.append(f"  ✗ {path}: expected type {expected}, got {type(actual).__name__}")
            elif op=="truthy"   and bool(actual) != expected: fails.append(f"  ✗ {path}: truthy={expected}, got {actual!r}")
            elif op=="exists":
                if (actual is not None) != expected: fails.append(f"  ✗ {path}: exists={expected}, got {actual!r}")
            elif op=="len_gt"   and not (isinstance(actual,(str,list,dict)) and len(actual)>expected): fails.append(f"  ✗ {path}: expected len>{expected}")
        except Exception as e:
            fails.append(f"  ✗ {path}: error — {e}")
    return fails

def post(ep, payload):
    t0=time.perf_counter()
    try:
        r=httpx.post(f"{BASE}{ep}",json=payload,headers={"X-API-Key": "1122"},timeout=30)
        el=(time.perf_counter()-t0)*1000
        if r.status_code not in (200,201):
            return {"_http_error":r.status_code,"_body":r.text[:400]}, el
        return r.json(), el
    except httpx.ConnectError:
        return {"_connection_error":f"Cannot connect to {BASE}"}, 0
    except Exception as e:
        return {"_error":str(e)}, 0

def run_test(tid, name, ep, payload, assertions):
    resp, el = post(ep, payload)
    if "_connection_error" in resp: return TR(tid,name,False,[resp["_connection_error"]])
    if "_http_error"       in resp: return TR(tid,name,False,[f"HTTP {resp['_http_error']}: {resp.get('_body','')}"])
    fails = check(resp, assertions)
    return TR(tid,name,len(fails)==0,fails,resp,round(el,1))


EP = "/analyze/phone/advanced"

TESTS = [
    # ── AP-01: OTP bypass risk ────────────────────────────────────────────────
    dict(id="AP-OTP-001", name="OTP: valid PK mobile — low bypass risk",
         payload={"value": "+923001234567"},
         expect={"otp_bypass_risk.otp_bypass_risk__lt": 40,
                 "otp_bypass_risk.otp_viable": True,
                 "credential_type": "phone_advanced"}),

    dict(id="AP-OTP-002", name="OTP: toll-free cannot receive SMS",
         payload={"value": "+18005551234"},
         expect={"otp_bypass_risk.otp_bypass_risk__gte": 30,
                 "otp_bypass_risk.risk_factors__type": "list"}),

    dict(id="AP-OTP-003", name="OTP: repeating digits = high bypass risk",
         payload={"value": "+12223333333"},
         expect={"otp_bypass_risk.otp_bypass_risk__gte": 20,
                 "otp_bypass_risk.risk_factors__type": "list"}),

    dict(id="AP-OTP-004", name="OTP: recommendation always present",
         payload={"value": "+923001234567"},
         expect={"otp_bypass_risk.recommendation__type": "str"}),

    # ── AP-02: SIM swap risk ──────────────────────────────────────────────────
    dict(id="AP-SIM-001", name="SIM swap: Jazz number gets PK risk factor",
         payload={"value": "+923001234567", "carrier": "Jazz"},
         expect={"sim_swap_risk.sim_swap_risk_score__gte": 20,
                 "sim_swap_risk.sim_swap_risk_level__in": ["High","Medium","Low"]}),

    dict(id="AP-SIM-002", name="SIM swap: mitigation steps present",
         payload={"value": "+923001234567", "carrier": "Jazz"},
         expect={"sim_swap_risk.mitigation__type": "list",
                 "sim_swap_risk.mitigation__len_gt": 0}),

    dict(id="AP-SIM-003", name="SIM swap: T-Mobile = high carrier risk",
         payload={"value": "+12125551234", "carrier": "T-Mobile"},
         expect={"sim_swap_risk.sim_swap_risk_score__gte": 30}),

    # ── AP-07: Smishing detection ─────────────────────────────────────────────
    dict(id="AP-SMS-001", name="Smishing: OTP harvesting message detected",
         payload={"value": "+923001234567",
                  "sms_body": "Your OTP is 123456. Please share this code to verify your JazzCash account."},
         expect={"sms_analysis.provided": True,
                 "sms_analysis.smishing_score__gte": 20,
                 "sms_analysis.smishing_indicators__type": "list"}),

    dict(id="AP-SMS-002", name="Smishing: bank suspension urgency message",
         payload={"value": "+923001234567",
                  "sms_body": "URGENT: Your HBL account has been blocked. Click here to verify: http://hbl-secure.xyz/verify"},
         expect={"sms_analysis.is_likely_smishing": True,
                 "sms_analysis.suspicious_urls__type": "list"}),

    dict(id="AP-SMS-003", name="Smishing: clean message = not smishing",
         payload={"value": "+923001234567",
                  "sms_body": "Hi, your package will arrive tomorrow between 2-4pm."},
         expect={"sms_analysis.provided": True,
                 "sms_analysis.is_likely_smishing": False}),

    dict(id="AP-SMS-004", name="Smishing: prize scam detected",
         payload={"value": "+923001234567",
                  "sms_body": "Congratulations! You have won a prize worth Rs50,000. Click to claim your reward now."},
         expect={"sms_analysis.smishing_score__gte": 20}),

    # ── AP-09: 2FA security rating ────────────────────────────────────────────
    dict(id="AP-2FA-001", name="2FA: rating always present",
         payload={"value": "+923001234567"},
         expect={"two_fa_rating.rating__type": "str",
                 "two_fa_rating.recommendation__type": "str",
                 "two_fa_rating.better_alternatives__type": "list"}),

    dict(id="AP-2FA-002", name="2FA: Jazz/PK gets rating",
         payload={"value": "+923001234567", "carrier": "Jazz"},
         expect={"two_fa_rating.rating__type": "str",
                 "two_fa_rating.combined_risk_score__type": "int"}),

    dict(id="AP-2FA-003", name="2FA: better_alternatives has 3+ options",
         payload={"value": "+923001234567"},
         expect={"two_fa_rating.better_alternatives__len_gt": 0}),

    # ── AP-10: Pakistani telecom fraud ───────────────────────────────────────
    dict(id="AP-PKF-001", name="PK fraud: Jazz number flagged as PK",
         payload={"value": "03001234567", "carrier": "Jazz"},
         expect={"pk_telecom.is_pk_number": True,
                 "pk_telecom.pk_fraud_context__type": "dict"}),

    dict(id="AP-PKF-002", name="PK fraud: non-PK number not flagged",
         payload={"value": "+447911123456"},
         expect={"pk_telecom.is_pk_number": False}),

    # ── AP-06: Phone reputation ───────────────────────────────────────────────
    dict(id="AP-REP-001", name="Reputation: dict structure always returned",
         payload={"value": "+923001234567"},
         expect={"phone_reputation__type": "dict",
                 "phone_reputation.source__type": "str"}),

    dict(id="AP-REP-002", name="Reputation: scam signals list present",
         payload={"value": "+19001234567"},
         expect={"phone_reputation__type": "dict"}),

    # ── General ───────────────────────────────────────────────────────────────
    dict(id="AP-RSK-001", name="Risk: level always present",
         payload={"value": "+923001234567"},
         expect={"overall_risk_level__in": ["Clean","Low","Medium","High","Critical"],
                 "all_flags__type": "list",
                 "masked_number__type": "str"}),

    dict(id="AP-RSK-002", name="Risk: high-risk smishing raises score",
         payload={"value": "+923001234567",
                  "sms_body": "URGENT action required! Your NADRA record is being deleted. "
                               "Call 0300-XXXXXXX immediately to verify your CNIC."},
         expect={"overall_risk_score__gte": 20}),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    print(f"\n{B}Aegis AI — Tier 5 Test Suite (Advanced Phone Security){Z}")
    print(f"Target: {C}{BASE}{Z}\n")
    try:
        r = httpx.get(f"{BASE}/health", timeout=5)
        h = r.json()
        print(f"{G}✓ Server healthy{Z} — v{h.get('version')} | redis: {h.get('redis')}\n")
    except Exception as e:
        print(f"{R}✗ Cannot reach {BASE} — {e}{Z}\n"); sys.exit(1)

    sep = "═"*70
    print(f"{B}{sep}{Z}")
    print(f"{B}{C}  ADVANCED PHONE SECURITY (12 features, 20 tests){Z}")
    print(f"{B}{sep}{Z}")

    tp = tf = 0
    for t in TESTS:
        r = run_test(t["id"], t["name"], EP, t["payload"], t["expect"])
        tag = f"{B}[{t['id']:>12}]{Z}"
        ms = f"{Y}({r.elapsed_ms:.0f}ms){Z}" if r.elapsed_ms else ""
        if r.passed:
            tp += 1
            print(f"  {tag} {G}PASS{Z}  {t['name']}  {ms}")
        else:
            tf += 1
            print(f"  {tag} {R}FAIL{Z}  {t['name']}  {ms}")
            for fx in r.failures:
                print(f"         {R}{fx}{Z}")
            if args.verbose and r.response:
                print(f"         {Y}Response:{Z}\n         " +
                      json.dumps(r.response, indent=2)[:700].replace("\n","\n         "))

    total = tp + tf
    print(f"\n{B}{'─'*70}{Z}")
    print(f"  Total: {total}   {G}Passed: {tp}{Z}   {R}Failed: {tf}{Z}")
    pct = tp/total*100 if total else 0
    print(f"  Pass rate: {B}{pct:.1f}%{Z}")
    print(f"{B}{sep}{Z}\n")
    sys.exit(0 if tf == 0 else 1)

if __name__ == "__main__":
    main()
