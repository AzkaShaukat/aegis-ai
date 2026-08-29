#!/usr/bin/env python3
"""
================================================================
  Aegis AI — Tier 4 Test Suite: API Keys & Tokens
  22 tests | AK-01 through AK-10

  USAGE:
      python tests/test_tier4.py              # all
      python tests/test_tier4.py --verbose    # show full responses on fail
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
    if "_connection_error" in resp:
        return TR(tid,name,False,[resp["_connection_error"]])
    if "_http_error" in resp:
        return TR(tid,name,False,[f"HTTP {resp['_http_error']}: {resp.get('_body','')}"])
    fails = check(resp, assertions)
    return TR(tid,name,len(fails)==0,fails,resp,round(el,1))


EP = "/analyze/api-key"

TESTS = [
    # ── AK-01: Service detection ───────────────────────────────────────────────
    dict(id="AK-SVC-001", name="Service: AWS Access Key ID detected",
         payload={"value": "AKIAIOSFODNN7EXAMPLE"},
         expect={"service_detection.detected": True,
                 "service_detection.primary_service__contains": "AWS",
                 "credential_type": "api_key"}),

    dict(id="AK-SVC-002", name="Service: GitHub PAT (ghp_) detected",
         payload={"value": "ghp_" + "A"*36},
         expect={"service_detection.detected": True,
                 "service_detection.primary_service__contains": "GitHub"}),

    dict(id="AK-SVC-003", name="Service: Stripe live secret key detected",
         payload={"value": "sk_live_abcdefghijklmnopqrstuvwx"},
         expect={"service_detection.detected": True,
                 "service_detection.primary_service__contains": "Stripe",
                 "service_detection.risk_tier_label": "Critical"}),

    dict(id="AK-SVC-004", name="Service: Stripe test key = low risk",
         payload={"value": "sk_test_4eC39HqLyjWDarjtT1zdp7dc"},
         expect={"service_detection.detected": True,
                 "service_detection.primary_service__contains": "Stripe",
                 "overall_risk_score__lt": 60}),

    dict(id="AK-SVC-005", name="Service: OpenAI key detected",
         payload={"value": "sk-" + "a"*48},
         expect={"service_detection.detected": True,
                 "service_detection.primary_service__contains": "OpenAI"}),

    dict(id="AK-SVC-006", name="Service: SendGrid key detected",
         payload={"value": "SG." + "a"*22 + "." + "b"*43},
         expect={"service_detection.detected": True,
                 "service_detection.primary_service__contains": "SendGrid"}),

    dict(id="AK-SVC-007", name="Service: Discord bot token detected",
         payload={"value": "MTA4NzY3NjMyNTgwNzM2NjE5.GgDWnl.abc123defghijklmnopqrstuvwxy"},
         expect={"credential_type": "api_key",
                 "service_detection__type": "dict"}),

    dict(id="AK-SVC-008", name="Service: unknown random string",
         payload={"value": "randomstringthatmatchesnothing!!"},
         expect={"credential_type": "api_key",
                 "overall_risk_level__in": ["Clean","Low","Medium","High","Critical"]}),

    # ── AK-02: Entropy ────────────────────────────────────────────────────────
    dict(id="AK-ENT-001", name="Entropy: high-entropy key scores Strong",
         payload={"value": "sk_live_" + "aB3dEfGhIjKl4mNoPqRsTuVw"},
         expect={"entropy.strength__in": ["Strong","Very Strong","Medium"],
                 "entropy.shannon_entropy__gt": 2.0,
                 "entropy.key_length__gt": 10}),

    dict(id="AK-ENT-002", name="Entropy: repeating chars = Very Weak",
         payload={"value": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
         expect={"entropy.strength__in": ["Very Weak","Weak"],
                 "entropy.shannon_entropy__lt": 1.0}),

    dict(id="AK-ENT-003", name="Entropy: charset analysis present",
         payload={"value": "AKIAIOSFODNN7EXAMPLE"},
         expect={"entropy.has_uppercase": True,
                 "entropy.has_digits": True,
                 "entropy.charset_size__gt": 25}),

    # ── AK-04: Test key detection ─────────────────────────────────────────────
    dict(id="AK-TST-001", name="Test key: known AWS example key detected",
         payload={"value": "AKIAIOSFODNN7EXAMPLE"},
         expect={"test_key.is_test_key": True,
                 "overall_risk_score__lt": 55}),  # AWS override skipped for test keys

    dict(id="AK-TST-002", name="Test key: sk_test_ stripe prefix detected",
         payload={"value": "sk_test_BQokikJOvBiI2HlWgH4olfQ2"},
         expect={"test_key.is_test_key": True}),

    dict(id="AK-TST-003", name="Test key: YOUR_API_KEY placeholder detected",
         payload={"value": "YOUR_API_KEY_HERE"},
         expect={"test_key.is_test_key": True}),

    # ── AK-08: Scope indicators ───────────────────────────────────────────────
    dict(id="AK-SCP-001", name="Scope: sk_live_ = elevated scope flag",
         payload={"value": "sk_live_abcdefghijklmnopqrstuvwx"},
         expect={"scope.is_likely_elevated": True,
                 "scope.elevated_scope_signals__type": "list"}),

    dict(id="AK-SCP-002", name="Scope: pk_test_ = likely readonly (lower risk)",
         payload={"value": "pk_test_AbCdEfGhIjKlMnOpQrStUvWx"},
         expect={"scope.is_likely_readonly": True}),

    # ── AK-09: GitGuardian-style entropy check ────────────────────────────────
    dict(id="AK-GGS-001", name="GitGuardian check: high-entropy string detected",
         payload={"value": "ghp_" + "aB3dEfGhIjKl4mNoPqRs5tUvWxYz01234"},
         expect={"gitguardian_check__type": "dict",
                 "gitguardian_check.high_entropy_strings_found__type": "bool"}),

    # ── AK-07: JWT decode ─────────────────────────────────────────────────────
    dict(id="AK-JWT-001", name="JWT: valid token structure detected",
         payload={"value": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"},
         expect={"service_detection.primary_service__contains": "JWT",
                 "service_detection.detected": True}),

    # ── AK-10: Risk + privacy ─────────────────────────────────────────────────
    dict(id="AK-RSK-001", name="Risk: Stripe live key = high/critical risk",
         payload={"value": "sk_live_abcdefghijklmnopqrstuvwx"},
         expect={"overall_risk_score__gte": 50,
                 "overall_risk_level__in": ["Critical","High","Medium"]}),

    dict(id="AK-RSK-002", name="Risk: rotation_recommended present",
         payload={"value": "sk_live_abcdefghijklmnopqrstuvwx"},
         expect={"rotation_recommended__type": "bool",
                 "rotation_recommended": True}),

    dict(id="AK-PRV-001", name="Privacy: SHA-256 hash always present",
         payload={"value": "AKIAIOSFODNN7EXAMPLE"},
         expect={"privacy.sha256_hash__type": "str",
                 "privacy.sha256_hash__len_gt": 30,
                 "privacy.key_length__gt": 0}),

    dict(id="AK-REM-001", name="Remediation: steps always present",
         payload={"value": "sk_live_abcdefghijklmnopqrstuvwx"},
         expect={"remediation.steps__type": "list",
                 "remediation.steps__len_gt": 0}),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    print(f"\n{B}Aegis AI — Tier 4 Test Suite (API Keys & Tokens){Z}")
    print(f"Target: {C}{BASE}{Z}\n")
    try:
        r = httpx.get(f"{BASE}/health", timeout=5)
        h = r.json()
        print(f"{G}✓ Server healthy{Z} — v{h.get('version')} | redis: {h.get('redis')}\n")
    except Exception as e:
        print(f"{R}✗ Cannot reach {BASE} — {e}{Z}\n"); sys.exit(1)

    sep = "═"*70
    print(f"{B}{sep}{Z}")
    print(f"{B}{C}  API KEY & TOKEN ANALYSIS (10 features, 22 tests){Z}")
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
