"""
Aegis AI v4 — Live API Test Script
Run: python manual_test.py
Requires API running: docker compose up
"""
import sys, json, requests
BASE = "http://localhost:8003"
G="\033[92m"; R="\033[91m"; Y="\033[93m"; B="\033[96m"; W="\033[1m"; X="\033[0m"

def hdr(t): print(f"\n{B}{W}{'═'*60}{X}\n{B}{W}  {t}{X}\n{B}{W}{'═'*60}{X}")
def post(body):
    try:
        r = requests.post(f"{BASE}/analyze", json=body, timeout=60)
        r.raise_for_status(); return r.json()
    except Exception as e: print(f"  {R}Error: {e}{X}"); return {}

def show(result):
    if not result: return
    score = result.get("suspicion_score",0)
    level = result.get("suspicion_level","?")
    verdict = result.get("verdict","")
    ico = "🟢" if level=="Low" else ("🟡" if level=="Medium" else "🔴")
    clr = G if level=="Low" else (Y if level=="Medium" else R)
    print(f"\n  {ico}  Score: {clr}{W}{score}/100{X}  Level: {clr}{W}{level}{X}")
    if verdict: print(f"  Verdict : {W}{verdict}{X}")
    bd = result.get("score_breakdown",{})
    if bd:
        non_zero = {k:v for k,v in bd.items() if v>0}
        if non_zero:
            print(f"  Breakdown: {non_zero}")
    flags = result.get("flags_raised",[])
    if flags:
        print(f"  Flags:"); [print(f"    {R}▸{X} {f}") for f in flags[:6]]
        if len(flags)>6: print(f"    +{len(flags)-6} more")
    lims = result.get("data_limitations",[])
    if lims: print(f"  {Y}Notes:{X}"); [print(f"    ⚠ {l}") for l in lims[:3]]

results = {}

hdr("HEALTH CHECK")
try:
    h = requests.get(f"{BASE}/health", timeout=5).json()
    print(f"\n  Status  : {G}{h.get('status')}{X}")
    print(f"  Redis   : {G+'OK' if h.get('redis_connected') else Y+'offline (no caching)'}{X}")
    print(f"  Phase2  : {[k for k,v in h.get('phase2_apis',{}).items() if v]}")
    print(f"  Phase3  : {[k for k,v in h.get('phase3_apis',{}).items() if v]}")
    print(f"  Phase4  : {[k for k,v in h.get('phase4_apis',{}).items() if v]}")
except Exception as e:
    print(f"\n  {R}API not reachable: {e}{X}\n  Start with: docker compose up")
    sys.exit(1)

hdr("E-1 Legitimate email (expect: Low 🟢)")
r = post({"value":"john.doe@gmail.com","input_type":"email"}); show(r)
results["E-1 legit gmail"] = r.get("suspicion_level") in ("Low","Medium")

hdr("E-2 Disposable email (expect: High 🔴)")
r = post({"value":"random@mailinator.com","input_type":"email"}); show(r)
fe2 = r.get("fe2_disposable",{}) or {}
ok = isinstance(fe2,dict) and fe2.get("is_disposable",False)
results["E-2 disposable"] = ok
print(f"\n  Disposable detected: {ok}")

hdr("E-3 Invalid email format (expect: High 🔴)")
r = post({"value":"notanemail","input_type":"email"}); show(r)
fe1 = r.get("fe1_format",{}) or {}
results["E-3 bad format"] = isinstance(fe1,dict) and not fe1.get("is_valid_format",True)

hdr("E-4 Yopmail disposable (expect: High 🔴)")
r = post({"value":"user@yopmail.com","input_type":"email"}); show(r)
fe2b = r.get("fe2_disposable",{}) or {}
results["E-4 yopmail"] = isinstance(fe2b,dict) and fe2b.get("is_disposable",False)

hdr("P-1 Valid PK mobile (expect: Valid 🟢)")
r = post({"value":"+923001234567","input_type":"phone"}); show(r)
fp1 = r.get("fp1_format",{}) or {}
print(f"\n  Country: {fp1.get('country_code')}  Type: {fp1.get('number_type')}")
results["P-1 PK mobile"] = isinstance(fp1,dict) and fp1.get("is_valid",False)

hdr("P-2 Invalid number (expect: Invalid 🔴)")
r = post({"value":"+1234","input_type":"phone"}); show(r)
fp1b = r.get("fp1_format",{}) or {}
results["P-2 invalid"] = isinstance(fp1b,dict) and not fp1b.get("is_valid",True)

hdr("P-3 UK landline")
r = post({"value":"+442071234567","input_type":"phone"}); show(r)
fp1c = r.get("fp1_format",{}) or {}
print(f"\n  Country: {fp1c.get('country_code')}")
results["P-3 UK"] = isinstance(fp1c,dict) and fp1c.get("country_code")=="GB"

hdr("WA-1 WhatsApp link generation")
r = post({"value":"+923001234567","input_type":"whatsapp"}); show(r)
fwa = r.get("fwa1_whatsapp",{}) or {}
print(f"\n  Link: {fwa.get('whatsapp_link','N/A')}")
results["WA-1 link"] = isinstance(fwa,dict) and fwa.get("number_valid",False)

hdr("SUMMARY")
print()
passed = 0
for name, ok in results.items():
    ico = f"{G}✓{X}" if ok else f"{R}✗{X}"
    print(f"  {ico}  {name}"); passed += int(bool(ok))
total = len(results)
print(f"\n  {Y}ℹ Social media tests: use /docs Swagger UI for live scraping{X}")
print(f"  {Y}ℹ Offline unit tests: pytest tests/ -v{X}")
print(f"\n  {'═'*40}")
print(f"  {(G+W) if passed==total else (Y+W)}  {passed}/{total} PASSED{X}")
print(f"  {'═'*40}\n")
