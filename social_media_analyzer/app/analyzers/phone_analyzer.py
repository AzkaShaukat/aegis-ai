"""Phone analysis: FP-1 format, FP-2 carrier/VoIP, FWA-1 WhatsApp."""
import re, asyncio, logging, httpx
from datetime import datetime
import phonenumbers
from phonenumbers import geocoder, carrier, number_type, is_valid_number, is_possible_number
from phonenumbers import PhoneNumberType, format_number, PhoneNumberFormat, parse as ph_parse
from app.models import (PhoneFormatResult, PhoneCarrierResult, WhatsAppResult,
                         PhoneAnalysisResult, SuspicionLevel)
from app.config import get_settings

logger   = logging.getLogger(__name__)
settings = get_settings()

TYPE_MAP = {
    PhoneNumberType.MOBILE:       "mobile",
    PhoneNumberType.FIXED_LINE:   "fixed_line",
    PhoneNumberType.VOIP:         "voip",
    PhoneNumberType.TOLL_FREE:    "toll_free",
    PhoneNumberType.PREMIUM_RATE: "premium_rate",
    PhoneNumberType.SHARED_COST:  "shared_cost",
    PhoneNumberType.PAGER:        "pager",
    PhoneNumberType.UNKNOWN:      "unknown",
}

def check_phone_format(phone: str) -> PhoneFormatResult:
    try:
        pn    = ph_parse(phone, None)
        valid = is_valid_number(pn)
        poss  = is_possible_number(pn)
        if not valid:
            return PhoneFormatResult(is_valid=False,is_possible=poss,suspicion_points=20,
                details={"error":"Invalid number according to phonenumbers library"})
        ntype    = TYPE_MAP.get(number_type(pn), "unknown")
        country  = geocoder.country_name_for_number(pn,"en")
        cc       = phonenumbers.region_code_for_number(pn)
        e164     = format_number(pn, PhoneNumberFormat.E164)
        national = format_number(pn, PhoneNumberFormat.NATIONAL)
        pts = 15 if ntype == "voip" else 5 if ntype in ("unknown","premium_rate") else 0
        return PhoneFormatResult(is_valid=True,is_possible=True,country_code=cc,country_name=country,
            number_type=ntype,formatted_e164=e164,formatted_national=national,suspicion_points=pts,details={})
    except Exception as e:
        return PhoneFormatResult(is_valid=False,is_possible=False,suspicion_points=20,details={"error":str(e)})

async def check_carrier(phone: str) -> PhoneCarrierResult:
    # Local phonenumbers carrier lookup
    try:
        pn    = ph_parse(phone, None)
        carr  = carrier.name_for_number(pn, "en") or "unknown"
        ntype = TYPE_MAP.get(number_type(pn), "unknown")
        is_voip = ntype == "voip"
        pts   = 20 if is_voip else 0
    except Exception as e:
        return PhoneCarrierResult(available=False,details={"error":str(e)})
    # Optional NumVerify for richer data
    if settings.numverify_api_key:
        try:
            async with httpx.AsyncClient(timeout=10) as c:
                r = await c.get("http://apilayer.net/api/validate",
                    params={"access_key":settings.numverify_api_key,"number":phone,"format":1})
            if r.status_code == 200:
                d = r.json()
                carr  = d.get("carrier",carr) or carr
                ltype = d.get("line_type","") or ntype
                is_voip = ltype.lower() in ("voip","virtual")
                pts   = 20 if is_voip else 0
                return PhoneCarrierResult(available=True,carrier=carr,line_type=ltype,
                    is_voip=is_voip,country=d.get("country_name"),suspicion_points=pts,details={"source":"numverify"})
        except: pass
    return PhoneCarrierResult(available=True,carrier=carr if carr != "unknown" else None,
        line_type=ntype,is_voip=is_voip,suspicion_points=pts,details={"source":"phonenumbers_lib"})

async def check_whatsapp(phone: str) -> WhatsAppResult:
    try:
        pn     = ph_parse(phone, None)
        valid  = is_valid_number(pn)
        if not valid: return WhatsAppResult(number_valid=False,details={"error":"Invalid number"})
        e164   = format_number(pn, PhoneNumberFormat.E164)
        digits = re.sub(r"[^\d]","",e164)
        wa_url = f"https://wa.me/{digits}"
        return WhatsAppResult(number_valid=True,formatted_number=e164,whatsapp_link=wa_url,
            details={"digits":digits,"link":wa_url})
    except Exception as e:
        return WhatsAppResult(number_valid=False,details={"error":str(e)})

def _classify(score: int) -> SuspicionLevel:
    if score >= 60: return SuspicionLevel.HIGH
    if score >= 30: return SuspicionLevel.MEDIUM
    return SuspicionLevel.LOW

def _verdict(fp1, fp2, is_wa: bool) -> str:
    if not fp1.is_valid: return "Invalid — not a real phone number"
    if fp2 and fp2.is_voip: return "VoIP/Fake — virtual number detected"
    if is_wa: return "Valid — WhatsApp number"
    return "Valid — real phone number"

async def analyze_phone(phone: str, is_whatsapp: bool = False) -> PhoneAnalysisResult:
    start = datetime.utcnow()
    fp1 = check_phone_format(phone)
    fp2, fwa = await asyncio.gather(check_carrier(phone), check_whatsapp(phone) if is_whatsapp else asyncio.coroutine(lambda: None)())
    score = min(100, fp1.suspicion_points + (fp2.suspicion_points if fp2 else 0))
    flags = []
    if not fp1.is_valid:   flags.append("[FP-1] Invalid phone number")
    if fp2 and fp2.is_voip: flags.append(f"[FP-2] VoIP/Virtual: {fp2.carrier}")
    dur = (datetime.utcnow()-start).total_seconds()
    return PhoneAnalysisResult(phone_number=phone,is_whatsapp=is_whatsapp,
        suspicion_score=score,suspicion_level=_classify(score),confidence=0.9,
        verdict=_verdict(fp1,fp2,is_whatsapp),
        fp1_format=fp1,fp2_carrier=fp2,fwa1_whatsapp=fwa if is_whatsapp else None,
        flags_raised=flags,score_breakdown={"fp1":fp1.suspicion_points,"fp2":fp2.suspicion_points if fp2 else 0},
        analysis_duration_seconds=round(dur,2))
