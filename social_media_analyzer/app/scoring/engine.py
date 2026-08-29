"""Aegis AI v4 — Scoring engine: Phase 1 + 2 + 3 + 4."""
import asyncio, logging, re
from datetime import datetime
from typing import List, Optional

from app.models import (ProfileData, SocialMediaAnalysisResult, SuspicionLevel,
    UsernameEntropyResult, NameDivergenceResult, ProfileCompletenessResult,
    PostingFrequencyResult, EngagementRatioResult, GrowthAnomalyResult,
    TwitterHeuristicsResult, SocialBladeResult, BotometerResult, ReverseImageResult,
    EmailRepResult, SerpApiResult, BioNLPResult, CrossPlatformResult, OsintResult,
    AccountAgeResult, LinkSafetyResult, ContentPatternResult, LanguageGeoResult)
from app.analyzers.f01_username_entropy   import analyze_username_entropy
from app.analyzers.f02_name_divergence    import analyze_name_divergence
from app.analyzers.f03_profile_completeness import analyze_profile_completeness
from app.analyzers.f04_posting_frequency  import analyze_posting_frequency
from app.analyzers.f05_engagement_ratio   import analyze_engagement_ratio
from app.analyzers.f06_growth_anomaly     import analyze_growth_anomaly
from app.analyzers.f07_twitter_heuristics import analyze_twitter_heuristics
from app.analyzers.f08_socialblade        import analyze_socialblade
from app.analyzers.f09_botometer          import analyze_botometer
from app.analyzers.f10_reverse_image      import analyze_reverse_image
from app.analyzers.f11_emailrep           import analyze_emailrep_from_profile
from app.analyzers.f12_serpapi            import analyze_serpapi_image
from app.analyzers.f13_bio_nlp            import analyze_bio_nlp
from app.analyzers.f14_crossplatform      import analyze_crossplatform
from app.analyzers.f15_osint              import analyze_osint
from app.analyzers.f16_account_age        import analyze_account_age
from app.analyzers.f17_link_safety        import analyze_link_safety
from app.analyzers.f18_content_pattern    import analyze_content_pattern
from app.analyzers.f19_language_geo       import analyze_language_geo

logger  = logging.getLogger(__name__)
P1_MAX  = 130.0

def _lvl(s: int) -> SuspicionLevel:
    if s >= 60: return SuspicionLevel.HIGH
    if s >= 30: return SuspicionLevel.MEDIUM
    return SuspicionLevel.LOW

def _norm(raw: float, mx: float) -> int:
    return max(0, min(100, round(raw / mx * 100)))

def _pts(obj) -> int:
    return getattr(obj,"suspicion_points",0) or 0

def _email_from_bio(bio: Optional[str]) -> Optional[str]:
    if not bio: return None
    m = re.search(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", bio)
    return m.group(0).lower() if m else None

async def run_social_analysis(profile: ProfileData, run_wayback=True,
                               run_phase2=True, run_phase3=True, run_phase4=True) -> SocialMediaAnalysisResult:
    start = datetime.utcnow()
    lims  = []
    if profile.is_private: lims.append("Private profile — limited data")
    if profile.scrape_error: lims.append(f"Scrape note: {profile.scrape_error}")

    # ── Phase 1 (sync) ───────────────────────────────────────────
    def safe1(fn, *args, fallback):
        try: return fn(*args)
        except Exception as e: lims.append(f"{fn.__name__}: {e}"); return fallback

    _u0 = UsernameEntropyResult(entropy_score=0,pattern_flags=[],suspicion_points=0,details={})
    _n0 = NameDivergenceResult(similarity_ratio=0,divergence_flag=False,suspicion_points=0,details={})
    _c0 = ProfileCompletenessResult(completeness_score=50,completeness_penalty=0,missing_fields=[],present_fields=[],details={})
    _p0 = PostingFrequencyResult(coefficient_of_variation=0,posting_entropy=0,mean_interval_hours=0,std_interval_hours=0,is_bot_regular=False,suspicion_points=0,posts_analyzed=0,details={})
    _e0 = EngagementRatioResult(engagement_rate=0,platform_baseline=0.01,deviation_multiplier=0,anomaly_type="insufficient_data",suspicion_points=0,details={})
    _g0 = GrowthAnomalyResult(wayback_snapshots_found=0,growth_timeline=[],spike_detected=False,spike_date=None,spike_magnitude=None,suspicion_points=0,details={})

    f01 = safe1(analyze_username_entropy, profile.username, fallback=_u0)
    f02 = safe1(analyze_name_divergence, profile.username, profile.display_name, fallback=_n0)
    f03 = safe1(analyze_profile_completeness, profile, fallback=_c0)
    f04 = safe1(analyze_posting_frequency, profile.recent_posts, fallback=_p0)
    f05 = safe1(analyze_engagement_ratio, profile.follower_count, profile.following_count,
                profile.recent_posts, profile.platform, fallback=_e0)

    if run_wayback:
        try: f06 = await analyze_growth_anomaly(profile.profile_url)
        except Exception as e: f06 = _g0; lims.append(f"F-06: {e}")
    else:
        f06 = _g0; lims.append("F-06 skipped")

    # ── Phase 2 (concurrent async) ───────────────────────────────
    f07=f08=f09=f10=f11=f12=None
    if run_phase2:
        async def s2(coro, cls):
            try: return await coro
            except Exception as e: return cls(available=False,details={"error":str(e)})
        f07,f08,f09,f10,f11,f12 = await asyncio.gather(
            s2(analyze_twitter_heuristics(profile.username, profile.platform), TwitterHeuristicsResult),
            s2(analyze_socialblade(profile.username, profile.platform),        SocialBladeResult),
            s2(analyze_botometer(profile.username, profile.platform),          BotometerResult),
            s2(analyze_reverse_image(profile.profile_picture_url),             ReverseImageResult),
            s2(analyze_emailrep_from_profile(profile.bio, profile.website_url, profile.email), EmailRepResult),
            s2(analyze_serpapi_image(profile.profile_picture_url),             SerpApiResult),
        )

    # ── Phase 3 (concurrent, mostly keyless) ─────────────────────
    f13=f14=f15=f16=None
    if run_phase3:
        async def bio_wrap():   return analyze_bio_nlp(profile.bio or "", profile.display_name or "")
        async def age_wrap():   return analyze_account_age(profile.account_created_at,
                                    profile.follower_count, profile.post_count,
                                    profile.platform.value, profile.recent_posts)
        email_q = profile.email or _email_from_bio(profile.bio)
        async def osint_wrap(): return await analyze_osint(email_q,"email") if email_q else {"suspicion_points":0,"flags":[],"leakcheck":{},"hudsonrock":{},"intelx":{},"details":{"skipped":"no email"}}

        raw13, raw14, raw15, raw16 = await asyncio.gather(bio_wrap(), analyze_crossplatform(profile.username, profile.platform.value), osint_wrap(), age_wrap())
        f13 = BioNLPResult(**raw13)
        f14 = CrossPlatformResult(**raw14)
        f15 = OsintResult(**raw15)
        f16 = AccountAgeResult(**raw16)

    # ── Phase 4 (concurrent) ─────────────────────────────────────
    f17=f18=f19=None
    if run_phase4:
        async def cp_wrap():  return analyze_content_pattern(profile.recent_posts, profile.bio or "")
        async def lg_wrap():  return analyze_language_geo(profile.bio, profile.location, profile.recent_posts)
        raw17, raw18, raw19 = await asyncio.gather(
            analyze_link_safety(profile.bio, profile.website_url),
            cp_wrap(), lg_wrap(),
        )
        f17 = raw17
        f18 = ContentPatternResult(**raw18)
        f19 = LanguageGeoResult(**raw19)

    # ── Score ─────────────────────────────────────────────────────
    p1_raw   = (_pts(f01)+_pts(f02)+f03.completeness_penalty+_pts(f04)+_pts(f05)+_pts(f06))
    p1_score = _norm(p1_raw, P1_MAX)

    p2_bonus = min(25, round(sum(_pts(f) for f in [f07,f08,f09,f10,f11,f12]) * 0.3)) if run_phase2 else 0
    p3_bonus = min(15, round(sum(_pts(f) for f in [f13,f14,f15,f16]) * 0.35)) if run_phase3 else 0
    p4_bonus = min(10, round(sum(_pts(f) for f in [f17,f18,f19]) * 0.3)) if run_phase4 else 0

    combined = min(100, p1_score + p2_bonus + p3_bonus + p4_bonus)

    # Override rules
    highs = sum([_pts(f01)>=15, _pts(f02)>=10, f03.completeness_penalty>=10, f04.is_bot_regular,
                 f05.anomaly_type in ("ghost_followers","like_farming"),
                 f06.spike_detected, bool(f07 and f07.classification=="Disruptive"),
                 bool(f09 and (_pts(f09))>=20), bool(f13 and _pts(f13)>=15),
                 bool(f15 and _pts(f15)>=20), bool(f17 and f17.malicious_links)])
    if highs >= 3:                          combined = max(combined, 60)
    if f06.spike_detected and f05.anomaly_type == "ghost_followers": combined = max(combined, 70)
    if f15 and _pts(f15) >= 20:             combined = max(combined, 65)
    if f17 and f17.malicious_links:         combined = max(combined, 75)

    # Collect flags
    flags = []
    if f01.pattern_flags: flags += [f"[F-01] {x}" for x in f01.pattern_flags]
    if f02.divergence_flag: flags.append(f"[F-02] Name divergence")
    if f03.missing_fields: flags.append(f"[F-03] Missing: {', '.join(f03.missing_fields[:4])}")
    if f04.is_bot_regular: flags.append(f"[F-04] Bot-regular posting CV={f04.coefficient_of_variation:.3f}")
    if f05.anomaly_type not in (None,"normal","insufficient_data"): flags.append(f"[F-05] {f05.anomaly_type}")
    if f06.spike_detected: flags.append(f"[F-06] Spike +{f06.spike_magnitude:,} on {f06.spike_date}")
    if f07 and f07.available and f07.classification in ("Disruptive","Problematic"): flags.append(f"[F-07] {f07.classification}")
    if f08 and f08.spike_detected: flags.append(f"[F-08] SocialBlade spike {f08.spike_month}")
    if f09 and _pts(f09)>0: flags.append(f"[F-09] Botometer CAP={f09.cap_score}")
    if f10 and f10.stolen_identity: flags.append(f"[F-10] Stolen photo ({f10.match_count} matches)")
    if f10 and f10.is_stock_photo:  flags.append(f"[F-10] Stock photo ({f10.match_count} matches)")
    if f13: flags += [f"[F-13] {x}" for x in f13.flags]
    if f14: flags += [f"[F-14] {x}" for x in f14.flags]
    if f15: flags += [f"[F-15] {x}" for x in f15.flags]
    if f16: flags += [f"[F-16] {x}" for x in f16.flags]
    if f17 and f17.malicious_links: flags.append(f"[F-17] Malicious links: {f17.malicious_links}")
    if f18: flags += [f"[F-18] {x}" for x in f18.flags]
    if f19: flags += [f"[F-19] {x}" for x in f19.flags]

    bdown = {"f01":_pts(f01),"f02":_pts(f02),"f03":f03.completeness_penalty,
             "f04":_pts(f04),"f05":_pts(f05),"f06":_pts(f06),
             "f07":_pts(f07),"f08":_pts(f08),"f09":_pts(f09),
             "f10":_pts(f10),"f11":_pts(f11),"f12":_pts(f12),
             "f13":_pts(f13),"f14":_pts(f14),"f15":_pts(f15),"f16":_pts(f16),
             "f17":_pts(f17),"f18":_pts(f18),"f19":_pts(f19)}
    dur  = (datetime.utcnow()-start).total_seconds()
    conf = round(max(0.2, 0.95-0.05*len(lims)), 2)
    logger.info(f"[Engine] @{profile.username} p1={p1_score}+p2={p2_bonus}+p3={p3_bonus}+p4={p4_bonus}={combined} {_lvl(combined).value} {dur:.1f}s")

    return SocialMediaAnalysisResult(
        profile_url=profile.profile_url, username=profile.username,
        platform=profile.platform.value, display_name=profile.display_name,
        suspicion_score=combined, suspicion_level=_lvl(combined), confidence=conf,
        f01_username_entropy=f01, f02_name_divergence=f02, f03_profile_completeness=f03,
        f04_posting_frequency=f04, f05_engagement_ratio=f05, f06_growth_anomaly=f06,
        f07_twitter_heuristics=f07, f08_socialblade=f08, f09_botometer=f09,
        f10_reverse_image=f10, f11_emailrep=f11, f12_serpapi=f12,
        f13_bio_nlp=f13, f14_crossplatform=f14, f15_osint=f15, f16_account_age=f16,
        f17_link_safety=f17, f18_content_pattern=f18, f19_language_geo=f19,
        flags_raised=flags, score_breakdown=bdown,
        analysis_duration_seconds=round(dur,2), scraped_successfully=profile.scrape_successful,
        scrape_error=profile.scrape_error, data_limitations=lims,
        phase2_ran=run_phase2, phase3_ran=run_phase3, phase4_ran=run_phase4)
