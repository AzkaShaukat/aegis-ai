"""Aegis AI v4 — Automated offline tests. Run: pytest tests/ -v"""
import pytest
from datetime import datetime, timezone, timedelta

# ── Models ───────────────────────────────────────────────────────
from app.models import AnalyzeRequest, InputType, Platform

class TestRequest:
    def test_at_stripped(self):
        r = AnalyzeRequest(value="@elonmusk", input_type=InputType.SOCIAL_MEDIA, platform="twitter")
        assert r.value == "elonmusk"
    def test_x_alias(self):
        r = AnalyzeRequest(value="u", input_type=InputType.SOCIAL_MEDIA, platform="x")
        assert r.platform == Platform.TWITTER
    def test_ig_alias(self):
        r = AnalyzeRequest(value="u", input_type=InputType.SOCIAL_MEDIA, platform="ig")
        assert r.platform == Platform.INSTAGRAM
    def test_tt_alias(self):
        r = AnalyzeRequest(value="u", input_type=InputType.SOCIAL_MEDIA, platform="tt")
        assert r.platform == Platform.TIKTOK
    def test_phone_plus_kept(self):
        r = AnalyzeRequest(value="+923001234567", input_type=InputType.PHONE)
        assert r.value.startswith("+")
    def test_email_at_kept(self):
        r = AnalyzeRequest(value="  test@gmail.com  ", input_type=InputType.EMAIL)
        assert "@" in r.value and r.value == "test@gmail.com"

# ── URL Builder ──────────────────────────────────────────────────
from app.scraper.base import build_url

class TestURLBuilder:
    def test_twitter(self): assert "twitter.com/elonmusk" in build_url("elonmusk", Platform.TWITTER)
    def test_instagram(self): assert "instagram.com/user" in build_url("user", Platform.INSTAGRAM)
    def test_tiktok_at(self): assert "tiktok.com/@khaby" in build_url("khaby", Platform.TIKTOK)
    def test_youtube_at(self): assert "youtube.com/@mkbhd" in build_url("mkbhd", Platform.YOUTUBE)
    def test_whatsapp_digits_only(self):
        url = build_url("+923001234567", Platform.WHATSAPP)
        assert "wa.me/923001234567" in url and "+" not in url.split("wa.me/")[1]
    def test_linkedin(self): assert "linkedin.com/in/johndoe" in build_url("johndoe", Platform.LINKEDIN)

# ── F-01 Username Entropy ────────────────────────────────────────
from app.analyzers.f01_username_entropy import analyze_username_entropy, shannon_entropy

class TestF01:
    def test_zero_entropy_uniform(self): assert shannon_entropy("aaaa") == 0.0
    def test_max_entropy_binary(self): assert round(shannon_entropy("ab"),2) == 1.0
    def test_high_entropy_random(self):
        r = analyze_username_entropy("xKj9mR2pZw4Q")
        assert r.entropy_score > 3.0 and r.suspicion_points > 0
    def test_clean_username_low(self):
        r = analyze_username_entropy("sarah_dev"); assert r.suspicion_points < 15
    def test_impersonation_detected(self):
        r = analyze_username_entropy("el0nmusk")
        assert any("impersonation" in f for f in r.pattern_flags) and r.suspicion_points >= 15
    def test_all_numeric_flagged(self):
        r = analyze_username_entropy("987654321")
        assert any("numeric" in f for f in r.pattern_flags)
    def test_capped_at_30(self): assert analyze_username_entropy("el0nmusk99xzxz!!").suspicion_points <= 30
    def test_empty_handled(self): assert analyze_username_entropy("").suspicion_points > 0

# ── F-02 Name Divergence ─────────────────────────────────────────
from app.analyzers.f02_name_divergence import analyze_name_divergence

class TestF02:
    def test_matching_names_low(self):
        assert analyze_name_divergence("sarah_dev","Sarah Dev").suspicion_points < 10
    def test_scam_display_flagged(self):
        r = analyze_name_divergence("abc123","💰 Guaranteed Crypto Returns Daily 🚀")
        assert r.suspicion_points > 0
    def test_no_display_safe(self):
        assert analyze_name_divergence("user123", None).suspicion_points == 0

# ── F-03 Profile Completeness ────────────────────────────────────
from app.analyzers.f03_profile_completeness import analyze_profile_completeness
from app.models import ProfileData

def _p(**kw):
    return ProfileData(username="u", platform=Platform.TWITTER,
                       profile_url="https://twitter.com/u", **kw)

class TestF03:
    def test_full_profile_low(self):
        p = _p(display_name="T",bio="bio",profile_picture_url="x.jpg",
               website_url="x.com",account_created_at=datetime(2020,1,1,tzinfo=timezone.utc),post_count=200)
        assert analyze_profile_completeness(p).completeness_penalty <= 5
    def test_empty_profile_high(self): assert analyze_profile_completeness(_p()).completeness_penalty >= 8
    def test_very_new_penalized(self):
        p = _p(account_created_at=datetime.now(timezone.utc)-timedelta(days=2))
        assert analyze_profile_completeness(p).completeness_penalty >= 5

# ── F-04 Posting Frequency ───────────────────────────────────────
from app.analyzers.f04_posting_frequency import analyze_posting_frequency

def _posts(gaps):
    t = datetime(2025,1,1,tzinfo=timezone.utc)
    out = []
    for g in gaps:
        t += timedelta(hours=g)
        out.append({"timestamp":t.isoformat(),"likes":5,"comments":1})
    return out

class TestF04:
    def test_regular_is_bot(self):
        r = analyze_posting_frequency(_posts([2.0]*20))
        assert r.is_bot_regular and r.coefficient_of_variation < 0.25
    def test_irregular_is_human(self):
        r = analyze_posting_frequency(_posts([1,14,3,48,72,2,24,8,120,5,200,36,96,7]))
        assert not r.is_bot_regular
    def test_empty_no_crash(self): assert analyze_posting_frequency([]).suspicion_points == 0
    def test_capped_25(self): assert analyze_posting_frequency(_posts([1.0]*50)).suspicion_points <= 25

# ── F-05 Engagement Ratio ────────────────────────────────────────
from app.analyzers.f05_engagement_ratio import analyze_engagement_ratio

def _eng(n, likes, comments):
    return [{"timestamp":f"2025-01-{i+1:02d}T10:00:00","likes":likes,"comments":comments} for i in range(n)]

class TestF05:
    def test_ghost_followers(self):
        r = analyze_engagement_ratio(50000,200,_eng(10,2,0),Platform.TWITTER)
        assert "ghost" in str(r.anomaly_type).lower() and r.suspicion_points >= 10
    def test_normal_engagement(self):
        r = analyze_engagement_ratio(1200,800,_eng(10,36,8),Platform.INSTAGRAM)
        assert r.suspicion_points < 10
    def test_no_data_handled(self):
        r = analyze_engagement_ratio(None,None,[],Platform.TWITTER)
        assert r is not None

# ── F-13 Bio NLP ─────────────────────────────────────────────────
from app.analyzers.f13_bio_nlp import analyze_bio_nlp

class TestF13:
    def test_scam_bio_high(self):
        r = analyze_bio_nlp("💰 Guaranteed profit! DM me for investment! Limited slots!")
        assert r["suspicion_points"] >= 15
    def test_clean_bio_low(self):
        r = analyze_bio_nlp("Software engineer. Coffee lover."); assert r["suspicion_points"] < 10
    def test_giveaway_detected(self):
        r = analyze_bio_nlp("FREE Bitcoin giveaway! Send 0.1 BTC get 1 BTC back!")
        assert any("giveaway" in f or "scam" in f.lower() for f in r["flags"])
    def test_high_emoji_flagged(self):
        r = analyze_bio_nlp("🚀🔥💎💰🎯🏆✅🌟💯🎉 Click now! 🚀🔥💎")
        assert r["suspicion_points"] > 5
    def test_empty_safe(self): assert analyze_bio_nlp("","")["suspicion_points"] == 0
    def test_capped_25(self):
        r = analyze_bio_nlp("💰💰 Guaranteed profit! DM! Giveaway! Official CEO! Free Bitcoin!")
        assert r["suspicion_points"] <= 25

# ── F-16 Account Age ─────────────────────────────────────────────
from app.analyzers.f16_account_age import analyze_account_age

class TestF16:
    def test_very_new_high(self):
        r = analyze_account_age(datetime.now(timezone.utc)-timedelta(days=3),100,10,"twitter")
        assert r["suspicion_points"] >= 12
    def test_old_low(self):
        r = analyze_account_age(datetime(2019,1,1,tzinfo=timezone.utc),5000,1000,"twitter")
        assert r["suspicion_points"] < 10
    def test_extreme_velocity(self):
        r = analyze_account_age(datetime.now(timezone.utc)-timedelta(days=10),1_000_000,5,"twitter")
        assert any("velocity" in f for f in r["flags"])
    def test_none_date_handled(self):
        r = analyze_account_age(None,1000,50,"twitter"); assert r["suspicion_points"] >= 3
    def test_capped_20(self):
        r = analyze_account_age(datetime.now(timezone.utc)-timedelta(days=1),1_000_000,1_000_000,"twitter")
        assert r["suspicion_points"] <= 20

# ── Email ─────────────────────────────────────────────────────────
from app.analyzers.email_analyzer import check_email_format, check_disposable_email

class TestEmail:
    def test_valid_gmail(self):
        r = check_email_format("test@gmail.com")
        assert r.is_valid_format and r.domain == "gmail.com" and r.is_free_provider
    def test_invalid_format(self):
        r = check_email_format("notanemail")
        assert not r.is_valid_format and r.suspicion_points >= 15
    def test_mailinator_disposable(self):
        r = check_disposable_email("x@mailinator.com")
        assert r.is_disposable and r.suspicion_points == 25
    def test_yopmail_disposable(self):
        assert check_disposable_email("y@yopmail.com").is_disposable
    def test_10minute_disposable(self):
        assert check_disposable_email("z@10minutemail.com").is_disposable
    def test_gmail_not_disposable(self):
        r = check_disposable_email("user@gmail.com")
        assert not r.is_disposable and r.suspicion_points == 0
    def test_outlook_not_disposable(self):
        assert not check_disposable_email("u@outlook.com").is_disposable

# ── Phone ─────────────────────────────────────────────────────────
from app.analyzers.phone_analyzer import check_phone_format, check_whatsapp

class TestPhone:
    def test_valid_pakistan(self):
        r = check_phone_format("+923001234567")
        assert r.is_valid and r.country_code == "PK"
    def test_valid_uk(self):
        r = check_phone_format("+442071234567")
        assert r.is_valid and r.country_code == "GB"
    def test_valid_us(self):
        r = check_phone_format("+12025551234")
        assert r.is_valid and r.country_code == "US"
    def test_invalid_short(self):
        r = check_phone_format("123"); assert not r.is_valid and r.suspicion_points >= 15
    def test_e164_generated(self):
        r = check_phone_format("+923001234567")
        if r.is_valid: assert r.formatted_e164 and r.formatted_e164.startswith("+")
    @pytest.mark.asyncio
    async def test_whatsapp_link(self):
        r = await check_whatsapp("+923001234567")
        assert r.number_valid and "wa.me/923001234567" in r.whatsapp_link
    @pytest.mark.asyncio
    async def test_whatsapp_invalid(self):
        r = await check_whatsapp("123"); assert not r.number_valid
