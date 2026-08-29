"""
═══════════════════════════════════════════════════════════════════
  Aegis AI v4 — Automated Offline Tests
  Run: pytest tests/ -v
  No Docker needed. No API keys needed. Runs in ~5 seconds.
═══════════════════════════════════════════════════════════════════
"""
import pytest
from datetime import datetime, timezone, timedelta
from app.models import AnalyzeRequest, InputType, Platform


# ═══════════════════════════════════════════════════════════════════
#  GROUP 1 — Request model + aliases
# ═══════════════════════════════════════════════════════════════════
class TestRequestModel:

    def test_at_stripped_from_username(self):
        r = AnalyzeRequest(value="@elonmusk", input_type=InputType.SOCIAL_MEDIA, platform="twitter")
        assert r.value == "elonmusk"

    def test_double_at_stripped(self):
        r = AnalyzeRequest(value="@@user123", input_type=InputType.SOCIAL_MEDIA, platform="twitter")
        assert r.value == "user123"

    def test_leading_spaces_stripped(self):
        r = AnalyzeRequest(value="  someuser  ", input_type=InputType.SOCIAL_MEDIA, platform="twitter")
        assert r.value == "someuser"

    def test_phone_plus_kept(self):
        r = AnalyzeRequest(value="+923001234567", input_type=InputType.PHONE)
        assert r.value.startswith("+")

    def test_email_at_kept(self):
        r = AnalyzeRequest(value="  test@gmail.com  ", input_type=InputType.EMAIL)
        assert r.value == "test@gmail.com"

    def test_platform_alias_x_to_twitter(self):
        r = AnalyzeRequest(value="u", input_type=InputType.SOCIAL_MEDIA, platform="x")
        assert r.platform == Platform.TWITTER

    def test_platform_alias_ig_to_instagram(self):
        r = AnalyzeRequest(value="u", input_type=InputType.SOCIAL_MEDIA, platform="ig")
        assert r.platform == Platform.INSTAGRAM

    def test_platform_alias_tt_to_tiktok(self):
        r = AnalyzeRequest(value="u", input_type=InputType.SOCIAL_MEDIA, platform="tt")
        assert r.platform == Platform.TIKTOK

    def test_platform_alias_fb_to_facebook(self):
        r = AnalyzeRequest(value="u", input_type=InputType.SOCIAL_MEDIA, platform="fb")
        assert r.platform == Platform.FACEBOOK

    def test_platform_alias_yt_to_youtube(self):
        r = AnalyzeRequest(value="u", input_type=InputType.SOCIAL_MEDIA, platform="yt")
        assert r.platform == Platform.YOUTUBE

    def test_platform_uppercase_normalised(self):
        r = AnalyzeRequest(value="u", input_type=InputType.SOCIAL_MEDIA, platform="TWITTER")
        assert r.platform == Platform.TWITTER


# ═══════════════════════════════════════════════════════════════════
#  GROUP 2 — URL builder
# ═══════════════════════════════════════════════════════════════════
from app.scraper.base import build_url

class TestURLBuilder:

    def test_twitter_url(self):
        assert "twitter.com/elonmusk" in build_url("elonmusk", Platform.TWITTER)

    def test_instagram_url(self):
        assert "instagram.com/cristiano" in build_url("cristiano", Platform.INSTAGRAM)

    def test_tiktok_has_at(self):
        assert "tiktok.com/@khaby" in build_url("khaby", Platform.TIKTOK)

    def test_youtube_has_at(self):
        assert "youtube.com/@mkbhd" in build_url("mkbhd", Platform.YOUTUBE)

    def test_linkedin_url(self):
        assert "linkedin.com/in/johndoe" in build_url("johndoe", Platform.LINKEDIN)

    def test_facebook_url(self):
        assert "facebook.com/zuck" in build_url("zuck", Platform.FACEBOOK)

    def test_whatsapp_strips_plus(self):
        url = build_url("+923001234567", Platform.WHATSAPP)
        assert "wa.me/923001234567" in url
        assert "+" not in url.split("wa.me/")[1]

    def test_whatsapp_strips_dashes(self):
        url = build_url("+92-300-1234567", Platform.WHATSAPP)
        assert "wa.me/923001234567" in url

    def test_whatsapp_strips_spaces(self):
        url = build_url("+44 207 123 4567", Platform.WHATSAPP)
        assert "+" not in url.split("wa.me/")[1]
        assert " " not in url


# ═══════════════════════════════════════════════════════════════════
#  GROUP 3 — F-01: Username Entropy
# ═══════════════════════════════════════════════════════════════════
from app.analyzers.f01_username_entropy import analyze_username_entropy, shannon_entropy

class TestUsernameEntropy:

    def test_zero_entropy_all_same(self):
        assert shannon_entropy("aaaa") == 0.0

    def test_max_entropy_two_chars(self):
        assert round(shannon_entropy("ab"), 2) == 1.0

    def test_random_username_high_entropy(self):
        r = analyze_username_entropy("xKj9mR2pZw4Q")
        assert r.entropy_score > 3.0
        assert r.suspicion_points > 0

    def test_normal_username_low_score(self):
        r = analyze_username_entropy("sarah_dev")
        assert r.suspicion_points < 15

    def test_impersonation_el0nmusk(self):
        r = analyze_username_entropy("el0nmusk")
        assert any("impersonation" in f for f in r.pattern_flags)
        assert r.suspicion_points >= 15

    def test_impersonation_cr1stiano(self):
        r = analyze_username_entropy("cr1stiano")
        assert any("impersonation" in f for f in r.pattern_flags)

    def test_all_numeric_flagged(self):
        r = analyze_username_entropy("987654321")
        assert any("numeric" in f for f in r.pattern_flags)

    def test_many_trailing_digits_flagged(self):
        r = analyze_username_entropy("user12345678")
        assert r.suspicion_points > 0

    def test_excessive_underscores_flagged(self):
        r = analyze_username_entropy("a_b_c_d_e")
        assert any("underscore" in f for f in r.pattern_flags)

    def test_score_capped_at_30(self):
        r = analyze_username_entropy("el0nmusk99xzxz!!qwertyuiop")
        assert r.suspicion_points <= 30

    def test_empty_username_no_crash(self):
        r = analyze_username_entropy("")
        assert r.suspicion_points > 0

    def test_very_short_username(self):
        r = analyze_username_entropy("ab")
        assert r.suspicion_points > 0


# ═══════════════════════════════════════════════════════════════════
#  GROUP 4 — F-02: Name Divergence
# ═══════════════════════════════════════════════════════════════════
from app.analyzers.f02_name_divergence import analyze_name_divergence

class TestNameDivergence:

    def test_matching_names_low_score(self):
        r = analyze_name_divergence("sarah_dev", "Sarah Dev")
        assert r.suspicion_points < 10

    def test_scam_keyword_guaranteed_flagged(self):
        r = analyze_name_divergence("user123", "Guaranteed Crypto Returns")
        assert r.suspicion_points > 0

    def test_scam_keyword_forex_flagged(self):
        r = analyze_name_divergence("x", "Forex Signal Expert 💰")
        assert r.suspicion_points > 0

    def test_scam_keyword_giveaway_flagged(self):
        r = analyze_name_divergence("x", "Free Bitcoin Giveaway Official")
        assert r.suspicion_points > 0

    def test_no_display_name_safe(self):
        r = analyze_name_divergence("user123", None)
        assert r.suspicion_points == 0

    def test_large_divergence_flagged(self):
        r = analyze_name_divergence("xkj9qmzw", "John Smith UK Investments")
        assert r.divergence_flag or r.suspicion_points > 0

    def test_score_capped_at_20(self):
        r = analyze_name_divergence("abc", "Guaranteed profit forex crypto signal dm giveaway airdrop")
        assert r.suspicion_points <= 20


# ═══════════════════════════════════════════════════════════════════
#  GROUP 5 — F-03: Profile Completeness
# ═══════════════════════════════════════════════════════════════════
from app.analyzers.f03_profile_completeness import analyze_profile_completeness
from app.models import ProfileData

def _profile(**kw):
    defaults = dict(username="u", platform=Platform.TWITTER,
                    profile_url="https://twitter.com/u")
    return ProfileData(**{**defaults, **kw})

class TestProfileCompleteness:

    def test_full_profile_low_penalty(self):
        p = _profile(display_name="T", bio="Software dev",
                     profile_picture_url="pic.jpg", website_url="dev.com",
                     account_created_at=datetime(2020,1,1,tzinfo=timezone.utc),
                     post_count=200, follower_count=5000)
        r = analyze_profile_completeness(p)
        assert r.completeness_penalty <= 5

    def test_empty_profile_high_penalty(self):
        r = analyze_profile_completeness(_profile())
        assert r.completeness_penalty >= 8

    def test_very_new_account_penalised(self):
        p = _profile(account_created_at=datetime.now(timezone.utc) - timedelta(days=2))
        r = analyze_profile_completeness(p)
        assert r.completeness_penalty >= 5

    def test_missing_bio_tracked(self):
        p = _profile(display_name="Test")
        r = analyze_profile_completeness(p)
        assert "bio" in r.missing_fields

    def test_bio_present_tracked(self):
        p = _profile(bio="Hello world")
        r = analyze_profile_completeness(p)
        assert "bio" in r.present_fields

    def test_private_profile_adds_penalty(self):
        p = _profile(bio="bio", display_name="T", profile_picture_url="x.jpg",
                     is_private=True,
                     account_created_at=datetime(2020,1,1,tzinfo=timezone.utc))
        r = analyze_profile_completeness(p)
        assert r.completeness_penalty >= 3

    def test_score_capped_at_15(self):
        p = _profile(account_created_at=datetime.now(timezone.utc) - timedelta(days=1),
                     is_private=True)
        r = analyze_profile_completeness(p)
        assert r.completeness_penalty <= 15


# ═══════════════════════════════════════════════════════════════════
#  GROUP 6 — F-04: Posting Frequency
# ═══════════════════════════════════════════════════════════════════
from app.analyzers.f04_posting_frequency import analyze_posting_frequency

def _posts_with_gaps(gap_hours_list):
    """Build a list of fake posts from a list of inter-post gaps in hours."""
    t = datetime(2025, 1, 1, tzinfo=timezone.utc)
    posts = []
    for g in gap_hours_list:
        t += timedelta(hours=g)
        posts.append({"timestamp": t.isoformat(), "likes": 5, "comments": 1})
    return posts

class TestPostingFrequency:

    def test_machine_regular_is_bot(self):
        r = analyze_posting_frequency(_posts_with_gaps([2.0] * 25))
        assert r.is_bot_regular
        assert r.coefficient_of_variation < 0.25

    def test_irregular_human_not_bot(self):
        r = analyze_posting_frequency(_posts_with_gaps([1,14,3,48,72,2,24,8,120,5,200,36,96,7,4,88]))
        assert not r.is_bot_regular

    def test_empty_posts_no_crash(self):
        r = analyze_posting_frequency([])
        assert r.suspicion_points == 0
        assert r.posts_analyzed == 0

    def test_single_post_no_crash(self):
        r = analyze_posting_frequency(_posts_with_gaps([24]))
        assert r is not None

    def test_score_capped_at_25(self):
        r = analyze_posting_frequency(_posts_with_gaps([1.0] * 60))
        assert r.suspicion_points <= 25

    def test_posts_analyzed_count_correct(self):
        posts = _posts_with_gaps([10] * 15)
        r = analyze_posting_frequency(posts)
        assert r.posts_analyzed == 15


# ═══════════════════════════════════════════════════════════════════
#  GROUP 7 — F-05: Engagement Ratio
# ═══════════════════════════════════════════════════════════════════
from app.analyzers.f05_engagement_ratio import analyze_engagement_ratio

def _eng_posts(n, likes, comments):
    return [{"timestamp": f"2025-01-{i+1:02d}T10:00:00",
             "likes": likes, "comments": comments} for i in range(n)]

class TestEngagementRatio:

    def test_ghost_followers_detected(self):
        r = analyze_engagement_ratio(100_000, 200, _eng_posts(10, 1, 0), Platform.TWITTER)
        assert "ghost" in str(r.anomaly_type).lower()
        assert r.suspicion_points >= 10

    def test_normal_engagement_low_score(self):
        r = analyze_engagement_ratio(1_500, 800, _eng_posts(10, 45, 10), Platform.INSTAGRAM)
        assert r.suspicion_points < 10

    def test_like_farming_detected(self):
        r = analyze_engagement_ratio(500, 200, _eng_posts(10, 100_000, 50_000), Platform.TWITTER)
        assert r.suspicion_points >= 10

    def test_no_followers_no_crash(self):
        r = analyze_engagement_ratio(None, None, [], Platform.TWITTER)
        assert r is not None
        assert r.anomaly_type == "insufficient_data"

    def test_score_capped_at_20(self):
        r = analyze_engagement_ratio(1_000_000, 200, _eng_posts(10, 0, 0), Platform.TWITTER)
        assert r.suspicion_points <= 20

    def test_platform_baseline_twitter(self):
        r = analyze_engagement_ratio(10_000, 200, _eng_posts(5, 50, 0), Platform.TWITTER)
        assert r.platform_baseline == 0.005

    def test_platform_baseline_tiktok(self):
        r = analyze_engagement_ratio(10_000, 200, _eng_posts(5, 500, 0), Platform.TIKTOK)
        assert r.platform_baseline == 0.05


# ═══════════════════════════════════════════════════════════════════
#  GROUP 8 — F-13: Bio NLP
# ═══════════════════════════════════════════════════════════════════
from app.analyzers.f13_bio_nlp import analyze_bio_nlp

class TestBioNLP:

    def test_clean_bio_low_score(self):
        r = analyze_bio_nlp("Software engineer. Coffee lover. Open source contributor.")
        assert r["suspicion_points"] < 10

    def test_guaranteed_profit_flagged(self):
        r = analyze_bio_nlp("💰 Guaranteed profit! Invest now!")
        assert r["suspicion_points"] >= 10
        assert any("financial" in f or "scam" in f.lower() for f in r["flags"])

    def test_dm_me_investment_flagged(self):
        r = analyze_bio_nlp("DM me for investment signals 📈")
        assert r["suspicion_points"] > 0
        assert any("dm" in f.lower() or "scam" in f.lower() for f in r["flags"])

    def test_giveaway_flagged(self):
        r = analyze_bio_nlp("FREE Bitcoin giveaway! Send 0.1 BTC get 1 BTC back!")
        assert any("giveaway" in f.lower() or "scam" in f.lower() for f in r["flags"])

    def test_urgency_flagged(self):
        r = analyze_bio_nlp("Limited slots only! Act now! Hurry up!")
        assert r["suspicion_points"] > 0

    def test_high_emoji_density_flagged(self):
        r = analyze_bio_nlp("🚀🔥💎💰🎯🏆✅🌟💯🎉🚀🔥💎💰 Click now!")
        assert r["suspicion_points"] > 5

    def test_suspicious_link_flagged(self):
        r = analyze_bio_nlp("Join my group: t.me/cryptosignals")
        assert any("link" in f.lower() for f in r["flags"])

    def test_phone_in_bio_flagged(self):
        r = analyze_bio_nlp("Contact me: +923001234567 for investment")
        assert any("phone" in f.lower() for f in r["flags"])

    def test_authority_claim_flagged(self):
        r = analyze_bio_nlp("Official admin of crypto group. Verified moderator.")
        assert r["suspicion_points"] > 0

    def test_empty_bio_safe(self):
        r = analyze_bio_nlp("", "")
        assert r["suspicion_points"] == 0

    def test_score_capped_at_25(self):
        r = analyze_bio_nlp(
            "💰💰 Guaranteed profit! DM me now! Limited slots! "
            "Official CEO! Free Bitcoin Giveaway! t.me/scam +1234567890 INVEST NOW!!!"
        )
        assert r["suspicion_points"] <= 25

    def test_returns_required_keys(self):
        r = analyze_bio_nlp("test")
        assert "suspicion_points" in r
        assert "flags" in r
        assert "details" in r


# ═══════════════════════════════════════════════════════════════════
#  GROUP 9 — F-16: Account Age
# ═══════════════════════════════════════════════════════════════════
from app.analyzers.f16_account_age import analyze_account_age

class TestAccountAge:

    def test_brand_new_account_high_score(self):
        r = analyze_account_age(
            datetime.now(timezone.utc) - timedelta(days=3), 100, 10, "twitter")
        assert r["suspicion_points"] >= 12
        assert any("7_days" in f for f in r["flags"])

    def test_week_old_flagged(self):
        r = analyze_account_age(
            datetime.now(timezone.utc) - timedelta(days=10), 500, 20, "twitter")
        assert r["suspicion_points"] >= 5

    def test_old_established_low(self):
        r = analyze_account_age(
            datetime(2019, 1, 1, tzinfo=timezone.utc), 5000, 1000, "twitter")
        assert r["suspicion_points"] < 10

    def test_extreme_velocity_flagged(self):
        r = analyze_account_age(
            datetime.now(timezone.utc) - timedelta(days=10),
            1_000_000, 5, "twitter")
        assert any("velocity" in f for f in r["flags"])

    def test_high_post_rate_flagged(self):
        r = analyze_account_age(
            datetime.now(timezone.utc) - timedelta(days=5),
            100, 1_000, "twitter")
        assert r["suspicion_points"] > 5

    def test_no_creation_date_returns_result(self):
        r = analyze_account_age(None, 1000, 50, "twitter")
        assert r["suspicion_points"] >= 3
        assert "creation_date_hidden" in r["flags"]

    def test_score_capped_at_20(self):
        r = analyze_account_age(
            datetime.now(timezone.utc) - timedelta(days=1),
            10_000_000, 10_000_000, "twitter")
        assert r["suspicion_points"] <= 20

    def test_returns_required_keys(self):
        r = analyze_account_age(datetime(2022,1,1,tzinfo=timezone.utc), 1000, 100, "twitter")
        assert "suspicion_points" in r
        assert "flags" in r
        assert "details" in r


# ═══════════════════════════════════════════════════════════════════
#  GROUP 10 — F-18: Content Pattern
# ═══════════════════════════════════════════════════════════════════
from app.analyzers.f18_content_pattern import analyze_content_pattern

class TestContentPattern:

    def test_clean_posts_low_score(self):
        posts = [{"text": f"Had a great time today visiting place {i}"} for i in range(5)]
        r = analyze_content_pattern(posts, "")
        assert r["suspicion_points"] < 10

    def test_copy_paste_posts_flagged(self):
        posts = [{"text": "DM me for investment guaranteed profit 100%"}] * 10
        r = analyze_content_pattern(posts, "")
        assert r["template_detected"] or r["suspicion_points"] > 0

    def test_scam_template_in_bio_flagged(self):
        r = analyze_content_pattern([], "DM me for investment details guaranteed")
        assert r["suspicion_points"] > 0

    def test_hashtag_spam_flagged(self):
        big_text = " ".join(f"#tag{i}" for i in range(60))
        posts = [{"text": big_text}]
        r = analyze_content_pattern(posts, "")
        assert r["suspicion_points"] > 0

    def test_empty_no_crash(self):
        r = analyze_content_pattern([], "")
        assert r is not None
        assert r["suspicion_points"] == 0

    def test_score_capped_at_20(self):
        scam = "Send crypto get back guaranteed profit DM me NOW limited slots"
        posts = [{"text": scam}] * 20
        r = analyze_content_pattern(posts, scam)
        assert r["suspicion_points"] <= 20


# ═══════════════════════════════════════════════════════════════════
#  GROUP 11 — F-19: Language / Geo
# ═══════════════════════════════════════════════════════════════════
from app.analyzers.f19_language_geo import analyze_language_geo, _detect_script

class TestLanguageGeo:

    def test_arabic_script_detected(self):
        assert _detect_script("مرحبا بالعالم هذا نص عربي") == "arabic"

    def test_chinese_script_detected(self):
        assert _detect_script("你好世界这是中文文本") == "chinese"

    def test_cyrillic_script_detected(self):
        assert _detect_script("Привет мир это русский текст") == "cyrillic"

    def test_latin_script_detected(self):
        assert _detect_script("Hello world this is english text") == "latin"

    def test_no_mismatch_latin_uk(self):
        r = analyze_language_geo("London based developer", "UK", [])
        assert not r["language_mismatch"]

    def test_mismatch_chinese_bio_claims_usa(self):
        r = analyze_language_geo("你好世界这是中文文本内容很多字", "USA", [])
        assert r["language_mismatch"]
        assert r["suspicion_points"] > 0

    def test_no_location_no_mismatch(self):
        r = analyze_language_geo("Hello world", None, [])
        assert not r["language_mismatch"]

    def test_empty_no_crash(self):
        r = analyze_language_geo(None, None, [])
        assert r is not None

    def test_score_capped_at_15(self):
        r = analyze_language_geo(
            "你好 مرحبا Привет 안녕하세요 こんにちは this is mixed", "USA", [])
        assert r["suspicion_points"] <= 15


# ═══════════════════════════════════════════════════════════════════
#  GROUP 12 — Email Format
# ═══════════════════════════════════════════════════════════════════
from app.analyzers.email_analyzer import check_email_format, check_disposable_email

class TestEmailFormat:

    def test_valid_gmail(self):
        r = check_email_format("test@gmail.com")
        assert r.is_valid_format
        assert r.domain == "gmail.com"
        assert r.is_free_provider

    def test_valid_outlook(self):
        r = check_email_format("user@outlook.com")
        assert r.is_valid_format
        assert r.is_free_provider

    def test_invalid_no_at(self):
        r = check_email_format("notanemail")
        assert not r.is_valid_format
        assert r.suspicion_points >= 15

    def test_invalid_no_domain(self):
        r = check_email_format("user@")
        assert not r.is_valid_format

    def test_invalid_empty(self):
        r = check_email_format("")
        assert not r.is_valid_format
        assert r.suspicion_points >= 15

    def test_invalid_double_at(self):
        r = check_email_format("user@@gmail.com")
        assert not r.is_valid_format

    def test_valid_business_email(self):
        r = check_email_format("contact@company.org")
        assert r.is_valid_format
        assert not r.is_free_provider

    def test_valid_subdomain(self):
        r = check_email_format("user@mail.company.co.uk")
        assert r.is_valid_format


# ═══════════════════════════════════════════════════════════════════
#  GROUP 13 — Disposable Email Detection
# ═══════════════════════════════════════════════════════════════════
class TestDisposableEmail:

    def test_mailinator_detected(self):
        r = check_disposable_email("x@mailinator.com")
        assert r.is_disposable and r.suspicion_points == 25

    def test_yopmail_detected(self):
        assert check_disposable_email("y@yopmail.com").is_disposable

    def test_10minutemail_detected(self):
        assert check_disposable_email("z@10minutemail.com").is_disposable

    def test_guerrillamail_detected(self):
        assert check_disposable_email("a@guerrillamail.com").is_disposable

    def test_trashmail_detected(self):
        assert check_disposable_email("t@trashmail.com").is_disposable

    def test_tempemail_detected(self):
        assert check_disposable_email("b@tempemail.net").is_disposable

    def test_throwaway_pattern_detected(self):
        assert check_disposable_email("u@throwaway-mail.xyz").is_disposable

    def test_gmail_not_disposable(self):
        r = check_disposable_email("user@gmail.com")
        assert not r.is_disposable and r.suspicion_points == 0

    def test_outlook_not_disposable(self):
        assert not check_disposable_email("u@outlook.com").is_disposable

    def test_protonmail_not_disposable(self):
        assert not check_disposable_email("u@protonmail.com").is_disposable

    def test_company_email_not_disposable(self):
        assert not check_disposable_email("hr@company.co.uk").is_disposable


# ═══════════════════════════════════════════════════════════════════
#  GROUP 14 — Phone Format
# ═══════════════════════════════════════════════════════════════════
from app.analyzers.phone_analyzer import check_phone_format

class TestPhoneFormat:

    def test_valid_pakistan_mobile(self):
        r = check_phone_format("+923001234567")
        assert r.is_valid and r.country_code == "PK"

    def test_valid_uk_landline(self):
        r = check_phone_format("+442071234567")
        assert r.is_valid and r.country_code == "GB"

    def test_valid_us_number(self):
        r = check_phone_format("+12025551234")
        assert r.is_valid and r.country_code == "US"

    def test_valid_india(self):
        r = check_phone_format("+919876543210")
        assert r.is_valid and r.country_code == "IN"

    def test_invalid_too_short(self):
        r = check_phone_format("+1234")
        assert not r.is_valid and r.suspicion_points >= 15

    def test_invalid_all_zeros(self):
        r = check_phone_format("000000000")
        assert not r.is_valid

    def test_invalid_letters(self):
        r = check_phone_format("abcdefg")
        assert not r.is_valid

    def test_e164_format_returned(self):
        r = check_phone_format("+923001234567")
        if r.is_valid:
            assert r.formatted_e164 and r.formatted_e164.startswith("+")

    def test_country_name_returned(self):
        r = check_phone_format("+923001234567")
        if r.is_valid:
            assert r.country_name and len(r.country_name) > 0

    def test_number_type_returned(self):
        r = check_phone_format("+923001234567")
        if r.is_valid:
            assert r.number_type in ("mobile","fixed_line","voip","unknown","fixed_line_or_mobile")


# ═══════════════════════════════════════════════════════════════════
#  GROUP 15 — WhatsApp
# ═══════════════════════════════════════════════════════════════════
from app.analyzers.phone_analyzer import check_whatsapp

class TestWhatsApp:

    @pytest.mark.asyncio
    async def test_valid_pk_generates_link(self):
        r = await check_whatsapp("+923001234567")
        assert r.number_valid
        assert "wa.me/923001234567" in r.whatsapp_link

    @pytest.mark.asyncio
    async def test_valid_uk_generates_link(self):
        r = await check_whatsapp("+447911123456")
        assert r.number_valid
        assert "wa.me/447911123456" in r.whatsapp_link

    @pytest.mark.asyncio
    async def test_invalid_number_not_valid(self):
        r = await check_whatsapp("123")
        assert not r.number_valid

    @pytest.mark.asyncio
    async def test_link_has_no_plus(self):
        r = await check_whatsapp("+923001234567")
        if r.number_valid:
            assert "+" not in r.whatsapp_link.split("wa.me/")[1]

    @pytest.mark.asyncio
    async def test_formatted_e164_returned(self):
        r = await check_whatsapp("+923001234567")
        if r.number_valid:
            assert r.formatted_number.startswith("+")


# ═══════════════════════════════════════════════════════════════════
#  GROUP 16 — Config / HIBP key detection
# ═══════════════════════════════════════════════════════════════════
from app.config import Settings

class TestConfig:

    def test_test_hibp_key_invalid(self):
        s = Settings(hibp_api_key="00000000000000000000000000000000")
        assert not s.hibp_key_valid

    def test_blank_hibp_key_invalid(self):
        s = Settings(hibp_api_key="")
        assert not s.hibp_key_valid

    def test_real_hibp_key_valid(self):
        s = Settings(hibp_api_key="somerealapikey123456")
        assert s.hibp_key_valid

    def test_leakcheck_always_available(self):
        s = Settings()
        assert s.p3_status()["leakcheck"] is True

    def test_hudsonrock_always_available(self):
        s = Settings()
        assert s.p3_status()["hudsonrock"] is True

    def test_email_status_has_free_sources(self):
        s = Settings()
        assert s.email_status()["leakcheck"] is True
        assert s.email_status()["hudsonrock"] is True

    def test_p2_false_without_keys(self):
        s = Settings(twitter_bearer_token="")
        assert s.p2_status()["twitter_heuristics"] is False

    def test_p2_true_with_twitter_key(self):
        s = Settings(twitter_bearer_token="some_token")
        assert s.p2_status()["twitter_heuristics"] is True
