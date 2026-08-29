"""
Unit tests for the 5-rule ensemble logic and confidence scoring.
Pure Python — no model loading required.
"""
import math
import pytest

from app.models.ensemble import five_rule_ensemble, sharpen_confidence, confidence_pct


class TestRule1:
    def test_fires_when_any_model_above_90(self):
        _, rule = five_rule_ensemble(0.92, 0.60, 0.50, 0.5, 0.45, 0.05)
        assert "Rule1" in rule

    def test_final_never_below_raw(self):
        p, _ = five_rule_ensemble(0.91, 0.30, 0.20, 0.5, 0.45, 0.05)
        raw = (0.91*0.5 + 0.30*0.45 + 0.20*0.05)
        assert p >= raw - 0.001

    def test_all_above_90_still_rule1(self):
        _, rule = five_rule_ensemble(0.91, 0.93, 0.95, 0.5, 0.45, 0.05)
        assert "Rule1" in rule

    def test_rule1_beats_rule2(self):
        # M1>=90% AND M3<10% — Rule1 fires first
        _, rule = five_rule_ensemble(0.92, 0.70, 0.05, 0.5, 0.45, 0.05)
        assert "Rule1" in rule


class TestRule2:
    def test_fires_when_any_below_10(self):
        p, rule = five_rule_ensemble(0.50, 0.02, 0.45, 0.5, 0.45, 0.05)
        assert "Rule2" in rule

    def test_final_less_than_min_score(self):
        p, _ = five_rule_ensemble(0.50, 0.02, 0.45, 0.5, 0.45, 0.05)
        assert p < 0.02  # final = 0.02 * 0.75 = 0.015

    def test_example_2pct_gives_1pt5(self):
        p, rule = five_rule_ensemble(0.50, 0.02, 0.45, 0.5, 0.45, 0.05)
        assert abs(p - 0.015) < 0.001
        assert "Rule2" in rule

    def test_does_not_fire_when_rule1_present(self):
        _, rule = five_rule_ensemble(0.95, 0.05, 0.50, 0.5, 0.45, 0.05)
        assert "Rule1" in rule  # Rule1 takes priority


class TestRule3:
    def test_fires_for_80_to_89_range(self):
        _, rule = five_rule_ensemble(0.85, 0.60, 0.50, 0.5, 0.45, 0.05)
        assert "Rule3" in rule

    def test_does_not_fire_when_rule1_present(self):
        _, rule = five_rule_ensemble(0.91, 0.85, 0.50, 0.5, 0.45, 0.05)
        assert "Rule1" in rule

    def test_result_between_dominant_and_average(self):
        p, _ = five_rule_ensemble(0.85, 0.50, 0.50, 0.5, 0.45, 0.05)
        raw = (0.85*0.5 + 0.50*0.45 + 0.50*0.05)
        assert p > raw  # dominant weighting pushes above plain average


class TestRule4:
    def test_fires_for_20_or_below(self):
        _, rule = five_rule_ensemble(0.50, 0.15, 0.50, 0.5, 0.45, 0.05)
        assert "Rule4" in rule

    def test_result_pulled_down_by_real_dominant(self):
        p, _ = five_rule_ensemble(0.50, 0.15, 0.50, 0.5, 0.45, 0.05)
        raw = (0.50*0.5 + 0.15*0.45 + 0.50*0.05)
        assert p < raw  # dominant real weighting pulls below plain average

    def test_does_not_fire_when_rule3_present(self):
        # M1=85% (rule3) AND M3=15% (rule4) — Rule3 fires first
        _, rule = five_rule_ensemble(0.85, 0.50, 0.15, 0.5, 0.45, 0.05)
        assert "Rule3" in rule


class TestRule5:
    def test_fires_for_mid_range(self):
        _, rule = five_rule_ensemble(0.50, 0.55, 0.45, 0.5, 0.45, 0.05)
        assert "Rule5" in rule

    def test_matches_plain_weighted_average(self):
        p1, p2, p3 = 0.50, 0.55, 0.45
        w1, w2, w3 = 0.5, 0.45, 0.05
        p, _ = five_rule_ensemble(p1, p2, p3, w1, w2, w3)
        expected = (p1*w1 + p2*w2 + p3*w3) / (w1+w2+w3)
        assert abs(p - expected) < 0.001


class TestSharpening:
    def test_high_scores_pushed_higher(self):
        assert sharpen_confidence(0.84) > 0.84
        assert sharpen_confidence(0.92) > 0.92

    def test_low_scores_pushed_lower(self):
        assert sharpen_confidence(0.16) < 0.16
        assert sharpen_confidence(0.08) < 0.08

    def test_50pct_unchanged(self):
        assert abs(sharpen_confidence(0.50) - 0.50) < 0.001


class TestConfidenceScore:
    def test_80pct_fake_gives_above_80_confidence(self):
        conf = confidence_pct(0.80)
        assert conf > 80.0

    def test_20pct_fake_gives_above_80_confidence(self):
        # 20% fake = 80% real conviction — confidence should mirror
        conf = confidence_pct(0.20)
        assert conf > 80.0

    def test_50pct_gives_50_confidence(self):
        conf = confidence_pct(0.50)
        assert abs(conf - 50.0) < 1.0

    def test_95pct_fake_gives_high_confidence(self):
        assert confidence_pct(0.95) > 90.0

    def test_05pct_fake_gives_high_confidence(self):
        assert confidence_pct(0.05) > 90.0

    def test_symmetry(self):
        # confidence(p) == confidence(1-p)
        for p in [0.1, 0.2, 0.3, 0.7, 0.8, 0.9]:
            assert abs(confidence_pct(p) - confidence_pct(1-p)) < 0.1
