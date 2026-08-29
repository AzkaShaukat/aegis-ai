"""Tests for schemas, preprocessing utilities, and ensemble logic."""
import math
import numpy as np
import pytest
import torch


class TestSchemas:
    def test_risk_level_values(self):
        from app.schemas import RiskLevel
        assert len([r for r in RiskLevel]) == 5

    def test_pipeline_enum(self):
        from app.schemas import Pipeline
        assert Pipeline.IMAGE == "image_ensemble"
        assert Pipeline.VIDEO == "video_ensemble"

    def test_model_agreement_values(self):
        from app.schemas import ModelAgreement
        assert ModelAgreement.HIGH == "high"
        assert ModelAgreement.LOW == "low"

    def test_image_url_request_valid(self):
        from app.schemas import ImageURLRequest
        req = ImageURLRequest(url="https://example.com/face.jpg")
        assert req.source_hint is None

    def test_image_url_request_with_hint(self):
        from app.schemas import ImageURLRequest
        req = ImageURLRequest(url="https://example.com/face.jpg", source_hint="whatsapp")
        assert req.source_hint == "whatsapp"

    def test_deepfake_result_construction(self):
        from app.schemas import (
            DeepfakeAnalysisResult, EnsembleWeights, FaceInfo,
            InputQuality, ModelAgreement, PerModelScores, Pipeline, RiskLevel,
        )
        result = DeepfakeAnalysisResult(
            scan_id="img-abc", scan_date="2026-03-20", pipeline_used=Pipeline.IMAGE,
            overall_risk_score=25, overall_risk_level=RiskLevel.LOW,
            ensemble_probability=0.25, verdict="LIKELY_REAL", message="...",
            confidence_note="...",
            per_model_scores=PerModelScores(
                model_1_name="EfficientNet", model_1_p_fake=0.2,
                model_2_name="ViT", model_2_p_fake=0.3,
                model_3_name="FreqCNN", model_3_p_fake=0.25,
            ),
            ensemble_weights=EnsembleWeights(
                model_1_weight=0.5, model_2_weight=0.45, model_3_weight=0.05, source="default",
            ),
            model_agreement=ModelAgreement.HIGH,
            face_info=FaceInfo(faces_detected=1),
            input_quality=InputQuality(status="good", blur_score=35.0,
                                       resolution_ok=True, face_visibility_ok=True),
            elapsed_ms=123.4,
        )
        assert result.overall_risk_score == 25


class TestPreprocessing:
    def test_normalize_imagenet_shape(self):
        from app.utils.preprocessing import normalize_imagenet
        img = np.random.randint(0, 255, (224, 224, 3), dtype=np.uint8)
        result = normalize_imagenet(img)
        assert result.shape == (3, 224, 224)
        assert result.dtype == np.float32

    def test_normalize_imagenet_range(self):
        from app.utils.preprocessing import normalize_imagenet
        img = np.ones((224, 224, 3), dtype=np.uint8) * 128
        result = normalize_imagenet(img)
        assert abs(result.mean()) < 2.0

    def test_fft_spectrum_shape(self):
        from app.utils.preprocessing import compute_fft_spectrum
        img = np.random.randint(0, 255, (224, 224, 3), dtype=np.uint8)
        spectrum = compute_fft_spectrum(img, size=128)
        assert spectrum.shape == (3, 128, 128)
        assert spectrum.dtype == np.float32

    def test_fft_spectrum_finite(self):
        from app.utils.preprocessing import compute_fft_spectrum
        img = np.random.randint(0, 255, (224, 224, 3), dtype=np.uint8)
        spectrum = compute_fft_spectrum(img)
        assert np.all(np.isfinite(spectrum))

    def test_to_tensor_batch_dim(self):
        from app.utils.preprocessing import to_tensor
        chw = np.zeros((3, 224, 224), dtype=np.float32)
        t = to_tensor(chw)
        assert t.shape == (1, 3, 224, 224)

    def test_preprocess_image_keys(self):
        from app.utils.preprocessing import preprocess_image_for_ensemble
        face_bgr = np.random.randint(0, 255, (224, 224, 3), dtype=np.uint8)
        result = preprocess_image_for_ensemble(face_bgr)
        assert "standard" in result and "fft" in result
        assert result["standard"].shape == (1, 3, 224, 224)
        assert result["fft"].shape == (1, 3, 128, 128)

    def test_whatsapp_sharpening_shape(self):
        from app.utils.preprocessing import apply_whatsapp_sharpening
        img = np.random.randint(0, 255, (224, 224, 3), dtype=np.uint8)
        result = apply_whatsapp_sharpening(img)
        assert result.shape == img.shape

    def test_temporal_sequences_shape(self):
        from app.utils.preprocessing import build_temporal_sequences
        frames = [np.random.randint(0, 255, (224, 224, 3), dtype=np.uint8) for _ in range(32)]
        seqs = build_temporal_sequences(frames, seq_len=16, target_size=112)
        assert len(seqs) == 2
        assert seqs[0].shape == (16, 3, 112, 112)

    def test_temporal_sequences_insufficient(self):
        from app.utils.preprocessing import build_temporal_sequences
        frames = [np.random.randint(0, 255, (224, 224, 3), dtype=np.uint8) for _ in range(10)]
        seqs = build_temporal_sequences(frames, seq_len=16)
        assert len(seqs) == 0


class TestEnsembleLogic:
    def test_model_agreement_high(self):
        from app.models.ensemble import compute_model_agreement
        assert compute_model_agreement({"m1": 0.8, "m2": 0.82, "m3": 0.79}) == "high"

    def test_model_agreement_medium(self):
        from app.models.ensemble import compute_model_agreement
        assert compute_model_agreement({"m1": 0.8, "m2": 0.62, "m3": 0.72}) == "medium"

    def test_model_agreement_low(self):
        from app.models.ensemble import compute_model_agreement
        assert compute_model_agreement({"m1": 0.9, "m2": 0.3, "m3": 0.5}) == "low"

    def test_srm_kernel_shape(self):
        from app.models.video_models import _build_srm_weights
        w = _build_srm_weights()
        assert w.shape == (9, 1, 3, 3)

    def test_srm_kernels_sum_zero(self):
        from app.models.video_models import _build_srm_weights
        w = _build_srm_weights()
        for i in range(9):
            assert abs(w[i, 0].sum().item()) < 0.01

    def test_srm_not_trainable(self):
        from app.models.video_models import FrequencySRMCNN
        model = FrequencySRMCNN()
        assert model.srm_layer.weight.requires_grad is False


class TestFiveRuleEnsemble:
    """Tests for the 5-rule ensemble logic."""

    def test_rule1_fires_when_any_model_above_90(self):
        from app.models.ensemble import five_rule_ensemble
        p, rule = five_rule_ensemble(0.95, 0.70, 0.60, 0.5, 0.45, 0.05)
        assert "Rule1" in rule
        # Final must be >= raw weighted average
        raw = 0.95*0.5 + 0.70*0.45 + 0.60*0.05
        assert p >= raw - 0.001  # floor = raw

    def test_rule1_final_never_below_raw(self):
        from app.models.ensemble import five_rule_ensemble
        # Even if dominant model is 90% and others are low, final >= raw
        p, rule = five_rule_ensemble(0.91, 0.30, 0.20, 0.5, 0.45, 0.05)
        raw = 0.91*0.5 + 0.30*0.45 + 0.20*0.05
        assert p >= raw - 0.001
        assert "Rule1" in rule

    def test_rule2_fires_when_any_below_10(self):
        from app.models.ensemble import five_rule_ensemble
        # M2=2% — strong REAL signal, no model >= 90%
        p, rule = five_rule_ensemble(0.50, 0.02, 0.45, 0.5, 0.45, 0.05)
        assert "Rule2" in rule
        # Final = min_score * 0.75 = 0.02 * 0.75 = 0.015
        assert abs(p - 0.015) < 0.001

    def test_rule2_final_less_than_min_score(self):
        from app.models.ensemble import five_rule_ensemble
        p, rule = five_rule_ensemble(0.40, 0.05, 0.35, 0.5, 0.45, 0.05)
        # Final must be less than 0.05 (the min score)
        assert p < 0.05

    def test_rule1_takes_priority_over_rule2(self):
        from app.models.ensemble import five_rule_ensemble
        # Both Rule1 (model_1 >= 90%) and Rule2 (model_3 < 10%) could fire
        # Rule1 should take priority
        p, rule = five_rule_ensemble(0.92, 0.70, 0.05, 0.5, 0.45, 0.05)
        assert "Rule1" in rule  # Rule1 fires first

    def test_rule3_fires_when_any_above_80(self):
        from app.models.ensemble import five_rule_ensemble
        # No model >= 90%, no model < 10%, but model_1 >= 80%
        p, rule = five_rule_ensemble(0.85, 0.60, 0.55, 0.5, 0.45, 0.05)
        assert "Rule3" in rule

    def test_rule4_fires_when_any_below_20(self):
        from app.models.ensemble import five_rule_ensemble
        # No previous rules fire
        p, rule = five_rule_ensemble(0.50, 0.15, 0.50, 0.5, 0.45, 0.05)
        assert "Rule4" in rule

    def test_rule5_fires_for_middle_scores(self):
        from app.models.ensemble import five_rule_ensemble
        # All scores in 0.25-0.75 range — no rules fire
        p, rule = five_rule_ensemble(0.50, 0.55, 0.45, 0.5, 0.45, 0.05)
        assert "Rule5" in rule

    def test_rule5_matches_plain_weighted_avg(self):
        from app.models.ensemble import five_rule_ensemble
        p1, p2, p3, w1, w2, w3 = 0.50, 0.55, 0.45, 0.5, 0.45, 0.05
        p, rule = five_rule_ensemble(p1, p2, p3, w1, w2, w3)
        expected = (p1*w1 + p2*w2 + p3*w3) / (w1+w2+w3)
        assert abs(p - expected) < 0.001

    def test_sharpen_confidence_pushes_high_scores_higher(self):
        from app.models.ensemble import sharpen_confidence
        # 84% should go to ~90%
        assert sharpen_confidence(0.84) > 0.84
        assert sharpen_confidence(0.84) > 0.88

    def test_sharpen_confidence_pushes_low_scores_lower(self):
        from app.models.ensemble import sharpen_confidence
        # 16% should go below 16%
        assert sharpen_confidence(0.16) < 0.16

    def test_sharpen_confidence_stable_at_50(self):
        from app.models.ensemble import sharpen_confidence
        # 50% should stay exactly 50%
        assert abs(sharpen_confidence(0.50) - 0.50) < 0.001
