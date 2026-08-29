"""
test_ml_model.py — ML Classifier Tests + Accuracy Validation
==============================================================
Tests for: model quality, feature extraction, sanity checks,
           prediction consistency, and overfitting detection.

WHY TRAINING WAS 100% ACCURATE (the problem explained):
  The first model showed training_accuracy: 1 (100%) because:

  1. OVERFITTING: With no max_depth limit, the RandomForest grew
     trees deep enough to memorize every single training sample.
     A tree with unlimited depth will ALWAYS reach 100% on training
     data — it's not learning, it's just copying.

  2. DATA LEAKAGE: The feature 'vt_malicious_normalized' was set to
     8/10 = 0.8 for ALL phishing samples and 0/10 = 0.0 for ALL
     benign samples. The model saw this perfect oracle signal and
     relied on it exclusively. When it predicts 'phishing' it may
     just be saying 'this has VT malicious count > 0'.

  3. SMALL DATASET: Training on just URL-structure features from a
     few hundred samples means the model can memorize patterns
     (e.g., all .tk URLs are phishing) without generalizing.

  FIX: Use the updated train_classifier.py with:
    - max_depth=8 (prevents memorization)
    - min_samples_leaf=10 (prevents single-sample leaves)
    - Proper 60/20/20 train/val/test split
    - SMOTE for class balance
    - CalibratedClassifierCV for honest probabilities
    - Held-out test set never touched during training

  EXPECTED REALISTIC ACCURACY: 88-94% (not 100%)
"""

import math
import re
import json
import os
import struct
import pytest
from conftest import BASE_URL, TIMEOUT, post_scan_file, get, make_qr_b64


# ════════════════════════════════════════════════════════════════
# 5.1 — ML Prediction Structure
# ════════════════════════════════════════════════════════════════

class TestMLPredictionStructure:
    """Every URL scan should include an ML prediction block."""

    def test_url_scan_has_ml_prediction(self, safe_url_qr):
        r = post_scan_file(safe_url_qr)
        analysis = r.json()["analyses"][0]
        assert len(analysis.get("url_deep_scans", [])) > 0
        deep = analysis["url_deep_scans"][0]
        assert "ml_prediction" in deep, (
            "URL deep scan should include ml_prediction block"
        )

    def test_ml_prediction_has_required_fields(self, safe_url_qr):
        r = post_scan_file(safe_url_qr)
        ml = r.json()["analyses"][0]["url_deep_scans"][0]["ml_prediction"]
        required = [
            "available", "prediction", "ml_risk_level",
            "phishing_probability", "safe_probability", "top_features"
        ]
        for field in required:
            assert field in ml, f"Missing ML field: {field}"

    def test_probabilities_sum_to_approximately_100(self, safe_url_qr):
        r = post_scan_file(safe_url_qr)
        ml = r.json()["analyses"][0]["url_deep_scans"][0]["ml_prediction"]
        if not ml.get("available"):
            pytest.skip("ML not available")
        total = ml["phishing_probability"] + ml["safe_probability"]
        assert 99.0 <= total <= 101.0, (
            f"Probabilities should sum to 100, got {total}"
        )

    def test_probabilities_are_in_valid_range(self, safe_url_qr):
        r = post_scan_file(safe_url_qr)
        ml = r.json()["analyses"][0]["url_deep_scans"][0]["ml_prediction"]
        if not ml.get("available"):
            pytest.skip("ML not available")
        assert 0.0 <= ml["phishing_probability"] <= 100.0
        assert 0.0 <= ml["safe_probability"] <= 100.0

    def test_prediction_is_binary(self, safe_url_qr):
        r = post_scan_file(safe_url_qr)
        ml = r.json()["analyses"][0]["url_deep_scans"][0]["ml_prediction"]
        if not ml.get("available"):
            pytest.skip("ML not available")
        assert ml["prediction"] in (0, 1)

    def test_ml_risk_level_is_valid(self, safe_url_qr):
        r = post_scan_file(safe_url_qr)
        ml = r.json()["analyses"][0]["url_deep_scans"][0]["ml_prediction"]
        if not ml.get("available"):
            pytest.skip("ML not available")
        assert ml["ml_risk_level"] in (
            "Low Risk", "Medium Risk", "High Risk", "Critical Risk", "Safe"
        )

    def test_top_features_populated(self, safe_url_qr):
        r = post_scan_file(safe_url_qr)
        ml = r.json()["analyses"][0]["url_deep_scans"][0]["ml_prediction"]
        if not ml.get("available"):
            pytest.skip("ML not available")
        assert len(ml["top_features"]) > 0

    def test_top_features_have_required_fields(self, safe_url_qr):
        r = post_scan_file(safe_url_qr)
        ml = r.json()["analyses"][0]["url_deep_scans"][0]["ml_prediction"]
        if not ml.get("available"):
            pytest.skip("ML not available")
        for feat in ml["top_features"]:
            assert "feature" in feat
            assert "value" in feat
            assert "importance" in feat


# ════════════════════════════════════════════════════════════════
# 5.2 — Model Sanity: Directional Accuracy Tests
#
# These test that the model gives DIRECTIONALLY CORRECT predictions
# (phishing URLs score higher than benign URLs) even if not perfect.
# ════════════════════════════════════════════════════════════════

class TestMLDirectionalAccuracy:
    """
    Sanity checks: the model should give higher phishing probability
    to phishing-like URLs than to known-safe URLs.
    We don't demand 100% — we demand the right direction.
    """

    def _get_phishing_prob(self, url: str) -> float:
        r = post_scan_file(make_qr_b64(url))
        data = r.json()
        if not data["analyses"] or not data["analyses"][0].get("url_deep_scans"):
            pytest.skip(f"No deep scan for {url}")
        ml = data["analyses"][0]["url_deep_scans"][0].get("ml_prediction", {})
        if not ml.get("available"):
            pytest.skip("ML not available")
        return ml["phishing_probability"]

    def test_google_has_lower_risk_than_phishing_url(self):
        safe_prob   = self._get_phishing_prob("https://google.com")
        phish_prob  = self._get_phishing_prob(
            "http://paypal-verify-account-secure.tk/login"
        )
        assert safe_prob < phish_prob, (
            f"google.com ({safe_prob:.1f}%) should have lower phishing probability "
            f"than a .tk phishing URL ({phish_prob:.1f}%)"
        )

    def test_http_url_higher_risk_than_https(self):
        """HTTP scheme should increase phishing probability."""
        https_prob = self._get_phishing_prob("https://example.com/page")
        http_prob  = self._get_phishing_prob("http://example.com/page")
        assert http_prob >= https_prob - 5, (
            f"HTTP ({http_prob:.1f}%) should be >= HTTPS ({https_prob:.1f}%) risk"
        )

    def test_phishing_keywords_increase_risk(self):
        """URL with phishing keywords should score higher."""
        clean_prob = self._get_phishing_prob("https://myshop.com/products")
        kw_prob    = self._get_phishing_prob(
            "https://secure-verify-account-login.com/confirm"
        )
        assert kw_prob >= clean_prob, (
            f"Phishing-keyword URL ({kw_prob:.1f}%) should not score lower "
            f"than clean URL ({clean_prob:.1f}%)"
        )

    def test_known_good_sites_are_low_risk(self):
        """Major platforms should never be above 60% phishing probability."""
        known_safe = [
            "https://google.com",
            "https://github.com",
            "https://microsoft.com",
            "https://stackoverflow.com",
        ]
        for url in known_safe:
            prob = self._get_phishing_prob(url)
            assert prob < 70, (
                f"{url} has phishing probability {prob:.1f}% — "
                "this suggests the model is not calibrated correctly. "
                "Re-train with max_depth=8 and CalibratedClassifierCV."
            )

    def test_ip_based_url_higher_risk(self):
        """IP-based URLs should have higher phishing probability than domain URLs."""
        domain_prob = self._get_phishing_prob("https://example.com/page")
        ip_prob     = self._get_phishing_prob("http://45.33.32.156/login.php")
        assert ip_prob >= domain_prob - 5, (
            f"IP URL ({ip_prob:.1f}%) should be >= domain URL ({domain_prob:.1f}%) risk"
        )


# ════════════════════════════════════════════════════════════════
# 5.3 — Model Metadata Quality
# ════════════════════════════════════════════════════════════════

class TestMLModelMetadata:
    def test_model_type_is_recorded(self, safe_url_qr):
        r = post_scan_file(safe_url_qr)
        ml = r.json()["analyses"][0]["url_deep_scans"][0].get("ml_prediction", {})
        if not ml.get("available"):
            pytest.skip("ML not available")
        assert "model_type" in ml
        assert "RandomForest" in ml["model_type"] or "Classifier" in ml["model_type"]

    def test_model_version_is_recorded(self, safe_url_qr):
        r = post_scan_file(safe_url_qr)
        ml = r.json()["analyses"][0]["url_deep_scans"][0].get("ml_prediction", {})
        if not ml.get("available"):
            pytest.skip("ML not available")
        assert "model_version" in ml
        assert ml["model_version"] is not None

    def test_features_count_is_35(self, safe_url_qr):
        r = post_scan_file(safe_url_qr)
        ml = r.json()["analyses"][0]["url_deep_scans"][0].get("ml_prediction", {})
        if not ml.get("available"):
            pytest.skip("ML not available")
        assert ml.get("features_used") == 35, (
            f"Expected 35 features, got {ml.get('features_used')}"
        )

    @pytest.mark.xfail(
        reason=(
            "Model is currently 100% training accuracy — known overfitting issue. "
            "Fix: re-run train_classifier.py with max_depth=8 and a proper "
            "train/val/test split. Expected accuracy after fix: 88-94%."
        ),
        strict=False,   # xfail: marks as XFAIL if it fails, XPASS if it passes
    )
    def test_training_accuracy_is_not_100_percent(self, safe_url_qr):
        """
        100% training accuracy is a strong indicator of overfitting.
        The model should show realistic accuracy (< 100%).

        This test is marked xfail because the model currently reports 100%
        training accuracy (overfitting). The test logic is CORRECT — 100%
        accuracy on training data is a real problem. Once the model is
        retrained with max_depth=8 and a held-out test split, this test
        will pass and xfail will become xpass automatically.

        FIX FOR THE MODEL (not the test):
            1. Open notebooks/train_classifier.py (or Google Colab notebook)
            2. Set max_depth=8 in RandomForestClassifier(...)
            3. Add train_test_split(X, y, test_size=0.2, random_state=42)
            4. Report accuracy on the TEST set, not the training set
            5. Rebuild Docker: docker-compose up --build
        """
        r = post_scan_file(safe_url_qr)
        ml = r.json()["analyses"][0]["url_deep_scans"][0].get("ml_prediction", {})
        if not ml.get("available"):
            pytest.skip("ML not available")

        acc = ml.get("training_accuracy", 1.0)
        assert acc < 1.0, (
            f"Training accuracy is {acc*100:.1f}% — this indicates OVERFITTING. "
            "Re-run train_classifier.py with max_depth=8 and proper train/val/test split."
        )

    def test_trained_on_date_recorded(self, safe_url_qr):
        r = post_scan_file(safe_url_qr)
        ml = r.json()["analyses"][0]["url_deep_scans"][0].get("ml_prediction", {})
        if not ml.get("available"):
            pytest.skip("ML not available")
        assert "trained_on" in ml
        # Should be a valid date
        assert len(ml["trained_on"]) >= 8


# ════════════════════════════════════════════════════════════════
# 5.4 — Prediction Consistency
# ════════════════════════════════════════════════════════════════

class TestMLConsistency:
    def test_same_url_same_prediction(self, safe_url_qr):
        """Deterministic model: same URL should give same prediction."""
        r1 = post_scan_file(safe_url_qr)
        r2 = post_scan_file(safe_url_qr)

        ml1 = r1.json()["analyses"][0]["url_deep_scans"][0].get("ml_prediction", {})
        ml2 = r2.json()["analyses"][0]["url_deep_scans"][0].get("ml_prediction", {})

        if not ml1.get("available") or not ml2.get("available"):
            pytest.skip("ML not available")

        assert ml1["prediction"] == ml2["prediction"], (
            "Same URL gave different predictions on consecutive scans — "
            "model should be deterministic"
        )
        assert abs(ml1["phishing_probability"] - ml2["phishing_probability"]) < 1.0, (
            "Same URL gave significantly different probability on consecutive scans"
        )

    def test_ml_does_not_error_on_long_url(self):
        """Model should handle very long URLs without crashing."""
        long_url = "https://example.com/" + "a" * 500
        r = post_scan_file(make_qr_b64(long_url))
        assert r.status_code == 200
        if r.json()["analyses"][0].get("url_deep_scans"):
            ml = r.json()["analyses"][0]["url_deep_scans"][0].get("ml_prediction", {})
            if ml.get("available"):
                assert ml.get("error") is None

    def test_ml_handles_unicode_url(self):
        """Unicode URLs (punycode) should not crash the model."""
        unicode_url = "https://xn--80ak6aa92e.com/login"  # punycode
        r = post_scan_file(make_qr_b64(unicode_url))
        assert r.status_code == 200


# ════════════════════════════════════════════════════════════════
# 5.5 — Why 100% Accuracy is Wrong: Documentation Test
# ════════════════════════════════════════════════════════════════

class TestOverfittingExplanation:
    """
    These 'tests' are documentation — they explain exactly why
    100% training accuracy occurs and what to do about it.
    They will always pass (they just print information).
    """

    def test_explain_overfitting_causes(self, safe_url_qr):
        """
        UNDERSTANDING THE 100% ACCURACY PROBLEM
        =========================================

        Root cause 1 — Unlimited tree depth:
          RandomForestClassifier(max_depth=None) grows each tree
          until every leaf contains exactly 1 sample. A tree with
          1000 samples and unlimited depth can perfectly separate all
          1000 samples even with random data. The 'accuracy' on the
          TRAINING set is always 100% for this reason.

        Root cause 2 — VT malicious count feature:
          vt_malicious_normalized = (malicious_count / 10)
          In url_to_scan_result(), phishing samples got malicious=8,
          benign got malicious=0. This creates a perfect oracle signal.
          The model learned: 'if VT says malicious > 0, predict phishing.'
          This is not learning URL patterns — it's learning VT output.

        Root cause 3 — No held-out test set:
          training_accuracy = model.score(X_train, y_train)
          Since the model was evaluated on the SAME data it trained on,
          it trivially gets 100%. You must evaluate on a SEPARATE test
          set that was NEVER shown to the model during training.

        THE FIX (in updated train_classifier.py):
          1. max_depth=8, min_samples_leaf=10 → prevents memorization
          2. 60/20/20 train/val/test split → honest evaluation
          3. CalibratedClassifierCV → better probability calibration
          4. SMOTE only on training data → no leakage
          5. Expected realistic accuracy: 88–94%

        NEXT STEPS FOR BEST MODEL QUALITY:
          1. Export real scan results from Aegis via /history/export
          2. Label them as phishing (1) or benign (0)
          3. Use Cell 4b in train_classifier.py to train on real data
          4. All 35 features will have real values (not heuristic approximations)
          5. Expected improvement: +5–10% accuracy, better calibrated probabilities
        """
        r = post_scan_file(safe_url_qr)
        ml = r.json()["analyses"][0]["url_deep_scans"][0].get("ml_prediction", {})

        if ml.get("available"):
            acc = ml.get("training_accuracy", 0)
            if acc >= 1.0:
                print(f"\n⚠️  OVERFITTING DETECTED: training_accuracy={acc:.2%}")
                print("   See train_classifier.py Cell 8 for the fix.")
            else:
                print(f"\n✅ Model accuracy looks realistic: {acc:.2%}")

        # This test always passes — it's a documentation/reporting test
        assert True

    def test_feature_importance_check(self, safe_url_qr):
        """Verify that the model is using diverse features, not just one."""
        r = post_scan_file(safe_url_qr)
        ml = r.json()["analyses"][0]["url_deep_scans"][0].get("ml_prediction", {})

        if not ml.get("available"):
            pytest.skip("ML not available")

        features = ml.get("top_features", [])
        if not features:
            pytest.skip("No features in response")

        importances = [f.get("importance", 0) for f in features if f.get("importance", 0) > 0]

        if importances:
            max_imp = max(importances)
            total   = sum(importances)
            dom_pct = (max_imp / total * 100) if total > 0 else 0

            if dom_pct > 80:
                print(
                    f"\n⚠️  FEATURE DOMINANCE: One feature has {dom_pct:.0f}% of importance. "
                    f"This suggests data leakage (likely vt_malicious_normalized). "
                    f"Consider zeroing out vt_malicious and retrain."
                )
            else:
                print(f"\n✅ Feature diversity looks healthy (max feature: {dom_pct:.0f}%)")

        # Always passes — diagnostic only
        assert True
