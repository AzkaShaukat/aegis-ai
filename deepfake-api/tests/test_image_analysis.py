"""Image analysis endpoint tests — all face detection mocked."""
import math
import numpy as np
import pytest
from unittest.mock import patch, MagicMock
from app.utils.face_detector import DetectedFace


def _mock_det(face_size=200):
    m = MagicMock()
    face = DetectedFace(x=50, y=50, w=face_size, h=face_size, confidence=0.95, method="mock")
    crop = np.ones((224, 224, 3), dtype=np.uint8) * 128
    m.detect.return_value = [face]
    m.detect_and_crop_primary.return_value = (crop, face)
    return m


def _no_face_det():
    m = MagicMock()
    m.detect.return_value = []
    m.detect_and_crop_primary.return_value = (None, None)
    return m


def _analyze(client, img_bytes, headers=None):
    """Run image analysis with mocked face detector."""
    with patch("app.analyzers.image_analyzer.get_face_detector", return_value=_mock_det()), \
         patch("app.utils.quality_gate.get_face_detector", return_value=_mock_det()):
        resp = client.post("/analyze/image",
                           files={"file": ("f.jpg", img_bytes, "image/jpeg")},
                           headers=headers or {})
    assert resp.status_code == 200
    return resp.json()


class TestBasic:
    def test_200_with_image(self, client, good_face_bytes):
        with patch("app.analyzers.image_analyzer.get_face_detector", return_value=_mock_det()), \
             patch("app.utils.quality_gate.get_face_detector", return_value=_mock_det()):
            assert client.post("/analyze/image", files={"file": ("f.jpg", good_face_bytes, "image/jpeg")}).status_code == 200

    def test_empty_400(self, client):
        assert client.post("/analyze/image", files={"file": ("e.jpg", b"", "image/jpeg")}).status_code == 400

    def test_no_file_422(self, client):
        assert client.post("/analyze/image").status_code == 422


class TestSchema:
    def test_scan_id(self, client, good_face_bytes):
        assert _analyze(client, good_face_bytes)["scan_id"].startswith("img-")

    def test_risk_score_range(self, client, good_face_bytes):
        assert 0 <= _analyze(client, good_face_bytes)["overall_risk_score"] <= 100

    def test_probability_range(self, client, good_face_bytes):
        assert 0.0 <= _analyze(client, good_face_bytes)["ensemble_probability"] <= 1.0

    def test_risk_level_valid(self, client, good_face_bytes):
        assert _analyze(client, good_face_bytes)["overall_risk_level"] in \
               {"Clean","Low Risk","Medium Risk","High Risk","Critical"}

    def test_verdict_valid(self, client, good_face_bytes):
        assert _analyze(client, good_face_bytes)["verdict"] in \
               {"REAL","LIKELY_REAL","UNCERTAIN","LIKELY_FAKE","FAKE","UNAVAILABLE"}

    def test_pipeline_image(self, client, good_face_bytes):
        assert _analyze(client, good_face_bytes)["pipeline_used"] == "image_ensemble"

    def test_model_scores_range(self, client, good_face_bytes):
        pms = _analyze(client, good_face_bytes)["per_model_scores"]
        for k in ("model_1_p_fake","model_2_p_fake","model_3_p_fake"):
            assert 0.0 <= pms[k] <= 1.0

    def test_agreement_valid(self, client, good_face_bytes):
        assert _analyze(client, good_face_bytes)["model_agreement"] in ("high","medium","low")

    def test_cached_field(self, client, good_face_bytes):
        assert "cached" in _analyze(client, good_face_bytes)

    def test_flags_consistent(self, client, good_face_bytes):
        d = _analyze(client, good_face_bytes)
        assert d["total_flags"] == len(d["all_flags"])

    def test_no_video_info(self, client, good_face_bytes):
        assert _analyze(client, good_face_bytes).get("video_info") is None


class TestVerdictAccuracy:
    def test_real_ensemble_real_verdict(self, client, good_face_bytes, real_image_ensemble):
        from app.models import ensemble as em
        em._registry["image"] = real_image_ensemble
        d = _analyze(client, good_face_bytes)
        assert d["verdict"] in ("REAL","LIKELY_REAL")
        assert d["overall_risk_score"] <= 35

    def test_fake_ensemble_fake_verdict(self, fake_client, good_face_bytes, fake_image_ensemble):
        from app.models import ensemble as em
        em._registry["image"] = fake_image_ensemble
        d = _analyze(fake_client, good_face_bytes)
        assert d["verdict"] in ("FAKE","LIKELY_FAKE")
        assert d["overall_risk_score"] >= 56

    def test_stub_mode_uncertain(self, unloaded_client, good_face_bytes, unloaded_ensemble):
        from app.models import ensemble as em
        em._registry["image"] = unloaded_ensemble
        d = _analyze(unloaded_client, good_face_bytes)
        # No models → p=0.5 → UNCERTAIN
        assert d["verdict"] == "UNCERTAIN"
        assert abs(d["ensemble_probability"] - 0.5) < 0.01


class TestEdgeCases:
    def test_no_face_unavailable(self, client, no_face_bytes):
        with patch("app.analyzers.image_analyzer.get_face_detector", return_value=_no_face_det()), \
             patch("app.utils.quality_gate.get_face_detector", return_value=_no_face_det()):
            resp = client.post("/analyze/image", files={"file": ("b.jpg", no_face_bytes, "image/jpeg")})
        assert resp.json()["verdict"] == "UNAVAILABLE"

    def test_whatsapp_hint(self, client, good_face_bytes):
        with patch("app.analyzers.image_analyzer.get_face_detector", return_value=_mock_det()), \
             patch("app.utils.quality_gate.get_face_detector", return_value=_mock_det()):
            resp = client.post("/analyze/image", files={"file": ("f.jpg", good_face_bytes, "image/jpeg")},
                               headers={"X-Source-Hint": "whatsapp"})
        assert resp.status_code == 200


class TestConfidenceEnhancement:
    def test_high_confidence_exceeds_90(self, client, good_face_bytes):
        """When ViT = 97%, ensemble must exceed 97% after boost + sharpening."""
        from fastapi.testclient import TestClient
        from app.main import app
        from app.models import ensemble as em
        from tests.conftest import make_stub_image_ensemble, _make_client

        high_conf = make_stub_image_ensemble(p1=0.80, p2=0.97, p3=0.70)
        for c in _make_client(high_conf, em._registry.get("video", make_stub_image_ensemble())):
            with patch("app.analyzers.image_analyzer.get_face_detector", return_value=_mock_det()), \
                 patch("app.utils.quality_gate.get_face_detector", return_value=_mock_det()):
                d = c.post("/analyze/image", files={"file": ("f.jpg", good_face_bytes, "image/jpeg")}).json()
        # ViT=97% → dominant boost 85% weight → raw ~95% → sharpened ~98%
        assert d["ensemble_probability"] >= 0.97, f"Expected >=0.97 but got {d['ensemble_probability']}"

    def test_low_confidence_below_10(self, client, good_face_bytes):
        """When one model = 5% (very real), ensemble must be below 10%."""
        from tests.conftest import make_stub_image_ensemble, _make_client
        from app.models import ensemble as em

        very_real = make_stub_image_ensemble(p1=0.05, p2=0.18, p3=0.12)
        for c in _make_client(very_real, em._registry.get("video", make_stub_image_ensemble())):
            with patch("app.analyzers.image_analyzer.get_face_detector", return_value=_mock_det()), \
                 patch("app.utils.quality_gate.get_face_detector", return_value=_mock_det()):
                d = c.post("/analyze/image", files={"file": ("f.jpg", good_face_bytes, "image/jpeg")}).json()
        assert d["ensemble_probability"] <= 0.10, f"Expected <=0.10 but got {d['ensemble_probability']}"

    def test_90plus_gives_fake_verdict(self, client, good_face_bytes):
        """92% dominant model → FAKE verdict."""
        from tests.conftest import make_stub_image_ensemble, _make_client
        from app.models import ensemble as em

        conf = make_stub_image_ensemble(p1=0.92, p2=0.75, p3=0.65)
        for c in _make_client(conf, em._registry.get("video", make_stub_image_ensemble())):
            with patch("app.analyzers.image_analyzer.get_face_detector", return_value=_mock_det()), \
                 patch("app.utils.quality_gate.get_face_detector", return_value=_mock_det()):
                d = c.post("/analyze/image", files={"file": ("f.jpg", good_face_bytes, "image/jpeg")}).json()
        assert d["verdict"] == "FAKE"
        assert d["ensemble_probability"] >= 0.92
