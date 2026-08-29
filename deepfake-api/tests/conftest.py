"""
Shared test fixtures.
All unit tests use mocked models — no .pth files required.

KEY FIX: load_all_models() is mocked in lifespan so real .pth files
on disk don't overwrite our test fixtures.
"""
from __future__ import annotations

import sys
try:
    import torch
except ImportError:
    from tests.mock_torch import torch_mock  # noqa

import math
import os
import tempfile
from unittest.mock import MagicMock, patch

import cv2
import numpy as np
import pytest
import torch
import torch.nn as nn

from app.models.ensemble import EnsembleState, ModelLoadStatus


# ── Mock model factory ────────────────────────────────────────────────────────

def make_mock_model(p_fake: float = 0.3) -> nn.Module:
    """
    Returns a mock model that always predicts p_fake.
    FIXED: uses model.return_value (not __call__) so MagicMock
    correctly returns the tensor when the model is called.
    """
    logit = math.log(max(p_fake, 1e-7) / max(1.0 - p_fake, 1e-7))
    model = MagicMock()  # no spec= so __call__ isn't restricted
    model.eval.return_value = model
    model.to.return_value = model
    # This is the correct way to make MagicMock return a tensor when called
    model.return_value = torch.tensor([[logit]], dtype=torch.float32)
    return model


def make_stub_image_ensemble(p1=0.1, p2=0.1, p3=0.1) -> EnsembleState:
    statuses = {
        "efficientnet": ModelLoadStatus(loaded=True, path="mock"),
        "vit":          ModelLoadStatus(loaded=True, path="mock"),
        "freqcnn":      ModelLoadStatus(loaded=True, path="mock"),
    }
    return EnsembleState(
        model_1=make_mock_model(p1),
        model_2=make_mock_model(p2),
        model_3=make_mock_model(p3),
        weights=[0.50, 0.45, 0.05],
        weight_source="default",
        statuses=statuses,
        device="cpu",
    )


def make_stub_video_ensemble(p_spatial=0.1, p_temporal=0.1, p_srm=0.1) -> EnsembleState:
    statuses = {
        "spatial":  ModelLoadStatus(loaded=True, path="mock"),
        "temporal": ModelLoadStatus(loaded=True, path="mock"),
        "freq_srm": ModelLoadStatus(loaded=True, path="mock"),
    }
    return EnsembleState(
        model_1=make_mock_model(p_spatial),
        model_2=make_mock_model(p_temporal),
        model_3=make_mock_model(p_srm),
        weights=[0.365, 0.338, 0.297],
        weight_source="auc_proportional",
        statuses=statuses,
        device="cpu",
    )


def make_unloaded_ensemble() -> EnsembleState:
    """Ensemble where no models are loaded (stub mode)."""
    statuses = {
        "model_1": ModelLoadStatus(loaded=False, path="not/found.pth", error="File not found"),
        "model_2": ModelLoadStatus(loaded=False, path="not/found.pth", error="File not found"),
        "model_3": ModelLoadStatus(loaded=False, path="not/found.pth", error="File not found"),
    }
    return EnsembleState(
        model_1=None, model_2=None, model_3=None,
        weights=[0.50, 0.45, 0.05],
        weight_source="default",
        statuses=statuses,
        device="cpu",
    )


# ── Synthetic image/video generators ─────────────────────────────────────────

def make_face_image_bytes(width=400, height=400, blur_sigma=0.0) -> bytes:
    img = np.ones((height, width, 3), dtype=np.uint8) * 200
    cx, cy, r = width // 2, height // 2, width // 3
    cv2.ellipse(img, (cx, cy), (r, int(r * 1.2)), 0, 0, 360, (200, 160, 120), -1)
    cv2.ellipse(img, (cx, cy - r // 2), (r - 10, r // 2), 0, 180, 360, (80, 50, 30), -1)
    ey = cy - r // 4
    for ex in [cx - r // 3, cx + r // 3]:
        cv2.ellipse(img, (ex, ey), (r // 5, r // 8), 0, 0, 360, (240, 240, 240), -1)
        cv2.circle(img, (ex, ey), r // 9, (60, 40, 20), -1)
        cv2.circle(img, (ex, ey), r // 18, (10, 10, 10), -1)
    cv2.ellipse(img, (cx, cy + r // 3), (r // 3, r // 8), 0, 0, 180, (120, 60, 60), -1)
    if blur_sigma > 0:
        img = cv2.GaussianBlur(img, (0, 0), sigmaX=blur_sigma)
    _, buf = cv2.imencode(".jpg", img, [cv2.IMWRITE_JPEG_QUALITY, 95])
    return buf.tobytes()


def make_no_face_image_bytes() -> bytes:
    img = np.full((200, 200, 3), 128, dtype=np.uint8)
    _, buf = cv2.imencode(".jpg", img)
    return buf.tobytes()


def make_blurry_face_image_bytes() -> bytes:
    return make_face_image_bytes(blur_sigma=15.0)


def make_tiny_face_image_bytes() -> bytes:
    img = np.ones((400, 400, 3), dtype=np.uint8) * 200
    cv2.circle(img, (200, 200), 20, (180, 140, 100), -1)
    _, buf = cv2.imencode(".jpg", img)
    return buf.tobytes()


def make_minimal_valid_mp4() -> bytes:
    frame = np.zeros((240, 320, 3), dtype=np.uint8)
    cv2.ellipse(frame, (160, 120), (70, 85), 0, 0, 360, (180, 140, 100), -1)
    cv2.circle(frame, (138, 105), 8, (30, 20, 10), -1)
    cv2.circle(frame, (182, 105), 8, (30, 20, 10), -1)
    with tempfile.NamedTemporaryFile(suffix=".mp4", delete=False) as tf:
        tmp = tf.name
    try:
        fourcc = cv2.VideoWriter_fourcc(*"mp4v")
        vw = cv2.VideoWriter(tmp, fourcc, 5.0, (320, 240))
        for _ in range(30):
            vw.write(frame)
        vw.release()
        with open(tmp, "rb") as f:
            return f.read()
    finally:
        os.unlink(tmp)


# ── pytest fixtures ───────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def good_face_bytes():
    return make_face_image_bytes()


@pytest.fixture(scope="session")
def no_face_bytes():
    return make_no_face_image_bytes()


@pytest.fixture(scope="session")
def blurry_face_bytes():
    return make_blurry_face_image_bytes()


@pytest.fixture(scope="session")
def tiny_face_bytes():
    return make_tiny_face_image_bytes()


@pytest.fixture(scope="session")
def short_video_bytes():
    return make_minimal_valid_mp4()


@pytest.fixture
def real_image_ensemble():
    return make_stub_image_ensemble(p1=0.05, p2=0.07, p3=0.06)


@pytest.fixture
def fake_image_ensemble():
    return make_stub_image_ensemble(p1=0.91, p2=0.88, p3=0.85)


@pytest.fixture
def uncertain_image_ensemble():
    return make_stub_image_ensemble(p1=0.48, p2=0.52, p3=0.50)


@pytest.fixture
def disagreeing_image_ensemble():
    return make_stub_image_ensemble(p1=0.9, p2=0.1, p3=0.5)


@pytest.fixture
def unloaded_ensemble():
    return make_unloaded_ensemble()


@pytest.fixture
def real_video_ensemble():
    return make_stub_video_ensemble(p_spatial=0.05, p_temporal=0.07, p_srm=0.06)


@pytest.fixture
def fake_video_ensemble():
    return make_stub_video_ensemble(p_spatial=0.90, p_temporal=0.87, p_srm=0.82)


def _make_client(img_ens, vid_ens):
    """
    Create test client with:
    1. load_all_models mocked so lifespan doesn't load real .pth files
    2. init_db mocked so SQLite isn't touched
    3. Rate limiter always returns allowed
    4. Registry set to our mock ensembles
    """
    from fastapi.testclient import TestClient
    from app.main import app
    from app.models import ensemble as ens_mod

    with patch("app.main.load_all_models"), \
         patch("app.main.init_db"), \
         patch("app.utils.rate_limiter.check_rate_limit", return_value=(True, 99, 60)):
        ens_mod._registry["image"] = img_ens
        ens_mod._registry["video"] = vid_ens
        with TestClient(app) as c:
            # Re-set after lifespan (belt and suspenders)
            ens_mod._registry["image"] = img_ens
            ens_mod._registry["video"] = vid_ens
            yield c


@pytest.fixture
def client(real_image_ensemble, real_video_ensemble):
    yield from _make_client(real_image_ensemble, real_video_ensemble)


@pytest.fixture
def fake_client(fake_image_ensemble, fake_video_ensemble):
    yield from _make_client(fake_image_ensemble, fake_video_ensemble)


@pytest.fixture
def unloaded_client(unloaded_ensemble):
    yield from _make_client(unloaded_ensemble, unloaded_ensemble)
