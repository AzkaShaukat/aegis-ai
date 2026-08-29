"""
Preprocessing pipelines that match training-time transforms exactly.

Image pipeline (Doc 1):
  - 224×224 RGB, ImageNet-normalised
  - FrequencyCNN branch: 128×128 FFT magnitude spectrum (log-scaled)

Video pipeline (Doc 2):
  - Spatial CNN: 224×224 per-frame, ImageNet-normalised
  - Temporal Transformer: (T, 3, 112, 112) sequences
  - Frequency SRM CNN: 224×224 (SRM filtering happens inside the model)
"""
from __future__ import annotations
import logging
import tempfile
from pathlib import Path
from typing import Generator

import cv2
import numpy as np
import torch

from app.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

_IMAGENET_MEAN = np.array(settings.IMAGENET_MEAN, dtype=np.float32)
_IMAGENET_STD = np.array(settings.IMAGENET_STD, dtype=np.float32)


# ── Image normalization ────────────────────────────────────────────────────

def normalize_imagenet(img_rgb: np.ndarray) -> np.ndarray:
    """
    Convert HWC uint8 (0-255) to CHW float32 (ImageNet-normalised).
    Matches transforms used in all EfficientNet and ViT training.
    """
    img = img_rgb.astype(np.float32) / 255.0
    img = (img - _IMAGENET_MEAN) / _IMAGENET_STD
    return img.transpose(2, 0, 1)  # HWC → CHW


def to_tensor(img_chw: np.ndarray) -> torch.Tensor:
    """CHW numpy → (1, C, H, W) float32 tensor."""
    return torch.from_numpy(img_chw).unsqueeze(0)


# ── FFT magnitude spectrum (for image FrequencyCNN, Doc 1) ────────────────

def compute_fft_spectrum(img_bgr: np.ndarray, size: int = 128) -> np.ndarray:
    """
    Compute FFT magnitude spectrum exactly as in test notebook Block 5 bgr_to_fft().
    Input:  BGR image (OpenCV format, any size)
    Output: (3, 128, 128) float32 normalised with mean=0.5 std=0.5

    Matches training code:
      gray = cv2.cvtColor(bgr, cv2.COLOR_BGR2GRAY)
      magnitude = |fftshift(fft2(gray))|
      magnitude = 20 * log(magnitude + 1)
      magnitude = normalize 0-255
      output = cv2.cvtColor(magnitude_uint8, cv2.COLOR_GRAY2BGR)
    Then FREQ_TRANSFORM: Resize(128,128) + Normalize(mean=0.5, std=0.5)
    """
    # Step 1: grayscale FFT (matches bgr_to_fft from test notebook)
    gray = cv2.cvtColor(img_bgr, cv2.COLOR_BGR2GRAY).astype(np.float32)
    magnitude = np.abs(np.fft.fftshift(np.fft.fft2(gray)))
    magnitude = 20.0 * np.log(magnitude + 1.0)
    magnitude = cv2.normalize(magnitude, None, 0, 255, cv2.NORM_MINMAX).astype(np.uint8)

    # Step 2: convert to 3-channel BGR (grayscale replicated to 3 channels)
    fft_bgr = cv2.cvtColor(magnitude, cv2.COLOR_GRAY2BGR)

    # Step 3: resize to 128×128
    fft_resized = cv2.resize(fft_bgr, (size, size))

    # Step 4: apply FREQ_TRANSFORM normalization (mean=0.5, std=0.5) → CHW float32
    fft_f = fft_resized.astype(np.float32) / 255.0
    fft_f = (fft_f - 0.5) / 0.5
    return fft_f.transpose(2, 0, 1)  # HWC → CHW, shape (3, 128, 128)


# ── Full image preprocessing ───────────────────────────────────────────────

def preprocess_image_for_ensemble(
    face_crop_bgr: np.ndarray,
) -> dict[str, torch.Tensor]:
    """
    Prepare tensor formats for the image ensemble.
    face_crop_bgr: BGR crop from OpenCV face detector.

    Returns:
      'standard' → (1, 3, 224, 224) ImageNet-normalised RGB — for EfficientNet + ViT
      'fft'      → (1, 3, 128, 128) FFT spectrum (mean=0.5, std=0.5) — for FrequencyCNN
    """
    # Resize to 224×224
    face_224_bgr = cv2.resize(face_crop_bgr, (224, 224))

    # Standard: convert BGR→RGB then ImageNet-normalize
    face_224_rgb = cv2.cvtColor(face_224_bgr, cv2.COLOR_BGR2RGB)
    standard = to_tensor(normalize_imagenet(face_224_rgb))

    # FFT: pass BGR directly (matches bgr_to_fft in test notebook)
    fft = torch.from_numpy(
        compute_fft_spectrum(face_224_bgr, size=128)
    ).unsqueeze(0)  # (1, 3, 128, 128)

    return {"standard": standard, "fft": fft}


# ── Video frame extraction ─────────────────────────────────────────────────

def extract_frames(
    video_path: str,
    fps_target: int = 3,
) -> Generator[np.ndarray, None, None]:
    """
    Extract frames from video at fps_target frames per second.
    Yields BGR frames.
    Matches NB1 pipeline: "Frame extraction at 3 fps (sample every 10th
    frame from 30 fps source)".
    """
    cap = cv2.VideoCapture(video_path)
    if not cap.isOpened():
        raise ValueError(f"Cannot open video: {video_path}")

    source_fps = cap.get(cv2.CAP_PROP_FPS) or 30.0
    frame_interval = max(1, round(source_fps / fps_target))
    frame_idx = 0

    try:
        while True:
            ret, frame = cap.read()
            if not ret:
                break
            if frame_idx % frame_interval == 0:
                yield frame
            frame_idx += 1
    finally:
        cap.release()


def build_temporal_sequences(
    frames_rgb: list[np.ndarray],
    seq_len: int = 16,
    target_size: int = 112,
) -> list[np.ndarray]:
    """
    Build non-overlapping 16-frame sequences for the Temporal Transformer.
    Each frame is resized to 112×112 (matches NB3 Doc 2).

    Returns list of arrays with shape (seq_len, 3, 112, 112).
    """
    sequences = []
    for start in range(0, len(frames_rgb) - seq_len + 1, seq_len):
        seq_frames = frames_rgb[start: start + seq_len]
        if len(seq_frames) < seq_len:
            break
        processed = []
        for frame in seq_frames:
            resized = cv2.resize(frame, (target_size, target_size))
            chw = normalize_imagenet(resized)   # (3, 112, 112)
            processed.append(chw)
        sequences.append(np.stack(processed, axis=0))  # (16, 3, 112, 112)
    return sequences


def preprocess_video_frames(
    face_crops_rgb: list[np.ndarray],
) -> dict[str, torch.Tensor | list[torch.Tensor]]:
    """
    Prepare tensor formats for the video ensemble.

    Returns dict with:
      'standard'  → (N, 3, 224, 224)  for Spatial CNN (one frame per crop)
      'sequences' → list of (1, 16, 3, 112, 112) tensors for Temporal Transformer
      (SRM CNN uses 'standard' — filtering happens inside the model)
    """
    # Standard spatial frames (224×224)
    spatial_tensors = []
    for crop in face_crops_rgb:
        face_224 = cv2.resize(crop, (224, 224))
        spatial_tensors.append(normalize_imagenet(face_224))

    standard = torch.from_numpy(
        np.stack(spatial_tensors, axis=0)
    ) if spatial_tensors else torch.zeros(0, 3, 224, 224)

    # Temporal sequences (16-frame, 112×112)
    seq_arrays = build_temporal_sequences(face_crops_rgb, seq_len=16, target_size=112)
    sequences = [
        torch.from_numpy(s).unsqueeze(0)  # (1, 16, 3, 112, 112)
        for s in seq_arrays
    ]

    return {"standard": standard, "sequences": sequences}


# ── WhatsApp compression compensation ─────────────────────────────────────

def apply_whatsapp_sharpening(img_bgr: np.ndarray) -> np.ndarray:
    """
    Light unsharp mask to partially compensate for WhatsApp's aggressive
    JPEG recompression. Matches 'source_hint: whatsapp' behaviour.
    """
    blurred = cv2.GaussianBlur(img_bgr, (0, 0), sigmaX=2.0)
    sharpened = cv2.addWeighted(img_bgr, 1.5, blurred, -0.5, 0)
    return sharpened
