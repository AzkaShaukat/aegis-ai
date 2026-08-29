# Aegis AI — Deepfake Detection API
## Port 8004 | Phase 1

Deepfake detection microservice for the Aegis AI cybersecurity platform.
Wraps two independently-trained 3-model ensembles behind a single FastAPI service.

| Pipeline | Models | Trained on | Best AUC |
|---|---|---|---|
| Image | EfficientNet-B4 + ViT-B/16 + FrequencyCNN | 140k GAN faces (StyleGAN2/3, ProGAN) | ~0.97 |
| Video | Spatial CNN + Temporal Transformer + Freq SRM CNN | FaceForensics++ (657k frames, 13,509 videos) | 0.9394 |

---

## Quick Start

```bash
# 1. Clone / unzip
cd deepfake-api

# 2. Configure
cp .env.example .env
# Edit .env — add paths to your .pth model checkpoints

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run
uvicorn app.main:app --host 0.0.0.0 --port 8004 --reload

# 5. Open interactive docs
# http://localhost:8004/docs
```

Or with Docker:
```bash
cp .env.example .env
# Create the shared Aegis network if it doesn't exist:
docker network create aegis_network
docker-compose up --build
```

---

## Placing your model checkpoints

Copy your trained `.pth` files from Google Drive into the `models/` directory:

```
models/
  image/
    efficientnet_best.pth    ← from NB2 best_model.pth (Doc 1)
    vit_best.pth             ← from NB3 best_model.pth (Doc 1)
    freqcnn_best.pth         ← from NB4 best_model.pth (Doc 1)
    ensemble_config.json     ← from NB5 ensemble_config.json (Doc 1) [optional]
  video/
    spatial_best.pth         ← from NB2 best_model.pth (Doc 2)
    temporal_best.pth        ← from NB3 best_model.pth (Doc 2)
    freq_srm_best.pth        ← from NB4 best_model.pth (Doc 2)
```

The API starts in **stub mode** if checkpoints are not found — all endpoints work and return neutral results (p_fake=0.5). This lets you test the API without models.

---

## API Endpoints

### `GET /health`
Returns load status of all 6 models and GPU availability.

### `POST /analyze/image`
Analyze a single face image for deepfake manipulation.
```bash
curl -X POST http://localhost:8004/analyze/image \
  -F "file=@face.jpg"
```

### `POST /analyze/image-url`
Fetch an image from a URL and analyze it.
```bash
curl -X POST http://localhost:8004/analyze/image-url \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com/face.jpg", "source_hint": "whatsapp"}'
```

### `POST /analyze/video`
Analyze a video file for deepfake manipulation.
```bash
curl -X POST http://localhost:8004/analyze/video \
  -F "file=@clip.mp4"
```

---

## Response structure

Every endpoint returns the same schema:

```json
{
  "scan_id": "img-a1b2c3d4e5f6",
  "scan_date": "2026-03-20",
  "pipeline_used": "image_ensemble",
  "overall_risk_score": 82,
  "overall_risk_level": "High Risk",
  "ensemble_probability": 0.8247,
  "verdict": "LIKELY_FAKE",
  "message": "🔴 LIKELY FAKE — Manipulation patterns detected (82% fake probability)",
  "confidence_note": "All three models agree (individual scores: M1=84%, M2=81%, M3=79%). Ensemble probability: 82% fake.",
  "per_model_scores": {
    "model_1_name": "EfficientNet-B4", "model_1_p_fake": 0.84,
    "model_2_name": "ViT-B/16",        "model_2_p_fake": 0.81,
    "model_3_name": "FrequencyCNN",    "model_3_p_fake": 0.79
  },
  "ensemble_weights": {
    "model_1_weight": 0.50, "model_2_weight": 0.45,
    "model_3_weight": 0.05, "source": "default"
  },
  "model_agreement": "high",
  "face_info": {
    "faces_detected": 1,
    "primary_face_size_px": 210,
    "face_detection_confidence": 0.85,
    "multiple_faces": false
  },
  "input_quality": {
    "status": "good",
    "blur_score": 142.3,
    "resolution_ok": true,
    "face_visibility_ok": true,
    "warnings": []
  },
  "video_info": null,
  "all_flags": [
    "Ensemble predicts 82% probability of manipulation",
    "Spatial/texture model detected face boundary or skin artifacts",
    "Frequency model detected GAN noise residuals"
  ],
  "total_flags": 3,
  "elapsed_ms": 2341.5
}
```

### Risk levels (consistent with all Aegis services)

| Score | Level | Action |
|---|---|---|
| 0–15 | Clean | Accept as real |
| 16–35 | Low Risk | Probably real — note lower confidence |
| 36–55 | Medium Risk | Flag for review |
| 56–75 | High Risk | Likely fake |
| 76–100 | Critical | High-confidence deepfake |

---

## Running tests

```bash
# Unit tests only (no .pth files needed, ~5 seconds)
pytest tests/ -m "not integration" -v

# Generate synthetic test assets first
python scripts/generate_synthetic_assets.py

# All tests including integration (requires .pth checkpoints)
pytest tests/ -v

# Run a specific test file
pytest tests/test_image_analysis.py -v

# Run with coverage
pip install pytest-cov
pytest tests/ -m "not integration" --cov=app --cov-report=term-missing
```

---

## Phase roadmap

| Phase | Status | Features |
|---|---|---|
| **Phase 1** | ✅ This release | /health, /analyze/image, /analyze/image-url, /analyze/video, quality gate, Docker |
| **Phase 2** | Planned | Async video (/analyze/video-async + /analyze/status), batch, GradCAM heatmap, video timeline |
| **Phase 3** | Planned | Feedback loop, metrics/prometheus, Redis caching, confidence calibration, rate limiting |

---

## Known limitations

- **Diffusion model blindspot**: Stable Diffusion / Midjourney faces were not in training data. Expected accuracy: 60–75%.
- **Audio deepfakes**: Vision only — voice cloning not detected.
- **Adversarial robustness**: A motivated attacker can craft inputs to evade detection.
- **Not for legal/forensic use**: Predictions are probabilistic, not definitive evidence.
- **Video scan time**: Full video analysis takes 30–90 seconds (async endpoint in Phase 2).

See `tests/assets/README.md` for recommended test datasets.
