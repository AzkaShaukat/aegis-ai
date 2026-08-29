# Aegis AI — Deepfake Detection API (Port 8004)
# Three-Phase Project Plan

---

## Architecture Summary

Two fully-trained model ensembles are wrapped behind a single FastAPI service:

| Pipeline | Input | Models | Best AUC | Dataset |
|---|---|---|---|---|
| Image | Single face photo | EfficientNet-B4 + ViT-B/16 + FrequencyCNN | ~0.97 | 140k GAN faces |
| Video | MP4/AVI/MOV | Spatial CNN + Temporal Transformer + Freq SRM CNN | 0.9394 | FaceForensics++ 657k frames |

---

## Phase 1 — Core API Foundation ✅ (This Deliverable)

**Goal:** Working API that loads both model ensembles and serves synchronous predictions with quality gating.

### Endpoints delivered
| Method | Endpoint | Description |
|---|---|---|
| GET | /health | Service health, model load status, GPU availability |
| POST | /analyze/image | Single image → image ensemble → risk verdict |
| POST | /analyze/video | Video file → video ensemble → risk verdict |
| POST | /analyze/image-url | URL of an image → fetch + image ensemble |

### Features delivered
- **Model loading** — Both ensembles loaded at startup from configurable .pth paths. Graceful stub mode if files are missing.
- **Standardized response schema** — Consistent with other Aegis microservices (risk_score 0–100, risk_level, per_model_scores, model_agreement, all_flags).
- **Quality gate** — Fast pre-inference check: face detection, resolution (min 80×80), blur score (Laplacian variance ≥ 20). Runs in < 50ms, saves inference cost on bad inputs.
- **Face detection preprocessing** — Haar Cascade + dlib fallback. Crops and aligns face before passing to model. Handles full photos, not just pre-cropped faces.
- **Docker setup** — docker-compose.yml with GPU support (optional), Redis-ready for Phase 3.
- **Full test suite** — 40+ unit tests with mocked models, 8 integration test stubs.

### Files delivered
```
app/config.py           — All settings via .env
app/schemas.py          — Pydantic request/response models
app/models/
  image_models.py       — EfficientNetB4, ViT, FrequencyCNN class definitions
  video_models.py       — SpatialCNN, TemporalTransformer, FreqSRMCNN
  ensemble.py           — Weighted ensemble logic for both pipelines
app/utils/
  face_detector.py      — Haar Cascade + dlib face detection
  preprocessing.py      — Image/video preprocessing pipelines
  quality_gate.py       — Blur, resolution, face presence checks
app/analyzers/
  image_analyzer.py     — Full image analysis pipeline
  video_analyzer.py     — Full video analysis pipeline
app/main.py             — FastAPI app, all routes, lifespan model loader
tests/                  — 40+ pytest tests
scripts/                — Test asset generators + download helpers
```

---

## Phase 2 — Async, Batch & Advanced Analysis

**Goal:** Non-blocking video processing, batch endpoints, and explainability features.

### Endpoints added
| Method | Endpoint | Description |
|---|---|---|
| POST | /analyze/video-async | Submit video job, returns job_id immediately |
| GET | /analyze/status/{job_id} | Poll job: queued → preprocessing → extracting_faces → running_models → complete |
| POST | /analyze/batch | Up to 10 images in one request, concurrent processing |
| POST | /analyze/image/explain | GradCAM heatmap showing which facial regions triggered detection |
| POST | /analyze/video/timeline | Per-second fake probability across video duration |

### Features added
- **Redis job queue** — Async video jobs stored in Redis with 1-hour TTL. Job state machine: `queued → preprocessing → extracting_faces → running_models → complete / failed`.
- **Progress messages** — Each job state transition updates a human-readable `progress_message` field so the polling client shows meaningful status.
- **GradCAM** — Gradient-weighted Class Activation Maps on EfficientNet-B4. Returns base64 heatmap overlay. Highlights blending seams, eye anomalies, boundary artifacts.
- **Video timeline** — Spatial CNN run on 1 frame/second. Returns `[{second: 0, p_fake: 0.12}, {second: 1, p_fake: 0.71}, ...]` for partial-manipulation detection.
- **Test-Time Augmentation (TTA)** — 3-pass TTA at inference (matches Doc 1 training design). Optional via request flag.
- **WhatsApp compression mode** — `source_hint: "whatsapp"` applies sharpening preprocessing before inference.
- **Batch result aggregation** — Returns per-image results + `batch_risk` (highest risk in batch) + `faces_detected_total`.

---

## Phase 3 — Feedback Loop, Metrics & Hardening

**Goal:** Production monitoring, continuous improvement infrastructure, and limitation transparency.

### Endpoints added
| Method | Endpoint | Description |
|---|---|---|
| POST | /feedback | Submit real/fake correction for a scan_id |
| GET | /feedback/stats | Correction counts, false positive/negative rates |
| GET | /metrics | JSON performance metrics |
| GET | /metrics/prometheus | Prometheus text format for Grafana |
| GET | /cache/stats | Redis memory usage |
| DELETE | /cache/purge | GDPR flush — clears all cached results |

### Features added
- **Feedback storage** — SQLite (persistent across restarts). Stores scan_id, original verdict, corrected verdict, timestamp. `training_ready: true` when 50+ corrections accumulated.
- **Limitation flags** — Every response includes a `limitations` block: `diffusion_model_blindspot`, `temporal_analysis_unavailable`, `novel_gan_risk`, `quality_degraded`. Lets the bot give appropriately caveated responses.
- **Confidence calibration** — Platt scaling layer (from Doc 1 future improvements). P(fake)=0.8 actually means ~80% of such predictions are fake.
- **Demographic fairness logging** — Log predictions per perceived skin tone bin (estimated by face brightness) to monitor for disparate error rates.
- **Rate limiting** — Redis sliding window: 10 image req/min, 3 video req/min per IP.
- **Model version tracking** — Each response includes `model_version` and `ensemble_weights` so predictions are auditable.
- **Caching** — Redis cache for image analysis (SHA-256 hash of image bytes, 1-hour TTL). Same image never analyzed twice.

---

## Test Data Guide

### For unit tests (no models needed)
All unit tests use synthetic PIL-generated images and mocked model outputs. Run with `pytest tests/ -m "not integration"`.

### For integration tests (requires .pth files)
Place your trained checkpoints at the paths in `.env`, then run `pytest tests/ -m integration`.

### Recommended real test assets

**Fake face images (GAN-generated):**
- Your own test split: `BASE_DIR/hdf5/test.h5` (from Doc 1 training)
- DFDC Public Preview: https://ai.facebook.com/datasets/dfdc/ (free, requires signup)
- Celeb-DF v2: https://github.com/yuezunli/celeb-deepfakeforensics (academic)

**Real face images:**
- LFW (Labeled Faces in the Wild): http://vis-www.cs.umass.edu/lfw/
- UTKFace: https://susanqq.github.io/UTKFace/ (Kaggle)

**Fake face videos:**
- Your FaceForensics++ test set (you already have this from training)
- DFDC test videos (same link above)

**Edge case images (auto-generated by `scripts/generate_synthetic_assets.py`):**
- Solid-colour images → expects `no_face_detected`
- PIL-drawn circle face → tests quality gate bypass
- Heavily blurred PIL image → expects `LOW_QUALITY` warning
- Tiny face (40×40) embedded in large image → expects resolution warning
