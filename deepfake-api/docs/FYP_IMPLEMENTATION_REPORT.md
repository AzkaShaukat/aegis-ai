# Aegis AI — Deepfake Detection API
## FYP Implementation & Technical Report
### Lahore Garrison University | Computer Science | 2025-2026
### Student: Azka Shaukat | FA22-BSSE-190

---

## 1. Project Overview

### 1.1 Problem Statement

Deepfake technology — AI-generated or AI-manipulated facial images and videos — has become a major cybersecurity and social threat. Pakistani users are increasingly targeted by deepfake-based fraud, fake news, and identity theft. Existing detection tools are either cloud-dependent (requiring data to leave the device), single-purpose (only images or only video), or black-box (no explanation of what they detected).

**Research Question:** Can a single, self-hostable REST API provide explainable, multi-model deepfake detection across both images and videos, with confidence levels that meaningfully exceed individual model performance?

### 1.2 Objectives

1. Design a multi-layer deepfake detection system covering spatial, frequency, and temporal analysis
2. Implement a face-detection preprocessing gate to reject non-face inputs efficiently
3. Develop a confidence enhancement algorithm that makes ensemble predictions stronger than individual models
4. Package the system as a production-ready Docker microservice with Redis caching and SQLite persistence
5. Integrate as a microservice within the Aegis AI cybersecurity platform (Port 8004)

---

## 2. System Architecture

### 2.1 High-Level Design

```
Client Request
    ↓
FastAPI Application (Python 3.11, Port 8004)
    ↓
Face Detection Preprocessing Gate
  → DNN (Tier 1) → Haar Cascade (Tier 2) → dlib (Tier 3)
  → REJECT if no face found
    ↓
Quality Gate (blur score, resolution, visibility)
    ↓
Two Parallel Pipelines
  ┌─────────────────────────┐   ┌─────────────────────────────────┐
  │ IMAGE PIPELINE           │   │ VIDEO PIPELINE                  │
  │ EfficientNet-B4          │   │ Spatial CNN (EffNet-B2)         │
  │ ViT-B/16                 │   │ Temporal Transformer            │
  │ FrequencyCNN             │   │ Frequency SRM CNN               │
  └─────────────────────────┘   └─────────────────────────────────┘
    ↓
Confidence Enhancement Engine
  → Dominant Model Boost (≥95%: 80% weight; ≥80%: 70% weight)
  → Smart Uncertain-Zone Logic
  → Temperature Scaling (T=1.35)
    ↓
Result Assembly + Redis Cache Write
    ↓
JSON Response to Client
```

### 2.2 Technology Stack

| Component | Technology | Version | Justification |
|---|---|---|---|
| API Framework | FastAPI + Uvicorn | 0.115 | Async-native, auto-generates OpenAPI docs, 3x faster than Flask for I/O tasks |
| Language | Python | 3.11 | Extensive ML ecosystem, native async/await |
| Deep Learning | PyTorch | 2.x | Flexible model loading, FP16 mixed precision |
| Model Architecture | timm | 0.9 | Pre-trained EfficientNet and ViT weights |
| Computer Vision | OpenCV | 4.13 | Face detection (DNN + Haar), frame extraction |
| Cache | Redis | 7 Alpine | Sub-millisecond TTL-native key-value, rate limiting |
| Persistence | SQLite + aiosqlite | — | Feedback storage, scan metrics — no external DB dependency |
| Containerization | Docker + Compose | 24+ | Reproducible deployment, Redis isolation |
| Validation | Pydantic v2 | 2.9 | Auto-generated OpenAPI schemas, type safety |
| HTTP Client | httpx | 0.27 | Async HTTP for image URL fetching |

---

## 3. Model Architectures

### 3.1 Image Pipeline (140,000 face dataset — StyleGAN2/3, ProGAN)

#### Model 1: EfficientNet-B4
- **Purpose:** Per-pixel texture analysis — detects blending seams, skin inconsistencies, sharpness differences
- **Architecture:** timm `efficientnet_b4`, `global_pool=""`, custom head: `AdaptiveAvgPool → BN(1792) → Dropout(0.4) → Linear(1792,512) → SiLU → BN(512) → Dropout(0.2) → Linear(512,1)`
- **Training:** 3-phase progressive unfreezing, OneCycleLR, AMP FP16
- **Val AUC:** ~0.97+

#### Model 2: Vision Transformer (ViT-B/16)
- **Purpose:** Global facial structure analysis — detects geometric inconsistencies across distant face regions
- **Architecture:** timm `vit_base_patch16_224`, 196 patches + CLS token, head: `LayerNorm(768) → Dropout(0.1) → Linear(768,256) → GELU → LayerNorm(256) → Dropout(0.05) → Linear(256,1)`
- **Training:** Layer-wise LR decay (0.75x per block), linear warmup + cosine decay
- **Val AUC:** 0.9643 (Phase 1 alone)

#### Model 3: FrequencyCNN
- **Purpose:** GAN noise residual detection — finds periodic upsampling artifacts invisible to human eye
- **Architecture:** 4-stage multi-scale CNN (`s1→s2→s3→s4`), each stage uses parallel 1×1/3×3/5×5 branches (named `b1/b3/b5`) with SE-style SpectralAttention and skip connections. Head: `GAP → BN(512) → Linear(512,256) → GELU → BN(256) → Linear(256,1)`
- **Input:** 128×128 FFT magnitude spectrum (grayscale FFT → log-scale → 3-channel)
- **Val AUC:** 0.8222

#### Image Ensemble Strategy
Grid search + Nelder-Mead optimization finds weights on validation set. Default: EfficientNet 50%, ViT 45%, FreqCNN 5% (FreqCNN bounded to 2–20% due to lower AUC). `ensemble_config.json` from Notebook 5 overrides defaults.

### 3.2 Video Pipeline (FaceForensics++ — 657,567 frames, 13,509 videos)

#### Model 1: Spatial CNN (EfficientNet-B2)
- **Purpose:** Per-frame texture artifacts — blending seams, colour mismatch
- **Architecture:** EffNet-B2 backbone, head: `AdaptiveAvgPool → Flatten → Dropout(0.4) → Linear(1408,256) → GELU → Dropout(0.3) → Linear(256,1)`
- **Training:** FaceForensics++ data with heavy compression augmentation (JPEG q=10-60)
- **Test AUC:** 0.9394

#### Model 2: Temporal Transformer
- **Purpose:** Inter-frame consistency — detects blinking anomalies, head-pose jitter, expression timing
- **Architecture:** Shared EfficientNet-B2 frame encoder → Linear(1408,512)+LayerNorm → CLS token → Learnable positional encoding (17×512) → 4-layer Transformer (8 heads, FF=2048, pre-norm) → head on CLS output
- **Key design choice:** Replaced BiLSTM (AUC=0.69, class collapse) with Transformer + Focal Loss → no gradient vanishing across 16 frames
- **Training:** Phase 1 (frozen backbone, 3 epochs) + Phase 2 (full fine-tune, 17 epochs), Focal Loss α=0.75 γ=2.0

#### Model 3: Frequency SRM CNN
- **Purpose:** GAN noise residuals in video frames — periodic upsampling artifacts survive JPEG compression
- **Architecture:** Fixed non-trainable SRM layer (3×3 high-pass kernels, groups=3) → Conv2d(9→3,1×1)+BN+ReLU → EfficientNet-B4 backbone → head
- **Key design choice:** Replaced FFT/DCT (AUC=0.47, learned backwards on JPEG quantization pattern) with SRM spatial residuals that survive compression
- **SRM kernels:** Laplacian/4, 2nd-order/4, 3rd-order/4 — all sum to zero (high-pass property)

---

## 4. Confidence Enhancement Algorithm

### 4.1 Motivation

Standard weighted averaging dilutes high-confidence individual predictions. If ViT detects 97% fake probability but EfficientNet shows only 80%, equal weighting produces ~88% — less than ViT alone. The client requirement was that the ensemble should *exceed* the most confident individual model.

### 4.2 Three-Stage Pipeline

**Stage 1 — Dominant Model Boost**
```python
if max_model_prob >= 0.95:
    dominant_weight = 0.80    # 80% to dominant, 10% each to others
elif max_model_prob >= 0.80:
    dominant_weight = 0.70    # 70% to dominant, 15% each to others
else:
    pass  # use original AUC-proportional weights
```

**Stage 2 — Uncertain-Zone Correction**
Applied only when the raw weighted average falls between 0.32 and 0.68 (the uncertain zone). In this zone:
- Image pipeline: boosts the FAKE-voting model by 0.22 when EfficientNet and ViT disagree
- Video pipeline: prioritizes Temporal Transformer in uncertain zone (inter-frame context)

**Stage 3 — Temperature Scaling**
```python
def sharpen_confidence(p, T=1.35):
    logit = log(p / (1-p))
    return 1 / (1 + exp(-logit * T))
```
Effect: 84%→90%, 77%→84%, 92%→96%, 97%→99%

### 4.3 Results

| Scenario | Without Enhancement | With Enhancement |
|---|---|---|
| ViT=97%, Eff=80%, Freq=50% | ~88% | ~99% |
| All models at 85% | ~85% | ~91% |
| Mixed signals (0.60 zone) | ~60% | ~65% |
| All models at 10% (real) | ~10% | ~7% |

---

## 5. Key Implementation Decisions

### 5.1 Face Detection Gate
**Decision:** Run face detection before any model inference.
**Reason:** Models give meaningless confidence scores on non-face images. Gate saves ~95% of compute for invalid inputs and gives users clear error feedback instead of a confusing high-confidence wrong answer.
**Implementation:** DNN (ResNet SSD) → Haar Cascade → dlib cascade. DNN tier uses OpenCV's built-in ResNet face detector which handles varied lighting and partial occlusion better than Haar.

### 5.2 FreqCNN FFT Preprocessing
**Decision:** Use grayscale FFT with log-scaling normalized at mean=0.5 std=0.5, not per-channel FFT with ImageNet normalization.
**Reason:** Matches training code exactly (`bgr_to_fft()` in test notebook). Previous implementation used per-channel FFT with ImageNet normalization — this caused ~10% accuracy degradation at inference even though training was correct.

### 5.3 FreqCNN Checkpoint Key Remapping
**Decision:** Apply `remap_freqcnn_keys()` on every checkpoint load.
**Reason:** Model was saved with `stage1/branch1/shortcut` naming but the inference definition uses `s1/b1/skip`. Without remapping, all FreqCNN weights load silently into wrong layers (PyTorch `strict=False` doesn't catch name mismatches, only shape mismatches).

### 5.4 Video Ensemble vs Image Ensemble
**Decision:** Temporal model gets priority boost in uncertain zone (video pipeline), EfficientNet vs ViT disagreement handled in image pipeline.
**Reason:** Temporal model has inter-frame context that single-frame models cannot access. When spatial and temporal models disagree in the uncertain zone, the temporal model is more likely to be correct for video-specific deepfake types (blinking, jitter, expression timing).

### 5.5 Redis as Optional Dependency
**Decision:** API degrades gracefully when Redis is unavailable.
**Reason:** During development and testing, requiring Redis creates friction. When Redis is down, caching is disabled, async jobs fall back to in-memory store, rate limiting falls back to in-memory counter. API continues to function correctly.

---

## 6. Phase Completion Summary

### Phase 1 — Core API
- FastAPI application, 4 endpoints (/health, /analyze/image, /analyze/image-url, /analyze/video)
- Both model ensembles with checkpoint loading and FreqCNN key remapping
- Face detection preprocessing gate (DNN + Haar + dlib cascade)
- Quality gate (blur, resolution, visibility)
- Docker + Redis setup

### Phase 2 — Async, Batch, Explain
- Async video jobs with Redis/memory job store and 5-state progress tracking
- Batch image analysis (up to 10 concurrent)
- GradCAM heatmap for EfficientNet-B4 spatial explanation
- Per-second video timeline for partial manipulation detection
- Feedback collection endpoint

### Phase 3 — Metrics, Rate Limiting, Persistence
- SQLite feedback store (persistent across restarts)
- Scan logging for metrics aggregation
- /metrics JSON endpoint (scan counts, cache rates, verdict distribution)
- /metrics/prometheus endpoint for Grafana integration
- Redis sliding window rate limiter with in-memory fallback
- Confidence enhancement algorithm (dominant model boost + temperature scaling)

---

## 7. Test Coverage

### Automated Test Suite
| Test File | Tests | What is Covered |
|---|---|---|
| `test_health.py` | 10 | Health schema, status values, root endpoint |
| `test_image_analysis.py` | 25 | Schema, verdict accuracy, edge cases, confidence enhancement |
| `test_video_analysis.py` | 18 | Video schema, face gate, async jobs, timeline |
| `test_quality_gate.py` | 12 | Face detection (mocked), blur, resolution, status |
| `test_schemas_preprocessing.py` | 21 | Pydantic models, FFT spectrum, SRM kernels, normalization |
| `test_phase2.py` | 22 | Batch, async, GradCAM, timeline, feedback, cache |
| **Total** | **108** | Full API surface coverage |

### Run automated tests
```bash
# All unit tests (no .pth files needed)
pytest tests/ -m "not integration" -v

# Integration tests (requires .pth checkpoints)
pytest tests/ -m integration -v
```

---

## 8. Docker Deployment

```yaml
# docker-compose.yml structure
services:
  redis:        # Redis 7 Alpine for caching + job store + rate limiting
  deepfake-api: # FastAPI on port 8004, depends on redis
volumes:
  redis_data:   # Persistent Redis storage
```

```bash
# Build and start
docker-compose up --build

# Start in background
docker-compose up -d

# View logs
docker-compose logs -f deepfake-api

# Stop
docker-compose down

# Rebuild after code change
docker-compose up --build --force-recreate

# Run tests inside container
docker-compose exec deepfake-api pytest tests/ -m "not integration" -v
```

---

## 9. Performance Characteristics

| Operation | Typical Time | Notes |
|---|---|---|
| Cache hit | < 50ms | Same image analyzed previously |
| Image analysis (CPU) | 1,500–5,000ms | All 3 models on CPU |
| Image analysis (GPU) | 200–800ms | All 3 models on CUDA |
| Video async submit | < 200ms | Returns job_id immediately |
| Video analysis (30s clip) | 45–90s | Dominated by frame extraction + 3 models |
| Quality gate | < 50ms | Face detection + blur check |
| GradCAM generation | +500–1,500ms | Additional backward pass on EfficientNet |

---

## 10. API Key Innovation Points

1. **Multi-tier confidence enhancement** — ensemble that exceeds individual model confidence
2. **Face detection preprocessing gate** — domain-specific input validation before expensive inference
3. **Dual ensemble architecture** — separate optimized pipelines for images vs videos
4. **FreqCNN FFT preprocessing matching training** — prevents the common inference-training mismatch
5. **Graceful Redis degradation** — production system continues working when cache is unavailable
6. **Explainable output** — GradCAM heatmaps, per-model scores, and human-readable flags
7. **Pakistan-specific integration** — designed to integrate with Aegis WhatsApp bot for Pakistani users
