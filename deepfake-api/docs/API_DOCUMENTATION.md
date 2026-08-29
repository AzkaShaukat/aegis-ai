# Aegis AI — Deepfake Detection API
## Complete API Reference & User Guide
### Version 3.0.0 | Port 8004 | Lahore Garrison University FYP 2025-2026

---

## Table of Contents
1. [What Is This API?](#1-what-is-this-api)
2. [Quick Start](#2-quick-start)
3. [How It Works](#3-how-it-works)
4. [All Endpoints Reference](#4-all-endpoints-reference)
5. [Request & Response Fields](#5-request--response-fields)
6. [Risk Levels Explained](#6-risk-levels-explained)
7. [Source Hints](#7-source-hints)
8. [Test URLs — Real vs Fake](#8-test-urls)
9. [Manual Testing Guide](#9-manual-testing-guide)
10. [Error Reference](#10-error-reference)
11. [Known Limitations](#11-known-limitations)

---

## 1. What Is This API?

Aegis AI Deepfake Detection is a self-hosted REST API that detects whether an image or video contains a deepfake (AI-generated or face-manipulated content). It uses an ensemble of three independent deep learning models with a face-detection preprocessing gate.

**Two detection pipelines:**

| Pipeline | Input | Models | Trained On | AUC |
|---|---|---|---|---|
| Image | JPEG / PNG / WebP / BMP | EfficientNet-B4 + ViT-B/16 + FrequencyCNN | 140k GAN faces (StyleGAN2/3, ProGAN) | ~0.97 |
| Video | MP4 / AVI / MOV | Spatial CNN + Temporal Transformer + SRM CNN | FaceForensics++ 657k frames | 0.93+ |

**What makes it different:**
- Face detection gate — no face = no analysis (saves compute, clear error)
- Confidence enhancement — when one model hits 95%+, ensemble EXCEEDS it after boosting
- Per-second video timeline — detect where in a video the deepfake appears
- GradCAM heatmaps — visual explanation of which facial region triggered the alert
- Redis caching — same image never analyzed twice
- Async video jobs — submit and poll; no HTTP timeouts

---

## 2. Quick Start

### Option A: Direct Python (no Docker)

```powershell
# Windows PowerShell
cd "D:\Aegis AI\deepfake-api"
cp .env.example .env
python -m pip install -r requirements.txt
python -m uvicorn app.main:app --port 8004 --reload
```

```bash
# Linux / macOS
cd deepfake-api
cp .env.example .env
pip install -r requirements.txt
uvicorn app.main:app --port 8004 --reload
```

### Option B: Docker (recommended for production)

```bash
docker-compose up --build
```

### Verify it works

```bash
curl http://localhost:8004/health
# Expected: {"status": "healthy" ...}
```

### Open interactive docs

Navigate to: **http://localhost:8004/docs**

Every endpoint is clickable and testable from the browser.

---

## 3. How It Works

### Face Detection Preprocessing Gate

Every request — image or video — goes through face detection first. If no face is found, the request is rejected immediately with a helpful error message. This gate has three tiers:

1. **OpenCV DNN** (ResNet SSD) — highest accuracy, works on varied inputs
2. **Haar Cascade** — fast fallback for photorealistic images
3. **dlib** — final fallback (if dlib is installed)

### Image Analysis Pipeline

```
Input image
  → Face detection gate (reject if no face)
  → Quality gate (size ≥ 80px, blur score ≥ 20, visibility ≥ 70%)
  → Crop & resize to 224×224
  → Three models in parallel:
      Model 1: EfficientNet-B4 → spatial texture artifacts
      Model 2: ViT-B/16 → global structural consistency
      Model 3: FrequencyCNN → GAN noise residuals (FFT spectrum)
  → Confidence enhancement:
      If any model ≥ 95%: give it 80% weight
      If any model ≥ 80%: give it 70% weight
  → Temperature scaling (T=1.35): pushes scores away from 50%
  → Return risk score, verdict, flags, per-model breakdown
```

### Video Analysis Pipeline

```
Input video
  → Extract frames at 3fps
  → Face detection on each frame (gate: ≥1 frame must have a face)
  → Quality gate on first detected face
  → Preprocess: spatial (224×224 per frame) + temporal (16-frame sequences at 112×112)
  → Three models:
      Model 1: Spatial CNN → per-frame texture artifacts
      Model 2: Temporal Transformer → inter-frame blinking/jitter/flickering
      Model 3: Frequency SRM CNN → noise residual patterns
  → Video confidence enhancement (temporal model priority in uncertain zone)
  → Temperature scaling
  → Optional: per-second timeline
  → Return verdict
```

### Confidence Enhancement

When one model is very confident, we want the ensemble to reflect that — not dilute it:

| Scenario | Before enhancement | After enhancement |
|---|---|---|
| ViT = 97%, others lower | ~88% | **~99%** |
| EfficientNet = 91%, others at ~70% | ~82% | **~91%+** |
| All models at 85% | ~85% | **~91%** |
| All models at 60% (uncertain) | ~60% | ~65% |

---

## 4. All Endpoints Reference

### System

| Method | Endpoint | Auth Required | Description |
|---|---|---|---|
| GET | `/` | No | Service info and version |
| GET | `/health` | No | Model status, GPU, Redis |
| GET | `/metrics` | No | Scan counts, cache rates, verdict distribution |
| GET | `/metrics/prometheus` | No | Prometheus format for Grafana |

### Phase 1 — Core Analysis

| Method | Endpoint | Rate Limit | Description |
|---|---|---|---|
| POST | `/analyze/image` | 30/min | Single image deepfake analysis |
| POST | `/analyze/image-url` | 20/min | Analyze image from URL |
| POST | `/analyze/video` | 5/min | Synchronous video (blocks until done) |

### Phase 2 — Advanced

| Method | Endpoint | Rate Limit | Description |
|---|---|---|---|
| POST | `/analyze/video-async` | 10/min | Submit video, returns job_id instantly |
| GET | `/analyze/status/{job_id}` | — | Poll async job result |
| POST | `/analyze/batch` | 10/min | Up to 10 images concurrently |
| POST | `/analyze/image/explain` | 10/min | Image + GradCAM heatmap |
| POST | `/analyze/video/timeline` | 5/min | Video + per-second p_fake |
| POST | `/feedback` | — | Submit real/fake correction |
| GET | `/feedback/stats` | — | Feedback collection stats |
| GET | `/cache/stats` | — | Redis cache info |
| DELETE | `/cache/purge` | — | GDPR flush all cached data |

---

## 5. Request & Response Fields

### Request: POST /analyze/image

```
Method: POST
Content-Type: multipart/form-data
URL: http://localhost:8004/analyze/image

Fields:
  file       (required) Image file — JPEG, PNG, WebP, or BMP
  
Headers (optional):
  X-Source-Hint    whatsapp | telegram | download | original
  X-API-Key        Your API key (if API_KEY is set in .env)
```

### Request: POST /analyze/image-url

```json
{
  "url": "https://example.com/face.jpg",
  "source_hint": "whatsapp"
}
```

### Request: POST /analyze/batch

```
Method: POST
Content-Type: multipart/form-data
Fields: files[] (up to 10 files)
```

### Response: DeepfakeAnalysisResult (all analysis endpoints)

| Field | Type | Description |
|---|---|---|
| `scan_id` | string | Unique ID — use for feedback submission |
| `scan_date` | string | Date of analysis (YYYY-MM-DD) |
| `pipeline_used` | string | `"image_ensemble"` or `"video_ensemble"` |
| `overall_risk_score` | integer | 0–100 — derived from ensemble_probability × 100 |
| `overall_risk_level` | string | Clean / Low Risk / Medium Risk / High Risk / Critical |
| `ensemble_probability` | float | Raw P(fake) from 0.0 to 1.0 |
| `verdict` | string | REAL / LIKELY_REAL / UNCERTAIN / LIKELY_FAKE / FAKE / UNAVAILABLE |
| `message` | string | Human-readable verdict with emoji |
| `confidence_note` | string | Detailed breakdown of which models contributed |
| `per_model_scores` | object | Individual P(fake) for each of the three models |
| `ensemble_weights` | object | Weights used for each model and their source |
| `model_agreement` | string | `"high"` / `"medium"` / `"low"` |
| `face_info` | object | How many faces detected, primary face size, confidence |
| `input_quality` | object | Status, blur score, resolution, warnings |
| `video_info` | object or null | Duration, frames, sequences (video pipeline only) |
| `timeline` | array or null | Per-second p_fake (only from `/analyze/video/timeline`) |
| `gradcam_heatmap` | string or null | Base64 JPEG heatmap (only from `/analyze/image/explain`) |
| `all_flags` | array | Human-readable signals that raised the score |
| `total_flags` | integer | Count of flags |
| `elapsed_ms` | float | Processing time in milliseconds |
| `cached` | boolean | Whether result was returned from Redis cache |
| `model_version` | string | API version |
| `privacy` | object | Note confirming no media is stored |

### Response: Async Job (GET /analyze/status/{job_id})

| Field | Type | Description |
|---|---|---|
| `job_id` | string | Job identifier |
| `status` | string | queued / preprocessing / extracting_faces / running_models / complete / failed |
| `progress_message` | string | Human-readable current stage |
| `created_at` | float | Unix timestamp when job was submitted |
| `started_at` | float or null | When processing began |
| `completed_at` | float or null | When finished |
| `elapsed_seconds` | float or null | Total processing duration |
| `result` | object or null | Full DeepfakeAnalysisResult when complete |
| `error` | string or null | Error message if failed |

---

## 6. Risk Levels Explained

### Score to level mapping

| Score | Level | Verdict | What it means | What to do |
|---|---|---|---|---|
| 0–15 | **Clean** | REAL | No manipulation signals at all | Accept as authentic |
| 16–35 | **Low Risk** | LIKELY_REAL | Minor anomalies, probably real | Note but generally accept |
| 36–55 | **Medium Risk** | UNCERTAIN | Models disagree, no conclusion | Manual review required |
| 56–75 | **High Risk** | LIKELY_FAKE | Manipulation patterns detected | Treat as likely fake |
| 76–100 | **Critical** | FAKE | High-confidence deepfake detected | Reject / flag immediately |

### Understanding model_agreement

| Value | Spread | What it means |
|---|---|---|
| `"high"` | All models within 0.15 of each other | All three models agree — result is reliable |
| `"medium"` | Spread 0.15–0.25 | Two models broadly agree, one diverges |
| `"low"` | Any two differ > 0.25 | Models strongly disagree — borderline case, less reliable |

**Rule of thumb:** When `model_agreement` is `"low"` and verdict is `UNCERTAIN`, always request human review.

### per_model_scores interpretation

| Model | What it detects |
|---|---|
| EfficientNet-B4 (Model 1) | Skin texture, face boundary blending seams, sharpness inconsistencies, colour mismatch |
| ViT-B/16 (Model 2) | Global facial structure, long-range geometric inconsistencies, overall face coherence |
| FrequencyCNN (Model 3) | GAN upsampling noise, double-compression traces, periodic synthetic noise patterns |

If only Model 3 flags something, it may be frequency artifacts from compression — lower confidence. If all three agree, confidence is highest.

---

## 7. Source Hints

The `X-Source-Hint` header (or `source_hint` JSON field) tells the API where the image came from so it can apply the right preprocessing:

| Value | What happens | When to use |
|---|---|---|
| `whatsapp` | Applies unsharp masking to partially recover detail lost to WhatsApp's JPEG compression | Images received via WhatsApp |
| `telegram` | Same as whatsapp | Images received via Telegram |
| `download` | No preprocessing | Downloaded from social media |
| `original` | No preprocessing (default) | Direct camera photos, uncompressed sources |

**Example with source hint:**
```bash
curl -X POST http://localhost:8004/analyze/image \
  -H "X-Source-Hint: whatsapp" \
  -F "file=@whatsapp_photo.jpg"
```

---

## 8. Test URLs

### For /analyze/image-url — Real faces (expect REAL / Low Risk)

```
https://upload.wikimedia.org/wikipedia/commons/8/8d/President_Barack_Obama.jpg
```

### For /analyze/image-url — GAN-generated faces (expect FAKE / High Risk)

```
https://thispersondoesnotexist.com/
```
Each page refresh generates a new StyleGAN3 face. Your models were trained on StyleGAN2/3 so these should score 70–95% fake.

### Test commands

```bash
# Real face — should score LOW (< 35)
curl -X POST http://localhost:8004/analyze/image-url \
  -H "Content-Type: application/json" \
  -d '{"url": "https://upload.wikimedia.org/wikipedia/commons/8/8d/President_Barack_Obama.jpg"}'

# GAN face — should score HIGH (> 56)
curl -X POST http://localhost:8004/analyze/image-url \
  -H "Content-Type: application/json" \
  -d '{"url": "https://thispersondoesnotexist.com/"}'
```

---

## 9. Manual Testing Guide

### Step 1: Start the API
```powershell
# Windows
cd "D:\Aegis AI\deepfake-api"
python -m uvicorn app.main:app --port 8004 --reload
```

### Step 2: Health check
```powershell
curl http://localhost:8004/health
```
Expected: `"status": "healthy"` and model load status for each of 6 models.

### Step 3: Test image with real photo
```powershell
curl -X POST http://localhost:8004/analyze/image -F "file=@your_photo.jpg"
```
Expected for real photo: `verdict: "REAL"` or `"LIKELY_REAL"`, risk_score < 35.

### Step 4: Test image with GAN face
Download a face from `https://thispersondoesnotexist.com/` and save it.
```powershell
curl -X POST http://localhost:8004/analyze/image -F "file=@stylegan_face.jpg"
```
Expected: `verdict: "FAKE"` or `"LIKELY_FAKE"`, risk_score > 56.

### Step 5: Test batch
```powershell
curl -X POST http://localhost:8004/analyze/batch `
  -F "files=@real_face.jpg" `
  -F "files=@fake_face.jpg"
```

### Step 6: Test GradCAM (visual explanation)
```powershell
curl -X POST http://localhost:8004/analyze/image/explain -F "file=@face.jpg" -o result.json
python -c "
import json, base64, pathlib
data = json.load(open('result.json'))
print('Verdict:', data['verdict'], '| Score:', data['overall_risk_score'])
h = data.get('gradcam_heatmap', '')
if h:
    b64 = h.split(',')[-1]
    pathlib.Path('heatmap.jpg').write_bytes(base64.b64decode(b64))
    print('Heatmap saved to heatmap.jpg')
"
```

### Step 7: Test async video
```powershell
# Submit
$RESPONSE = curl -s -X POST http://localhost:8004/analyze/video-async -F "file=@video.mp4" | ConvertFrom-Json
$JOB_ID = $RESPONSE.job_id
Write-Host "Job ID: $JOB_ID"

# Poll
do {
    Start-Sleep 2
    $STATUS = (curl -s "http://localhost:8004/analyze/status/$JOB_ID" | ConvertFrom-Json).status
    Write-Host "Status: $STATUS"
} while ($STATUS -notin @("complete","failed"))

# View result
curl "http://localhost:8004/analyze/status/$JOB_ID" | python -m json.tool
```

### Step 8: Test video timeline
```powershell
curl -X POST http://localhost:8004/analyze/video/timeline -F "file=@video.mp4" | python -m json.tool
# Look for "timeline" field: [{second: 0, p_fake: 0.12}, ...]
```

### Step 9: Submit feedback
```powershell
curl -X POST http://localhost:8004/feedback `
  -H "Content-Type: application/json" `
  -d '{"scan_id": "img-abc123", "original_verdict": "REAL", "corrected_verdict": "fake", "notes": "This is a StyleGAN face"}'
```

### Step 10: Check metrics
```powershell
curl http://localhost:8004/metrics | python -m json.tool
curl http://localhost:8004/metrics/prometheus
```

---

## 10. Error Reference

| HTTP Status | When it happens | How to fix |
|---|---|---|
| `200 UNAVAILABLE` | No face detected in image/video | Send image with a clearly visible face |
| `400 Bad Request` | Empty file, unreadable bytes, corrupted image | Check file is not empty and is a valid image/video |
| `401 Unauthorized` | Wrong or missing X-API-Key | Add correct key: `-H "X-API-Key: yourkey"` |
| `413 Request Too Large` | Video exceeds 100 MB | Compress video: `ffmpeg -i input.mp4 -crf 28 output.mp4` |
| `415 Unsupported Media` | Wrong file type | Use JPEG/PNG/WebP/BMP for images, MP4/AVI/MOV for video |
| `422 Unprocessable` | Missing required field | Check request format — `file` or `url` field missing |
| `429 Too Many Requests` | Rate limit hit | Wait 60 seconds. Max: 30 images/min, 5 videos/min |
| `500 Internal Error` | Analysis crash | Check server logs. May be a GPU memory issue |
| `503 Service Unavailable` | Models not loaded | Check .env model paths. API may be in stub mode |

---

## 11. Known Limitations

| Limitation | Severity | Notes |
|---|---|---|
| Stable Diffusion / Midjourney blindspot | High | Not in training data. Expected 60–75% accuracy |
| No audio deepfake detection | High | Voice cloning, lip-sync-only fakes not detected |
| Adversarial inputs | High | Determined attacker can craft inputs to evade detection |
| Not legal evidence | High | Probabilistic — not suitable for legal proceedings |
| Low-quality video | Medium | Below 144p equivalent, face crops become unreliable |
| Heavy occlusion | Medium | Sunglasses/masks covering > 40% face reduces accuracy |
| New GAN architectures | Medium | Post-training GAN variants may produce different artifact signatures |
| Short videos | Low | < 2 seconds = < 1 temporal sequence = limited inter-frame analysis |
| Multiple faces | Low | Only the largest face is analyzed — multi-person videos may use wrong face |
