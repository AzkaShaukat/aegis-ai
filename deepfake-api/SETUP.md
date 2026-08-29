# Aegis AI Deepfake Detection API — Setup Guide

## Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Python | 3.11 | Required. 3.12 works but some timm versions differ |
| Docker Desktop | 4.x | For containerized deployment |
| NVIDIA GPU | Optional | 10–15× faster inference |

---

## Option A: Docker (Recommended for Production)

### Step 1 — Copy project files
Extract the zip. Your folder structure should be:
```
D:\Aegis AI\deepfake-api\
  app/
    models/
      efficientnet_best.pth      ← from NB2 (image)
      vit_best.pth               ← from NB3 (image)
      freqcnn_best.pth           ← from NB4 (image)
      ensemble_config.json       ← from NB5 (image) [optional]
      spatial_best.pth           ← from NB2 (video)
      temporal_best.pth          ← from NB3 (video)
      freq_srm_best.pth          ← from NB4 (video)
      ensemble_video_config.json ← from NB5 (video) [optional]
  docker-compose.yml
  .env.example
```

### Step 2 — Configure environment
```bash
cp .env.example .env
```
Edit `.env` if needed (defaults work out of the box).

### Step 3 — Start services
```bash
docker-compose up --build
```

### Step 4 — Verify startup
```bash
docker-compose logs deepfake-api | grep "Application startup"
# Expected: INFO: Application startup complete.
```

### Step 5 — Health check
```bash
curl http://localhost:8004/health
# Expected: {"status": "healthy", ...}
```

### Common Docker Issues

| Error | Fix |
|---|---|
| `port 6379 already allocated` | `docker stop $(docker ps -q --filter "publish=6379")` then retry |
| `network aegis_network incorrect label` | `docker network rm aegis_network` then retry |
| `IMAGENET_MEAN not found` | Add `IMAGENET_MEAN: list = [0.485, 0.456, 0.406]` to config.py Settings |
| `RATE_LIMIT_ENABLED not found` | Add `RATE_LIMIT_ENABLED: bool = True` to config.py Settings |

---

## Option B: Direct Python (Development)

### Step 1 — Install Python 3.11 packages
```powershell
# Windows — always use explicit python path to avoid version conflicts
C:\Users\<user>\AppData\Local\Programs\Python\Python311\python.exe -m pip install -r requirements.txt
```

### Step 2 — Configure
```powershell
cp .env.example .env
```

### Step 3 — Start API
```powershell
C:\Users\<user>\AppData\Local\Programs\Python\Python311\python.exe -m uvicorn app.main:app --port 8004 --reload
```

---

## Running Tests

### Unit Tests (no model files needed, ~30s)
```bash
# All unit tests
pytest tests/ -m "not integration" -v

# Specific test file
pytest tests/test_ensemble_rules.py -v
pytest tests/test_face_detection.py -v

# With coverage
pip install pytest-cov
pytest tests/ -m "not integration" --cov=app --cov-report=term-missing
```

### Integration Tests (requires .pth files in app/models/)
```bash
pytest tests/ -m integration -v
```

### Inside Docker container
```bash
docker-compose exec deepfake-api pytest tests/ -m "not integration" -v
```

---

## Manual API Testing

### Open Swagger UI
```
http://localhost:8004/docs
```
Every endpoint is interactive — click, upload file, execute.

### Key test commands (PowerShell)
```powershell
# Health
curl http://localhost:8004/health

# Real face (should score LOW, ≤ 35)
curl -X POST http://localhost:8004/analyze/image-url `
  -H "Content-Type: application/json" `
  -d '{"url":"https://upload.wikimedia.org/wikipedia/commons/8/8d/President_Barack_Obama.jpg"}'

# GAN face (should score HIGH, ≥ 56)
curl -X POST http://localhost:8004/analyze/image-url `
  -H "Content-Type: application/json" `
  -d '{"url":"https://thispersondoesnotexist.com/"}'

# Upload image
curl -X POST http://localhost:8004/analyze/image -F "file=@face.jpg"

# Upload video (async — recommended for videos)
$R = curl -s -X POST http://localhost:8004/analyze/video-async -F "file=@video.mp4" | ConvertFrom-Json
$JOB = $R.job_id

# Poll until complete
do { Start-Sleep 2; $S = (curl -s "http://localhost:8004/analyze/status/$JOB" | ConvertFrom-Json).status; Write-Host $S } while ($S -notin @("complete","failed"))
curl "http://localhost:8004/analyze/status/$JOB"

# Metrics
curl http://localhost:8004/metrics
```
