# Aegis AI Deepfake API — All Commands

## Setup (Windows PowerShell)

```powershell
cd "D:\Aegis AI\deepfake-api"

# Install Python dependencies
python -m pip install -r requirements.txt

# Copy config (edit .env to set model paths)
cp .env.example .env
```

## Run Without Docker

```powershell
# Start API (auto-reloads on file changes)
python -m uvicorn app.main:app --port 8004 --reload

# Start without auto-reload (faster startup)
python -m uvicorn app.main:app --port 8004
```

## Run With Docker

```bash
# Start everything (Redis + API)
docker-compose up --build

# Start in background
docker-compose up -d --build

# Stop
docker-compose down

# Stop and remove volumes (full reset)
docker-compose down -v

# Rebuild after code changes
docker-compose up --build --force-recreate

# View live logs
docker-compose logs -f deepfake-api

# View Redis logs
docker-compose logs -f redis

# Shell into running container
docker-compose exec deepfake-api bash
```

## Testing

```powershell
# All unit tests (no models needed, ~30 seconds)
python -m pytest tests\ -m "not integration" -v

# Unit tests, skip video tests
python -m pytest tests\ -m "not integration" -v -k "not video"

# Specific test file
python -m pytest tests\test_image_analysis.py -v
python -m pytest tests\test_phase2.py -v
python -m pytest tests\test_quality_gate.py -v

# Run with coverage report
pip install pytest-cov
python -m pytest tests\ -m "not integration" --cov=app --cov-report=term-missing

# Integration tests (requires .pth files in app/models/)
python -m pytest tests\ -m integration -v

# Run tests inside Docker container
docker-compose exec deepfake-api python -m pytest tests/ -m "not integration" -v
```

## Generate Synthetic Test Assets

```bash
# Create test images and videos for manual testing
python scripts/generate_synthetic_assets.py
# Output: tests/assets/*.jpg and tests/assets/*.mp4
```

## Manual Testing (curl)

```powershell
# Health check
curl http://localhost:8004/health

# Analyze image
curl -X POST http://localhost:8004/analyze/image -F "file=@face.jpg"

# Analyze image from URL (real face)
curl -X POST http://localhost:8004/analyze/image-url `
  -H "Content-Type: application/json" `
  -d '{"url":"https://upload.wikimedia.org/wikipedia/commons/8/8d/President_Barack_Obama.jpg"}'

# Analyze image from URL (GAN face - refresh URL for new face)
curl -X POST http://localhost:8004/analyze/image-url `
  -H "Content-Type: application/json" `
  -d '{"url":"https://thispersondoesnotexist.com/"}'

# Batch (up to 10 images)
curl -X POST http://localhost:8004/analyze/batch `
  -F "files=@face1.jpg" -F "files=@face2.jpg"

# GradCAM heatmap
curl -X POST http://localhost:8004/analyze/image/explain -F "file=@face.jpg" -o result.json

# Video (synchronous - blocks until done)
curl -X POST http://localhost:8004/analyze/video -F "file=@video.mp4"

# Video async - submit
curl -X POST http://localhost:8004/analyze/video-async -F "file=@video.mp4"

# Video async - poll (replace JOB_ID)
curl http://localhost:8004/analyze/status/JOB_ID

# Video timeline
curl -X POST http://localhost:8004/analyze/video/timeline -F "file=@video.mp4"

# Metrics
curl http://localhost:8004/metrics
curl http://localhost:8004/metrics/prometheus

# Cache
curl http://localhost:8004/cache/stats
curl -X DELETE http://localhost:8004/cache/purge

# Feedback
curl -X POST http://localhost:8004/feedback `
  -H "Content-Type: application/json" `
  -d '{"scan_id":"img-abc","original_verdict":"REAL","corrected_verdict":"fake"}'

curl http://localhost:8004/feedback/stats
```

## Open Interactive Docs

```
http://localhost:8004/docs
```
Click any endpoint → "Try it out" → upload files or fill JSON → "Execute"

## Model Files Location

Place your trained .pth files in `app/models/`:

```
app/models/
├── efficientnet_best.pth    ← from NB2 (Doc 1)
├── vit_best.pth             ← from NB3 (Doc 1)
├── freqcnn_best.pth         ← from NB4 (Doc 1)
├── ensemble_config.json     ← from NB5 (Doc 1) [optional]
├── spatial_best.pth         ← from NB2 (Doc 2)
├── temporal_best.pth        ← from NB3 (Doc 2)
└── freq_srm_best.pth        ← from NB4 (Doc 2)
```
