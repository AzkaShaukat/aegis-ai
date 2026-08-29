#!/bin/bash
# run_on_host.sh — Run Orchestra directly on Linux/Mac (no Docker)
echo ""
echo "🛡️  Aegis Orchestra — Running on Host (no Docker)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Stop Docker container if running
docker stop aegis-orchestra-dev 2>/dev/null

# Install deps
pip install -r requirements.txt --quiet

# Set localhost URLs
export LINK_ANALYZER_URL=http://localhost:8000
export QR_SCANNER_URL=http://localhost:8001
export CREDENTIAL_ANALYZER_URL=http://localhost:8002
export PROFILE_ANALYZER_URL=http://localhost:8003
export REDIS_URL=redis://localhost:6379/2
export CELERY_BROKER_URL=redis://localhost:6379/3
export CELERY_RESULT_BACKEND=redis://localhost:6379/3
export OLLAMA_HOST=http://localhost:11434
export OLLAMA_MODEL=llama3.2:latest
export OLLAMA_ENABLED=true
export TESTING=true
export LOG_LEVEL=DEBUG
export ORCHESTRA_PORT=8006

echo "✅ Using localhost URLs"
echo ""
echo "Starting orchestra on port 8006..."
uvicorn app.main:app --host 0.0.0.0 --port 8006 --reload --log-level info
