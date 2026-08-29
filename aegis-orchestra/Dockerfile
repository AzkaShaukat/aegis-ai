# ============================================================
# Aegis AI — Orchestra Service Only (port 8006)
# All other services (8000-8004) run SEPARATELY on the host
# ============================================================
FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app/ ./app/
COPY .env.host ./.env

# Expose only orchestra port
EXPOSE 8006

# Start orchestra bot
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8006"]
