FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    libglib2.0-0 libsm6 libxext6 libxrender-dev libgl1 curl \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN mkdir -p /app/data
EXPOSE 8004
# --workers 4      = 4 parallel processes, so one long video scan doesn't block others
# --timeout-keep-alive 600  = keep connection alive 10 min (prevents Failed to fetch on large uploads)
CMD ["uvicorn", "app.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8004", \
     "--workers", "4", \
     "--timeout-keep-alive", "600", \
     "--log-level", "info"]
