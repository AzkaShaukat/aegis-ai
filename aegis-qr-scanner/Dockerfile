# Use python 3.9 slim (lightweight)
FROM python:3.9-slim

WORKDIR /code

# 1. Install System Dependencies
# libgl1-mesa-glx is REPLACED by libgl1
RUN apt-get update && apt-get install -y \
    libzbar0 \
    libgl1 \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

# 2. Install Python Dependencies
COPY ./requirements.txt /code/requirements.txt
RUN pip install --no-cache-dir --upgrade -r /code/requirements.txt

# 3. Copy Application Code
COPY ./app /code/app

# 4. Run on Port 8001
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8001"]