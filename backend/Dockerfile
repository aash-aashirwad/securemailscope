FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN mkdir -p uploads

EXPOSE 8000
# Render (and similar PaaS) inject a $PORT env var and require the
# container to bind to it; docker-compose doesn't set $PORT, so the
# ${PORT:-8000} default keeps `docker compose up` working unchanged.
# Shell form (not exec-form JSON array) is required for that ${PORT:-8000}
# expansion to actually happen.
CMD uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}
