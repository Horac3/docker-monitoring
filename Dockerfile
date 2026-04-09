FROM python:3.12-slim

LABEL maintainer="you@example.com"
LABEL description="Docker container memory monitor with email alerts"

WORKDIR /app

# System deps (none heavy — just pip packages)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY monitor.py .

# Log directory
RUN mkdir -p /var/log/docker-monitor

CMD ["python", "-u", "monitor.py"]