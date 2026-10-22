FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PG_DB=/data/phishing.db \
    PG_BENCH_DATA=/data/benchmark-data \
    PG_BENCH_RUNS=/data/benchmark-runs

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn==22.0.0

COPY . .
RUN useradd --create-home --uid 10001 app && mkdir -p /data && chown -R app /data
USER app
VOLUME /data
EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s   CMD python -c "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/api/health' % os.environ.get('PORT', '5000'), timeout=3)"

# One worker: benchmark jobs and the Tranco refresh keep state in memory. Threads give concurrency.
# PORT is set by hosts such as Render; 5000 otherwise (docker compose).
CMD gunicorn --bind 0.0.0.0:${PORT:-5000} --workers 1 --threads 8 --timeout 120 app:app
