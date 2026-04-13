FROM python:3.10-slim AS builder

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ---------------------------------------------------------------------------
# Production image – only compiled artefacts and installed packages
# ---------------------------------------------------------------------------
FROM python:3.10-slim

# Security: run as non-root
RUN groupadd -r appgroup && useradd -r -g appgroup appuser

WORKDIR /app

# Copy only installed packages from builder
COPY --from=builder /install /usr/local

COPY src/ ./src/

ENV PYTHONPATH=/app/src
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Health check – calls the in-process HTTP health server
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/healthz')" || exit 1

USER appuser

EXPOSE 8080

CMD ["python", "src/main.py"]