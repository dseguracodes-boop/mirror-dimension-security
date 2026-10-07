FROM python:3.12-slim

WORKDIR /app

# Install system dependencies (openssl for TLS certs)
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssl \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml .
COPY . .

# Install dependencies and package in editable mode
RUN pip install --no-cache-dir -e .

# Expose default shield proxy port
EXPOSE 8080 8443

# Environment defaults
ENV PYTHONUNBUFFERED=1
ENV ESPEJO_STORAGE_PATH=/app/evidence_vault/mirror_shield.db

ENTRYPOINT ["espejo"]
CMD ["proxy", "api", "--port", "8080", "--host", "0.0.0.0"]
