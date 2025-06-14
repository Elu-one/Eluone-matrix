# ELULMC Sovereign AGI Secure Container
FROM python:3.11-slim-bullseye

# Security: Create non-root user
RUN groupadd -r elulmc && useradd -r -g elulmc -s /bin/false elulmc

# Security: Update system packages
RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    git \
    libssl-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Security: Remove unnecessary files
RUN find . -name "*.pyc" -delete && \
    find . -name "__pycache__" -type d -exec rm -rf {} + || true && \
    rm -rf .git .github tests docs

# Security: Set proper permissions
RUN chown -R elulmc:elulmc /app && \
    chmod -R 755 /app && \
    chmod +x deployment/enclave_server/secure_inference_server.py

# Security: Switch to non-root user
USER elulmc

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Expose port
EXPOSE 8080

# Environment variables
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1
ENV FLASK_ENV=production

# Default command
CMD ["python", "deployment/enclave_server/secure_inference_server.py", "--config", "deployment/config/inference_config.json"]