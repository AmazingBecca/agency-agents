FROM python:3.11-slim

WORKDIR /orchestrator

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    git \
    libpoppler-cpp-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip install --no-cache-dir \
    Flask==2.3.0 \
    flask-cors==4.0.0 \
    requests==2.31.0 \
    watchdog==3.0.0 \
    google-auth==2.25.0 \
    google-auth-oauthlib==1.2.0 \
    google-auth-httplib2==0.2.0 \
    google-api-python-client==2.100.0 \
    python-dotenv==1.0.0 \
    pydantic==2.5.0 \
    pdf2image==1.16.0 \
    pillow==10.0.0 \
    python-magic==0.4.27

# Copy orchestrator script
COPY orchestrator.py /orchestrator/orchestrator.py

# Create log directory
RUN mkdir -p /tmp && chmod 777 /tmp

# Expose port
EXPOSE 5000

# Environment variables
ENV FLASK_ENV=production
ENV LISTEN_PORT=5000
ENV PYTHONUNBUFFERED=1

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

# Run orchestrator
CMD ["python", "orchestrator.py"]
