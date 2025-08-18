# Optional Docker image for running the Web Recon Visualizer
# Note: This image does not install Amass/Sublist3r by default. You can extend it if desired.

FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# Install system whois client (useful for some TLDs)
RUN apt-get update && apt-get install -y --no-install-recommends \
    whois \
    && rm -rf /var/lib/apt/lists/*

# Install tools needed for Amass
RUN apt-get update && apt-get install -y --no-install-recommends curl unzip ca-certificates nmap && rm -rf /var/lib/apt/lists/*

# Install Amass in the image via official release (Linux amd64 example)
ARG AMASS_VERSION=v3.25.1
RUN curl -fsSL -o /tmp/amass.zip https://github.com/owasp-amass/amass/releases/download/${AMASS_VERSION}/amass_Linux_amd64.zip \
    && unzip -q /tmp/amass.zip -d /opt/amass \
    && install -m 0755 /opt/amass/*/amass /usr/local/bin/amass \
    && rm -rf /tmp/amass.zip /opt/amass

# Ensure Sublist3r CLI via pip remains available


WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY frontend ./frontend

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
