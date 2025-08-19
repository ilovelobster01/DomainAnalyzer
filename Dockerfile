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
RUN apt-get update && apt-get install -y --no-install-recommends curl unzip ca-certificates nmap proxychains4 && rm -rf /var/lib/apt/lists/*

# Configure proxychains to use tor service on docker network by default
RUN printf "strict_chain\nquiet_mode\ndns_proxy\nremote_dns_subnet 224\n[ProxyList]\nsocks5 tor 9050\n" > /etc/proxychains.conf

# Install Amass in the image via official release (detect arch)
ARG AMASS_VERSION=v4.1.0
ARG TARGETARCH
RUN set -eux; \
    arch="${TARGETARCH:-$(dpkg --print-architecture)}"; \
    case "$arch" in \
      amd64|x86_64) AMASS_ARCH=amd64 ;; \
      arm64|aarch64) AMASS_ARCH=arm64 ;; \
      *) AMASS_ARCH=amd64 ;; \
    esac; \
    for OSNAME in Linux linux; do \
      URL="https://github.com/owasp-amass/amass/releases/download/${AMASS_VERSION}/amass_${OSNAME}_${AMASS_ARCH}.zip"; \
      echo "Attempting $URL"; \
      if curl -fsSL -o /tmp/amass.zip "$URL"; then break; fi; \
    done; \
    test -s /tmp/amass.zip; \
    unzip -q /tmp/amass.zip -d /opt/amass; \
    install -m 0755 /opt/amass/*/amass /usr/local/bin/amass; \
    rm -rf /tmp/amass.zip /opt/amass

# Ensure Sublist3r CLI via pip remains available


WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY frontend ./frontend

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
