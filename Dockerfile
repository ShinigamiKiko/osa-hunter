# ── Stage 1: deps ─────────────────────────────────────────────
FROM node:22-slim AS deps
WORKDIR /app
COPY backend/package.json backend/package-lock.json ./
ENV PUPPETEER_SKIP_DOWNLOAD=1
# Optional build-only CA bundle for environments with a corporate HTTPS proxy.
RUN --mount=type=secret,id=build_ca \
    if [ -s /run/secrets/build_ca ]; then export NODE_EXTRA_CA_CERTS=/run/secrets/build_ca; fi; \
    npm ci --omit=dev --ignore-scripts

# Assemble the application in the small dependency stage before copying it once.
FROM deps AS application
COPY backend ./
COPY policy.yaml ./policy.yaml
COPY frontend/public/assets/osa.png ./frontend/public/assets/osa.png
RUN mkdir -p /app/.trivy-cache

# ── Stage 2: runtime ──────────────────────────────────────────
FROM node:22-slim
ARG SEMGREP_VERSION=1.180.0
ARG TRIVY_VERSION=0.69.3
ARG TRIVY_SHA256=1816b632dfe529869c740c0913e36bd1629cb7688bd5634f4a858c1d57c88b75
ARG GRYPE_VERSION=0.120.1
ARG GRYPE_SHA256=0a9ee97ef5ae2ee953b0a80098105052e846cdbe319a57d808b519c33cd1343d
ARG COMPOSER_VERSION=2.10.3
ARG COMPOSER_SHA256=7a2d379d5b8ffdaa028580ef26494c36d2feef4b178d3dd1473a4dbc5e17c8d6

# One tools layer avoids duplicating large intermediate filesystems on vfs.
# Downloaded release archives retain checksum validation.
RUN --mount=type=secret,id=build_ca \
    set -eu; \
    if [ -s /run/secrets/build_ca ]; then \
      export PIP_CERT=/run/secrets/build_ca CURL_CA_BUNDLE=/run/secrets/build_ca; \
    fi; \
    apt-get update && apt-get install -y --no-install-recommends \
      curl tar ca-certificates chromium chromium-sandbox php-cli php-mbstring php-zip unzip git fonts-liberation fonts-noto \
      python3 python3-pip \
    && rm -rf /var/lib/apt/lists/* \
    && pip3 install "semgrep==${SEMGREP_VERSION}" --break-system-packages --no-cache-dir --quiet \
    && curl -fSL --retry 3 "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" -o /tmp/trivy.tar.gz \
    && echo "${TRIVY_SHA256}  /tmp/trivy.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy \
    && rm /tmp/trivy.tar.gz && trivy --version \
    && curl -fSL --retry 3 "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_amd64.tar.gz" -o /tmp/grype.tar.gz \
    && echo "${GRYPE_SHA256}  /tmp/grype.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/grype.tar.gz -C /usr/local/bin grype \
    && rm /tmp/grype.tar.gz && grype version \
    && curl -fSL --retry 3 "https://getcomposer.org/download/${COMPOSER_VERSION}/composer.phar" -o /usr/local/bin/composer \
    && echo "${COMPOSER_SHA256}  /usr/local/bin/composer" | sha256sum -c - \
    && chmod +x /usr/local/bin/composer && composer --version \
    && groupadd -r appuser && useradd -r -g appuser -d /app appuser \
    && mkdir -p /app && chown appuser:appuser /app
WORKDIR /app

COPY --from=application --chown=appuser:appuser /app ./

ENV PUPPETEER_SKIP_DOWNLOAD=1
ENV PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium
ENV NODE_ENV=production
ENV PORT=3001
ENV TRIVY_CACHE_DIR=/app/.trivy-cache

USER appuser
EXPOSE 3001 9100
STOPSIGNAL SIGTERM
CMD ["node", "server.js"]
