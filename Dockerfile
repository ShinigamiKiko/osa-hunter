# ── Stage 1: deps ─────────────────────────────────────────────
FROM node:22-slim AS deps
WORKDIR /app
COPY backend/package.json backend/package-lock.json ./
ENV PUPPETEER_SKIP_DOWNLOAD=1
RUN npm ci --omit=dev --ignore-scripts

# ── Stage 2: runtime ──────────────────────────────────────────
FROM node:22-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl tar ca-certificates chromium chromium-sandbox php-cli php-mbstring php-zip unzip git fonts-liberation fonts-noto \
    python3 python3-pip \
    && rm -rf /var/lib/apt/lists/* \
    && pip3 install semgrep --break-system-packages --quiet





ARG TRIVY_VERSION=0.69.3
ARG TRIVY_SHA256=1816b632dfe529869c740c0913e36bd1629cb7688bd5634f4a858c1d57c88b75
RUN curl -fSL --retry 3 "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" -o /tmp/trivy.tar.gz \
    && echo "${TRIVY_SHA256}  /tmp/trivy.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy \
    && rm /tmp/trivy.tar.gz && trivy --version

ARG GRYPE_VERSION=0.88.0
ARG GRYPE_SHA256=7a7e1bf0caf88350eeb7433f41ce6e7b69d1eed57ce67abf24eae62562f38948
RUN curl -fSL --retry 3 "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_amd64.tar.gz" -o /tmp/grype.tar.gz \
    && echo "${GRYPE_SHA256}  /tmp/grype.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/grype.tar.gz -C /usr/local/bin grype \
    && rm /tmp/grype.tar.gz && grype version

# Install a pinned Composer PHAR only after checking its official release digest.
ARG COMPOSER_VERSION=2.10.3
ARG COMPOSER_SHA256=7a2d379d5b8ffdaa028580ef26494c36d2feef4b178d3dd1473a4dbc5e17c8d6
RUN curl -fSL --retry 3 "https://getcomposer.org/download/${COMPOSER_VERSION}/composer.phar" -o /usr/local/bin/composer \
    && echo "${COMPOSER_SHA256}  /usr/local/bin/composer" | sha256sum -c - \
    && chmod +x /usr/local/bin/composer && composer --version


RUN groupadd -r appuser && useradd -r -g appuser -d /app appuser
WORKDIR /app

COPY --from=deps /app/node_modules ./node_modules
COPY backend/server.js .
COPY backend/lib ./lib
COPY backend/migrations ./migrations
COPY policy.yaml ./policy.yaml
COPY frontend/public/assets/osa.png ./frontend/public/assets/osa.png

ENV PUPPETEER_SKIP_DOWNLOAD=1
ENV PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium
ENV NODE_ENV=production
ENV PORT=3001
ENV TRIVY_CACHE_DIR=/app/.trivy-cache

RUN chown -R appuser:appuser /app && mkdir -p /app/.trivy-cache && chown -R appuser:appuser /app/.trivy-cache
USER appuser
EXPOSE 3001 9100
STOPSIGNAL SIGTERM
CMD ["node", "server.js"]
