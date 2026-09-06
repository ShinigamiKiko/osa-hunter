'use strict';

function envInt(name, fallback, min = 1) {
  const value = parseInt(process.env[name] || '', 10);
  return Number.isFinite(value) && value >= min ? value : fallback;
}

module.exports = {
  HTTP_CONCURRENCY: envInt('HTTP_CONCURRENCY', 10),
  HTTP_TIMEOUT_MS: envInt('HTTP_TIMEOUT_MS', 12000),
  GRYPE_CONCURRENCY: envInt('GRYPE_CONCURRENCY', 1),
  GRYPE_QUEUE_SIZE: envInt('GRYPE_QUEUE_SIZE', 4, 0),
  TRIVY_CONCURRENCY: envInt('TRIVY_CONCURRENCY', 1),
  TRIVY_QUEUE_SIZE: envInt('TRIVY_QUEUE_SIZE', 4, 0),
};
