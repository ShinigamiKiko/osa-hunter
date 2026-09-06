'use strict';

const client = require('prom-client');

const register = new client.Registry();
client.collectDefaultMetrics({ register, prefix: 'osa_' });

const requests = new client.Counter({
  name: 'osa_http_requests_total',
  help: 'Total HTTP requests handled by the backend.',
  labelNames: ['method', 'route', 'status_code'],
  registers: [register],
});

const duration = new client.Histogram({
  name: 'osa_http_request_duration_seconds',
  help: 'HTTP request duration in seconds.',
  labelNames: ['method', 'route', 'status_code'],
  buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30],
  registers: [register],
});

const inFlight = new client.Gauge({
  name: 'osa_http_requests_in_flight',
  help: 'HTTP requests currently being processed.',
  registers: [register],
});

const cacheOperations = new client.Counter({
  name: 'osa_cache_operations_total',
  help: 'Cache hits and misses.',
  labelNames: ['cache', 'result'],
  registers: [register],
});

const externalErrors = new client.Counter({
  name: 'osa_external_api_errors_total',
  help: 'Errors returned by external services.',
  labelNames: ['service'],
  registers: [register],
});

function observeCache(cache, result) { cacheOperations.inc({ cache, result }); }
function observeExternalError(service) { externalErrors.inc({ service }); }

function routeName(req) {
  const route = req.route?.path;
  if (route) return `${req.baseUrl || ''}${route}`;
  return 'unmatched';
}

function observeRequest(req, res, startedAt) {
  const labels = {
    method: req.method,
    route: routeName(req),
    status_code: String(res.statusCode),
  };
  requests.inc(labels);
  duration.observe(labels, (Date.now() - startedAt) / 1000);
  inFlight.dec();
}

function requestMetrics(req, res, next) {
  const startedAt = Date.now();
  inFlight.inc();
  let observed = false;
  const observe = () => {
    if (observed) return;
    observed = true;
    observeRequest(req, res, startedAt);
  };
  res.on('finish', observe);
  res.on('close', observe);
  next();
}

async function metricsHandler(req, res) {
  res.set('Content-Type', register.contentType);
  return res.end(await register.metrics());
}

module.exports = { metricsHandler, observeCache, observeExternalError, requestMetrics, register };
