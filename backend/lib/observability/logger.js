'use strict';

const SENSITIVE_HEADERS = new Set(['authorization', 'cookie', 'set-cookie', 'x-api-key']);

function write(level, message, fields = {}) {
  const entry = {
    timestamp: new Date().toISOString(),
    level,
    service: 'osa-hunter-backend',
    message,
    ...fields,
  };
  const stream = level === 'error' || level === 'warn' ? process.stderr : process.stdout;
  stream.write(`${JSON.stringify(entry)}\n`);
}

function installConsoleLogger() {
  for (const level of ['log', 'warn', 'error']) {
    console[level] = (...args) => {
      const error = args.find(value => value instanceof Error);
      const message = args
        .filter(value => !(value instanceof Error))
        .map(value => typeof value === 'string' ? value : JSON.stringify(value))
        .join(' ');
      write(level === 'log' ? 'info' : level, message || 'log_message', error ? {
        error: error.message,
        stack: error.stack,
      } : {});
    };
  }
}

function requestFields(req) {
  return {
    requestId: req.requestId,
    method: req.method,
    path: req.originalUrl?.split('?')[0],
    remoteAddress: req.ip || req.socket?.remoteAddress,
  };
}

function logRequest(req, statusCode, durationMs) {
  write(statusCode >= 500 ? 'error' : statusCode >= 400 ? 'warn' : 'info', 'http_request', {
    ...requestFields(req),
    statusCode,
    durationMs: Number(durationMs.toFixed(2)),
  });
}

function logError(message, error, fields = {}) {
  write('error', message, {
    ...fields,
    error: error?.message || String(error),
    stack: error?.stack,
  });
}

function redactHeaders(headers) {
  return Object.fromEntries(Object.entries(headers || {}).map(([name, value]) => [
    name,
    SENSITIVE_HEADERS.has(name.toLowerCase()) ? '[REDACTED]' : value,
  ]));
}

module.exports = { installConsoleLogger, logError, logRequest, redactHeaders, write };
