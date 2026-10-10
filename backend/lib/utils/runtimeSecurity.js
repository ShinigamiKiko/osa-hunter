'use strict';

function requireSecret(env, name, minimum) {
  const value = env[name];
  if (typeof value !== 'string' || value.trim().length < minimum
      || /^(?:replace[-_ ]|change[-_ ]?me|password(?:123)?$)/i.test(value)) {
    throw new Error(`${name} must be configured with at least ${minimum} characters in production; example/default values are not accepted`);
  }
  return value;
}

function validateDatabasePassword(env = process.env) {
  return requireSecret(env, 'PGPASSWORD', 16);
}

function validateAdminPassword(env = process.env) {
  const password = requireSecret(env, 'ADMIN_PASSWORD', 12);
  if (Buffer.byteLength(password, 'utf8') > 72) {
    throw new Error('ADMIN_PASSWORD must not exceed 72 UTF-8 bytes');
  }
  return password;
}

function validateProductionConfig(env = process.env) {
  if (env.NODE_ENV !== 'production') return;
  requireSecret(env, 'SESSION_SECRET', 32);
  validateDatabasePassword(env);
  validateAdminPassword(env);
  if (env.HTTPS !== 'true') {
    throw new Error('HTTPS=true is required in production; terminate TLS at the trusted reverse proxy');
  }
  if (env.SESSION_COOKIE_SECURE === 'false') {
    throw new Error('SESSION_COOKIE_SECURE cannot be false in production');
  }
}

function useSecureCookies(env = process.env) {
  return env.NODE_ENV === 'production' || env.SESSION_COOKIE_SECURE === 'true';
}

module.exports = { validateProductionConfig, validateDatabasePassword, validateAdminPassword, useSecureCookies };
