'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const path = require('node:path');
const { validateProductionConfig, useSecureCookies } = require('../lib/utils/runtimeSecurity');

const production = () => ({ NODE_ENV: 'production', SESSION_SECRET: 'a'.repeat(64),
  PGPASSWORD: 'b'.repeat(32), ADMIN_PASSWORD: 'c'.repeat(32), HTTPS: 'true' });

test('production rejects missing, short and example secrets without exposing their values', () => {
  for (const name of ['SESSION_SECRET', 'PGPASSWORD', 'ADMIN_PASSWORD']) {
    for (const value of [undefined, '', 'admin', 'osa', 'password123', 'replace-with-a-random-64-character-secret']) {
      const env = { ...production(), [name]: value };
      assert.throws(() => validateProductionConfig(env), error => error.message.includes(name)
        && !error.message.includes('replace-with-a-random-64-character-secret'));
    }
  }
});

test('production requires TLS and cannot disable secure cookies', () => {
  assert.doesNotThrow(() => validateProductionConfig(production()));
  for (const HTTPS of [undefined, '', 'false']) {
    assert.throws(() => validateProductionConfig({ ...production(), HTTPS }), /HTTPS=true/);
  }
  assert.throws(() => validateProductionConfig({ ...production(), SESSION_COOKIE_SECURE: 'false' }), /SESSION_COOKIE_SECURE/);
  assert.equal(useSecureCookies(production()), true);
});

test('production bootstrap rejects bcrypt-truncated administrator passwords', () => {
  assert.throws(() => validateProductionConfig({ ...production(), ADMIN_PASSWORD: '🦊'.repeat(19) }), /72 UTF-8 bytes/);
  assert.doesNotThrow(() => validateProductionConfig({ ...production(), ADMIN_PASSWORD: 'a'.repeat(72) }));
});

test('local development can still start without production credentials or TLS', () => {
  assert.doesNotThrow(() => validateProductionConfig({ NODE_ENV: 'development' }));
  assert.equal(useSecureCookies({ NODE_ENV: 'development' }), false);
  assert.equal(useSecureCookies({ NODE_ENV: 'development', SESSION_COOKIE_SECURE: 'true' }), true);
});

test('the actual production entry point fails before attempting database initialization', () => {
  const result = spawnSync(process.execPath, [path.join(__dirname, '../server.js')], {
    env: { ...process.env, ...production(), SESSION_SECRET: '', PGHOST: '127.0.0.1', PGPORT: '1' },
    encoding: 'utf8', timeout: 10000,
  });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /SESSION_SECRET/);
  assert.doesNotMatch(result.stdout + result.stderr, /migration_failed|ECONNREFUSED/);
});
