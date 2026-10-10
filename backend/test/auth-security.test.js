'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const bcrypt = require('bcryptjs');
let accounts, queries;
const dbPath = require.resolve('../lib/auth/db');
require.cache[dbPath] = { id: dbPath, filename: dbPath, loaded: true, exports: { getPool: () => ({
  query: async (sql, args = []) => {
    queries.push({ sql, args });
    if (/JOIN users/.test(sql)) return { rows: [{ id: 42, user_id: 1, username: 'admin', role: 'admin' }] };
    if (/SELECT.*FROM users WHERE id/.test(sql)) return { rows: accounts.has(args[0]) ? [accounts.get(args[0])] : [] };
    if (/UPDATE users SET password/.test(sql)) {
      const user = accounts.get(args[1]);
      if (!user) return { rows: [], rowCount: 0 };
      user.password = args[0]; user.session_version++;
      return { rows: [{ ...user }], rowCount: 1 };
    }
    if (/DELETE FROM users/.test(sql)) return { rowCount: Number(accounts.delete(args[0])) };
    if (/INSERT INTO gate_policy/.test(sql)) return { rows: [{ body: JSON.parse(args[1]), updated_by: args[2] }] };
    return { rows: [], rowCount: 1 };
  },
}) } };
const { requireAuth } = require('../lib/auth/middleware');
const auth = require('../lib/auth/routes');
const policy = require('../lib/routes/policy.route');
const createRouter = require('../lib/utils/router');
const { configureTrustedProxy } = require('../lib/utils/trustedProxy');

test.beforeEach(() => {
  accounts = new Map([1,2].map(id => [id, { id, username: id === 1 ? 'admin' : 'reader',
    role: id === 1 ? 'admin' : 'user', session_version: 1, password: bcrypt.hashSync('old-password', 4) }]));
  queries = [];
});
async function withApp(app, fn) {
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  try { await fn(`http://127.0.0.1:${server.address().port}`); }
  finally { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
}
function app() {
  const app = express(); app.use(express.json());
  app.use((req, res, next) => {
    const [id, version, role] = (req.get('test-session') || '').split(':');
    req.session = { regenerate: cb => cb(), destroy: cb => cb() };
    if (id) req.session.user = { id: Number(id), sessionVersion: Number(version), role: role || 'admin' };
    next();
  });
  app.use('/api', requireAuth, auth, policy);
  app.get('/api/private', (req, res) => res.json({ user: req.user }));
  return app;
}
const json = (body, headers = {}) => ({ method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(body) });

test('policy writes require a current administrator; admin API keys also reach user management', async () => {
  await withApp(app(), async base => {
    const body = { body: { rules: [], defaults: { decision: 'deny' } } };
    const options = { ...json(body, { 'test-session': '2:1:admin' }), method: 'PUT' };
    assert.equal((await fetch(base + '/api/policy', options)).status, 403);
    const key = { 'x-api-key': 'osa_test' };
    const saved = await fetch(base + '/api/policy', { ...json(body, key), method: 'PUT' });
    assert.equal(saved.status, 200); assert.equal((await saved.json()).updated_by, 'admin');
    assert.equal((await fetch(base + '/api/auth/users', { headers: key })).status, 200);
    assert.equal((await fetch(base + '/api/policy', { ...options, headers: { ...options.headers, 'test-session': '1:1:admin' } })).status, 200);
  });
});

test('deleted, old-version and unversioned sessions fail on APIs and nginx auth endpoint', async () => {
  accounts.delete(2);
  await withApp(app(), async base => {
    for (const session of ['2:1:user', '1:0:admin', '1::admin']) {
      for (const path of ['/api/private', '/api/auth/me']) {
        assert.equal((await fetch(base + path, { headers: { 'test-session': session } })).status, 401);
      }
    }
    const response = await fetch(base + '/api/auth/me', { headers: { 'test-session': '1:1:admin' } });
    assert.equal(response.status, 200); assert.equal((await response.json()).user.username, 'admin');
  });
});

test('browser Accept headers never redirect API auth checks, including revoked sessions', async () => {
  await withApp(app(), async base => {
    const accept = 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8';
    for (const session of ['', '1:0:admin']) {
      for (const path of ['/api/auth/me', '/api/private']) {
        const response = await fetch(base + path, {
          headers: { Accept: accept, 'test-session': session }, redirect: 'manual',
        });
        assert.equal(response.status, 401);
        assert.equal(response.headers.get('location'), null);
        assert.deepEqual(await response.json(), { error: 'Unauthorized' });
      }
    }
    const response = await fetch(base + '/api/auth/me', {
      headers: { Accept: accept, 'test-session': '1:1:admin' }, redirect: 'manual',
    });
    assert.equal(response.status, 200);
    assert.equal((await response.json()).user.username, 'admin');
  });
});

test('administrator password reset and deletion revoke existing sessions', async () => {
  await withApp(app(), async base => {
    const response = await fetch(base + '/api/auth/users/2/password', {
      ...json({ password: 'reset-password' }, { 'x-api-key': 'osa_test' }), method: 'PATCH' });
    assert.equal(response.status, 200);
    assert.equal((await fetch(base + '/api/auth/me', { headers: { 'test-session': '2:1:user' } })).status, 401);
    assert.equal((await fetch(base + '/api/auth/me', { headers: { 'test-session': '2:2:user' } })).status, 200);
    assert.equal((await fetch(base + '/api/auth/users/2', { method: 'DELETE', headers: { 'x-api-key': 'osa_test' } })).status, 200);
    assert.equal((await fetch(base + '/api/auth/me', { headers: { 'test-session': '2:2:user' } })).status, 401);
  });
});

test('optional wrong JSON types return 400 promptly on actual scan routes', async () => {
  const instance = express(); instance.use(express.json());
  for (const file of ['library-scan', 'dependency-scan', 'composer-scan', 'activity', 'grype']) instance.use('/api', require(`../lib/routes/${file}.route`));
  instance.use('/api', require('../lib/auth/api-key-routes'));
  await withApp(instance, async base => {
    for (const [path, body] of [
      ['/libscan', { name: 'pkg', ecosystem: 'npm', version: 123 }],
      ['/depscan', { name: 'pkg', system: 'NPM', version: {} }],
      ['/composerscan', { name: 'vendor/pkg', version: [] }],
      ['/activity', { name: 'pkg', ecosystem: false }],
      ['/osscan', { name: 'pkg', distro: 123, version: '1' }],
      ['/auth/api-keys', { name: {} }],
    ]) assert.equal((await fetch(base + '/api' + path, { ...json(body), signal: AbortSignal.timeout(2000) })).status, 400, path);
  });
});

test('async route failures reach the Express error handler', async () => {
  const instance = express(), router = createRouter();
  router.get('/fail', async () => { throw new Error('later failure'); });
  instance.use(router); instance.use((err, req, res, next) => res.status(502).json({ error: err.message }));
  await withApp(instance, async base => {
    const response = await fetch(base + '/fail', { signal: AbortSignal.timeout(2000) });
    assert.equal(response.status, 502); assert.equal((await response.json()).error, 'later failure');
  });
});

test('forwarded addresses are accepted only from a configured immediate proxy', async () => {
  for (const [addresses, hosts, expected] of [['', '', '127.0.0.1'], ['127.0.0.1', '', '203.0.113.8'], ['', 'frontend', '203.0.113.8']]) {
    const instance = express();
    instance.use(configureTrustedProxy(instance, { addresses, hosts, lookup: async () => [{ address: '127.0.0.1' }] }));
    instance.get('/', (req, res) => res.json({ ip: req.ip, protocol: req.protocol }));
    await withApp(instance, async base => {
      const response = await fetch(base, { headers: { 'X-Forwarded-For': '198.51.100.1, 203.0.113.8', 'X-Forwarded-Proto': 'https' } });
      const data = await response.json(); assert.equal(data.ip, expected);
      assert.equal(data.protocol, addresses || hosts ? 'https' : 'http');
    });
  }
});

test('logging a completed proxy response tolerates a disconnected socket with no peer address', async () => {
  const { logRequest } = require('../lib/observability/logger');
  const instance = express();
  instance.use(configureTrustedProxy(instance, { addresses: '127.0.0.1', hosts: '' }));
  let loggingError, logged = false;
  instance.get('/', (req, res) => {
    res.once('finish', () => {
      // Socket.remoteAddress can disappear after nginx closes its auth subrequest.
      Object.defineProperty(req.socket, 'remoteAddress', { value: undefined, configurable: true });
      try { logRequest(req, 200, 1); logged = true; } catch (error) { loggingError = error; }
    });
    res.json({ ok: true });
  });
  await withApp(instance, async base => {
    const response = await fetch(base, { headers: { 'X-Forwarded-For': '203.0.113.8', Connection: 'close' } });
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { ok: true });
  });
  assert.equal(loggingError, undefined);
  assert.equal(logged, true);
});
