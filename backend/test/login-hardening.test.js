'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const bcrypt = require('bcryptjs');
const accounts = new Map();
let comparisons, queries, rotations;
const realCompare = bcrypt.compare;
bcrypt.compare = async (password, hash) => {
  comparisons.push({ password, hash });
  return password === 'correct-password' || password === 'dummy-matches';
};
const dbPath = require.resolve('../lib/auth/db');
require.cache[dbPath] = { id: dbPath, filename: dbPath, loaded: true, exports: {
  getPool: () => ({ query: async (sql, args) => {
    queries.push(args[0]);
    return { rows: accounts.has(args[0]) ? [accounts.get(args[0])] : [] };
  } }),
} };
test.after(() => { bcrypt.compare = realCompare; });

async function withLogin(fn) {
  comparisons = []; queries = []; rotations = 0;
  accounts.clear();
  accounts.set('reader', { id: 1, username: 'reader', role: 'user', session_version: 3,
    password: bcrypt.hashSync('correct-password', 12) });
  delete require.cache[require.resolve('../lib/auth/routes')];
  const app = express(); app.use(express.json());
  app.use((req, res, next) => {
    Object.defineProperty(req, 'ip', { value: req.get('test-ip') || '203.0.113.1' });
    req.session = { regenerate: cb => { rotations++; cb(); }, save: cb => cb() };
    next();
  });
  app.use(require('../lib/auth/routes'));
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  const login = (username, password = 'wrong', ip = '203.0.113.1') => fetch(
    `http://127.0.0.1:${server.address().port}/auth/login`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'test-ip': ip },
      body: JSON.stringify({ username, password }),
    });
  try { await fn(login); }
  finally { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
}

test('unknown accounts compare a cost-12 hash and cannot authenticate when dummy comparison succeeds', () => withLogin(async login => {
  assert.equal((await login('missing', 'dummy-matches')).status, 401);
  assert.equal(comparisons.length, 1);
  assert.equal(bcrypt.getRounds(comparisons[0].hash), 12);
  assert.equal(rotations, 0);
  const response = await login('reader', 'correct-password');
  assert.equal(response.status, 200);
  assert.equal((await response.json()).user.sessionVersion, 3);
  assert.equal(rotations, 1);
}));

test('account limits span peer addresses and whitespace aliases without merging case-sensitive accounts', () => withLogin(async login => {
  for (let i = 0; i < 10; i++) assert.equal((await login(i % 2 ? ' missing ' : 'missing', 'wrong', `203.0.113.${i + 1}`)).status, 401);
  assert.equal((await login('missing', 'wrong', '203.0.113.100')).status, 429);
  assert.equal(queries.length, 10);
  assert.equal(comparisons.length, 10);
  assert.equal((await login('Missing', 'wrong', '203.0.113.101')).status, 401);
  assert.equal((await login('reader', 'correct-password', '203.0.113.102')).status, 200);
}));

test('IP limits still stop password spraying across distinct accounts', () => withLogin(async login => {
  for (let i = 0; i < 10; i++) assert.equal((await login(`spray-${i}`)).status, 401);
  assert.equal((await login('another-name')).status, 429);
  assert.equal(comparisons.length, 10);
}));

test('account limiter keys obey the database character limit while accepting existing Unicode usernames', () => withLogin(async login => {
  assert.equal((await login('x'.repeat(65))).status, 400);
  assert.equal(comparisons.length, 0);
  const username = '🦊'.repeat(64);
  accounts.set(username, { ...accounts.get('reader'), username });
  assert.equal((await login(username, 'correct-password')).status, 200);
  assert.equal(queries.at(-1), username);
}));
