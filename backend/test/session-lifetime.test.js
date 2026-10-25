'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');

const dbPath = require.resolve('../lib/auth/db');
require.cache[dbPath] = { id: dbPath, filename: dbPath, loaded: true, exports: { getPool: () => ({
  query: async () => ({ rows: [{ id: 1, username: 'admin', role: 'admin', session_version: 1 }] }),
}) } };
const { IDLE_MS, MAX_MS, startSession, sessionExpired, noteActivity } = require('../lib/auth/sessionPolicy');
const { requireAuth } = require('../lib/auth/middleware');

const HOUR = 3_600_000;

test('defaults: 30 minutes idle, 12 hours after sign-in', () => {
  assert.equal(IDLE_MS, 30 * 60_000);
  assert.equal(MAX_MS, 12 * HOUR);
});

test('a session expires when idle, when too old, or when it predates the timestamps', () => {
  const start = Date.UTC(2026, 9, 25, 8);
  const session = {};
  startSession(session, start);
  assert.equal(sessionExpired(session, start + IDLE_MS - 1), false);
  assert.equal(sessionExpired(session, start + IDLE_MS), true, 'idle limit');
  assert.equal(sessionExpired({}, start), true, 'sessions from before this change sign in again');
  assert.equal(sessionExpired({ authenticatedAt: start }, start), true);
});

test('activity extends the idle window but never the absolute limit', () => {
  const start = Date.UTC(2026, 9, 25, 8);
  const session = {};
  startSession(session, start);
  // A user active every 10 minutes for a whole day.
  let now = start;
  while (now < start + MAX_MS - 10 * 60_000) {
    now += 10 * 60_000;
    assert.equal(sessionExpired(session, now), false, `active at +${(now - start) / 60_000} min`);
    noteActivity(session, now);
  }
  assert.equal(sessionExpired(session, start + MAX_MS), true, 'still capped at the absolute limit');
});

test('activity is recorded at most once a minute', () => {
  const session = {};
  startSession(session, 0);
  noteActivity(session, 30_000);
  assert.equal(session.lastSeenAt, 0);
  noteActivity(session, 60_000);
  assert.equal(session.lastSeenAt, 60_000);
});

async function call(session) {
  const app = express();
  let destroyed = 0;
  app.use((req, res, next) => { req.session = session && { ...session, destroy: cb => { destroyed++; cb(); } }; next(); });
  app.use('/api', requireAuth);
  app.get('/api/private', (req, res) => res.json({ user: req.user.username, lastSeenAt: req.session.lastSeenAt }));
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  try {
    const response = await fetch(`http://127.0.0.1:${server.address().port}/api/private`);
    return { status: response.status, body: await response.json(), destroyed };
  } finally { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
}

test('requireAuth rejects and destroys an expired session, and keeps a live one', async () => {
  const user = { id: 1, sessionVersion: 1 };
  const now = Date.now();
  const live = await call({ user, authenticatedAt: now - HOUR, lastSeenAt: now - 5 * 60_000 });
  assert.equal(live.status, 200);
  assert.ok(live.body.lastSeenAt >= now, 'activity recorded');

  for (const session of [
    { user, authenticatedAt: now - HOUR, lastSeenAt: now - IDLE_MS - 1 },   // idle
    { user, authenticatedAt: now - MAX_MS - 1, lastSeenAt: now },           // too old
    { user },                                                               // legacy
  ]) {
    const expired = await call(session);
    assert.equal(expired.status, 401);
    assert.deepEqual(expired.body, { error: 'Session expired' });
    assert.equal(expired.destroyed, 1, 'removed from the store');
  }
});
