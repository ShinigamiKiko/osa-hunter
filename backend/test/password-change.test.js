'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const bcrypt = require('bcryptjs');

// POST /auth/password decides who may change a credential, so its rules are
// pinned here: the session identifies the account, the current password proves
// it is really them, and a wrong guess is rate limited like a login is.
//
// The route reaches the database through lib/auth/db, which is replaced in the
// require cache before the router is loaded.
const dbPath = require.resolve('../lib/auth/db');
const stored = { id: 7, password: bcrypt.hashSync('old-password', 4) };
const queries = [];

require.cache[dbPath] = {
  id: dbPath,
  filename: dbPath,
  loaded: true,
  exports: {
    getPool: () => ({
      query: async (sql, args) => {
        queries.push({ sql, args });
        if (/SELECT password FROM users/i.test(sql)) {
          return args[0] === stored.id ? { rows: [{ password: stored.password }] } : { rows: [] };
        }
        if (/UPDATE users SET password/i.test(sql)) {
          stored.password = args[0];
          return { rowCount: 1 };
        }
        return { rows: [], rowCount: 0 };
      },
    }),
  },
};

const authRoutes = require('../lib/auth/routes');

function server({ user = { id: 7, username: 'dev', role: 'user' } } = {}) {
  const app = express();
  app.use(express.json());
  app.use((req, res, next) => {
    // Minimal stand-in for express-session.
    req.session = user ? { user, regenerate: cb => cb(null) } : { regenerate: cb => cb(null) };
    next();
  });
  app.use('/api', authRoutes);
  const listener = app.listen(0);
  return listener;
}

async function change(listener, body) {
  const r = await fetch(`http://127.0.0.1:${listener.address().port}/api/auth/password`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  return { status: r.status, body: await r.json().catch(() => ({})) };
}

async function withServer(opts, fn) {
  const listener = server(opts);
  await new Promise(resolve => listener.once('listening', resolve));
  try { await fn(listener); } finally {
    await new Promise(resolve => listener.close(resolve));
  }
}

test('a signed-in user can change their own password', async () => {
  await withServer({}, async (s) => {
    const r = await change(s, { currentPassword: 'old-password', newPassword: 'a-new-password' });
    assert.equal(r.status, 200);
    assert.ok(await bcrypt.compare('a-new-password', stored.password), 'the new password is stored');
    assert.ok(!await bcrypt.compare('old-password', stored.password), 'the old one no longer works');
    // Restore for the tests that follow.
    stored.password = bcrypt.hashSync('old-password', 4);
  });
});

test('the stored password is hashed, never the plain text', async () => {
  await withServer({}, async (s) => {
    await change(s, { currentPassword: 'old-password', newPassword: 'another-password' });
    assert.ok(!stored.password.includes('another-password'));
    assert.match(stored.password, /^\$2[aby]\$/, 'bcrypt hash');
    stored.password = bcrypt.hashSync('old-password', 4);
  });
});

test('a wrong current password changes nothing', async () => {
  await withServer({}, async (s) => {
    const before = stored.password;
    const r = await change(s, { currentPassword: 'not-it', newPassword: 'a-new-password' });
    assert.equal(r.status, 403);
    assert.match(r.body.error, /current password/i);
    assert.equal(stored.password, before);
  });
});

test('without a session there is nobody to change the password of', async () => {
  await withServer({ user: null }, async (s) => {
    const before = stored.password;
    const r = await change(s, { currentPassword: 'old-password', newPassword: 'a-new-password' });
    assert.equal(r.status, 401);
    assert.equal(stored.password, before);
  });
});

test('a form mistake does not eat the rate-limit budget', async () => {
  // Regression: the limiter counted every request, so three typos in the new
  // password locked the user out without anyone guessing anything.
  await withServer({}, async (s) => {
    for (let i = 0; i < 10; i++) {
      const r = await change(s, { currentPassword: 'old-password', newPassword: 'short' });
      assert.equal(r.status, 400, 'still a validation error, not a lockout');
    }
    const ok = await change(s, { currentPassword: 'old-password', newPassword: 'a-new-password' });
    assert.equal(ok.status, 200, 'and the real change still goes through');
    stored.password = bcrypt.hashSync('old-password', 4);
  });
});

test('weak or unchanged passwords are refused', async () => {
  await withServer({}, async (s) => {
    const before = stored.password;
    for (const [body, expected] of [
      [{ currentPassword: 'old-password', newPassword: 'short' }, /8 characters/],
      [{ currentPassword: 'old-password', newPassword: 'old-password' }, /differ/],
      [{ currentPassword: 'old-password' }, /required/],
      [{ newPassword: 'a-new-password' }, /required/],
    ]) {
      const r = await change(s, body);
      assert.equal(r.status, 400, JSON.stringify(body));
      assert.match(r.body.error, expected);
    }
    assert.equal(stored.password, before, 'nothing was written');
  });
});

test('repeated wrong guesses are rate limited, like the login form', async () => {
  await withServer({}, async (s) => {
    let sawLimit = false;
    for (let i = 0; i < 12; i++) {
      const r = await change(s, { currentPassword: 'wrong', newPassword: 'a-new-password' });
      if (r.status === 429) { sawLimit = true; break; }
    }
    assert.ok(sawLimit, 'guessing the current password must not be unlimited');
  });
});
