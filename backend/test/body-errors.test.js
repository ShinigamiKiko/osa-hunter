'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const { jsonBodyErrors } = require('../lib/utils/bodyErrors');

// A client sending a bad body must be told so. Without this handler
// express.json() throws and the generic handler answers 500 with a stack trace
// in the log, which reads like the server crashed.
function withServer(fn) {
  return async () => {
    const app = express();
    app.use(express.json({ limit: '100b' }));
    app.use(jsonBodyErrors);
    app.post('/echo', (req, res) => res.json({ got: req.body }));
    // Stands in for server.js's catch-all: anything reaching it is a 500.
    app.use((err, req, res, _next) => res.status(500).json({ error: 'Internal server error' }));

    const server = app.listen(0);
    await new Promise(resolve => server.once('listening', resolve));
    const base = `http://127.0.0.1:${server.address().port}`;
    try {
      await fn(async (body, headers = {}) => {
        const r = await fetch(`${base}/echo`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', ...headers },
          body,
        });
        return { status: r.status, body: await r.json().catch(() => null) };
      });
    } finally {
      await new Promise(resolve => server.close(resolve));
    }
  };
}

test('malformed JSON is a client error, not a server crash', withServer(async (post) => {
  // This is the shape PowerShell produced: quotes mangled into a broken object.
  const r = await post('{`"username`":`"admin`"}');
  assert.equal(r.status, 400);
  assert.match(r.body.error, /not valid JSON/i);
}));

test('an oversized body is rejected as too large', withServer(async (post) => {
  const r = await post(JSON.stringify({ pad: 'x'.repeat(500) }));
  assert.equal(r.status, 413);
  assert.match(r.body.error, /too large/i);
}));

test('a valid body still reaches the route untouched', withServer(async (post) => {
  const r = await post(JSON.stringify({ username: 'admin' }));
  assert.equal(r.status, 200);
  assert.deepEqual(r.body.got, { username: 'admin' });
}));

test('errors that are not body-parser errors still fall through to the 500 handler', () => {
  // The handler must not swallow real failures on their way to the catch-all.
  let passed = null;
  const next = e => { passed = e; };
  const boom = new Error('database is on fire');
  jsonBodyErrors(boom, {}, { headersSent: false }, next);
  assert.equal(passed, boom);
});
