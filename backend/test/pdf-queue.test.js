'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
process.env.PDF_CONCURRENCY = '1';
process.env.PDF_QUEUE_SIZE = '2';
let active = 0, maximum = 0, launches = 0, failLaunch = false, unlock, held = false;
const puppeteerPath = require.resolve('puppeteer');
require.cache[puppeteerPath] = { id: puppeteerPath, filename: puppeteerPath, loaded: true, exports: {
  launch: async () => {
    launches++;
    if (failLaunch) throw new Error('launch failed');
    active++; maximum = Math.max(maximum, active);
    if (held) await new Promise(resolve => { unlock = resolve; });
    return {
      newPage: async () => ({ setJavaScriptEnabled: async () => {}, setRequestInterception: async () => {}, on() {},
        setDefaultNavigationTimeout() {}, setDefaultTimeout() {}, setContent: async () => {}, pdf: async () => Buffer.from('%PDF-1.4') }),
      close: async () => { active--; },
    };
  },
} };
const route = require('../lib/routes/export.route');
const payload = { type: 'sast', params: { scanData: { repo: 'fixture', complete: true, findings: [], counts: {} } } };
async function withServer(fn) {
  const app = express(); app.use(express.json()); app.use('/api', route);
  const server = app.listen(0, '127.0.0.1'); await new Promise(resolve => server.once('listening', resolve));
  const post = () => fetch(`http://127.0.0.1:${server.address().port}/api/export/pdf`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload),
  });
  try { await fn(post); }
  finally { held = false; unlock?.(); server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
}

test('PDF exports bound Chromium concurrency and reject a full queue with a retry hint', async () => {
  active = 0; maximum = 0; launches = 0; held = true;
  await withServer(async post => {
    const requests = Array.from({ length: 4 }, () => post());
    const rejected = await Promise.race(requests);
    assert.equal(rejected.status, 503); assert.equal(rejected.headers.get('retry-after'), '30');
    assert.equal(launches, 1); assert.equal(active, 1);
    held = false; unlock();
    const responses = await Promise.all(requests);
    assert.deepEqual(responses.map(r => r.status).sort(), [200, 200, 200, 503]);
    assert.equal(maximum, 1); assert.equal(launches, 3);
    const successful = responses.find(r => r.status === 200);
    assert.match(await successful.text(), /^%PDF/);
  });
  assert.equal(active, 0);
});

test('a failed Chromium launch releases its slot so the next export can succeed', async () => {
  failLaunch = true;
  await withServer(async post => {
    assert.equal((await post()).status, 500);
    failLaunch = false;
    assert.equal((await post()).status, 200);
  });
});
